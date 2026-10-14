"""Detection rule validation and the YAML the rule engine evaluates.

One code path decides what a stored ``DetectionRule`` means to the engine
(``engine_yaml_for_rule``) and the same checks back ``POST /siem/rules``,
``PUT /siem/rules/{id}`` and ``POST /siem/rules/validate``
(``validate_rule``), so a rule the API accepts is a rule the engine loads.

Accepted definitions:

* ``rule_yaml``: a Sigma-like document. ``detection`` is required and holds
  named selections plus a ``condition`` (``and`` / ``or`` / ``not`` and
  parentheses over selection names). Selections map fields to values; a
  list value is any-of; ``Field|contains`` / ``|startswith`` / ``|endswith``
  / ``|re`` / ``|cidr`` / ``|gt`` / ``|gte`` / ``|lt`` / ``|lte`` /
  ``|exists`` and ``|all`` modifiers are evaluated by the engine. A list of
  maps is OR over the maps; a list of plain values is a keyword search over
  ``message`` / ``raw_log``. ``timewindow`` + ``threshold`` (+ ``group_by``)
  inside ``detection`` turn the rule into a count rule.
* ``detection_logic``: either a full detection block (it has a
  ``condition`` key, as Sigma imports store it), a set of named selections
  referenced by the rule's ``condition``, or a single selection (field ->
  value) evaluated as ``selection``.

Not supported (reported as field errors, never accepted silently): Sigma
aggregation pipes (``| count() > 5``), ``1 of`` / ``all of`` / ``them``
quantifiers, lists of conditions, and modifiers other than the ones above.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from ipaddress import ip_network
from typing import Any, Optional

import yaml

from src.siem.rules.engine import (
    DetectionRuleInstance,
    FieldMatcher,
    UnsupportedModifierError,
)

ALLOWED_SEVERITIES = ("critical", "high", "medium", "low", "informational")

#: Keys of a detection block that are settings, not selections.
_DETECTION_SETTINGS = frozenset({"condition", "timewindow", "threshold", "group_by"})
_CONDITION_OPERATORS = frozenset({"AND", "OR", "NOT"})
_UNSUPPORTED_CONDITION = re.compile(r"\|\s*\w|\b\d+\s+of\b|\ball\s+of\b|\bany\s+of\b|\bthem\b", re.I)
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-*]*$")


@dataclass
class RuleValidation:
    """Outcome of ``validate_rule``."""

    field_errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: The detection block the engine will evaluate (None when invalid).
    detection: Optional[dict[str, Any]] = None

    @property
    def valid(self) -> bool:
        return not self.field_errors

    def add(self, field_name: str, message: str) -> None:
        self.field_errors.append({"field": field_name, "message": message})

    def messages(self) -> list[str]:
        return [f"{e['field']}: {e['message']}" for e in self.field_errors]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": self.messages(),
            "field_errors": list(self.field_errors),
            "warnings": list(self.warnings),
            "detection": self.detection if self.valid else None,
        }


def _condition_identifiers(condition: str) -> list[str]:
    tokens = re.sub(r"(\(|\))", r" \1 ", condition).split()
    return [t for t in tokens if t not in ("(", ")") and t.upper() not in _CONDITION_OPERATORS]


def detection_block_from_logic(logic: dict[str, Any], condition: Optional[str]) -> dict[str, Any]:
    """The detection block a stored ``detection_logic`` stands for.

    * has ``condition``: already a full block (Sigma imports store this);
    * the rule's ``condition`` names keys of ``logic`` whose values are
      mappings / lists: named selections plus that condition;
    * otherwise: one selection called ``selection`` evaluated with the
      rule's condition (default ``selection``).
    """
    if "condition" in logic:
        return dict(logic)
    if condition:
        names = _condition_identifiers(condition)
        if names and all(
            name in logic and isinstance(logic[name], (dict, list)) for name in names
        ):
            return {**logic, "condition": condition}
    return {"selection": logic, "condition": condition or "selection"}


def _check_value(path: str, matcher: FieldMatcher, value: Any, result: RuleValidation) -> None:
    values = value if isinstance(value, list) else [value]
    op = matcher.operator
    if op == "regex":
        for v in values:
            try:
                re.compile(str(v))
            except re.error as exc:
                result.add(path, f"invalid regular expression {v!r}: {exc}")
    elif op == "cidr":
        for v in values:
            try:
                ip_network(str(v), strict=False)
            except ValueError as exc:
                result.add(path, f"invalid CIDR {v!r}: {exc}")
    elif op in (">", "<", ">=", "<="):
        for v in values:
            try:
                float(v)
            except (TypeError, ValueError):
                result.add(path, f"numeric comparison needs a number, got {v!r}")


def _check_selection(path: str, name: str, body: Any, result: RuleValidation) -> None:
    if isinstance(body, list):
        if not body:
            result.add(path, f"selection '{name}' is an empty list")
        for index, item in enumerate(body):
            if isinstance(item, dict):
                _check_selection(f"{path}[{index}]", f"{name}[{index}]", item, result)
            elif not isinstance(item, (str, int, float)):
                result.add(f"{path}[{index}]", "list items must be field maps or keywords")
        return
    if not isinstance(body, dict):
        result.add(path, f"selection '{name}' must be a mapping of field -> value")
        return
    fields = {k: v for k, v in body.items() if k not in _DETECTION_SETTINGS}
    if not fields:
        result.add(path, f"selection '{name}' has no field conditions (it would match every log)")
        return
    for field_name, value in fields.items():
        field_path = f"{path}.{field_name}"
        if not isinstance(field_name, str) or not field_name.split("|")[0].strip():
            result.add(field_path, "field name must be a non-empty string")
            continue
        try:
            matcher = FieldMatcher(field_name, value)
        except UnsupportedModifierError as exc:
            result.add(field_path, str(exc))
            continue
        if value is None or value == [] or value == {}:
            result.add(field_path, "value is empty")
            continue
        if isinstance(value, dict) and matcher.operator == "exact" and matcher.modifier_operator is None:
            result.add(
                field_path,
                "unknown operator map; use one of regex, contains, startswith, endswith, "
                "all, cidr, exists, >, <, >=, <= (or a Sigma modifier such as Field|contains)",
            )
            continue
        _check_value(field_path, matcher, matcher.value, result)


def _check_condition(path: str, condition: Any, selections: set[str], result: RuleValidation) -> None:
    if isinstance(condition, list):
        result.add(path, "a list of conditions is not supported; combine them with 'or'")
        return
    if not isinstance(condition, str) or not condition.strip():
        result.add(path, "condition is required (e.g. 'selection and not filter')")
        return
    if _UNSUPPORTED_CONDITION.search(condition):
        result.add(
            path,
            "aggregation pipes and '1 of' / 'all of' / 'them' quantifiers are not supported; "
            "name the selections explicitly and use detection.timewindow/threshold for counts",
        )
        return
    tokens = re.sub(r"(\(|\))", r" \1 ", condition).split()
    depth = 0
    expect_operand = True
    for token in tokens:
        upper = token.upper()
        if token == "(":
            if not expect_operand:
                result.add(path, "missing 'and' / 'or' before '('")
                return
            depth += 1
        elif token == ")":
            if expect_operand:
                result.add(path, "unexpected ')'")
                return
            depth -= 1
            if depth < 0:
                result.add(path, "unbalanced parentheses")
                return
        elif upper == "NOT":
            if not expect_operand:
                result.add(path, "'not' must follow 'and' / 'or' or start the condition")
                return
        elif upper in ("AND", "OR"):
            if expect_operand:
                result.add(path, f"'{token}' needs a selection on its left")
                return
            expect_operand = True
        else:
            if not expect_operand:
                result.add(path, f"missing 'and' / 'or' before '{token}'")
                return
            if not _IDENTIFIER.match(token):
                result.add(path, f"'{token}' is not a valid selection name")
                return
            if token not in selections:
                result.add(path, f"condition references unknown selection '{token}'")
            expect_operand = False
    if depth != 0:
        result.add(path, "unbalanced parentheses")
    elif expect_operand:
        result.add(path, "condition ends with an operator")


def _check_detection(
    detection: Any,
    result: RuleValidation,
    *,
    base_path: str,
    selection_paths: Optional[dict[str, str]] = None,
    condition_path: Optional[str] = None,
) -> None:
    if not isinstance(detection, dict):
        result.add(base_path, "detection must be a mapping of named selections plus a condition")
        return
    selections = {k: v for k, v in detection.items() if k not in _DETECTION_SETTINGS}
    if not selections:
        result.add(base_path, "detection needs at least one named selection")
    for name, body in selections.items():
        path = (selection_paths or {}).get(name, f"{base_path}.{name}")
        _check_selection(path, str(name), body, result)
    _check_condition(
        condition_path or f"{base_path}.condition",
        detection.get("condition"),
        {str(k) for k in selections},
        result,
    )
    timewindow = detection.get("timewindow")
    threshold = detection.get("threshold")
    for key, value in (("timewindow", timewindow), ("threshold", threshold)):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            result.add(f"{base_path}.{key}", f"{key} must be a non-negative integer")
    if bool(timewindow) != bool(threshold):
        result.warnings.append(
            "timewindow and threshold only take effect together; this rule fires on every match",
        )
    group_by = detection.get("group_by")
    if group_by is not None and not (
        isinstance(group_by, list) and all(isinstance(g, str) for g in group_by)
    ):
        result.add(f"{base_path}.group_by", "group_by must be a list of field names")


def _yaml_error_message(exc: yaml.YAMLError) -> str:
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or str(exc)
    if mark is not None:
        return f"invalid YAML at line {mark.line + 1}, column {mark.column + 1}: {problem}"
    return f"invalid YAML: {problem}"


def validate_rule(
    *,
    name: Optional[str] = None,
    title: Optional[str] = None,
    severity: Optional[str] = None,
    rule_yaml: Optional[str] = None,
    detection_logic: Optional[dict[str, Any]] = None,
    condition: Optional[str] = None,
    require_identity: bool = True,
    require_detection: bool = True,
) -> RuleValidation:
    """Validate a rule definition the way the engine will load it."""
    result = RuleValidation()

    if require_identity:
        if not (name or "").strip():
            result.add("name", "name is required")
        if not (title or "").strip():
            result.add("title", "title is required")
    if severity is not None and severity not in ALLOWED_SEVERITIES:
        result.add("severity", f"severity must be one of {', '.join(ALLOWED_SEVERITIES)}")

    if rule_yaml is not None and rule_yaml.strip():
        try:
            parsed = yaml.safe_load(rule_yaml)
        except yaml.YAMLError as exc:
            result.add("rule_yaml", _yaml_error_message(exc))
            return result
        if not isinstance(parsed, dict):
            result.add("rule_yaml", "the YAML document must be a mapping at the top level")
            return result
        if "detection" not in parsed:
            result.add("rule_yaml.detection", "detection is required")
            return result
        level = parsed.get("level", parsed.get("severity"))
        if level is not None and str(level).lower() not in ALLOWED_SEVERITIES:
            result.add("rule_yaml.level", f"level must be one of {', '.join(ALLOWED_SEVERITIES)}")
        if not parsed.get("title") and not title:
            result.add("rule_yaml.title", "title is required")
        _check_detection(parsed["detection"], result, base_path="rule_yaml.detection")
        if detection_logic:
            result.warnings.append(
                "rule_yaml is provided, so the engine evaluates it; detection_logic is kept for reference only",
            )
        detection = parsed["detection"]
    elif detection_logic is not None:
        if not isinstance(detection_logic, dict) or not detection_logic:
            result.add("detection_logic", "detection_logic must be a non-empty mapping")
            return result
        detection = detection_block_from_logic(detection_logic, condition)
        wrapped = "selection" in detection and detection.get("selection") is detection_logic
        _check_detection(
            detection,
            result,
            base_path="detection_logic",
            selection_paths={"selection": "detection_logic"} if wrapped else None,
            condition_path="condition" if condition and "condition" not in detection_logic else None,
        )
    else:
        if require_detection:
            result.add(
                "detection_logic",
                "detection logic is required: send rule_yaml (Sigma-like YAML) or detection_logic "
                "(field -> value conditions); a rule without it would never fire",
            )
        return result

    if result.valid:
        # Last line of defence: the engine itself must accept the block.
        try:
            instance = DetectionRuleInstance({"id": "validation", "title": title or "validation",
                                              "status": "active", "detection": detection})
            instance.evaluate({})
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            result.add("rule_yaml" if rule_yaml else "detection_logic", f"the rule engine rejected it: {exc}")
            return result
        result.detection = detection
    return result


def _json_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def engine_yaml_for_rule(rule: Any) -> Optional[str]:
    """The YAML the engine loads for a stored ``DetectionRule`` (None: nothing to evaluate).

    The engine rule id is the database id (so match counters and alerts point
    at the row), ``status`` is active (the database ``enabled`` flag already
    decided whether the rule loads; Sigma's ``stable`` / ``test`` statuses
    would otherwise disable it), and severity / MITRE come from the row.
    """
    data: Optional[dict[str, Any]] = None
    if getattr(rule, "rule_yaml", None):
        parsed = yaml.safe_load(rule.rule_yaml)
        if isinstance(parsed, dict):
            data = dict(parsed)
    elif getattr(rule, "detection_logic", None):
        logic = rule.detection_logic
        if isinstance(logic, str):
            logic = json.loads(logic)
        if isinstance(logic, dict):
            data = {
                "title": rule.title or rule.name,
                "description": rule.description or "",
                "detection": detection_block_from_logic(logic, getattr(rule, "condition", None)),
            }
    if data is None:
        return None
    # Count settings stored in the rule's columns (Create Rule's
    # timewindow / threshold / group_by) apply unless the detection block
    # sets its own.
    detection = data.get("detection")
    if isinstance(detection, dict):
        detection = dict(detection)
        timewindow = getattr(rule, "timewindow", None)
        threshold = getattr(rule, "threshold", None)
        if timewindow and threshold and "timewindow" not in detection and "threshold" not in detection:
            detection["timewindow"] = int(timewindow)
            detection["threshold"] = int(threshold)
            group_by = _json_list(getattr(rule, "group_by", None))
            if group_by and "group_by" not in detection:
                detection["group_by"] = [str(g) for g in group_by]
        data["detection"] = detection
    data["id"] = str(rule.id)
    data["status"] = "active"
    if getattr(rule, "severity", None):
        data["severity"] = rule.severity
    data.setdefault("title", rule.title or rule.name)
    tactics = _json_list(getattr(rule, "mitre_tactics", None))
    techniques = _json_list(getattr(rule, "mitre_techniques", None))
    if tactics or techniques:
        data["mitre"] = {"tactics": tactics, "techniques": techniques}
    return yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
