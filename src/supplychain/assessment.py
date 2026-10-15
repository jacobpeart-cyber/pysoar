"""SBOM validation, NTIA minimum-element compliance and vendor scoring (wave 4).

Everything here is computed from stored or uploaded data:

- ``validate_sbom_document`` checks an uploaded CycloneDX / SPDX JSON document
  against the structural rules of its spec (format marker, spec version,
  component / package entries with names) and returns the errors; a document
  with errors is rejected, never partially stored.
- ``dependency_stats`` derives direct / transitive dependency counts from the
  document's own dependency graph (CycloneDX ``dependencies``, SPDX
  ``relationships``); without a graph the counts stay 0 and the NTIA
  "dependency relationship" element is reported missing.
- ``assess_sbom`` evaluates the NTIA minimum elements per stored component
  (supplier, name, version, unique identifier) plus the SBOM-level author,
  timestamp and dependency relationships. ``not_assessed`` when the SBOM has
  no components.
- Vendor assessments are scored from stored questionnaire answers only
  (``VENDOR_QUESTIONS``); with no answers the vendor is ``not_assessed``.
"""

from __future__ import annotations

import json
from typing import Any, Optional

#: Upload / import limits.
MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_SBOM_COMPONENTS = 20_000

CYCLONEDX_SPEC_VERSIONS = ("1.2", "1.3", "1.4", "1.5", "1.6")
SPDX_PREFIX = "SPDX-2."


class SBOMValidationError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors[:10]))


def detect_format(doc: Any) -> Optional[str]:
    if isinstance(doc, dict) and "spdxVersion" in doc:
        return "spdx_json"
    if isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx_json"
    return None


def validate_sbom_document(doc: Any, sbom_format: str) -> None:
    """Raise SBOMValidationError listing every structural problem found."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        raise SBOMValidationError(["document is not a JSON object"])
    if sbom_format == "cyclonedx_json":
        if doc.get("bomFormat") != "CycloneDX":
            errors.append("bomFormat must be 'CycloneDX'")
        if str(doc.get("specVersion")) not in CYCLONEDX_SPEC_VERSIONS:
            errors.append(f"specVersion must be one of {', '.join(CYCLONEDX_SPEC_VERSIONS)}")
        comps = doc.get("components", [])
        if not isinstance(comps, list):
            errors.append("components must be an array")
            comps = []
        for i, c in enumerate(comps):
            if not isinstance(c, dict):
                errors.append(f"components[{i}] is not an object")
            elif not c.get("name"):
                errors.append(f"components[{i}] has no name")
            elif not c.get("type"):
                errors.append(f"components[{i}] ({c.get('name')}) has no type")
            if len(errors) > 50:
                break
        deps = doc.get("dependencies", [])
        if deps is not None and not isinstance(deps, list):
            errors.append("dependencies must be an array")
    elif sbom_format == "spdx_json":
        if not str(doc.get("spdxVersion", "")).startswith(SPDX_PREFIX):
            errors.append("spdxVersion must be SPDX-2.x")
        if doc.get("SPDXID") != "SPDXRef-DOCUMENT":
            errors.append("SPDXID must be 'SPDXRef-DOCUMENT'")
        if not doc.get("name"):
            errors.append("document name is required")
        if not isinstance(doc.get("creationInfo"), dict) or not doc["creationInfo"].get("created"):
            errors.append("creationInfo.created is required")
        pkgs = doc.get("packages", [])
        if not isinstance(pkgs, list):
            errors.append("packages must be an array")
            pkgs = []
        for i, p in enumerate(pkgs):
            if not isinstance(p, dict):
                errors.append(f"packages[{i}] is not an object")
            elif not p.get("name"):
                errors.append(f"packages[{i}] has no name")
            elif not str(p.get("SPDXID", "")).startswith("SPDXRef-"):
                errors.append(f"packages[{i}] ({p.get('name')}) has no SPDXRef- SPDXID")
            if len(errors) > 50:
                break
        rels = doc.get("relationships", [])
        if rels is not None and not isinstance(rels, list):
            errors.append("relationships must be an array")
    else:
        errors.append(f"unsupported SBOM format {sbom_format!r} (spdx_json or cyclonedx_json)")
    if errors:
        raise SBOMValidationError(errors)


_SPDX_DEP_TYPES = {
    "DEPENDS_ON", "DEV_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF",
    "OPTIONAL_DEPENDENCY_OF", "DEPENDENCY_OF", "CONTAINS", "CONTAINED_BY", "DEV_TOOL_OF",
}


def dependency_stats(doc: dict[str, Any], sbom_format: str) -> dict[str, Any]:
    """Direct / transitive counts from the document's dependency graph."""
    edges: list[tuple[str, str]] = []
    root: Optional[str] = None
    if sbom_format == "cyclonedx_json":
        root = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
        for d in doc.get("dependencies") or []:
            if isinstance(d, dict) and d.get("ref"):
                for target in d.get("dependsOn") or []:
                    edges.append((str(d["ref"]), str(target)))
    else:
        described = [
            r.get("relatedSpdxElement") for r in doc.get("relationships") or []
            if isinstance(r, dict) and r.get("relationshipType") == "DESCRIBES"
            and r.get("spdxElementId") == "SPDXRef-DOCUMENT"
        ]
        root = described[0] if len(described) == 1 else None
        for r in doc.get("relationships") or []:
            if not isinstance(r, dict) or r.get("relationshipType") not in _SPDX_DEP_TYPES:
                continue
            a, b = str(r.get("spdxElementId")), str(r.get("relatedSpdxElement"))
            # *_OF relationships point from the dependency to its dependent.
            edges.append((b, a) if str(r["relationshipType"]).endswith("_OF") or r["relationshipType"] == "CONTAINED_BY" else (a, b))
    if not edges:
        return {"has_graph": False, "edges": 0, "direct": 0, "transitive": 0}
    targets = {b for _, b in edges}
    direct = {b for a, b in edges if a == root} if root else set()
    return {
        "has_graph": True,
        "edges": len(edges),
        "direct": len(direct),
        "transitive": len(targets - direct) if root else 0,
    }


def stored_graph(sbom_content: Optional[str], sbom_format: str) -> dict[str, Any]:
    """dependency_stats of a stored SBOM document (no graph when unreadable)."""
    if not sbom_content or sbom_format not in ("cyclonedx_json", "spdx_json"):
        return {"has_graph": False, "edges": 0, "direct": 0, "transitive": 0}
    try:
        doc = json.loads(sbom_content)
    except (json.JSONDecodeError, TypeError):
        return {"has_graph": False, "edges": 0, "direct": 0, "transitive": 0}
    if not isinstance(doc, dict):
        return {"has_graph": False, "edges": 0, "direct": 0, "transitive": 0}
    return dependency_stats(doc, sbom_format)


NTIA_COMPONENT_ELEMENTS = ("supplier", "component_name", "version", "unique_identifier")


def assess_sbom(
    *,
    components: list[dict[str, Any]],
    author: Optional[str],
    timestamp: Any,
    has_dependency_graph: bool,
    sbom_format: Optional[str] = None,
    sbom_id: Optional[str] = None,
) -> dict[str, Any]:
    """NTIA minimum elements from stored component rows; status + per-element coverage."""
    total = len(components)
    coverage: dict[str, float] = {}
    missing_components: dict[str, list[str]] = {}
    for element in NTIA_COMPONENT_ELEMENTS:
        have = 0
        missing: list[str] = []
        for c in components:
            if element == "supplier":
                ok = bool(c.get("vendor"))
            elif element == "component_name":
                ok = bool(c.get("name"))
            elif element == "version":
                ok = bool(c.get("version")) and str(c.get("version")).lower() not in ("unknown", "noassertion")
            else:
                ok = bool(c.get("purl") or c.get("cpe") or c.get("checksum_sha256"))
            if ok:
                have += 1
            elif len(missing) < 20:
                missing.append(f"{c.get('name')}@{c.get('version')}")
        coverage[element] = round(have / total * 100, 1) if total else 0.0
        if missing:
            missing_components[element] = missing
    doc_elements = {
        "author": bool(author),
        "timestamp": bool(timestamp),
        "dependency_relationships": bool(has_dependency_graph),
    }
    required = {**{k: total > 0 and coverage[k] == 100.0 for k in NTIA_COMPONENT_ELEMENTS}, **doc_elements}
    missing_elements = [k for k, ok in required.items() if not ok]
    if total == 0:
        status = "not_assessed"
    else:
        status = "compliant" if not missing_elements else "non_compliant"
    pct = round(sum(1 for v in required.values() if v) / len(required) * 100, 1)
    recommendations = []
    for element in missing_elements:
        if element in coverage:
            recommendations.append(f"{element}: {coverage[element]}% of components carry it")
        else:
            recommendations.append(f"SBOM {element.replace('_', ' ')} is missing")
    return {
        "status": status,
        "sbom_id": sbom_id,
        "basis": "NTIA minimum elements evaluated on the stored components",
        "components_assessed": total,
        "overall_compliant": status == "compliant",
        "element_coverage": coverage,
        "missing_components": missing_components,
        # Kept for existing callers of POST /compliance/validate-sbom.
        "cisa_compliance": {
            "compliant": status == "compliant",
            "required_elements": required,
            "missing_elements": missing_elements,
            "compliance_percentage": pct if total else 0.0,
        },
        "ntia_compliance": {
            "ntia_compliant": status == "compliant",
            "elements": required,
            "confidence_score": pct if total else 0.0,
        },
        "recommendations": recommendations or (["SBOM meets the NTIA minimum elements"] if total else
                                               ["SBOM has no components; nothing to assess"]),
        "sbom_format": sbom_format,
    }


# ---------------------------------------------------------------------------
# Vendor questionnaire
# ---------------------------------------------------------------------------

#: (key, question, weight). Answers: yes / partial / no / n/a.
VENDOR_QUESTIONS: tuple[tuple[str, str, int], ...] = (
    ("mfa_enforced", "Is multi-factor authentication enforced for all workforce and admin access?", 3),
    ("encryption_at_rest", "Is customer data encrypted at rest?", 3),
    ("encryption_in_transit", "Is customer data encrypted in transit (TLS 1.2+)?", 3),
    ("vulnerability_management", "Are systems scanned and patched under a defined SLA?", 3),
    ("incident_response_plan", "Is there a tested incident response plan?", 2),
    ("breach_notification", "Is customer breach notification contractually committed (e.g. 72h)?", 2),
    ("access_reviews", "Are privileged access reviews performed at least quarterly?", 2),
    ("penetration_testing", "Is an independent penetration test performed at least annually?", 2),
    ("independent_audit", "Is there a current independent audit report (SOC 2 Type II / ISO 27001)?", 2),
    ("security_training", "Does the workforce receive annual security awareness training?", 1),
    ("background_checks", "Are background checks performed for personnel with data access?", 1),
    ("business_continuity", "Is there a tested business continuity / disaster recovery plan?", 1),
    ("subprocessor_management", "Are subprocessors assessed and disclosed to customers?", 1),
    ("data_retention_deletion", "Is customer data deleted on contract end within a defined period?", 1),
)
_ANSWER_VALUE = {"yes": 1.0, "partial": 0.5, "no": 0.0}
VALID_ANSWERS = ("yes", "partial", "no", "n/a")


def normalise_answers(raw: Any) -> dict[str, str]:
    """Validate answers: known keys, values yes/partial/no/n/a. Raises ValueError."""
    if raw is None:
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("questionnaire_responses is not JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("questionnaire_responses must be an object of question key -> answer")
    known = {k for k, _, _ in VENDOR_QUESTIONS}
    out: dict[str, str] = {}
    for key, value in raw.items():
        if key not in known:
            raise ValueError(f"unknown question {key!r}; see GET /supplychain/vendors/questionnaire")
        answer = str(value).strip().lower()
        if answer not in VALID_ANSWERS:
            raise ValueError(f"answer for {key!r} must be one of {', '.join(VALID_ANSWERS)}")
        out[key] = answer
    return out


def summarise_answers(raw: Any) -> dict[str, Any]:
    """Score (0-100) from stored answers; ``not_assessed`` without answers."""
    try:
        answers = normalise_answers(raw)
    except ValueError:
        answers = {}
    scored = [(w, _ANSWER_VALUE[answers[k]]) for k, _, w in VENDOR_QUESTIONS if answers.get(k) in _ANSWER_VALUE]
    total = len(VENDOR_QUESTIONS)
    answered = sum(1 for k, _, _ in VENDOR_QUESTIONS if k in answers)
    if not scored:
        return {"status": "not_assessed", "score": None, "answered": answered, "total": total}
    weight = sum(w for w, _ in scored)
    score = round(sum(w * v for w, v in scored) / weight * 100, 1)
    return {
        "status": "complete" if answered == total else "partial",
        "score": score,
        "answered": answered,
        "total": total,
    }
