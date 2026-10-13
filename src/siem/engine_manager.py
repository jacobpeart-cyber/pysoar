"""
Per-organisation managers for the SIEM Rule Engine and Correlation Engine.

Tenancy model (wave 1, docs/audit/2026-10-08/PLAN.md):

* Every organisation gets its own ``RuleEngine`` and ``CorrelationEngine``.
  A log from org A is only ever evaluated against org A's engine, so it can
  never trigger org B's custom rules or correlate with org B's events.
* An organisation's rule engine holds that organisation's enabled rules PLUS
  the enabled platform rules (``DetectionRule.organization_id IS NULL``, the
  built-ins installed by ``src.siem.rule_seeder``). Platform rules therefore
  apply to every organisation's logs, and the alert / correlation they
  produce carries the log's organisation (see ``src.siem.pipeline``).
* Logs with no organisation (for example syslog when no default org is
  configured) use the ``None`` key: platform rules only, and a correlation
  buffer that is never shared with any tenant.

Engines live in-process and are rebuilt lazily after rule CRUD through
``reload_rules``. They are bounded by an LRU so a long-running worker that
has seen many organisations does not grow without limit; an evicted engine
is simply rebuilt from the database on next use (correlation state for that
organisation starts afresh).
"""

from __future__ import annotations

import json
import threading
from collections import OrderedDict
from typing import Any, Optional

import yaml
from sqlalchemy import or_, select

from src.core.logging import get_logger
from src.siem.correlation import CorrelationEngine
from src.siem.rules.engine import RuleEngine

logger = get_logger(__name__)

#: Maximum number of organisations whose engines are kept in memory.
MAX_CACHED_ORGANIZATIONS = 1024

_lock = threading.RLock()
_rule_engines: "OrderedDict[Optional[str], RuleEngine]" = OrderedDict()
_loaded_orgs: set[Optional[str]] = set()
_correlation_engines: "OrderedDict[Optional[str], CorrelationEngine]" = OrderedDict()


def _touch(cache: "OrderedDict[Optional[str], Any]", key: Optional[str]) -> None:
    cache.move_to_end(key)
    while len(cache) > MAX_CACHED_ORGANIZATIONS:
        evicted, _ = cache.popitem(last=False)
        if cache is _rule_engines:
            _loaded_orgs.discard(evicted)


def get_rule_engine(organization_id: Optional[str] = None) -> RuleEngine:
    """Return the RuleEngine for ``organization_id`` (``None`` = platform rules only)."""
    with _lock:
        engine = _rule_engines.get(organization_id)
        if engine is None:
            engine = RuleEngine()
            _rule_engines[organization_id] = engine
            logger.info("RuleEngine created", organization_id=organization_id)
        _touch(_rule_engines, organization_id)
        return engine


def get_correlation_engine(organization_id: Optional[str] = None) -> CorrelationEngine:
    """Return the CorrelationEngine (and its event buffers) for ``organization_id``."""
    with _lock:
        engine = _correlation_engines.get(organization_id)
        if engine is None:
            engine = CorrelationEngine()
            _correlation_engines[organization_id] = engine
            logger.info("CorrelationEngine created", organization_id=organization_id)
        _touch(_correlation_engines, organization_id)
        return engine


def _rule_scope(organization_id: Optional[str]):
    """Rules that apply to an organisation: its own plus platform (NULL-org) rules."""
    from src.siem.models import DetectionRule

    if organization_id is None:
        return DetectionRule.organization_id.is_(None)
    return or_(
        DetectionRule.organization_id == organization_id,
        DetectionRule.organization_id.is_(None),
    )


async def load_rules_from_db(db, organization_id: Optional[str] = None) -> int:
    """Load the enabled rules that apply to ``organization_id`` into its engine.

    ``organization_id=None`` loads the platform (built-in) rules only.
    """
    from src.siem.models import DetectionRule

    engine = get_rule_engine(organization_id)

    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.enabled == True,  # noqa: E712
            _rule_scope(organization_id),
        )
    )
    rules = result.scalars().all()

    loaded = 0
    for rule in rules:
        try:
            if rule.rule_yaml:
                instance = engine.load_rule_from_yaml(rule.rule_yaml)
                if instance:
                    loaded += 1
            elif rule.detection_logic:
                logic = (
                    json.loads(rule.detection_logic)
                    if isinstance(rule.detection_logic, str)
                    else rule.detection_logic
                )
                yaml_content = _build_yaml_from_logic(rule, logic)
                instance = engine.load_rule_from_yaml(yaml_content)
                if instance:
                    loaded += 1
        except (ValueError, TypeError, KeyError, yaml.YAMLError) as e:
            logger.warning("Failed to load detection rule", rule_id=rule.id, error=str(e))

    with _lock:
        _loaded_orgs.add(organization_id)
    logger.info(
        "Loaded detection rules",
        organization_id=organization_id,
        loaded=loaded,
        total=len(rules),
    )
    return loaded


async def ensure_rules_loaded(db, organization_id: Optional[str] = None) -> None:
    """Load ``organization_id``'s rules on first use (lazy initialisation)."""
    with _lock:
        loaded = organization_id in _loaded_orgs and organization_id in _rule_engines
    if not loaded:
        await load_rules_from_db(db, organization_id)


async def reload_rules(db, organization_id: Optional[str] = None) -> int:
    """Rebuild rule engines after rule CRUD.

    A change to an organisation's own rule only invalidates that
    organisation's engine. A change to a platform rule (``organization_id``
    None) invalidates every engine, because platform rules are part of every
    organisation's rule set; the others are rebuilt lazily on next use.
    """
    with _lock:
        if organization_id is None:
            _rule_engines.clear()
            _loaded_orgs.clear()
        else:
            _rule_engines.pop(organization_id, None)
            _loaded_orgs.discard(organization_id)
    return await load_rules_from_db(db, organization_id)


def reset_engines() -> None:
    """Drop every cached rule and correlation engine (tests / admin reset)."""
    with _lock:
        _rule_engines.clear()
        _loaded_orgs.clear()
        _correlation_engines.clear()


def _build_yaml_from_logic(rule, logic: dict) -> str:
    """Build YAML rule definition from detection_logic JSON."""
    condition = getattr(rule, "condition", None) or "selection"

    yaml_dict = {
        "title": rule.title or rule.name,
        "id": str(rule.id),
        "status": "active",
        "description": rule.description or "",
        "level": rule.severity or "medium",
        "detection": {
            "selection": logic,
            "condition": condition,
        },
    }

    if rule.mitre_tactics:
        tactics = json.loads(rule.mitre_tactics) if isinstance(rule.mitre_tactics, str) else rule.mitre_tactics
        yaml_dict["tags"] = tactics

    return yaml.dump(yaml_dict, default_flow_style=False)
