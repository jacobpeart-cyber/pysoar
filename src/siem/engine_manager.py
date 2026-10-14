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

Rule CRUD happens in one API process while logs are evaluated in others
(other API workers, the ingest-queue consumers, Celery pollers). Each
process therefore re-checks an organisation's rule fingerprint (count and
latest ``updated_at`` of the rules that apply to it) at most every
``RULE_REFRESH_SECONDS`` and rebuilds the engine when it changed, so a rule
created, edited, disabled or deleted anywhere takes effect everywhere within
that interval.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Optional

import yaml
from sqlalchemy import func, or_, select

from src.core.logging import get_logger
from src.siem.correlation import CorrelationEngine
from src.siem.rules.engine import RuleEngine

logger = get_logger(__name__)

#: Maximum number of organisations whose engines are kept in memory.
MAX_CACHED_ORGANIZATIONS = 1024
#: How often a process re-checks whether an organisation's rules changed.
RULE_REFRESH_SECONDS = 30.0

_lock = threading.RLock()
_rule_engines: "OrderedDict[Optional[str], RuleEngine]" = OrderedDict()
_loaded_orgs: set[Optional[str]] = set()
_correlation_engines: "OrderedDict[Optional[str], CorrelationEngine]" = OrderedDict()
#: organisation -> (fingerprint at load, monotonic time of the last check)
_fingerprints: dict[Optional[str], tuple[tuple, float]] = {}


def _touch(cache: "OrderedDict[Optional[str], Any]", key: Optional[str]) -> None:
    cache.move_to_end(key)
    while len(cache) > MAX_CACHED_ORGANIZATIONS:
        evicted, _ = cache.popitem(last=False)
        if cache is _rule_engines:
            _loaded_orgs.discard(evicted)
            _fingerprints.pop(evicted, None)


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


async def _rules_fingerprint(db, organization_id: Optional[str]) -> tuple:
    """(count, latest updated_at) of every rule that applies to the organisation."""
    from src.siem.models import DetectionRule

    row = (
        await db.execute(
            select(func.count(DetectionRule.id), func.max(DetectionRule.updated_at)).where(
                _rule_scope(organization_id),
            ),
        )
    ).one()
    return (int(row[0] or 0), str(row[1]) if row[1] is not None else None)


async def load_rules_from_db(db, organization_id: Optional[str] = None) -> int:
    """Load the enabled rules that apply to ``organization_id`` into a fresh engine.

    ``organization_id=None`` loads the platform (built-in) rules only. The
    engine is rebuilt from scratch, so a disabled or deleted rule is gone.
    """
    from src.siem.models import DetectionRule
    from src.siem.rule_validation import engine_yaml_for_rule

    fingerprint = await _rules_fingerprint(db, organization_id)
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.enabled == True,  # noqa: E712
            _rule_scope(organization_id),
        )
    )
    rules = result.scalars().all()

    engine = RuleEngine()
    loaded = 0
    for rule in rules:
        try:
            yaml_content = engine_yaml_for_rule(rule)
            if yaml_content and engine.load_rule_from_yaml(yaml_content):
                loaded += 1
            else:
                logger.warning("Detection rule has nothing the engine can evaluate", rule_id=rule.id)
        except (ValueError, TypeError, KeyError, yaml.YAMLError) as e:
            logger.warning("Failed to load detection rule", rule_id=rule.id, error=str(e))

    with _lock:
        _rule_engines[organization_id] = engine
        _touch(_rule_engines, organization_id)
        _loaded_orgs.add(organization_id)
        _fingerprints[organization_id] = (fingerprint, time.monotonic())
    logger.info(
        "Loaded detection rules",
        organization_id=organization_id,
        loaded=loaded,
        total=len(rules),
    )
    return loaded


async def ensure_rules_loaded(db, organization_id: Optional[str] = None) -> None:
    """Load ``organization_id``'s rules on first use; reload when they changed.

    The change check (one aggregate query) runs at most every
    ``RULE_REFRESH_SECONDS`` per organisation and process.
    """
    with _lock:
        loaded = organization_id in _loaded_orgs and organization_id in _rule_engines
        known = _fingerprints.get(organization_id)
    if not loaded or known is None:
        await load_rules_from_db(db, organization_id)
        return
    fingerprint, checked_at = known
    if time.monotonic() - checked_at < RULE_REFRESH_SECONDS:
        return
    current = await _rules_fingerprint(db, organization_id)
    if current != fingerprint:
        logger.info("Detection rules changed; reloading", organization_id=organization_id)
        await load_rules_from_db(db, organization_id)
        return
    with _lock:
        _fingerprints[organization_id] = (fingerprint, time.monotonic())


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
            _fingerprints.clear()
        else:
            _rule_engines.pop(organization_id, None)
            _loaded_orgs.discard(organization_id)
            _fingerprints.pop(organization_id, None)
    return await load_rules_from_db(db, organization_id)


def reset_engines() -> None:
    """Drop every cached rule and correlation engine (tests / admin reset)."""
    with _lock:
        _rule_engines.clear()
        _loaded_orgs.clear()
        _correlation_engines.clear()
        _fingerprints.clear()


def _build_yaml_from_logic(rule, logic: dict) -> str:
    """Build the engine YAML for a rule from its detection_logic JSON.

    Kept for callers that pass the logic explicitly; the mapping itself lives
    in ``src.siem.rule_validation`` so the validator, the dry-run test route
    and the engine agree on what ``detection_logic`` means.
    """
    from src.siem.rule_validation import detection_block_from_logic

    yaml_dict: dict[str, Any] = {
        "title": rule.title or rule.name,
        "id": str(rule.id),
        "status": "active",
        "description": rule.description or "",
        "level": rule.severity or "medium",
        "detection": detection_block_from_logic(logic, getattr(rule, "condition", None)),
    }
    return yaml.dump(yaml_dict, default_flow_style=False)
