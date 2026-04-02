"""
Singleton managers for SIEM Rule Engine and Correlation Engine.

Holds module-level instances that persist across requests.
Rules are loaded from DB on first access and can be reloaded after CRUD operations.
"""

import logging
from typing import Optional

from src.siem.rules.engine import RuleEngine
from src.siem.correlation import CorrelationEngine

logger = logging.getLogger(__name__)

# Module-level singletons
_rule_engine: Optional[RuleEngine] = None
_correlation_engine: Optional[CorrelationEngine] = None
_rules_loaded: bool = False


def get_rule_engine() -> RuleEngine:
    """Get or create the singleton RuleEngine instance."""
    global _rule_engine
    if _rule_engine is None:
        _rule_engine = RuleEngine()
        logger.info("RuleEngine singleton created")
    return _rule_engine


def get_correlation_engine() -> CorrelationEngine:
    """Get or create the singleton CorrelationEngine instance."""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
        logger.info("CorrelationEngine singleton created")
    return _correlation_engine


async def load_rules_from_db(db) -> int:
    """Load all enabled detection rules from database into the engine."""
    global _rules_loaded
    from sqlalchemy import select
    from src.siem.models import DetectionRule

    engine = get_rule_engine()

    result = await db.execute(
        select(DetectionRule).where(DetectionRule.enabled == True)
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
                import json
                logic = json.loads(rule.detection_logic) if isinstance(rule.detection_logic, str) else rule.detection_logic
                yaml_content = _build_yaml_from_logic(rule, logic)
                instance = engine.load_rule_from_yaml(yaml_content)
                if instance:
                    loaded += 1
        except Exception as e:
            logger.warning(f"Failed to load rule {rule.id}: {e}")

    _rules_loaded = True
    logger.info(f"Loaded {loaded}/{len(rules)} detection rules from database")
    return loaded


async def ensure_rules_loaded(db) -> None:
    """Ensure rules are loaded (lazy initialization)."""
    global _rules_loaded
    if not _rules_loaded:
        await load_rules_from_db(db)


async def reload_rules(db) -> int:
    """Force reload all rules from database."""
    global _rule_engine, _rules_loaded
    _rule_engine = RuleEngine()
    _rules_loaded = False
    return await load_rules_from_db(db)


def _build_yaml_from_logic(rule, logic: dict) -> str:
    """Build YAML rule definition from detection_logic JSON."""
    import json
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

    import yaml
    return yaml.dump(yaml_dict, default_flow_style=False)
