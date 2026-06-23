"""IncidentResponse must serialize incidents whose JSON columns are populated.

The ORM stores affected_systems / affected_users / indicators / tags / mitre_*
as JSON strings. IncidentResponse declares them as list/dict with
from_attributes=True, so the raw string reaches validation. This was only ever
exercised once those columns started getting populated (auto-created incidents
inheriting alert artifacts), at which point the incident list endpoint began
500-ing with a pydantic dict_type/list_type error. These tests pin the parse.
"""

import json

from src.schemas.incident import IncidentResponse


class _Inc:
    """Minimal stand-in for an Incident ORM row (from_attributes reads attrs)."""

    def __init__(self, **kw):
        defaults = dict(
            id="inc-1", title="t", description=None, severity="critical",
            incident_type="c2", priority=3, status="open", assigned_to=None,
            impact=None, affected_systems=None, affected_users=None,
            detected_at=None, contained_at=None, resolved_at=None,
            root_cause=None, resolution=None, lessons_learned=None,
            recommendations=None, indicators=None, evidence=None, tags=None,
            mitre_tactics=None, mitre_techniques=None, external_id=None,
            ticket_url=None, created_at=None, updated_at=None,
        )
        defaults.update(kw)
        for k, v in defaults.items():
            setattr(self, k, v)


def test_json_string_list_columns_parse():
    inc = _Inc(
        affected_systems=json.dumps(["staging-api", "file-share-01"]),
        affected_users=json.dumps(["alice@corp"]),
        indicators=json.dumps(["185.220.101.7"]),  # list form (IOC values)
        tags=json.dumps(["ransomware"]),
    )
    r = IncidentResponse.model_validate(inc)
    assert r.affected_systems == ["staging-api", "file-share-01"]
    assert r.affected_users == ["alice@corp"]
    assert r.indicators == ["185.220.101.7"]
    assert r.tags == ["ransomware"]


def test_indicators_dict_form_still_accepted():
    inc = _Inc(indicators=json.dumps({"ips": ["1.2.3.4"]}), evidence=json.dumps({"k": "v"}))
    r = IncidentResponse.model_validate(inc)
    assert r.indicators == {"ips": ["1.2.3.4"]}
    assert r.evidence == {"k": "v"}


def test_null_and_garbage_columns_do_not_raise():
    # None stays None; an unparseable string degrades to None rather than 500.
    inc = _Inc(affected_systems=None, indicators="not json{", tags="")
    r = IncidentResponse.model_validate(inc)
    assert r.affected_systems is None
    assert r.indicators is None
    assert r.tags is None


def test_already_parsed_value_passes_through():
    inc = _Inc(affected_systems=["h1"], indicators=["1.1.1.1"])
    r = IncidentResponse.model_validate(inc)
    assert r.affected_systems == ["h1"]
    assert r.indicators == ["1.1.1.1"]
