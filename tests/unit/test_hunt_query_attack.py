"""HuntQueryBuilder uses authoritative ATT&CK terms, not the retired
8-entry keyword dict."""

from src.hunting.engine import HuntQueryBuilder


def test_dict_is_retired():
    assert not hasattr(HuntQueryBuilder, "MITRE_TECHNIQUE_PATTERNS"), (
        "the hardcoded 8-entry MITRE_TECHNIQUE_PATTERNS must be gone"
    )


def test_technique_terms_become_search_text():
    qb = HuntQueryBuilder()
    q = qb.build_log_query(
        {"title": "hunt", "mitre_techniques": ["T1110"]},
        {"time_range_hours": 24},
        technique_terms=["Brute Force", "Password Guessing"],
    )
    assert "Brute Force" in q.query_text
    assert "Password Guessing" in q.query_text


def test_falls_back_to_ids_without_terms():
    # No KB terms resolved → use the technique ids themselves rather than
    # silently expanding to nothing (the old dict's failure mode).
    qb = HuntQueryBuilder()
    q = qb.build_log_query(
        {"title": "hunt", "mitre_techniques": ["T1110", "T9999"]},
        {"time_range_hours": 24},
    )
    assert "T1110" in q.query_text


def test_no_techniques_uses_title_description():
    qb = HuntQueryBuilder()
    q = qb.build_log_query(
        {"title": "lateral movement", "description": "rdp then powershell"},
        {"time_range_hours": 24},
    )
    assert "lateral movement" in q.query_text
