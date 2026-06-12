"""Hunt finding scoring — evidence-driven, not constants.

Audit gap #13: score_finding returned fixed values per finding type
(lateral_movement=0.85, frequency=0.70 …) regardless of how strong the
evidence actually was. A hostname seen 6 times scored identically to one
seen 600 times. Now the type provides a prior and the evidence magnitude
(relative to the analyzer's own threshold) scales it.
"""

from src.hunting.engine import HuntAnalyzer


def _score(finding):
    return HuntAnalyzer.score_finding(finding)


def test_frequency_score_scales_with_magnitude():
    at_threshold = _score({
        "type": "frequency_anomaly",
        "evidence": [{"type": "frequency", "value": 5, "threshold": 5}],
    })
    way_over = _score({
        "type": "frequency_anomaly",
        "evidence": [{"type": "frequency", "value": 50, "threshold": 5}],
    })
    assert way_over > at_threshold


def test_rarer_values_score_higher():
    seen_once = _score({
        "type": "rare_value",
        "evidence": [{"type": "rare_value", "value": 1, "max_occurrences": 3}],
    })
    seen_thrice = _score({
        "type": "rare_value",
        "evidence": [{"type": "rare_value", "value": 3, "max_occurrences": 3}],
    })
    assert seen_once > seen_thrice


def test_lateral_movement_scales_with_host_count():
    two_hosts = _score({
        "type": "lateral_movement",
        "evidence": [{"type": "lateral_movement", "user": "u", "host_count": 2}],
    })
    eight_hosts = _score({
        "type": "lateral_movement",
        "evidence": [{"type": "lateral_movement", "user": "u", "host_count": 8}],
    })
    assert eight_hosts > two_hosts


def test_data_volume_scales_with_bytes():
    small = _score({
        "type": "large_transfer",
        "evidence": [{"type": "data_volume", "bytes": 1_000_000, "threshold": 1_000_000}],
    })
    huge = _score({
        "type": "large_transfer",
        "evidence": [{"type": "data_volume", "bytes": 500_000_000, "threshold": 1_000_000}],
    })
    assert huge > small


def test_type_priors_still_rank_lateral_above_rare():
    lateral = _score({
        "type": "lateral_movement",
        "evidence": [{"type": "lateral_movement", "user": "u", "host_count": 4}],
    })
    rare = _score({
        "type": "rare_value",
        "evidence": [{"type": "rare_value", "value": 2, "max_occurrences": 3}],
    })
    assert lateral > rare


def test_corroboration_bumps_score():
    single = _score({
        "type": "frequency_anomaly",
        "evidence": [{"type": "frequency", "value": 10, "threshold": 5}],
    })
    corroborated = _score({
        "type": "frequency_anomaly",
        "evidence": [
            {"type": "frequency", "value": 10, "threshold": 5},
            {"type": "cluster_size", "value": 8, "threshold": 5},
            {"type": "rare_value", "value": 1, "max_occurrences": 3},
        ],
    })
    assert corroborated > single


def test_scores_bounded_and_legacy_evidence_safe():
    for finding in (
        {"type": "frequency_anomaly", "evidence": [{"type": "frequency", "value": 10_000, "threshold": 1}]},
        {"type": "rare_value", "evidence": [{"type": "rare_value", "value": 1}]},  # no max_occurrences
        {"type": "unknown_kind", "evidence": []},
        {"type": "time_cluster"},  # no evidence key at all
    ):
        s = _score(finding)
        assert 0.0 <= s <= 1.0


def test_analyzers_attach_thresholds_to_evidence():
    items = [{"hostname": "h1"}] * 6
    findings = HuntAnalyzer.analyze_frequency(items, "hostname", 5)
    assert findings and findings[0]["evidence"][0]["threshold"] == 5

    items = [{"username": "alice"}]
    findings = HuntAnalyzer.analyze_rare_values(items, "username", 2)
    assert findings and findings[0]["evidence"][0]["max_occurrences"] == 2
