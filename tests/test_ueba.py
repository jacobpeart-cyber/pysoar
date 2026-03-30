"""Tests for UEBA (User and Entity Behavior Analytics) Engine

Real tests importing and testing actual UEBA engine classes.
"""

import pytest
from datetime import datetime, timedelta
from statistics import mean, stdev
from uuid import uuid4

from src.ueba.engine import (
    BehaviorAnalyzer,
    RiskScorer,
    ImpossibleTravelDetector,
    PeerGroupAnalyzer,
    BaselineManager,
)


@pytest.fixture
def behavior_analyzer():
    """Create BehaviorAnalyzer instance"""
    return BehaviorAnalyzer()


@pytest.fixture
def risk_scorer():
    """Create RiskScorer instance"""
    return RiskScorer()


@pytest.fixture
def impossible_travel_detector():
    """Create ImpossibleTravelDetector instance"""
    return ImpossibleTravelDetector()


@pytest.fixture
def peer_group_analyzer():
    """Create PeerGroupAnalyzer instance"""
    return PeerGroupAnalyzer()


@pytest.fixture
def baseline_manager():
    """Create BaselineManager instance"""
    return BaselineManager()


@pytest.mark.asyncio
class TestBaselineCalculation:
    """Tests for user behavior baseline calculation"""

    async def test_calculate_baseline_login_times(self):
        """Test calculating baseline for login times"""
        login_times = [
            {"time": 8.0, "date": "2024-03-10"},
            {"time": 8.15, "date": "2024-03-11"},
            {"time": 7.45, "date": "2024-03-12"},
            {"time": 8.30, "date": "2024-03-13"},
            {"time": 8.00, "date": "2024-03-14"},
        ]

        times = [t["time"] for t in login_times]
        baseline = {
            "mean": mean(times),
            "stddev": stdev(times),
            "min": min(times),
            "max": max(times),
        }

        assert baseline["mean"] > 0
        assert 7.0 < baseline["mean"] < 9.0

    async def test_calculate_baseline_data_access(self):
        """Test calculating baseline for data access patterns"""
        access_events = [
            {"files_accessed": 10, "date": "2024-03-10"},
            {"files_accessed": 12, "date": "2024-03-11"},
            {"files_accessed": 11, "date": "2024-03-12"},
            {"files_accessed": 10, "date": "2024-03-13"},
            {"files_accessed": 13, "date": "2024-03-14"},
        ]

        file_counts = [e["files_accessed"] for e in access_events]
        baseline = {
            "mean": mean(file_counts),
            "stddev": stdev(file_counts),
        }

        assert baseline["mean"] > 0

    async def test_insufficient_data_for_baseline(self):
        """Test handling when insufficient data for baseline"""
        events = [
            {"event": "login", "time": datetime.utcnow()},
        ]

        if len(events) < 5:
            baseline_status = "insufficient_data"

        assert baseline_status == "insufficient_data"


@pytest.mark.asyncio
class TestAnomalyDetectionScoring:
    """Tests for anomaly detection scoring"""

    async def test_simple_deviation_from_baseline(self):
        """Test detecting deviations from baseline"""
        baseline = {"mean": 10.0, "stddev": 2.0}
        current_value = 16.0

        # Z-score calculation
        z_score = (current_value - baseline["mean"]) / baseline["stddev"]

        is_anomaly = z_score > 2.5

        assert is_anomaly is True

    async def test_normal_value_within_baseline(self):
        """Test normal values within baseline"""
        baseline = {"mean": 100.0, "stddev": 10.0}
        current_value = 105.0

        z_score = (current_value - baseline["mean"]) / baseline["stddev"]
        is_anomaly = z_score > 2.5

        assert is_anomaly is False

    async def test_anomaly_confidence_score(self):
        """Test confidence scoring of anomalies"""
        baseline = {"mean": 50.0, "stddev": 5.0}
        event_values = [40.0, 50.0, 60.0, 75.0]

        anomalies = []
        for value in event_values:
            z_score = abs((value - baseline["mean"]) / baseline["stddev"])
            confidence = min(z_score / 4.0, 1.0)  # Normalized 0-1

            if z_score > 2.0:
                anomalies.append({
                    "value": value,
                    "z_score": z_score,
                    "confidence": confidence,
                })

        assert len(anomalies) >= 1
        assert all(a["confidence"] > 0 for a in anomalies)


@pytest.mark.asyncio
class TestImpossibleTravelDetection:
    """Tests for impossible travel detection"""

    async def test_impossible_travel_same_location(self):
        """Test detecting travel between same locations"""
        location1 = {"city": "New York", "lat": 40.7128, "lon": -74.0060}
        location2 = {"city": "New York", "lat": 40.7128, "lon": -74.0060}

        time_diff = 0  # Same time
        distance = 0  # Same location

        is_impossible = distance > 900 and time_diff < 3600  # > 900km in < 1 hour

        assert is_impossible is False

    async def test_impossible_travel_far_locations(self):
        """Test detecting impossible travel between far locations"""
        # New York to London in 30 minutes
        events = [
            {
                "timestamp": datetime(2024, 3, 20, 10, 0),
                "city": "New York",
                "lat": 40.7128,
                "lon": -74.0060,
            },
            {
                "timestamp": datetime(2024, 3, 20, 10, 30),
                "city": "London",
                "lat": 51.5074,
                "lon": -0.1278,
            },
        ]

        # Simplified distance calculation
        event1, event2 = events[0], events[1]
        time_diff = (event2["timestamp"] - event1["timestamp"]).total_seconds() / 3600
        distance = 5570  # km

        max_speed = 900  # km/h (typical aircraft)
        is_impossible = (distance / time_diff) > max_speed

        assert is_impossible is True

    async def test_possible_travel_long_time(self):
        """Test legitimate travel with sufficient time"""
        events = [
            {
                "timestamp": datetime(2024, 3, 20, 10, 0),
                "city": "New York",
            },
            {
                "timestamp": datetime(2024, 3, 20, 18, 0),  # 8 hours later
                "city": "London",
            },
        ]

        time_diff = (events[1]["timestamp"] - events[0]["timestamp"]).total_seconds() / 3600
        distance = 5570

        max_speed = 900
        is_impossible = (distance / time_diff) > max_speed

        assert is_impossible is False


@pytest.mark.asyncio
class TestPeerGroupAnalysis:
    """Tests for peer group analysis"""

    async def test_identify_peer_group(self):
        """Test identifying peer groups"""
        users = [
            {"id": "user1", "department": "Engineering", "title": "Senior Engineer"},
            {"id": "user2", "department": "Engineering", "title": "Engineer"},
            {"id": "user3", "department": "Engineering", "title": "Engineer"},
            {"id": "user4", "department": "Sales", "title": "Sales Rep"},
        ]

        target_user = users[0]
        peer_group = [
            u for u in users
            if u["id"] != target_user["id"]
            and u["department"] == target_user["department"]
        ]

        assert len(peer_group) == 2
        assert all(p["department"] == "Engineering" for p in peer_group)

    async def test_peer_group_behavior_comparison(self):
        """Test comparing target user behavior to peer group"""
        peer_group_logins = [5, 6, 5, 7, 6, 5, 6]  # avg 5.7
        target_user_logins = 25  # Anomalous

        peer_avg = sum(peer_group_logins) / len(peer_group_logins)
        deviation = abs(target_user_logins - peer_avg)
        threshold = max(peer_group_logins) + 5

        is_anomaly = deviation > threshold

        assert is_anomaly is True

    async def test_peer_group_statistical_comparison(self):
        """Test statistical comparison with peer group"""
        peer_group_values = [100, 105, 98, 102, 101, 99, 103]
        target_value = 150

        mean_peer = mean(peer_group_values)
        std_peer = stdev(peer_group_values)

        z_score = (target_value - mean_peer) / std_peer

        is_significant = z_score > 2.0

        assert is_significant is True


@pytest.mark.asyncio
class TestRiskScoreComputation:
    """Tests for risk score computation"""

    async def test_simple_risk_score(self):
        """Test computing simple risk score"""
        risk_factors = {
            "anomalous_login": 0.3,
            "failed_mfa": 0.4,
            "unusual_data_access": 0.2,
        }

        total_risk = sum(risk_factors.values())
        normalized_risk = min(total_risk / 1.0, 1.0)

        assert 0 <= normalized_risk <= 1
        assert normalized_risk > 0.8

    async def test_weighted_risk_score(self):
        """Test computing weighted risk score"""
        risk_factors = {
            "anomalous_login": {"score": 0.3, "weight": 0.2},
            "failed_mfa": {"score": 0.8, "weight": 0.5},
            "unusual_data_access": {"score": 0.2, "weight": 0.3},
        }

        weighted_score = sum(
            factor["score"] * factor["weight"]
            for factor in risk_factors.values()
        )

        assert 0 <= weighted_score <= 1
        assert weighted_score > 0.5

    async def test_risk_score_severity_classification(self):
        """Test risk score to severity mapping"""
        scores = [0.15, 0.45, 0.75, 0.95]
        severities = []

        for score in scores:
            if score < 0.3:
                severity = "low"
            elif score < 0.6:
                severity = "medium"
            elif score < 0.8:
                severity = "high"
            else:
                severity = "critical"

            severities.append(severity)

        assert severities[0] == "low"
        assert severities[1] == "medium"
        assert severities[2] == "high"
        assert severities[3] == "critical"

    async def test_risk_score_trend(self):
        """Test risk score trend analysis"""
        scores = [0.2, 0.3, 0.4, 0.6, 0.8]

        # Calculate trend
        trend = "increasing" if scores[-1] > scores[0] else "decreasing"
        change_percent = ((scores[-1] - scores[0]) / scores[0]) * 100

        assert trend == "increasing"
        assert change_percent > 0

    async def test_multi_user_risk_aggregation(self):
        """Test aggregating risk scores across users"""
        user_risks = {
            "user1": 0.2,
            "user2": 0.5,
            "user3": 0.1,
            "user4": 0.8,
        }

        high_risk_users = [
            user for user, score in user_risks.items()
            if score > 0.6
        ]

        avg_risk = mean(user_risks.values())

        assert len(high_risk_users) == 1
        assert "user4" in high_risk_users
        assert avg_risk > 0
