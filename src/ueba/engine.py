"""
UEBA Analytics Engine
Core algorithms for behavior analysis, anomaly detection, and risk scoring.
"""

import math
from datetime import datetime, timedelta
from typing import Any, Optional, Tuple
from statistics import mean, stdev, median, quantiles

from src.core.logging import get_logger
from src.core.config import settings

logger = get_logger(__name__)


class BehaviorAnalyzer:
    """
    Analyzes various types of entity behavior for anomalies.
    """

    def __init__(self, baseline_manager: "BaselineManager"):
        self.baseline_manager = baseline_manager
        self.deviation_threshold = 3.0  # Standard deviations

    def analyze_authentication(self, entity_id: str, auth_event: dict) -> dict:
        """
        Analyze authentication event for anomalies.

        Args:
            entity_id: ID of the entity
            auth_event: Authentication event data

        Returns:
            Dictionary with analysis results and anomaly scores
        """
        anomalies = []
        risk_score = 0.0

        auth_time = auth_event.get("timestamp")
        auth_hour = datetime.fromisoformat(auth_time).hour if auth_time else None

        # Check login time vs baseline
        baseline = self.baseline_manager.get_baseline(entity_id, "login_pattern")
        if baseline and auth_hour is not None:
            typical_hours = baseline.get("time_patterns", {}).get("typical_hours", [])
            if typical_hours and auth_hour not in typical_hours:
                anomalies.append({
                    "type": "unusual_login_time",
                    "description": f"Login at hour {auth_hour}, typical hours: {typical_hours}",
                    "severity": "medium"
                })
                risk_score += 10.0

        # Check source IP vs baseline
        source_ip = auth_event.get("source_ip")
        if source_ip and baseline:
            typical_ips = baseline.get("typical_values", [])
            if typical_ips and source_ip not in typical_ips:
                anomalies.append({
                    "type": "new_login_location",
                    "description": f"Login from new source IP: {source_ip}",
                    "severity": "low"
                })
                risk_score += 5.0

        # Check authentication method
        auth_method = auth_event.get("method")
        if auth_method and baseline:
            typical_methods = baseline.get("typical_values", [])
            if typical_methods and auth_method not in typical_methods:
                anomalies.append({
                    "type": "unusual_auth_method",
                    "description": f"Unusual authentication method: {auth_method}",
                    "severity": "low"
                })
                risk_score += 3.0

        # Check failed attempt frequency
        failed_attempts = auth_event.get("failed_attempts", 0)
        if failed_attempts > 5:
            anomalies.append({
                "type": "multiple_failed_attempts",
                "description": f"{failed_attempts} failed authentication attempts",
                "severity": "high"
            })
            risk_score += 15.0

        return {
            "is_anomalous": len(anomalies) > 0,
            "risk_score": risk_score,
            "anomalies": anomalies
        }

    def analyze_data_access(self, entity_id: str, access_event: dict) -> dict:
        """
        Analyze data access event for suspicious patterns.

        Args:
            entity_id: ID of the entity
            access_event: Data access event data

        Returns:
            Dictionary with analysis results
        """
        anomalies = []
        risk_score = 0.0

        # Volume analysis
        access_volume = access_event.get("file_count", 1)
        baseline = self.baseline_manager.get_baseline(entity_id, "data_access")

        if baseline:
            stats = baseline.get("statistical_model", {})
            mean_volume = stats.get("mean", 1)
            std_volume = stats.get("std", 1)

            if std_volume > 0:
                z_score = (access_volume - mean_volume) / std_volume
                if z_score > self.deviation_threshold:
                    anomalies.append({
                        "type": "unusual_data_volume",
                        "description": f"Accessed {access_volume} files (typical: {mean_volume:.1f})",
                        "severity": "medium"
                    })
                    risk_score += 12.0

        # Sensitivity level analysis
        sensitivity = access_event.get("sensitivity_level")
        if sensitivity and baseline:
            typical_sensitivity = baseline.get("typical_values", [])
            if sensitivity not in typical_sensitivity and sensitivity == "critical":
                anomalies.append({
                    "type": "sensitive_data_access",
                    "description": f"Access to {sensitivity} sensitivity data",
                    "severity": "high"
                })
                risk_score += 20.0

        # Bulk download detection
        if access_event.get("is_bulk_download"):
            anomalies.append({
                "type": "bulk_download",
                "description": "Bulk file download detected",
                "severity": "high"
            })
            risk_score += 25.0

        # Unusual file types
        file_types = access_event.get("file_types", [])
        if baseline:
            typical_types = baseline.get("typical_values", [])
            unusual_types = [ft for ft in file_types if ft not in typical_types]
            if unusual_types:
                anomalies.append({
                    "type": "unusual_file_types",
                    "description": f"Accessed unusual file types: {unusual_types}",
                    "severity": "low"
                })
                risk_score += 5.0

        return {
            "is_anomalous": len(anomalies) > 0,
            "risk_score": risk_score,
            "anomalies": anomalies
        }

    def analyze_network_activity(self, entity_id: str, network_event: dict) -> dict:
        """
        Analyze network activity for exfiltration and C2 patterns.

        Args:
            entity_id: ID of the entity
            network_event: Network activity event data

        Returns:
            Dictionary with analysis results
        """
        anomalies = []
        risk_score = 0.0

        # Destination analysis
        destination = network_event.get("destination_ip")
        baseline = self.baseline_manager.get_baseline(entity_id, "network_activity")

        if destination and baseline:
            typical_destinations = baseline.get("typical_values", [])
            if typical_destinations and destination not in typical_destinations:
                anomalies.append({
                    "type": "new_network_destination",
                    "description": f"Connection to new destination: {destination}",
                    "severity": "medium"
                })
                risk_score += 10.0

        # Volume analysis (potential exfiltration)
        bytes_transferred = network_event.get("bytes_transferred", 0)
        if baseline:
            stats = baseline.get("statistical_model", {})
            mean_volume = stats.get("mean", 0)
            std_volume = stats.get("std", 1)

            if std_volume > 0:
                z_score = (bytes_transferred - mean_volume) / std_volume
                if z_score > self.deviation_threshold:
                    anomalies.append({
                        "type": "unusual_data_volume",
                        "description": f"Transferred {bytes_transferred} bytes (typical: {mean_volume:.0f})",
                        "severity": "high"
                    })
                    risk_score += 20.0

        # Protocol analysis
        protocol = network_event.get("protocol")
        if protocol and baseline:
            typical_protocols = baseline.get("typical_values", [])
            if typical_protocols and protocol not in typical_protocols:
                anomalies.append({
                    "type": "unusual_protocol",
                    "description": f"Unusual protocol: {protocol}",
                    "severity": "low"
                })
                risk_score += 5.0

        # Port analysis
        dest_port = network_event.get("destination_port")
        if dest_port in [25, 587, 465]:  # SMTP ports
            anomalies.append({
                "type": "suspicious_port",
                "description": f"Connection to mail server port {dest_port}",
                "severity": "medium"
            })
            risk_score += 12.0

        return {
            "is_anomalous": len(anomalies) > 0,
            "risk_score": risk_score,
            "anomalies": anomalies
        }

    def analyze_privilege_usage(self, entity_id: str, privilege_event: dict) -> dict:
        """
        Analyze privilege escalation and admin actions.

        Args:
            entity_id: ID of the entity
            privilege_event: Privilege usage event data

        Returns:
            Dictionary with analysis results
        """
        anomalies = []
        risk_score = 0.0

        # Privilege escalation detection
        if privilege_event.get("is_escalation"):
            anomalies.append({
                "type": "privilege_escalation",
                "description": f"Escalated from {privilege_event.get('previous_privilege')} to {privilege_event.get('new_privilege')}",
                "severity": "high"
            })
            risk_score += 30.0

        # Service account misuse
        if privilege_event.get("is_service_account") and privilege_event.get("interactive_use"):
            anomalies.append({
                "type": "service_account_misuse",
                "description": "Service account used interactively",
                "severity": "critical"
            })
            risk_score += 40.0

        # Unusual admin action
        action_type = privilege_event.get("action_type")
        baseline = self.baseline_manager.get_baseline(entity_id, "privilege_usage")

        if action_type and baseline:
            typical_actions = baseline.get("typical_values", [])
            if typical_actions and action_type not in typical_actions:
                anomalies.append({
                    "type": "unusual_admin_action",
                    "description": f"Unusual administrative action: {action_type}",
                    "severity": "medium"
                })
                risk_score += 15.0

        # Privilege usage frequency
        if privilege_event.get("is_frequent_escalation"):
            anomalies.append({
                "type": "frequent_escalation",
                "description": "Multiple privilege escalations in short timeframe",
                "severity": "high"
            })
            risk_score += 20.0

        return {
            "is_anomalous": len(anomalies) > 0,
            "risk_score": risk_score,
            "anomalies": anomalies
        }


class RiskScorer:
    """
    Calculates and manages entity risk scores.
    """

    SEVERITY_WEIGHTS = {
        "critical": 40,
        "high": 20,
        "medium": 10,
        "low": 5
    }

    def __init__(self):
        self.risk_decay_days = 30
        self.risk_cap = 100.0

    def calculate_entity_risk(self, entity_id: str, alerts: list[dict], historical_risk: float = 0.0) -> float:
        """
        Calculate overall entity risk score using time decay and severity weighting.

        Args:
            entity_id: ID of the entity
            alerts: List of recent alerts for the entity
            historical_risk: Historical risk baseline

        Returns:
            Risk score (0-100)
        """
        current_risk = historical_risk * 0.3  # Weight historical risk at 30%

        for alert in alerts:
            severity = alert.get("severity", "low")
            weight = self.SEVERITY_WEIGHTS.get(severity, 5)

            # Apply time decay
            created_at = alert.get("created_at")
            if created_at:
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at)
                days_old = (datetime.utcnow() - created_at).days
                decay_factor = math.exp(-days_old / self.risk_decay_days)
            else:
                decay_factor = 1.0

            current_risk += weight * decay_factor

        # Cap risk at 100
        return min(current_risk, self.risk_cap)

    def update_risk_level(self, risk_score: float) -> str:
        """
        Map risk score to risk level.

        Args:
            risk_score: Numeric risk score (0-100)

        Returns:
            Risk level string
        """
        if risk_score >= 75:
            return "critical"
        elif risk_score >= 50:
            return "high"
        elif risk_score >= 25:
            return "medium"
        else:
            return "low"

    def get_risk_factors(self, entity_id: str, alerts: list[dict]) -> list[dict]:
        """
        Break down risk factors contributing to entity risk.

        Args:
            entity_id: ID of the entity
            alerts: List of alerts

        Returns:
            List of risk factor dictionaries
        """
        factors = []

        # Group by severity
        severity_counts = {}
        for alert in alerts:
            severity = alert.get("severity", "low")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity, count in severity_counts.items():
            weight = self.SEVERITY_WEIGHTS.get(severity, 5)
            factors.append({
                "factor": f"{severity}_alerts",
                "count": count,
                "contribution": weight * count
            })

        return sorted(factors, key=lambda x: x["contribution"], reverse=True)

    def get_risk_trend(self, entity_id: str, alerts: list[dict], days: int = 30) -> list[dict]:
        """
        Calculate daily risk score trend.

        Args:
            entity_id: ID of the entity
            alerts: List of alerts
            days: Number of days to include

        Returns:
            List of daily risk scores
        """
        daily_risks = {}

        # Initialize days
        for i in range(days):
            date = (datetime.utcnow() - timedelta(days=i)).date()
            daily_risks[date] = 0.0

        # Aggregate risks by day
        for alert in alerts:
            created_at = alert.get("created_at")
            if created_at:
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at)
                date = created_at.date()

                severity = alert.get("severity", "low")
                weight = self.SEVERITY_WEIGHTS.get(severity, 5)
                if date in daily_risks:
                    daily_risks[date] += weight

        # Convert to sorted list
        trend = [
            {
                "date": str(date),
                "risk_score": score
            }
            for date, score in sorted(daily_risks.items())
        ]

        return trend


class ImpossibleTravelDetector:
    """
    Detects impossible travel between two locations.
    """

    EARTH_RADIUS_KM = 6371
    MAX_HUMAN_SPEED_KMH = 900  # Fastest commercial aircraft

    def check_impossible_travel(
        self,
        entity_id: str,
        current_location: dict,
        current_time: datetime,
        last_location: dict,
        last_time: datetime
    ) -> Optional[dict]:
        """
        Check if travel between two locations is physically impossible.

        Args:
            entity_id: ID of the entity
            current_location: Current location dict with lat, lon
            current_time: Current timestamp
            last_location: Previous location dict with lat, lon
            last_time: Previous timestamp

        Returns:
            Alert dict if impossible travel detected, None otherwise
        """
        # Extract coordinates
        current_lat = current_location.get("latitude")
        current_lon = current_location.get("longitude")
        last_lat = last_location.get("latitude")
        last_lon = last_location.get("longitude")

        if not all([current_lat, current_lon, last_lat, last_lon]):
            return None

        # Calculate distance using Haversine formula
        distance = self._haversine_distance(
            last_lat, last_lon,
            current_lat, current_lon
        )

        # Calculate time elapsed
        time_diff = (current_time - last_time).total_seconds() / 3600  # hours
        if time_diff <= 0:
            return None

        # Calculate required speed
        required_speed = distance / time_diff

        # Check if impossible
        if required_speed > self.MAX_HUMAN_SPEED_KMH:
            return {
                "type": "impossible_travel",
                "description": f"Travel from {last_location.get('city')} to {current_location.get('city')} requires {required_speed:.1f} km/h (max possible: {self.MAX_HUMAN_SPEED_KMH})",
                "severity": "critical",
                "evidence": {
                    "distance_km": distance,
                    "time_hours": time_diff,
                    "required_speed_kmh": required_speed,
                    "from_location": last_location,
                    "to_location": current_location
                }
            }

        return None

    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate distance between two coordinates using Haversine formula.

        Returns:
            Distance in kilometers
        """
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)

        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad

        a = math.sin(dlat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
        c = 2 * math.asin(math.sqrt(a))

        return self.EARTH_RADIUS_KM * c


class PeerGroupAnalyzer:
    """
    Analyzes entity behavior relative to peer groups.
    """

    def __init__(self):
        self.min_cluster_size = 5

    def build_peer_groups(self, entities: list[dict], method: str = "department") -> list[dict]:
        """
        Build peer groups based on entity attributes.

        Args:
            entities: List of entity dictionaries
            method: Grouping method (department, role, custom)

        Returns:
            List of peer group dictionaries
        """
        groups = {}

        if method == "department":
            grouping_key = "department"
        elif method == "role":
            grouping_key = "role"
        else:
            grouping_key = "custom_group"

        for entity in entities:
            group_key = entity.get(grouping_key, "unassigned")
            if group_key not in groups:
                groups[group_key] = {
                    "name": group_key,
                    "members": [],
                    "member_count": 0
                }
            groups[group_key]["members"].append(entity["id"])
            groups[group_key]["member_count"] += 1

        return list(groups.values())

    def auto_cluster_peers(self, entities: list[dict], features: list[str]) -> list[dict]:
        """
        Automatically cluster peers using k-means-like approach.

        Args:
            entities: List of entity dictionaries
            features: Feature names to use for clustering

        Returns:
            List of auto-clustered peer groups
        """
        if len(entities) < self.min_cluster_size:
            return []

        clusters = []

        # Extract numeric and categorical features for distance computation
        numeric_features = []
        categorical_features = []
        for f in features:
            sample_vals = [entity.get(f) for entity in entities if entity.get(f) is not None]
            if sample_vals and isinstance(sample_vals[0], (int, float)):
                numeric_features.append(f)
            else:
                categorical_features.append(f)

        # Normalize numeric features for distance calculation
        feature_stats = {}
        for f in numeric_features:
            vals = [float(entity.get(f, 0)) for entity in entities]
            f_min = min(vals) if vals else 0
            f_max = max(vals) if vals else 1
            f_range = f_max - f_min if f_max != f_min else 1
            feature_stats[f] = {"min": f_min, "range": f_range}

        def compute_distance(e1: dict, e2: dict) -> float:
            """Compute normalized distance between two entities"""
            dist = 0.0
            count = 0
            # Numeric distance (normalized)
            for f in numeric_features:
                v1 = float(e1.get(f, 0))
                v2 = float(e2.get(f, 0))
                stats = feature_stats[f]
                norm_diff = abs(v1 - v2) / stats["range"] if stats["range"] > 0 else 0
                dist += norm_diff
                count += 1
            # Categorical distance (0 or 1)
            for f in categorical_features:
                v1 = e1.get(f, "unknown")
                v2 = e2.get(f, "unknown")
                dist += 0 if v1 == v2 else 1
                count += 1
            return dist / max(count, 1)

        # Agglomerative clustering with distance threshold
        distance_threshold = 0.3
        assigned = [False] * len(entities)
        cluster_idx = 0

        for i in range(len(entities)):
            if assigned[i]:
                continue
            # Start a new cluster with entity i
            cluster_members = [entities[i]["id"]]
            assigned[i] = True

            for j in range(i + 1, len(entities)):
                if assigned[j]:
                    continue
                dist = compute_distance(entities[i], entities[j])
                if dist <= distance_threshold:
                    cluster_members.append(entities[j]["id"])
                    assigned[j] = True

            if len(cluster_members) >= self.min_cluster_size:
                # Compute cluster centroid stats
                centroid = {}
                cluster_entities = [e for e in entities if e.get("id") in cluster_members]
                for f in numeric_features:
                    vals = [float(e.get(f, 0)) for e in cluster_entities]
                    centroid[f] = sum(vals) / len(vals) if vals else 0
                for f in categorical_features:
                    vals = [e.get(f, "unknown") for e in cluster_entities]
                    # Most common value
                    centroid[f] = max(set(vals), key=vals.count) if vals else "unknown"

                clusters.append({
                    "name": f"cluster_{cluster_idx}",
                    "members": cluster_members,
                    "member_count": len(cluster_members),
                    "centroid": centroid,
                })
                cluster_idx += 1

        return clusters

    def compare_to_peers(self, entity_id: str, entity_data: dict, peer_group: list[dict]) -> dict:
        """
        Compare entity behavior to peer group.

        Args:
            entity_id: ID of the entity
            entity_data: Entity data dictionary
            peer_group: List of peer entity data

        Returns:
            Dictionary with percentile rankings
        """
        comparisons = {}

        # Compare risk score
        entity_risk = entity_data.get("risk_score", 0)
        peer_risks = [e.get("risk_score", 0) for e in peer_group]

        if peer_risks:
            percentile = (sum(1 for r in peer_risks if r < entity_risk) / len(peer_risks)) * 100
            comparisons["risk_percentile"] = percentile

        # Compare activity levels
        entity_activity = entity_data.get("activity_count", 0)
        peer_activities = [e.get("activity_count", 0) for e in peer_group]

        if peer_activities:
            percentile = (sum(1 for a in peer_activities if a < entity_activity) / len(peer_activities)) * 100
            comparisons["activity_percentile"] = percentile

        return comparisons

    def detect_peer_deviation(self, entity_id: str, entity_data: dict, peer_group: list[dict]) -> list[dict]:
        """
        Detect behaviors that deviate from peer group norms.

        Args:
            entity_id: ID of the entity
            entity_data: Entity data dictionary
            peer_group: List of peer entity data

        Returns:
            List of deviation dictionaries
        """
        deviations = []

        if not peer_group or len(peer_group) < 2:
            return deviations

        # Risk score comparison
        entity_risk = entity_data.get("risk_score", 0)
        peer_risks = [e.get("risk_score", 0) for e in peer_group]

        if peer_risks:
            mean_risk = mean(peer_risks)
            if len(peer_risks) > 1:
                std_risk = stdev(peer_risks)
            else:
                std_risk = 0

            if std_risk > 0:
                z_score = (entity_risk - mean_risk) / std_risk
                if z_score > 2.5:  # More than 2.5 std devs above mean
                    deviations.append({
                        "type": "elevated_risk",
                        "description": f"Risk score {entity_risk:.1f} exceeds peer average {mean_risk:.1f}",
                        "z_score": z_score
                    })

        # Activity frequency comparison
        entity_activity = entity_data.get("activity_count", 0)
        peer_activities = [e.get("activity_count", 0) for e in peer_group]

        if peer_activities and len(peer_activities) > 1:
            mean_activity = mean(peer_activities)
            std_activity = stdev(peer_activities)

            if std_activity > 0:
                z_score = (entity_activity - mean_activity) / std_activity
                if z_score > 2.5:
                    deviations.append({
                        "type": "unusual_activity",
                        "description": f"Activity level {entity_activity} exceeds peer average {mean_activity:.1f}",
                        "z_score": z_score
                    })

        return deviations


class BaselineManager:
    """
    Manages behavior baselines for entities.
    """

    def __init__(self):
        self.min_samples = 10

    def build_baseline(
        self,
        entity_id: str,
        behavior_type: str,
        events: list[dict],
        lookback_days: int = 30
    ) -> dict:
        """
        Build baseline from historical events.

        Args:
            entity_id: ID of the entity
            behavior_type: Type of behavior to baseline
            events: Historical events
            lookback_days: Number of days to include

        Returns:
            Baseline dictionary with statistics
        """
        if len(events) < self.min_samples:
            return {"confidence": 0.0, "sample_count": len(events)}

        # Extract values based on behavior type
        if behavior_type == "login_pattern":
            values = [e.get("hour", 0) for e in events if "hour" in e]
        elif behavior_type == "data_access":
            values = [e.get("file_count", 0) for e in events if "file_count" in e]
        elif behavior_type == "network_activity":
            values = [e.get("bytes_transferred", 0) for e in events if "bytes_transferred" in e]
        else:
            values = [e.get("value", 0) for e in events]

        if not values:
            return {"confidence": 0.0, "sample_count": 0}

        stats = self.calculate_statistics(values)

        # Extract typical values
        typical_values = list(set([e.get("value") for e in events if "value" in e]))[:10]

        # Extract time patterns
        time_patterns = self._extract_time_patterns(events)

        # Calculate confidence based on sample count
        confidence = min(len(events) / 100, 1.0)

        return {
            "statistical_model": stats,
            "typical_values": typical_values,
            "time_patterns": time_patterns,
            "confidence": confidence,
            "sample_count": len(events),
            "behavior_type": behavior_type
        }

    def update_baseline(self, baseline: dict, new_event: dict) -> dict:
        """
        Incrementally update baseline with new event.

        Args:
            baseline: Current baseline dictionary
            new_event: New event data

        Returns:
            Updated baseline
        """
        baseline["sample_count"] = baseline.get("sample_count", 0) + 1
        baseline["confidence"] = min(baseline["sample_count"] / 100, 1.0)
        return baseline

    def get_baseline(self, entity_id: str, behavior_type: str, baseline_data: dict = None) -> Optional[dict]:
        """
        Get baseline for entity and behavior type.

        Args:
            entity_id: ID of the entity
            behavior_type: Type of behavior
            baseline_data: Entity's baseline data

        Returns:
            Baseline dictionary or None
        """
        if not baseline_data:
            return None

        return baseline_data.get(behavior_type, {})

    def is_anomalous(
        self,
        value: float,
        baseline: dict,
        threshold_sigma: float = 3.0
    ) -> Tuple[bool, float]:
        """
        Determine if value is anomalous relative to baseline.

        Args:
            value: Value to check
            baseline: Baseline statistics
            threshold_sigma: Standard deviation threshold

        Returns:
            Tuple of (is_anomalous, deviation_score)
        """
        if not baseline or "statistical_model" not in baseline:
            return False, 0.0

        stats = baseline["statistical_model"]
        mean_val = stats.get("mean", 0)
        std_val = stats.get("std", 1)

        if std_val == 0:
            return False, 0.0

        z_score = (value - mean_val) / std_val
        is_anomalous = abs(z_score) > threshold_sigma

        return is_anomalous, abs(z_score)

    def calculate_statistics(self, values: list[float]) -> dict:
        """
        Calculate statistical measures from values.

        Args:
            values: List of numeric values

        Returns:
            Dictionary with statistics
        """
        if not values:
            return {}

        sorted_vals = sorted(values)
        n = len(values)

        stats = {
            "count": n,
            "mean": mean(values),
            "median": median(values),
            "min": min(values),
            "max": max(values),
        }

        # Standard deviation
        if n > 1:
            stats["std"] = stdev(values)
        else:
            stats["std"] = 0

        # Quartiles
        if n >= 4:
            try:
                quarts = quantiles(values, n=4)
                stats["q1"] = quarts[0]
                stats["q2"] = quarts[1]
                stats["q3"] = quarts[2]
                stats["iqr"] = quarts[2] - quarts[0]
            except Exception:
                stats["q1"] = sorted_vals[n // 4]
                stats["q3"] = sorted_vals[3 * n // 4]
                stats["iqr"] = stats["q3"] - stats["q1"]

        return stats

    def _extract_time_patterns(self, events: list[dict]) -> dict:
        """
        Extract hourly, daily, and weekly patterns from events.

        Args:
            events: List of events

        Returns:
            Dictionary with time patterns
        """
        hourly_counts = {}
        daily_counts = {}

        for event in events:
            timestamp = event.get("timestamp")
            if timestamp:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp)
                else:
                    dt = timestamp

                hour = dt.hour
                day = dt.weekday()

                hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
                daily_counts[day] = daily_counts.get(day, 0) + 1

        # Get most common hours and days
        typical_hours = sorted(
            hourly_counts.keys(),
            key=lambda h: hourly_counts[h],
            reverse=True
        )[:5]

        typical_days = sorted(
            daily_counts.keys(),
            key=lambda d: daily_counts[d],
            reverse=True
        )[:3]

        return {
            "typical_hours": typical_hours,
            "typical_days": typical_days,
            "hourly_distribution": hourly_counts,
            "daily_distribution": daily_counts
        }
