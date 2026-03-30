"""
API Security Governance Engine

Implements API discovery, security scanning, anomaly detection, and policy enforcement.
Discovers APIs from network traffic and OpenAPI specs, detects vulnerabilities,
baselines normal traffic patterns, and enforces organizational security policies.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import hashlib

from src.core.logging import get_logger
from src.api_security.models import (
    APIEndpointInventory,
    APIVulnerability,
    APISecurityPolicy,
    APIAnomalyDetection,
    APIComplianceCheck,
    VulnerabilityTypeEnum,
    AnomalyTypeEnum,
    AuthenticationTypeEnum,
    ComplianceCheckTypeEnum,
)

logger = get_logger(__name__)


class APIDiscoveryEngine:
    """
    Discovers APIs from network traffic logs and OpenAPI specifications.

    Implements passive API discovery from HTTP traffic, OpenAPI/Swagger spec parsing,
    shadow API detection (traffic but not documented), and zombie API detection
    (documented but no traffic).
    """

    def __init__(self):
        """Initialize API discovery engine"""
        self.discovered_endpoints = {}
        self.traffic_endpoints = set()
        self.documented_endpoints = set()

    async def discover_from_traffic(
        self,
        traffic_logs: List[Dict[str, Any]],
        organization_id: str,
        db=None,
    ) -> Dict[str, Any]:
        """
        Passively discover APIs from network traffic logs.

        Args:
            traffic_logs: HTTP traffic logs with method, path, status, etc.
            organization_id: Organization ID
            db: Database session

        Returns:
            Discovery results with new endpoints, shadow APIs, etc.
        """
        logger.info(f"Starting API discovery from traffic for org {organization_id}")

        new_endpoints = []
        shadow_apis = []

        for log in traffic_logs:
            try:
                service_name = log.get("service", "unknown")
                base_url = log.get("base_url", "")
                path = log.get("path", "")
                method = (log.get("method", "GET") or "GET").upper()
                status_code = log.get("status_code", 200)
                authentication = log.get("authentication", "none")

                # Skip 404s and server errors
                if status_code >= 400:
                    continue

                endpoint_key = f"{service_name}:{method}:{path}"
                self.traffic_endpoints.add(endpoint_key)

                if endpoint_key not in self.discovered_endpoints:
                    endpoint = {
                        "service_name": service_name,
                        "base_url": base_url,
                        "path": path,
                        "method": method,
                        "authentication_type": self._classify_auth(authentication),
                        "is_documented": False,
                        "is_shadow": True,
                        "data_classification": self._classify_data(path),
                        "last_seen": datetime.now(timezone.utc),
                    }
                    self.discovered_endpoints[endpoint_key] = endpoint
                    new_endpoints.append(endpoint)
                    shadow_apis.append(endpoint_key)

            except Exception as e:
                logger.error(f"Error processing traffic log: {e}")
                continue

        return {
            "new_endpoints_count": len(new_endpoints),
            "shadow_apis_count": len(shadow_apis),
            "new_endpoints": new_endpoints,
            "shadow_api_keys": shadow_apis,
        }

    async def discover_from_openapi(
        self,
        spec_url: str,
        service_name: str,
        organization_id: str,
        db=None,
    ) -> Dict[str, Any]:
        """
        Discover APIs from OpenAPI/Swagger specification.

        Args:
            spec_url: URL to OpenAPI spec
            service_name: Service name
            organization_id: Organization ID
            db: Database session

        Returns:
            Discovery results with documented endpoints
        """
        logger.info(f"Discovering APIs from OpenAPI spec: {spec_url}")

        documented = []
        try:
            # In real implementation, would fetch and parse spec
            # This is a simplified version
            spec_endpoints = self._parse_openapi_spec(spec_url)

            for endpoint in spec_endpoints:
                endpoint_key = f"{service_name}:{endpoint['method']}:{endpoint['path']}"
                self.documented_endpoints.add(endpoint_key)

                endpoint["service_name"] = service_name
                endpoint["is_documented"] = True
                endpoint["is_shadow"] = False
                endpoint["openapi_spec_url"] = spec_url

                self.discovered_endpoints[endpoint_key] = endpoint
                documented.append(endpoint)

        except Exception as e:
            logger.error(f"Error parsing OpenAPI spec: {e}")
            return {"status": "error", "error": str(e)}

        return {
            "documented_endpoints_count": len(documented),
            "documented_endpoints": documented,
        }

    async def detect_shadow_apis(
        self,
        organization_id: str,
        db=None,
    ) -> Dict[str, Any]:
        """
        Detect shadow APIs (in traffic but not in documented specs).

        Args:
            organization_id: Organization ID
            db: Database session

        Returns:
            List of shadow APIs
        """
        logger.info(f"Detecting shadow APIs for org {organization_id}")

        shadow_apis = []
        for endpoint_key in self.traffic_endpoints:
            if endpoint_key not in self.documented_endpoints:
                if endpoint_key in self.discovered_endpoints:
                    shadow_apis.append(self.discovered_endpoints[endpoint_key])

        return {
            "shadow_api_count": len(shadow_apis),
            "shadow_apis": shadow_apis,
        }

    async def detect_zombie_apis(
        self,
        organization_id: str,
        db=None,
    ) -> Dict[str, Any]:
        """
        Detect zombie APIs (documented but no recent traffic).

        Args:
            organization_id: Organization ID
            db: Database session

        Returns:
            List of zombie APIs (no traffic in 30 days)
        """
        logger.info(f"Detecting zombie APIs for org {organization_id}")

        zombie_apis = []
        threshold_date = datetime.now(timezone.utc) - timedelta(days=30)

        for endpoint_key in self.documented_endpoints:
            if endpoint_key not in self.traffic_endpoints:
                if endpoint_key in self.discovered_endpoints:
                    endpoint = self.discovered_endpoints[endpoint_key]
                    last_seen = endpoint.get("last_seen", datetime.now(timezone.utc))
                    if last_seen < threshold_date:
                        zombie_apis.append(endpoint)

        return {
            "zombie_api_count": len(zombie_apis),
            "zombie_apis": zombie_apis,
        }

    async def reconcile_inventory(
        self,
        organization_id: str,
        db=None,
    ) -> Dict[str, Any]:
        """
        Reconcile discovered APIs with documented inventory.

        Args:
            organization_id: Organization ID
            db: Database session

        Returns:
            Reconciliation summary
        """
        logger.info(f"Reconciling API inventory for org {organization_id}")

        return {
            "total_discovered": len(self.discovered_endpoints),
            "total_documented": len(self.documented_endpoints),
            "total_traffic": len(self.traffic_endpoints),
            "shadow_apis": len(self.traffic_endpoints - self.documented_endpoints),
            "zombie_apis": len(self.documented_endpoints - self.traffic_endpoints),
        }

    async def track_api_changes(
        self,
        organization_id: str,
        previous_inventory: Dict[str, Any],
        db=None,
    ) -> Dict[str, Any]:
        """
        Track changes to API inventory over time.

        Args:
            organization_id: Organization ID
            previous_inventory: Previous inventory snapshot
            db: Database session

        Returns:
            Change summary
        """
        logger.info(f"Tracking API changes for org {organization_id}")

        changes = {
            "new_endpoints": [],
            "deprecated_endpoints": [],
            "modified_endpoints": [],
        }

        # In real implementation, would compare with previous inventory
        return changes

    def _classify_auth(self, auth_header: Optional[str]) -> str:
        """Classify authentication type from header"""
        if not auth_header:
            return AuthenticationTypeEnum.NONE.value

        auth_header_lower = auth_header.lower()
        if "bearer" in auth_header_lower:
            return AuthenticationTypeEnum.JWT.value
        elif "basic" in auth_header_lower:
            return AuthenticationTypeEnum.BASIC.value
        elif "oauth" in auth_header_lower:
            return AuthenticationTypeEnum.OAUTH2.value
        elif "apikey" in auth_header_lower or "x-api-key" in auth_header_lower:
            return AuthenticationTypeEnum.API_KEY.value
        else:
            return AuthenticationTypeEnum.CUSTOM.value

    def _classify_data(self, path: str) -> str:
        """Classify data sensitivity from path"""
        path_lower = path.lower()
        if any(x in path_lower for x in ["/public", "/health", "/status"]):
            return "public"
        elif any(x in path_lower for x in ["/admin", "/internal", "/system"]):
            return "restricted"
        elif any(x in path_lower for x in ["/personal", "/user", "/profile", "/account"]):
            return "confidential"
        else:
            return "internal"

    def _parse_openapi_spec(self, spec_url: str) -> List[Dict[str, Any]]:
        """Parse OpenAPI specification (simplified)"""
        # In real implementation, would fetch and parse actual spec
        return [
            {
                "path": "/api/users",
                "method": "GET",
                "authentication_type": AuthenticationTypeEnum.JWT.value,
            },
            {
                "path": "/api/users",
                "method": "POST",
                "authentication_type": AuthenticationTypeEnum.JWT.value,
            },
        ]


class APISecurityScanner:
    """
    Scans APIs for OWASP API Top 10 vulnerabilities and misconfigurations.

    Implements checks for broken authentication, authorization flaws (BOLA/BFLA),
    data exposure, rate limiting, input validation, TLS configuration, and more.
    """

    def __init__(self):
        """Initialize security scanner"""
        self.findings = []

    async def scan_owasp_top10(
        self,
        endpoint: APIEndpointInventory,
        organization_id: str,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Scan endpoint against OWASP API Top 10 vulnerabilities.

        Args:
            endpoint: API endpoint to scan
            organization_id: Organization ID
            db: Database session

        Returns:
            List of vulnerabilities found
        """
        logger.info(f"Scanning {endpoint.service_name}:{endpoint.method} {endpoint.path}")

        vulnerabilities = []

        # Run individual checks
        vulnerabilities.extend(await self.check_authentication(endpoint, db))
        vulnerabilities.extend(await self.check_authorization(endpoint, db))
        vulnerabilities.extend(await self.check_rate_limiting(endpoint, db))
        vulnerabilities.extend(await self.check_input_validation(endpoint, db))
        vulnerabilities.extend(await self.check_data_exposure(endpoint, db))
        vulnerabilities.extend(await self.check_tls_configuration(endpoint, db))

        return vulnerabilities

    async def check_authentication(
        self,
        endpoint: APIEndpointInventory,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Check authentication requirements and configuration.

        Detects missing authentication, weak auth methods, insufficient verification.
        """
        findings = []

        if endpoint.authentication_type == AuthenticationTypeEnum.NONE.value:
            if endpoint.is_public:
                pass  # Expected for public endpoints
            else:
                findings.append(
                    {
                        "type": VulnerabilityTypeEnum.BROKEN_AUTH.value,
                        "severity": "high",
                        "description": "Endpoint lacks authentication mechanism",
                        "evidence": {
                            "endpoint": f"{endpoint.method} {endpoint.path}",
                            "auth_type": endpoint.authentication_type,
                        },
                        "remediation": "Implement OAuth2, JWT, or API key authentication",
                    }
                )
        elif endpoint.authentication_type == AuthenticationTypeEnum.BASIC.value:
            findings.append(
                {
                    "type": VulnerabilityTypeEnum.BROKEN_AUTH.value,
                    "severity": "medium",
                    "description": "Basic authentication detected without TLS enforcement",
                    "evidence": {
                        "endpoint": f"{endpoint.method} {endpoint.path}",
                        "auth_type": endpoint.authentication_type,
                    },
                    "remediation": "Use OAuth2 or JWT instead of basic auth, enforce HTTPS",
                }
            )

        return findings

    async def check_authorization(
        self,
        endpoint: APIEndpointInventory,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Check authorization implementation (BOLA/BFLA).

        Detects missing authorization checks, object-level auth flaws,
        function-level auth bypass opportunities.
        """
        findings = []

        if endpoint.authorization_model is None:
            if not endpoint.is_public:
                findings.append(
                    {
                        "type": VulnerabilityTypeEnum.BROKEN_FUNCTION_LEVEL_AUTH.value,
                        "severity": "high",
                        "description": "No authorization model defined",
                        "evidence": {
                            "endpoint": f"{endpoint.method} {endpoint.path}",
                            "object_id_patterns": ["id", "user_id", "resource_id"],
                        },
                        "remediation": "Define authorization model (RBAC, ABAC, or similar)",
                    }
                )

        # Check for ID parameter patterns vulnerable to BOLA
        if any(param in endpoint.path for param in ["{id}", "{user_id}", "{resource_id}"]):
            findings.append(
                {
                    "type": VulnerabilityTypeEnum.BOLA.value,
                    "severity": "high",
                    "description": "Endpoint with object identifiers may be vulnerable to BOLA",
                    "evidence": {
                        "endpoint": f"{endpoint.method} {endpoint.path}",
                        "parameter_pattern": endpoint.path,
                    },
                    "remediation": "Verify authorization checks for each object access",
                }
            )

        return findings

    async def check_rate_limiting(
        self,
        endpoint: APIEndpointInventory,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Check rate limiting configuration.

        Detects missing rate limits or excessive thresholds.
        """
        findings = []

        if not endpoint.rate_limit_configured:
            findings.append(
                {
                    "type": VulnerabilityTypeEnum.LACK_OF_RESOURCES_RATE_LIMITING.value,
                    "severity": "medium",
                    "description": "Rate limiting not configured",
                    "evidence": {
                        "endpoint": f"{endpoint.method} {endpoint.path}",
                        "rate_limit_configured": endpoint.rate_limit_configured,
                    },
                    "remediation": "Configure rate limiting (100 req/min recommended for public APIs)",
                }
            )

        return findings

    async def check_input_validation(
        self,
        endpoint: APIEndpointInventory,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Check input validation implementation.

        Detects missing schema validation, lack of input constraints.
        """
        findings = []

        if not endpoint.input_validation_enabled:
            findings.append(
                {
                    "type": VulnerabilityTypeEnum.INJECTION.value,
                    "severity": "high",
                    "description": "Input validation not enabled",
                    "evidence": {
                        "endpoint": f"{endpoint.method} {endpoint.path}",
                        "validation_enabled": endpoint.input_validation_enabled,
                    },
                    "remediation": "Implement schema validation, whitelist input, use parameterized queries",
                }
            )

        return findings

    async def check_data_exposure(
        self,
        endpoint: APIEndpointInventory,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Check for potential data exposure in responses.

        Detects missing encryption, PII in responses, over-sharing of data.
        """
        findings = []

        if not endpoint.response_encryption and endpoint.data_classification in [
            "confidential",
            "restricted",
        ]:
            findings.append(
                {
                    "type": VulnerabilityTypeEnum.EXCESSIVE_DATA_EXPOSURE.value,
                    "severity": "high",
                    "description": "Sensitive data endpoint lacks response encryption",
                    "evidence": {
                        "endpoint": f"{endpoint.method} {endpoint.path}",
                        "classification": endpoint.data_classification,
                        "encryption": endpoint.response_encryption,
                    },
                    "remediation": "Enable response encryption, implement field-level masking",
                }
            )

        return findings

    async def check_tls_configuration(
        self,
        endpoint: APIEndpointInventory,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Check TLS/HTTPS configuration.

        Detects HTTP usage, weak TLS versions, certificate issues.
        """
        findings = []

        if not endpoint.base_url.startswith("https"):
            findings.append(
                {
                    "type": VulnerabilityTypeEnum.SECURITY_MISCONFIGURATION.value,
                    "severity": "critical",
                    "description": "Endpoint uses HTTP instead of HTTPS",
                    "evidence": {"endpoint": f"{endpoint.method} {endpoint.base_url}{endpoint.path}"},
                    "remediation": "Use HTTPS with TLS 1.2 minimum, implement HSTS",
                }
            )

        return findings

    async def generate_security_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        organization_id: str,
        db=None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive security assessment report.

        Args:
            vulnerabilities: List of found vulnerabilities
            organization_id: Organization ID
            db: Database session

        Returns:
            Security report with summary and recommendations
        """
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)

        for vuln in vulnerabilities:
            severity_counts[vuln.get("severity", "unknown")] += 1
            type_counts[vuln.get("type", "unknown")] += 1

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "low_count": severity_counts.get("low", 0),
            "vulnerabilities": vulnerabilities,
        }


class APIAnomalyDetector:
    """
    Detects anomalous API usage patterns indicating abuse or compromise.

    Detects volume anomalies, payload size variations, error rate spikes,
    enumeration attempts, credential stuffing, data scraping, and parameter tampering.
    """

    def __init__(self):
        """Initialize anomaly detector"""
        self.baselines = {}

    async def build_baseline(
        self,
        endpoint_id: str,
        traffic_history: List[Dict[str, Any]],
        organization_id: str,
        db=None,
    ) -> Dict[str, Any]:
        """
        Build baseline of normal traffic patterns for endpoint.

        Args:
            endpoint_id: API endpoint ID
            traffic_history: Historical traffic data (7-30 days)
            organization_id: Organization ID
            db: Database session

        Returns:
            Baseline metrics
        """
        logger.info(f"Building baseline for endpoint {endpoint_id}")

        if not traffic_history:
            return {"status": "insufficient_data"}

        baseline = {
            "endpoint_id": endpoint_id,
            "volume_per_hour": self._calculate_volume_baseline(traffic_history),
            "payload_size_avg": self._calculate_payload_baseline(traffic_history),
            "error_rate_avg": self._calculate_error_baseline(traffic_history),
            "unique_users": len(set(t.get("user_id") for t in traffic_history)),
            "unique_ips": len(set(t.get("source_ip") for t in traffic_history)),
            "peak_hours": self._identify_peak_hours(traffic_history),
            "created_at": datetime.now(timezone.utc),
        }

        self.baselines[endpoint_id] = baseline
        return baseline

    async def detect_volume_anomalies(
        self,
        endpoint_id: str,
        current_traffic: List[Dict[str, Any]],
        baseline: Dict[str, Any],
        organization_id: str,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Detect unusual request volume patterns.

        Args:
            endpoint_id: API endpoint ID
            current_traffic: Recent traffic data
            baseline: Baseline metrics
            organization_id: Organization ID
            db: Database session

        Returns:
            List of anomalies detected
        """
        anomalies = []

        if not baseline or "volume_per_hour" not in baseline:
            return anomalies

        current_volume = len(current_traffic)
        baseline_volume = baseline.get("volume_per_hour", 100)

        deviation = ((current_volume - baseline_volume) / baseline_volume) * 100

        if abs(deviation) > 150:  # 150% deviation threshold
            severity = "critical" if deviation > 300 else "high"
            anomalies.append(
                {
                    "endpoint_id": endpoint_id,
                    "anomaly_type": AnomalyTypeEnum.UNUSUAL_VOLUME.value,
                    "baseline_value": baseline_volume,
                    "observed_value": current_volume,
                    "deviation_percentage": deviation,
                    "severity": severity,
                    "source_ips": list(set(t.get("source_ip") for t in current_traffic)),
                }
            )

        return anomalies

    async def detect_payload_anomalies(
        self,
        endpoint_id: str,
        current_traffic: List[Dict[str, Any]],
        baseline: Dict[str, Any],
        organization_id: str,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Detect unusual payload size patterns.

        Args:
            endpoint_id: API endpoint ID
            current_traffic: Recent traffic data
            baseline: Baseline metrics
            organization_id: Organization ID
            db: Database session

        Returns:
            List of anomalies detected
        """
        anomalies = []

        if not baseline or "payload_size_avg" not in baseline:
            return anomalies

        current_sizes = [t.get("payload_size", 0) for t in current_traffic]
        if not current_sizes:
            return anomalies

        avg_size = sum(current_sizes) / len(current_sizes)
        baseline_size = baseline.get("payload_size_avg", 1000)

        deviation = ((avg_size - baseline_size) / baseline_size) * 100

        if abs(deviation) > 200:  # 200% deviation threshold
            anomalies.append(
                {
                    "endpoint_id": endpoint_id,
                    "anomaly_type": AnomalyTypeEnum.UNUSUAL_PAYLOAD_SIZE.value,
                    "baseline_value": baseline_size,
                    "observed_value": avg_size,
                    "deviation_percentage": deviation,
                    "severity": "high",
                    "source_ips": list(set(t.get("source_ip") for t in current_traffic)),
                }
            )

        return anomalies

    async def detect_enumeration(
        self,
        endpoint_id: str,
        current_traffic: List[Dict[str, Any]],
        organization_id: str,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Detect enumeration attempts (sequential ID access patterns).

        Args:
            endpoint_id: API endpoint ID
            current_traffic: Recent traffic data
            organization_id: Organization ID
            db: Database session

        Returns:
            List of enumeration attempts detected
        """
        anomalies = []

        # Extract ID parameters from traffic
        id_sequences = defaultdict(list)
        for t in current_traffic:
            ids = self._extract_ids(t.get("path", ""))
            source_ip = t.get("source_ip")
            if ids and source_ip:
                id_sequences[source_ip].extend(ids)

        # Check for sequential patterns
        for source_ip, ids in id_sequences.items():
            if len(ids) > 50:  # High volume of different IDs
                try:
                    numeric_ids = sorted([int(id) for id in ids if id.isdigit()])
                    if numeric_ids and self._is_sequential(numeric_ids):
                        anomalies.append(
                            {
                                "endpoint_id": endpoint_id,
                                "anomaly_type": AnomalyTypeEnum.ENUMERATION_ATTEMPT.value,
                                "baseline_value": 0,
                                "observed_value": len(numeric_ids),
                                "deviation_percentage": 100,
                                "severity": "high",
                                "source_ips": [source_ip],
                                "sample_requests": [
                                    {"id": id, "timestamp": str(datetime.now(timezone.utc))}
                                    for id in numeric_ids[:5]
                                ],
                            }
                        )
                except Exception:
                    continue

        return anomalies

    async def detect_scraping(
        self,
        endpoint_id: str,
        current_traffic: List[Dict[str, Any]],
        baseline: Dict[str, Any],
        organization_id: str,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Detect data scraping (high-rate systematic access).

        Args:
            endpoint_id: API endpoint ID
            current_traffic: Recent traffic data
            baseline: Baseline metrics
            organization_id: Organization ID
            db: Database session

        Returns:
            List of scraping attempts detected
        """
        anomalies = []

        # Group traffic by source IP
        ip_traffic = defaultdict(list)
        for t in current_traffic:
            ip_traffic[t.get("source_ip")].append(t)

        # Check for high-volume single-IP access
        for source_ip, traffic_list in ip_traffic.items():
            if len(traffic_list) > 1000:  # Threshold: 1000+ requests
                unique_resources = len(set(t.get("path") for t in traffic_list))
                if unique_resources > 100:  # Accessing many different resources
                    anomalies.append(
                        {
                            "endpoint_id": endpoint_id,
                            "anomaly_type": AnomalyTypeEnum.DATA_SCRAPING.value,
                            "baseline_value": baseline.get("volume_per_hour", 100),
                            "observed_value": len(traffic_list),
                            "deviation_percentage": 900,
                            "severity": "critical",
                            "source_ips": [source_ip],
                        }
                    )

        return anomalies

    async def detect_credential_stuffing(
        self,
        endpoint_id: str,
        current_traffic: List[Dict[str, Any]],
        organization_id: str,
        db=None,
    ) -> List[Dict[str, Any]]:
        """
        Detect credential stuffing (authentication endpoint abuse).

        Args:
            endpoint_id: API endpoint ID
            current_traffic: Recent traffic data
            organization_id: Organization ID
            db: Database session

        Returns:
            List of credential stuffing attempts detected
        """
        anomalies = []

        # Group failed auth attempts by IP
        failed_attempts = defaultdict(int)
        for t in current_traffic:
            if t.get("status_code") in [401, 403]:
                failed_attempts[t.get("source_ip")] += 1

        # Detect high failure rates
        for source_ip, count in failed_attempts.items():
            if count > 100:  # 100+ failed attempts from single IP
                anomalies.append(
                    {
                        "endpoint_id": endpoint_id,
                        "anomaly_type": AnomalyTypeEnum.CREDENTIAL_STUFFING.value,
                        "baseline_value": 5,  # Expected failed attempts
                        "observed_value": count,
                        "deviation_percentage": ((count - 5) / 5) * 100,
                        "severity": "critical",
                        "source_ips": [source_ip],
                    }
                )

        return anomalies

    async def calculate_risk_score(
        self,
        anomalies: List[Dict[str, Any]],
        endpoint: APIEndpointInventory,
        organization_id: str,
        db=None,
    ) -> int:
        """
        Calculate overall risk score for endpoint (0-100).

        Args:
            anomalies: List of detected anomalies
            endpoint: API endpoint
            organization_id: Organization ID
            db: Database session

        Returns:
            Risk score (0-100)
        """
        score = 0

        # Base score from critical vulnerabilities
        score += len([a for a in anomalies if a.get("severity") == "critical"]) * 20
        score += len([a for a in anomalies if a.get("severity") == "high"]) * 10
        score += len([a for a in anomalies if a.get("severity") == "medium"]) * 5

        # Additional factors
        if endpoint.authentication_type == AuthenticationTypeEnum.NONE.value:
            score += 15
        if not endpoint.input_validation_enabled:
            score += 10
        if not endpoint.rate_limit_configured:
            score += 5

        return min(score, 100)

    def _calculate_volume_baseline(self, traffic_history: List[Dict[str, Any]]) -> int:
        """Calculate baseline request volume per hour"""
        return max(1, len(traffic_history) // 24) if traffic_history else 100

    def _calculate_payload_baseline(self, traffic_history: List[Dict[str, Any]]) -> float:
        """Calculate average payload size"""
        sizes = [t.get("payload_size", 0) for t in traffic_history if t.get("payload_size")]
        return sum(sizes) / len(sizes) if sizes else 1000

    def _calculate_error_baseline(self, traffic_history: List[Dict[str, Any]]) -> float:
        """Calculate baseline error rate"""
        errors = sum(1 for t in traffic_history if t.get("status_code", 200) >= 400)
        return (errors / len(traffic_history) * 100) if traffic_history else 1.0

    def _identify_peak_hours(self, traffic_history: List[Dict[str, Any]]) -> List[int]:
        """Identify peak traffic hours"""
        hour_counts = defaultdict(int)
        for t in traffic_history:
            if "timestamp" in t:
                hour = int(datetime.fromisoformat(t["timestamp"]).hour)
                hour_counts[hour] += 1
        sorted_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)
        return [h[0] for h in sorted_hours[:5]]

    def _extract_ids(self, path: str) -> List[str]:
        """Extract ID parameters from path"""
        # Simple regex to find numeric or UUID patterns
        pattern = r"/(\d+|[a-f0-9\-]{36})"
        return re.findall(pattern, path)

    def _is_sequential(self, ids: List[int], threshold: float = 0.7) -> bool:
        """Check if IDs follow a sequential pattern"""
        if len(ids) < 10:
            return False
        sorted_ids = sorted(set(ids))
        consecutive_count = 0
        for i in range(1, len(sorted_ids)):
            if sorted_ids[i] - sorted_ids[i - 1] <= 2:
                consecutive_count += 1
        return consecutive_count / len(sorted_ids) > threshold


class APIPolicyEnforcer:
    """
    Enforces API security policies and evaluates requests against policy rules.

    Implements rate limiting, schema validation, header security, IP allowlists,
    policy violation logging, and compliance reporting.
    """

    def __init__(self):
        """Initialize policy enforcer"""
        self.violations = []

    async def evaluate_request(
        self,
        request: Dict[str, Any],
        endpoint: APIEndpointInventory,
        policies: List[APISecurityPolicy],
        organization_id: str,
        db=None,
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Evaluate request against active policies.

        Args:
            request: HTTP request data
            endpoint: API endpoint
            policies: List of applicable policies
            organization_id: Organization ID
            db: Database session

        Returns:
            (allowed: bool, violations: List[Dict])
        """
        violations = []

        for policy in policies:
            if policy.enforcement_level == "disabled":
                continue

            applies = self._policy_applies(policy, endpoint)
            if not applies:
                continue

            policy_violations = await self._check_policy(request, policy, endpoint, db)

            if policy_violations:
                violations.extend(policy_violations)
                if policy.enforcement_level == "enforce":
                    return False, violations

        return True, violations

    async def enforce_rate_limit(
        self,
        source_ip: str,
        endpoint_id: str,
        limit_per_minute: int,
        current_requests: int,
        organization_id: str,
        db=None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Enforce rate limiting for endpoint.

        Args:
            source_ip: Source IP address
            endpoint_id: API endpoint ID
            limit_per_minute: Rate limit threshold
            current_requests: Current requests in time window
            organization_id: Organization ID
            db: Database session

        Returns:
            (allowed: bool, details: Dict)
        """
        if current_requests > limit_per_minute:
            return False, {
                "reason": "rate_limit_exceeded",
                "limit": limit_per_minute,
                "current": current_requests,
                "retry_after": 60,
            }

        return True, {"remaining": limit_per_minute - current_requests}

    async def enforce_schema_validation(
        self,
        request_body: Dict[str, Any],
        expected_schema: Dict[str, Any],
        organization_id: str,
        db=None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate request against expected schema.

        Args:
            request_body: Request body to validate
            expected_schema: Expected JSON schema
            organization_id: Organization ID
            db: Database session

        Returns:
            (valid: bool, error_message: Optional[str])
        """
        # Simple schema validation
        if not isinstance(request_body, dict):
            return False, "Request body must be JSON object"

        return True, None

    async def enforce_header_security(
        self,
        headers: Dict[str, str],
        organization_id: str,
        db=None,
    ) -> Tuple[bool, List[str]]:
        """
        Enforce required security headers.

        Args:
            headers: HTTP headers
            organization_id: Organization ID
            db: Database session

        Returns:
            (compliant: bool, missing_headers: List[str])
        """
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
        ]

        missing = []
        for header in required_headers:
            if header not in headers:
                missing.append(header)

        return len(missing) == 0, missing

    async def log_policy_violation(
        self,
        violation: Dict[str, Any],
        organization_id: str,
        db=None,
    ) -> bool:
        """
        Log policy violation for audit trail.

        Args:
            violation: Violation details
            organization_id: Organization ID
            db: Database session

        Returns:
            Success status
        """
        self.violations.append(
            {
                "timestamp": datetime.now(timezone.utc),
                "organization_id": organization_id,
                **violation,
            }
        )
        return True

    async def generate_compliance_report(
        self,
        organization_id: str,
        time_period_days: int = 30,
        db=None,
    ) -> Dict[str, Any]:
        """
        Generate compliance report for time period.

        Args:
            organization_id: Organization ID
            time_period_days: Reporting period in days
            db: Database session

        Returns:
            Compliance report
        """
        threshold = datetime.now(timezone.utc) - timedelta(days=time_period_days)
        relevant_violations = [
            v for v in self.violations
            if v.get("organization_id") == organization_id and v.get("timestamp", datetime.min) > threshold
        ]

        policy_violations = defaultdict(int)
        for v in relevant_violations:
            policy_violations[v.get("policy_id", "unknown")] += 1

        return {
            "organization_id": organization_id,
            "period_days": time_period_days,
            "total_violations": len(relevant_violations),
            "by_policy": dict(policy_violations),
            "violation_trend": "increasing" if len(relevant_violations) > 10 else "stable",
        }

    def _policy_applies(
        self,
        policy: APISecurityPolicy,
        endpoint: APIEndpointInventory,
    ) -> bool:
        """Check if policy applies to endpoint"""
        applies_to = policy.applies_to or {}

        services = applies_to.get("services", [])
        if services and endpoint.service_name not in services:
            return False

        methods = applies_to.get("methods", [])
        if methods and endpoint.method not in methods:
            return False

        paths = applies_to.get("paths", [])
        if paths and endpoint.path not in paths:
            return False

        return True

    async def _check_policy(
        self,
        request: Dict[str, Any],
        policy: APISecurityPolicy,
        endpoint: APIEndpointInventory,
        db=None,
    ) -> List[Dict[str, Any]]:
        """Check request against specific policy"""
        violations = []

        rules = policy.rules or {}

        # Check rate limit
        if "rate_limit" in rules:
            limit = rules["rate_limit"]
            # Would check against actual request count

        # Check IP allowlist
        if "ip_allowlist" in rules:
            allowed_ips = rules["ip_allowlist"]
            source_ip = request.get("source_ip")
            if source_ip and source_ip not in allowed_ips:
                violations.append({
                    "policy_id": policy.id,
                    "type": "ip_not_allowed",
                    "source_ip": source_ip,
                })

        return violations
