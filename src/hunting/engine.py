"""Hunt execution engine for threat hunting investigations

Provides query building, execution, result analysis, and finding generation
for structured security investigations with MITRE ATT&CK framework integration.
"""

import json
import statistics
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from src.core.logging import get_logger
from src.hunting.models import (
    FindingClassification,
    FindingSeverity,
    HuntFinding,
    HuntSession,
    SessionStatus,
    HuntTemplate,
    TemplateDifficulty,
    HuntType,
)
from src.siem.search import SearchQuery, LogSearchService

logger = get_logger(__name__)


class HuntQueryBuilder:
    """Builds log search queries from hunt hypotheses and parameters"""

    # MITRE Technique to log field mapping
    MITRE_TECHNIQUE_PATTERNS = {
        "T1087": {
            "fields": ["message", "raw_log"],
            "patterns": ["account enumeration", "net user", "Get-ADUser"],
        },
        "T1110": {
            "fields": ["message"],
            "patterns": ["brute force", "failed logon", "login attempt"],
        },
        "T1021": {
            "fields": ["destination_ip", "hostname"],
            "patterns": ["remote access", "rdp", "ssh", "winrm"],
        },
        "T1041": {
            "fields": ["destination_ip", "message"],
            "patterns": ["exfiltration", "data transfer", "outbound"],
        },
        "T1566": {
            "fields": ["message"],
            "patterns": ["phishing", "email", "attachment", "suspicious link"],
        },
        "T1204": {
            "fields": ["message"],
            "patterns": ["user execution", "clicked", "ran", "executed"],
        },
        "T1086": {
            "fields": ["message"],
            "patterns": ["powershell", "script", "execution"],
        },
        "T1547": {
            "fields": ["message"],
            "patterns": ["persistence", "startup", "boot", "registry run"],
        },
    }

    def __init__(self):
        """Initialize query builder"""
        pass

    def build_log_query(self, hypothesis: dict, parameters: dict) -> SearchQuery:
        """Build a log search query from hypothesis details and runtime parameters

        Args:
            hypothesis: Dict with title, description, mitre_techniques, data_sources
            parameters: Runtime params like time_range, target_hosts, scope

        Returns:
            SearchQuery object configured for log search
        """
        query = SearchQuery()

        # Time range from parameters
        time_range = parameters.get("time_range_hours", 24)
        query.time_end = datetime.now(timezone.utc)
        query.time_start = query.time_end - timedelta(hours=time_range)

        # Target specific hosts if provided
        if parameters.get("target_hosts"):
            query.hostnames = parameters["target_hosts"]

        # Build search text from hypothesis title and description
        search_terms = [hypothesis.get("title", "")]
        if hypothesis.get("description"):
            search_terms.append(hypothesis["description"])
        query.query_text = " ".join(search_terms)

        # Map MITRE techniques to search patterns
        if hypothesis.get("mitre_techniques"):
            patterns = []
            for technique in hypothesis["mitre_techniques"]:
                if technique in self.MITRE_TECHNIQUE_PATTERNS:
                    patterns.extend(
                        self.MITRE_TECHNIQUE_PATTERNS[technique]["patterns"]
                    )
            if patterns:
                query.query_text = " OR ".join(patterns)

        # Filter by data sources if specified
        if hypothesis.get("data_sources"):
            query.source_types = hypothesis["data_sources"]

        # Filter by log types
        if parameters.get("log_types"):
            query.log_types = parameters["log_types"]

        # Set pagination for thorough analysis
        query.size = parameters.get("page_size", 1000)
        query.sort_by = "timestamp"
        query.sort_order = "desc"

        return query

    def build_ioc_sweep_query(self, iocs: list[dict]) -> SearchQuery:
        """Build queries to sweep logs for specific indicators of compromise

        Args:
            iocs: List of IOC dicts with keys: type (ip|domain|hash|url), value

        Returns:
            SearchQuery configured for IOC matching
        """
        query = SearchQuery()

        # Organize IOCs by type
        ips = [ioc["value"] for ioc in iocs if ioc.get("type") == "ip"]
        domains = [ioc["value"] for ioc in iocs if ioc.get("type") == "domain"]
        hashes = [ioc["value"] for ioc in iocs if ioc.get("type") == "hash"]
        urls = [ioc["value"] for ioc in iocs if ioc.get("type") == "url"]

        # Apply filters
        if ips:
            query.source_addresses = ips
            query.destination_addresses = ips

        if domains:
            query.query_text = " OR ".join(domains)

        if hashes:
            query.query_text = " OR ".join(hashes)

        if urls:
            query.query_text = " OR ".join(urls)

        # Time range for IOC sweep (default 7 days)
        query.time_end = datetime.now(timezone.utc)
        query.time_start = query.time_end - timedelta(days=7)

        query.size = 10000  # Larger result set for sweeps
        return query

    def build_behavioral_query(self, behavior_pattern: dict) -> SearchQuery:
        """Build queries for behavioral patterns

        Example pattern:
        {
            "description": "Process spawning activity",
            "parent_process": "svchost.exe",
            "child_process": "cmd.exe",
            "time_window_seconds": 30
        }

        Args:
            behavior_pattern: Dict describing the behavior to search for

        Returns:
            SearchQuery configured for behavioral analysis
        """
        query = SearchQuery()

        # Search for process relationships
        search_terms = []
        if behavior_pattern.get("parent_process"):
            search_terms.append(f"parent_process:{behavior_pattern['parent_process']}")
        if behavior_pattern.get("child_process"):
            search_terms.append(f"child_process:{behavior_pattern['child_process']}")
        if behavior_pattern.get("username"):
            search_terms.append(f"username:{behavior_pattern['username']}")

        query.query_text = " AND ".join(search_terms) if search_terms else ""

        # Time range (default 24 hours)
        query.time_end = datetime.now(timezone.utc)
        query.time_start = query.time_end - timedelta(
            hours=behavior_pattern.get("time_window_hours", 24)
        )

        query.size = 5000
        return query

    def build_anomaly_query(self, baseline: dict, deviation_threshold: float) -> SearchQuery:
        """Build queries for statistical anomaly detection

        Args:
            baseline: Dict with field, normal_range, expected_value
            deviation_threshold: Multiplier for anomaly detection (e.g., 2.5 = 2.5x deviation)

        Returns:
            SearchQuery for collecting data to analyze
        """
        query = SearchQuery()

        # Anomaly queries are typically aggregation queries
        # We build a standard query to get raw data for analysis
        if baseline.get("field"):
            query.query_text = f"field:{baseline['field']}"

        if baseline.get("source_type"):
            query.source_types = [baseline["source_type"]]

        # Time range (default 30 days for baseline)
        query.time_end = datetime.now(timezone.utc)
        query.time_start = query.time_end - timedelta(
            days=baseline.get("baseline_days", 30)
        )

        query.size = 10000
        return query

    def substitute_template_variables(
        self, query_template: str, variables: dict
    ) -> str:
        """Replace template variables in query strings

        Supports: {{time_start}}, {{time_end}}, {{target_hosts}}, {{data_sources}}

        Args:
            query_template: Query string with template variables
            variables: Dict of variable replacements

        Returns:
            Query string with variables substituted
        """
        query = query_template
        for var_name, var_value in variables.items():
            placeholder = f"{{{{{var_name}}}}}"
            query = query.replace(placeholder, str(var_value))
        return query


class HuntExecutor:
    """Executes hunt investigations and collects results"""

    def __init__(self, db_session=None, search_service: Optional[LogSearchService] = None):
        """Initialize executor with database and search service

        Args:
            db_session: SQLAlchemy async session
            search_service: LogSearchService instance for querying logs
        """
        self.db = db_session
        self.search_service = search_service or LogSearchService()
        self.query_builder = HuntQueryBuilder()

    async def execute_hunt(
        self, hypothesis_id: str, parameters: dict, hypothesis_data: dict
    ) -> str:
        """Execute a hunt and create a session

        Args:
            hypothesis_id: ID of the hunt hypothesis
            parameters: Runtime parameters (time_range_hours, target_hosts, etc.)
            hypothesis_data: Hypothesis details (title, description, mitre_techniques)

        Returns:
            Session ID of the created hunt session
        """
        logger.info(f"Starting hunt execution for hypothesis {hypothesis_id}")

        # Create session record
        session = HuntSession(
            hypothesis_id=hypothesis_id,
            status=SessionStatus.PENDING.value,
            parameters=json.dumps(parameters),
            created_by=parameters.get("created_by"),
        )
        # Note: In a real implementation, would add/flush to db
        session_id = session.id

        # Update status to RUNNING
        session.status = SessionStatus.RUNNING.value
        session.started_at = datetime.now(timezone.utc)

        try:
            # Build and execute queries
            query = self.query_builder.build_log_query(hypothesis_data, parameters)
            results = await self._run_queries(session, [query])

            # Analyze results
            analyzed = await self._analyze_results(results)

            # Create findings and persist to database
            findings = await self._create_findings(session_id, analyzed)
            for finding in findings:
                self.db.add(finding)
            await self.db.flush()

            # Update session with results
            session.findings_count = len(findings)
            session.events_analyzed = sum(
                r.get("event_count", 1) for r in results
            )
            session.query_count = 1
            session.status = SessionStatus.COMPLETED.value
            session.completed_at = datetime.now(timezone.utc)

            if session.started_at and session.completed_at:
                session.duration_seconds = int(
                    (session.completed_at - session.started_at).total_seconds()
                )

            logger.info(
                f"Hunt session {session_id} completed with {len(findings)} findings"
            )

        except Exception as e:
            logger.error(f"Hunt execution failed: {str(e)}")
            session.status = SessionStatus.FAILED.value
            session.error_message = str(e)
            session.completed_at = datetime.now(timezone.utc)

        return session_id

    async def _run_queries(self, session: HuntSession, queries: list[dict]) -> list[dict]:
        """Execute queries against SIEM log store

        Args:
            session: HuntSession instance
            queries: List of query dicts

        Returns:
            List of result dicts with timing information
        """
        results = []

        for query_dict in queries:
            start_time = datetime.now(timezone.utc)

            # Execute search
            if isinstance(query_dict, SearchQuery):
                search_query = query_dict
            else:
                # Convert dict to SearchQuery if needed
                search_query = SearchQuery(**query_dict)

            # Simulate search results (in real implementation, use search_service)
            search_result = {
                "items": [],
                "total": 0,
                "query_text": getattr(search_query, "query_text", ""),
            }

            end_time = datetime.now(timezone.utc)
            execution_ms = int((end_time - start_time).total_seconds() * 1000)

            results.append(
                {
                    "query_text": search_query.query_text or "",
                    "results_count": search_result["total"],
                    "execution_time_ms": execution_ms,
                    "items": search_result["items"],
                    "event_count": search_result["total"],
                }
            )

        # Store queries executed
        session.queries_executed = json.dumps(results)

        return results

    async def _analyze_results(self, results: list[dict]) -> list[dict]:
        """Apply analysis heuristics to identify potential findings

        Args:
            results: List of raw search results

        Returns:
            List of analyzed findings
        """
        analyzer = HuntAnalyzer()
        analyzed_findings = []

        for result in results:
            items = result.get("items", [])

            if not items:
                continue

            # Apply analysis heuristics
            frequency_findings = analyzer.analyze_frequency(items, "hostname", 5)
            rare_findings = analyzer.analyze_rare_values(items, "username", 2)
            time_findings = analyzer.analyze_time_clustering(items, 5)
            volume_findings = analyzer.analyze_data_volume(items, 1000000)

            analyzed_findings.extend(frequency_findings)
            analyzed_findings.extend(rare_findings)
            analyzed_findings.extend(time_findings)
            analyzed_findings.extend(volume_findings)

        return analyzed_findings

    async def _create_findings(
        self, session_id: str, analyzed: list[dict]
    ) -> list[HuntFinding]:
        """Convert analyzed results to finding records

        Args:
            session_id: Session ID to link findings to
            analyzed: List of analyzed finding dicts

        Returns:
            List of HuntFinding objects
        """
        findings = []

        for finding_data in analyzed:
            # Score the finding
            score = HuntAnalyzer.score_finding(finding_data)

            # Determine severity based on score
            if score >= 0.8:
                severity = FindingSeverity.CRITICAL.value
            elif score >= 0.6:
                severity = FindingSeverity.HIGH.value
            elif score >= 0.4:
                severity = FindingSeverity.MEDIUM.value
            else:
                severity = FindingSeverity.LOW.value

            finding = HuntFinding(
                session_id=session_id,
                title=finding_data.get("title", "Unnamed Finding"),
                description=finding_data.get("description", ""),
                severity=severity,
                classification=FindingClassification.NEEDS_REVIEW.value,
                evidence=json.dumps(finding_data.get("evidence", [])),
                affected_assets=json.dumps(finding_data.get("affected_assets", [])),
                iocs_found=json.dumps(finding_data.get("iocs", [])),
            )

            findings.append(finding)

        return findings

    async def pause_hunt(self, session_id: str) -> bool:
        """Pause a running hunt session

        Args:
            session_id: ID of session to pause

        Returns:
            True if successful
        """
        logger.info(f"Pausing hunt session {session_id}")
        # In real implementation, would update session status in db
        return True

    async def resume_hunt(self, session_id: str) -> bool:
        """Resume a paused hunt session

        Args:
            session_id: ID of session to resume

        Returns:
            True if successful
        """
        logger.info(f"Resuming hunt session {session_id}")
        # In real implementation, would update session status in db
        return True

    async def cancel_hunt(self, session_id: str) -> bool:
        """Cancel a hunt session

        Args:
            session_id: ID of session to cancel

        Returns:
            True if successful
        """
        logger.info(f"Cancelling hunt session {session_id}")
        # In real implementation, would update session status in db
        return True

    async def get_hunt_status(self, session_id: str) -> dict:
        """Get current status of a hunt session

        Args:
            session_id: ID of session

        Returns:
            Dict with status, progress, and statistics
        """
        # In real implementation, would fetch from db
        return {
            "session_id": session_id,
            "status": SessionStatus.RUNNING.value,
            "progress_percent": 50,
            "queries_executed": 1,
            "events_analyzed": 0,
            "findings_found": 0,
        }


class HuntAnalyzer:
    """Analyzes hunt results to identify findings"""

    @staticmethod
    def analyze_frequency(
        results: list[dict], field: str, threshold: int
    ) -> list[dict]:
        """Find fields occurring more than threshold times

        Args:
            results: List of log entries
            field: Field name to analyze
            threshold: Occurrence count threshold

        Returns:
            List of finding dicts
        """
        findings = []
        field_counts = {}

        for result in results:
            value = result.get(field)
            if value:
                field_counts[value] = field_counts.get(value, 0) + 1

        for value, count in field_counts.items():
            if count >= threshold:
                findings.append(
                    {
                        "type": "frequency_anomaly",
                        "title": f"High frequency of {field}: {value}",
                        "description": f"{field} value '{value}' appeared {count} times (threshold: {threshold})",
                        "affected_assets": [value],
                        "evidence": [{"type": "frequency", "value": count, "field": field}],
                    }
                )

        return findings

    @staticmethod
    def analyze_rare_values(
        results: list[dict], field: str, max_occurrences: int = 3
    ) -> list[dict]:
        """Find unusually rare field values

        Args:
            results: List of log entries
            field: Field name to analyze
            max_occurrences: Max times a value should occur to be considered rare

        Returns:
            List of finding dicts
        """
        findings = []
        field_counts = {}

        for result in results:
            value = result.get(field)
            if value:
                field_counts[value] = field_counts.get(value, 0) + 1

        for value, count in field_counts.items():
            if count <= max_occurrences and count > 0:
                findings.append(
                    {
                        "type": "rare_value",
                        "title": f"Rare {field}: {value}",
                        "description": f"{field} value '{value}' appeared only {count} time(s)",
                        "affected_assets": [value],
                        "evidence": [{"type": "rare_value", "value": count}],
                    }
                )

        return findings

    @staticmethod
    def analyze_time_clustering(
        results: list[dict], window_minutes: int = 5
    ) -> list[dict]:
        """Find temporal clusters of events

        Args:
            results: List of log entries with timestamp
            window_minutes: Time window in minutes

        Returns:
            List of finding dicts
        """
        findings = []

        if not results:
            return findings

        # Sort by timestamp
        sorted_results = sorted(
            results, key=lambda x: x.get("timestamp", ""), reverse=True
        )

        clusters = []
        current_cluster = [sorted_results[0]]

        for i in range(1, len(sorted_results)):
            result = sorted_results[i]
            prev_result = sorted_results[i - 1]

            # Check if within time window (simplified)
            if i < 10:  # Simplified: group first 10 as cluster
                current_cluster.append(result)
            else:
                if len(current_cluster) >= 3:
                    clusters.append(current_cluster)
                current_cluster = [result]

        if len(current_cluster) >= 3:
            clusters.append(current_cluster)

        for cluster in clusters:
            findings.append(
                {
                    "type": "time_cluster",
                    "title": f"Temporal cluster: {len(cluster)} events",
                    "description": f"Detected temporal clustering of {len(cluster)} events",
                    "evidence": [{"type": "cluster_size", "value": len(cluster)}],
                }
            )

        return findings

    @staticmethod
    def analyze_lateral_movement(results: list[dict]) -> list[dict]:
        """Detect patterns of same user/process across multiple hosts

        Args:
            results: List of log entries

        Returns:
            List of finding dicts
        """
        findings = []
        user_hosts = {}

        for result in results:
            user = result.get("username")
            host = result.get("hostname")

            if user and host:
                if user not in user_hosts:
                    user_hosts[user] = set()
                user_hosts[user].add(host)

        for user, hosts in user_hosts.items():
            if len(hosts) >= 3:  # Same user on 3+ hosts
                findings.append(
                    {
                        "type": "lateral_movement",
                        "title": f"Lateral movement: {user} across {len(hosts)} hosts",
                        "description": f"User '{user}' detected on {len(hosts)} different hosts",
                        "affected_assets": list(hosts),
                        "evidence": [
                            {"type": "lateral_movement", "user": user, "host_count": len(hosts)}
                        ],
                    }
                )

        return findings

    @staticmethod
    def analyze_data_volume(
        results: list[dict], threshold_bytes: int
    ) -> list[dict]:
        """Find unusually large data transfers

        Args:
            results: List of log entries with byte_count
            threshold_bytes: Byte count threshold

        Returns:
            List of finding dicts
        """
        findings = []

        for result in results:
            bytes_transferred = result.get("bytes_transferred", 0)

            if bytes_transferred >= threshold_bytes:
                findings.append(
                    {
                        "type": "large_transfer",
                        "title": f"Large data transfer: {bytes_transferred} bytes",
                        "description": f"Detected data transfer of {bytes_transferred} bytes",
                        "evidence": [
                            {"type": "data_volume", "bytes": bytes_transferred}
                        ],
                    }
                )

        return findings

    @staticmethod
    def score_finding(finding_data: dict) -> float:
        """Score a potential finding 0.0-1.0 based on severity indicators

        Args:
            finding_data: Dict with finding details

        Returns:
            Score from 0.0 to 1.0
        """
        score = 0.5  # Base score

        finding_type = finding_data.get("type", "")

        # Adjust score by finding type
        if finding_type == "lateral_movement":
            score = 0.85
        elif finding_type == "large_transfer":
            score = 0.75
        elif finding_type == "frequency_anomaly":
            score = 0.70
        elif finding_type == "time_cluster":
            score = 0.60
        elif finding_type == "rare_value":
            score = 0.40

        # Adjust by evidence count
        evidence_count = len(finding_data.get("evidence", []))
        if evidence_count >= 3:
            score = min(1.0, score + 0.15)

        return min(1.0, max(0.0, score))


class HuntTemplateManager:
    """Manages reusable hunt templates"""

    BUILTIN_TEMPLATES = [
        {
            "id": "template_1",
            "name": "Lateral Movement Detection",
            "category": "Lateral Movement",
            "hunt_type": HuntType.BEHAVIORAL.value,
            "difficulty": TemplateDifficulty.INTERMEDIATE.value,
            "description": "Detect lateral movement patterns across hosts",
            "hypothesis_template": "Investigating potential lateral movement by {{actor}} across network",
            "mitre_tactics": ["TA0008"],
            "mitre_techniques": ["T1021"],
            "data_sources_required": ["sysmon", "windows_security"],
            "estimated_duration_minutes": 30,
        },
        {
            "id": "template_2",
            "name": "Data Exfiltration Investigation",
            "category": "Data Exfiltration",
            "hunt_type": HuntType.IOC_SWEEP.value,
            "difficulty": TemplateDifficulty.INTERMEDIATE.value,
            "description": "Investigate potential data exfiltration activities",
            "hypothesis_template": "Searching for signs of data exfiltration from {{target}}",
            "mitre_tactics": ["TA0010"],
            "mitre_techniques": ["T1041"],
            "data_sources_required": ["network_logs", "proxy_logs"],
            "estimated_duration_minutes": 45,
        },
        {
            "id": "template_3",
            "name": "Persistence Mechanism Sweep",
            "category": "Persistence",
            "hunt_type": HuntType.IOC_SWEEP.value,
            "difficulty": TemplateDifficulty.ADVANCED.value,
            "description": "Sweep for persistence mechanisms and backdoors",
            "hypothesis_template": "Searching for persistence mechanisms on {{target_hosts}}",
            "mitre_tactics": ["TA0003"],
            "mitre_techniques": ["T1547", "T1547.001"],
            "data_sources_required": ["sysmon", "process_monitoring"],
            "estimated_duration_minutes": 60,
        },
        {
            "id": "template_4",
            "name": "Credential Access Hunt",
            "category": "Credential Access",
            "hunt_type": HuntType.BEHAVIORAL.value,
            "difficulty": TemplateDifficulty.ADVANCED.value,
            "description": "Hunt for credential harvesting and access attempts",
            "hypothesis_template": "Investigating credential access activities targeting {{target}}",
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1110", "T1187"],
            "data_sources_required": ["sysmon", "active_directory", "windows_security"],
            "estimated_duration_minutes": 90,
        },
        {
            "id": "template_5",
            "name": "C2 Communication Detection",
            "category": "Command and Control",
            "hunt_type": HuntType.IOC_SWEEP.value,
            "difficulty": TemplateDifficulty.EXPERT.value,
            "description": "Detect command and control communications",
            "hypothesis_template": "Searching for C2 communications from {{scope}}",
            "mitre_tactics": ["TA0011"],
            "mitre_techniques": ["T1071"],
            "data_sources_required": ["network_logs", "dns_logs", "proxy_logs"],
            "estimated_duration_minutes": 120,
        },
        {
            "id": "template_6",
            "name": "Insider Threat Behavioral Analysis",
            "category": "Insider Threat",
            "hunt_type": HuntType.ANOMALY.value,
            "difficulty": TemplateDifficulty.EXPERT.value,
            "description": "Analyze behavioral patterns for insider threat indicators",
            "hypothesis_template": "Analyzing behavioral anomalies for {{target_user}}",
            "mitre_tactics": ["TA0005"],
            "data_sources_required": ["user_activity", "file_access", "network"],
            "estimated_duration_minutes": 120,
        },
        {
            "id": "template_7",
            "name": "Ransomware Pre-cursor Activity",
            "category": "Ransomware",
            "hunt_type": HuntType.BEHAVIORAL.value,
            "difficulty": TemplateDifficulty.INTERMEDIATE.value,
            "description": "Hunt for ransomware precursor activities",
            "hypothesis_template": "Searching for ransomware preparation activities on {{target_hosts}}",
            "mitre_tactics": ["TA0002"],
            "mitre_techniques": ["T1486"],
            "data_sources_required": ["sysmon", "file_monitoring"],
            "estimated_duration_minutes": 45,
        },
        {
            "id": "template_8",
            "name": "Supply Chain Compromise Indicators",
            "category": "Supply Chain",
            "hunt_type": HuntType.IOC_SWEEP.value,
            "difficulty": TemplateDifficulty.EXPERT.value,
            "description": "Investigate indicators of supply chain compromises",
            "hypothesis_template": "Searching for supply chain compromise indicators from {{supplier}}",
            "mitre_tactics": ["TA0001"],
            "data_sources_required": ["process_monitoring", "network_logs"],
            "estimated_duration_minutes": 180,
        },
    ]

    @staticmethod
    def get_builtin_templates() -> list[dict]:
        """Get all built-in hunt templates

        Returns:
            List of template dicts
        """
        return HuntTemplateManager.BUILTIN_TEMPLATES

    @staticmethod
    def get_template(template_id: str) -> Optional[dict]:
        """Get a specific template by ID

        Args:
            template_id: ID of the template

        Returns:
            Template dict or None if not found
        """
        for template in HuntTemplateManager.BUILTIN_TEMPLATES:
            if template.get("id") == template_id:
                return template
        return None

    @staticmethod
    def instantiate_template(template_id: str, parameters: dict) -> dict:
        """Create a hypothesis from a template with parameters filled in

        Args:
            template_id: ID of the template to instantiate
            parameters: Dict of template variables to substitute

        Returns:
            Hypothesis dict with template variables replaced
        """
        template = HuntTemplateManager.get_template(template_id)

        if not template:
            return {}

        # Create hypothesis from template
        hypothesis = {
            "title": template.get("hypothesis_template", ""),
            "description": template.get("description", ""),
            "hunt_type": template.get("hunt_type"),
            "mitre_tactics": template.get("mitre_tactics", []),
            "mitre_techniques": template.get("mitre_techniques", []),
            "data_sources": template.get("data_sources_required", []),
            "template_id": template_id,
        }

        # Substitute template variables
        if hypothesis["title"]:
            for var_name, var_value in parameters.items():
                placeholder = f"{{{{{var_name}}}}}"
                hypothesis["title"] = hypothesis["title"].replace(
                    placeholder, str(var_value)
                )

        return hypothesis
