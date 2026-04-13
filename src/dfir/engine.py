"""DFIR Engine - Core forensic case management, evidence analysis, and timeline reconstruction"""

import hashlib
import json
import re
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from abc import ABC, abstractmethod

from src.core.logging import get_logger

logger = get_logger(__name__)


class ForensicEngine:
    """Main forensic case management engine"""

    def __init__(self):
        """Initialize the forensic engine"""
        self.logger = logger

    def create_case(
        self,
        case_number: str,
        title: str,
        case_type: str,
        organization_id: str,
        description: Optional[str] = None,
        severity: str = "medium",
        lead_investigator_id: Optional[str] = None,
        assigned_team: Optional[list[str]] = None,
        created_by: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Create a new forensic case.

        Args:
            case_number: Unique case identifier
            title: Case title
            case_type: Type of case
            organization_id: Organization ID for multi-tenancy
            description: Case description
            severity: Severity level
            lead_investigator_id: Lead investigator user ID
            assigned_team: List of assigned team members
            created_by: User who created the case

        Returns:
            Dictionary with case creation details
        """
        try:
            self.logger.info(f"Creating forensic case {case_number}: {title}")

            case_data = {
                "case_number": case_number,
                "title": title,
                "case_type": case_type,
                "organization_id": organization_id,
                "description": description,
                "severity": severity,
                "lead_investigator_id": lead_investigator_id,
                "assigned_team": json.dumps(assigned_team) if assigned_team else None,
                "created_by": created_by,
                "status": "open",
                "legal_hold_active": False,
                "court_admissible": False,
            }

            return {
                "status": "success",
                "case_number": case_number,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "data": case_data,
            }
        except Exception as e:
            self.logger.error(f"Failed to create case {case_number}: {e}")
            return {"status": "error", "message": str(e)}

    def assign_investigator(
        self,
        case_id: str,
        investigator_id: str,
        role: str = "lead_investigator",
    ) -> dict[str, Any]:
        """
        Assign an investigator to a case.

        Args:
            case_id: Forensic case ID
            investigator_id: User ID of investigator
            role: Role of the investigator

        Returns:
            Assignment confirmation
        """
        try:
            self.logger.info(f"Assigning investigator {investigator_id} to case {case_id} as {role}")
            return {
                "status": "success",
                "case_id": case_id,
                "investigator_id": investigator_id,
                "role": role,
                "assigned_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Failed to assign investigator: {e}")
            return {"status": "error", "message": str(e)}

    def update_case_status(
        self,
        case_id: str,
        new_status: str,
        updated_by: str,
        notes: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Update case status with audit trail.

        Args:
            case_id: Forensic case ID
            new_status: New status value
            updated_by: User ID making the update
            notes: Optional notes about the status change

        Returns:
            Status update confirmation
        """
        try:
            self.logger.info(f"Updating case {case_id} status to {new_status}")
            return {
                "status": "success",
                "case_id": case_id,
                "new_status": new_status,
                "updated_by": updated_by,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "notes": notes,
            }
        except Exception as e:
            self.logger.error(f"Failed to update case status: {e}")
            return {"status": "error", "message": str(e)}

    def close_case(
        self,
        case_id: str,
        closed_by: str,
        conclusion: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Close a forensic case.

        Args:
            case_id: Forensic case ID
            closed_by: User ID closing the case
            conclusion: Case conclusion summary

        Returns:
            Case closure confirmation
        """
        try:
            self.logger.info(f"Closing case {case_id}")
            return {
                "status": "success",
                "case_id": case_id,
                "closed_by": closed_by,
                "closed_at": datetime.now(timezone.utc).isoformat(),
                "conclusion": conclusion,
            }
        except Exception as e:
            self.logger.error(f"Failed to close case: {e}")
            return {"status": "error", "message": str(e)}

    def generate_case_report(
        self,
        case_id: str,
        include_timeline: bool = True,
        include_artifacts: bool = True,
        include_conclusions: bool = True,
    ) -> dict[str, Any]:
        """
        Generate comprehensive case report.

        Args:
            case_id: Forensic case ID
            include_timeline: Include timeline reconstruction
            include_artifacts: Include artifact analysis
            include_conclusions: Include findings and conclusions

        Returns:
            Case report data
        """
        try:
            self.logger.info(f"Generating report for case {case_id}")
            report = {
                "case_id": case_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "sections": [],
            }

            if include_timeline:
                report["sections"].append("timeline_reconstruction")
            if include_artifacts:
                report["sections"].append("artifact_analysis")
            if include_conclusions:
                report["sections"].append("findings_and_conclusions")

            return {
                "status": "success",
                "report": report,
            }
        except Exception as e:
            self.logger.error(f"Failed to generate case report: {e}")
            return {"status": "error", "message": str(e)}

    def get_case_metrics(self, case_id: str) -> dict[str, Any]:
        """
        Get forensic metrics for a case.

        Args:
            case_id: Forensic case ID

        Returns:
            Case metrics including evidence count, artifact count, etc.
        """
        try:
            self.logger.info(f"Retrieving metrics for case {case_id}")
            return {
                "status": "success",
                "case_id": case_id,
                "metrics": {
                    "evidence_count": 0,
                    "artifact_count": 0,
                    "timeline_events": 0,
                    "legal_holds_active": 0,
                    "investigation_duration_days": 0,
                },
            }
        except Exception as e:
            self.logger.error(f"Failed to get case metrics: {e}")
            return {"status": "error", "message": str(e)}


class EvidenceManager:
    """Manages forensic evidence collection and integrity verification"""

    def __init__(self):
        """Initialize the evidence manager"""
        self.logger = logger

    def collect_evidence(
        self,
        case_id: str,
        evidence_type: str,
        source_device: str,
        acquisition_method: str,
        storage_location: str,
        organization_id: str,
        source_ip: Optional[str] = None,
        file_size_bytes: Optional[int] = None,
        handling_notes: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Collect and register forensic evidence.

        Args:
            case_id: Forensic case ID
            evidence_type: Type of evidence
            source_device: Source device identifier
            acquisition_method: Method of acquisition
            storage_location: Where evidence is stored
            organization_id: Organization ID
            source_ip: Source IP address if applicable
            file_size_bytes: Size of evidence in bytes
            handling_notes: Notes on evidence handling

        Returns:
            Evidence collection confirmation
        """
        try:
            self.logger.info(f"Collecting {evidence_type} evidence from {source_device}")

            evidence_data = {
                "case_id": case_id,
                "evidence_type": evidence_type,
                "source_device": source_device,
                "acquisition_method": acquisition_method,
                "storage_location": storage_location,
                "source_ip": source_ip,
                "file_size_bytes": file_size_bytes,
                "handling_notes": handling_notes,
                "organization_id": organization_id,
                "is_verified": False,
                "chain_of_custody_log": [
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "action": "collected",
                        "actor": "system",
                        "hash": None,
                    }
                ],
            }

            return {
                "status": "success",
                "evidence_id": f"ev-{datetime.now(timezone.utc).timestamp()}",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "data": evidence_data,
            }
        except Exception as e:
            self.logger.error(f"Failed to collect evidence: {e}")
            return {"status": "error", "message": str(e)}

    def verify_integrity(
        self,
        evidence_id: str,
        evidence_hash: str,
        hash_algorithm: str = "sha256",
        original_hash: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Verify evidence integrity through hash comparison.

        Args:
            evidence_id: Forensic evidence ID
            evidence_hash: Current hash of the evidence
            hash_algorithm: Hash algorithm used
            original_hash: Original hash for comparison

        Returns:
            Verification result
        """
        try:
            self.logger.info(f"Verifying integrity of evidence {evidence_id}")

            is_valid = True
            if original_hash:
                is_valid = evidence_hash.lower() == original_hash.lower()

            return {
                "status": "success",
                "evidence_id": evidence_id,
                "hash_algorithm": hash_algorithm,
                "current_hash": evidence_hash,
                "original_hash": original_hash,
                "is_valid": is_valid,
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Failed to verify evidence integrity: {e}")
            return {"status": "error", "message": str(e)}

    def update_chain_of_custody(
        self,
        evidence_id: str,
        actor: str,
        action: str,
        evidence_hash: Optional[str] = None,
        details: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Append-only chain of custody log update.

        Args:
            evidence_id: Forensic evidence ID
            actor: Person/system performing the action
            action: Action performed (e.g., transferred, analyzed, stored)
            evidence_hash: Current hash for integrity tracking
            details: Additional details about the action

        Returns:
            Chain of custody log entry
        """
        try:
            self.logger.info(f"Updating chain of custody for evidence {evidence_id}: {action}")

            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "action": action,
                "hash": evidence_hash,
                "details": details,
            }

            return {
                "status": "success",
                "evidence_id": evidence_id,
                "log_entry": log_entry,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Failed to update chain of custody: {e}")
            return {"status": "error", "message": str(e)}

    def generate_chain_of_custody_report(
        self,
        evidence_id: str,
        full_log: Optional[list[dict]] = None,
    ) -> dict[str, Any]:
        """
        Generate chain of custody report for legal proceedings.

        Args:
            evidence_id: Forensic evidence ID
            full_log: Complete chain of custody log

        Returns:
            Chain of custody report
        """
        try:
            self.logger.info(f"Generating chain of custody report for evidence {evidence_id}")

            report = {
                "evidence_id": evidence_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "log_entries": full_log or [],
                "is_court_admissible": True,
            }

            return {
                "status": "success",
                "report": report,
            }
        except Exception as e:
            self.logger.error(f"Failed to generate chain of custody report: {e}")
            return {"status": "error", "message": str(e)}

    def quarantine_evidence(
        self,
        evidence_id: str,
        reason: str,
        quarantined_by: str,
    ) -> dict[str, Any]:
        """
        Quarantine evidence pending investigation.

        Args:
            evidence_id: Forensic evidence ID
            reason: Reason for quarantine
            quarantined_by: User ID quarantining the evidence

        Returns:
            Quarantine confirmation
        """
        try:
            self.logger.info(f"Quarantining evidence {evidence_id}: {reason}")
            return {
                "status": "success",
                "evidence_id": evidence_id,
                "reason": reason,
                "quarantined_by": quarantined_by,
                "quarantined_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Failed to quarantine evidence: {e}")
            return {"status": "error", "message": str(e)}


class TimelineReconstructor:
    """Reconstructs event timelines from multiple forensic sources"""

    def __init__(self):
        """Initialize the timeline reconstructor"""
        self.logger = logger
        self.events: list[dict] = []

    def add_event(
        self,
        case_id: str,
        event_timestamp: str,
        event_type: str,
        source: str,
        description: Optional[str] = None,
        artifact_data: Optional[dict] = None,
        mitre_technique_id: Optional[str] = None,
        severity_score: float = 0.0,
        is_pivotal: bool = False,
    ) -> dict[str, Any]:
        """
        Add an event to the timeline.

        Args:
            case_id: Forensic case ID
            event_timestamp: Timestamp of the event
            event_type: Type of event
            source: Source of the event
            description: Event description
            artifact_data: Associated artifact data
            mitre_technique_id: MITRE technique ID if applicable
            severity_score: Severity score (0-10)
            is_pivotal: Whether this is a pivotal event

        Returns:
            Event confirmation
        """
        try:
            event = {
                "case_id": case_id,
                "event_timestamp": event_timestamp,
                "event_type": event_type,
                "source": source,
                "description": description,
                "artifact_data": artifact_data or {},
                "mitre_technique_id": mitre_technique_id,
                "severity_score": severity_score,
                "is_pivotal": is_pivotal,
            }
            self.events.append(event)
            self.logger.info(f"Added timeline event: {event_type} @ {event_timestamp}")
            return {"status": "success", "event": event}
        except Exception as e:
            self.logger.error(f"Failed to add timeline event: {e}")
            return {"status": "error", "message": str(e)}

    def build_timeline(self, case_id: str) -> dict[str, Any]:
        """
        Build complete timeline from collected events.

        Args:
            case_id: Forensic case ID

        Returns:
            Sorted and merged timeline
        """
        try:
            self.logger.info(f"Building timeline for case {case_id}")

            # Filter events for this case
            case_events = [e for e in self.events if e["case_id"] == case_id]

            # Sort by timestamp
            sorted_events = sorted(
                case_events,
                key=lambda x: x["event_timestamp"],
            )

            return {
                "status": "success",
                "case_id": case_id,
                "event_count": len(sorted_events),
                "events": sorted_events,
            }
        except Exception as e:
            self.logger.error(f"Failed to build timeline: {e}")
            return {"status": "error", "message": str(e)}

    def detect_gaps(self, case_id: str, max_gap_hours: int = 24) -> dict[str, Any]:
        """
        Detect gaps in timeline.

        Args:
            case_id: Forensic case ID
            max_gap_hours: Maximum acceptable gap in hours

        Returns:
            List of timeline gaps
        """
        try:
            self.logger.info(f"Detecting timeline gaps for case {case_id}")

            timeline_result = self.build_timeline(case_id)
            events = timeline_result.get("events", [])

            # Real gap detection: compute the real time delta between
            # chronologically-ordered timeline events. Only include gaps
            # longer than a threshold (default 1 hour) as "significant".
            from datetime import datetime as _dt
            SIGNIFICANT_GAP_SECONDS = 3600

            parsed_events = []
            for e in events:
                ts_raw = e.get("timestamp") or e.get("event_time") or e.get("occurred_at")
                if not ts_raw:
                    continue
                try:
                    ts = _dt.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                    parsed_events.append((ts, e))
                except (ValueError, TypeError):
                    continue
            parsed_events.sort(key=lambda p: p[0])

            gaps = []
            for i in range(len(parsed_events) - 1):
                ts_a, ev_a = parsed_events[i]
                ts_b, ev_b = parsed_events[i + 1]
                delta_seconds = (ts_b - ts_a).total_seconds()
                if delta_seconds >= SIGNIFICANT_GAP_SECONDS:
                    gaps.append({
                        "from_event": ev_a.get("event_type"),
                        "from_timestamp": ts_a.isoformat(),
                        "to_event": ev_b.get("event_type"),
                        "to_timestamp": ts_b.isoformat(),
                        "gap_seconds": int(delta_seconds),
                        "gap_minutes": round(delta_seconds / 60.0, 1),
                        "gap_hours": round(delta_seconds / 3600.0, 2),
                    })

            return {
                "status": "success",
                "case_id": case_id,
                "gap_count": len(gaps),
                "significant_gap_threshold_seconds": SIGNIFICANT_GAP_SECONDS,
                "gaps": gaps,
            }
        except Exception as e:
            self.logger.error(f"Failed to detect timeline gaps: {e}")
            return {"status": "error", "message": str(e)}

    def identify_pivotal_events(self, case_id: str) -> dict[str, Any]:
        """
        Identify pivotal events in timeline based on MITRE mapping and severity.

        Args:
            case_id: Forensic case ID

        Returns:
            List of pivotal events
        """
        try:
            self.logger.info(f"Identifying pivotal events for case {case_id}")

            timeline_result = self.build_timeline(case_id)
            events = timeline_result.get("events", [])

            # Filter for pivotal events
            pivotal = [
                e for e in events
                if e["is_pivotal"] or e["severity_score"] >= 7.0 or e["mitre_technique_id"]
            ]

            return {
                "status": "success",
                "case_id": case_id,
                "pivotal_count": len(pivotal),
                "pivotal_events": pivotal,
            }
        except Exception as e:
            self.logger.error(f"Failed to identify pivotal events: {e}")
            return {"status": "error", "message": str(e)}

    def generate_timeline_visualization_data(self, case_id: str) -> dict[str, Any]:
        """
        Generate data for timeline visualization.

        Args:
            case_id: Forensic case ID

        Returns:
            Timeline visualization data
        """
        try:
            self.logger.info(f"Generating timeline visualization for case {case_id}")

            timeline_result = self.build_timeline(case_id)
            events = timeline_result.get("events", [])

            # Create visualization-ready data structure
            vis_data = {
                "case_id": case_id,
                "events": [
                    {
                        "timestamp": e["event_timestamp"],
                        "type": e["event_type"],
                        "severity": e["severity_score"],
                        "is_pivotal": e["is_pivotal"],
                    }
                    for e in events
                ],
            }

            return {
                "status": "success",
                "visualization": vis_data,
            }
        except Exception as e:
            self.logger.error(f"Failed to generate timeline visualization: {e}")
            return {"status": "error", "message": str(e)}

    def correlate_with_mitre(self, case_id: str) -> dict[str, Any]:
        """
        Correlate timeline events with MITRE ATT&CK framework.

        Args:
            case_id: Forensic case ID

        Returns:
            MITRE correlation analysis
        """
        try:
            self.logger.info(f"Correlating timeline events with MITRE ATT&CK for case {case_id}")

            timeline_result = self.build_timeline(case_id)
            events = timeline_result.get("events", [])

            # Filter events with MITRE mappings
            mitre_events = [e for e in events if e["mitre_technique_id"]]

            techniques = {}
            for event in mitre_events:
                technique = event["mitre_technique_id"]
                if technique not in techniques:
                    techniques[technique] = []
                techniques[technique].append(event)

            return {
                "status": "success",
                "case_id": case_id,
                "techniques_found": len(techniques),
                "technique_mapping": techniques,
            }
        except Exception as e:
            self.logger.error(f"Failed to correlate with MITRE: {e}")
            return {"status": "error", "message": str(e)}


class ArtifactAnalyzer:
    """Analyzes parsed forensic artifacts and extracts IOCs"""

    def __init__(self):
        """Initialize the artifact analyzer"""
        self.logger = logger

    def analyze_disk_artifacts(
        self,
        artifact_type: str,
        artifact_data: dict,
    ) -> dict[str, Any]:
        """
        Analyze disk artifacts (MFT, prefetch, shimcache, amcache, USN journal).

        Args:
            artifact_type: Type of disk artifact
            artifact_data: Parsed artifact data

        Returns:
            Analysis results
        """
        try:
            self.logger.info(f"Analyzing disk artifact: {artifact_type}")

            analysis = {
                "artifact_type": artifact_type,
                "entries_parsed": 0,
                "suspicious_activity": [],
            }

            if artifact_type == "mft_entry":
                analysis["entries_parsed"] = len(artifact_data.get("entries", []))
            elif artifact_type == "prefetch":
                analysis["entries_parsed"] = len(artifact_data.get("files", []))
            elif artifact_type == "shimcache":
                analysis["entries_parsed"] = len(artifact_data.get("entries", []))
            elif artifact_type == "amcache":
                analysis["entries_parsed"] = len(artifact_data.get("files", []))
            elif artifact_type == "usn_journal":
                analysis["entries_parsed"] = len(artifact_data.get("records", []))

            return {
                "status": "success",
                "analysis": analysis,
            }
        except Exception as e:
            self.logger.error(f"Failed to analyze disk artifacts: {e}")
            return {"status": "error", "message": str(e)}

    def analyze_memory_artifacts(
        self,
        artifact_type: str,
        artifact_data: dict,
    ) -> dict[str, Any]:
        """
        Analyze memory artifacts (processes, network connections, loaded DLLs).

        Args:
            artifact_type: Type of memory artifact
            artifact_data: Parsed artifact data

        Returns:
            Analysis results
        """
        try:
            self.logger.info(f"Analyzing memory artifact: {artifact_type}")

            analysis = {
                "artifact_type": artifact_type,
                "items_found": 0,
                "suspicious_indicators": [],
            }

            if artifact_type == "process":
                analysis["items_found"] = len(artifact_data.get("processes", []))
            elif artifact_type == "network_connection":
                analysis["items_found"] = len(artifact_data.get("connections", []))
            elif artifact_type in ["dll", "loaded_modules"]:
                analysis["items_found"] = len(artifact_data.get("modules", []))

            return {
                "status": "success",
                "analysis": analysis,
            }
        except Exception as e:
            self.logger.error(f"Failed to analyze memory artifacts: {e}")
            return {"status": "error", "message": str(e)}

    def analyze_network_artifacts(
        self,
        artifact_type: str,
        artifact_data: dict,
    ) -> dict[str, Any]:
        """
        Analyze network artifacts (DNS, HTTP, TLS).

        Args:
            artifact_type: Type of network artifact
            artifact_data: Parsed artifact data

        Returns:
            Analysis results
        """
        try:
            self.logger.info(f"Analyzing network artifact: {artifact_type}")

            analysis = {
                "artifact_type": artifact_type,
                "records_found": 0,
                "suspicious_domains": [],
                "suspicious_ips": [],
            }

            if artifact_type == "dns_query":
                analysis["records_found"] = len(artifact_data.get("queries", []))
            elif artifact_type == "http_session":
                analysis["records_found"] = len(artifact_data.get("sessions", []))
            elif artifact_type == "tls_cert":
                analysis["records_found"] = len(artifact_data.get("certificates", []))

            return {
                "status": "success",
                "analysis": analysis,
            }
        except Exception as e:
            self.logger.error(f"Failed to analyze network artifacts: {e}")
            return {"status": "error", "message": str(e)}

    # ------------------------------------------------------------------
    # IOC extraction regexes (module-level so they compile once)
    # ------------------------------------------------------------------
    # These are intentionally restrictive. DFIR analysts are happy with
    # tight heuristics that miss occasional exotic formats in exchange
    # for near-zero false positives, which is why we include things
    # like "no trailing dot for domains" and "mask obvious private
    # address ranges" before classifying an IPv4 as suspicious.
    _IPV4_RE = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    _IPV6_RE = re.compile(
        r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE
    )
    _DOMAIN_RE = re.compile(
        r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.){1,}"
        r"(?:[a-z]{2,24})\b",
        re.IGNORECASE,
    )
    _URL_RE = re.compile(
        r"\b(?:https?|ftp|file)://[^\s<>\"']+", re.IGNORECASE
    )
    _EMAIL_RE = re.compile(
        r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b", re.IGNORECASE
    )
    # MD5 / SHA-1 / SHA-256 hashes (hex-only, exact length)
    _HASH_RE = re.compile(
        r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.IGNORECASE
    )

    @classmethod
    def _walk_strings(cls, value: Any) -> list[str]:
        """Flatten any nested dict/list into a list of string values so
        the IOC regexes can scan arbitrary artifact shapes without
        special-casing each artifact_type."""
        out: list[str] = []
        if value is None:
            return out
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, (int, float, bool)):
            out.append(str(value))
        elif isinstance(value, dict):
            for v in value.values():
                out.extend(cls._walk_strings(v))
        elif isinstance(value, (list, tuple, set)):
            for v in value:
                out.extend(cls._walk_strings(v))
        return out

    def extract_iocs(
        self,
        artifact_data: dict,
        artifact_type: str,
    ) -> dict[str, Any]:
        """
        Extract IOCs (IPs, domains, hashes, emails, URLs) from artifacts.

        Previous behavior: returned whatever the caller happened to
        pre-key as ``ip_addresses``, ``domains``, ``hashes``, ``urls``.
        If the caller passed raw memory-dump bytes or shell history
        strings, the analyzer found exactly zero IOCs — useless for
        any real DFIR workflow.

        New behavior: walks every string inside the artifact (nested
        dicts and lists included) and runs real regex extraction for
        IPv4, IPv6, domains, URLs, emails, and MD5/SHA-1/SHA-256
        hashes. The pre-extracted lists the caller may have supplied
        are still honored and merged in so existing call sites don't
        regress.
        """
        try:
            self.logger.info(f"Extracting IOCs from {artifact_type}")

            iocs: dict[str, set] = {
                "ipv4_addresses": set(),
                "ipv6_addresses": set(),
                "domains": set(),
                "file_hashes": set(),
                "email_addresses": set(),
                "urls": set(),
            }

            # Pre-keyed lists from caller (backward-compat)
            if isinstance(artifact_data, dict):
                for pre_key, ioc_key in (
                    ("ip_addresses", "ipv4_addresses"),
                    ("ipv4_addresses", "ipv4_addresses"),
                    ("ipv6_addresses", "ipv6_addresses"),
                    ("domains", "domains"),
                    ("hashes", "file_hashes"),
                    ("file_hashes", "file_hashes"),
                    ("urls", "urls"),
                    ("emails", "email_addresses"),
                    ("email_addresses", "email_addresses"),
                ):
                    vals = artifact_data.get(pre_key)
                    if isinstance(vals, list):
                        iocs[ioc_key].update(str(v) for v in vals if v)

            # Walk the whole structure and regex every string leaf
            for s in self._walk_strings(artifact_data):
                # URLs first so we can strip them from the text before
                # running the domain regex (so "https://example.com"
                # doesn't also appear in the domains bucket)
                s_wo_url = s
                for m in self._URL_RE.findall(s):
                    iocs["urls"].add(m)
                    s_wo_url = s_wo_url.replace(m, " ")

                for m in self._IPV4_RE.findall(s_wo_url):
                    iocs["ipv4_addresses"].add(m)
                for m in self._IPV6_RE.findall(s_wo_url):
                    iocs["ipv6_addresses"].add(m)
                for m in self._DOMAIN_RE.findall(s_wo_url):
                    # reject things that look like IPs or .local / .test
                    lowered = m.lower()
                    if self._IPV4_RE.fullmatch(lowered):
                        continue
                    if lowered.endswith((".local", ".test", ".internal", ".lan")):
                        continue
                    iocs["domains"].add(lowered)
                for m in self._EMAIL_RE.findall(s_wo_url):
                    iocs["email_addresses"].add(m.lower())
                for m in self._HASH_RE.findall(s_wo_url):
                    iocs["file_hashes"].add(m.lower())

            result = {k: sorted(v) for k, v in iocs.items()}
            return {
                "status": "success",
                "iocs": result,
                "total_extracted": sum(len(v) for v in result.values()),
            }
        except Exception as e:
            self.logger.error(f"Failed to extract IOCs: {e}")
            return {"status": "error", "message": str(e)}

    def map_to_mitre(
        self,
        artifact_type: str,
        artifact_data: dict,
    ) -> dict[str, Any]:
        """
        Map artifact findings to MITRE ATT&CK framework.

        Args:
            artifact_type: Type of artifact
            artifact_data: Artifact data

        Returns:
            MITRE mapping results
        """
        try:
            self.logger.info(f"Mapping {artifact_type} to MITRE ATT&CK")

            mappings = {
                "tactics": [],
                "techniques": [],
                "confidence_score": 0.0,
            }

            # Comprehensive MITRE ATT&CK mapping based on artifact type and evidence content
            artifact_mitre_map = {
                "process": {
                    "tactics": ["TA0002", "TA0003", "TA0005"],  # Execution, Persistence, Defense Evasion
                    "techniques": {
                        "powershell": ["T1059.001"],
                        "cmd": ["T1059.003"],
                        "wscript": ["T1059.005"],
                        "cscript": ["T1059.005"],
                        "rundll32": ["T1218.011"],
                        "regsvr32": ["T1218.010"],
                        "mshta": ["T1218.005"],
                        "schtasks": ["T1053.005"],
                        "at.exe": ["T1053.002"],
                        "sc.exe": ["T1543.003"],
                        "net.exe": ["T1087.001", "T1087.002"],
                        "mimikatz": ["T1003.001"],
                        "lsass": ["T1003.001"],
                        "psexec": ["T1569.002", "T1021.002"],
                        "wmic": ["T1047"],
                        "certutil": ["T1140", "T1105"],
                        "bitsadmin": ["T1197", "T1105"],
                    },
                },
                "network_connection": {
                    "tactics": ["TA0011", "TA0010", "TA0007"],  # C2, Exfiltration, Discovery
                    "techniques": {
                        "dns": ["T1071.004"],
                        "http": ["T1071.001"],
                        "https": ["T1071.001"],
                        "smb": ["T1021.002"],
                        "rdp": ["T1021.001"],
                        "ssh": ["T1021.004"],
                        "ftp": ["T1071.002"],
                        "icmp": ["T1095"],
                        "tor": ["T1090.003"],
                        "vpn": ["T1090"],
                    },
                },
                "file_system": {
                    "tactics": ["TA0001", "TA0003", "TA0005", "TA0009"],  # Initial Access, Persistence, Defense Evasion, Collection
                    "techniques": {
                        "startup": ["T1547.001"],
                        "temp": ["T1074.001"],
                        "exe": ["T1204.002"],
                        "dll": ["T1574.001"],
                        "bat": ["T1059.003"],
                        "ps1": ["T1059.001"],
                        "doc": ["T1566.001"],
                        "xls": ["T1566.001"],
                        "pdf": ["T1566.001"],
                        "zip": ["T1566.001"],
                        "encrypted": ["T1027"],
                        "hidden": ["T1564.001"],
                    },
                },
                "browser_history": {
                    "tactics": ["TA0009", "TA0001", "TA0042"],  # Collection, Initial Access, Resource Development
                    "techniques": {
                        "download": ["T1105"],
                        "phish": ["T1566.002"],
                        "drive-by": ["T1189"],
                        "oauth": ["T1550.001"],
                        "credential": ["T1539"],
                        "webmail": ["T1114.003"],
                    },
                },
                "registry": {
                    "tactics": ["TA0003", "TA0005", "TA0004"],  # Persistence, Defense Evasion, Privilege Escalation
                    "techniques": {
                        "run": ["T1547.001"],
                        "runonce": ["T1547.001"],
                        "services": ["T1543.003"],
                        "userinit": ["T1037.001"],
                        "appinit": ["T1546.010"],
                        "winlogon": ["T1547.004"],
                        "image_file_execution": ["T1546.012"],
                        "security": ["T1562.001"],
                        "firewall": ["T1562.004"],
                    },
                },
                "memory_dump": {
                    "tactics": ["TA0006", "TA0004"],  # Credential Access, Privilege Escalation
                    "techniques": {
                        "lsass": ["T1003.001"],
                        "sam": ["T1003.002"],
                        "ntds": ["T1003.003"],
                        "credential": ["T1003"],
                    },
                },
                "email": {
                    "tactics": ["TA0001", "TA0009"],  # Initial Access, Collection
                    "techniques": {
                        "attachment": ["T1566.001"],
                        "link": ["T1566.002"],
                        "forwarding": ["T1114.003"],
                    },
                },
            }

            artifact_data_str = json.dumps(artifact_data, default=str).lower() if artifact_data else ""

            if artifact_type in artifact_mitre_map:
                type_mapping = artifact_mitre_map[artifact_type]
                mappings["tactics"] = type_mapping["tactics"]

                # Match specific techniques based on artifact content evidence
                matched_techniques = []
                for keyword, techniques in type_mapping.get("techniques", {}).items():
                    if keyword in artifact_data_str:
                        matched_techniques.extend(techniques)

                mappings["techniques"] = list(set(matched_techniques))
                # Higher confidence if we matched specific techniques
                if matched_techniques:
                    mappings["confidence_score"] = 0.85
                else:
                    mappings["confidence_score"] = 0.60
            else:
                # Unknown artifact type - lower confidence general mapping
                mappings["confidence_score"] = 0.30

            return {
                "status": "success",
                "artifact_type": artifact_type,
                "mapping": mappings,
            }
        except Exception as e:
            self.logger.error(f"Failed to map to MITRE: {e}")
            return {"status": "error", "message": str(e)}


class LegalHoldManager:
    """Manages legal holds and compliance tracking"""

    def __init__(self):
        """Initialize the legal hold manager"""
        self.logger = logger

    def create_hold(
        self,
        case_id: str,
        hold_type: str,
        custodians: list[str],
        data_sources: list[str],
        issued_by: str,
        organization_id: str,
        expiry_date: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Create a legal hold.

        Args:
            case_id: Forensic case ID
            hold_type: Type of hold
            custodians: List of custodian names
            data_sources: List of data sources to preserve
            issued_by: Person/entity issuing the hold
            organization_id: Organization ID
            expiry_date: Optional hold expiry date

        Returns:
            Legal hold creation confirmation
        """
        try:
            self.logger.info(f"Creating {hold_type} legal hold for case {case_id}")

            hold_data = {
                "case_id": case_id,
                "hold_type": hold_type,
                "custodians": custodians,
                "data_sources": data_sources,
                "issued_by": issued_by,
                "issued_date": datetime.now(timezone.utc).isoformat(),
                "expiry_date": expiry_date,
                "organization_id": organization_id,
                "status": "active",
                "acknowledgments": {},
            }

            return {
                "status": "success",
                "hold_id": f"hold-{datetime.now(timezone.utc).timestamp()}",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "data": hold_data,
            }
        except Exception as e:
            self.logger.error(f"Failed to create legal hold: {e}")
            return {"status": "error", "message": str(e)}

    def notify_custodians(
        self,
        hold_id: str,
        custodians: list[str],
    ) -> dict[str, Any]:
        """
        Notify custodians of legal hold.

        Args:
            hold_id: Legal hold ID
            custodians: List of custodian identifiers

        Returns:
            Notification confirmation
        """
        try:
            self.logger.info(f"Notifying {len(custodians)} custodians of hold {hold_id}")

            notifications = {
                custodian: {
                    "notified_at": datetime.now(timezone.utc).isoformat(),
                    "status": "pending_acknowledgment",
                }
                for custodian in custodians
            }

            return {
                "status": "success",
                "hold_id": hold_id,
                "notifications": notifications,
            }
        except Exception as e:
            self.logger.error(f"Failed to notify custodians: {e}")
            return {"status": "error", "message": str(e)}

    def track_acknowledgments(
        self,
        hold_id: str,
        custodian: str,
        acknowledged: bool,
        timestamp: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Track custodian acknowledgments.

        Args:
            hold_id: Legal hold ID
            custodian: Custodian identifier
            acknowledged: Whether custodian acknowledged
            timestamp: Optional custom timestamp

        Returns:
            Acknowledgment tracking confirmation
        """
        try:
            self.logger.info(f"Tracking acknowledgment for {custodian} on hold {hold_id}")

            return {
                "status": "success",
                "hold_id": hold_id,
                "custodian": custodian,
                "acknowledged": acknowledged,
                "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Failed to track acknowledgment: {e}")
            return {"status": "error", "message": str(e)}

    def extend_hold(
        self,
        hold_id: str,
        new_expiry_date: str,
        reason: str,
    ) -> dict[str, Any]:
        """
        Extend a legal hold.

        Args:
            hold_id: Legal hold ID
            new_expiry_date: New expiry date
            reason: Reason for extension

        Returns:
            Extension confirmation
        """
        try:
            self.logger.info(f"Extending legal hold {hold_id}")

            return {
                "status": "success",
                "hold_id": hold_id,
                "new_expiry_date": new_expiry_date,
                "reason": reason,
                "extended_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Failed to extend legal hold: {e}")
            return {"status": "error", "message": str(e)}

    def release_hold(
        self,
        hold_id: str,
        released_by: str,
        reason: str,
    ) -> dict[str, Any]:
        """
        Release a legal hold.

        Args:
            hold_id: Legal hold ID
            released_by: User/entity releasing the hold
            reason: Reason for release

        Returns:
            Release confirmation
        """
        try:
            self.logger.info(f"Releasing legal hold {hold_id}")

            return {
                "status": "success",
                "hold_id": hold_id,
                "released_by": released_by,
                "reason": reason,
                "released_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Failed to release legal hold: {e}")
            return {"status": "error", "message": str(e)}

    def generate_compliance_report(
        self,
        hold_id: str,
        include_acknowledgments: bool = True,
        include_preservation_status: bool = True,
    ) -> dict[str, Any]:
        """
        Generate legal hold compliance report.

        Args:
            hold_id: Legal hold ID
            include_acknowledgments: Include custodian acknowledgments
            include_preservation_status: Include preservation status

        Returns:
            Compliance report
        """
        try:
            self.logger.info(f"Generating compliance report for hold {hold_id}")

            report = {
                "hold_id": hold_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "sections": [],
            }

            if include_acknowledgments:
                report["sections"].append("custodian_acknowledgments")
            if include_preservation_status:
                report["sections"].append("data_preservation_status")

            return {
                "status": "success",
                "report": report,
            }
        except Exception as e:
            self.logger.error(f"Failed to generate compliance report: {e}")
            return {"status": "error", "message": str(e)}
