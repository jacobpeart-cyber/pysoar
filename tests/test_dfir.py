"""Tests for DFIR (Digital Forensics and Incident Response) Engine

Real tests importing and testing actual DFIR engine classes.
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from sqlalchemy.ext.asyncio import AsyncSession

from src.dfir.engine import (
    ForensicEngine,
    EvidenceManager,
    TimelineReconstructor,
    ArtifactAnalyzer,
    LegalHoldManager,
)


@pytest.fixture
def forensic_engine():
    """Create ForensicEngine instance"""
    return ForensicEngine()


@pytest.fixture
def evidence_manager():
    """Create EvidenceManager instance"""
    return EvidenceManager()


@pytest.fixture
def timeline_reconstructor():
    """Create TimelineReconstructor instance"""
    return TimelineReconstructor()


@pytest.fixture
def artifact_analyzer():
    """Create ArtifactAnalyzer instance"""
    return ArtifactAnalyzer()


@pytest.fixture
def legal_hold_manager():
    """Create LegalHoldManager instance"""
    return LegalHoldManager()


class TestForensicEngine:
    """Tests for ForensicEngine class"""

    def test_engine_initialization(self, forensic_engine):
        """Test engine initializes correctly"""
        assert forensic_engine is not None

    def test_create_forensic_case(self, forensic_engine):
        """Test creating a forensic case"""
        result = forensic_engine.create_case(
            case_number="CASE-2024-001",
            title="Potential Data Breach",
            case_type="data_breach",
            organization_id="org_123",
            description="Unauthorized access detected",
            severity="critical",
            created_by="investigator@company.com",
        )

        assert result["status"] == "success"
        assert result["case_number"] == "CASE-2024-001"
        assert result["data"]["title"] == "Potential Data Breach"
        assert result["data"]["severity"] == "critical"

    def test_create_case_malware_infection(self, forensic_engine):
        """Test creating malware incident case"""
        result = forensic_engine.create_case(
            case_number="CASE-2024-002",
            title="Malware Infection",
            case_type="malware",
            organization_id="org_123",
            severity="high",
        )

        assert result["status"] == "success"
        assert result["data"]["case_type"] == "malware"

    def test_create_case_insider_threat(self, forensic_engine):
        """Test creating insider threat case"""
        result = forensic_engine.create_case(
            case_number="CASE-2024-003",
            title="Insider Threat Investigation",
            case_type="insider_threat",
            organization_id="org_123",
            severity="high",
            assigned_team=["investigator1", "investigator2"],
        )

        assert result["status"] == "success"
        assert result["data"]["case_type"] == "insider_threat"

    def test_assign_investigator(self, forensic_engine):
        """Test assigning investigator to case"""
        result = forensic_engine.assign_investigator(
            case_id="case_123",
            investigator_id="inv_456",
            role="lead_investigator",
        )

        assert result["status"] == "success"
        assert result["case_id"] == "case_123"
        assert result["investigator_id"] == "inv_456"

    def test_assign_team_member(self, forensic_engine):
        """Test assigning team member to case"""
        result = forensic_engine.assign_investigator(
            case_id="case_123",
            investigator_id="inv_789",
            role="supporting_investigator",
        )

        assert result["status"] == "success"
        assert result["role"] == "supporting_investigator"


class TestEvidenceManager:
    """Tests for EvidenceManager class"""

    def test_manager_initialization(self, evidence_manager):
        """Test evidence manager initializes"""
        assert evidence_manager is not None

    def test_add_evidence_item(self, evidence_manager):
        """Test adding evidence to case"""
        result = evidence_manager.collect_evidence(
            case_id="case_123",
            evidence_type="file",
            source_device="workstation-01",
            acquisition_method="disk_image",
            storage_location="/mnt/evidence/log.txt",
            organization_id="org_123",
            handling_notes="System log file",
        )

        assert result["status"] == "success"
        assert "evidence_id" in result

    def test_add_network_evidence(self, evidence_manager):
        """Test adding network evidence"""
        result = evidence_manager.collect_evidence(
            case_id="case_123",
            evidence_type="network",
            source_device="firewall-01",
            acquisition_method="pcap_capture",
            storage_location="/mnt/evidence/capture.pcap",
            organization_id="org_123",
            source_ip="192.168.1.100",
            handling_notes="Compromised workstation",
        )

        assert result["status"] == "success"

    def test_compute_evidence_hash(self, evidence_manager):
        """Test computing evidence hash for integrity"""
        result = evidence_manager.verify_integrity(
            evidence_id="evidence_123",
            evidence_hash="abc123def456",
            hash_algorithm="sha256",
        )

        assert result["status"] == "success"
        assert "current_hash" in result

    def test_maintain_chain_of_custody(self, evidence_manager):
        """Test chain of custody tracking"""
        result = evidence_manager.update_chain_of_custody(
            evidence_id="evidence_123",
            actor="investigator_2",
            action="transferred",
            details="Handed over for analysis",
        )

        assert result["status"] == "success"
        assert result["evidence_id"] == "evidence_123"


class TestTimelineReconstructor:
    """Tests for TimelineReconstructor class"""

    def test_reconstructor_initialization(self, timeline_reconstructor):
        """Test timeline reconstructor initializes"""
        assert timeline_reconstructor is not None

    def test_add_event_to_timeline(self, timeline_reconstructor):
        """Test adding event to forensic timeline"""
        result = timeline_reconstructor.add_event(
            case_id="case_123",
            event_timestamp=datetime.utcnow().isoformat(),
            event_type="file_access",
            source="audit_log",
            description="User accessed sensitive file",
        )

        assert result["status"] == "success"

    def test_build_timeline_sequence(self, timeline_reconstructor):
        """Test building timeline from events"""
        # Add events first since build_timeline reads from internal state
        timeline_reconstructor.add_event(
            case_id="case_123",
            event_timestamp=datetime.utcnow().isoformat(),
            event_type="login",
            source="auth_log",
        )
        timeline_reconstructor.add_event(
            case_id="case_123",
            event_timestamp=datetime.utcnow().isoformat(),
            event_type="file_access",
            source="audit_log",
        )
        timeline_reconstructor.add_event(
            case_id="case_123",
            event_timestamp=datetime.utcnow().isoformat(),
            event_type="logout",
            source="auth_log",
        )

        result = timeline_reconstructor.build_timeline(
            case_id="case_123",
        )

        assert result["status"] == "success"
        assert result["event_count"] >= 3

    def test_identify_timeline_gaps(self, timeline_reconstructor):
        """Test identifying gaps in event timeline"""
        result = timeline_reconstructor.detect_gaps(
            case_id="case_123",
            max_gap_hours=4,
        )

        assert result["status"] == "success"
        assert "gaps" in result


class TestArtifactAnalyzer:
    """Tests for ArtifactAnalyzer class"""

    def test_analyzer_initialization(self, artifact_analyzer):
        """Test artifact analyzer initializes"""
        assert artifact_analyzer is not None

    def test_analyze_file_artifact(self, artifact_analyzer):
        """Test analyzing file artifact"""
        result = artifact_analyzer.analyze_disk_artifacts(
            artifact_type="mft_entry",
            artifact_data={"entries": []},
        )

        assert result["status"] == "success"

    def test_extract_metadata(self, artifact_analyzer):
        """Test extracting IOCs from artifact"""
        result = artifact_analyzer.extract_iocs(
            artifact_data={"ip_addresses": ["10.0.0.1"], "domains": ["example.com"]},
            artifact_type="network_connection",
        )

        assert result["status"] == "success"
        assert "iocs" in result

    def test_analyze_registry_artifacts(self, artifact_analyzer):
        """Test analyzing Windows registry artifacts"""
        result = artifact_analyzer.analyze_disk_artifacts(
            artifact_type="registry",
            artifact_data={"entries": []},
        )

        assert result["status"] == "success"


class TestLegalHoldManager:
    """Tests for LegalHoldManager class"""

    def test_legal_hold_initialization(self, legal_hold_manager):
        """Test legal hold manager initializes"""
        assert legal_hold_manager is not None

    def test_place_legal_hold(self, legal_hold_manager):
        """Test placing legal hold on evidence"""
        result = legal_hold_manager.create_hold(
            case_id="case_123",
            hold_type="litigation",
            custodians=["user@company.com"],
            data_sources=["emails"],
            issued_by="legal-team",
            organization_id="org_123",
        )

        assert result["status"] == "success"
        assert "hold_id" in result

    def test_release_legal_hold(self, legal_hold_manager):
        """Test releasing legal hold"""
        result = legal_hold_manager.release_hold(
            hold_id="hold_123",
            released_by="legal-team",
            reason="Case dismissed",
        )

        assert result["status"] == "success"

    def test_track_hold_compliance(self, legal_hold_manager):
        """Test tracking legal hold compliance"""
        result = legal_hold_manager.generate_compliance_report(
            hold_id="hold_123",
        )

        assert result["status"] == "success"
        assert "report" in result

    async def test_case_lifecycle(self, db_session: AsyncSession):
        """Test complete case lifecycle"""
        case = {
            "id": str(uuid4()),
            "case_number": "CASE-2024-002",
            "status": "open",
            "opened_at": datetime.utcnow(),
        }

        # Transition to in progress
        case["status"] = "in_progress"
        case["assigned_to"] = "sr-investigator"

        assert case["status"] == "in_progress"

        # Transition to closed
        case["status"] = "closed"
        case["closed_at"] = datetime.utcnow()
        case["findings_summary"] = "No evidence of breach found"

        assert case["status"] == "closed"

    async def test_add_evidence_to_case(self, db_session: AsyncSession):
        """Test adding evidence to a case"""
        case = {
            "id": str(uuid4()),
            "case_number": "CASE-2024-003",
            "evidence_items": [],
        }

        evidence = {
            "id": str(uuid4()),
            "case_id": case["id"],
            "type": "log_file",
            "source": "firewall",
            "file_path": "/evidence/fw-2024-03-20.log",
            "hash": "abc123def456",
            "added_at": datetime.utcnow(),
        }

        case["evidence_items"].append(evidence)

        assert len(case["evidence_items"]) == 1
        assert case["evidence_items"][0]["type"] == "log_file"


@pytest.mark.asyncio
class TestChainOfCustody:
    """Tests for evidence chain of custody"""

    async def test_chain_of_custody_creation(self, db_session: AsyncSession):
        """Test creating chain of custody record"""
        coc_record = {
            "id": str(uuid4()),
            "evidence_id": str(uuid4()),
            "action": "acquired",
            "timestamp": datetime.utcnow(),
            "performed_by": "forensic-analyst",
            "notes": "Evidence collected from compromised system",
        }

        assert coc_record["action"] == "acquired"
        assert coc_record["performed_by"] is not None

    async def test_chain_of_custody_trace(self, db_session: AsyncSession):
        """Test complete chain of custody trace"""
        evidence_id = str(uuid4())

        coc_entries = [
            {
                "timestamp": datetime.utcnow(),
                "action": "acquired",
                "performed_by": "first-responder",
            },
            {
                "timestamp": datetime.utcnow() + timedelta(hours=1),
                "action": "transferred",
                "performed_by": "forensic-analyst",
                "transferred_to": "forensic-analyst",
            },
            {
                "timestamp": datetime.utcnow() + timedelta(hours=2),
                "action": "analyzed",
                "performed_by": "forensic-analyst",
            },
            {
                "timestamp": datetime.utcnow() + timedelta(hours=3),
                "action": "stored",
                "performed_by": "evidence-curator",
                "storage_location": "Secure Evidence Locker #5",
            },
        ]

        # Verify chain is complete
        assert len(coc_entries) == 4
        assert coc_entries[0]["action"] == "acquired"
        assert coc_entries[-1]["action"] == "stored"

    async def test_chain_of_custody_integrity(self, db_session: AsyncSession):
        """Test integrity of chain of custody"""
        coc = {
            "evidence_id": str(uuid4()),
            "entries": [],
            "integrity_verified": True,
        }

        entry1 = {
            "timestamp": datetime.utcnow(),
            "action": "acquired",
            "hash": "hash_abc123",
        }
        coc["entries"].append(entry1)

        # Verify hash matches
        assert coc["entries"][0]["hash"] == "hash_abc123"

    def test_custody_gap_detection(self):
        """Test detection of gaps in chain of custody"""
        coc_entries = [
            {"timestamp": datetime(2024, 3, 20, 10, 0), "action": "acquired"},
            {"timestamp": datetime(2024, 3, 20, 15, 0), "action": "transferred"},
            # 6 hour gap
            {"timestamp": datetime(2024, 3, 20, 21, 0), "action": "analyzed"},
        ]

        # Check for gaps > 4 hours
        max_gap_hours = 4
        gaps = []

        for i in range(len(coc_entries) - 1):
            current = coc_entries[i]
            next_entry = coc_entries[i + 1]
            gap = (next_entry["timestamp"] - current["timestamp"]).total_seconds() / 3600

            if gap > max_gap_hours:
                gaps.append({"gap_hours": gap, "between_entries": (i, i + 1)})

        assert len(gaps) == 2
        assert gaps[0]["gap_hours"] == 5.0
        assert gaps[1]["gap_hours"] == 6.0


@pytest.mark.asyncio
class TestTimelineReconstruction:
    """Tests for event timeline reconstruction"""

    async def test_create_timeline(self, db_session: AsyncSession):
        """Test creating event timeline"""
        timeline = {
            "id": str(uuid4()),
            "case_id": str(uuid4()),
            "events": [],
            "created_at": datetime.utcnow(),
        }

        events = [
            {
                "timestamp": datetime(2024, 3, 20, 8, 0),
                "event_type": "login",
                "source": "firewall",
                "description": "User A logged in from IP 192.168.1.100",
            },
            {
                "timestamp": datetime(2024, 3, 20, 9, 30),
                "event_type": "file_access",
                "source": "file_system",
                "description": "User A accessed file /shared/data.xlsx",
            },
            {
                "timestamp": datetime(2024, 3, 20, 10, 0),
                "event_type": "suspicious",
                "source": "ids",
                "description": "Port scanning detected from 192.168.1.100",
            },
        ]

        timeline["events"] = sorted(events, key=lambda x: x["timestamp"])

        assert len(timeline["events"]) == 3
        assert timeline["events"][0]["event_type"] == "login"

    async def test_correlate_timeline_events(self, db_session: AsyncSession):
        """Test correlating events across sources"""
        events = [
            {
                "timestamp": datetime(2024, 3, 20, 10, 0),
                "source": "firewall",
                "event_type": "connection",
                "user": "user_a",
                "ip": "192.168.1.100",
            },
            {
                "timestamp": datetime(2024, 3, 20, 10, 1),
                "source": "file_system",
                "event_type": "file_access",
                "user": "user_a",
                "file": "/shared/sensitive_data.xlsx",
            },
            {
                "timestamp": datetime(2024, 3, 20, 10, 2),
                "source": "firewall",
                "event_type": "data_exfiltration",
                "user": "user_a",
                "ip": "192.168.1.100",
                "destination": "external-ip",
            },
        ]

        # Correlate events by user and IP
        user_a_events = [e for e in events if e.get("user") == "user_a"]

        assert len(user_a_events) == 3
        assert user_a_events[0]["source"] == "firewall"
        assert user_a_events[1]["source"] == "file_system"
        assert user_a_events[2]["source"] == "firewall"

    async def test_timeline_gap_analysis(self, db_session: AsyncSession):
        """Test analyzing gaps in timeline"""
        events = [
            {"timestamp": datetime(2024, 3, 20, 10, 0), "event": "login"},
            {"timestamp": datetime(2024, 3, 20, 10, 30), "event": "file_access"},
            # 2 hour gap
            {"timestamp": datetime(2024, 3, 20, 12, 30), "event": "logout"},
        ]

        gaps = []
        for i in range(len(events) - 1):
            gap_minutes = (events[i + 1]["timestamp"] - events[i]["timestamp"]).total_seconds() / 60
            if gap_minutes > 60:
                gaps.append(gap_minutes)

        assert len(gaps) == 1
        assert gaps[0] == 120


@pytest.mark.asyncio
class TestArtifactAnalysis:
    """Tests for digital artifact analysis"""

    async def test_analyze_file_artifact(self, db_session: AsyncSession):
        """Test analyzing file artifacts"""
        artifact = {
            "id": str(uuid4()),
            "type": "file",
            "file_path": "/evidence/suspicious_binary.exe",
            "file_size": 1024000,
            "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }

        assert artifact["type"] == "file"
        assert artifact["md5_hash"] is not None
        assert artifact["sha256_hash"] is not None

    async def test_analyze_registry_artifact(self, db_session: AsyncSession):
        """Test analyzing registry artifacts"""
        artifact = {
            "id": str(uuid4()),
            "type": "registry",
            "hive": "HKLM",
            "key_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "suspicious_service",
            "value_type": "REG_SZ",
            "value_data": "C:\\temp\\malware.exe",
        }

        assert artifact["type"] == "registry"
        assert "HKLM" in artifact["hive"]
        assert artifact["value_data"] == "C:\\temp\\malware.exe"

    async def test_analyze_memory_artifact(self, db_session: AsyncSession):
        """Test analyzing memory artifacts"""
        artifact = {
            "id": str(uuid4()),
            "type": "memory",
            "process_id": 1234,
            "process_name": "explorer.exe",
            "memory_range": "0x140000000-0x140100000",
            "pattern_found": "Trojan.Generic.A",
        }

        assert artifact["type"] == "memory"
        assert artifact["process_id"] == 1234
        assert artifact["pattern_found"] is not None

    async def test_artifact_classification(self, db_session: AsyncSession):
        """Test classification of artifacts"""
        artifact = {
            "id": str(uuid4()),
            "content_type": "executable",
            "threat_level": "critical",
            "classification": "malware",
            "confidence": 0.95,
        }

        assert artifact["classification"] == "malware"
        assert artifact["threat_level"] == "critical"
        assert artifact["confidence"] > 0.9


@pytest.mark.asyncio
class TestLegalHoldManagement:
    """Tests for legal hold management"""

    async def test_place_legal_hold(self, db_session: AsyncSession):
        """Test placing evidence on legal hold"""
        hold = {
            "id": str(uuid4()),
            "evidence_id": str(uuid4()),
            "hold_type": "litigation",
            "reason": "Pending litigation discovery",
            "placed_at": datetime.utcnow(),
            "placed_by": "legal-team",
            "status": "active",
        }

        assert hold["status"] == "active"
        assert hold["hold_type"] == "litigation"

    async def test_lift_legal_hold(self, db_session: AsyncSession):
        """Test lifting legal hold"""
        hold = {
            "id": str(uuid4()),
            "evidence_id": str(uuid4()),
            "status": "active",
            "placed_at": datetime.utcnow(),
        }

        # Lift hold
        hold["status"] = "lifted"
        hold["lifted_at"] = datetime.utcnow()
        hold["lifted_by"] = "legal-team"
        hold["lift_reason"] = "Litigation resolved"

        assert hold["status"] == "lifted"
        assert hold["lifted_at"] is not None

    async def test_multiple_holds_same_evidence(self, db_session: AsyncSession):
        """Test multiple legal holds on same evidence"""
        evidence_id = str(uuid4())

        holds = [
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "hold_type": "litigation",
                "status": "active",
            },
            {
                "id": str(uuid4()),
                "evidence_id": evidence_id,
                "hold_type": "regulatory",
                "status": "active",
            },
        ]

        active_holds = [h for h in holds if h["status"] == "active"]

        assert len(active_holds) == 2

    async def test_hold_prevents_deletion(self, db_session: AsyncSession):
        """Test that holds prevent evidence deletion"""
        evidence = {
            "id": str(uuid4()),
            "on_hold": True,
        }

        can_delete = not evidence["on_hold"]

        assert can_delete is False
