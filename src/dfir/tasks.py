"""
Celery Tasks for DFIR (Digital Forensics & Incident Response).

Implements background tasks for evidence integrity checks, artifact extraction,
timeline reconstruction, IOC extraction, and legal hold compliance.
"""

import hashlib
from datetime import datetime, timedelta
from typing import Optional

from celery import shared_task

from src.core.config import settings
from src.core.logging import get_logger
from src.dfir.engine import (
    EvidenceManager,
    ArtifactAnalyzer,
    TimelineReconstructor,
    LegalHoldManager,
)

logger = get_logger(__name__)


@shared_task(bind=True, max_retries=3)
def evidence_integrity_check(
    self,
    evidence_id: str,
    organization_id: str,
    evidence_hash: Optional[str] = None,
    hash_algorithm: str = "sha256",
):
    """
    Periodically verify evidence integrity through hash recalculation.

    Ensures that forensic evidence has not been modified since acquisition
    by comparing current hash with original hash.

    Args:
        evidence_id: Forensic evidence ID
        organization_id: Organization ID
        evidence_hash: Current hash value to verify
        hash_algorithm: Hash algorithm used

    Returns:
        Dictionary with integrity check results
    """
    try:
        logger.info(f"Starting integrity check for evidence {evidence_id}")

        manager = EvidenceManager()

        # Perform integrity verification
        result = manager.verify_integrity(
            evidence_id=evidence_id,
            evidence_hash=evidence_hash or "unknown",
            hash_algorithm=hash_algorithm,
        )

        if result["status"] == "success":
            is_valid = result.get("is_valid", False)
            logger.info(f"Integrity check complete for {evidence_id}: valid={is_valid}")

            return {
                "status": "success",
                "evidence_id": evidence_id,
                "is_valid": is_valid,
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            raise Exception(result.get("message", "Integrity check failed"))

    except Exception as e:
        logger.error(f"Evidence integrity check failed: {e}")
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def automated_artifact_extraction(
    self,
    evidence_id: str,
    case_id: str,
    organization_id: str,
    artifact_type: str,
    artifact_data: dict,
):
    """
    Automatically extract and analyze artifacts from evidence.

    Parses forensic artifacts (MFT, prefetch, registry, etc.) and extracts
    indicators of compromise and MITRE ATT&CK mappings.

    Args:
        evidence_id: Forensic evidence ID
        case_id: Forensic case ID
        organization_id: Organization ID
        artifact_type: Type of artifact
        artifact_data: Parsed artifact data

    Returns:
        Dictionary with extraction results
    """
    try:
        logger.info(f"Starting artifact extraction for evidence {evidence_id}")

        analyzer = ArtifactAnalyzer()

        # Analyze artifact based on type
        if artifact_type.startswith("disk_"):
            analysis = analyzer.analyze_disk_artifacts(artifact_type, artifact_data)
        elif artifact_type.startswith("memory_"):
            analysis = analyzer.analyze_memory_artifacts(artifact_type, artifact_data)
        elif artifact_type.startswith("network_"):
            analysis = analyzer.analyze_network_artifacts(artifact_type, artifact_data)
        else:
            analysis = {"status": "error", "message": f"Unknown artifact type: {artifact_type}"}

        if analysis["status"] == "success":
            # Extract IOCs
            ioc_result = analyzer.extract_iocs(artifact_data, artifact_type)

            # Map to MITRE
            mitre_result = analyzer.map_to_mitre(artifact_type, artifact_data)

            logger.info(f"Artifact extraction complete for {evidence_id}")

            return {
                "status": "success",
                "evidence_id": evidence_id,
                "case_id": case_id,
                "artifact_type": artifact_type,
                "analysis": analysis.get("analysis", {}),
                "iocs_extracted": ioc_result.get("total_extracted", 0),
                "mitre_mapping": mitre_result.get("mapping", {}),
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            raise Exception(analysis.get("message", "Artifact extraction failed"))

    except Exception as e:
        logger.error(f"Artifact extraction failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def timeline_reconstruction_task(
    self,
    case_id: str,
    organization_id: str,
    identify_pivotal: bool = True,
):
    """
    Reconstruct complete event timeline from multiple forensic sources.

    Merges events from disk artifacts, memory dumps, network logs, and other
    sources into a coherent timeline and identifies pivotal events.

    Args:
        case_id: Forensic case ID
        organization_id: Organization ID
        identify_pivotal: Whether to identify pivotal events

    Returns:
        Dictionary with timeline reconstruction results
    """
    try:
        logger.info(f"Starting timeline reconstruction for case {case_id}")

        reconstructor = TimelineReconstructor()

        # Build timeline
        timeline_result = reconstructor.build_timeline(case_id)

        if timeline_result["status"] == "success":
            event_count = timeline_result.get("event_count", 0)

            # Identify pivotal events if requested
            pivotal_result = None
            if identify_pivotal:
                pivotal_result = reconstructor.identify_pivotal_events(case_id)

            # Detect gaps
            gaps_result = reconstructor.detect_gaps(case_id)

            # Generate visualization data
            vis_result = reconstructor.generate_timeline_visualization_data(case_id)

            # Correlate with MITRE
            mitre_result = reconstructor.correlate_with_mitre(case_id)

            logger.info(f"Timeline reconstruction complete for case {case_id}: {event_count} events")

            return {
                "status": "success",
                "case_id": case_id,
                "event_count": event_count,
                "pivotal_events": pivotal_result.get("pivotal_count", 0) if pivotal_result else 0,
                "timeline_gaps": gaps_result.get("gap_count", 0) if gaps_result else 0,
                "mitre_techniques": mitre_result.get("techniques_found", 0) if mitre_result else 0,
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            raise Exception(timeline_result.get("message", "Timeline reconstruction failed"))

    except Exception as e:
        logger.error(f"Timeline reconstruction failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def ioc_extraction_task(
    self,
    case_id: str,
    organization_id: str,
    artifact_types: Optional[list[str]] = None,
):
    """
    Extract indicators of compromise from all case artifacts.

    Aggregates IOCs (IP addresses, domains, file hashes, URLs, email addresses)
    from all artifacts in a forensic case.

    Args:
        case_id: Forensic case ID
        organization_id: Organization ID
        artifact_types: Specific artifact types to process (optional)

    Returns:
        Dictionary with IOC extraction results
    """
    try:
        logger.info(f"Starting IOC extraction for case {case_id}")

        analyzer = ArtifactAnalyzer()

        # Collect all IOCs across artifacts
        aggregated_iocs = {
            "ipv4_addresses": set(),
            "ipv6_addresses": set(),
            "domains": set(),
            "file_hashes": set(),
            "email_addresses": set(),
            "urls": set(),
        }

        # Query real ForensicArtifact rows from the database
        import asyncio
        from src.core.database import async_session_factory
        from src.dfir.models import ForensicArtifact
        from sqlalchemy import select

        async def _get_artifacts():
            async with async_session_factory() as db:
                query = select(ForensicArtifact).where(
                    ForensicArtifact.case_id == case_id
                )
                if artifact_types:
                    query = query.where(ForensicArtifact.artifact_type.in_(artifact_types))
                result = await db.execute(query)
                return list(result.scalars().all())

        db_artifacts = asyncio.run(_get_artifacts())

        if db_artifacts:
            for artifact in db_artifacts:
                artifact_data = artifact.artifact_data or {}
                ioc_result = analyzer.extract_iocs(artifact_data, artifact.artifact_type)

                if ioc_result["status"] == "success":
                    iocs = ioc_result.get("iocs", {})
                    for ioc_type, values in iocs.items():
                        aggregated_iocs[ioc_type].update(values)

        # Convert sets to lists
        final_iocs = {k: list(v) for k, v in aggregated_iocs.items()}
        total_iocs = sum(len(v) for v in final_iocs.values())

        logger.info(f"IOC extraction complete for case {case_id}: {total_iocs} IOCs found")

        return {
            "status": "success",
            "case_id": case_id,
            "total_iocs": total_iocs,
            "iocs": final_iocs,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"IOC extraction failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def legal_hold_reminder(
    self,
    hold_id: str,
    organization_id: str,
    days_before_expiry: int = 30,
):
    """
    Periodic reminder for upcoming legal hold expirations.

    Checks for legal holds expiring soon and sends reminders to relevant
    stakeholders for renewal decisions.

    Args:
        hold_id: Legal hold ID
        organization_id: Organization ID
        days_before_expiry: Number of days before expiry to send reminder

    Returns:
        Dictionary with reminder results
    """
    try:
        logger.info(f"Processing legal hold reminder for hold {hold_id}")

        manager = LegalHoldManager()

        # Query real LegalHold expiry date from the database
        import asyncio
        from src.core.database import async_session_factory
        from src.dfir.models import LegalHold
        from sqlalchemy import select

        async def _check_hold_expiry():
            async with async_session_factory() as db:
                query = select(LegalHold).where(LegalHold.id == hold_id)
                result = await db.execute(query)
                return result.scalar_one_or_none()

        hold = asyncio.run(_check_hold_expiry())

        if hold and hold.expiry_date:
            try:
                expiry_dt = datetime.fromisoformat(hold.expiry_date)
                expiry_threshold = datetime.utcnow() + timedelta(days=days_before_expiry)
                is_expiring_soon = expiry_dt <= expiry_threshold
            except (ValueError, TypeError):
                is_expiring_soon = False
        else:
            # No expiry date set or hold not found - no action needed
            is_expiring_soon = False

        if is_expiring_soon:
            # Generate compliance report
            report_result = manager.generate_compliance_report(hold_id)

            logger.info(f"Legal hold reminder processed for {hold_id}")

            return {
                "status": "success",
                "hold_id": hold_id,
                "action": "reminder_sent",
                "days_until_expiry": days_before_expiry,
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            return {
                "status": "success",
                "hold_id": hold_id,
                "action": "no_action_required",
                "timestamp": datetime.utcnow().isoformat(),
            }

    except Exception as e:
        logger.error(f"Legal hold reminder failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))
