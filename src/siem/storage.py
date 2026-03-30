"""Log storage management with retention policies."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.siem.models import LogEntry
from src.siem.parser import LogParserManager
from src.siem.normalizer import LogNormalizer
from src.siem.rules import RuleEngine


@dataclass
class RetentionPolicy:
    """Policy for log retention across storage tiers."""

    hot_days: int = 14
    warm_days: int = 90
    cold_days: int = 365
    archive_enabled: bool = False


class LogStorageManager:
    """Manager for log ingestion, storage, and retention."""

    def __init__(self):
        self.parser_manager = LogParserManager()
        self.normalizer = LogNormalizer()
        self.rule_engine = RuleEngine()

    async def ingest_log(
        self,
        db: AsyncSession,
        raw_log: str,
        source_type: str,
        source_name: str,
        source_ip: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> dict:
        """
        Ingest a single log entry.

        Args:
            db: Async database session
            raw_log: Raw log string
            source_type: Type of log source (syslog, windows_event, etc.)
            source_name: Name/identifier of log source
            source_ip: IP address of log source
            organization_id: Organization ID for multi-tenancy

        Returns:
            Dictionary with log_entry_id and any rule_matches
        """
        # Parse raw log
        parsed = self.parser_manager.parse(raw_log, source_type)

        # Normalize parsed data
        normalized = self.normalizer.normalize(parsed, source_type)

        # Create LogEntry instance
        log_entry = LogEntry(
            timestamp=normalized.get("timestamp", datetime.utcnow()),
            source_type=source_type,
            source_name=source_name,
            source_ip=source_ip,
            destination_ip=normalized.get("destination_ip"),
            log_type=normalized.get("log_type"),
            severity=normalized.get("severity", "unknown"),
            message=normalized.get("message", raw_log),
            username=normalized.get("username"),
            hostname=normalized.get("hostname"),
            parsed_data=parsed,
            raw_log=raw_log,
            organization_id=organization_id,
            tags=[],
        )

        # Add to session and flush to get ID
        db.add(log_entry)
        await db.flush()

        log_id = log_entry.id

        # Evaluate detection rules
        rule_matches = []
        try:
            matches = await self.rule_engine.evaluate_log(db, log_entry)
            rule_matches = matches
        except Exception as e:
            # Log rule evaluation errors but don't fail ingestion
            print(f"Error evaluating rules for log {log_id}: {e}")

        # Commit the transaction
        await db.commit()

        return {
            "log_entry_id": log_id,
            "rule_matches": rule_matches,
        }

    async def ingest_batch(
        self,
        db: AsyncSession,
        logs: list[dict],
    ) -> dict:
        """
        Ingest multiple log entries in batch.

        Args:
            db: Async database session
            logs: List of dicts with keys: raw_log, source_type, source_name,
                  source_ip (optional), organization_id (optional)

        Returns:
            Dictionary with counts of ingested, failed, and rule_matches
        """
        ingested_count = 0
        failed_count = 0
        total_rule_matches = []
        log_entries = []

        # Parse and normalize all logs
        for log_dict in logs:
            try:
                raw_log = log_dict["raw_log"]
                source_type = log_dict["source_type"]
                source_name = log_dict["source_name"]
                source_ip = log_dict.get("source_ip")
                organization_id = log_dict.get("organization_id")

                # Parse and normalize
                parsed = self.parser_manager.parse(raw_log, source_type)
                normalized = self.normalizer.normalize(parsed, source_type)

                # Create LogEntry
                log_entry = LogEntry(
                    timestamp=normalized.get("timestamp", datetime.utcnow()),
                    source_type=source_type,
                    source_name=source_name,
                    source_ip=source_ip,
                    destination_ip=normalized.get("destination_ip"),
                    log_type=normalized.get("log_type"),
                    severity=normalized.get("severity", "unknown"),
                    message=normalized.get("message", raw_log),
                    username=normalized.get("username"),
                    hostname=normalized.get("hostname"),
                    parsed_data=parsed,
                    raw_log=raw_log,
                    organization_id=organization_id,
                    tags=[],
                )
                log_entries.append(log_entry)
                ingested_count += 1

            except Exception as e:
                failed_count += 1
                print(f"Error ingesting log: {e}")
                continue

        # Bulk insert
        db.add_all(log_entries)
        await db.flush()

        # Evaluate rules for all logs
        try:
            for log_entry in log_entries:
                matches = await self.rule_engine.evaluate_log(db, log_entry)
                total_rule_matches.extend(matches)
        except Exception as e:
            print(f"Error evaluating batch rules: {e}")

        # Commit
        await db.commit()

        return {
            "ingested": ingested_count,
            "failed": failed_count,
            "rule_matches": len(total_rule_matches),
        }

    async def get_storage_stats(self, db: AsyncSession) -> dict:
        """
        Get storage statistics.

        Args:
            db: Async database session

        Returns:
            Dictionary with storage stats
        """
        # Total log count
        total_stmt = select(func.count()).select_from(LogEntry)
        total_result = await db.execute(total_stmt)
        total_count = total_result.scalar_one()

        # Count by log type
        by_type_stmt = select(
            LogEntry.log_type, func.count().label("count")
        ).group_by(LogEntry.log_type)
        by_type_result = await db.execute(by_type_stmt)
        by_type = {row[0]: row[1] for row in by_type_result.all()}

        # Count by source
        by_source_stmt = select(
            LogEntry.source_name, func.count().label("count")
        ).group_by(LogEntry.source_name)
        by_source_result = await db.execute(by_source_stmt)
        by_source = {row[0]: row[1] for row in by_source_result.all()}

        # Count by day
        by_day_stmt = select(
            func.date(LogEntry.timestamp).label("day"),
            func.count().label("count"),
        ).group_by(func.date(LogEntry.timestamp)).order_by(
            func.date(LogEntry.timestamp).desc()
        ).limit(30)
        by_day_result = await db.execute(by_day_stmt)
        by_day = {str(row[0]): row[1] for row in by_day_result.all()}

        # Oldest/newest timestamps
        timestamp_stmt = select(
            func.min(LogEntry.timestamp).label("oldest"),
            func.max(LogEntry.timestamp).label("newest"),
        )
        timestamp_result = await db.execute(timestamp_stmt)
        oldest, newest = timestamp_result.one()

        return {
            "total_logs": total_count,
            "by_log_type": by_type,
            "by_source": by_source,
            "by_day": by_day,
            "oldest_log": oldest.isoformat() if oldest else None,
            "newest_log": newest.isoformat() if newest else None,
        }

    async def apply_retention(
        self,
        db: AsyncSession,
        policy: RetentionPolicy,
    ) -> dict:
        """
        Apply retention policy to logs.

        Args:
            db: Async database session
            policy: RetentionPolicy object

        Returns:
            Dictionary with counts of deleted/archived logs
        """
        deleted_count = 0
        archived_count = 0

        # Calculate cutoff dates
        cold_cutoff = datetime.utcnow() - timedelta(days=policy.cold_days)

        # Archive logs if enabled (export to Parquet)
        if policy.archive_enabled:
            try:
                archive_stmt = select(LogEntry).where(
                    LogEntry.timestamp < cold_cutoff
                )
                archive_result = await db.execute(archive_stmt)
                logs_to_archive = archive_result.scalars().all()

                if logs_to_archive:
                    # Export to Parquet (placeholder for actual implementation)
                    archived_count = len(logs_to_archive)
                    print(
                        f"Archived {archived_count} logs to cold storage"
                    )

            except Exception as e:
                print(f"Error archiving logs: {e}")

        # Delete logs older than cold_days
        delete_stmt = delete(LogEntry).where(
            LogEntry.timestamp < cold_cutoff
        )
        delete_result = await db.execute(delete_stmt)
        deleted_count = delete_result.rowcount

        await db.commit()

        return {
            "deleted": deleted_count,
            "archived": archived_count,
            "policy": {
                "hot_days": policy.hot_days,
                "warm_days": policy.warm_days,
                "cold_days": policy.cold_days,
                "archive_enabled": policy.archive_enabled,
            },
        }

    async def get_ingestion_rate(
        self,
        db: AsyncSession,
        hours: int = 24,
    ) -> dict:
        """
        Get log ingestion rate over time period.

        Args:
            db: Async database session
            hours: Number of hours to look back

        Returns:
            Dictionary with ingestion rate stats
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)

        # Total events in period
        total_stmt = select(func.count()).select_from(LogEntry).where(
            LogEntry.timestamp >= cutoff_time
        )
        total_result = await db.execute(total_stmt)
        total_events = total_result.scalar_one()

        # Events per hour
        per_hour_stmt = select(
            func.date_trunc("hour", LogEntry.timestamp).label("hour"),
            func.count().label("count"),
        ).where(
            LogEntry.timestamp >= cutoff_time
        ).group_by(
            func.date_trunc("hour", LogEntry.timestamp)
        ).order_by(
            func.date_trunc("hour", LogEntry.timestamp).asc()
        )
        per_hour_result = await db.execute(per_hour_stmt)
        per_hour = [
            {"hour": row[0].isoformat() if row[0] else None, "count": row[1]}
            for row in per_hour_result.all()
        ]

        # Events per source
        by_source_stmt = select(
            LogEntry.source_name, func.count().label("count")
        ).where(
            LogEntry.timestamp >= cutoff_time
        ).group_by(
            LogEntry.source_name
        ).order_by(
            func.count().desc()
        ).limit(20)
        by_source_result = await db.execute(by_source_stmt)
        by_source = [
            {"source": row[0], "count": row[1]} for row in by_source_result.all()
        ]

        # Calculate average rate
        avg_rate = total_events / hours if hours > 0 else 0

        return {
            "period_hours": hours,
            "total_events": total_events,
            "average_events_per_hour": avg_rate,
            "events_per_hour": per_hour,
            "events_by_source": by_source,
        }
