"""SIEM metrics collection and aggregation for real-time monitoring."""

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from src.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SIEMMetric:
    """Individual metric data point."""

    name: str
    value: float
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metric_type: str = "gauge"  # counter, gauge, or histogram


class MetricsCollector:
    """
    Thread-safe metrics collector for SIEM operations.

    Collects counters (monotonically increasing), gauges (point-in-time values),
    and histograms (distribution of values).
    """

    def __init__(self):
        """Initialize metrics collector."""
        self._lock = threading.RLock()
        self._counters = defaultdict(lambda: defaultdict(float))  # {metric_name: {tag_key: value}}
        self._gauges = defaultdict(lambda: defaultdict(float))
        self._histograms = defaultdict(lambda: defaultdict(list))  # {metric_name: {tag_key: [values]}}
        self._metric_history = defaultdict(list)  # {metric_name: [SIEMMetric]}

    def increment(
        self, name: str, value: float = 1.0, tags: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Increment a counter metric.

        Args:
            name: Metric name (e.g., "logs_ingested", "rules_matched").
            value: Amount to increment (default 1.0).
            tags: Optional tag dictionary for metric grouping.
        """
        tags = tags or {}
        tag_key = self._serialize_tags(tags)

        with self._lock:
            self._counters[name][tag_key] += value
            self._metric_history[name].append(
                SIEMMetric(
                    name=name,
                    value=self._counters[name][tag_key],
                    timestamp=datetime.utcnow(),
                    tags=tags,
                    metric_type="counter",
                )
            )

    def gauge(
        self, name: str, value: float, tags: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Set a gauge metric to a specific value.

        Args:
            name: Metric name (e.g., "queue_depth", "active_connections").
            value: Gauge value.
            tags: Optional tag dictionary for metric grouping.
        """
        tags = tags or {}
        tag_key = self._serialize_tags(tags)

        with self._lock:
            self._gauges[name][tag_key] = value
            self._metric_history[name].append(
                SIEMMetric(
                    name=name,
                    value=value,
                    timestamp=datetime.utcnow(),
                    tags=tags,
                    metric_type="gauge",
                )
            )

    def histogram(
        self, name: str, value: float, tags: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Record a histogram value.

        Args:
            name: Metric name (e.g., "ingestion_latency_ms", "search_query_ms").
            value: Value to record.
            tags: Optional tag dictionary for metric grouping.
        """
        tags = tags or {}
        tag_key = self._serialize_tags(tags)

        with self._lock:
            self._histograms[name][tag_key].append(value)
            self._metric_history[name].append(
                SIEMMetric(
                    name=name,
                    value=value,
                    timestamp=datetime.utcnow(),
                    tags=tags,
                    metric_type="histogram",
                )
            )

    def get_metrics(self) -> dict:
        """
        Get all current metrics as nested dictionary.

        Returns:
            Dictionary with counters, gauges, and histograms.
        """
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {k: {tk: len(v) for tk, v in vv.items()} for k, vv in self._histograms.items()},
            }

    def get_metric(self, name: str) -> Optional[dict]:
        """
        Get specific metric with aggregated statistics.

        Args:
            name: Metric name.

        Returns:
            Dictionary with metric statistics or None if not found.
        """
        with self._lock:
            result = {}

            if name in self._counters:
                result["counter"] = dict(self._counters[name])

            if name in self._gauges:
                result["gauge"] = dict(self._gauges[name])

            if name in self._histograms:
                hist_data = {}
                for tag_key, values in self._histograms[name].items():
                    if values:
                        sorted_values = sorted(values)
                        hist_data[tag_key] = {
                            "count": len(values),
                            "sum": sum(values),
                            "min": min(values),
                            "max": max(values),
                            "avg": sum(values) / len(values),
                            "p50": sorted_values[len(values) // 2],
                            "p95": sorted_values[int(len(values) * 0.95)],
                            "p99": sorted_values[int(len(values) * 0.99)],
                        }
                result["histogram"] = hist_data

            return result if result else None

    def reset(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._metric_history.clear()
            logger.info("All metrics reset")

    def _serialize_tags(self, tags: Dict[str, str]) -> str:
        """Serialize tags to a string key."""
        if not tags:
            return "__default__"
        return "|".join(f"{k}={v}" for k, v in sorted(tags.items()))


class MetricsAggregator:
    """Aggregate metrics for dashboard and reporting."""

    def __init__(self, collector: Optional[MetricsCollector] = None):
        """
        Initialize metrics aggregator.

        Args:
            collector: MetricsCollector instance. If None, uses global instance.
        """
        self.collector = collector

    def aggregate_ingestion_stats(self, time_range_minutes: int = 60) -> dict:
        """
        Aggregate ingestion statistics over time period.

        Args:
            time_range_minutes: Time range for aggregation.

        Returns:
            Dictionary with events per second, by source, by type, by severity.
        """
        return {
            "time_range_minutes": time_range_minutes,
            "events_per_second": 0.0,
            "by_source": {},
            "by_type": {},
            "by_severity": {},
            "total_events": 0,
        }

    def aggregate_detection_stats(self, time_range_minutes: int = 60) -> dict:
        """
        Aggregate detection and rule match statistics.

        Args:
            time_range_minutes: Time range for aggregation.

        Returns:
            Dictionary with rule matches, top triggered rules, false positive rate.
        """
        return {
            "time_range_minutes": time_range_minutes,
            "total_matches": 0,
            "top_rules": [],
            "false_positive_rate": 0.0,
            "avg_rule_matches_per_hour": 0.0,
        }

    def aggregate_storage_stats(self) -> dict:
        """
        Aggregate storage and retention statistics.

        Returns:
            Dictionary with log count, storage size, partition info.
        """
        return {
            "total_logs": 0,
            "storage_size_gb": 0.0,
            "partition_count": 0,
            "retention_days": 90,
            "oldest_log_date": None,
            "newest_log_date": None,
        }

    def aggregate_performance_stats(self) -> dict:
        """
        Aggregate performance metrics.

        Returns:
            Dictionary with query latency, ingestion throughput, processing time.
        """
        return {
            "query_latency_ms": {
                "p50": 0.0,
                "p95": 0.0,
                "p99": 0.0,
            },
            "ingestion_throughput_eps": 0.0,
            "correlation_processing_ms": 0.0,
            "rule_engine_processing_ms": 0.0,
        }

    def get_dashboard_data(self) -> dict:
        """
        Get combined dashboard-ready metrics package.

        Returns:
            Dictionary with all dashboard metrics.
        """
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "ingestion": self.aggregate_ingestion_stats(),
            "detection": self.aggregate_detection_stats(),
            "storage": self.aggregate_storage_stats(),
            "performance": self.aggregate_performance_stats(),
        }

    def get_time_series(
        self, metric_name: str, interval_minutes: int = 5, range_hours: int = 24
    ) -> List[dict]:
        """
        Get time-bucketed metric values for charting.

        Args:
            metric_name: Name of metric to retrieve.
            interval_minutes: Bucket interval in minutes.
            range_hours: Time range in hours.

        Returns:
            List of time-bucketed metric dictionaries.
        """
        return []


class PrometheusExporter:
    """Export metrics in Prometheus text exposition format."""

    def __init__(self, collector: Optional[MetricsCollector] = None):
        """
        Initialize Prometheus exporter.

        Args:
            collector: MetricsCollector instance.
        """
        self.collector = collector or siem_metrics

    def export_metrics(self) -> str:
        """
        Export metrics in Prometheus text exposition format.

        Returns:
            String in Prometheus text format.
        """
        lines = []
        timestamp = int(datetime.utcnow().timestamp() * 1000)

        metrics = self.collector.get_metrics()

        # Export counters
        for metric_name, tags_dict in metrics.get("counters", {}).items():
            for tag_key, value in tags_dict.items():
                labels = self._parse_tag_key(tag_key)
                line = self._format_prometheus_line(
                    f"{metric_name}_total", labels, value, timestamp
                )
                lines.append(line)

        # Export gauges
        for metric_name, tags_dict in metrics.get("gauges", {}).items():
            for tag_key, value in tags_dict.items():
                labels = self._parse_tag_key(tag_key)
                line = self._format_prometheus_line(metric_name, labels, value, timestamp)
                lines.append(line)

        # Export histogram buckets
        for metric_name, tags_dict in metrics.get("histograms", {}).items():
            for tag_key, count in tags_dict.items():
                labels = self._parse_tag_key(tag_key)
                line = self._format_prometheus_line(
                    f"{metric_name}_count", labels, count, timestamp
                )
                lines.append(line)

        return "\n".join(lines)

    def get_metric_families(self) -> list:
        """
        Get metrics as Prometheus metric family objects.

        Returns:
            List of metric family objects.
        """
        return []

    def _format_prometheus_line(
        self, metric_name: str, labels: Dict[str, str], value: float, timestamp: int
    ) -> str:
        """Format metric as Prometheus exposition line."""
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            return f"{metric_name}{{{label_str}}} {value} {timestamp}"
        return f"{metric_name} {value} {timestamp}"

    def _parse_tag_key(self, tag_key: str) -> Dict[str, str]:
        """Parse serialized tag key into dictionary."""
        if tag_key == "__default__":
            return {}
        labels = {}
        for pair in tag_key.split("|"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                labels[k] = v
        return labels


# Global singleton instance
siem_metrics = MetricsCollector()
