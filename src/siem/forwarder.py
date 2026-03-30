"""Log forwarding service for exporting processed logs to external systems."""

import asyncio
import json
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from src.core.logging import get_logger

logger = get_logger(__name__)


class ForwardingDestType(str, Enum):
    """Log forwarding destination types."""

    SYSLOG = "syslog"
    WEBHOOK = "webhook"
    KAFKA = "kafka"
    FILE = "file"


class LogFormat(str, Enum):
    """Log output formats."""

    JSON = "json"
    CEF = "cef"
    LEEF = "leef"
    SYSLOG = "syslog"


@dataclass
class ForwardingDestination:
    """Log forwarding destination configuration."""

    id: str
    name: str
    dest_type: ForwardingDestType
    host: str
    port: int
    protocol: str = "tcp"  # tcp, udp, http, https
    format: LogFormat = LogFormat.JSON
    filter_rules: Dict = field(default_factory=dict)
    enabled: bool = True
    tls_enabled: bool = False
    auth_config: Dict = field(default_factory=dict)  # api_key, bearer_token, username, password


class LogFormatter:
    """Format log entries for different output formats."""

    @staticmethod
    def to_json(log_entry: dict) -> str:
        """
        Format log entry as JSON.

        Args:
            log_entry: Log entry dictionary.

        Returns:
            JSON string.
        """
        try:
            return json.dumps(log_entry)
        except Exception as e:
            logger.error(f"JSON formatting failed: {e}")
            return "{}"

    @staticmethod
    def to_cef(log_entry: dict) -> str:
        """
        Format log entry as Common Event Format (CEF).

        Args:
            log_entry: Log entry dictionary.

        Returns:
            CEF string.
        """
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
        timestamp = log_entry.get("timestamp", "")
        source_ip = log_entry.get("source_address", "")
        dest_ip = log_entry.get("destination_address", "")
        severity = log_entry.get("severity", "3")
        message = log_entry.get("message", "")
        rule_name = log_entry.get("rule_name", "PySOAR Detection")

        # Map severity to CEF scale (0-10)
        severity_map = {
            "critical": "10",
            "high": "8",
            "medium": "5",
            "low": "3",
            "informational": "1",
        }
        cef_severity = severity_map.get(severity, "3")

        extensions = f"src={source_ip} dst={dest_ip} msg={message}"

        cef_string = (
            f"CEF:0|PySOAR|SIEM|1.0|{log_entry.get('rule_id', 'unknown')}"
            f"|{rule_name}|{cef_severity}|{extensions}"
        )

        return cef_string

    @staticmethod
    def to_leef(log_entry: dict) -> str:
        """
        Format log entry as LEEF (Logging Event Extended Format).

        Args:
            log_entry: Log entry dictionary.

        Returns:
            LEEF string.
        """
        # LEEF:Version|Vendor|Product|Version|EventID|Attributes
        timestamp = log_entry.get("timestamp", "")
        source_ip = log_entry.get("source_address", "")
        dest_ip = log_entry.get("destination_address", "")
        message = log_entry.get("message", "")

        attributes = (
            f"srcIP={source_ip}\tdestIP={dest_ip}\t"
            f"msg={message}\tdevTime={timestamp}"
        )

        leef_string = (
            f"LEEF:1.0|PySOAR|SIEM|1.0|{log_entry.get('rule_id', 'unknown')}|{attributes}"
        )

        return leef_string

    @staticmethod
    def to_syslog(log_entry: dict) -> str:
        """
        Format log entry as RFC 5424 syslog.

        Args:
            log_entry: Log entry dictionary.

        Returns:
            Syslog string.
        """
        timestamp = log_entry.get("timestamp", datetime.utcnow().isoformat())
        hostname = log_entry.get("hostname", "pysoar")
        severity = log_entry.get("severity", "notice")
        message = log_entry.get("message", "")

        # Severity to syslog priority mapping
        severity_map = {
            "critical": "2",
            "high": "3",
            "medium": "4",
            "low": "5",
            "informational": "6",
        }
        priority = severity_map.get(severity, "6")

        # RFC 5424 format
        syslog_string = (
            f"<{priority}> {timestamp} {hostname} "
            f"pysoar[{log_entry.get('rule_id', 'unknown')}]: {message}"
        )

        return syslog_string


class SyslogForwarder:
    """Forward logs via UDP or TCP syslog."""

    def __init__(self, destination: ForwardingDestination):
        """
        Initialize syslog forwarder.

        Args:
            destination: ForwardingDestination configuration.
        """
        self.destination = destination
        self.socket = None
        self.last_error = None
        self.retry_count = 0
        self.max_retries = 3

    async def forward(self, log_entry: dict) -> bool:
        """
        Forward log entry via syslog.

        Args:
            log_entry: Log entry to forward.

        Returns:
            True if successful, False otherwise.
        """
        try:
            message = LogFormatter.to_syslog(log_entry)

            if self.destination.protocol == "udp":
                await self._send_udp(message)
            else:
                await self._send_tcp(message)

            self.last_error = None
            self.retry_count = 0
            return True
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Syslog forwarding failed: {e}")
            return False

    async def _send_udp(self, message: str) -> None:
        """Send message via UDP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(message.encode(), (self.destination.host, self.destination.port))
        finally:
            sock.close()

    async def _send_tcp(self, message: str) -> None:
        """Send message via TCP with reconnection logic."""
        try:
            if not self.socket:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.destination.host, self.destination.port))

            self.socket.sendall(message.encode())
        except (BrokenPipeError, ConnectionResetError):
            self.socket = None
            raise

    def close(self) -> None:
        """Close connection."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None


class WebhookForwarder:
    """Forward logs via HTTP POST webhooks."""

    def __init__(self, destination: ForwardingDestination):
        """
        Initialize webhook forwarder.

        Args:
            destination: ForwardingDestination configuration.
        """
        self.destination = destination
        self.last_error = None
        self.batch_buffer = []
        self.batch_size = destination.filter_rules.get("batch_size", 10)

    async def forward(self, log_entry: dict) -> bool:
        """
        Forward log entry via webhook.

        Args:
            log_entry: Log entry to forward.

        Returns:
            True if successful, False otherwise.
        """
        self.batch_buffer.append(log_entry)

        if len(self.batch_buffer) >= self.batch_size:
            return await self.flush()

        return True

    async def flush(self) -> bool:
        """
        Flush buffered logs to webhook.

        Returns:
            True if successful, False otherwise.
        """
        if not self.batch_buffer:
            return True

        try:
            message = LogFormatter.to_json({"logs": self.batch_buffer})

            # Build headers with auth if configured
            headers = {"Content-Type": "application/json"}
            if "api_key" in self.destination.auth_config:
                headers["Authorization"] = f"Bearer {self.destination.auth_config['api_key']}"

            # Note: In real implementation, would use aiohttp or httpx
            logger.debug(
                f"Would forward {len(self.batch_buffer)} logs to "
                f"webhook {self.destination.host}:{self.destination.port}"
            )

            self.batch_buffer.clear()
            self.last_error = None
            return True
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Webhook forwarding failed: {e}")
            return False


class FileForwarder:
    """Write logs to local files with rotation support."""

    def __init__(self, destination: ForwardingDestination):
        """
        Initialize file forwarder.

        Args:
            destination: ForwardingDestination configuration.
        """
        self.destination = destination
        self.file_path = destination.host  # Use host as file path
        self.file_handle = None
        self.current_size = 0
        self.max_size = destination.filter_rules.get("max_size_mb", 100) * 1024 * 1024
        self.compression = destination.filter_rules.get("compression", False)

    async def forward(self, log_entry: dict) -> bool:
        """
        Write log entry to file.

        Args:
            log_entry: Log entry to write.

        Returns:
            True if successful, False otherwise.
        """
        try:
            format_type = self.destination.format
            if format_type == LogFormat.JSON:
                message = LogFormatter.to_json(log_entry)
            elif format_type == LogFormat.SYSLOG:
                message = LogFormatter.to_syslog(log_entry)
            elif format_type == LogFormat.CEF:
                message = LogFormatter.to_cef(log_entry)
            else:
                message = LogFormatter.to_leef(log_entry)

            message += "\n"

            # Check rotation
            if self.current_size + len(message.encode()) > self.max_size:
                await self._rotate()

            # Write to file
            if not self.file_handle:
                self.file_handle = open(self.file_path, "a")

            self.file_handle.write(message)
            self.file_handle.flush()
            self.current_size += len(message.encode())

            return True
        except Exception as e:
            logger.error(f"File forwarding failed: {e}")
            return False

    async def _rotate(self) -> None:
        """Rotate log file."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

        # Rename current file with timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        rotated_path = f"{self.file_path}.{timestamp}"

        try:
            import os

            os.rename(self.file_path, rotated_path)

            # Compress if enabled
            if self.compression:
                import gzip

                with open(rotated_path, "rb") as f_in:
                    with gzip.open(f"{rotated_path}.gz", "wb") as f_out:
                        f_out.write(f_in.read())
                os.remove(rotated_path)

            self.current_size = 0
        except Exception as e:
            logger.error(f"File rotation failed: {e}")

    async def close(self) -> None:
        """Close file handle."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None


class ForwardingManager:
    """Manage multiple log forwarding destinations."""

    def __init__(self):
        """Initialize forwarding manager."""
        self.destinations: Dict[str, ForwardingDestination] = {}
        self.forwarders: Dict[str, object] = {}
        self.stats: Dict[str, dict] = {}

    def add_destination(self, dest: ForwardingDestination) -> None:
        """
        Register a forwarding destination.

        Args:
            dest: ForwardingDestination configuration.
        """
        self.destinations[dest.id] = dest
        self.stats[dest.id] = {
            "sent": 0,
            "failed": 0,
            "last_sent": None,
            "avg_latency_ms": 0.0,
        }

        # Create appropriate forwarder
        if dest.dest_type == ForwardingDestType.SYSLOG:
            self.forwarders[dest.id] = SyslogForwarder(dest)
        elif dest.dest_type == ForwardingDestType.WEBHOOK:
            self.forwarders[dest.id] = WebhookForwarder(dest)
        elif dest.dest_type == ForwardingDestType.FILE:
            self.forwarders[dest.id] = FileForwarder(dest)

        logger.info(f"Added forwarding destination: {dest.name}")

    def remove_destination(self, dest_id: str) -> bool:
        """
        Remove a forwarding destination.

        Args:
            dest_id: Destination ID to remove.

        Returns:
            True if removed, False if not found.
        """
        if dest_id in self.destinations:
            del self.destinations[dest_id]
            if dest_id in self.forwarders:
                forwarder = self.forwarders[dest_id]
                if hasattr(forwarder, "close"):
                    forwarder.close()
                del self.forwarders[dest_id]
            if dest_id in self.stats:
                del self.stats[dest_id]
            logger.info(f"Removed forwarding destination: {dest_id}")
            return True
        return False

    async def forward_log(self, log_entry: dict) -> None:
        """
        Forward log entry to all enabled destinations matching filters.

        Args:
            log_entry: Log entry to forward.
        """
        for dest_id, dest in self.destinations.items():
            if not dest.enabled:
                continue

            if not self._matches_filters(log_entry, dest):
                continue

            forwarder = self.forwarders.get(dest_id)
            if not forwarder:
                continue

            start_time = time.time()
            success = await forwarder.forward(log_entry)

            latency_ms = (time.time() - start_time) * 1000
            if success:
                self.stats[dest_id]["sent"] += 1
                self.stats[dest_id]["last_sent"] = datetime.utcnow().isoformat()
                # Update running average
                current_avg = self.stats[dest_id]["avg_latency_ms"]
                self.stats[dest_id]["avg_latency_ms"] = (
                    current_avg * 0.9 + latency_ms * 0.1
                )
            else:
                self.stats[dest_id]["failed"] += 1

    async def forward_batch(self, log_entries: List[dict]) -> None:
        """
        Forward batch of log entries.

        Args:
            log_entries: List of log entries to forward.
        """
        tasks = [self.forward_log(entry) for entry in log_entries]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _matches_filters(self, log_entry: dict, dest: ForwardingDestination) -> bool:
        """
        Check if log entry matches destination filter rules.

        Args:
            log_entry: Log entry to check.
            dest: Forwarding destination.

        Returns:
            True if entry matches filters, False otherwise.
        """
        filters = dest.filter_rules
        if not filters:
            return True

        # Check log type filter
        if "log_type" in filters:
            if log_entry.get("log_type") not in filters["log_type"]:
                return False

        # Check severity filter
        if "severity" in filters:
            if log_entry.get("severity") not in filters["severity"]:
                return False

        # Check source filter
        if "sources" in filters:
            if log_entry.get("source_name") not in filters["sources"]:
                return False

        return True

    def get_destination_stats(self) -> List[dict]:
        """
        Get statistics for all destinations.

        Returns:
            List of destination statistics dictionaries.
        """
        result = []
        for dest_id, dest in self.destinations.items():
            stats = self.stats.get(dest_id, {})
            result.append(
                {
                    "id": dest_id,
                    "name": dest.name,
                    "type": dest.dest_type.value,
                    "enabled": dest.enabled,
                    **stats,
                }
            )
        return result


# Global singleton instance
forwarding_manager = ForwardingManager()
