"""Real-time log collection from multiple sources"""

import asyncio
import hashlib
import os
import re
import socket
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.core.events import EventBus, Event, EventType
from src.core.logging import get_logger

logger = get_logger(__name__)


class Collector(ABC):
    """Base collector class"""

    def __init__(self, name: str, event_bus: Optional[EventBus] = None):
        self.name = name
        self.enabled = False
        self.last_health_check = datetime.now(timezone.utc)
        self.events_received = 0
        self.events_dropped = 0
        self.bytes_processed = 0
        self.last_error: Optional[str] = None
        self.event_bus = event_bus

    @abstractmethod
    async def start(self):
        """Start the collector"""
        pass

    @abstractmethod
    async def stop(self):
        """Stop the collector"""
        pass

    def get_health(self) -> Dict[str, Any]:
        """Get collector health status"""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "events_received": self.events_received,
            "events_dropped": self.events_dropped,
            "bytes_processed": self.bytes_processed,
            "last_error": self.last_error,
            "last_health_check": self.last_health_check.isoformat(),
        }


class HTTPCollector(Collector):
    """Collect log events via HTTP POST endpoint"""

    def __init__(self, port: int = 8001, event_bus: Optional[EventBus] = None):
        super().__init__("HTTP Collector", event_bus)
        self.port = port
        self.api_keys: Dict[str, str] = {}  # source_name -> api_key
        self.rate_limits: Dict[str, tuple] = {}  # source -> (count, reset_time)
        self.rate_limit_per_minute = 10000

    async def start(self):
        """Start HTTP collector"""
        self.enabled = True
        logger.info(f"HTTPCollector started on port {self.port}")

    async def stop(self):
        """Stop HTTP collector"""
        self.enabled = False
        logger.info("HTTPCollector stopped")

    async def accept_logs(
        self,
        org_id: str,
        source_name: str,
        api_key: str,
        events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Accept and process log batch.

        Events should be list of log objects, each with:
        - timestamp (ISO format)
        - level (info, warning, error, critical)
        - source (component name)
        - message (log message)
        - data (optional additional fields)
        """
        # Validate API key
        if not self._validate_api_key(source_name, api_key):
            self.events_dropped += len(events)
            return {"accepted": 0, "dropped": len(events), "reason": "Invalid API key"}

        # Check rate limit
        if self._is_rate_limited(source_name):
            self.events_dropped += len(events)
            return {
                "accepted": 0,
                "dropped": len(events),
                "reason": "Rate limit exceeded",
            }

        # Process events
        accepted = 0
        for event in events:
            try:
                # Normalize and validate
                normalized = self._normalize_event(event, org_id, source_name)
                self.events_received += 1
                self.bytes_processed += len(str(event))
                accepted += 1

                # Emit to event bus
                if self.event_bus:
                    event_type = (
                        EventType.THREAT_DETECTED
                        if normalized.get("level") in ("error", "critical")
                        else EventType.SYSTEM_HEALTH
                    )
                    await self.event_bus.publish(
                        event_type=event_type,
                        org_id=org_id,
                        data=normalized,
                        source_module="siem_collector_http",
                    )

            except Exception as e:
                logger.error(f"Error processing event from {source_name}: {e}")
                self.events_dropped += 1

        return {"accepted": accepted, "dropped": len(events) - accepted}

    def _validate_api_key(self, source_name: str, api_key: str) -> bool:
        """Validate API key for source"""
        if source_name not in self.api_keys:
            return False
        return self.api_keys[source_name] == api_key

    def _is_rate_limited(self, source_name: str) -> bool:
        """Check if source is rate limited"""
        now = time.time()

        if source_name not in self.rate_limits:
            self.rate_limits[source_name] = (1, now + 60)
            return False

        count, reset_time = self.rate_limits[source_name]

        if now > reset_time:
            self.rate_limits[source_name] = (1, now + 60)
            return False

        if count >= self.rate_limit_per_minute:
            return True

        self.rate_limits[source_name] = (count + 1, reset_time)
        return False

    def _normalize_event(
        self,
        event: Dict[str, Any],
        org_id: str,
        source_name: str,
    ) -> Dict[str, Any]:
        """Normalize log event"""
        return {
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "level": event.get("level", "info"),
            "source": source_name,
            "message": event.get("message", ""),
            "org_id": org_id,
            "data": event.get("data", {}),
        }


class SyslogCollector(Collector):
    """Collect syslog events from TCP/UDP"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 514,
        event_bus: Optional[EventBus] = None,
    ):
        super().__init__("Syslog Collector", event_bus)
        self.host = host
        self.port = port
        self.tcp_server: Optional[asyncio.Server] = None
        self.udp_transport = None
        self.udp_protocol = None
        self.tls_enabled = False

    async def start(self):
        """Start syslog server (UDP and TCP)"""
        try:
            # Start UDP listener
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(self),
                local_addr=(self.host, self.port),
            )
            self.udp_transport = transport
            self.udp_protocol = protocol

            # Start TCP listener
            self.tcp_server = await asyncio.start_server(
                self._handle_tcp_connection,
                self.host,
                self.port,
            )

            self.enabled = True
            logger.info(f"SyslogCollector started on {self.host}:{self.port}")

        except Exception as e:
            logger.error(f"Failed to start SyslogCollector: {e}")
            self.last_error = str(e)

    async def stop(self):
        """Stop syslog server"""
        self.enabled = False

        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()

        if self.udp_transport:
            self.udp_transport.close()

        logger.info("SyslogCollector stopped")

    async def _handle_tcp_connection(self, reader, writer):
        """Handle TCP syslog connection"""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                await self._process_syslog_message(line.decode().strip())

        except Exception as e:
            logger.error(f"Error handling TCP connection: {e}")
        finally:
            writer.close()

    async def _process_syslog_message(self, message: str):
        """Parse and process syslog message (RFC 3164 and RFC 5424)"""
        try:
            event = self._parse_syslog(message)
            self.events_received += 1
            self.bytes_processed += len(message)

            # Emit to event bus
            if self.event_bus:
                level = event.get("level", "info")
                event_type = (
                    EventType.THREAT_DETECTED
                    if level in ("critical", "alert", "emergency", "error")
                    else EventType.SYSTEM_HEALTH
                )
                # Extract org_id from event data if available, otherwise use default
                org_id = event.get("org_id", "default")
                await self.event_bus.publish(
                    event_type=event_type,
                    org_id=org_id,
                    data=event,
                    source_module="siem_collector_syslog",
                )

        except Exception as e:
            logger.error(f"Error processing syslog message: {e}")
            self.events_dropped += 1

    def _parse_syslog(self, message: str) -> Dict[str, Any]:
        """Parse syslog message (simplified)"""
        # Try RFC 5424 format first
        rfc5424_pattern = (
            r"<(?P<pri>\d+)>(?P<version>\d+) "
            r"(?P<timestamp>\S+) (?P<hostname>\S+) "
            r"(?P<app>\S+) (?P<pid>\S+) (?P<mid>\S+) "
            r"(?P<sd>\S+) (?P<msg>.*)"
        )

        match = re.match(rfc5424_pattern, message)
        if match:
            parts = match.groupdict()
            pri = int(parts["pri"])
            severity = pri % 8
            facility = pri // 8

            return {
                "timestamp": parts["timestamp"],
                "hostname": parts["hostname"],
                "app": parts["app"],
                "pid": parts["pid"],
                "message": parts["msg"],
                "level": self._severity_to_level(severity),
                "facility": facility,
            }

        # Fall back to RFC 3164 format
        rfc3164_pattern = (
            r"<(?P<pri>\d+)>(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) "
            r"(?P<hostname>\S+) (?P<tag>\S+): (?P<msg>.*)"
        )

        match = re.match(rfc3164_pattern, message)
        if match:
            parts = match.groupdict()
            pri = int(parts["pri"])
            severity = pri % 8

            return {
                "timestamp": parts["timestamp"],
                "hostname": parts["hostname"],
                "tag": parts["tag"],
                "message": parts["msg"],
                "level": self._severity_to_level(severity),
            }

        # Fallback: treat as raw message
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message,
            "level": "info",
        }

    def _severity_to_level(self, severity: int) -> str:
        """Convert syslog severity to log level"""
        levels = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
        return levels[min(severity, 7)]


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog"""

    def __init__(self, collector: "SyslogCollector"):
        self.collector = collector
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        """Handle incoming UDP syslog message"""
        try:
            message = data.decode().strip()
            asyncio.create_task(self.collector._process_syslog_message(message))
        except Exception as e:
            logger.error(f"Error processing UDP syslog: {e}")


class FileCollector(Collector):
    """Tail log files"""

    def __init__(
        self,
        paths: List[str],
        org_id: str = "default",
        event_bus: Optional[EventBus] = None,
    ):
        super().__init__("File Collector", event_bus)
        self.paths = paths
        self.org_id = org_id
        self.positions: Dict[str, int] = {}  # path -> file_position
        self.poll_interval = 5
        self.task: Optional[asyncio.Task] = None

    async def start(self):
        """Start file collector"""
        self.enabled = True
        self.task = asyncio.create_task(self._poll_files())
        logger.info(f"FileCollector started for {len(self.paths)} files")

    async def stop(self):
        """Stop file collector"""
        self.enabled = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("FileCollector stopped")

    async def _poll_files(self):
        """Poll files for new content"""
        try:
            while self.enabled:
                for path in self.paths:
                    await self._check_file(path)
                await asyncio.sleep(self.poll_interval)
        except asyncio.CancelledError:
            pass

    async def _check_file(self, path: str):
        """Check file for new content"""
        try:
            if not os.path.exists(path):
                logger.warning(f"File not found: {path}")
                return

            # Get current size
            current_size = os.path.getsize(path)
            last_position = self.positions.get(path, 0)

            # File rotated
            if current_size < last_position:
                last_position = 0

            # Read new content
            with open(path, "r") as f:
                f.seek(last_position)
                new_lines = f.readlines()
                new_position = f.tell()

            # Process new lines
            for line in new_lines:
                line = line.strip()
                if line:
                    await self._process_log_line(path, line)
                    self.bytes_processed += len(line)

            self.positions[path] = new_position

        except Exception as e:
            logger.error(f"Error checking file {path}: {e}")
            self.last_error = str(e)

    async def _process_log_line(self, path: str, line: str):
        """Process individual log line"""
        try:
            self.events_received += 1

            level = self._detect_level(line)
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": os.path.basename(path),
                "message": line,
                "level": level,
                "org_id": self.org_id,
            }

            # Emit to event bus
            if self.event_bus:
                event_type = (
                    EventType.THREAT_DETECTED
                    if level in ("critical", "error")
                    else EventType.SYSTEM_HEALTH
                )
                await self.event_bus.publish(
                    event_type=event_type,
                    org_id=self.org_id,
                    data=event,
                    source_module="siem_collector_file",
                )

        except Exception as e:
            logger.error(f"Error processing log line: {e}")
            self.events_dropped += 1

    def _detect_level(self, line: str) -> str:
        """Detect log level from line"""
        line_lower = line.lower()
        if "critical" in line_lower or "fatal" in line_lower:
            return "critical"
        elif "error" in line_lower:
            return "error"
        elif "warning" in line_lower or "warn" in line_lower:
            return "warning"
        return "info"


class CloudCollector(Collector):
    """Collect logs from cloud providers"""

    def __init__(self, provider: str, config: Dict[str, Any]):
        super().__init__(f"Cloud Collector ({provider})")
        self.provider = provider
        self.config = config
        self.poll_interval = config.get("poll_interval", 60)
        self.task: Optional[asyncio.Task] = None

    async def start(self):
        """Start cloud collector"""
        self.enabled = True
        self.task = asyncio.create_task(self._poll_cloud())
        logger.info(f"CloudCollector started for {self.provider}")

    async def stop(self):
        """Stop cloud collector"""
        self.enabled = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("CloudCollector stopped")

    async def _poll_cloud(self):
        """Poll cloud provider for logs"""
        try:
            while self.enabled:
                if self.provider == "aws":
                    await self._poll_aws()
                elif self.provider == "azure":
                    await self._poll_azure()
                elif self.provider == "gcp":
                    await self._poll_gcp()

                await asyncio.sleep(self.poll_interval)

        except asyncio.CancelledError:
            pass

    async def _poll_aws(self):
        """Poll AWS CloudTrail (stub)"""
        try:
            # Implementation would use boto3
            logger.debug("Polling AWS CloudTrail")
        except Exception as e:
            logger.error(f"Error polling AWS: {e}")
            self.last_error = str(e)

    async def _poll_azure(self):
        """Poll Azure Activity Logs (stub)"""
        try:
            # Implementation would use azure-monitor-query
            logger.debug("Polling Azure Activity Logs")
        except Exception as e:
            logger.error(f"Error polling Azure: {e}")
            self.last_error = str(e)

    async def _poll_gcp(self):
        """Poll GCP Cloud Logging (stub)"""
        try:
            # Implementation would use google-cloud-logging
            logger.debug("Polling GCP Cloud Logging")
        except Exception as e:
            logger.error(f"Error polling GCP: {e}")
            self.last_error = str(e)


class CollectorManager:
    """Manage and monitor multiple collectors with event bus integration"""

    def __init__(self, event_bus: Optional[EventBus] = None):
        self.event_bus = event_bus
        self.collectors: Dict[str, Collector] = {}
        self.http_collector: Optional[HTTPCollector] = None
        self.syslog_collector: Optional[SyslogCollector] = None
        self.file_collector: Optional[FileCollector] = None

    def initialize_collectors(
        self,
        http_port: int = 8001,
        syslog_host: str = "0.0.0.0",
        syslog_port: int = 514,
        file_paths: Optional[List[str]] = None,
        org_id: str = "default",
    ):
        """Initialize and register all collectors with event bus"""
        # Create HTTP collector
        self.http_collector = HTTPCollector(port=http_port, event_bus=self.event_bus)
        self.collectors[self.http_collector.name] = self.http_collector

        # Create Syslog collector
        self.syslog_collector = SyslogCollector(
            host=syslog_host,
            port=syslog_port,
            event_bus=self.event_bus,
        )
        self.collectors[self.syslog_collector.name] = self.syslog_collector

        # Create File collector if paths provided
        if file_paths:
            self.file_collector = FileCollector(
                paths=file_paths,
                org_id=org_id,
                event_bus=self.event_bus,
            )
            self.collectors[self.file_collector.name] = self.file_collector

        logger.info(f"Initialized {len(self.collectors)} collectors with event bus")

    async def register(self, collector: Collector):
        """Register a collector"""
        # Wire event bus if not already set
        if not collector.event_bus and self.event_bus:
            collector.event_bus = self.event_bus
        self.collectors[collector.name] = collector
        logger.info(f"Registered collector: {collector.name}")

    async def start_all(self):
        """Start all collectors"""
        for collector in self.collectors.values():
            try:
                await collector.start()
            except Exception as e:
                logger.error(f"Failed to start {collector.name}: {e}")

    async def stop_all(self):
        """Stop all collectors"""
        for collector in self.collectors.values():
            try:
                await collector.stop()
            except Exception as e:
                logger.error(f"Failed to stop {collector.name}: {e}")

    def get_health(self) -> Dict[str, Any]:
        """Get health status of all collectors"""
        return {
            name: collector.get_health()
            for name, collector in self.collectors.items()
        }

    async def auto_restart_failed(self):
        """Auto-restart failed collectors"""
        for collector in self.collectors.values():
            if collector.last_error and not collector.enabled:
                try:
                    logger.info(f"Auto-restarting {collector.name}")
                    await collector.start()
                except Exception as e:
                    logger.error(f"Failed to auto-restart {collector.name}: {e}")
