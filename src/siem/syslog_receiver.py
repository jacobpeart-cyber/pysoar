"""Async syslog receiver for UDP and TCP log ingestion.

This module provides a high-performance syslog receiver supporting RFC 3164 and RFC 5424
formats over both UDP and TCP protocols. Includes batching, rate limiting, and health
monitoring capabilities.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from src.siem.parser import LogParserManager

logger = logging.getLogger(__name__)


class SyslogFacility(Enum):
    """Syslog facility codes (RFC 5424)."""

    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23

    @classmethod
    def from_code(cls, code: int) -> str:
        """Get facility name from code."""
        try:
            return cls(code).name.lower()
        except ValueError:
            return f"local{code - 16}" if 16 <= code <= 23 else "unknown"


class SyslogSeverity(Enum):
    """Syslog severity levels (RFC 5424)."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7

    @classmethod
    def from_code(cls, code: int) -> str:
        """Get severity name from code."""
        try:
            return cls(code).name.lower()
        except ValueError:
            return "unknown"


@dataclass
class SyslogMessage:
    """Parsed syslog message with metadata."""

    raw_message: str
    source_ip: str
    source_port: int
    priority: int
    facility: int
    severity: int
    timestamp: Optional[str] = None
    hostname: Optional[str] = None
    app_name: Optional[str] = None
    process_id: Optional[str] = None
    message: str = ""
    version: Optional[int] = None
    structured_data: Optional[str] = None


@dataclass
class SourceStats:
    """Statistics for a syslog source."""

    source_ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    message_count: int = 0
    error_count: int = 0


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog messages."""

    def __init__(
        self,
        message_queue: asyncio.Queue,
        max_queue_size: int = 100000,
        rate_limit_per_sec: int = 10000,
    ):
        """Initialize UDP protocol.

        Args:
            message_queue: Queue to put received messages
            max_queue_size: Maximum queue size before dropping
            rate_limit_per_sec: Max messages per source IP per second
        """
        self.message_queue = message_queue
        self.max_queue_size = max_queue_size
        self.rate_limit_per_sec = rate_limit_per_sec
        self.transport = None
        self.source_stats: Dict[str, SourceStats] = {}
        self.parser = LogParserManager()

    def connection_made(self, transport):
        """Called when connection is made."""
        self.transport = transport
        logger.info("UDP syslog listener started")

    def datagram_received(self, data: bytes, addr: tuple):
        """Handle incoming UDP datagram.

        Args:
            data: Raw message bytes
            addr: Tuple of (source_ip, source_port)
        """
        source_ip, source_port = addr

        try:
            # Rate limiting per source
            stats = self._get_or_create_stats(source_ip)
            if not self._check_rate_limit(stats):
                logger.warning(
                    f"Rate limit exceeded for {source_ip}, dropping message"
                )
                stats.error_count += 1
                return

            # Decode message
            raw_message = data.decode("utf-8", errors="replace").strip()

            # Queue message (non-blocking with drop if full)
            try:
                self.message_queue.put_nowait(
                    {
                        "raw_message": raw_message,
                        "source_ip": source_ip,
                        "source_port": source_port,
                        "timestamp": time.time(),
                    }
                )
                stats.message_count += 1
                stats.last_seen = time.time()
            except asyncio.QueueFull:
                logger.error("Message queue full, dropping message")
                stats.error_count += 1

        except Exception as e:
            logger.error(f"Error processing UDP message from {source_ip}: {e}")
            stats = self._get_or_create_stats(source_ip)
            stats.error_count += 1

    def error_received(self, exc: Exception):
        """Called when an error occurs."""
        logger.error(f"UDP error: {exc}")

    def connection_lost(self, exc: Optional[Exception]):
        """Called when connection is lost."""
        if exc:
            logger.error(f"UDP connection lost: {exc}")

    def _get_or_create_stats(self, source_ip: str) -> SourceStats:
        """Get or create stats for a source."""
        if source_ip not in self.source_stats:
            self.source_stats[source_ip] = SourceStats(source_ip=source_ip)
        return self.source_stats[source_ip]

    def _check_rate_limit(self, stats: SourceStats) -> bool:
        """Check if source has exceeded rate limit."""
        current_time = time.time()
        time_elapsed = current_time - stats.first_seen

        if time_elapsed >= 1.0:
            # Reset stats for new second
            stats.first_seen = current_time
            stats.message_count = 1
            return True

        return stats.message_count < self.rate_limit_per_sec


class SyslogTCPProtocol(asyncio.Protocol):
    """TCP protocol handler for syslog messages."""

    def __init__(
        self,
        message_queue: asyncio.Queue,
        max_queue_size: int = 100000,
        rate_limit_per_sec: int = 10000,
    ):
        """Initialize TCP protocol.

        Args:
            message_queue: Queue to put received messages
            max_queue_size: Maximum queue size
            rate_limit_per_sec: Max messages per source per second
        """
        self.message_queue = message_queue
        self.max_queue_size = max_queue_size
        self.rate_limit_per_sec = rate_limit_per_sec
        self.transport = None
        self.source_ip = None
        self.source_port = None
        self.buffer = b""
        self.connection_time = time.time()
        self.message_count = 0
        self.error_count = 0

    def connection_made(self, transport):
        """Called when connection is made."""
        self.transport = transport
        peer_name = transport.get_extra_info("peername")
        if peer_name:
            self.source_ip, self.source_port = peer_name
            logger.debug(f"TCP connection from {self.source_ip}:{self.source_port}")

    def data_received(self, data: bytes):
        """Handle incoming TCP data.

        Args:
            data: Raw bytes received
        """
        if not data:
            return

        try:
            self.buffer += data
            self._process_buffer()
        except Exception as e:
            logger.error(f"Error processing TCP data: {e}")
            self.error_count += 1
            self.transport.close()

    def connection_lost(self, exc: Optional[Exception]):
        """Called when connection is lost."""
        if exc:
            logger.debug(f"TCP connection lost: {exc}")
        else:
            logger.debug(
                f"TCP connection closed: {self.message_count} messages received"
            )

    def _process_buffer(self):
        """Process buffered data for complete messages."""
        while self.buffer:
            # Try octet-counting framing first (RFC 5425)
            if self.buffer[0:1].isdigit():
                message, consumed = self._extract_octet_counted()
                if message is None:
                    break
                self._queue_message(message)
                self.buffer = self.buffer[consumed:]
            else:
                # Newline-delimited framing
                message, consumed = self._extract_newline_delimited()
                if message is None:
                    break
                self._queue_message(message)
                self.buffer = self.buffer[consumed:]

    def _extract_octet_counted(self) -> tuple:
        """Extract message using octet-counting framing.

        Returns:
            Tuple of (message, bytes_consumed) or (None, 0) if incomplete
        """
        # Find space after digit count
        space_idx = self.buffer.find(b" ")
        if space_idx == -1:
            return None, 0

        try:
            count = int(self.buffer[:space_idx])
            msg_start = space_idx + 1
            msg_end = msg_start + count

            if len(self.buffer) < msg_end:
                return None, 0

            message = self.buffer[msg_start:msg_end].decode("utf-8", errors="replace")
            return message, msg_end

        except (ValueError, UnicodeDecodeError):
            return None, 0

    def _extract_newline_delimited(self) -> tuple:
        """Extract message using newline-delimited framing.

        Returns:
            Tuple of (message, bytes_consumed) or (None, 0) if incomplete
        """
        newline_idx = self.buffer.find(b"\n")
        if newline_idx == -1:
            return None, 0

        message = self.buffer[:newline_idx].decode("utf-8", errors="replace").strip()
        return message, newline_idx + 1

    def _queue_message(self, raw_message: str):
        """Queue a parsed message."""
        try:
            if self.message_count >= self.rate_limit_per_sec:
                logger.warning(
                    f"Rate limit exceeded for {self.source_ip}, closing connection"
                )
                self.transport.close()
                return

            self.message_queue.put_nowait(
                {
                    "raw_message": raw_message,
                    "source_ip": self.source_ip or "unknown",
                    "source_port": self.source_port or 0,
                    "timestamp": time.time(),
                }
            )
            self.message_count += 1

        except asyncio.QueueFull:
            logger.error("Message queue full, closing connection")
            self.transport.close()
        except Exception as e:
            logger.error(f"Error queuing message: {e}")
            self.error_count += 1


class SyslogReceiver:
    """Main async syslog receiver for UDP and TCP."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        udp_port: int = 5514,
        tcp_port: int = 5514,
        max_queue_size: int = 100000,
        batch_size: int = 100,
        flush_interval: int = 5,
        message_handler: Optional[Callable] = None,
    ):
        """Initialize syslog receiver.

        Args:
            host: Host to listen on
            udp_port: UDP port for syslog
            tcp_port: TCP port for syslog
            max_queue_size: Maximum queue size
            batch_size: Number of messages to batch before flush
            flush_interval: Seconds between batch flushes
            message_handler: Async function to call with batch of messages
        """
        self.host = host
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.message_handler = message_handler

        self.message_queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self.parser = LogParserManager()

        # Stats tracking
        self.stats = {
            "messages_received": 0,
            "messages_processed": 0,
            "messages_dropped": 0,
            "bytes_received": 0,
            "errors": 0,
            "start_time": time.time(),
        }

        # Transports
        self.udp_transport = None
        self.tcp_server = None
        self._running = False

    async def start(self) -> None:
        """Start both UDP and TCP listeners."""
        loop = asyncio.get_event_loop()

        try:
            # Start UDP listener
            udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(self.message_queue),
                local_addr=(self.host, self.udp_port),
            )
            self.udp_transport = udp_transport
            logger.info(f"Syslog UDP listener started on {self.host}:{self.udp_port}")

            # Start TCP listener
            self.tcp_server = await loop.create_server(
                lambda: SyslogTCPProtocol(self.message_queue),
                self.host,
                self.tcp_port,
            )
            logger.info(f"Syslog TCP listener started on {self.host}:{self.tcp_port}")

            self._running = True

            # Start batch processor
            await self._batch_processor()

        except Exception as e:
            logger.error(f"Error starting syslog receiver: {e}")
            self._running = False
            raise

    async def stop(self) -> None:
        """Gracefully shutdown receivers."""
        logger.info("Stopping syslog receiver...")
        self._running = False

        # Flush remaining batch
        if not self.message_queue.empty():
            batch = []
            while not self.message_queue.empty():
                try:
                    batch.append(self.message_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            if batch:
                await self._flush_batch(batch)

        # Close transports
        if self.udp_transport:
            self.udp_transport.close()
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()

        logger.info("Syslog receiver stopped")

    async def _batch_processor(self) -> None:
        """Background task that batches and processes messages."""
        batch = []
        last_flush = time.time()

        while self._running:
            try:
                current_time = time.time()
                timeout = max(0.1, self.flush_interval - (current_time - last_flush))

                # Try to get a message with timeout
                try:
                    message = await asyncio.wait_for(
                        self.message_queue.get(), timeout=timeout
                    )
                    batch.append(message)
                    self.stats["messages_received"] += 1

                except asyncio.TimeoutError:
                    # Timeout - check if we should flush
                    pass

                # Check if we should flush
                should_flush = (
                    len(batch) >= self.batch_size
                    or (time.time() - last_flush) >= self.flush_interval
                ) and batch

                if should_flush:
                    await self._flush_batch(batch)
                    batch = []
                    last_flush = time.time()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch processor: {e}")
                self.stats["errors"] += 1
                await asyncio.sleep(1)

    async def _flush_batch(self, batch: List[Dict[str, Any]]) -> None:
        """Write batch to storage or handler.

        Args:
            batch: List of message dicts
        """
        if not batch:
            return

        try:
            # Process each message
            processed = []
            for msg_dict in batch:
                try:
                    processed_msg = await self._process_message(msg_dict)
                    if processed_msg:
                        processed.append(processed_msg)
                        self.stats["messages_processed"] += 1
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    self.stats["errors"] += 1

            # Call message handler if provided
            if self.message_handler and processed:
                try:
                    await self.message_handler(processed)
                except Exception as e:
                    logger.error(f"Error in message handler: {e}")
                    self.stats["errors"] += 1

        except Exception as e:
            logger.error(f"Error flushing batch: {e}")
            self.stats["errors"] += 1

    async def _process_message(self, msg_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single syslog message.

        Args:
            msg_dict: Dict with raw_message, source_ip, source_port, timestamp

        Returns:
            Processed message dict or None on error
        """
        try:
            raw_message = msg_dict.get("raw_message", "")
            source_ip = msg_dict.get("source_ip", "unknown")
            source_port = msg_dict.get("source_port", 0)
            recv_time = msg_dict.get("timestamp", time.time())

            # Update stats
            self.stats["bytes_received"] += len(raw_message.encode())

            # Parse the syslog message
            parsed = self.parser.parsers["syslog"].parse(raw_message)

            if not parsed:
                logger.warning(f"Failed to parse syslog from {source_ip}")
                return None

            # Extract key fields
            priority = parsed.get("priority", 0)
            facility = (priority >> 3) & 0x1F
            severity = priority & 0x07

            return {
                "raw_message": raw_message,
                "source_ip": source_ip,
                "source_port": source_port,
                "received_at": recv_time,
                "facility": SyslogFacility.from_code(facility),
                "severity": SyslogSeverity.from_code(severity),
                "priority": priority,
                "hostname": parsed.get("hostname", source_ip),
                "app_name": parsed.get("app_name", "unknown"),
                "process_id": parsed.get("process_id"),
                "timestamp": parsed.get("timestamp"),
                "message": parsed.get("message", raw_message),
                "parsed_fields": parsed,
            }

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            self.stats["errors"] += 1
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Get receiver statistics.

        Returns:
            Dict with stats
        """
        uptime = time.time() - self.stats["start_time"]
        return {
            **self.stats,
            "uptime_seconds": uptime,
            "messages_per_second": (
                self.stats["messages_received"] / uptime if uptime > 0 else 0
            ),
            "queue_size": self.message_queue.qsize(),
            "running": self._running,
        }

    def get_health(self) -> Dict[str, Any]:
        """Get health status.

        Returns:
            Health check dict
        """
        stats = self.get_stats()
        error_rate = (
            stats["errors"] / stats["messages_received"]
            if stats["messages_received"] > 0
            else 0
        )

        health_status = "healthy"
        if error_rate > 0.1:
            health_status = "degraded"
        if error_rate > 0.5 or not self._running:
            health_status = "unhealthy"

        return {
            "status": health_status,
            "uptime": stats["uptime_seconds"],
            "messages_received": stats["messages_received"],
            "error_rate": error_rate,
            "queue_size": stats["queue_size"],
        }
