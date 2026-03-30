"""Event bus and real-time streaming pipeline with Redis Streams"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from redis import asyncio as aioredis

from src.core.logging import get_logger
from src.core.websocket import manager as ws_manager

logger = get_logger(__name__)


class EventType(str, Enum):
    """Enumeration of event types"""

    # Alert events
    ALERT_CREATED = "alert_created"
    ALERT_UPDATED = "alert_updated"
    ALERT_ESCALATED = "alert_escalated"
    ALERT_RESOLVED = "alert_resolved"

    # Incident events
    INCIDENT_CREATED = "incident_created"
    INCIDENT_ESCALATED = "incident_escalated"
    INCIDENT_RESOLVED = "incident_resolved"
    INCIDENT_UPDATED = "incident_updated"

    # Playbook events
    PLAYBOOK_TRIGGERED = "playbook_triggered"
    PLAYBOOK_EXECUTION_STARTED = "playbook_execution_started"
    PLAYBOOK_STEP_COMPLETED = "playbook_step_completed"
    PLAYBOOK_EXECUTION_COMPLETED = "playbook_execution_completed"
    PLAYBOOK_EXECUTION_FAILED = "playbook_execution_failed"

    # Remediation events
    REMEDIATION_EXECUTED = "remediation_executed"
    REMEDIATION_FAILED = "remediation_failed"

    # Threat events
    THREAT_DETECTED = "threat_detected"
    IOC_MATCHED = "ioc_matched"

    # Compliance events
    COMPLIANCE_VIOLATION = "compliance_violation"
    COMPLIANCE_CHECK_PASSED = "compliance_check_passed"

    # User behavior events
    USER_ANOMALY = "user_anomaly"

    # Collaboration events
    WARROOM_CREATED = "warroom_created"
    WARROOM_MESSAGE = "warroom_message"
    WARROOM_CLOSED = "warroom_closed"

    # Integration events
    INTEGRATION_EVENT = "integration_event"

    # System events
    SYSTEM_HEALTH = "system_health"
    SYSTEM_ALERT = "system_alert"


class Event:
    """Represents a system event"""

    def __init__(
        self,
        event_type: EventType,
        org_id: str,
        data: Dict[str, Any],
        source_module: str = "system",
    ):
        self.id = str(uuid.uuid4())
        self.type = event_type
        self.org_id = org_id
        self.data = data
        self.source_module = source_module
        self.timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "id": self.id,
            "type": self.type.value,
            "org_id": self.org_id,
            "data": self.data,
            "source_module": self.source_module,
            "timestamp": self.timestamp.isoformat(),
        }


class EventBus:
    """Central event bus for publishing and subscribing to events"""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None
        self.handlers: Dict[EventType, List[Callable]] = {}
        self.stream_name = "events:stream"

    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis = await aioredis.from_url(self.redis_url)
            logger.info("EventBus initialized with Redis")
        except Exception as e:
            logger.error(f"Failed to initialize EventBus: {e}")

    async def publish(
        self,
        event_type: EventType,
        org_id: str,
        data: Dict[str, Any],
        source_module: str = "system",
    ) -> Optional[str]:
        """
        Publish an event to Redis Streams.

        Returns the stream ID if successful.
        """
        event = Event(event_type, org_id, data, source_module)

        if not self.redis:
            logger.warning("EventBus not initialized, skipping publish")
            return None

        try:
            # Add to Redis Stream
            stream_id = await self.redis.xadd(
                self.stream_name,
                {"data": json.dumps(event.to_dict())},
            )
            logger.debug(f"Event published: {event_type} {event.id}")

            # Trigger local handlers
            if event_type in self.handlers:
                for handler in self.handlers[event_type]:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            await handler(event)
                        else:
                            handler(event)
                    except Exception as e:
                        logger.error(f"Error in event handler: {e}")

            return stream_id.decode() if isinstance(stream_id, bytes) else stream_id

        except Exception as e:
            logger.error(f"Failed to publish event: {e}")
            return None

    async def subscribe(
        self,
        event_types: List[EventType],
        handler: Callable,
    ):
        """Register an async handler for event types"""
        for event_type in event_types:
            if event_type not in self.handlers:
                self.handlers[event_type] = []
            self.handlers[event_type].append(handler)
            logger.info(f"Subscribed to {event_type}")

    async def close(self):
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()


class EventProcessor:
    """
    Processes events from Redis Streams.

    - Consumes from Redis Streams
    - Routes events to registered handlers
    - Pushes to WebSocket via ConnectionManager
    - Triggers async processing via Celery
    """

    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.redis: Optional[aioredis.Redis] = None
        self.task: Optional[asyncio.Task] = None
        self.stream_name = "events:stream"
        self.consumer_group = "event_processor"
        self.last_processed_id = "0"
        self.dead_letter_queue = "events:dlq"

    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis = await aioredis.from_url(self.event_bus.redis_url)

            # Create consumer group if it doesn't exist
            try:
                await self.redis.xgroup_create(
                    self.stream_name,
                    self.consumer_group,
                    id="0",
                    mkstream=True,
                )
            except Exception as e:
                # Group likely already exists
                logger.debug(f"Consumer group creation: {e}")

            self.task = asyncio.create_task(self._process_stream())
            logger.info("EventProcessor initialized")
        except Exception as e:
            logger.error(f"Failed to initialize EventProcessor: {e}")

    async def _process_stream(self):
        """Process events from Redis Streams"""
        if not self.redis:
            return

        try:
            while True:
                try:
                    # Read pending messages
                    messages = await self.redis.xreadgroup(
                        {self.stream_name: ">"},
                        self.consumer_group,
                        block=1000,
                        count=10,
                    )

                    if not messages:
                        continue

                    for stream_name, message_list in messages:
                        for message_id, message_data in message_list:
                            await self._handle_event(message_id, message_data)

                except Exception as e:
                    logger.error(f"Error processing stream: {e}")
                    await asyncio.sleep(1)

        except asyncio.CancelledError:
            logger.info("EventProcessor stopped")

    async def _handle_event(self, message_id: bytes, message_data: dict):
        """Handle a single event from the stream"""
        try:
            event_json = message_data.get(b"data", b"{}").decode()
            event_dict = json.loads(event_json)

            org_id = event_dict.get("org_id")
            event_type_str = event_dict.get("type")

            # Route to WebSocket
            if org_id:
                # Broadcast to org
                await ws_manager.broadcast_to_org(org_id, event_dict)

            # Acknowledge message
            if self.redis:
                await self.redis.xack(self.stream_name, self.consumer_group, message_id)
                logger.debug(f"Event processed: {event_type_str}")

        except Exception as e:
            logger.error(f"Error handling event: {e}")
            # Move to dead letter queue
            await self._send_to_dlq(message_data, str(e))

    async def _send_to_dlq(self, message_data: dict, error: str):
        """Send failed message to dead letter queue"""
        if not self.redis:
            return

        try:
            dlq_entry = {
                "data": json.dumps(message_data),
                "error": error,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await self.redis.xadd(self.dead_letter_queue, dlq_entry)
        except Exception as e:
            logger.error(f"Failed to send to DLQ: {e}")

    async def close(self):
        """Close processor"""
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        if self.redis:
            await self.redis.close()


class SIEMEventPipeline:
    """
    Real-time SIEM event pipeline.

    - Accepts raw log events via Redis Streams
    - Batch processing: accumulate events, process in batches of 100
    - Back-pressure handling: if queue exceeds threshold, drop lowest-priority events
    - Metrics: events_per_second, queue_depth, processing_latency
    """

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None
        self.input_stream = "siem:logs:input"
        self.batch_size = 100
        self.queue_threshold = 10000
        self.batch_timeout_seconds = 5

        # Metrics
        self.events_received = 0
        self.events_dropped = 0
        self.bytes_processed = 0
        self.processing_start_time = time.time()

        self.task: Optional[asyncio.Task] = None
        self.batch: List[Dict[str, Any]] = []
        self.batch_timer: Optional[asyncio.Task] = None

    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis = await aioredis.from_url(self.redis_url)
            self.task = asyncio.create_task(self._process_loop())
            logger.info("SIEMEventPipeline initialized")
        except Exception as e:
            logger.error(f"Failed to initialize SIEMEventPipeline: {e}")

    async def ingest_log(self, log_data: Dict[str, Any]) -> bool:
        """
        Ingest a log event.

        Returns True if accepted, False if dropped due to back-pressure.
        """
        if not self.redis:
            return False

        try:
            # Check queue depth
            queue_size = await self.redis.xlen(self.input_stream)

            if queue_size > self.queue_threshold:
                # Drop low-priority events
                if log_data.get("priority", 5) < 7:
                    self.events_dropped += 1
                    logger.warning(f"Event dropped due to back-pressure (queue: {queue_size})")
                    return False

            # Add to input stream
            await self.redis.xadd(
                self.input_stream,
                {"data": json.dumps(log_data)},
            )

            self.events_received += 1
            self.bytes_processed += len(json.dumps(log_data))

            return True

        except Exception as e:
            logger.error(f"Failed to ingest log: {e}")
            return False

    async def _process_loop(self):
        """Main processing loop"""
        if not self.redis:
            return

        try:
            while True:
                try:
                    # Read from input stream
                    messages = await self.redis.xread(
                        {self.input_stream: self.batch[-1]["id"] if self.batch else "$"},
                        block=1000,
                        count=50,
                    )

                    if messages:
                        for stream_name, message_list in messages:
                            for message_id, message_data in message_list:
                                await self._add_to_batch(message_id, message_data)

                    # Process batch if full or timeout
                    if len(self.batch) >= self.batch_size:
                        await self._process_batch()

                except Exception as e:
                    logger.error(f"Error in processing loop: {e}")
                    await asyncio.sleep(1)

        except asyncio.CancelledError:
            logger.info("SIEMEventPipeline stopped")

    async def _add_to_batch(self, message_id: bytes, message_data: dict):
        """Add message to processing batch"""
        try:
            event_json = message_data.get(b"data", b"{}").decode()
            event_dict = json.loads(event_json)
            event_dict["id"] = message_id.decode() if isinstance(message_id, bytes) else message_id

            self.batch.append(event_dict)

            # Set timeout for batch processing
            if len(self.batch) == 1:
                self.batch_timer = asyncio.create_task(
                    self._batch_timeout()
                )

        except Exception as e:
            logger.error(f"Error adding to batch: {e}")

    async def _batch_timeout(self):
        """Process batch after timeout"""
        try:
            await asyncio.sleep(self.batch_timeout_seconds)
            if self.batch:
                await self._process_batch()
        except asyncio.CancelledError:
            pass

    async def _process_batch(self):
        """Process accumulated batch of events"""
        if not self.batch:
            return

        batch_to_process = self.batch[:]
        self.batch = []

        try:
            logger.debug(f"Processing batch of {len(batch_to_process)} events")

            # Process events (normalization, correlation, enrichment)
            for event in batch_to_process:
                org_id = event.get("org_id", "default")

                # Normalize event
                normalized = self._normalize_event(event)

                # Publish to event bus
                await ws_manager.broadcast_to_org(org_id, normalized)

            if self.batch_timer:
                self.batch_timer.cancel()
                self.batch_timer = None

        except Exception as e:
            logger.error(f"Error processing batch: {e}")

    def _normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw log event"""
        return {
            "type": "siem_event",
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "source": event.get("source", "unknown"),
            "level": event.get("level", "info"),
            "message": event.get("message", ""),
            "data": event,
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get pipeline metrics"""
        elapsed = time.time() - self.processing_start_time
        events_per_second = self.events_received / elapsed if elapsed > 0 else 0

        return {
            "events_received": self.events_received,
            "events_dropped": self.events_dropped,
            "bytes_processed": self.bytes_processed,
            "events_per_second": events_per_second,
            "queue_depth": len(self.batch),
            "uptime_seconds": elapsed,
        }

    async def close(self):
        """Close pipeline"""
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        if self.batch_timer:
            self.batch_timer.cancel()

        if self.redis:
            await self.redis.close()
