"""Token budgets, run admission and the provider circuit breaker (design sections 5/6).

Everything lives in Redis; clients are created lazily **inside the running
event loop** (per-loop factory), so a quota object used from two
``asyncio.run()`` calls never shares a connection.

Budgets (``reserve`` -> ``settle``, every turn)
    ``llm:budget:{org}:{day}:interactive`` and ``:autonomous`` hold the
    tokens already reserved/consumed today (UTC). A Lua script performs
    ``INCRBY`` only when ``current + reserve <= bucket cap`` **and**
    ``interactive + autonomous + reserve <= daily total``, and sets ``EXPIRE``
    in the same script. ``settle`` adjusts the bucket by ``actual - reserved``
    (clamped at zero). The autonomous cap is
    ``min(llm_autonomous_daily_token_budget, total * (100 - reserve_pct) / 100)``
    so the interactive reserve (default 40 %) can never be consumed by
    autonomous runs; interactive may burst into the autonomous share.

Redis down
    interactive: budget check is skipped (``Reservation.degraded``) and
    admission falls back to a process-local ``asyncio.Semaphore(4)`` per org;
    autonomous: fails closed with ``QuotaBackendUnavailable``.

Admission (``admit``)
    per-actor runs/minute plus ``llm:active:{actor}`` / ``llm:active:org:{org}``
    concurrency counters via ``INCR`` + ``EXPIRE``, released in ``finally``.
    Autonomous runs use ``agent:<soc_agent_id>`` actor buckets.

Circuit breaker
    per ``(provider, credential_source, org)``: opens after 5 transient/auth
    failures in 60 s, holds 60 s, then admits a single half-open probe.
"""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Literal, Optional

from redis import asyncio as aioredis
from redis.exceptions import RedisError

from src.core.config import Settings, settings as app_settings
from src.core.logging import get_logger
from src.llm.base import LLMError, LLMQuotaExceeded, LLMRateLimitError

logger = get_logger(__name__)

Bucket = Literal["interactive", "autonomous"]
BUCKETS: tuple[Bucket, ...] = ("interactive", "autonomous")

BUDGET_KEY_TTL_SECONDS = 48 * 3600
ADMISSION_TTL_SECONDS = {"interactive": 180, "autonomous": 1000}
BREAKER_FAILURE_THRESHOLD = 5
BREAKER_WINDOW_SECONDS = 60
BREAKER_OPEN_SECONDS = 60
LOCAL_FALLBACK_CONCURRENCY = 4
LOCAL_FALLBACK_WAIT_SECONDS = 5.0
NOTIFY_THRESHOLDS: tuple[int, ...] = (80, 100)

# -- Lua ------------------------------------------------------------------
# KEYS[1] = this bucket, KEYS[2] = the other bucket
# ARGV[1] = reserve, ARGV[2] = bucket cap, ARGV[3] = daily total, ARGV[4] = ttl
RESERVE_LUA = """-- pysoar:llm:reserve
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local other = tonumber(redis.call('GET', KEYS[2]) or '0')
local reserve = tonumber(ARGV[1])
local cap = tonumber(ARGV[2])
local total = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
if (cur + reserve > cap) or (cur + other + reserve > total) then
  return {0, cur, other}
end
local new = redis.call('INCRBY', KEYS[1], reserve)
redis.call('EXPIRE', KEYS[1], ttl)
return {1, new, other}
"""

# KEYS[1] = bucket; ARGV[1] = delta (actual - reserved, may be negative), ARGV[2] = ttl
SETTLE_LUA = """-- pysoar:llm:settle
local delta = tonumber(ARGV[1])
local new = redis.call('INCRBY', KEYS[1], delta)
if new < 0 then
  redis.call('SET', KEYS[1], 0)
  new = 0
end
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
return new
"""

# KEYS[1] = counter; ARGV[1] = ttl -> INCR + EXPIRE atomically
INCR_EXPIRE_LUA = """-- pysoar:llm:incr_expire
local new = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
return new
"""

# KEYS[1] = counter -> DECR clamped at zero
DECR_CLAMP_LUA = """-- pysoar:llm:decr_clamp
local new = redis.call('DECR', KEYS[1])
if new < 0 then
  redis.call('SET', KEYS[1], 0)
  new = 0
end
return new
"""


class QuotaBackendUnavailable(LLMQuotaExceeded):
    """Redis is unreachable and the caller's mode fails closed (autonomous)."""

    code = "quota_backend_unavailable"


class CircuitOpen(LLMError):
    """The provider breaker is open; no provider call was attempted."""

    code = "llm_unavailable"
    retryable = False


@dataclass
class Reservation:
    org_id: str
    bucket: Bucket
    day: str
    reserved: int
    bucket_used: int  # after this reservation
    bucket_cap: int
    credential_source: Literal["org", "platform"] = "org"
    degraded: bool = False  # Redis down: nothing was reserved
    threshold_crossed: Optional[int] = None  # 80 when this reservation first crossed 80 %
    settled: bool = False

    @property
    def key(self) -> str:
        return budget_key(self.org_id, self.day, self.bucket)


@dataclass
class Admission:
    org_id: str
    actor_key: str
    bucket: Bucket
    degraded: bool = False
    _release: list[Callable[[], Awaitable[None]]] = field(default_factory=list, repr=False)


@dataclass(frozen=True)
class BucketUsage:
    bucket: Bucket
    used: int
    cap: int

    @property
    def remaining(self) -> int:
        return max(self.cap - self.used, 0)


def utc_day(now: Optional[datetime] = None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%d")


def budget_key(org_id: str, day: str, bucket: str) -> str:
    return f"llm:budget:{org_id}:{day}:{bucket}"


def platform_budget_key(day: str, bucket: str) -> str:
    return f"llm:budget:platform:{day}:{bucket}"


def default_redis_factory(cfg: Optional[Settings] = None) -> Callable[[], aioredis.Redis]:
    """Factory building a fresh client from ``settings.redis_url`` (per loop)."""
    cfg = cfg or app_settings

    def _make() -> aioredis.Redis:
        return aioredis.from_url(
            cfg.redis_url,
            decode_responses=True,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
        )

    return _make


def _is_redis_down(exc: BaseException) -> bool:
    return isinstance(exc, (RedisError, OSError, asyncio.TimeoutError, TimeoutError))


class TokenQuota:
    """Budget, admission and breaker operations for one process/loop."""

    def __init__(
        self,
        *,
        redis_factory: Optional[Callable[[], Any]] = None,
        cfg: Optional[Settings] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self.cfg = cfg or app_settings
        self._factory = redis_factory or default_redis_factory(self.cfg)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._client: Any = None
        self._client_loop: Optional[asyncio.AbstractEventLoop] = None
        self._local_semaphores: dict[tuple[int, str], asyncio.Semaphore] = {}

    # -- redis lifecycle ---------------------------------------------------

    async def _redis(self) -> Any:
        loop = asyncio.get_running_loop()
        if self._client is not None and self._client_loop is loop:
            return self._client
        if self._client is not None:
            await self._close_client(self._client)
        self._client = self._factory()
        self._client_loop = loop
        return self._client

    @staticmethod
    async def _close_client(client: Any) -> None:
        closer = getattr(client, "aclose", None) or getattr(client, "close", None)
        if closer is None:
            return
        try:
            result = closer()
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:  # noqa: BLE001 - closing is best effort
            logger.warning("llm_quota_redis_close_failed", error=str(exc))

    async def aclose(self) -> None:
        client, self._client, self._client_loop = self._client, None, None
        if client is not None:
            await self._close_client(client)

    async def __aenter__(self) -> "TokenQuota":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # -- budgets -----------------------------------------------------------

    def daily_total(self) -> int:
        return int(self.cfg.llm_daily_token_budget)

    def bucket_cap(self, bucket: Bucket) -> int:
        total = self.daily_total()
        if bucket == "interactive":
            return total
        autonomous_share = total * (100 - int(self.cfg.llm_interactive_reserve_pct)) // 100
        return min(int(self.cfg.llm_autonomous_daily_token_budget), autonomous_share)

    @staticmethod
    def _other(bucket: Bucket) -> Bucket:
        return "autonomous" if bucket == "interactive" else "interactive"

    async def reserve(
        self,
        org_id: str,
        bucket: Bucket,
        tokens: int,
        *,
        credential_source: Literal["org", "platform"] = "org",
    ) -> Reservation:
        """Reserve ``tokens`` for one turn or raise ``LLMQuotaExceeded``."""
        if not org_id:
            raise ValueError("reserve requires an organization id")
        if bucket not in BUCKETS:
            raise ValueError(f"unknown bucket {bucket!r}")
        tokens = max(int(tokens), 0)
        day = utc_day(self._clock())
        cap = self.bucket_cap(bucket)
        key = budget_key(org_id, day, bucket)
        other = budget_key(org_id, day, self._other(bucket))
        try:
            redis = await self._redis()
            result = await redis.eval(RESERVE_LUA, 2, key, other, tokens, cap, self.daily_total(), BUDGET_KEY_TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001 - classified below
            if not _is_redis_down(exc):
                raise
            return self._reserve_degraded(org_id, bucket, day, tokens, cap, credential_source, exc)
        ok, used, other_used = int(result[0]), int(result[1]), int(result[2])
        if not ok:
            first = await self._mark_threshold(key, 100)
            err = LLMQuotaExceeded(
                f"{bucket} token budget exhausted for organization (used={used}, cap={cap}, "
                f"other_bucket={other_used}, requested={tokens})"
            )
            err.bucket = bucket  # type: ignore[attr-defined]
            err.used = used  # type: ignore[attr-defined]
            err.cap = cap  # type: ignore[attr-defined]
            err.first_exhaustion = first  # type: ignore[attr-defined]
            logger.warning("llm_budget_exhausted", organization_id=org_id, bucket=bucket, used=used, cap=cap)
            raise err
        if credential_source == "platform":
            await self._track_platform(day, bucket, tokens)
        threshold: Optional[int] = None
        if cap > 0 and used * 100 >= cap * 80:
            if await self._mark_threshold(key, 80):
                threshold = 80
        return Reservation(
            org_id=org_id,
            bucket=bucket,
            day=day,
            reserved=tokens,
            bucket_used=used,
            bucket_cap=cap,
            credential_source=credential_source,
            threshold_crossed=threshold,
        )

    def _reserve_degraded(
        self,
        org_id: str,
        bucket: Bucket,
        day: str,
        tokens: int,
        cap: int,
        credential_source: Literal["org", "platform"],
        exc: Exception,
    ) -> Reservation:
        if bucket == "autonomous":
            logger.error("llm_quota_backend_unavailable", organization_id=org_id, bucket=bucket, error=str(exc))
            raise QuotaBackendUnavailable("quota backend unavailable; autonomous runs fail closed") from exc
        logger.warning(
            "llm_quota_degraded",
            organization_id=org_id,
            bucket=bucket,
            error=str(exc),
            note="Redis unreachable: interactive turn admitted without budget accounting",
        )
        return Reservation(
            org_id=org_id,
            bucket=bucket,
            day=day,
            reserved=0,
            bucket_used=0,
            bucket_cap=cap,
            credential_source=credential_source,
            degraded=True,
        )

    async def settle(self, reservation: Reservation, actual_tokens: int) -> None:
        """Replace the reservation with the measured (or estimated) usage."""
        if reservation.settled:
            return
        reservation.settled = True
        if reservation.degraded:
            return
        delta = max(int(actual_tokens), 0) - reservation.reserved
        try:
            redis = await self._redis()
            await redis.eval(SETTLE_LUA, 1, reservation.key, delta, BUDGET_KEY_TTL_SECONDS)
            if reservation.credential_source == "platform" and delta:
                await self._track_platform(reservation.day, reservation.bucket, delta)
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise
            logger.warning(
                "llm_quota_settle_lost",
                organization_id=reservation.org_id,
                bucket=reservation.bucket,
                delta=delta,
                error=str(exc),
            )

    async def _track_platform(self, day: str, bucket: Bucket, delta: int) -> None:
        """Platform-wide accounting for shared-key usage (visibility only, not enforced)."""
        try:
            redis = await self._redis()
            await redis.eval(SETTLE_LUA, 1, platform_budget_key(day, bucket), delta, BUDGET_KEY_TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise

    async def _mark_threshold(self, key: str, pct: int) -> bool:
        """``SET NX`` a notification flag; True when this call set it (first crossing)."""
        try:
            redis = await self._redis()
            return bool(await redis.set(f"{key}:notified:{pct}", "1", nx=True, ex=BUDGET_KEY_TTL_SECONDS))
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise
            return False

    async def usage(self, org_id: str, *, day: Optional[str] = None) -> dict[str, BucketUsage]:
        """Today's reserved/consumed tokens per bucket. Raises ``QuotaBackendUnavailable`` when Redis is down."""
        if not org_id:
            raise ValueError("usage requires an organization id")
        day = day or utc_day(self._clock())
        out: dict[str, BucketUsage] = {}
        try:
            redis = await self._redis()
            for bucket in BUCKETS:
                raw = await redis.get(budget_key(org_id, day, bucket))
                out[bucket] = BucketUsage(bucket=bucket, used=int(raw or 0), cap=self.bucket_cap(bucket))
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise
            raise QuotaBackendUnavailable("quota backend unavailable") from exc
        return out

    # -- run admission -----------------------------------------------------

    def _local_semaphore(self, org_id: str) -> asyncio.Semaphore:
        key = (id(asyncio.get_running_loop()), org_id)
        sem = self._local_semaphores.get(key)
        if sem is None:
            sem = asyncio.Semaphore(LOCAL_FALLBACK_CONCURRENCY)
            self._local_semaphores[key] = sem
        return sem

    @contextlib.asynccontextmanager
    async def admit(self, org_id: str, actor_key: str, bucket: Bucket) -> AsyncIterator[Admission]:
        """Admission for one run; releases the concurrency slots on exit."""
        if not org_id or not actor_key:
            raise ValueError("admit requires organization id and actor key")
        admission = Admission(org_id=org_id, actor_key=actor_key, bucket=bucket)
        try:
            await self._admit_redis(admission)
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise
            await self._admit_degraded(admission, exc)
        try:
            yield admission
        finally:
            for release in reversed(admission._release):
                try:
                    await release()
                except Exception as rel_exc:  # noqa: BLE001 - release is best effort
                    logger.warning("llm_admission_release_failed", organization_id=org_id, error=str(rel_exc))

    async def _admit_redis(self, admission: Admission) -> None:
        redis = await self._redis()
        now = self._clock()
        ttl = ADMISSION_TTL_SECONDS[admission.bucket]
        minute = now.strftime("%Y%m%d%H%M")
        rpm_key = f"llm:runs:{admission.actor_key}:{minute}"
        runs = int(await redis.eval(INCR_EXPIRE_LUA, 1, rpm_key, 60))
        if runs > int(self.cfg.llm_user_runs_per_minute):
            retry_after = float(60 - now.second)
            raise LLMRateLimitError(
                f"run rate limit exceeded for {admission.actor_key} ({runs}/min)", retry_after=retry_after
            )

        actor_key = f"llm:active:{admission.actor_key}"
        active_actor = int(await redis.eval(INCR_EXPIRE_LUA, 1, actor_key, ttl))
        if active_actor > int(self.cfg.llm_user_concurrency):
            await redis.eval(DECR_CLAMP_LUA, 1, actor_key)
            raise LLMRateLimitError(
                f"too many concurrent runs for {admission.actor_key} ({active_actor})", retry_after=1.0
            )
        admission._release.append(lambda: self._decr(actor_key))

        org_key = f"llm:active:org:{admission.org_id}"
        active_org = int(await redis.eval(INCR_EXPIRE_LUA, 1, org_key, ttl))
        if active_org > int(self.cfg.llm_org_concurrency):
            await redis.eval(DECR_CLAMP_LUA, 1, org_key)
            await redis.eval(DECR_CLAMP_LUA, 1, actor_key)
            admission._release.clear()
            raise LLMRateLimitError(
                f"too many concurrent runs for organization ({active_org})", retry_after=1.0
            )
        admission._release.append(lambda: self._decr(org_key))

    async def _decr(self, key: str) -> None:
        try:
            redis = await self._redis()
            await redis.eval(DECR_CLAMP_LUA, 1, key)
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise
            logger.warning("llm_admission_release_lost", key=key, error=str(exc))

    async def _admit_degraded(self, admission: Admission, exc: Exception) -> None:
        if admission.bucket == "autonomous":
            logger.error("llm_admission_backend_unavailable", organization_id=admission.org_id, error=str(exc))
            raise QuotaBackendUnavailable("quota backend unavailable; autonomous runs fail closed") from exc
        logger.warning(
            "llm_admission_degraded",
            organization_id=admission.org_id,
            error=str(exc),
            note=f"Redis unreachable: process-local semaphore({LOCAL_FALLBACK_CONCURRENCY}) per org in effect",
        )
        sem = self._local_semaphore(admission.org_id)
        try:
            await asyncio.wait_for(sem.acquire(), timeout=LOCAL_FALLBACK_WAIT_SECONDS)
        except asyncio.TimeoutError as wait_exc:
            raise LLMRateLimitError("organization at local concurrency limit", retry_after=1.0) from wait_exc
        admission.degraded = True

        async def _release() -> None:
            sem.release()

        admission._release.append(_release)

    # -- autonomous kickoff caps (design section 6) --------------------------

    async def try_start_autonomous(
        self, org_id: str, *, max_running: int = 3, max_per_hour: int = 20
    ) -> tuple[bool, str]:
        """Enqueue-time admission for an autonomous investigation.

        Returns ``(allowed, reason)``; on success the ``running`` counter is
        incremented and must be released with :meth:`finish_autonomous`.
        Fails closed (``QuotaBackendUnavailable``) when Redis is down.
        """
        if not org_id:
            raise ValueError("try_start_autonomous requires an organization id")
        try:
            redis = await self._redis()
            now = self._clock()
            usage = await self.usage(org_id)
            if usage["autonomous"].remaining <= 0:
                return False, "queued_budget_exceeded"
            running_key = f"llm:auto:running:{org_id}"
            running = int(await redis.eval(INCR_EXPIRE_LUA, 1, running_key, ADMISSION_TTL_SECONDS["autonomous"]))
            if running > max_running:
                await redis.eval(DECR_CLAMP_LUA, 1, running_key)
                return False, "queued_concurrency"
            hour_key = f"llm:auto:started:{org_id}:{now.strftime('%Y%m%d%H')}"
            started = int(await redis.eval(INCR_EXPIRE_LUA, 1, hour_key, 3600))
            if started > max_per_hour:
                await redis.eval(DECR_CLAMP_LUA, 1, running_key)
                return False, "queued_hourly_cap"
            return True, "ok"
        except QuotaBackendUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise
            raise QuotaBackendUnavailable("quota backend unavailable; autonomous kickoff fails closed") from exc

    async def finish_autonomous(self, org_id: str) -> None:
        await self._decr(f"llm:auto:running:{org_id}")

    # -- circuit breaker ---------------------------------------------------

    @staticmethod
    def _breaker_prefix(provider: str, credential_source: str, org_id: str) -> str:
        return f"llm:cb:{provider}:{credential_source}:{org_id}"

    async def breaker_check(self, provider: str, credential_source: str, org_id: str) -> None:
        """Raise ``CircuitOpen`` when the breaker is open (or a probe is already in flight)."""
        prefix = self._breaker_prefix(provider, credential_source, org_id)
        try:
            redis = await self._redis()
            if await redis.get(f"{prefix}:open"):
                raise CircuitOpen(f"{provider} circuit open for organization")
            if await redis.get(f"{prefix}:halfopen"):
                probe = await redis.set(f"{prefix}:probe", "1", nx=True, ex=BREAKER_OPEN_SECONDS)
                if not probe:
                    raise CircuitOpen(f"{provider} circuit half-open; probe already in flight")
        except CircuitOpen:
            raise
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise
            logger.warning("llm_breaker_check_degraded", provider=provider, error=str(exc))

    async def breaker_record_failure(self, provider: str, credential_source: str, org_id: str) -> bool:
        """Count a transient/auth failure. Returns True when the breaker (re)opened."""
        prefix = self._breaker_prefix(provider, credential_source, org_id)
        try:
            redis = await self._redis()
            if await redis.get(f"{prefix}:halfopen"):
                await self._open_breaker(redis, prefix, provider, org_id)
                return True
            failures = int(await redis.eval(INCR_EXPIRE_LUA, 1, f"{prefix}:fail", BREAKER_WINDOW_SECONDS))
            if failures >= BREAKER_FAILURE_THRESHOLD:
                await self._open_breaker(redis, prefix, provider, org_id)
                return True
            return False
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise
            return False

    async def _open_breaker(self, redis: Any, prefix: str, provider: str, org_id: str) -> None:
        await redis.set(f"{prefix}:open", "1", ex=BREAKER_OPEN_SECONDS)
        await redis.set(f"{prefix}:halfopen", "1", ex=BREAKER_OPEN_SECONDS * 2)
        await redis.delete(f"{prefix}:probe", f"{prefix}:fail")
        # One breaker_open log line per minute per breaker.
        if await redis.set(f"{prefix}:logged", "1", nx=True, ex=60):
            logger.error("llm_breaker_open", provider=provider, organization_id=org_id, hold_seconds=BREAKER_OPEN_SECONDS)

    async def breaker_record_success(self, provider: str, credential_source: str, org_id: str) -> None:
        prefix = self._breaker_prefix(provider, credential_source, org_id)
        try:
            redis = await self._redis()
            await redis.delete(f"{prefix}:open", f"{prefix}:halfopen", f"{prefix}:probe", f"{prefix}:fail")
        except Exception as exc:  # noqa: BLE001
            if not _is_redis_down(exc):
                raise


# -- budget events (SC-5) ----------------------------------------------------


async def record_budget_event(
    db: Any,
    *,
    org_id: str,
    bucket: str,
    pct: int,
    used: int,
    cap: int,
    run_id: Optional[str] = None,
    actor_id: str = "system",
) -> None:
    """Write the ``security/llm.budget.threshold`` AuditTrail row (flush only; caller commits)
    and broadcast a system event on the existing WebSocket channel.

    Called by the runtime when ``Reservation.threshold_crossed`` is set or an
    ``LLMQuotaExceeded`` with ``first_exhaustion`` is raised, because only the
    runtime holds the DB session.
    """
    from src.audit_evidence.engine import AuditLogger

    await AuditLogger(db, org_id).log_event(
        event_type="security",
        action="llm.budget.exhausted" if pct >= 100 else "llm.budget.threshold",
        actor_type="system",
        actor_id=actor_id,
        resource_type="llm_budget",
        resource_id=f"{org_id}:{bucket}",
        description=f"LLM {bucket} token budget at {pct}% ({used}/{cap} tokens today)",
        new_value={"bucket": bucket, "pct": pct, "used": used, "cap": cap, "control": "SC-5"},
        result="denied" if pct >= 100 else "success",
        risk_level="high" if pct >= 100 else "medium",
        run_id=run_id,
    )
    try:
        from src.services.websocket_manager import notify_system_event

        await notify_system_event(
            "llm_budget",
            f"LLM {bucket} token budget at {pct}%",
            {"organization_id": org_id, "bucket": bucket, "pct": pct, "used": used, "cap": cap},
        )
    except Exception as exc:  # noqa: BLE001 - notification is best effort, audit row is not
        logger.warning("llm_budget_notify_failed", organization_id=org_id, error=str(exc))


__all__ = [
    "ADMISSION_TTL_SECONDS",
    "BUCKETS",
    "Admission",
    "Bucket",
    "BucketUsage",
    "CircuitOpen",
    "DECR_CLAMP_LUA",
    "INCR_EXPIRE_LUA",
    "QuotaBackendUnavailable",
    "RESERVE_LUA",
    "Reservation",
    "SETTLE_LUA",
    "TokenQuota",
    "budget_key",
    "default_redis_factory",
    "platform_budget_key",
    "record_budget_event",
    "utc_day",
]
