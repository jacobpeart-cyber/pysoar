"""TokenQuota: reserve/settle, bucket split, admission, breaker and Redis-down semantics.

``fakeredis`` is not in the venv, so ``FakeRedis`` below is a minimal
in-memory client implementing exactly the commands ``src.llm.quota`` uses
(``eval`` dispatches on the ``-- pysoar:llm:*`` marker comment of each script).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from src.llm.base import LLMQuotaExceeded, LLMRateLimitError
from src.llm.quota import (
    LOCAL_FALLBACK_CONCURRENCY,
    CircuitOpen,
    QuotaBackendUnavailable,
    TokenQuota,
    budget_key,
    platform_budget_key,
    utc_day,
)


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttl: dict[str, int] = {}
        self.down = False
        self.closed = 0
        self.evals: list[str] = []

    def _check(self) -> None:
        if self.down:
            raise RedisConnectionError("Error 111 connecting to redis:6379. Connection refused.")

    async def get(self, key: str) -> str | None:
        self._check()
        return self.store.get(key)

    async def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool | None:
        self._check()
        if nx and key in self.store:
            return None
        self.store[key] = str(value)
        if ex is not None:
            self.ttl[key] = ex
        return True

    async def delete(self, *keys: str) -> int:
        self._check()
        n = 0
        for key in keys:
            if self.store.pop(key, None) is not None:
                n += 1
            self.ttl.pop(key, None)
        return n

    async def incrby(self, key: str, amount: int) -> int:
        self._check()
        value = int(self.store.get(key, "0")) + int(amount)
        self.store[key] = str(value)
        return value

    async def expire(self, key: str, seconds: int) -> bool:
        self._check()
        self.ttl[key] = int(seconds)
        return True

    async def eval(self, script: str, numkeys: int, *args: Any) -> Any:
        self._check()
        keys = [str(a) for a in args[:numkeys]]
        argv = [str(a) for a in args[numkeys:]]
        marker = script.splitlines()[0].strip()
        self.evals.append(marker)
        if marker == "-- pysoar:llm:reserve":
            cur = int(self.store.get(keys[0], "0"))
            other = int(self.store.get(keys[1], "0"))
            reserve, cap, total, ttl = (int(float(a)) for a in argv)
            if cur + reserve > cap or cur + other + reserve > total:
                return [0, cur, other]
            new = await self.incrby(keys[0], reserve)
            await self.expire(keys[0], ttl)
            return [1, new, other]
        if marker == "-- pysoar:llm:settle":
            delta, ttl = int(float(argv[0])), int(float(argv[1]))
            new = await self.incrby(keys[0], delta)
            if new < 0:
                self.store[keys[0]] = "0"
                new = 0
            await self.expire(keys[0], ttl)
            return new
        if marker == "-- pysoar:llm:incr_expire":
            new = await self.incrby(keys[0], 1)
            await self.expire(keys[0], int(float(argv[0])))
            return new
        if marker == "-- pysoar:llm:decr_clamp":
            new = await self.incrby(keys[0], -1)
            if new < 0:
                self.store[keys[0]] = "0"
                new = 0
            return new
        raise AssertionError(f"unexpected script {marker!r}")

    async def aclose(self) -> None:
        self.closed += 1


def _cfg(**overrides: Any) -> SimpleNamespace:
    base = dict(
        redis_url="redis://unused",
        llm_daily_token_budget=1000,
        llm_autonomous_daily_token_budget=800,
        llm_interactive_reserve_pct=40,
        llm_user_runs_per_minute=3,
        llm_user_concurrency=2,
        llm_org_concurrency=3,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


FIXED_NOW = datetime(2026, 9, 20, 10, 30, 15, tzinfo=timezone.utc)


@pytest.fixture
def redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture
def quota(redis: FakeRedis) -> TokenQuota:
    return TokenQuota(redis_factory=lambda: redis, cfg=_cfg(), clock=lambda: FIXED_NOW)


def test_bucket_caps_split_interactive_reserve() -> None:
    q = TokenQuota(redis_factory=FakeRedis, cfg=_cfg())
    assert q.daily_total() == 1000
    assert q.bucket_cap("interactive") == 1000
    # min(800, 1000 * 60%) = 600: autonomous can never eat the 40 % reserve
    assert q.bucket_cap("autonomous") == 600
    q2 = TokenQuota(redis_factory=FakeRedis, cfg=_cfg(llm_autonomous_daily_token_budget=100))
    assert q2.bucket_cap("autonomous") == 100


async def test_reserve_then_settle_down(quota: TokenQuota, redis: FakeRedis) -> None:
    day = utc_day(FIXED_NOW)
    res = await quota.reserve("org-a", "interactive", 300)
    assert res.reserved == 300 and res.bucket_used == 300 and res.bucket_cap == 1000
    assert res.degraded is False and res.threshold_crossed is None
    assert redis.store[budget_key("org-a", day, "interactive")] == "300"
    assert redis.ttl[budget_key("org-a", day, "interactive")] == 48 * 3600
    await quota.settle(res, 120)
    assert redis.store[budget_key("org-a", day, "interactive")] == "120"
    assert res.settled is True
    await quota.settle(res, 999)  # idempotent
    assert redis.store[budget_key("org-a", day, "interactive")] == "120"


async def test_settle_charges_overrun_and_never_goes_negative(quota: TokenQuota, redis: FakeRedis) -> None:
    day = utc_day(FIXED_NOW)
    res = await quota.reserve("org-a", "interactive", 100)
    await quota.settle(res, 250)
    assert redis.store[budget_key("org-a", day, "interactive")] == "250"
    res2 = await quota.reserve("org-a", "interactive", 50)
    redis.store[budget_key("org-a", day, "interactive")] = "10"  # simulate concurrent drift
    await quota.settle(res2, 0)
    assert redis.store[budget_key("org-a", day, "interactive")] == "0"


async def test_autonomous_cannot_consume_interactive_reserve(quota: TokenQuota) -> None:
    res = await quota.reserve("org-a", "autonomous", 600)
    assert res.bucket_used == 600
    with pytest.raises(LLMQuotaExceeded) as info:
        await quota.reserve("org-a", "autonomous", 1)
    assert info.value.bucket == "autonomous" and info.value.cap == 600  # type: ignore[attr-defined]
    assert info.value.first_exhaustion is True  # type: ignore[attr-defined]
    # interactive still has its 40 % reserve (and the whole remainder)
    ok = await quota.reserve("org-a", "interactive", 400)
    assert ok.bucket_used == 400
    with pytest.raises(LLMQuotaExceeded) as second:
        await quota.reserve("org-a", "interactive", 1)  # 600 + 400 == daily total
    assert second.value.first_exhaustion is True  # type: ignore[attr-defined]
    with pytest.raises(LLMQuotaExceeded) as third:
        await quota.reserve("org-a", "interactive", 1)
    assert third.value.first_exhaustion is False  # type: ignore[attr-defined]


async def test_interactive_may_burst_into_autonomous_share(quota: TokenQuota) -> None:
    res = await quota.reserve("org-a", "interactive", 900)
    assert res.bucket_used == 900
    with pytest.raises(LLMQuotaExceeded):
        await quota.reserve("org-a", "autonomous", 200)  # 900 + 200 > 1000
    small = await quota.reserve("org-a", "autonomous", 100)
    assert small.bucket_used == 100


async def test_buckets_are_per_org_and_per_day(quota: TokenQuota, redis: FakeRedis) -> None:
    await quota.reserve("org-a", "interactive", 1000)
    other = await quota.reserve("org-b", "interactive", 1000)
    assert other.bucket_used == 1000
    tomorrow = TokenQuota(redis_factory=lambda: redis, cfg=_cfg(), clock=lambda: FIXED_NOW + timedelta(days=1))
    again = await tomorrow.reserve("org-a", "interactive", 1000)
    assert again.day != utc_day(FIXED_NOW) and again.bucket_used == 1000


async def test_threshold_80_reported_once(quota: TokenQuota) -> None:
    first = await quota.reserve("org-a", "interactive", 850)
    assert first.threshold_crossed == 80
    second = await quota.reserve("org-a", "interactive", 10)
    assert second.threshold_crossed is None


async def test_platform_key_usage_is_tracked_platform_wide(quota: TokenQuota, redis: FakeRedis) -> None:
    day = utc_day(FIXED_NOW)
    res = await quota.reserve("org-a", "interactive", 100, credential_source="platform")
    assert redis.store[platform_budget_key(day, "interactive")] == "100"
    await quota.settle(res, 40)
    assert redis.store[platform_budget_key(day, "interactive")] == "40"
    await quota.reserve("org-b", "interactive", 100, credential_source="org")
    assert redis.store[platform_budget_key(day, "interactive")] == "40"


async def test_usage_reports_both_buckets(quota: TokenQuota) -> None:
    await quota.reserve("org-a", "interactive", 100)
    await quota.reserve("org-a", "autonomous", 50)
    usage = await quota.usage("org-a")
    assert usage["interactive"].used == 100 and usage["interactive"].remaining == 900
    assert usage["autonomous"].used == 50 and usage["autonomous"].cap == 600


async def test_redis_down_interactive_degrades_autonomous_fails_closed(quota: TokenQuota, redis: FakeRedis) -> None:
    redis.down = True
    res = await quota.reserve("org-a", "interactive", 100)
    assert res.degraded is True and res.reserved == 0
    await quota.settle(res, 50)  # no-op, no raise
    with pytest.raises(QuotaBackendUnavailable) as info:
        await quota.reserve("org-a", "autonomous", 100)
    assert isinstance(info.value, LLMQuotaExceeded)
    assert info.value.code == "quota_backend_unavailable"
    with pytest.raises(QuotaBackendUnavailable):
        await quota.usage("org-a")


async def test_settle_after_redis_dies_is_logged_not_raised(quota: TokenQuota, redis: FakeRedis) -> None:
    res = await quota.reserve("org-a", "interactive", 100)
    redis.down = True
    await quota.settle(res, 10)
    assert res.settled is True


async def test_non_redis_errors_propagate(redis: FakeRedis) -> None:
    class Broken(FakeRedis):
        async def eval(self, *a: Any, **k: Any) -> Any:
            raise ValueError("programming error")

    q = TokenQuota(redis_factory=Broken, cfg=_cfg(), clock=lambda: FIXED_NOW)
    with pytest.raises(ValueError):
        await q.reserve("org-a", "interactive", 1)


async def test_admission_counters_and_release(quota: TokenQuota, redis: FakeRedis) -> None:
    async with quota.admit("org-a", "user:u1", "interactive") as adm:
        assert adm.degraded is False
        assert redis.store["llm:active:user:u1"] == "1"
        assert redis.store["llm:active:org:org-a"] == "1"
        assert redis.ttl["llm:active:user:u1"] == 180
        assert redis.store["llm:runs:user:u1:202609201030"] == "1"
        assert redis.ttl["llm:runs:user:u1:202609201030"] == 60
    assert redis.store["llm:active:user:u1"] == "0"
    assert redis.store["llm:active:org:org-a"] == "0"


async def test_admission_releases_on_exception(quota: TokenQuota, redis: FakeRedis) -> None:
    with pytest.raises(RuntimeError):
        async with quota.admit("org-a", "user:u1", "interactive"):
            raise RuntimeError("boom")
    assert redis.store["llm:active:user:u1"] == "0" and redis.store["llm:active:org:org-a"] == "0"


async def test_runs_per_minute_limit(quota: TokenQuota) -> None:
    for _ in range(3):
        async with quota.admit("org-a", "user:u1", "interactive"):
            pass
    with pytest.raises(LLMRateLimitError) as info:
        async with quota.admit("org-a", "user:u1", "interactive"):
            pass
    assert info.value.retry_after == 45.0  # 60 - 15 s into the minute


async def test_user_and_org_concurrency_caps(quota: TokenQuota, redis: FakeRedis) -> None:
    cm1 = quota.admit("org-a", "user:u1", "interactive")
    cm2 = quota.admit("org-a", "user:u1", "interactive")
    await cm1.__aenter__()
    await cm2.__aenter__()
    with pytest.raises(LLMRateLimitError):
        async with quota.admit("org-a", "user:u1", "interactive"):
            pass
    assert redis.store["llm:active:user:u1"] == "2"  # failed attempt rolled back
    cm3 = quota.admit("org-a", "user:u2", "interactive")
    await cm3.__aenter__()
    with pytest.raises(LLMRateLimitError):
        async with quota.admit("org-a", "user:u3", "interactive"):
            pass
    assert redis.store["llm:active:org:org-a"] == "3"
    assert redis.store["llm:active:user:u3"] == "0"
    for cm in (cm1, cm2, cm3):
        await cm.__aexit__(None, None, None)
    assert redis.store["llm:active:org:org-a"] == "0"


async def test_autonomous_admission_uses_agent_bucket_and_long_ttl(quota: TokenQuota, redis: FakeRedis) -> None:
    async with quota.admit("org-a", "agent:s1", "autonomous"):
        assert redis.ttl["llm:active:agent:s1"] == 1000


async def test_admission_redis_down_semantics(quota: TokenQuota, redis: FakeRedis) -> None:
    redis.down = True
    with pytest.raises(QuotaBackendUnavailable):
        async with quota.admit("org-a", "agent:s1", "autonomous"):
            pass
    held = []
    for _ in range(LOCAL_FALLBACK_CONCURRENCY):
        cm = quota.admit("org-a", "user:u", "interactive")
        adm = await cm.__aenter__()
        assert adm.degraded is True
        held.append(cm)
    sem = quota._local_semaphore("org-a")
    assert sem.locked()
    for cm in held:
        await cm.__aexit__(None, None, None)
    assert not sem.locked()


async def test_try_start_autonomous_caps(quota: TokenQuota, redis: FakeRedis) -> None:
    for _ in range(3):
        assert await quota.try_start_autonomous("org-a") == (True, "ok")
    assert await quota.try_start_autonomous("org-a") == (False, "queued_concurrency")
    assert redis.store["llm:auto:running:org-a"] == "3"
    await quota.finish_autonomous("org-a")
    assert await quota.try_start_autonomous("org-a", max_per_hour=3) == (False, "queued_hourly_cap")
    await quota.reserve("org-a", "autonomous", 600)
    assert await quota.try_start_autonomous("org-a") == (False, "queued_budget_exceeded")
    redis.down = True
    with pytest.raises(QuotaBackendUnavailable):
        await quota.try_start_autonomous("org-a")


async def test_circuit_breaker_opens_after_five_failures_then_probes(quota: TokenQuota, redis: FakeRedis) -> None:
    key = ("gemini", "org", "org-a")
    await quota.breaker_check(*key)
    for i in range(4):
        assert await quota.breaker_record_failure(*key) is False
    assert await quota.breaker_record_failure(*key) is True
    with pytest.raises(CircuitOpen) as info:
        await quota.breaker_check(*key)
    assert info.value.code == "llm_unavailable" and info.value.retryable is False
    assert redis.ttl["llm:cb:gemini:org:org-a:open"] == 60
    # other tuple unaffected
    await quota.breaker_check("gemini", "platform", "org-a")
    await quota.breaker_check("gemini", "org", "org-b")
    # hold expires -> half-open: exactly one probe passes
    del redis.store["llm:cb:gemini:org:org-a:open"]
    await quota.breaker_check(*key)
    with pytest.raises(CircuitOpen):
        await quota.breaker_check(*key)
    # probe fails -> reopens immediately
    assert await quota.breaker_record_failure(*key) is True
    assert "llm:cb:gemini:org:org-a:open" in redis.store
    # probe succeeds -> fully closed
    del redis.store["llm:cb:gemini:org:org-a:open"]
    await quota.breaker_check(*key)
    await quota.breaker_record_success(*key)
    remaining = {k for k in redis.store if k.startswith("llm:cb:gemini:org:org-a")}
    assert remaining == {"llm:cb:gemini:org:org-a:logged"}  # one breaker_open log line per minute
    await quota.breaker_check(*key)


async def test_breaker_degrades_open_when_redis_down(quota: TokenQuota, redis: FakeRedis) -> None:
    redis.down = True
    await quota.breaker_check("gemini", "org", "org-a")
    assert await quota.breaker_record_failure("gemini", "org", "org-a") is False
    await quota.breaker_record_success("gemini", "org", "org-a")


def test_redis_client_is_per_event_loop() -> None:
    clients: list[FakeRedis] = []

    def factory() -> FakeRedis:
        client = FakeRedis()
        clients.append(client)
        return client

    quota = TokenQuota(redis_factory=factory, cfg=_cfg(), clock=lambda: FIXED_NOW)

    async def _use() -> None:
        await quota.reserve("org-a", "interactive", 1)
        await quota.reserve("org-a", "interactive", 1)

    asyncio.run(_use())
    asyncio.run(_use())
    assert len(clients) == 2 and clients[0] is not clients[1]
    assert clients[0].closed == 1  # replaced client was closed
    asyncio.run(quota.aclose())
    assert clients[1].closed == 1


async def test_record_budget_event_writes_audit_row(db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy import select

    from src.audit_evidence.models import AuditTrail
    from src.llm.quota import record_budget_event

    broadcasts: list[tuple[str, str, dict[str, Any]]] = []

    async def fake_notify(event_type: str, message: str, data: dict[str, Any] | None = None) -> None:
        broadcasts.append((event_type, message, data or {}))

    monkeypatch.setattr("src.services.websocket_manager.notify_system_event", fake_notify)
    await record_budget_event(db_session, org_id="org-a", bucket="autonomous", pct=100, used=600, cap=600, run_id="run-1")
    await db_session.commit()
    rows = (await db_session.execute(select(AuditTrail).where(AuditTrail.organization_id == "org-a"))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.event_type == "security" and row.action == "llm.budget.exhausted"
    assert row.result == "denied" and row.risk_level == "high" and row.run_id == "run-1"
    assert row.new_value["control"] == "SC-5"
    assert broadcasts and broadcasts[0][0] == "llm_budget" and broadcasts[0][2]["pct"] == 100
