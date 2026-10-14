"""Wave 3 (W3-E): phishing tracking, awareness scoring, training honesty.

Covers the deliverables for the phishing side of package W3-E:

* public tracking endpoints (pixel / click / report) that exist, work without
  authentication, are keyed by an unguessable per-recipient token, record a
  real CampaignEvent per recipient, never leak which tokens exist, and are
  rate-limited;
* the send path renders the per-recipient tracking URLs into the template;
* awareness scores are recalculated from recorded events, not caller input;
* the training catalogue is an honest 501;
* the ``/awareness-scores/high-risk`` route-order fix.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from src.phishing_sim.models import (
    CampaignEvent,
    PhishingCampaign,
    PhishingTarget,
    SecurityAwarenessScore,
)
from src.phishing_sim.tracking import (
    LINK_PLACEHOLDER,
    PIXEL_PLACEHOLDER,
    REPORT_PLACEHOLDER,
    generate_tracking_token,
    render_body,
    tracking_urls,
)

BASE = "/api/v1/phishing_sim"


async def _seed_campaign_target(db, org_id, *, token=None):
    """A real active campaign + one recipient target in ``org_id``."""
    campaign = PhishingCampaign(
        name=f"camp-{uuid.uuid4().hex[:6]}",
        campaign_type="email_phishing",
        status="active",
        total_targets=1,
        created_by="seed",
        organization_id=org_id,
    )
    db.add(campaign)
    await db.commit()
    await db.refresh(campaign)

    tok = token or generate_tracking_token()
    target = PhishingTarget(
        campaign_id=campaign.id,
        recipient_email="recipient@pysoar-tests.io",
        recipient_name="Reci Pient",
        status="sent",
        tracking_id=str(uuid.uuid4()),
        tracking_token=tok,
        organization_id=org_id,
    )
    db.add(target)
    await db.commit()
    return campaign.id, tok


# ---------------------------------------------------------------------------
# tracking helper (pure)
# ---------------------------------------------------------------------------
def test_tracking_token_is_unguessable_and_unique():
    tokens = {generate_tracking_token() for _ in range(100)}
    assert len(tokens) == 100
    assert all(len(t) >= 32 for t in tokens)


def test_render_body_substitutes_urls_and_injects_pixel():
    token = "TKN"
    urls = tracking_urls(token, base_url="https://x.test")
    html = f"<p>Hi {PIXEL_PLACEHOLDER} <a href='{LINK_PLACEHOLDER}'>go</a> {REPORT_PLACEHOLDER}</p>"
    out = render_body(html, token, is_html=True, base_url="https://x.test")
    assert urls["click"] in out
    assert urls["report"] in out
    assert urls["pixel"] in out  # pixel url inside the <img> tag

    # An HTML body with no placeholders still gets a pixel appended.
    plain_html = "<p>no markers</p>"
    out2 = render_body(plain_html, token, is_html=True, base_url="https://x.test")
    assert urls["pixel"] in out2

    assert render_body(None, token, is_html=True) is None


# ---------------------------------------------------------------------------
# public tracking endpoints
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_open_pixel_records_event_and_returns_gif(
    client: AsyncClient, db_session, org_a,
):
    org_id = org_a.id
    campaign_id, token = await _seed_campaign_target(db_session, org_id)

    resp = await client.get(f"{BASE}/t/{token}.gif")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/gif"
    assert resp.content[:6] == b"GIF89a"

    events = (await db_session.execute(
        select(CampaignEvent).where(CampaignEvent.campaign_id == campaign_id)
    )).scalars().all()
    assert [e.event_type for e in events] == ["email_opened"]
    assert events[0].organization_id == org_id

    campaign = (await db_session.execute(
        select(PhishingCampaign).where(PhishingCampaign.id == campaign_id)
    )).scalar_one()
    assert campaign.emails_opened == 1


@pytest.mark.asyncio
async def test_click_records_event_and_redirects(client: AsyncClient, db_session, org_a):
    org_id = org_a.id
    campaign_id, token = await _seed_campaign_target(db_session, org_id)

    resp = await client.get(f"{BASE}/c/{token}", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"]  # a safe destination, never empty

    events = (await db_session.execute(
        select(CampaignEvent).where(CampaignEvent.campaign_id == campaign_id)
    )).scalars().all()
    assert [e.event_type for e in events] == ["link_clicked"]

    # Clicking a simulated phish lowers the recipient's awareness score.
    score = (await db_session.execute(
        select(SecurityAwarenessScore).where(
            SecurityAwarenessScore.user_email == "recipient@pysoar-tests.io",
            SecurityAwarenessScore.organization_id == org_id,
        )
    )).scalar_one()
    assert score.times_clicked == 1
    assert score.overall_score < 50


@pytest.mark.asyncio
async def test_report_records_event_and_returns_204(client: AsyncClient, db_session, org_a):
    org_id = org_a.id
    campaign_id, token = await _seed_campaign_target(db_session, org_id)

    resp = await client.post(f"{BASE}/r/{token}")
    assert resp.status_code == 204

    events = (await db_session.execute(
        select(CampaignEvent).where(CampaignEvent.campaign_id == campaign_id)
    )).scalars().all()
    assert [e.event_type for e in events] == ["reported_as_phishing"]


@pytest.mark.asyncio
async def test_unknown_token_does_not_leak_and_records_nothing(
    client: AsyncClient, db_session, org_a,
):
    # A token with no target: every endpoint behaves identically to a valid
    # one (pixel 200, click 302, report 204) so the token space can't be probed.
    bogus = generate_tracking_token()
    assert (await client.get(f"{BASE}/t/{bogus}.gif")).status_code == 200
    assert (await client.get(f"{BASE}/c/{bogus}", follow_redirects=False)).status_code == 302
    assert (await client.post(f"{BASE}/r/{bogus}")).status_code == 204

    count = (await db_session.execute(select(CampaignEvent))).scalars().all()
    assert count == []


@pytest.mark.asyncio
async def test_tracking_is_rate_limited(client: AsyncClient, db_session, org_a):
    org_id = org_a.id
    campaign_id, token = await _seed_campaign_target(db_session, org_id)

    for _ in range(45):
        assert (await client.get(f"{BASE}/t/{token}.gif")).status_code == 200

    events = (await db_session.execute(
        select(CampaignEvent).where(CampaignEvent.campaign_id == campaign_id)
    )).scalars().all()
    # The per-(token, ip) limiter caps recorded events well below 45.
    assert 0 < len(events) <= 30


# ---------------------------------------------------------------------------
# awareness scores derived from events
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_awareness_calculate_derives_from_events(
    client: AsyncClient, db_session, org_a, org_a_headers,
):
    org_id = org_a.id
    campaign_id, token = await _seed_campaign_target(db_session, org_id)
    email = "learner@pysoar-tests.io"
    for etype in ("email_sent", "email_sent", "link_clicked"):
        db_session.add(CampaignEvent(
            campaign_id=campaign_id, target_email=email,
            event_type=etype, organization_id=org_id,
        ))
    await db_session.commit()

    resp = await client.post(
        f"{BASE}/awareness-scores/{email}/calculate?user_name=Learner",
        headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # 1 click over 2 sends -> 100 - int(0.5*40) = 80 (derived, not invented).
    assert body["overall_score"] == 80
    assert body["times_clicked"] == 1


@pytest.mark.asyncio
async def test_awareness_calculate_404_without_events(
    client: AsyncClient, db_session, org_a, org_a_headers,
):
    resp = await client.post(
        f"{BASE}/awareness-scores/nobody@pysoar-tests.io/calculate?user_name=No",
        headers=org_a_headers,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# route-order + training honesty
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_high_risk_route_is_reachable(client: AsyncClient, org_a_headers):
    resp = await client.get(f"{BASE}/awareness-scores/high-risk", headers=org_a_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_training_catalogue_is_honest_501(client: AsyncClient, org_a_headers):
    resp = await client.get(f"{BASE}/training/modules", headers=org_a_headers)
    assert resp.status_code == 501
    assert resp.json()["detail"]["error"] == "not_implemented"


# ---------------------------------------------------------------------------
# authenticated record_event still works + viewer is read-only
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_record_event_viewer_forbidden(
    client: AsyncClient, db_session, org_a, viewer_headers,
):
    org_id = org_a.id
    campaign_id, _ = await _seed_campaign_target(db_session, org_id)
    resp = await client.post(
        f"{BASE}/campaigns/{campaign_id}/events",
        json={"target_email": "x@pysoar-tests.io", "event_type": "link_clicked"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


async def test_repeated_events_never_inflate_counters_and_public_repeats_are_capped(
    client: AsyncClient, db_session, org_a,
) -> None:
    """Campaign counters count recipients: the first event of a type per
    recipient moves them, repeats do not. The public endpoints store at most
    ``_PUBLIC_EVENT_CAP`` repeats per recipient and type, then write nothing
    while still answering identically, so a leaked token cannot grow the
    table or push a rate past 100 %."""
    from sqlalchemy import func, select

    from src.api.v1.endpoints import phishing_sim as mod
    from src.phishing_sim.models import CampaignEvent, PhishingCampaign

    org_id = org_a.id
    campaign_id, token = await _seed_campaign_target(db_session, org_id)
    cap = mod._PUBLIC_EVENT_CAP
    for _ in range(cap + 10):
        resp = await client.get(f"{BASE}/t/{token}.gif")
        assert resp.status_code == 200
        mod._limiter._buckets.clear()  # isolate from the per-token rate limit
    stored = (await db_session.execute(
        select(func.count(CampaignEvent.id)).where(
            CampaignEvent.campaign_id == campaign_id, CampaignEvent.event_type == "email_opened",
        )
    )).scalar_one()
    assert stored == cap
    campaign = await db_session.get(PhishingCampaign, campaign_id)
    await db_session.refresh(campaign)
    assert campaign.emails_opened == 1

    # A click repeated through the public endpoint counts one recipient once.
    for _ in range(3):
        resp = await client.get(f"{BASE}/c/{token}", follow_redirects=False)
        assert resp.status_code in (302, 303, 307)
        mod._limiter._buckets.clear()
    await db_session.refresh(campaign)
    assert campaign.links_clicked == 1
