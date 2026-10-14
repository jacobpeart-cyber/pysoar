"""Phishing tracking tokens and public tracking URLs.

A phishing simulation can only measure who opened / clicked / reported if
the message carries links the recipient's browser will hit WITHOUT a login.
Those links must be:

* **unguessable** — one per recipient, generated with :mod:`secrets` so an
  attacker (or a curious employee) cannot enumerate other recipients'
  tokens and forge events for them;
* **opaque** — the token identifies the ``PhishingTarget`` row server-side;
  nothing about the campaign, org or recipient is encoded in it.

The three public endpoints in ``src/api/v1/endpoints/phishing_sim.py`` resolve
a token back to its target row and record the event. This module only knows
how to mint a token and render the URLs into a template body; it never touches
the database so it is safe to import from both the request path and the
Celery send task.
"""

from __future__ import annotations

import os
import secrets

# 32 bytes -> ~43 url-safe characters. Collision-resistant and infeasible to
# guess, which is the whole point: events are accepted for a token or not at
# all, with no fallback to a scannable id space.
_TOKEN_NBYTES = 32

# Placeholders a template author (or the default body) can drop into the
# HTML / text so the per-recipient URLs land in the right place. If the HTML
# body contains none of them, the send task injects the pixel automatically
# (see ``render_body``).
PIXEL_PLACEHOLDER = "{{tracking_pixel}}"
LINK_PLACEHOLDER = "{{tracking_link}}"
REPORT_PLACEHOLDER = "{{report_link}}"


def generate_tracking_token() -> str:
    """Return a fresh, unguessable per-recipient tracking token."""
    return secrets.token_urlsafe(_TOKEN_NBYTES)


def public_base_url() -> str:
    """Public origin the recipient's browser can reach.

    Shared with :func:`src.services.notifications._public_base_url` via the
    same env var so links are consistent across the platform.
    """
    return os.environ.get("PYSOAR_PUBLIC_URL", "https://pysoar.it.com").rstrip("/")


def tracking_urls(token: str, base_url: str | None = None) -> dict[str, str]:
    """The three public tracking URLs for one recipient token."""
    base = (base_url or public_base_url()).rstrip("/")
    root = f"{base}/api/v1/phishing_sim"
    return {
        "pixel": f"{root}/t/{token}.gif",
        "click": f"{root}/c/{token}",
        "report": f"{root}/r/{token}",
    }


def _pixel_tag(pixel_url: str) -> str:
    return (
        f'<img src="{pixel_url}" width="1" height="1" alt="" '
        f'style="display:none" />'
    )


def render_body(
    body: str | None,
    token: str,
    *,
    is_html: bool,
    base_url: str | None = None,
) -> str | None:
    """Render tracking placeholders (and recipient token) into a message body.

    * ``{{tracking_link}}`` / ``{{report_link}}`` -> the click-redirect and
      report URLs.
    * ``{{tracking_pixel}}`` -> a 1x1 pixel ``<img>`` (HTML) or the pixel URL
      (text).
    * ``{{tracking_id}}`` -> the raw token (kept for templates that build
      their own URLs).
    * For an HTML body that references none of the placeholders, the pixel is
      appended so an open can still be measured.
    """
    if body is None:
        return None

    urls = tracking_urls(token, base_url=base_url)
    pixel_fragment = _pixel_tag(urls["pixel"]) if is_html else urls["pixel"]

    rendered = (
        body.replace(PIXEL_PLACEHOLDER, pixel_fragment)
        .replace(LINK_PLACEHOLDER, urls["click"])
        .replace(REPORT_PLACEHOLDER, urls["report"])
        .replace("{{tracking_id}}", token)
    )

    if is_html and PIXEL_PLACEHOLDER not in body and urls["pixel"] not in rendered:
        rendered = f"{rendered}\n{pixel_fragment}"

    return rendered


# A transparent 1x1 GIF. Returned by the pixel endpoint for every request so
# a valid or invalid token is indistinguishable from the caller's side (no
# enumeration oracle).
TRANSPARENT_GIF: bytes = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
    b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
    b"\x00\x00\x02\x02D\x01\x00;"
)
