"""
URL validation utility to prevent SSRF attacks.

Validates URLs before making outbound requests to prevent
Server-Side Request Forgery (SSRF) attacks that could access
internal services, cloud metadata endpoints, or private networks.
"""

import ipaddress
import logging
import socket
from urllib.parse import urlparse
from typing import Optional, Set

logger = logging.getLogger(__name__)

# Blocked hostnames that should never be accessed by the application
BLOCKED_HOSTNAMES: Set[str] = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    # Cloud metadata endpoints
    "metadata.google.internal",
    "169.254.169.254",
    "metadata.internal",
    # Kubernetes internal
    "kubernetes.default.svc",
    "kubernetes.default",
}

# Allowed URL schemes
ALLOWED_SCHEMES: Set[str] = {"http", "https"}


def validate_url(
    url: str,
    allow_private: bool = False,
    allowed_domains: Optional[Set[str]] = None,
) -> tuple[bool, str]:
    """
    Validate a URL is safe to fetch (not internal/private).

    Args:
        url: The URL to validate
        allow_private: If True, allows private IP ranges (for internal integrations)
        allowed_domains: If set, only these domains are allowed

    Returns:
        (is_valid, reason) tuple
    """
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False, f"Blocked scheme: {parsed.scheme}"

        hostname = parsed.hostname
        if not hostname:
            return False, "No hostname in URL"

        # Check blocked hostnames
        if hostname.lower() in BLOCKED_HOSTNAMES:
            return False, f"Blocked hostname: {hostname}"

        # Check domain allowlist if provided
        if allowed_domains and hostname.lower() not in allowed_domains:
            return False, f"Domain not in allowlist: {hostname}"

        # Resolve hostname and check IP ranges
        try:
            resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
            for family, type_, proto, canonname, sockaddr in resolved:
                ip = ipaddress.ip_address(sockaddr[0])
                if not allow_private:
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                        logger.warning(
                            f"SSRF blocked: {url} resolves to private/internal IP {ip}"
                        )
                        return False, f"URL resolves to private/internal IP"
        except socket.gaierror:
            return False, f"Cannot resolve hostname: {hostname}"

        return True, "OK"

    except Exception as e:
        logger.error(f"URL validation error: {e}")
        return False, f"URL validation failed: {str(e)}"
