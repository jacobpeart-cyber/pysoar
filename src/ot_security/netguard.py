"""Network guard for OT active discovery.

Active discovery opens TCP sockets from the API host, so a target is only
ever probed when all of the following hold:

1. it is not a loopback, link-local, multicast, unspecified or reserved
   range and does not overlap the platform deny list (cloud metadata,
   shared address space), whatever the tenant's zones say;
2. the platform operator has allowlisted it in
   ``settings.ot_discovery_allowed_cidrs`` (empty list = discovery disabled,
   so the gate fails closed);
3. it lies inside one of the tenant's own OT zones (a tenant with no zone
   cannot run discovery at all).

The same deny rule is applied when a zone is created or updated so that a
tenant cannot widen the allowlist through zone configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Iterable, Optional, Union

Network = Union[IPv4Network, IPv6Network]

PLATFORM_DENY_NETWORKS: tuple[Network, ...] = tuple(
    ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local incl. cloud metadata 169.254.169.254
        "100.64.0.0/10",  # carrier-grade NAT / cloud shared address space
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
    )
)


def internal_network_reason(net: Network) -> Optional[str]:
    """Return why ``net`` must never be probed, or ``None`` when it may be."""
    if net.is_loopback:
        return "loopback"
    if net.is_link_local:
        return "link-local"
    if net.is_multicast:
        return "multicast"
    if net.is_unspecified:
        return "unspecified"
    if net.is_reserved:
        return "reserved"
    for deny in PLATFORM_DENY_NETWORKS:
        if deny.version == net.version and net.overlaps(deny):
            return f"platform-internal ({deny})"
    return None


def parse_cidrs(raw: Iterable[str]) -> list[Network]:
    """Parse CIDR strings, silently skipping unparseable entries."""
    out: list[Network] = []
    for item in raw:
        try:
            out.append(ip_network(str(item).strip(), strict=False))
        except ValueError:
            continue
    return out


def contained_in(net: Network, allowed: Iterable[Network]) -> bool:
    return any(a.version == net.version and net.subnet_of(a) for a in allowed)  # type: ignore[arg-type]


@dataclass(frozen=True)
class DiscoveryRefusal:
    error: str
    detail: str


def check_discovery_target(
    net: Network,
    platform_allowlist: list[Network],
    zone_networks: list[Network],
) -> Optional[DiscoveryRefusal]:
    """Return the refusal for ``net`` or ``None`` when it may be probed."""
    reason = internal_network_reason(net)
    if reason:
        return DiscoveryRefusal("target_network_refused", f"{net} is a {reason} range and is never scanned")
    if not platform_allowlist:
        return DiscoveryRefusal(
            "ot_discovery_disabled",
            "active OT discovery is disabled on this platform (OT_DISCOVERY_ALLOWED_CIDRS is empty)",
        )
    if not contained_in(net, platform_allowlist):
        return DiscoveryRefusal(
            "cidr_outside_platform_allowlist",
            f"{net} is not inside the platform's OT_DISCOVERY_ALLOWED_CIDRS",
        )
    if not zone_networks:
        return DiscoveryRefusal(
            "ot_zones_required",
            "configure at least one OT zone with a network_cidr before running discovery",
        )
    if not contained_in(net, zone_networks):
        return DiscoveryRefusal(
            "cidr_outside_ot_zones",
            f"{net} must lie inside one of the organization's OT zone networks",
        )
    return None
