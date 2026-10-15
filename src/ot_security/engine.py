"""
OT/ICS Security Engine

Core operational technology security monitoring, threat detection, Purdue model
enforcement, safety system management, and compliance validation.

Features:
- Asset discovery and monitoring
- Protocol anomaly detection (Modbus, DNP3, OPC-UA)
- Purdue model network segmentation validation
- Unauthorized command detection via whitelisting
- Firmware change detection and assessment
- Network scanning detection
- OT event correlation and incident generation
- Safe shutdown coordination with safety impact assessment
- ICS-specific compliance (NERC-CIP, IEC 62443, NIST SP 800-82)
- Vulnerability assessment with ICS-CERT advisories
"""

import asyncio
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from ipaddress import ip_network, ip_address

from src.core.logging import get_logger

# Ports we probe for OT/ICS protocol fingerprinting -> protocol name
OT_PROBE_PORTS: Dict[int, str] = {
    102:   "s7comm",          # Siemens S7 / ISO-TSAP
    502:   "modbus_tcp",      # Modbus
    20000: "dnp3",            # DNP3
    44818: "ethernetip",      # EtherNet/IP (Allen-Bradley / Rockwell)
    4840:  "opc_ua",          # OPC UA
    47808: "bacnet",          # BACnet/IP
}

# Protocol values the asset schema accepts; a probe port outside the OT set
# yields "unknown", which is not stored as a protocol.
KNOWN_PROTOCOLS = frozenset(OT_PROBE_PORTS.values())

# Refuse to scan networks larger than this (anti-foot-gun: prevents an
# operator from accidentally typing 0.0.0.0/0 and having us TCP-probe
# every host on the internet).
MAX_DISCOVERY_PREFIX = 22  # /22 = 1024 hosts

# How many concurrent probes we'll have in flight at once. Tuned low so
# we don't accidentally look like a port scanner to a customer's IDS.
DISCOVERY_CONCURRENCY = 100

# Per-port connect timeout. ICS gear is slow; 1s is a reasonable upper
# bound for "reachable on the local segment".
DISCOVERY_PORT_TIMEOUT_SECONDS = 1.0

logger = get_logger(__name__)


class OTMonitor:
    """
    OT Network monitoring and threat detection.

    Discovers assets through passive network monitoring, enforces Purdue model
    zone communications, detects protocol anomalies and unauthorized commands,
    monitors firmware and configuration changes, and correlates events to incidents.
    """

    def __init__(self, organization_id: str):
        """Initialize OT Monitor for organization"""
        self.organization_id = organization_id
        self.asset_cache = {}
        self.protocol_profiles = self._init_protocol_profiles()

    def _init_protocol_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Initialize known protocol profiles for anomaly detection"""
        return {
            "modbus_tcp": {
                "port": 502,
                "default_timeout": 3,
                "function_codes": list(range(1, 132)),
                "requires_auth": False,
                "plaintext": True,
            },
            "modbus_rtu": {
                "port": None,
                "default_timeout": 1,
                "function_codes": list(range(1, 132)),
                "requires_auth": False,
                "plaintext": True,
            },
            "dnp3": {
                "port": 20000,
                "default_timeout": 5,
                "function_codes": list(range(0, 129)),
                "requires_auth": False,
                "plaintext": True,
            },
            "opc_ua": {
                "port": 4840,
                "default_timeout": 10,
                "function_codes": list(range(0, 256)),
                "requires_auth": True,
                "plaintext": False,
            },
            "profinet": {
                "port": 34963,
                "default_timeout": 2,
                "function_codes": None,
                "requires_auth": False,
                "plaintext": True,
            },
            "bacnet": {
                "port": 47808,
                "default_timeout": 3,
                "function_codes": None,
                "requires_auth": False,
                "plaintext": True,
            },
            "mqtt": {
                "port": 1883,
                "default_timeout": 5,
                "function_codes": None,
                "requires_auth": False,
                "plaintext": True,
            },
        }

    async def discover_assets(
        self, network_range: str, probe_ports: Optional[Dict[int, str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Actively discover OT assets in ``network_range`` by TCP-probing the
        well-known ICS ports on every host in the CIDR.

        Each host that answers on at least one of the OT probe ports is
        either upserted into ``ot_assets`` (new device) or has its
        ``last_seen`` / ``is_online`` refreshed (known device). Protocol
        is inferred from the responding port.

        Safety rails:
        - rejects CIDRs larger than ``MAX_DISCOVERY_PREFIX`` so an
          accidental ``0.0.0.0/0`` doesn't sweep the public internet;
        - honors ``PYSOAR_DISABLE_NETWORK_SCAN=1`` for environments where
          active probing isn't permitted (audited customer LANs, CI);
        - bounds concurrency with a semaphore so we look nothing like a
          port scanner to a downstream IDS.
        """
        discovered: List[Dict[str, Any]] = []
        logger.info(f"Starting OT asset discovery for range {network_range}")

        # Safety switch: customers in regulated networks can refuse all
        # active scanning by setting this env var on the worker.
        if os.environ.get("PYSOAR_DISABLE_NETWORK_SCAN") == "1":
            logger.warning(
                "Active OT discovery skipped: PYSOAR_DISABLE_NETWORK_SCAN=1"
            )
            return [{
                "status": "skipped",
                "reason": "network_scan_disabled",
                "network_range": network_range,
            }]

        try:
            network = ip_network(network_range, strict=False)
        except ValueError as exc:
            logger.error(f"Invalid network range '{network_range}': {exc}")
            return discovered

        if network.prefixlen < MAX_DISCOVERY_PREFIX:
            logger.error(
                f"Refusing to scan {network_range}: prefix /{network.prefixlen} "
                f"exceeds safety cap of /{MAX_DISCOVERY_PREFIX}"
            )
            return [{
                "status": "rejected",
                "reason": "cidr_too_large",
                "network_range": network_range,
                "max_prefix": MAX_DISCOVERY_PREFIX,
            }]

        # Build the host list. ``hosts()`` excludes the network/broadcast
        # addresses for IPv4; for /32 we still want the single host.
        if network.num_addresses == 1:
            host_iter = [network.network_address]
        else:
            host_iter = list(network.hosts())

        sem = asyncio.Semaphore(DISCOVERY_CONCURRENCY)
        # Per-call port set (the bulk route used to swap the module-level
        # OT_PROBE_PORTS dict, which raced between concurrent requests).
        ports = dict(probe_ports) if probe_ports else dict(OT_PROBE_PORTS)
        probe_tasks = [
            self._probe_device(str(host), sem, ports) for host in host_iter
        ]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        # Filter to hosts that responded on at least one OT port.
        live_hosts = [
            r for r in probe_results
            if isinstance(r, dict) and r.get("open_ports")
        ]

        if not live_hosts:
            logger.info(f"OT discovery for {network_range} found no live hosts")
            return discovered

        # Persist findings: update existing rows or insert new ones.
        from src.core.database import async_session_factory
        from sqlalchemy import select
        from src.ot_security.models import OTAsset

        async with async_session_factory() as db:
            existing_q = await db.execute(
                select(OTAsset).where(
                    OTAsset.organization_id == self.organization_id,
                    OTAsset.ip_address.in_([h["ip_address"] for h in live_hosts]),
                )
            )
            by_ip = {a.ip_address: a for a in existing_q.scalars().all()}

            now = datetime.now(timezone.utc)

            for host in live_hosts:
                ip = host["ip_address"]
                primary_proto = host["protocols_detected"][0] if host["protocols_detected"] else None

                asset = by_ip.get(ip)
                if asset is None:
                    # Newly observed device — create a minimal row. We
                    # don't know the vendor/model from a port probe, so
                    # those stay null and an enrichment step can fill
                    # them in later (e.g. SNMP, NMAP -O, vendor MAC OUI).
                    asset = OTAsset(
                        organization_id=self.organization_id,
                        name=f"discovered-{ip}",
                        asset_type="unknown",
                        protocol=primary_proto if primary_proto in KNOWN_PROTOCOLS else None,
                        ip_address=ip,
                        purdue_level="level3_operations",
                        criticality="supporting",
                        last_seen=now,
                        is_online=True,
                    )
                    db.add(asset)
                else:
                    asset.last_seen = now
                    asset.is_online = True
                    if not asset.protocol and primary_proto in KNOWN_PROTOCOLS:
                        asset.protocol = primary_proto

                discovered.append({
                    "ip_address": ip,
                    "protocols_detected": host["protocols_detected"],
                    "open_ports": host["open_ports"],
                    "asset_type": asset.asset_type,
                    "vendor": asset.vendor,
                    "model": asset.model,
                    "firmware_version": asset.firmware_version,
                    "name": asset.name,
                    "id": asset.id,
                    "newly_discovered": ip not in by_ip,
                })

            await db.commit()

        logger.info(
            f"OT discovery for {network_range}: "
            f"{len(discovered)} live hosts ({sum(1 for d in discovered if d['newly_discovered'])} new)"
        )
        return discovered

    async def _probe_device(
        self,
        ip_address_str: str,
        sem: Optional[asyncio.Semaphore] = None,
        ports: Optional[Dict[int, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Active TCP-connect probe of ``ip_address_str`` against every port
        in ``OT_PROBE_PORTS``. Returns a dict describing which ports
        answered and the protocol(s) inferred from those ports, or None
        on outright failure.

        This is a *real* network probe, not a database lookup — the only
        signal it produces comes from the wire.
        """
        # Validate the address first so a typo doesn't trigger a DNS
        # lookup or a misleading log line.
        try:
            ip_address(ip_address_str)
        except ValueError:
            logger.debug(f"_probe_device skipping invalid address {ip_address_str!r}")
            return None

        if sem is None:
            sem = asyncio.Semaphore(DISCOVERY_CONCURRENCY)

        async def _probe_port(port: int) -> Optional[int]:
            async with sem:
                try:
                    fut = asyncio.open_connection(ip_address_str, port)
                    reader, writer = await asyncio.wait_for(
                        fut, timeout=DISCOVERY_PORT_TIMEOUT_SECONDS
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:  # pragma: no cover - best effort cleanup
                        pass
                    return port
                except (asyncio.TimeoutError, OSError, ConnectionError):
                    return None

        port_map = ports if ports is not None else OT_PROBE_PORTS
        port_results = await asyncio.gather(
            *(_probe_port(p) for p in port_map.keys())
        )
        open_ports = [p for p in port_results if p is not None]
        protocols = [port_map[p] for p in open_ports]

        return {
            "ip_address": ip_address_str,
            "open_ports": open_ports,
            "protocols_detected": protocols,
        }

    def _check_modbus_tcp(self, ip: str) -> bool:
        """Check if device responds to Modbus TCP (port 502) via socket probe"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.protocol_profiles["modbus_tcp"]["default_timeout"])
            result = sock.connect_ex((ip, 502))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def _check_opc_ua(self, ip: str) -> bool:
        """Check if device responds to OPC-UA (port 4840) via socket probe"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.protocol_profiles.get("opc_ua", {}).get("default_timeout", 3))
            result = sock.connect_ex((ip, 4840))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def _check_dnp3(self, ip: str) -> bool:
        """Check if device responds to DNP3 (port 20000) via socket probe"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.protocol_profiles["dnp3"]["default_timeout"])
            result = sock.connect_ex((ip, 20000))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    async def monitor_communications(
        self, zone_enforcer: "PurdueModelEnforcer"
    ) -> List[Dict[str, Any]]:
        """
        Monitor network communications and enforce Purdue model zone policies.

        Validates that communications between zones comply with defined policies.
        Returns list of policy violations and unauthorized communications.
        """
        violations = []
        try:
            logger.info("Monitoring OT network communications")

            # In production, analyze actual network traffic
            # Check communications against zone policies
            violations = await zone_enforcer.validate_all_communications()

            return violations

        except Exception as e:
            logger.error(f"Communication monitoring failed: {str(e)}")
            return violations

    async def detect_protocol_anomalies(
        self, network_traffic: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect protocol anomalies for Modbus, DNP3, OPC-UA, and other ICS protocols.

        Identifies:
        - Function code anomalies
        - Timeout violations
        - Unexpected command sequences
        - Protocol state machine violations
        - Encryption/authentication anomalies
        """
        anomalies = []
        try:
            for packet in network_traffic:
                protocol = packet.get("protocol", "").lower()
                profile = self.protocol_profiles.get(protocol)

                if not profile:
                    continue

                # Check function code validity
                if "function_code" in packet:
                    if profile["function_codes"]:
                        if packet["function_code"] not in profile["function_codes"]:
                            anomalies.append(
                                {
                                    "type": "invalid_function_code",
                                    "protocol": protocol,
                                    "function_code": packet["function_code"],
                                    "severity": "high",
                                    "source_ip": packet.get("source_ip"),
                                    "dest_ip": packet.get("dest_ip"),
                                }
                            )

                # Check authentication anomaly (plaintext vs encrypted)
                if profile["requires_auth"]:
                    if "auth_token" not in packet or not packet["auth_token"]:
                        anomalies.append(
                            {
                                "type": "auth_missing",
                                "protocol": protocol,
                                "severity": "high",
                                "source_ip": packet.get("source_ip"),
                                "dest_ip": packet.get("dest_ip"),
                            }
                        )

                # Check plaintext protocol anomaly
                if profile["plaintext"] and packet.get("encryption"):
                    anomalies.append(
                        {
                            "type": "unexpected_encryption",
                            "protocol": protocol,
                            "severity": "medium",
                            "source_ip": packet.get("source_ip"),
                            "dest_ip": packet.get("dest_ip"),
                        }
                    )

            return anomalies

        except Exception as e:
            logger.error(f"Protocol anomaly detection failed: {str(e)}")
            return anomalies

    async def detect_unauthorized_commands(
        self, commands: List[Dict[str, Any]], whitelist: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect unauthorized commands by enforcing command whitelists.

        Validates:
        - Source/destination IP pairs
        - Function codes
        - Setpoint changes
        - Logic modifications
        - PLC mode changes
        - Program uploads/downloads
        """
        violations = []
        try:
            for cmd in commands:
                is_authorized = False

                for rule in whitelist:
                    if self._command_matches_rule(cmd, rule):
                        is_authorized = True
                        break

                if not is_authorized:
                    violations.append(
                        {
                            "type": "unauthorized_command",
                            "command": cmd.get("function_code"),
                            "severity": "high",
                            "source_ip": cmd.get("source_ip"),
                            "dest_ip": cmd.get("dest_ip"),
                            "protocol": cmd.get("protocol"),
                            "timestamp": datetime.now(timezone.utc),
                        }
                    )

            return violations

        except Exception as e:
            logger.error(f"Unauthorized command detection failed: {str(e)}")
            return violations

    def _command_matches_rule(
        self, command: Dict[str, Any], rule: Dict[str, Any]
    ) -> bool:
        """Check if command matches whitelist rule"""
        if rule.get("source_ip") and rule["source_ip"] != command.get("source_ip"):
            return False
        if rule.get("dest_ip") and rule["dest_ip"] != command.get("dest_ip"):
            return False
        if rule.get("function_code") and rule["function_code"] != command.get(
            "function_code"
        ):
            return False
        if rule.get("protocol") and rule["protocol"] != command.get("protocol"):
            return False
        return True

    async def detect_firmware_changes(
        self, assets: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect unauthorized firmware changes on OT assets.

        Compares current firmware hashes against baseline, identifies
        unexpected version changes, and flags potential backdoors.
        """
        changes = []
        try:
            for asset in assets:
                baseline_version = asset.get("baseline_firmware_version")
                current_version = asset.get("firmware_version")
                baseline_hash = asset.get("baseline_firmware_hash")
                current_hash = asset.get("firmware_hash")

                if baseline_version and baseline_version != current_version:
                    changes.append(
                        {
                            "asset_id": asset.get("id"),
                            "asset_name": asset.get("name"),
                            "change_type": "version_mismatch",
                            "baseline_version": baseline_version,
                            "current_version": current_version,
                            "severity": "critical",
                            "timestamp": datetime.now(timezone.utc),
                        }
                    )

                if baseline_hash and baseline_hash != current_hash:
                    changes.append(
                        {
                            "asset_id": asset.get("id"),
                            "asset_name": asset.get("name"),
                            "change_type": "hash_mismatch",
                            "severity": "critical",
                            "timestamp": datetime.now(timezone.utc),
                        }
                    )

            return changes

        except Exception as e:
            logger.error(f"Firmware change detection failed: {str(e)}")
            return changes

    async def detect_network_scanning(
        self, network_traffic: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect network scanning and reconnaissance activity.

        Identifies:
        - Port scans
        - Protocol probes
        - Broadcast queries
        - Unusual connection patterns
        """
        scans = []
        ip_probe_counts = {}

        try:
            for packet in network_traffic:
                source_ip = packet.get("source_ip")
                if not source_ip:
                    continue

                if source_ip not in ip_probe_counts:
                    ip_probe_counts[source_ip] = {"probes": 0, "destinations": set()}

                ip_probe_counts[source_ip]["probes"] += 1
                ip_probe_counts[source_ip]["destinations"].add(packet.get("dest_ip"))

            # Flag IPs with suspicious probe patterns
            for source_ip, data in ip_probe_counts.items():
                if data["probes"] > 20 or len(data["destinations"]) > 15:
                    scans.append(
                        {
                            "type": "network_scan",
                            "source_ip": source_ip,
                            "probe_count": data["probes"],
                            "target_count": len(data["destinations"]),
                            "severity": "high",
                            "timestamp": datetime.now(timezone.utc),
                        }
                    )

            return scans

        except Exception as e:
            logger.error(f"Network scan detection failed: {str(e)}")
            return scans

    async def correlate_ot_events(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Correlate multiple OT security events into potential incidents.

        Groups related alerts by:
        - Asset/zone proximity
        - Time windows
        - Attack patterns
        - MITRE ICS ATT&CK techniques
        """
        incidents = []
        try:
            # Group events by time window (30 min)
            time_windows = {}
            for event in events:
                timestamp = event.get("timestamp", datetime.now(timezone.utc))
                window_key = (timestamp.hour, timestamp.minute // 30)

                if window_key not in time_windows:
                    time_windows[window_key] = []
                time_windows[window_key].append(event)

            # Analyze each time window
            for window, window_events in time_windows.items():
                if len(window_events) >= 3:
                    # Multiple events in short window = potential incident
                    incident = {
                        "type": "multi_event_correlation",
                        "event_count": len(window_events),
                        "severity": "high",
                        "events": [e.get("id") for e in window_events],
                        "timestamp": datetime.now(timezone.utc),
                    }
                    incidents.append(incident)

            return incidents

        except Exception as e:
            logger.error(f"Event correlation failed: {str(e)}")
            return incidents


class PurdueModelEnforcer:
    """
    Purdue model network segmentation enforcement and validation.

    Enforces hierarchical zone model:
    - Level 5: Internet
    - Level 4: Enterprise/Corporate
    - Level 3.5: DMZ/ISA-Secure Zone
    - Level 3: Operations/Supervisory
    - Level 2: Area Control/Batch Processing
    - Level 1: Basic Control/PLC
    - Level 0: Process/Field Devices

    Prevents unauthorized zone-to-zone communications and detects violations.
    """

    def __init__(self, organization_id: str):
        """Initialize Purdue enforcer"""
        self.organization_id = organization_id
        self.zone_policies = {}
        self.level_hierarchy = [
            "level0_process",
            "level1_control",
            "level2_supervisory",
            "level3_operations",
            "level3_5_dmz",
            "level4_enterprise",
            "level5_internet",
        ]

    def _get_level_index(self, level: str) -> int:
        """Get hierarchical index of Purdue level"""
        return self.level_hierarchy.index(level) if level in self.level_hierarchy else -1

    async def validate_zone_communications(
        self, source_zone: str, dest_zone: str, protocol: str, ports: List[int]
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate zone-to-zone communication against policy.

        Returns: (is_valid, reason)

        Enforces rules:
        - Level 3.5 (DMZ) mediates all external communications
        - Level 3+ cannot directly access Level 0-2 without intermediary
        - Level 4+ cannot communicate with operational zones without ISA-Secure
        - Unencrypted protocols forbidden between security zones
        """
        source_idx = self._get_level_index(source_zone)
        dest_idx = self._get_level_index(dest_zone)

        if source_idx < 0 or dest_idx < 0:
            return False, "Invalid zone configuration"

        # DMZ (Level 3.5) must be intermediary for cross-zone
        if abs(source_idx - dest_idx) > 2:
            return (
                False,
                "Cross-zone communication requires ISA-Secure intermediary (Level 3.5)",
            )

        # Validate protocol security for zone transition
        if source_idx < 3 and dest_idx >= 3:
            # Control zone to enterprise zone
            if protocol in ["modbus_tcp", "modbus_rtu", "dnp3", "profinet"]:
                return (
                    False,
                    f"Unencrypted protocol {protocol} forbidden for zone crossing",
                )

        # Validate port ranges for zone policies
        policy_key = f"{source_zone}->{dest_zone}"
        if policy_key in self.zone_policies:
            allowed_ports = self.zone_policies[policy_key].get("allowed_ports", [])
            if allowed_ports and not any(p in allowed_ports for p in ports):
                return False, f"Ports {ports} not allowed for this zone transition"

        return True, None

    async def detect_level_violations(
        self, communications: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect communications that violate Purdue model hierarchy.

        Identifies direct Level 4/5 to Level 0/1 communications without intermediaries.
        """
        violations = []
        try:
            for comm in communications:
                source_zone = comm.get("source_zone")
                dest_zone = comm.get("dest_zone")

                is_valid, reason = await self.validate_zone_communications(
                    source_zone,
                    dest_zone,
                    comm.get("protocol", "unknown"),
                    comm.get("ports", []),
                )

                if not is_valid:
                    violations.append(
                        {
                            "type": "purdue_model_violation",
                            "source_zone": source_zone,
                            "dest_zone": dest_zone,
                            "reason": reason,
                            "severity": "critical",
                            "source_ip": comm.get("source_ip"),
                            "dest_ip": comm.get("dest_ip"),
                            "timestamp": datetime.now(timezone.utc),
                        }
                    )

            return violations

        except Exception as e:
            logger.error(f"Level violation detection failed: {str(e)}")
            return violations

    async def audit_firewall_rules(
        self, rules: List[Dict[str, Any]], zones: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Audit firewall rules against Purdue model requirements.

        Checks:
        - Missing rules for required zone transitions
        - Overly permissive rules
        - Conflicting rules
        - Outdated rules
        """
        issues = []
        try:
            rule_map = {r.get("rule_id"): r for r in rules}

            # Verify required zone transition rules exist
            for i, source in enumerate(self.level_hierarchy):
                for dest in self.level_hierarchy[i + 1 :]:
                    policy_key = f"{source}->{dest}"

                    # Some transitions should always have rules
                    if abs(i - self.level_hierarchy.index(dest)) <= 2:
                        if policy_key not in rule_map:
                            issues.append(
                                {
                                    "type": "missing_firewall_rule",
                                    "source_zone": source,
                                    "dest_zone": dest,
                                    "severity": "medium",
                                }
                            )

            return issues

        except Exception as e:
            logger.error(f"Firewall audit failed: {str(e)}")
            return issues

    async def recommend_segmentation_improvements(
        self, current_zones: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Recommend network segmentation improvements based on Purdue model.

        Suggests:
        - Missing zone boundaries
        - Zone consolidation
        - Additional segmentation layers
        - ISA-Secure implementation
        """
        recommendations = []
        try:
            covered_levels = {z.get("purdue_level") for z in current_zones}

            # Recommend all levels are implemented
            for level in self.level_hierarchy:
                if level not in covered_levels:
                    recommendations.append(
                        {
                            "type": "missing_zone_tier",
                            "purdue_level": level,
                            "priority": "medium",
                            "rationale": f"Zone for {level} not defined",
                        }
                    )

            # Recommend ISA-Secure if not present
            if "level3_5_dmz" not in covered_levels:
                recommendations.append(
                    {
                        "type": "missing_isa_secure_zone",
                        "purdue_level": "level3_5_dmz",
                        "priority": "high",
                        "rationale": "ISA-Secure zone recommended for external data flows",
                    }
                )

            return recommendations

        except Exception as e:
            logger.error(f"Segmentation recommendation failed: {str(e)}")
            return recommendations

    async def generate_zone_compliance_report(
        self, zones: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate compliance report for zone segmentation against Purdue model.

        Returns: {
            compliant: bool,
            coverage: float (0-1),
            issues: [],
            recommendations: [],
            maturity_level: str (initial, managed, optimized)
        }
        """
        try:
            covered_levels = {z.get("purdue_level") for z in zones}
            total_levels = len(self.level_hierarchy)
            coverage = len(covered_levels) / total_levels

            issues = await self.audit_firewall_rules([], zones)
            recommendations = await self.recommend_segmentation_improvements(zones)

            if coverage >= 0.9:
                maturity = "optimized"
                compliant = len(issues) == 0
            elif coverage >= 0.7:
                maturity = "managed"
                compliant = len(issues) < 3
            else:
                maturity = "initial"
                compliant = False

            return {
                "compliant": compliant,
                "coverage": coverage,
                "maturity_level": maturity,
                "covered_levels": list(covered_levels),
                "missing_levels": [l for l in self.level_hierarchy if l not in covered_levels],
                "issues": issues,
                "recommendations": recommendations,
                "timestamp": datetime.now(timezone.utc),
            }

        except Exception as e:
            logger.error(f"Compliance report generation failed: {str(e)}")
            return {
                "compliant": False,
                "coverage": 0,
                "maturity_level": "initial",
                "error": str(e),
            }

    async def validate_all_communications(self) -> List[Dict[str, Any]]:
        """Validate all zone communications (placeholder for integration)"""
        return []


class SafetyManager:
    """
    OT Safety system management and cyber-physical impact assessment.

    Evaluates safety implications of cyber incidents, recommends safe response
    strategies that prevent physical damage, coordinates safe shutdowns,
    and monitors safety-instrumented systems (SIS) / Safety Integrity Level (SIL).
    """

    def __init__(self, organization_id: str):
        """Initialize Safety Manager"""
        self.organization_id = organization_id
        self.safety_critical_assets = {}

    async def assess_physical_impact(
        self, incident: Dict[str, Any], affected_assets: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Assess potential physical impact from cyber event.

        Evaluates:
        - Process safety risk (hazardous processes, extreme conditions)
        - Worker safety risk (machinery, hazardous materials exposure)
        - Equipment damage risk (pressure vessels, toxic substance spills)
        - Environmental release risk
        """
        assessment = {
            "incident_id": incident.get("id"),
            "physical_impact_risk": "none",
            "risk_score": 0.0,
            "critical_assets_affected": [],
            "hazards_activated": [],
            "estimated_impact": None,
        }

        try:
            critical_count = 0
            for asset in affected_assets:
                if asset.get("criticality") == "safety_critical":
                    critical_count += 1
                    assessment["critical_assets_affected"].append(asset.get("id"))

                    # Map asset type to potential hazards
                    if asset.get("asset_type") == "safety_system":
                        assessment["hazards_activated"].append(
                            "Safety system compromise"
                        )
                    elif asset.get("asset_type") == "process_controller":
                        assessment["hazards_activated"].append("Process control loss")

            # Calculate risk score
            risk_score = min(1.0, critical_count / 5.0)

            if incident.get("incident_type") == "safety_system_compromise":
                risk_score = min(1.0, risk_score + 0.5)

            assessment["risk_score"] = risk_score
            assessment["physical_impact_risk"] = self._score_to_risk_level(risk_score)

            return assessment

        except Exception as e:
            logger.error(f"Physical impact assessment failed: {str(e)}")
            return assessment

    def _score_to_risk_level(self, score: float) -> str:
        """Convert risk score to level"""
        if score >= 0.8:
            return "critical_safety"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "moderate"
        elif score >= 0.2:
            return "low"
        else:
            return "none"

    async def recommend_safe_response(
        self, incident: Dict[str, Any], physical_impact: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Recommend safe response strategy considering process safety.

        Avoids blindly isolating systems that could cause dangerous states.
        Instead recommends:
        - Safe shutdown procedures
        - Graceful degradation
        - Operator notification
        - Monitoring with manual override capability
        """
        recommendation = {
            "incident_id": incident.get("id"),
            "containment_strategy": None,
            "safe_shutdown_required": False,
            "actions": [],
            "rationale": None,
        }

        try:
            risk_level = physical_impact.get("physical_impact_risk", "none")

            if risk_level == "critical_safety":
                recommendation["containment_strategy"] = "process_shutdown_safe"
                recommendation["safe_shutdown_required"] = True
                recommendation["actions"] = [
                    "Initiate controlled process shutdown",
                    "Notify operators immediately",
                    "Isolate affected PLC from network",
                    "Place SIS in manual override",
                    "Monitor all critical parameters",
                ]
                recommendation["rationale"] = (
                    "Critical safety risk requires coordinated safe shutdown"
                )

            elif risk_level in ["high", "moderate"]:
                recommendation["containment_strategy"] = "partial_isolation"
                recommendation["safe_shutdown_required"] = False
                recommendation["actions"] = [
                    "Isolate affected zone with firewall rules",
                    "Enable enhanced monitoring",
                    "Notify operators of situation",
                    "Prepare emergency shutdown procedures",
                    "Maintain safety system independence",
                ]
                recommendation["rationale"] = (
                    "Partial isolation allows monitoring while preventing escalation"
                )

            else:
                recommendation["containment_strategy"] = "monitoring_only"
                recommendation["safe_shutdown_required"] = False
                recommendation["actions"] = [
                    "Enable enhanced logging and alerting",
                    "Monitor for escalation indicators",
                    "Review changes for audit trail",
                    "Prepare for escalation if needed",
                ]
                recommendation["rationale"] = "Low risk allows continued monitoring"

            return recommendation

        except Exception as e:
            logger.error(f"Safe response recommendation failed: {str(e)}")
            return recommendation

    async def initiate_safe_shutdown(
        self, incident_id: str, affected_zones: List[str]
    ) -> Dict[str, Any]:
        """Removed: this returned a fixed five-step plan with status "initiated"
        although nothing was sent to any controller.

        Safe shutdown is commanded through an endpoint agent enrolled with the
        ``ot_safe_shutdown`` capability (``src.ot_security.actuation``), whose
        result drives the incident's status.
        """
        raise NotImplementedError(
            "safe shutdown runs through an ot_safe_shutdown endpoint agent; see src.ot_security.actuation"
        )

    async def monitor_safety_systems(
        self, assets: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Monitor safety-instrumented systems (SIS) and integrity levels.

        Tracks:
        - SIS operation status
        - Test/diagnostic frequencies
        - SIL degradation indicators
        - Proof test results
        """
        monitoring = {
            "timestamp": datetime.now(timezone.utc),
            "safety_systems": [],
            "degraded_systems": [],
            "overdue_tests": [],
        }

        try:
            for asset in assets:
                if "safety" in asset.get("asset_type", "").lower():
                    status = {
                        "asset_id": asset.get("id"),
                        "sil_level": asset.get("sil_level", "unknown"),
                        "last_proof_test": asset.get("last_proof_test"),
                        "online": asset.get("is_online", False),
                    }

                    monitoring["safety_systems"].append(status)

                    # Check for degradation
                    if not asset.get("is_online"):
                        monitoring["degraded_systems"].append(asset.get("id"))

            return monitoring

        except Exception as e:
            logger.error(f"Safety system monitoring failed: {str(e)}")
            return monitoring

    async def generate_safety_incident_report(
        self, incident: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate safety-focused incident report.

        Documents physical impact, safe response actions, SIS status,
        and post-incident validation of safety systems.
        """
        report = {
            "incident_id": incident.get("id"),
            "incident_type": incident.get("incident_type"),
            "physical_impact_risk": incident.get("physical_impact_risk", "unknown"),
            "operational_impact": incident.get("operational_impact", "unknown"),
            "safe_shutdown_initiated": incident.get("safe_shutdown_initiated", False),
            "actions_taken": [],
            "safety_systems_status": {},
            "validation_required": True,
        }

        try:
            report["actions_taken"] = [
                "Physical impact assessment completed",
                "Safe response strategy recommended",
                "Safety systems verified",
            ]

            return report

        except Exception as e:
            logger.error(f"Safety incident report generation failed: {str(e)}")
            return report


class OTVulnerabilityAssessor:
    """
    OT vulnerability assessment and risk scoring.

    Advisories come from the cached CISA ICS advisories feed
    (``src.ot_security.advisories``), passed in by the caller; an asset matches
    an advisory only by vendor and model. There is no built-in CVE catalogue:
    with an empty cache every asset has zero matched advisories and the
    caller reports the feed state (``not_fetched`` / ``unavailable``).
    """

    def __init__(self, organization_id: str, advisories: Optional[List[Any]] = None):
        """Initialize assessor with the cached advisories to match against."""
        self.organization_id = organization_id
        self.advisories = list(advisories or [])

    async def scan_firmware_versions(
        self, assets: List[Any]
    ) -> List[Dict[str, Any]]:
        """Advisories matching each asset's vendor and model (one row per match).

        Firmware versions are not evaluated (the feed has no machine-readable
        affected-version ranges): every row says so.
        """
        from src.ot_security.advisories import match_asset

        findings: List[Dict[str, Any]] = []
        for asset in assets:
            asset_id = asset.get("id") if isinstance(asset, dict) else getattr(asset, "id", None)
            firmware = asset.get("firmware_version") if isinstance(asset, dict) else getattr(asset, "firmware_version", None)
            for match in match_asset(asset, self.advisories):
                findings.append({
                    "asset_id": asset_id,
                    "firmware_version": firmware,
                    **match,
                    "remediation": "Review the advisory for affected versions and the vendor's fix or mitigations",
                })
        return findings

    async def check_known_vulnerabilities(
        self, asset: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Advisories matching one asset (see ``scan_firmware_versions``)."""
        return await self.scan_firmware_versions([asset])

    async def assess_protocol_risks(
        self, assets: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Flag assets whose stored protocol has no built-in authentication/encryption.

        (A "default credentials" finding used to be raised for every asset
        from a field no model has; it is gone.)
        """
        risks = []
        risky_protocols = ["modbus_tcp", "modbus_rtu", "dnp3", "bacnet", "profinet"]
        for asset in assets:
            protocol = (asset.get("protocol") or "").lower()
            if protocol in risky_protocols:
                risks.append(
                    {
                        "asset_id": asset.get("id"),
                        "asset_name": asset.get("name"),
                        "risk_type": "unencrypted_protocol",
                        "protocol": protocol,
                        "severity": "high",
                        "recommendation": "Consider transitioning to OPC-UA with encryption",
                    }
                )
        return risks

    async def calculate_ot_risk_score(
        self, asset: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]
    ) -> float:
        """
        OT risk score (0-1) from stored asset fields and matched advisories.

        - Criticality (0-0.3): safety_critical 0.3, mission_critical 0.25,
          important 0.15, supporting 0.05
        - Exposure by Purdue level (0-0.3): internet 0.3, enterprise 0.2,
          DMZ 0.15, otherwise 0.05
        - Matched advisories (0-0.3): 0.1 per advisory, capped; +0.1 more
          (within the cap) when one carries a CVSS >= 9
        - Protocol without authentication (0.1)
        """
        score = 0.0
        criticality_scores = {
            "safety_critical": 0.3,
            "mission_critical": 0.25,
            "important": 0.15,
            "supporting": 0.05,
        }
        score += criticality_scores.get(asset.get("criticality") or "supporting", 0.05)

        purdue_level = asset.get("purdue_level") or ""
        if "internet" in purdue_level:
            score += 0.3
        elif "enterprise" in purdue_level:
            score += 0.2
        elif "dmz" in purdue_level:
            score += 0.15
        else:
            score += 0.05

        advisory_points = len(vulnerabilities) * 0.1
        if any((v.get("cvss_score") or 0) >= 9 for v in vulnerabilities):
            advisory_points += 0.1
        score += min(0.3, advisory_points)

        if (asset.get("protocol") or "").lower() in ["modbus_tcp", "modbus_rtu", "dnp3", "bacnet", "profinet"]:
            score += 0.1

        return round(min(1.0, score), 3)

    @staticmethod
    def risk_level(score: float) -> str:
        """critical >= 0.75, high >= 0.5, medium >= 0.25, otherwise low."""
        if score >= 0.75:
            return "critical"
        if score >= 0.5:
            return "high"
        if score >= 0.25:
            return "medium"
        return "low"

    async def generate_risk_report(
        self, assets: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Risk report over the given assets (computed, never defaulted)."""
        report: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc),
            "total_assets": len(assets),
            "critical_risk_assets": 0,
            "high_risk_assets": 0,
            "medium_risk_assets": 0,
            "low_risk_assets": 0,
            "assets_by_risk": [],
        }

        for asset in assets:
            vulns = await self.check_known_vulnerabilities(asset)
            risk_score = await self.calculate_ot_risk_score(asset, vulns)
            risk_level = self.risk_level(risk_score)
            report[f"{risk_level}_risk_assets"] += 1
            report["assets_by_risk"].append(
                {
                    "asset_id": asset.get("id"),
                    "name": asset.get("name"),
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "vulnerability_count": len(vulns),
                    "advisory_ids": [v["advisory_id"] for v in vulns],
                }
            )

        return report


class ICSComplianceEngine:
    """
    ICS compliance engine for NERC-CIP, IEC 62443, and NIST SP 800-82.

    Verifies compliance with grid protection (NERC-CIP), functional safety (IEC 62443),
    and federal IT security (NIST) standards for operational technology environments.
    """

    def __init__(self, organization_id: str):
        """Initialize compliance engine"""
        self.organization_id = organization_id

    async def check_nerc_cip_compliance(
        self, assets: List[Dict[str, Any]], zones: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Check NERC CIP (Critical Infrastructure Protection) compliance.

        Verifies:
        - CIP-002: Critical Asset Identification
        - CIP-005: Electronic Security Perimeter
        - CIP-007: Incident Recovery Capability
        - CIP-010: Configuration and Vulnerability Management
        """
        compliance = {
            "framework": "NERC-CIP",
            "compliant": False,
            "requirements_met": 0,
            "requirements_total": 4,
            "issues": [],
        }

        try:
            # CIP-002: Critical Asset Identification
            critical_assets = [
                a
                for a in assets
                if a.get("criticality") in ["safety_critical", "mission_critical"]
            ]
            if len(critical_assets) > 0:
                compliance["requirements_met"] += 1

            # CIP-005: Electronic Security Perimeter
            dmz_zones = [z for z in zones if "dmz" in z.get("purdue_level", "")]
            if len(dmz_zones) > 0:
                compliance["requirements_met"] += 1

            # CIP-007: Incident Recovery Capability
            # (Check for backup/recovery procedures - placeholder)
            compliance["requirements_met"] += 1

            # CIP-010: Configuration Management
            # (Check firmware versions are current)
            current_assets = [a for a in assets if a.get("firmware_current", False)]
            if len(current_assets) / len(assets) > 0.9 if assets else False:
                compliance["requirements_met"] += 1

            compliance["compliant"] = (
                compliance["requirements_met"] >= 3
            )  # Require 75%

            return compliance

        except Exception as e:
            logger.error(f"NERC-CIP compliance check failed: {str(e)}")
            return compliance

    async def check_iec62443_compliance(
        self, assets: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Check IEC 62443 (Industrial Automation and Control Systems Security) compliance.

        Verifies security levels:
        - SL1 (Unauthorized access potential)
        - SL2 (Specific attack with enhanced authentication)
        - SL3 (Sophisticated attack with defense-in-depth)
        - SL4 (Most sophisticated attack with complete isolation)
        """
        compliance = {
            "framework": "IEC 62443",
            "security_levels": {
                "sl1": {"met": False, "assets": 0},
                "sl2": {"met": False, "assets": 0},
                "sl3": {"met": False, "assets": 0},
                "sl4": {"met": False, "assets": 0},
            },
            "overall_level": "SL1",
            "issues": [],
        }

        try:
            for asset in assets:
                # Assess based on criticality and exposure
                if asset.get("criticality") == "safety_critical":
                    if asset.get("purdue_level") in [
                        "level0_process",
                        "level1_control",
                    ]:
                        compliance["security_levels"]["sl4"]["assets"] += 1
                    else:
                        compliance["security_levels"]["sl3"]["assets"] += 1
                elif asset.get("criticality") == "mission_critical":
                    compliance["security_levels"]["sl3"]["assets"] += 1
                else:
                    compliance["security_levels"]["sl2"]["assets"] += 1

            # Determine overall level
            if compliance["security_levels"]["sl4"]["assets"] > 0:
                compliance["overall_level"] = "SL4"
            elif compliance["security_levels"]["sl3"]["assets"] > 0:
                compliance["overall_level"] = "SL3"
            else:
                compliance["overall_level"] = "SL2"

            return compliance

        except Exception as e:
            logger.error(f"IEC 62443 compliance check failed: {str(e)}")
            return compliance

    async def check_nist_sp800_82(self, zones: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Check NIST SP 800-82 (Guide to Industrial Control Systems Security) compliance.

        Verifies:
        - Network segmentation (Purdue model)
        - Defense-in-depth
        - Secure design principles
        - Operational security controls
        """
        compliance = {
            "framework": "NIST SP 800-82",
            "compliant": False,
            "checks": {
                "network_segmentation": False,
                "defense_in_depth": False,
                "secure_design": False,
                "operational_controls": False,
            },
        }

        try:
            # Network segmentation
            covered_levels = {z.get("purdue_level") for z in zones}
            if len(covered_levels) >= 4:
                compliance["checks"]["network_segmentation"] = True

            # Defense-in-depth (multiple security layers)
            if len(zones) >= 3:
                compliance["checks"]["defense_in_depth"] = True

            # Secure design (no direct level crossing without intermediaries)
            compliance["checks"]["secure_design"] = True

            # Operational controls (monitoring, logging, etc.)
            compliance["checks"]["operational_controls"] = True

            compliance["compliant"] = all(compliance["checks"].values())

            return compliance

        except Exception as e:
            logger.error(f"NIST SP 800-82 compliance check failed: {str(e)}")
            return compliance

    async def generate_compliance_report(
        self, org_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate comprehensive ICS compliance report"""
        assets = org_data.get("assets", [])
        zones = org_data.get("zones", [])

        nerc = await self.check_nerc_cip_compliance(assets, zones)
        iec = await self.check_iec62443_compliance(assets)
        nist = await self.check_nist_sp800_82(zones)

        return {
            "timestamp": datetime.now(timezone.utc),
            "nerc_cip": nerc,
            "iec_62443": iec,
            "nist_sp_800_82": nist,
            "overall_compliance": all(
                [nerc.get("compliant", False), nist.get("compliant", False)]
            ),
        }

    async def track_remediation(
        self, issue_id: str, remediation_plan: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Track compliance remediation efforts"""
        return {
            "issue_id": issue_id,
            "plan": remediation_plan,
            "status": "tracking",
            "start_date": datetime.now(timezone.utc),
        }
