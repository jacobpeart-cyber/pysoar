"""Dark Web Monitoring Module

What is implemented (see src/darkweb/monitor_scan.py):
- Monitors with their own search terms, watched domains and watched emails
- Have I Been Pwned account lookups (HIBP_API_KEY), domain breach lookups and
  the recent breach catalogue, with credential-leak rows for account hits
- abuse.ch URLhaus / ThreatFox and AlienVault OTX feed items that mention a
  monitor term, labelled as threat-intel feed matches (not dark-web posts)
- Credential remediation tracking (recorded decisions; no identity-provider
  action is executed) and threat-intel correlation of findings

Not implemented: Tor forum, Telegram, paste-site crawling beyond HIBP's paste
index, ransomware leak-site monitoring and takedown submission (the takedown
route answers 501).
"""

from src.darkweb.models import (
    DarkWebMonitor,
    DarkWebFinding,
    DarkWebMonitorType,
    FindingType,
    SourcePlatform,
    CredentialLeak,
    PasswordType,
    RemediationAction,
    BrandThreat,
    BrandThreatType,
    TakedownStatus,
)

__all__ = [
    "DarkWebMonitor",
    "DarkWebFinding",
    "DarkWebMonitorType",
    "FindingType",
    "SourcePlatform",
    "CredentialLeak",
    "PasswordType",
    "RemediationAction",
    "BrandThreat",
    "BrandThreatType",
    "TakedownStatus",
]
