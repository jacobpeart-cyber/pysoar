"""Threat Intelligence Platform Module

This module provides comprehensive threat intelligence capabilities for PySOAR:

- Feed Management: Ingest threat data from multiple feeds (STIX, CSV, MISP, TAXII, etc.)
- Indicator Management: Store and manage threat indicators with full enrichment
- Threat Actor Tracking: Monitor known threat actors and their characteristics
- Campaign Correlation: Link indicators and actors to threat campaigns
- Intelligence Reporting: Generate threat intelligence reports
- IOC Matching: Match indicators against system logs and events
- Enrichment Engine: Automatically enrich indicators with external intelligence
- Lifecycle Management: Track indicator validity, expiration, and sightings
"""

from src.intel.models import (
    ThreatFeed,
    ThreatIndicator,
    ThreatActor,
    ThreatCampaign,
    IntelReport,
    IndicatorSighting,
)

__all__ = [
    "ThreatFeed",
    "ThreatIndicator",
    "ThreatActor",
    "ThreatCampaign",
    "IntelReport",
    "IndicatorSighting",
]
