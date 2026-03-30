"""
Phishing Simulation & Security Awareness Module for PySOAR

Provides comprehensive phishing campaign management, user awareness training,
and security risk scoring capabilities. Enables organizations to simulate
realistic phishing attacks, track employee responses, and deliver targeted
security awareness training to improve human security posture.

Features:
- Campaign Management: Email, spear, smishing, vishing, USB drop, QR code, social media attacks
- Template Engine: Template creation with personalization and tracking pixels
- Event Tracking: Email delivery, opens, clicks, credential submission, reporting
- Awareness Scoring: User and department risk profiling with trend analysis
- Training Management: Auto-assignment, completion tracking, certification
- Dashboard: Campaign metrics, risk heatmap, department comparison, ROI
"""

from src.phishing_sim.engine import (
    AwarenessScorer,
    CampaignManager,
    EventTracker,
    TemplateEngine,
    TrainingManager,
)

__all__ = [
    "CampaignManager",
    "TemplateEngine",
    "EventTracker",
    "AwarenessScorer",
    "TrainingManager",
]
