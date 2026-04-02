"""API v1 router aggregating all endpoint routers"""

from fastapi import APIRouter

from src.api.v1.endpoints import (
    agentic,
    ai,
    alerts,
    api_keys,
    api_security,
    assets,
    audit,
    audit_evidence,
    auth,
    mfa,
    case_management,
    collaboration,
    compliance,
    container_security,
    darkweb,
    data_lake,
    deception,
    dfir,
    dlp,
    exposure,
    health,
    hunting,
    incidents,
    integrations,
    intel,
    iocs,
    itdr,
    metrics,
    organizations,
    ot_security,
    phishing_sim,
    playbook_builder,
    playbooks,
    privacy,
    remediation,
    risk_quant,
    settings,
    siem,
    simulation,
    stig,
    supplychain,
    threat_modeling,
    ueba,
    users,
    vulnmgmt,
    websocket,
    zerotrust,
    tickethub,
    backup,
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(mfa.router)
api_router.include_router(users.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(playbooks.router)
api_router.include_router(iocs.router)
api_router.include_router(assets.router)
api_router.include_router(websocket.router)
api_router.include_router(settings.router)
api_router.include_router(audit.router)
api_router.include_router(metrics.router, prefix="/metrics", tags=["metrics"])
api_router.include_router(api_keys.router, prefix="/api-keys", tags=["api-keys"])
api_router.include_router(organizations.router, tags=["organizations"])
api_router.include_router(case_management.router, tags=["case-management"])
api_router.include_router(siem.router, tags=["siem"])
api_router.include_router(hunting.router, tags=["threat-hunting"])
api_router.include_router(intel.router, tags=["threat-intelligence"])
api_router.include_router(exposure.router, tags=["exposure-management"])
api_router.include_router(ai.router, tags=["ai-ml-engine"])
api_router.include_router(ueba.router, tags=["ueba"])
api_router.include_router(simulation.router, tags=["attack-simulation"])
api_router.include_router(deception.router, tags=["deception"])
api_router.include_router(remediation.router, tags=["remediation"])
api_router.include_router(compliance.router, tags=["compliance"])
api_router.include_router(zerotrust.router, tags=["zero-trust"])
api_router.include_router(stig.router, tags=["stig-scap"])
api_router.include_router(audit_evidence.router, tags=["audit-evidence"])

# --- New Modules (Batch 1: Must-Have) ---
api_router.include_router(dfir.router, tags=["dfir"])
api_router.include_router(itdr.router, tags=["identity-threat"])
api_router.include_router(vulnmgmt.router, tags=["vulnerability-management"])
api_router.include_router(supplychain.router, tags=["supply-chain"])
api_router.include_router(darkweb.router, tags=["dark-web-monitoring"])
api_router.include_router(integrations.router, tags=["integrations"])

# --- New Modules (Batch 2: Differentiators) ---
api_router.include_router(agentic.router, tags=["agentic-soc"])
api_router.include_router(playbook_builder.router, tags=["playbook-builder"])
api_router.include_router(dlp.router, tags=["data-loss-prevention"])
api_router.include_router(risk_quant.router, tags=["risk-quantification"])
api_router.include_router(ot_security.router, tags=["ot-ics-security"])
api_router.include_router(container_security.router, tags=["container-security"])

# --- New Modules (Batch 3: Innovation Edge) ---
api_router.include_router(privacy.router, tags=["privacy-engineering"])
api_router.include_router(threat_modeling.router, tags=["threat-modeling"])
api_router.include_router(api_security.router, tags=["api-security"])
api_router.include_router(data_lake.router, tags=["data-lake"])
api_router.include_router(collaboration.router, tags=["collaboration"])
api_router.include_router(phishing_sim.router, tags=["phishing-simulation"])

# --- Unified Ticket Hub ---
api_router.include_router(tickethub.router, tags=["ticket-hub"])

# --- Backup & Restore ---
api_router.include_router(backup.router, tags=["backup-restore"])
