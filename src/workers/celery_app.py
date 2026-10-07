"""Celery application configuration"""

from celery import Celery
from celery.schedules import crontab
from kombu import Queue

from src.core.config import settings

# Create Celery app
celery_app = Celery(
    "pysoar",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "src.workers.tasks",
        # Playbook execution loop — the runner that consumes pending
        # PlaybookExecution rows and the scheduled-trigger sweep.
        "src.playbooks.tasks",
        # Deception — honeypot dispatch reconciliation (deploying →
        # active/failed once the agent reports its listener result).
        "src.deception.tasks",
        "src.tasks.automation_tasks",
        "src.intel.tasks",
        "src.phishing_sim.tasks",
        # SIEM module's celery tasks — includes
        # `siem.poll_cloud_integrations` for the 5-min cloud-log
        # poller. Without this entry the @shared_task decorator
        # registers but the worker never imports the module on boot,
        # so the beat schedule entry fires into the void.
        "src.siem.tasks",
        # Agentic SOC autonomous investigations — `run_investigation`
        # drives AutonomousInvestigator through the guarded AgentRunner
        # (org-resolved LLM provider + read-only tool allow-list). Missing
        # this entry silently drops every investigation kickoff on the floor.
        "src.agentic.tasks",
        # STIG fleet sweep + scan execution.
        "src.stig.tasks",
        # ITDR — identity threat detection (dormant admin / MFA-less
        # privileged / stale credential) runs hourly across all orgs
        # and fires on_itdr_threat → alerts → investigator chain.
        "src.itdr.tasks",
        # Supply chain — typosquat detection against dep list + vendor
        # cert expiry + vuln cross-reference. Included so the beat-
        # scheduled sweeps below can resolve the task names.
        "src.supplychain.tasks",
        # Dark-web monitoring — real HIBP / URLhaus / ThreatFox / OTX
        # scan that persists findings into darkweb_findings and fires
        # on_darkweb_finding for criticals. Without this entry the beat
        # sweep below wouldn't be able to resolve the task.
        "src.darkweb.tasks",
        # Integration housekeeping — health-probes every installed
        # integration (persisting health_status), expires old
        # integration_executions / deactivated webhook endpoints, and
        # clears lapsed rate-limit windows. Without this entry the beat
        # entries below can't resolve the task names.
        "src.integrations.tasks",
        # UEBA background pipeline — baseline learning, entity risk
        # recalculation (with real 30-day decay), impossible-travel
        # detection, peer-group rebuilds, high-risk-entity alerting, and
        # behavior-event retention. Without this entry the beat entries
        # below can't resolve the task names.
        "src.ueba.tasks",
        # CTEM / exposure background pipeline — SIEM-driven asset
        # discovery and attack-surface change detection (snapshot diffing).
        "src.exposure.tasks",
    ],
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    task_soft_time_limit=3300,  # 55 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_concurrency=2,
    # Memory-leak containment (prod incidents 2026-05-20 and 2026-09-01:
    # leaking workers grew to 0.7-1.5 GB RSS each, kernel OOM-killed them
    # for weeks, then froze the 4 GB host outright). Recycle each child
    # after a bounded number of tasks AND whenever its RSS crosses the
    # threshold below.
    #
    # 2026-09-01 follow-up: 500 MB was still too generous. A per-child cap
    # only recycles a child *between* tasks, so the real fix is bounding
    # the tasks themselves (see the streaming/batching work in
    # src/exposure/tasks.py, src/tasks/automation_tasks.py,
    # src/ueba/tasks.py, src/itdr/tasks.py and src/intel/feeds.py).
    # Dropping the cap to 300 MB means that even if a *new* unbounded path
    # appears, the child is recycled with ~1.2 GB of container headroom
    # left instead of ~1 GB, so the kernel never has to shoot anything.
    worker_max_tasks_per_child=50,
    worker_max_memory_per_child=300_000,  # KB == 300 MB
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    result_expires=86400,  # Results expire after 1 day
)

# --- Queues -----------------------------------------------------------------
# Autonomous investigations get their own queue (design v2 section 8): one LLM
# run can hold a worker child for minutes, and a backlog of them must never
# starve playbook execution, ingest or the notification fan-out.
#
# Both queues are declared here, so a worker started without `-Q` consumes
# both and nothing is silently dropped. To isolate investigations in
# production, run a dedicated worker:
#
#   celery -A src.workers.celery_app worker -Q investigations \
#       --concurrency=2 --max-memory-per-child=400000
#
# (`--max-memory-per-child=400000` is the design's 400 MB recycle threshold
# for that queue; the global 500 MB in `worker_max_memory_per_child` above
# still applies to the default worker.)
celery_app.conf.task_default_queue = "celery"
celery_app.conf.task_queues = (
    Queue("celery"),
    Queue("investigations"),
)
celery_app.conf.task_routes = {
    "src.agentic.tasks.run_investigation": {"queue": "investigations"},
    "src.agentic.tasks.autonomous_triage": {"queue": "investigations"},
}
# Per-task limits: an investigation is capped at a 600 s wall clock inside the
# runtime, so 900 s soft / 960 s hard leaves room for persistence and still
# kills a wedged run well inside the global hour.
#
# The remaining entries are the known-heavy sweeps identified in the
# 2026-09-01 OOM post-mortem. Each one now streams/batches its reads, but a
# wall-clock limit is the backstop: a sweep that somehow starts growing again
# gets killed in minutes instead of holding a child at multi-GB RSS for the
# full global hour (long enough for the kernel OOM killer to pick a victim).
_HEAVY_SWEEP_LIMITS = {
    "soft_time_limit": 900,  # 15 min
    "time_limit": 960,
}
_NETWORK_SWEEP_LIMITS = {
    "soft_time_limit": 1800,  # 30 min
    "time_limit": 1860,
}
celery_app.conf.task_annotations = {
    "src.agentic.tasks.run_investigation": {
        "soft_time_limit": 900,
        "time_limit": 960,
    },
    # Full-table / all-org sweeps over log_entries, behavior_events,
    # threat_indicators and alerts.
    "src.exposure.tasks.run_asset_discovery": dict(_HEAVY_SWEEP_LIMITS),
    "src.exposure.tasks.detect_attack_surface_changes": dict(_HEAVY_SWEEP_LIMITS),
    "src.ueba.tasks.update_entity_baselines": dict(_HEAVY_SWEEP_LIMITS),
    "src.ueba.tasks.calculate_entity_risks": dict(_HEAVY_SWEEP_LIMITS),
    "src.ueba.tasks.update_peer_groups": dict(_HEAVY_SWEEP_LIMITS),
    "src.ueba.tasks.cleanup_old_behavior_events": dict(_HEAVY_SWEEP_LIMITS),
    "automation.periodic_ioc_sweep": dict(_HEAVY_SWEEP_LIMITS),
    "automation.auto_escalate_stale_alerts": dict(_HEAVY_SWEEP_LIMITS),
    "automation.auto_close_resolved_alerts": dict(_HEAVY_SWEEP_LIMITS),
    "automation.hourly_correlation_sweep": dict(_HEAVY_SWEEP_LIMITS),
    "intel.poll_threat_feeds": dict(_HEAVY_SWEEP_LIMITS),
    "siem.poll_cloud_integrations": dict(_HEAVY_SWEEP_LIMITS),
    "src.itdr.tasks.scheduled_identity_threat_sweep": dict(_HEAVY_SWEEP_LIMITS),
    "src.supplychain.tasks.supplychain_cross_org_sweep": dict(_HEAVY_SWEEP_LIMITS),
    # Round 2 of the memory bounding: these tasks now page their tables in
    # fixed windows with per-run caps; the wall clock is the backstop.
    "src.stig.tasks.scheduled_fleet_stig_sweep": dict(_HEAVY_SWEEP_LIMITS),
    # run_stig_scan polls agent results for up to 600 s by design.
    "src.stig.tasks.run_stig_scan": dict(_HEAVY_SWEEP_LIMITS),
    "src.stig.tasks.auto_remediate_findings": dict(_HEAVY_SWEEP_LIMITS),
    "src.integrations.tasks.rate_limit_reset": dict(_HEAVY_SWEEP_LIMITS),
    "src.integrations.tasks.connector_update_check": dict(_HEAVY_SWEEP_LIMITS),
    "src.supplychain.tasks.vulnerability_cross_reference": dict(_HEAVY_SWEEP_LIMITS),
    "src.supplychain.tasks.vendor_certification_expiry_check": dict(_HEAVY_SWEEP_LIMITS),
    "src.supplychain.tasks.typosquatting_scan": dict(_HEAVY_SWEEP_LIMITS),
    "src.darkweb.tasks.credential_leak_check": dict(_HEAVY_SWEEP_LIMITS),
    "src.darkweb.tasks.threat_correlation": dict(_HEAVY_SWEEP_LIMITS),
    "deception.reconcile_honeypot_dispatches": dict(_HEAVY_SWEEP_LIMITS),
    "playbooks.check_scheduled_playbooks": dict(_HEAVY_SWEEP_LIMITS),
    "src.exposure.tasks.run_vuln_scan": dict(_HEAVY_SWEEP_LIMITS),
    "src.exposure.tasks.import_scanner_results": dict(_HEAVY_SWEEP_LIMITS),
    "src.exposure.tasks.calculate_risk_scores": dict(_HEAVY_SWEEP_LIMITS),
    "src.exposure.tasks.check_sla_breaches": dict(_HEAVY_SWEEP_LIMITS),
    "src.exposure.tasks.sync_kev_database": dict(_HEAVY_SWEEP_LIMITS),
    # All-org retention purge of llm_call_logs / agent_run_transcripts:
    # 10k-row committed windows with a per-run cap; the wall clock is the
    # backstop.
    "src.agentic.tasks.purge_agentic_retention": dict(_HEAVY_SWEEP_LIMITS),
    # These two make one outbound network call per row (a full dark-web
    # scan per monitor / an HTTP probe per integration), so a 15-minute
    # ceiling would cut off legitimate work; they get 30 minutes, still
    # well inside the global hour.
    "src.darkweb.tasks.darkweb_cross_org_sweep": dict(_NETWORK_SWEEP_LIMITS),
    "src.integrations.tasks.health_check_all_integrations": dict(_NETWORK_SWEEP_LIMITS),
}

# Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    "cleanup-old-executions": {
        "task": "src.workers.tasks.cleanup_old_executions",
        "schedule": 3600.0,  # Every hour
    },
    "refresh-ioc-enrichments": {
        "task": "src.workers.tasks.refresh_ioc_enrichments",
        "schedule": 86400.0,  # Every 24 hours
    },
    "check-scheduled-playbooks": {
        "task": "playbooks.check_scheduled_playbooks",
        "schedule": 60.0,  # Every minute
    },
    # --- Honeypot dispatch reconciliation ---
    # Flips honeypot decoys from "deploying" to active/failed once the
    # deception agent posts its listener deploy result.
    "deception-honeypot-reconcile": {
        "task": "deception.reconcile_honeypot_dispatches",
        "schedule": 60.0,
    },
    # --- Scheduled automation tasks (src.tasks.automation_tasks) ---
    "auto-escalate-stale-alerts": {
        "task": "automation.auto_escalate_stale_alerts",
        "schedule": 1800.0,  # Every 30 minutes
    },
    "auto-close-resolved-alerts": {
        "task": "automation.auto_close_resolved_alerts",
        "schedule": 3600.0,  # Every 1 hour
    },
    "periodic-ioc-sweep": {
        "task": "automation.periodic_ioc_sweep",
        "schedule": 900.0,  # Every 15 minutes
    },
    "daily-threat-briefing": {
        "task": "automation.daily_threat_briefing",
        "schedule": crontab(hour=8, minute=0),  # Every day at 08:00 UTC
    },
    "hourly-correlation-sweep": {
        "task": "automation.hourly_correlation_sweep",
        "schedule": 3600.0,  # Every 1 hour
    },
    # --- Threat intelligence feed polling (src.intel.tasks) ---
    "poll-threat-feeds": {
        "task": "intel.poll_threat_feeds",
        "schedule": 1800.0,  # Every 30 minutes — fetch all enabled feeds
    },
    # --- SIEM cloud log polling (src.siem.tasks.poll_cloud_integrations) ---
    # Pulls AWS CloudTrail / Azure Activity Log / GCP Cloud Logging into
    # log_entries every 5 minutes for every installed cloud integration.
    "siem-cloud-poll": {
        "task": "siem.poll_cloud_integrations",
        "schedule": 300.0,  # Every 5 minutes
    },
    # --- Autonomous SOC triage (src.agentic.tasks.auto_triage_new_alerts) ---
    # Every 60s, scan for new critical/high alerts that don't yet have an
    # Investigation row and kick off the LLM-driven AutonomousInvestigator
    # on each. Turns the agent from reactive (wait for chat) to a
    # standing on-call analyst that handles incoming work automatically.
    "agentic-auto-triage": {
        "task": "src.agentic.tasks.auto_triage_new_alerts",
        "schedule": 60.0,
    },
    # --- Broad-signal sweep (non-alert sources) ---
    # Watches UEBA risk alerts, dark web findings, and decoy
    # interactions and kicks off investigations on each. Closes the
    # gap where the old auto-triage only covered alerts; now the
    # agent investigates every security signal the platform emits.
    "agentic-broad-sweep": {
        "task": "src.agentic.tasks.auto_triage_broad_sweep",
        "schedule": 120.0,  # Every 2 minutes
    },
    # --- Supply chain: daily typosquat + vuln cross-ref sweep ---
    # Scans every org's software_components against a small popular-
    # packages list (typosquat), then cross-references declared CVE
    # ids against the vulnerabilities table so newly-disclosed CVEs
    # propagate into supply-chain-risk rows. Vendor cert expiry runs
    # weekly on Mondays morning so cert-rotation work has a full week.
    "supplychain-typosquat-sweep": {
        "task": "src.supplychain.tasks.supplychain_cross_org_sweep",
        "schedule": 86400.0,  # Daily
    },
    # --- ITDR: hourly identity threat sweep across all orgs ---
    # Populates IdentityThreat rows for dormant_admin, MFA-missing
    # privileged users, and stale credentials. Each detection fires
    # on_itdr_threat → alert → investigator chain so identity
    # threats flow into the same autonomous pipeline as alerts.
    "itdr-identity-threat-sweep": {
        "task": "src.itdr.tasks.scheduled_identity_threat_sweep",
        "schedule": 3600.0,  # Every hour
    },
    # --- Post-incident followup ---
    # Re-notify if recommended actions on an open incident are
    # still awaiting approval 4+ hours after creation. Turns
    # "incident opened at 3 AM but nobody approved the block" into
    # a second page at 7 AM instead of silent rot.
    "agentic-incident-followup": {
        "task": "src.agentic.tasks.followup_open_incidents",
        "schedule": crontab(minute="*/30"),  # Every 30 min
    },
    # --- Dark web cross-org sweep ---
    # Every 30 min, iterate every enabled DarkWebMonitor across every
    # org and hit URLhaus + HIBP /breaches + ThreatFox + OTX. Persists
    # new findings (deduped by content_hash) and fires
    # on_darkweb_finding -> alert -> investigator chain on criticals.
    # Previous state: no beat entry -> zero dark-web scans ever ran
    # in production.
    "darkweb-cross-org-sweep": {
        "task": "src.darkweb.tasks.darkweb_cross_org_sweep",
        "schedule": 1800.0,  # Every 30 min
    },
    # --- Integration housekeeping (src.integrations.tasks) ---
    # Hourly: real HTTP health probes against every installed
    # integration's third-party API (persists health_status /
    # last_health_check) and clearing of lapsed rate-limit windows.
    # Daily: retention cleanup of integration execution history and
    # deactivated webhook endpoints.
    "integrations-health-check": {
        "task": "src.integrations.tasks.health_check_all_integrations",
        "schedule": 3600.0,  # Every hour
    },
    "integrations-rate-limit-reset": {
        "task": "src.integrations.tasks.rate_limit_reset",
        "schedule": 3600.0,  # Every hour
    },
    "integrations-execution-cleanup": {
        "task": "src.integrations.tasks.execution_cleanup",
        "schedule": 86400.0,  # Daily — 30-day retention by default
    },
    "integrations-webhook-cleanup": {
        "task": "src.integrations.tasks.webhook_cleanup",
        "schedule": 86400.0,  # Daily — 90-day retention of inactive endpoints
    },
    # --- UEBA background pipeline (src.ueba.tasks) ---
    # All entries run argument-less and therefore sweep every
    # organization (each task org-scopes its per-entity queries).
    # `process_behavior_events` is deliberately NOT scheduled — it is the
    # on-demand ingest worker task.
    "ueba-update-baselines": {
        "task": "src.ueba.tasks.update_entity_baselines",
        "schedule": crontab(hour=2, minute=0),  # Daily 02:00 UTC — learn from last 30d of events
    },
    "ueba-calculate-entity-risks": {
        "task": "src.ueba.tasks.calculate_entity_risks",
        "schedule": 3600.0,  # Hourly — real 30d alert-decay + rolling anomaly counter
    },
    "ueba-impossible-travel": {
        "task": "src.ueba.tasks.detect_impossible_travel",
        "schedule": 900.0,  # Every 15 minutes
    },
    "ueba-update-peer-groups": {
        "task": "src.ueba.tasks.update_peer_groups",
        "schedule": crontab(hour=3, minute=0),  # Daily 03:00 UTC
    },
    "ueba-generate-alerts": {
        "task": "src.ueba.tasks.generate_ueba_alerts",
        "schedule": 3600.0,  # Hourly — deduped per entity, no spam
    },
    "ueba-event-cleanup": {
        "task": "src.ueba.tasks.cleanup_old_behavior_events",
        "schedule": 86400.0,  # Daily — 90-day retention by default
    },
    # --- Agentic retention (src.agentic.tasks.purge_agentic_retention) ---
    # Rolls expiring call-log days into llm_usage_daily, then deletes raw
    # llm_call_logs and agent_run_transcripts past each organization's
    # retention (agentic_policy settings, 30..1095 days, default 365).
    "agentic-retention-purge": {
        "task": "src.agentic.tasks.purge_agentic_retention",
        "schedule": crontab(hour=5, minute=15),  # Daily 05:15 UTC, off-peak
    },
    # --- Weekly STIG fleet sweep (src.stig.tasks.scheduled_fleet_stig_sweep) ---
    # FedRAMP/NIST SP 800-137 continuous monitoring: every active endpoint
    # agent is scanned against every loaded STIG benchmark once per week.
    # Findings populate STIGScanResult via the ARF ingest path.
    "stig-fleet-sweep": {
        "task": "src.stig.tasks.scheduled_fleet_stig_sweep",
        "schedule": crontab(day_of_week=0, hour=6, minute=0),  # Sundays 06:00 UTC
    },
    # --- CTEM exposure sweeps (all-org; org=None) ---
    "exposure-asset-discovery": {
        "task": "src.exposure.tasks.run_asset_discovery",
        "schedule": crontab(hour=1, minute=30),  # Daily 01:30 UTC — SIEM-driven
    },
    "exposure-attack-surface": {
        "task": "src.exposure.tasks.detect_attack_surface_changes",
        "schedule": crontab(hour=4, minute=0),  # Daily 04:00 UTC — snapshot diff
    },
}
