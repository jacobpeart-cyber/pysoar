"""Celery application configuration"""

from celery.schedules import crontab

from celery import Celery

from src.core.config import settings

# Create Celery app
celery_app = Celery(
    "pysoar",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "src.workers.tasks",
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
        # drives AutonomousInvestigator against a real Gemini + tool
        # loop. Missing this entry silently drops every investigation
        # kickoff on the floor.
        "src.agentic.tasks",
        # STIG fleet sweep + scan execution.
        "src.stig.tasks",
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
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    result_expires=86400,  # Results expire after 1 day
)

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
        "task": "src.workers.tasks.check_scheduled_playbooks",
        "schedule": 60.0,  # Every minute
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
    # --- Weekly STIG fleet sweep (src.stig.tasks.scheduled_fleet_stig_sweep) ---
    # FedRAMP/NIST SP 800-137 continuous monitoring: every active endpoint
    # agent is scanned against every loaded STIG benchmark once per week.
    # Findings populate STIGScanResult via the ARF ingest path.
    "stig-fleet-sweep": {
        "task": "src.stig.tasks.scheduled_fleet_stig_sweep",
        "schedule": crontab(day_of_week=0, hour=6, minute=0),  # Sundays 06:00 UTC
    },
}
