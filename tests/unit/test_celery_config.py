"""Guard the Celery worker memory-protection settings.

Prod incident 2026-05-20 → 2026-06-11: celery workers leaked until each
child reached 1-1.5 GB RSS, the kernel OOM-killed them in a loop for
weeks, and the 4 GB t3.medium eventually froze hard (failed EC2
reachability check, full outage until manual reboot). These settings
bound the damage: leaked children get recycled long before they reach
kernel-OOM territory.
"""

from src.workers.celery_app import celery_app


def test_worker_recycles_after_bounded_task_count():
    max_tasks = celery_app.conf.worker_max_tasks_per_child
    assert max_tasks is not None, "worker_max_tasks_per_child unset — leaks accumulate forever"
    assert 1 <= max_tasks <= 200


def test_worker_recycles_before_kernel_oom_territory():
    max_kb = celery_app.conf.worker_max_memory_per_child
    assert max_kb is not None, "worker_max_memory_per_child unset — child RSS unbounded"
    # OOM-killed children in the incident were 700 MB - 1.1 GB RSS.
    # Recycle threshold must sit well below that, but above the ~200 MB
    # a healthy worker needs.
    assert 200_000 <= max_kb <= 600_000
