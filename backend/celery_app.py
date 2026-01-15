"""
SentinelDLP - Celery Application Configuration (FR-005/GAP-001)
Async task queue for enterprise scalability (1000+ concurrent users)
"""

import os
from celery import Celery

# Redis connection from environment
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
REDIS_RESULT_BACKEND = os.getenv("REDIS_RESULT_BACKEND", "redis://redis:6379/1")

# Create Celery app
celery_app = Celery(
    "sentineldlp",
    broker=REDIS_URL,
    backend=REDIS_RESULT_BACKEND,
    include=["tasks"]
)

# Celery configuration for enterprise workload
celery_app.conf.update(
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

    # Result backend settings
    result_expires=86400,  # Results expire after 24 hours
    result_extended=True,  # Store additional metadata

    # Task execution settings
    task_acks_late=True,  # Acknowledge after task completes (reliability)
    task_reject_on_worker_lost=True,  # Requeue if worker dies
    task_time_limit=600,  # 10 minute hard limit per task
    task_soft_time_limit=540,  # 9 minute soft limit (cleanup time)

    # Worker settings
    worker_prefetch_multiplier=1,  # One task at a time per worker (for large files)
    worker_max_tasks_per_child=100,  # Recycle workers to prevent memory leaks
    worker_concurrency=4,  # Default concurrency per worker (configurable)

    # Queue configuration
    task_default_queue="sentineldlp_analysis",
    task_queues={
        "sentineldlp_analysis": {
            "exchange": "sentineldlp",
            "routing_key": "analysis"
        },
        "sentineldlp_priority": {
            "exchange": "sentineldlp",
            "routing_key": "priority"
        }
    },

    # Task routing
    task_routes={
        "tasks.analyze_document_task": {"queue": "sentineldlp_analysis"},
        "tasks.analyze_text_task": {"queue": "sentineldlp_analysis"},
    },

    # Retry policy
    task_default_retry_delay=30,  # 30 seconds between retries
    task_max_retries=3,  # Maximum 3 retries

    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
)

# Optional: Configure task rate limiting
celery_app.conf.task_annotations = {
    "tasks.analyze_document_task": {
        "rate_limit": "100/m"  # 100 tasks per minute per worker
    }
}
