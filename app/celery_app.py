"""Celery composition root for WardHound background work."""

import os

from celery import Celery

celery_app = Celery(
    "wardhound",
    broker=os.environ["CELERY_BROKER_URL"],
    include=["app.tasks.jumpserver", "app.tasks.digest"],
)
celery_app.conf.beat_schedule = {
    "poll-jumpserver": {
        "task": "app.tasks.jumpserver.poll_jumpserver",
        "schedule": float(os.getenv("JUMPSERVER_POLL_INTERVAL_SECONDS", "300")),
    },
    "generate-daily-digest": {
        "task": "app.tasks.digest.generate_daily_digest",
        "schedule": float(os.getenv("DIGEST_SCHEDULE_INTERVAL_SECONDS", "86400")),
    },
}
