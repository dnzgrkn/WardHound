"""Celery composition root for WardHound background work."""

import os

from celery import Celery

celery_app = Celery(
    "wardhound",
    broker=os.environ["CELERY_BROKER_URL"],
    include=["app.tasks.jumpserver"],
)
celery_app.conf.beat_schedule = {
    "poll-jumpserver": {
        "task": "app.tasks.jumpserver.poll_jumpserver",
        "schedule": float(os.getenv("JUMPSERVER_POLL_INTERVAL_SECONDS", "300")),
    }
}
