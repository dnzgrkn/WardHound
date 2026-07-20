"""Celery composition root for WardHound background work."""

import os

from celery import Celery

celery_app = Celery(
    "wardhound",
    broker=os.environ["CELERY_BROKER_URL"],
    include=[
        "app.tasks.jumpserver",
        "app.tasks.digest",
        "app.tasks.packetfence",
        "app.tasks.active_directory",
    ],
)
celery_app.conf.beat_schedule = {
    "poll-jumpserver": {
        "task": "app.tasks.jumpserver.poll_jumpserver",
        "schedule": float(os.getenv("JUMPSERVER_POLL_INTERVAL_SECONDS", "300")),
    },
    "poll-packetfence": {
        "task": "app.tasks.packetfence.poll_packetfence",
        "schedule": float(os.getenv("PACKETFENCE_POLL_INTERVAL_SECONDS", "300")),
    },
    "poll-active-directory": {
        "task": "app.tasks.active_directory.poll_active_directory",
        "schedule": float(os.getenv("AD_POLL_INTERVAL_SECONDS", "300")),
    },
    "generate-daily-digest": {
        "task": "app.tasks.digest.generate_daily_digest",
        "schedule": float(os.getenv("DIGEST_SCHEDULE_INTERVAL_SECONDS", "86400")),
    },
}
