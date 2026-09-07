"""Queue abstraction over Redis/Celery for async pipeline processing."""
from __future__ import annotations
from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

try:
    from celery import Celery  # type: ignore

    celery_app = Celery(
        "emailthreat",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
    )
    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
    )
    CELERY_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    logger.warning("Celery unavailable, running synchronously: %s", exc)
    celery_app = None
    CELERY_AVAILABLE = False


def enqueue(task_name: str, *args, **kwargs) -> object | None:
    """Enqueue a task if Celery is available, else return None (caller runs sync)."""
    if CELERY_AVAILABLE and celery_app is not None:
        return celery_app.send_task(task_name, args=args, kwargs=kwargs)
    return None
