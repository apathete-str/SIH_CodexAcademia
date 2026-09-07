"""IMAP/POP3 mailbox connector (background Celery task)."""
from app.core.logging import get_logger
from app.core.queue import celery_app
from app.ingest.ingest_service import ingest_email
from app.models.email_record import EmailSource

logger = get_logger(__name__)


@celery_app.task(name="ingest.imap_poll")
def imap_poll(host: str, username: str, password: str, folder: str = "INBOX", limit: int = 50) -> int:
    """Connect to an IMAP mailbox and ingest recent unseen emails."""
    import imaplib

    count = 0
    try:
        mail = imaplib.IMAP4_SSL(host)
        mail.login(username, password)
        mail.select(folder)
        status, data = mail.search(None, "UNSEEN")
        if status != "OK":
            return 0
        ids = data[0].split()
        for msg_id in ids[:limit]:
            status, msg_data = mail.fetch(msg_id, "(RFC822)")
            if status == "OK":
                raw = msg_data[0][1]
                ingest_email(raw, EmailSource.IMAP, metadata={"imap_host": host})
                count += 1
        mail.logout()
    except Exception as exc:  # pragma: no cover
        logger.error("IMAP poll failed: %s", exc)
    logger.info("IMAP poll ingested %d emails from %s", count, host)
    return count
