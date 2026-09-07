"""Central ingestion service. All ingestion paths converge here."""
from __future__ import annotations
import hashlib
import uuid

from app.core.logging import get_logger
from app.core.storage import storage
from app.models.email_record import EmailRecord, EmailSource
from app.parse.parser import parse_email_bytes

logger = get_logger(__name__)


def _compute_id(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def ingest_email(raw: bytes, source: EmailSource, metadata: dict | None = None) -> EmailRecord:
    """Ingest raw email bytes, store them, parse into a canonical record.

    This is the single funnel for MTA, IMAP, upload, and API ingestion.
    """
    email_id = _compute_id(raw)
    logger.info("Ingesting email %s via %s", email_id[:12], source.value)

    # Persist raw artifact for forensics.
    raw_ref = storage.save(f"raw/{email_id}.eml", raw)

    record = parse_email_bytes(raw, email_id=email_id, source=source)
    record.raw_ref = raw_ref
    record.raw_sha256 = email_id
    if metadata:
        record.metadata.update(metadata)

    return record


def generate_case_id() -> str:
    return f"case-{uuid.uuid4().hex[:12]}"
