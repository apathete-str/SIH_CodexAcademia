"""Tamper-evident hash-chained forensic events."""
from datetime import datetime, timezone
import hashlib
import json
from app.config import settings
from app.core.security import hmac_sha256
from app.models.forensic import CustodyEvent, EvidenceType


def append_event(chain: list[CustodyEvent], actor: str, action: str, entity_type: EvidenceType, entity_id: str, entity_hash: str) -> CustodyEvent:
    sequence = len(chain) + 1
    prev_hash = chain[-1].event_hash if chain else None
    payload = {"sequence": sequence, "actor": actor, "action": action, "entity_type": entity_type.value, "entity_id": entity_id, "entity_hash": entity_hash, "prev_hash": prev_hash}
    event_hash = hmac_sha256(settings.secret_key, json.dumps(payload, sort_keys=True, separators=(",", ":")))
    event = CustodyEvent(sequence=sequence, timestamp=datetime.now(timezone.utc), actor=actor, action=action, entity_type=entity_type, entity_id=entity_id, entity_hash=entity_hash, prev_hash=prev_hash, event_hash=event_hash)
    chain.append(event)
    return event


def verify_chain(chain: list[CustodyEvent]) -> tuple[bool, str]:
    previous = None
    for expected, event in enumerate(chain, 1):
        if event.sequence != expected or event.prev_hash != previous:
            return False, f"sequence or predecessor mismatch at event {event.sequence}"
        payload = {"sequence": event.sequence, "actor": event.actor, "action": event.action, "entity_type": event.entity_type.value, "entity_id": event.entity_id, "entity_hash": event.entity_hash, "prev_hash": event.prev_hash}
        expected_hash = hmac_sha256(settings.secret_key, json.dumps(payload, sort_keys=True, separators=(",", ":")))
        if not hashlib.sha256(expected_hash.encode()).hexdigest() == hashlib.sha256(event.event_hash.encode()).hexdigest():
            return False, f"hash mismatch at event {event.sequence}"
        previous = event.event_hash
    return True, "chain verified"
