"""Postfix milter integration adapter.

Install pymilter in deployments and configure Postfix to call the milter.
The adapter deliberately fails open by default; production policy should be
configured explicitly based on the organization's mail-flow requirements.
"""
from app.core.logging import get_logger
from app.ingest.ingest_service import ingest_email
from app.models.email_record import EmailSource

logger = get_logger(__name__)

try:
    import Milter  # type: ignore
except ImportError:  # pragma: no cover
    Milter = None


class ThreatMilter:
    """Minimal milter adapter that collects message bytes for analysis."""

    def __init__(self) -> None:
        self._chunks: list[bytes] = []
        self._headers: dict[str, str] = {}

    def header(self, name: str, value: str) -> int:
        self._headers[name] = value
        return 0

    def body(self, chunk: bytes) -> int:
        self._chunks.append(chunk)
        return 0

    def eom(self) -> int:
        raw = b"\n".join(f"{key}: {value}".encode() for key, value in self._headers.items())
        raw += b"\n\n" + b"".join(self._chunks)
        record = ingest_email(raw, EmailSource.MTA, metadata={"mta_headers": self._headers})
        logger.info("MTA email %s ingested", record.id[:12])
        return 0


def run_milter(socket_path: str = "inet:9999@127.0.0.1") -> None:
    """Run the Postfix milter process (requires pymilter)."""
    if Milter is None:
        raise RuntimeError("pymilter is required to run the MTA adapter")
    Milter.factory = ThreatMilter
    Milter.runmilter("emailthreat", socket_path, 10)
