"""Provider protocol for enrichment integrations."""
from typing import Protocol

from app.models.enrichment import EnrichmentResult
from app.models.email_record import EmailRecord


class EnrichmentProvider(Protocol):
    name: str

    def enrich(self, email: EmailRecord) -> EnrichmentResult: ...
