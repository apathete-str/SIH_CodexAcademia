"""Offline deterministic enrichment provider for demos and tests."""
from datetime import datetime, timezone
import hashlib
import ipaddress
from urllib.parse import urlparse

from app.models.email_record import EmailRecord
from app.models.enrichment import (
    AttachmentReputation, DomainReputation, EnrichmentResult, IpReputation, UrlReputation,
)


class MockEnrichmentProvider:
    name = "mock"

    def enrich(self, email: EmailRecord) -> EnrichmentResult:
        urls = []
        for url in email.urls:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            suspicious = any(token in url.lower() for token in ("login", "verify", "secure", "wallet", "update"))
            urls.append(UrlReputation(url=url, expanded_url=url, safe_browsing="malicious" if suspicious else "safe", is_shortened=host in {"bit.ly", "tinyurl.com"}, risk=0.88 if suspicious else 0.03))
        domains = []
        for domain in email.domains:
            suspicious = any(token in domain for token in ("paypa1", "micros0ft", "secure-login", "verify-account"))
            domains.append(DomainReputation(domain=domain, registered=datetime.now(timezone.utc), age_days=12 if suspicious else 1800, is_typosquat=suspicious, typosquat_of="paypal.com" if "paypa1" in domain else None, risk=0.9 if suspicious else 0.04))
        ips = []
        for ip in email.ips:
            try:
                private = ipaddress.ip_address(ip).is_private
            except ValueError:
                private = True
            digest = hashlib.sha256(ip.encode()).hexdigest()
            ips.append(IpReputation(ip=ip, asn=f"AS{int(digest[:6], 16) % 90000 + 1000}", org="Private Network" if private else "Example Hosting", is_datacenter=not private, reputation_score=0.15 if not private else 0.02))
        attachments = []
        for attachment in email.attachments:
            executable = attachment.content_type in {"application/x-msdownload", "application/vnd.ms-office"} or attachment.filename.lower().endswith((".exe", ".js", ".vbs", ".scr"))
            attachments.append(AttachmentReputation(sha256=attachment.sha256, filename=attachment.filename, content_type=attachment.content_type, is_executable=executable, is_macro=attachment.filename.lower().endswith((".docm", ".xlsm")), risk=0.95 if executable else 0.05))
        return EnrichmentResult(email_id=email.id, urls=urls, domains=domains, ips=ips, attachments=attachments, provider=self.name)
