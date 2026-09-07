"""Feature extraction from normalized email and enrichment."""
import re
from app.models.email_record import EmailRecord
from app.models.enrichment import EnrichmentResult


def extract_features(email: EmailRecord, enrichment: EnrichmentResult) -> dict[str, float]:
    text = f"{email.subject} {email.body_text}".lower()
    urgency = len(re.findall(r"urgent|immediately|within 24 hours|action required|verify", text))
    credential = len(re.findall(r"password|login|credential|otp|bank|payment", text))
    return {
        "url_count": min(len(email.urls) / 10, 1.0),
        "suspicious_url_risk": max((item.risk for item in enrichment.urls), default=0.0),
        "typosquat_risk": max((item.risk for item in enrichment.domains if item.is_typosquat), default=0.0),
        "attachment_risk": max((item.risk for item in enrichment.attachments), default=0.0),
        "auth_failure": sum(value in {"fail", "softfail", "none"} for value in (email.auth_results.spf, email.auth_results.dkim, email.auth_results.dmarc)) / 3,
        "urgency_language": min(urgency / 3, 1.0),
        "credential_language": min(credential / 4, 1.0),
        "reply_to_mismatch": float(bool(email.reply_to and email.from_addr and email.reply_to.lower() != email.from_addr.lower())),
    }
