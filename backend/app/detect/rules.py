"""High precision rule signals that complement ML scoring."""
from app.models.email_record import EmailRecord
from app.models.enrichment import EnrichmentResult
from app.models.threat import Signal
from app.detect.features import extract_features


def evaluate_rules(email: EmailRecord, enrichment: EnrichmentResult) -> list[Signal]:
    features = extract_features(email, enrichment)
    signals = []
    for name, description, weight in [
        ("authentication_failure", "One or more sender authentication checks failed or were absent.", 0.18),
        ("suspicious_url", "A URL has phishing-like language or reputation risk.", 0.25),
        ("typosquatting", "A linked domain resembles a trusted brand but is not the exact domain.", 0.2),
        ("dangerous_attachment", "An executable or macro-enabled attachment is present.", 0.25),
        ("urgency_language", "The message pressures the recipient to act quickly.", 0.08),
        ("credential_request", "The message requests credentials, OTPs, payments, or account access.", 0.1),
        ("reply_to_mismatch", "Reply-To differs from the visible sender address.", 0.16),
    ]:
        key = {"authentication_failure": "auth_failure", "suspicious_url": "suspicious_url_risk", "typosquatting": "typosquat_risk", "dangerous_attachment": "attachment_risk", "urgency_language": "urgency_language", "credential_request": "credential_language", "reply_to_mismatch": "reply_to_mismatch"}[name]
        score = features[key]
        if score > 0:
            signals.append(Signal(name=name, weight=weight, score=round(score, 4), description=description))
    return signals
