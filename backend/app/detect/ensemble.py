"""Explainable hybrid threat scoring ensemble."""
from app.models.email_record import EmailRecord
from app.models.enrichment import EnrichmentResult
from app.models.threat import ModelContribution, ThreatAssessment, ThreatCategory, Verdict
from app.detect.rules import evaluate_rules


def assess_threat(email: EmailRecord, enrichment: EnrichmentResult) -> ThreatAssessment:
    signals = evaluate_rules(email, enrichment)
    rule_score = min(sum(signal.weight * signal.score for signal in signals) / 0.55, 1.0)
    text = f"{email.subject} {email.body_text}".lower()
    phishing_terms = sum(term in text for term in ("verify", "login", "password", "account", "payment"))
    nlp_score = min(phishing_terms / 5, 1.0)
    combined = min((rule_score * 0.7) + (nlp_score * 0.3), 1.0)
    if combined >= 0.7:
        verdict = Verdict.MALICIOUS
    elif combined >= 0.35:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.BENIGN
    category = ThreatCategory.PHISHING if ("suspicious_url" in {s.name for s in signals} or nlp_score > 0.4) else ThreatCategory.MALWARE if any(s.name == "dangerous_attachment" for s in signals) else ThreatCategory.BENIGN
    top = sorted(signals, key=lambda signal: signal.score * signal.weight, reverse=True)[:3]
    explanation = " ".join(signal.description for signal in top) or "No significant threat indicators were found."
    return ThreatAssessment(email_id=email.id, threat_score=round(combined * 100, 2), verdict=verdict, category=category, confidence=round(min(0.55 + abs(combined - 0.5), 0.99), 3), signals=signals, model_contributions=[ModelContribution(model_name="rules", score=rule_score, weight=0.7), ModelContribution(model_name="linguistic", score=nlp_score, weight=0.3)], explanation=explanation, shap_values={s.name: round(s.score * s.weight, 4) for s in signals})
