from fastapi.testclient import TestClient
from app.main import app
from app.forensic.chain_of_custody import append_event, verify_chain
from app.models.forensic import CustodyEvent, EvidenceType


def sample_email() -> bytes:
    return b"From: Alert <alert@paypa1-secure-login.com>\nTo: user@example.org\nReply-To: thief@evil.example\nSubject: Urgent verify account\nReceived: from relay.example [8.8.8.8] by mx.example; Fri, 04 Sep 2026 10:00:00 +0000\nAuthentication-Results: spf=fail dkim=none dmarc=fail\n\nUrgent action required. Verify your account login and password at https://secure-login.example/verify"


def test_end_to_end_analysis():
    response = TestClient(app).post("/api/v1/ingest/analyze", files={"file": ("sample.eml", sample_email(), "message/rfc822")})
    assert response.status_code == 200
    result = response.json()
    assert result["threat"]["verdict"] == "malicious"
    assert result["threat"]["threat_score"] > 70
    assert result["geo"]["sender_ip"] == "8.8.8.8"
    assert any(ioc["type"] == "url" for ioc in result["iocs"])
    assert len(result["custody_chain"]) == 5
    assert [event["stage"] for event in result["timeline"]] == ["ingestion", "parsing", "enrichment", "detection", "geolocation"]


def test_chain_of_custody_detects_tampering():
    chain: list[CustodyEvent] = []
    append_event(chain, "analyst", "captured", EvidenceType.RAW_EMAIL, "email-1", "abc")
    append_event(chain, "analyst", "parsed", EvidenceType.PARSED_RECORD, "email-1", "def")
    assert verify_chain(chain)[0] is True
    chain[1].entity_hash = "tampered"
    assert verify_chain(chain)[0] is False
