"""RFC-compatible email parser producing the canonical EmailRecord."""
from __future__ import annotations
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html import unescape
import re

from app.core.security import sha256
from app.core.storage import storage
from app.models.email_record import (
    Attachment,
    AuthResult,
    EmailRecord,
    EmailSource,
    ReceivedHop,
)
from app.parse.extractor import extract_domains, extract_ips, extract_urls


def _header(message: Message, name: str) -> str:
    return str(message.get(name, "")).strip()


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _addresses(value: str) -> list[str]:
    return [address for _, address in getaddresses([value]) if address]


def _body_parts(message: Message) -> tuple[str, str]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_filename():
            continue
        try:
            content = part.get_content()
        except (UnicodeDecodeError, LookupError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if part.get_content_type() == "text/html":
            html_parts.append(str(content))
        elif part.get_content_type() == "text/plain":
            text_parts.append(str(content))
    return "\n".join(text_parts), "\n".join(html_parts)


def _received_hops(message: Message) -> list[ReceivedHop]:
    hops: list[ReceivedHop] = []
    for value in message.get_all("Received", []):
        text = str(value)
        ip_match = re.search(r"\[([0-9a-fA-F:.]+)\]|\b((?:\d{1,3}\.){3}\d{1,3})\b", text)
        ip = next((group for group in (ip_match.groups() if ip_match else ()) if group), None)
        by_match = re.search(r"\bby\s+([^\s;]+)", text, re.IGNORECASE)
        from_match = re.search(r"\bfrom\s+([^\s(]+)", text, re.IGNORECASE)
        timestamp = _parse_date(text.rsplit(";", 1)[-1].strip()) if ";" in text else None
        hops.append(ReceivedHop(
            from_host=from_match.group(1) if from_match else None,
            by_host=by_match.group(1) if by_match else None,
            ip=ip,
            timestamp=timestamp,
            helo=None,
        ))
    return hops


def _auth_results(message: Message) -> AuthResult:
    text = " ".join(str(value) for value in message.get_all("Authentication-Results", []))
    def result(name: str) -> str | None:
        match = re.search(rf"\b{name}=(pass|fail|softfail|neutral|none|temperror|permerror)\b", text, re.I)
        return match.group(1).lower() if match else None
    return AuthResult(spf=result("spf"), dkim=result("dkim"), dmarc=result("dmarc"))


def parse_email_bytes(raw: bytes, email_id: str, source: EmailSource) -> EmailRecord:
    """Parse bytes using the stdlib's strict email policy."""
    message = BytesParser(policy=policy.default).parsebytes(raw)
    body_text, body_html = _body_parts(message)
    attachments: list[Attachment] = []
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(Attachment(
            filename=filename,
            content_type=part.get_content_type(),
            size=len(payload),
            sha256=sha256(payload),
            storage_ref=storage.save(f"attachments/{sha256(payload)}-{filename}", payload),
        ))

    all_content = "\n".join([_header(message, "Subject"), body_text, body_html])
    urls = extract_urls(all_content)
    domains = extract_domains(all_content + " " + _header(message, "From"))
    ips = extract_ips(" ".join(str(v) for v in message.get_all("Received", [])))
    from_name, from_addr = getaddresses([_header(message, "From")])[0] if getaddresses([_header(message, "From")]) else (None, None)
    headers = {key: str(value) for key, value in message.items()}

    return EmailRecord(
        id=email_id,
        source=source,
        message_id=_header(message, "Message-ID") or None,
        subject=_header(message, "Subject"),
        from_addr=from_addr,
        from_display=from_name or None,
        to_addrs=_addresses(_header(message, "To")),
        cc_addrs=_addresses(_header(message, "Cc")),
        reply_to=_header(message, "Reply-To") or None,
        date=_parse_date(_header(message, "Date")),
        received_chain=_received_hops(message),
        auth_results=_auth_results(message),
        body_text=body_text or re.sub(r"<[^>]+>", " ", unescape(body_html)),
        body_html=body_html,
        urls=urls,
        domains=domains,
        ips=ips,
        attachments=attachments,
        headers=headers,
    )
