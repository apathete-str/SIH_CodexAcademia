"""Safe extraction helpers for URLs, domains, and IP addresses."""
import ipaddress
import re
from urllib.parse import urlparse

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DOMAIN_RE = re.compile(r"(?<![@\w])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w])")


def extract_urls(text: str) -> list[str]:
    urls = []
    for match in _URL_RE.findall(text or ""):
        urls.append(match.rstrip(".,;:!?)]}"))
    return list(dict.fromkeys(urls))


def extract_ips(text: str) -> list[str]:
    result = []
    for candidate in _IP_RE.findall(text or ""):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate not in result:
            result.append(candidate)
    return result


def extract_domains(text: str) -> list[str]:
    result = []
    for candidate in _DOMAIN_RE.findall(text or ""):
        candidate = candidate.lower().rstrip(".")
        try:
            if ipaddress.ip_address(candidate):
                continue
        except ValueError:
            pass
        if candidate not in result:
            result.append(candidate)
    return result


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()
