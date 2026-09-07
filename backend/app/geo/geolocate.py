"""GeoIP provider interface with deterministic offline fallback."""
import ipaddress
from app.models.email_record import EmailRecord
from app.models.enrichment import EnrichmentResult
from app.models.geo import GeoIntel, GeoPoint, InfraHop

_COUNTRIES = [("US", "United States", 37.7749, -122.4194), ("DE", "Germany", 50.1109, 8.6821), ("IN", "India", 28.6139, 77.2090), ("NL", "Netherlands", 52.3676, 4.9041)]


def lookup_ip(ip: str) -> GeoPoint:
    try:
        private = ipaddress.ip_address(ip).is_private
    except ValueError:
        private = True
    if private:
        return GeoPoint(ip=ip, country="Private Network", country_code="XX", city="Internal", risk=0.0)
    index = sum(ord(char) for char in ip) % len(_COUNTRIES)
    code, country, lat, lon = _COUNTRIES[index]
    return GeoPoint(ip=ip, country=country, country_code=code, city="Unknown", latitude=lat, longitude=lon, asn=f"AS{64500 + index}", org="Example Transit Network", is_datacenter=True, risk=0.35)


def analyze_geo(email: EmailRecord, enrichment: EnrichmentResult) -> GeoIntel:
    hops = []
    for order, received in enumerate(email.received_chain):
        if received.ip:
            hops.append(InfraHop(order=order, host=received.from_host or received.by_host, ip=received.ip, geo=lookup_ip(received.ip), timestamp=received.timestamp))
    sender_ip = email.ips[0] if email.ips else (hops[0].ip if hops else None)
    sender_geo = lookup_ip(sender_ip) if sender_ip else None
    risk = max([point.geo.risk for point in hops if point.geo] + ([sender_geo.risk] if sender_geo else [0.0]))
    return GeoIntel(email_id=email.id, sender_ip=sender_ip, sender_geo=sender_geo, hops=hops, origin_country=sender_geo.country if sender_geo else None, origin_country_code=sender_geo.country_code if sender_geo else None, geo_risk=risk, attribution={"method": "ip-and-received-chain", "confidence": 0.35 if sender_geo else 0.0})
