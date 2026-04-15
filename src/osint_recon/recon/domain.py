from __future__ import annotations

import asyncio
import socket
from datetime import datetime

import dns.resolver
import httpx
import whois

from osint_recon.cache import ReconCache
from osint_recon.models import (
    DnsRecords,
    DomainReport,
    SecurityHeaders,
    SubdomainRecord,
    WhoisInfo,
)


async def get_subdomains(domain: str, client: httpx.AsyncClient) -> list[SubdomainRecord]:
    """Fetch subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = await client.get(url, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []

    seen: set[str] = set()
    results: list[SubdomainRecord] = []
    for entry in data:
        name = entry.get("common_name", "").lstrip("*.").lower()
        if not name or name in seen or not name.endswith(domain):
            continue
        seen.add(name)
        not_before = None
        if nb := entry.get("not_before"):
            try:
                not_before = datetime.fromisoformat(nb)
            except ValueError:
                pass
        results.append(
            SubdomainRecord(
                hostname=name,
                issuer=entry.get("issuer_name"),
                not_before=not_before,
            )
        )
    return results


def _resolve(domain: str, rdtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rdtype)
        return [r.to_text() for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception):
        return []


async def get_dns_records(domain: str) -> DnsRecords:
    """Query DNS records for a domain."""
    loop = asyncio.get_event_loop()
    a, aaaa, mx, ns, txt = await asyncio.gather(
        loop.run_in_executor(None, _resolve, domain, "A"),
        loop.run_in_executor(None, _resolve, domain, "AAAA"),
        loop.run_in_executor(None, _resolve, domain, "MX"),
        loop.run_in_executor(None, _resolve, domain, "NS"),
        loop.run_in_executor(None, _resolve, domain, "TXT"),
    )

    spf = None
    dmarc = None
    for record in txt:
        clean = record.strip('"')
        if clean.startswith("v=spf1"):
            spf = clean
            break

    dmarc_records = await loop.run_in_executor(None, _resolve, f"_dmarc.{domain}", "TXT")
    for record in dmarc_records:
        clean = record.strip('"')
        if clean.startswith("v=DMARC1"):
            dmarc = clean
            break

    return DnsRecords(a=a, aaaa=aaaa, mx=mx, ns=ns, txt=txt, spf=spf, dmarc=dmarc)


def _whois_socket_fallback(domain: str) -> dict:
    """Raw WHOIS socket query — fallback when system whois binary is missing (Windows)."""
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=10) as s:
            s.sendall(f"{domain}\r\n".encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
        text = raw.decode("utf-8", errors="replace")
        # Parse referral server
        refer = None
        for line in text.splitlines():
            if line.lower().startswith("refer:"):
                refer = line.split(":", 1)[1].strip()
                break
        if refer:
            with socket.create_connection((refer, 43), timeout=10) as s:
                s.sendall(f"{domain}\r\n".encode())
                raw = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
            text = raw.decode("utf-8", errors="replace")
        return _parse_whois_text(text)
    except (OSError, UnicodeDecodeError):
        return {}


def _parse_whois_text(text: str) -> dict:
    """Extract basic WHOIS fields from raw text."""
    result: dict = {}
    field_map = {
        "registrar": "registrar",
        "creation date": "creation_date",
        "updated date": "updated_date",
        "registry expiry date": "expiration_date",
        "registrant name": "registrant_name",
        "registrant organization": "registrant_org",
    }
    for line in text.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key_lower = key.strip().lower()
        if key_lower in field_map:
            result[field_map[key_lower]] = value.strip()
    return result


async def get_whois(domain: str) -> WhoisInfo:
    """Look up WHOIS data for a domain."""
    loop = asyncio.get_event_loop()
    try:
        w = await loop.run_in_executor(None, whois.whois, domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        return WhoisInfo(
            registrar=w.registrar,
            creation_date=creation,
            expiration_date=expiration,
            registrant_name=w.get("name"),
            registrant_org=w.get("org"),
        )
    except Exception:
        # Fallback for Windows (no whois binary)
        data = await loop.run_in_executor(None, _whois_socket_fallback, domain)
        if not data:
            return WhoisInfo()
        creation_date = None
        expiration_date = None
        if cd := data.get("creation_date"):
            try:
                creation_date = datetime.fromisoformat(cd.replace("Z", "+00:00"))
            except ValueError:
                pass
        if ed := data.get("expiration_date"):
            try:
                expiration_date = datetime.fromisoformat(ed.replace("Z", "+00:00"))
            except ValueError:
                pass
        return WhoisInfo(
            registrar=data.get("registrar"),
            creation_date=creation_date,
            expiration_date=expiration_date,
            registrant_name=data.get("registrant_name"),
            registrant_org=data.get("registrant_org"),
        )


async def check_security_headers(domain: str, client: httpx.AsyncClient) -> SecurityHeaders:
    """Check security-related HTTP headers."""
    try:
        resp = await client.head(f"https://{domain}", follow_redirects=True, timeout=10.0)
        headers = resp.headers
    except httpx.HTTPError:
        return SecurityHeaders()

    return SecurityHeaders(
        hsts="strict-transport-security" in headers,
        csp="content-security-policy" in headers,
        x_frame_options="x-frame-options" in headers,
        x_content_type_options="x-content-type-options" in headers,
        referrer_policy="referrer-policy" in headers,
    )


async def recon_domain(domain: str, cache: ReconCache | None = None) -> DomainReport:
    """Run all domain reconnaissance and return a combined report."""
    if cache:
        cached = cache.get("domain", domain)
        if cached:
            return DomainReport.model_validate(cached)

    async with httpx.AsyncClient(
        headers={"User-Agent": "osint-recon/0.1"},
        follow_redirects=True,
    ) as client:
        subdomains, dns_records, whois_info, sec_headers = await asyncio.gather(
            get_subdomains(domain, client),
            get_dns_records(domain),
            get_whois(domain),
            check_security_headers(domain, client),
        )

    report = DomainReport(
        domain=domain,
        subdomains=subdomains,
        dns=dns_records,
        whois=whois_info,
        security_headers=sec_headers,
    )

    if cache:
        cache.set("domain", domain, report.model_dump(mode="json"))

    return report
