from __future__ import annotations

import asyncio
import hashlib
import re

import dns.resolver
import httpx
import tldextract

from osint_recon.cache import ReconCache
from osint_recon.models import BreachInfo, EmailReport

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def validate_format(email: str) -> bool:
    """Validate email format using regex and TLD extraction."""
    if not _EMAIL_RE.match(email):
        return False
    domain_part = email.rsplit("@", 1)[1]
    ext = tldextract.extract(domain_part)
    return bool(ext.domain and ext.suffix)


async def check_mx(email: str) -> bool:
    """Verify that the email's domain has MX records."""
    domain = email.rsplit("@", 1)[1]
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, dns.resolver.resolve, domain, "MX")
        return len(answers) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception):
        return False


async def check_hibp(
    email: str,
    api_key: str | None,
    client: httpx.AsyncClient,
) -> list[BreachInfo]:
    """Check Have I Been Pwned for breaches associated with the email."""
    if not api_key:
        return []

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "osint-recon/0.1",
    }
    try:
        resp = await client.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []

    return [
        BreachInfo(
            name=b.get("Name", "Unknown"),
            date=b.get("BreachDate", ""),
            data_classes=b.get("DataClasses", []),
        )
        for b in data
    ]


async def get_gravatar(email: str, client: httpx.AsyncClient) -> str | None:
    """Get Gravatar URL if the email has an associated avatar."""
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://gravatar.com/avatar/{email_hash}?d=404"
    try:
        resp = await client.head(url, timeout=10.0)
        if resp.status_code == 200:
            return f"https://gravatar.com/avatar/{email_hash}"
    except httpx.HTTPError:
        pass
    return None


async def recon_email(
    email: str,
    cache: ReconCache | None = None,
    hibp_api_key: str | None = None,
) -> EmailReport:
    """Run all email reconnaissance and return a combined report."""
    if cache:
        cached = cache.get("email", email)
        if cached:
            return EmailReport.model_validate(cached)

    valid = validate_format(email)

    async with httpx.AsyncClient(follow_redirects=True) as client:
        mx_valid, breaches, gravatar_url = await asyncio.gather(
            check_mx(email),
            check_hibp(email, hibp_api_key, client),
            get_gravatar(email, client),
        )

    report = EmailReport(
        email=email,
        valid_format=valid,
        mx_valid=mx_valid,
        breaches=breaches,
        gravatar_url=gravatar_url,
    )

    if cache:
        cache.set("email", email, report.model_dump(mode="json"))

    return report
