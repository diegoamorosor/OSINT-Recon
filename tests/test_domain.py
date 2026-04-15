from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from osint_recon.recon.domain import (
    check_security_headers,
    get_dns_records,
    get_subdomains,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.asyncio
async def test_get_subdomains_deduplication():
    """crt.sh duplicates and wildcards should be deduplicated."""
    data = json.loads((FIXTURES / "crtsh_response.json").read_text())

    async with respx.mock:
        respx.get("https://crt.sh/").respond(200, json=data)
        async with httpx.AsyncClient() as client:
            results = await get_subdomains("example.com", client)

    hostnames = [r.hostname for r in results]
    # www.example.com appears twice in fixture — should be deduplicated
    assert hostnames.count("www.example.com") == 1
    # wildcard *.example.com should become example.com
    assert "example.com" in hostnames
    # api and mail should be present
    assert "api.example.com" in hostnames
    assert "mail.example.com" in hostnames


@pytest.mark.asyncio
async def test_get_subdomains_error_handling():
    """Network errors should return an empty list."""
    async with respx.mock:
        respx.get("https://crt.sh/").respond(500)
        async with httpx.AsyncClient() as client:
            results = await get_subdomains("example.com", client)
    assert results == []


@pytest.mark.asyncio
async def test_get_dns_records():
    """DNS resolution should populate the model correctly."""
    mock_answer_a = MagicMock()
    mock_answer_a.__iter__ = lambda self: iter([MagicMock(to_text=lambda: "93.184.216.34")])

    mock_answer_mx = MagicMock()
    mock_answer_mx.__iter__ = lambda self: iter([MagicMock(to_text=lambda: "10 mail.example.com.")])

    mock_answer_txt = MagicMock()
    txt1 = MagicMock()
    txt1.to_text = lambda: '"v=spf1 include:_spf.example.com ~all"'
    mock_answer_txt.__iter__ = lambda self: iter([txt1])

    mock_answer_dmarc = MagicMock()
    dmarc1 = MagicMock()
    dmarc1.to_text = lambda: '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
    mock_answer_dmarc.__iter__ = lambda self: iter([dmarc1])

    def mock_resolve(domain, rdtype):
        if rdtype == "A":
            return [r.to_text() for r in mock_answer_a]
        if rdtype == "MX":
            return [r.to_text() for r in mock_answer_mx]
        if rdtype == "TXT" and domain.startswith("_dmarc."):
            return [r.to_text() for r in mock_answer_dmarc]
        if rdtype == "TXT":
            return [r.to_text() for r in mock_answer_txt]
        return []

    with patch("osint_recon.recon.domain._resolve", side_effect=mock_resolve):
        records = await get_dns_records("example.com")

    assert "93.184.216.34" in records.a
    assert any("mail.example.com" in m for m in records.mx)
    assert records.spf is not None and "v=spf1" in records.spf
    assert records.dmarc is not None and "v=DMARC1" in records.dmarc


@pytest.mark.asyncio
async def test_check_security_headers_all_present():
    """All security headers present should return all True."""
    async with respx.mock:
        respx.head("https://secure.example.com").respond(
            200,
            headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin",
            },
        )
        async with httpx.AsyncClient() as client:
            sh = await check_security_headers("secure.example.com", client)

    assert sh.hsts is True
    assert sh.csp is True
    assert sh.x_frame_options is True
    assert sh.x_content_type_options is True
    assert sh.referrer_policy is True


@pytest.mark.asyncio
async def test_check_security_headers_none_present():
    """No security headers should return all False."""
    async with respx.mock:
        respx.head("https://insecure.example.com").respond(200, headers={})
        async with httpx.AsyncClient() as client:
            sh = await check_security_headers("insecure.example.com", client)

    assert sh.hsts is False
    assert sh.csp is False
    assert sh.x_frame_options is False


@pytest.mark.asyncio
async def test_check_security_headers_connection_error():
    """Connection errors should return all-false SecurityHeaders."""
    async with respx.mock:
        respx.head("https://down.example.com").mock(side_effect=httpx.ConnectError("fail"))
        async with httpx.AsyncClient() as client:
            sh = await check_security_headers("down.example.com", client)

    assert sh.hsts is False
    assert sh.csp is False
