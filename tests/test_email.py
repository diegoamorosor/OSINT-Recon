from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from osint_recon.recon.email import check_hibp, get_gravatar, validate_format

FIXTURES = Path(__file__).parent / "fixtures"


class TestValidateFormat:
    def test_valid_emails(self):
        assert validate_format("user@example.com") is True
        assert validate_format("user.name+tag@domain.co.uk") is True
        assert validate_format("a@b.io") is True

    def test_invalid_emails(self):
        assert validate_format("not-an-email") is False
        assert validate_format("@example.com") is False
        assert validate_format("user@") is False
        assert validate_format("user@.com") is False
        assert validate_format("") is False


@pytest.mark.asyncio
async def test_check_hibp_with_key():
    """HIBP should return breaches when API key is provided."""
    data = json.loads((FIXTURES / "hibp_response.json").read_text())

    async with respx.mock:
        respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com").respond(
            200, json=data
        )
        async with httpx.AsyncClient() as client:
            breaches = await check_hibp("test@example.com", "fake-key", client)

    assert len(breaches) == 2
    assert breaches[0].name == "Adobe"
    assert "Passwords" in breaches[0].data_classes


@pytest.mark.asyncio
async def test_check_hibp_without_key():
    """HIBP should return empty list when no API key."""
    async with httpx.AsyncClient() as client:
        breaches = await check_hibp("test@example.com", None, client)
    assert breaches == []


@pytest.mark.asyncio
async def test_check_hibp_no_breaches():
    """HIBP 404 means no breaches found."""
    async with respx.mock:
        respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/clean@example.com").respond(404)
        async with httpx.AsyncClient() as client:
            breaches = await check_hibp("clean@example.com", "fake-key", client)
    assert breaches == []


@pytest.mark.asyncio
async def test_get_gravatar_exists():
    """Gravatar should return URL when avatar exists."""
    async with respx.mock:
        respx.head(url__startswith="https://gravatar.com/avatar/").respond(200)
        async with httpx.AsyncClient() as client:
            url = await get_gravatar("test@example.com", client)
    assert url is not None
    assert "gravatar.com/avatar/" in url


@pytest.mark.asyncio
async def test_get_gravatar_not_exists():
    """Gravatar should return None when no avatar."""
    async with respx.mock:
        respx.head(url__startswith="https://gravatar.com/avatar/").respond(404)
        async with httpx.AsyncClient() as client:
            url = await get_gravatar("nobody@example.com", client)
    assert url is None
