from __future__ import annotations

import httpx
import pytest
import respx

from osint_recon.recon.username import PLATFORMS, check_presence


@pytest.mark.asyncio
async def test_check_presence_found():
    """Platform returning 200 should be marked as found (unless in uncertain set)."""
    async with respx.mock:
        # Mock all platforms
        for p in PLATFORMS:
            url = p["url"].format("testuser")
            respx.get(url).respond(200)

        async with httpx.AsyncClient(follow_redirects=True) as client:
            results = await check_presence("testuser", client)

    # Non-uncertain platforms with 200 should be "found"
    from osint_recon.recon.username import _UNCERTAIN_PLATFORMS
    for r in results:
        if r.platform in _UNCERTAIN_PLATFORMS:
            assert r.status == "uncertain"
        else:
            assert r.status == "found"


@pytest.mark.asyncio
async def test_check_presence_not_found():
    """Platform returning 404 should be marked as not_found."""
    async with respx.mock:
        for p in PLATFORMS:
            url = p["url"].format("nonexistentuser12345")
            respx.get(url).respond(404)

        async with httpx.AsyncClient(follow_redirects=True) as client:
            results = await check_presence("nonexistentuser12345", client)

    from osint_recon.recon.username import _UNCERTAIN_PLATFORMS
    for r in results:
        if r.platform in _UNCERTAIN_PLATFORMS:
            assert r.status == "uncertain"
        else:
            assert r.status == "not_found"


@pytest.mark.asyncio
async def test_check_presence_error():
    """Connection errors should be marked as uncertain."""
    async with respx.mock:
        for p in PLATFORMS:
            url = p["url"].format("erroruser")
            respx.get(url).mock(side_effect=httpx.ConnectError("fail"))

        async with httpx.AsyncClient(follow_redirects=True) as client:
            results = await check_presence("erroruser", client)

    for r in results:
        assert r.status == "uncertain"
        assert r.http_code == 0


@pytest.mark.asyncio
async def test_check_presence_returns_all_platforms():
    """Should return a result for every configured platform."""
    async with respx.mock:
        for p in PLATFORMS:
            url = p["url"].format("anyuser")
            respx.get(url).respond(200)

        async with httpx.AsyncClient(follow_redirects=True) as client:
            results = await check_presence("anyuser", client)

    assert len(results) == len(PLATFORMS)
    platform_names = {r.platform for r in results}
    expected_names = {p["name"] for p in PLATFORMS}
    assert platform_names == expected_names
