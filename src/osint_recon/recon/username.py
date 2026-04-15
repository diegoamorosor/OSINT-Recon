from __future__ import annotations

import asyncio

import httpx

from osint_recon.cache import ReconCache
from osint_recon.models import PlatformResult, UsernameReport

PLATFORMS: list[dict[str, str]] = [
    {"name": "GitHub", "url": "https://github.com/{}"},
    {"name": "GitLab", "url": "https://gitlab.com/{}"},
    {"name": "Twitter/X", "url": "https://x.com/{}"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}"},
    {"name": "Medium", "url": "https://medium.com/@{}"},
    {"name": "Dev.to", "url": "https://dev.to/{}"},
    {"name": "StackOverflow", "url": "https://stackoverflow.com/users/{}"},
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}"},
    {"name": "Keybase", "url": "https://keybase.io/{}"},
    {"name": "Mastodon", "url": "https://mastodon.social/@{}"},
    {"name": "Lobste.rs", "url": "https://lobste.rs/u/{}"},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{}"},
    {"name": "Replit", "url": "https://replit.com/@{}"},
    {"name": "HackTheBox", "url": "https://app.hackthebox.com/users/{}"},
    {"name": "TryHackMe", "url": "https://tryhackme.com/p/{}"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}"},
    {"name": "Telegram", "url": "https://t.me/{}"},
]

# Platforms that typically block scraping or always return 200
_UNCERTAIN_PLATFORMS = {"LinkedIn", "Instagram", "Twitter/X", "HackTheBox"}


async def _check_one(
    platform: dict[str, str],
    username: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> PlatformResult:
    url = platform["url"].format(username)
    name = platform["name"]
    async with semaphore:
        try:
            resp = await client.get(url, timeout=10.0)
            code = resp.status_code

            if name in _UNCERTAIN_PLATFORMS:
                status = "uncertain"
            elif code == 200:
                status = "found"
            elif code == 404:
                status = "not_found"
            else:
                status = "uncertain"

            return PlatformResult(platform=name, url=url, status=status, http_code=code)
        except httpx.HTTPError:
            return PlatformResult(platform=name, url=url, status="uncertain", http_code=0)


async def check_presence(
    username: str,
    client: httpx.AsyncClient,
    concurrency: int = 10,
) -> list[PlatformResult]:
    """Check username presence across platforms with bounded concurrency."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [_check_one(p, username, client, semaphore) for p in PLATFORMS]
    return list(await asyncio.gather(*tasks))


async def recon_username(
    username: str,
    cache: ReconCache | None = None,
) -> UsernameReport:
    """Run username reconnaissance and return a combined report."""
    if cache:
        cached = cache.get("username", username)
        if cached:
            return UsernameReport.model_validate(cached)

    async with httpx.AsyncClient(
        headers={"User-Agent": "osint-recon/0.1"},
        follow_redirects=True,
    ) as client:
        results = await check_presence(username, client)

    report = UsernameReport(username=username, results=results)

    if cache:
        cache.set("username", username, report.model_dump(mode="json"))

    return report
