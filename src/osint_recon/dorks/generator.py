from __future__ import annotations

from osint_recon.models import DorkSet


def generate_for_domain(domain: str) -> DorkSet:
    """Generate Google dorks for a given domain."""
    return DorkSet(
        category="domain",
        dorks=[
            f'site:{domain}',
            f'site:{domain} ext:pdf',
            f'site:{domain} ext:xlsx',
            f'site:{domain} ext:docx',
            f'site:{domain} ext:sql',
            f'site:{domain} ext:log',
            f'site:{domain} ext:env',
            f'site:{domain} ext:conf',
            f'site:{domain} ext:bak',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:api',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} intext:"password"',
            f'site:pastebin.com "{domain}"',
            f'site:github.com "{domain}"',
            f'site:trello.com "{domain}"',
            f'inurl:"{domain}" ext:sql',
            f'inurl:"{domain}" ext:env',
        ],
    )


def generate_for_email(email: str) -> DorkSet:
    """Generate Google dorks for a given email address."""
    local, _, domain = email.partition("@")
    return DorkSet(
        category="email",
        dorks=[
            f'"{email}"',
            f'intext:"{email}"',
            f'site:pastebin.com "{email}"',
            f'site:github.com "{email}"',
            f'site:linkedin.com "{email}"',
            f'"{local}" site:{domain}',
            f'filetype:pdf "{email}"',
            f'filetype:xlsx "{email}"',
            f'filetype:csv "{email}"',
        ],
    )


def generate_for_username(username: str) -> DorkSet:
    """Generate Google dorks for a given username."""
    return DorkSet(
        category="username",
        dorks=[
            f'"{username}"',
            f'inurl:"{username}"',
            f'site:github.com "{username}"',
            f'site:gitlab.com "{username}"',
            f'site:pastebin.com "{username}"',
            f'site:reddit.com/user/{username}',
            f'site:medium.com "@{username}"',
            f'site:keybase.io "{username}"',
            f'"{username}" site:t.me',
            f'"{username}" filetype:pdf',
        ],
    )
