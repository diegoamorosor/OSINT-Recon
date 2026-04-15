from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


# ── Domain models ──────────────────────────────────────────────

class SubdomainRecord(BaseModel):
    hostname: str
    issuer: str | None = None
    not_before: datetime | None = None


class DnsRecords(BaseModel):
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    spf: str | None = None
    dmarc: str | None = None


class WhoisInfo(BaseModel):
    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    registrant_name: str | None = None
    registrant_org: str | None = None


class SecurityHeaders(BaseModel):
    hsts: bool = False
    csp: bool = False
    x_frame_options: bool = False
    x_content_type_options: bool = False
    referrer_policy: bool = False


class DomainReport(BaseModel):
    domain: str
    subdomains: list[SubdomainRecord] = Field(default_factory=list)
    dns: DnsRecords = Field(default_factory=DnsRecords)
    whois: WhoisInfo = Field(default_factory=WhoisInfo)
    security_headers: SecurityHeaders = Field(default_factory=SecurityHeaders)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── Email models ───────────────────────────────────────────────

class BreachInfo(BaseModel):
    name: str
    date: str = ""
    data_classes: list[str] = Field(default_factory=list)


class EmailReport(BaseModel):
    email: str
    valid_format: bool = False
    mx_valid: bool = False
    breaches: list[BreachInfo] = Field(default_factory=list)
    gravatar_url: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── Username models ────────────────────────────────────────────

class PlatformResult(BaseModel):
    platform: str
    url: str
    status: Literal["found", "not_found", "uncertain"] = "uncertain"
    http_code: int = 0


class UsernameReport(BaseModel):
    username: str
    results: list[PlatformResult] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── Dorks & scoring ───────────────────────────────────────────

class DorkSet(BaseModel):
    category: str
    dorks: list[str] = Field(default_factory=list)


class RiskScore(BaseModel):
    overall: float = 0.0
    exposure: float = 0.0
    security_posture: float = 100.0
    digital_footprint: float = 0.0
    details: list[str] = Field(default_factory=list)


# ── Full report ────────────────────────────────────────────────

class FullReport(BaseModel):
    target: str
    domain_report: DomainReport | None = None
    email_report: EmailReport | None = None
    username_report: UsernameReport | None = None
    dorks: list[DorkSet] = Field(default_factory=list)
    risk: RiskScore = Field(default_factory=RiskScore)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
