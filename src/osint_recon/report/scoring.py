from __future__ import annotations

from typing import Protocol, runtime_checkable

from osint_recon.models import (
    DomainReport,
    EmailReport,
    FullReport,
    RiskScore,
    UsernameReport,
)


@runtime_checkable
class ScoringStrategy(Protocol):
    """Protocol for risk scoring strategies.

    Implement this to plug in alternative scorers (e.g. LLM-based)
    in the future.
    """

    def score(self, report: FullReport) -> RiskScore: ...


# ── Heuristic helpers ──────────────────────────────────────────

def _score_exposure(
    domain: DomainReport | None,
    email: EmailReport | None,
    username: UsernameReport | None,
) -> tuple[float, list[str]]:
    """Compute exposure score (0-100, higher = more exposed)."""
    score = 0.0
    details: list[str] = []

    if email and email.breaches:
        breach_pts = min(len(email.breaches) * 10, 50)
        score += breach_pts
        details.append(f"{len(email.breaches)} breach(es) found (+{breach_pts})")

    if domain and domain.subdomains:
        sub_pts = min(len(domain.subdomains) * 2, 20)
        score += sub_pts
        details.append(f"{len(domain.subdomains)} subdomain(s) found (+{sub_pts})")

    if username:
        found = sum(1 for r in username.results if r.status == "found")
        plat_pts = min(found * 3, 30)
        score += plat_pts
        if found:
            details.append(f"Username found on {found} platform(s) (+{plat_pts})")

    return min(score, 100.0), details


def _score_security_posture(domain: DomainReport | None) -> tuple[float, list[str]]:
    """Compute security posture (0-100, higher = better)."""
    if domain is None:
        return 100.0, []

    score = 100.0
    details: list[str] = []
    h = domain.security_headers

    deductions = [
        (h.hsts, 20, "Missing HSTS header"),
        (h.csp, 20, "Missing Content-Security-Policy header"),
        (h.x_frame_options, 10, "Missing X-Frame-Options header"),
        (h.x_content_type_options, 10, "Missing X-Content-Type-Options header"),
        (h.referrer_policy, 10, "Missing Referrer-Policy header"),
    ]
    for present, penalty, msg in deductions:
        if not present:
            score -= penalty
            details.append(f"{msg} (-{penalty})")

    dns = domain.dns
    if not dns.spf:
        score -= 15
        details.append("No SPF record found (-15)")
    if not dns.dmarc:
        score -= 15
        details.append("No DMARC record found (-15)")

    return max(score, 0.0), details


def _score_digital_footprint(
    domain: DomainReport | None,
    email: EmailReport | None,
    username: UsernameReport | None,
) -> tuple[float, list[str]]:
    """Compute digital footprint (0-100, higher = larger footprint)."""
    score = 0.0
    details: list[str] = []

    if username:
        found = sum(1 for r in username.results if r.status == "found")
        score += min(found * 5, 40)

    if email:
        if email.gravatar_url:
            score += 10
            details.append("Gravatar profile found (+10)")
        score += min(len(email.breaches) * 5, 25)

    if domain:
        score += min(len(domain.subdomains) * 1, 25)

    return min(score, 100.0), details


# ── Main scorer ────────────────────────────────────────────────

class HeuristicScorer:
    """Deterministic risk scorer using weighted heuristics."""

    def score(self, report: FullReport) -> RiskScore:
        domain = report.domain_report
        email = report.email_report
        username = report.username_report

        exposure, exp_details = _score_exposure(domain, email, username)
        posture, pos_details = _score_security_posture(domain)
        footprint, fp_details = _score_digital_footprint(domain, email, username)

        # Overall: weighted average — exposure and posture matter most
        overall = (exposure * 0.35) + ((100 - posture) * 0.40) + (footprint * 0.25)

        all_details = exp_details + pos_details + fp_details

        return RiskScore(
            overall=round(overall, 1),
            exposure=round(exposure, 1),
            security_posture=round(posture, 1),
            digital_footprint=round(footprint, 1),
            details=all_details,
        )
