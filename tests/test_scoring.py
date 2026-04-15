from __future__ import annotations

from osint_recon.models import (
    BreachInfo,
    DnsRecords,
    DomainReport,
    EmailReport,
    FullReport,
    PlatformResult,
    SecurityHeaders,
    UsernameReport,
)
from osint_recon.report.scoring import HeuristicScorer, ScoringStrategy


def _make_domain(
    subdomains_count: int = 0,
    hsts: bool = True,
    csp: bool = True,
    spf: str | None = "v=spf1",
    dmarc: str | None = "v=DMARC1",
) -> DomainReport:
    from osint_recon.models import SubdomainRecord
    return DomainReport(
        domain="example.com",
        subdomains=[SubdomainRecord(hostname=f"s{i}.example.com") for i in range(subdomains_count)],
        dns=DnsRecords(spf=spf, dmarc=dmarc),
        security_headers=SecurityHeaders(
            hsts=hsts,
            csp=csp,
            x_frame_options=True,
            x_content_type_options=True,
            referrer_policy=True,
        ),
    )


def _make_email(breaches_count: int = 0, gravatar: bool = False) -> EmailReport:
    return EmailReport(
        email="test@example.com",
        valid_format=True,
        mx_valid=True,
        breaches=[BreachInfo(name=f"Breach{i}") for i in range(breaches_count)],
        gravatar_url="https://gravatar.com/avatar/abc" if gravatar else None,
    )


def _make_username(found: int = 0, not_found: int = 0) -> UsernameReport:
    results = []
    for i in range(found):
        results.append(PlatformResult(platform=f"P{i}", url=f"https://p{i}.com/user", status="found"))
    for i in range(not_found):
        results.append(PlatformResult(platform=f"NP{i}", url=f"https://np{i}.com/user", status="not_found"))
    return UsernameReport(username="testuser", results=results)


class TestHeuristicScorer:
    scorer = HeuristicScorer()

    def test_protocol_compliance(self):
        """HeuristicScorer should satisfy the ScoringStrategy protocol."""
        assert isinstance(self.scorer, ScoringStrategy)

    def test_zero_risk_baseline(self):
        """No data should produce minimal risk."""
        report = FullReport(target="test")
        score = self.scorer.score(report)
        assert score.overall == 0.0
        assert score.exposure == 0.0
        assert score.security_posture == 100.0
        assert score.digital_footprint == 0.0

    def test_exposure_from_breaches(self):
        """Breaches should increase exposure score."""
        report = FullReport(
            target="test",
            email_report=_make_email(breaches_count=3),
        )
        score = self.scorer.score(report)
        assert score.exposure == 30.0  # 3 * 10

    def test_exposure_capped(self):
        """Exposure from breaches should cap at 50."""
        report = FullReport(
            target="test",
            email_report=_make_email(breaches_count=10),
        )
        score = self.scorer.score(report)
        # 10 breaches * 10 = 100, capped at 50
        assert score.exposure >= 50.0

    def test_security_posture_all_missing(self):
        """Missing all headers + SPF + DMARC should bottom out posture."""
        report = FullReport(
            target="test",
            domain_report=_make_domain(hsts=False, csp=False, spf=None, dmarc=None),
        )
        # Override x_frame, x_content_type, referrer to False
        report.domain_report.security_headers.x_frame_options = False
        report.domain_report.security_headers.x_content_type_options = False
        report.domain_report.security_headers.referrer_policy = False
        score = self.scorer.score(report)
        assert score.security_posture == 0.0

    def test_security_posture_all_present(self):
        """All headers + SPF + DMARC present should keep posture at 100."""
        report = FullReport(
            target="test",
            domain_report=_make_domain(),
        )
        score = self.scorer.score(report)
        assert score.security_posture == 100.0

    def test_username_exposure(self):
        """Found platforms should contribute to exposure."""
        report = FullReport(
            target="test",
            username_report=_make_username(found=5),
        )
        score = self.scorer.score(report)
        assert score.exposure == 15.0  # 5 * 3

    def test_digital_footprint_gravatar(self):
        """Gravatar should add to digital footprint."""
        report = FullReport(
            target="test",
            email_report=_make_email(gravatar=True),
        )
        score = self.scorer.score(report)
        assert score.digital_footprint >= 10.0

    def test_scores_clamped_0_100(self):
        """All scores should be within [0, 100]."""
        report = FullReport(
            target="test",
            domain_report=_make_domain(subdomains_count=100, hsts=False, csp=False, spf=None, dmarc=None),
            email_report=_make_email(breaches_count=20, gravatar=True),
            username_report=_make_username(found=20),
        )
        report.domain_report.security_headers.x_frame_options = False
        report.domain_report.security_headers.x_content_type_options = False
        report.domain_report.security_headers.referrer_policy = False
        score = self.scorer.score(report)
        assert 0 <= score.overall <= 100
        assert 0 <= score.exposure <= 100
        assert 0 <= score.security_posture <= 100
        assert 0 <= score.digital_footprint <= 100
