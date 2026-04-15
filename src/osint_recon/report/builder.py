from __future__ import annotations

from osint_recon import __version__
from osint_recon.models import FullReport


def build_markdown(report: FullReport) -> str:
    """Assemble a full Markdown report from a FullReport."""
    lines: list[str] = []
    _h = lines.append

    _h(f"# OSINT Reconnaissance Report")
    _h(f"**Target:** `{report.target}`")
    _h(f"**Generated:** {report.generated_at:%Y-%m-%d %H:%M:%S UTC}")
    _h("")
    _h("---")
    _h("")

    # ── Risk Summary ──
    r = report.risk
    _h("## Risk Summary")
    _h("")
    _h("| Category | Score |")
    _h("|----------|-------|")
    _h(f"| **Overall Risk** | **{r.overall}/100** |")
    _h(f"| Exposure | {r.exposure}/100 |")
    _h(f"| Security Posture | {r.security_posture}/100 |")
    _h(f"| Digital Footprint | {r.digital_footprint}/100 |")
    _h("")
    if r.details:
        _h("### Risk Details")
        _h("")
        for d in r.details:
            _h(f"- {d}")
        _h("")

    # ── Domain ──
    dr = report.domain_report
    if dr:
        _h("---")
        _h("")
        _h("## Domain Analysis")
        _h("")

        _h(f"### Subdomains ({len(dr.subdomains)})")
        _h("")
        if dr.subdomains:
            _h("| Hostname | Issuer |")
            _h("|----------|--------|")
            for s in dr.subdomains[:50]:
                issuer = s.issuer or "—"
                _h(f"| `{s.hostname}` | {issuer} |")
            if len(dr.subdomains) > 50:
                _h(f"| ... and {len(dr.subdomains) - 50} more | |")
        else:
            _h("No subdomains found via crt.sh.")
        _h("")

        _h("### DNS Records")
        _h("")
        dns = dr.dns
        for rtype, values in [
            ("A", dns.a), ("AAAA", dns.aaaa), ("MX", dns.mx),
            ("NS", dns.ns), ("TXT", dns.txt),
        ]:
            if values:
                _h(f"**{rtype}:**")
                for v in values:
                    _h(f"- `{v}`")
                _h("")
        if dns.spf:
            _h(f"**SPF:** `{dns.spf}`")
            _h("")
        if dns.dmarc:
            _h(f"**DMARC:** `{dns.dmarc}`")
            _h("")

        _h("### WHOIS Information")
        _h("")
        w = dr.whois
        _h(f"- **Registrar:** {w.registrar or 'Unknown'}")
        _h(f"- **Created:** {w.creation_date or 'Unknown'}")
        _h(f"- **Expires:** {w.expiration_date or 'Unknown'}")
        if w.registrant_name:
            _h(f"- **Registrant:** {w.registrant_name}")
        if w.registrant_org:
            _h(f"- **Organization:** {w.registrant_org}")
        _h("")

        _h("### Security Headers")
        _h("")
        sh = dr.security_headers
        _h("| Header | Present |")
        _h("|--------|---------|")
        for name, present in [
            ("Strict-Transport-Security", sh.hsts),
            ("Content-Security-Policy", sh.csp),
            ("X-Frame-Options", sh.x_frame_options),
            ("X-Content-Type-Options", sh.x_content_type_options),
            ("Referrer-Policy", sh.referrer_policy),
        ]:
            icon = "Yes" if present else "**No**"
            _h(f"| {name} | {icon} |")
        _h("")

    # ── Email ──
    er = report.email_report
    if er:
        _h("---")
        _h("")
        _h("## Email Analysis")
        _h("")
        _h(f"- **Email:** `{er.email}`")
        _h(f"- **Valid format:** {'Yes' if er.valid_format else 'No'}")
        _h(f"- **MX records:** {'Yes' if er.mx_valid else 'No'}")
        if er.gravatar_url:
            _h(f"- **Gravatar:** [{er.gravatar_url}]({er.gravatar_url})")
        _h("")

        _h(f"### Breaches ({len(er.breaches)})")
        _h("")
        if er.breaches:
            _h("| Breach | Date | Data Types |")
            _h("|--------|------|------------|")
            for b in er.breaches:
                classes = ", ".join(b.data_classes[:5]) if b.data_classes else "—"
                _h(f"| {b.name} | {b.date or '—'} | {classes} |")
        else:
            _h("No breaches found (or HIBP API key not configured).")
        _h("")

    # ── Username ──
    ur = report.username_report
    if ur:
        _h("---")
        _h("")
        _h("## Username Presence")
        _h("")
        found = [r for r in ur.results if r.status == "found"]
        not_found = [r for r in ur.results if r.status == "not_found"]
        uncertain = [r for r in ur.results if r.status == "uncertain"]

        _h(f"**Found:** {len(found)} | **Not found:** {len(not_found)} | **Uncertain:** {len(uncertain)}")
        _h("")

        _h("| Platform | Status | URL |")
        _h("|----------|--------|-----|")
        for res in sorted(ur.results, key=lambda x: (x.status != "found", x.platform)):
            status_label = {
                "found": "Found",
                "not_found": "Not Found",
                "uncertain": "Uncertain",
            }[res.status]
            _h(f"| {res.platform} | {status_label} | {res.url} |")
        _h("")

    # ── Dorks ──
    if report.dorks:
        _h("---")
        _h("")
        _h("## Google Dorks")
        _h("")
        for dork_set in report.dorks:
            _h(f"### {dork_set.category.title()} Dorks")
            _h("")
            for d in dork_set.dorks:
                _h(f"- `{d}`")
            _h("")

    # ── Footer ──
    _h("---")
    _h("")
    _h(f"_Report generated by osint-recon v{__version__}_")
    _h("")

    return "\n".join(lines)
