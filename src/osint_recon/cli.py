from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from osint_recon import __version__
from osint_recon.cache import ReconCache
from osint_recon.dorks.generator import (
    generate_for_domain,
    generate_for_email,
    generate_for_username,
)
from osint_recon.models import FullReport
from osint_recon.recon.domain import recon_domain
from osint_recon.recon.email import recon_email
from osint_recon.recon.username import recon_username
from osint_recon.report.builder import build_markdown
from osint_recon.report.scoring import HeuristicScorer

console = Console()
scorer = HeuristicScorer()


import contextlib

@contextlib.contextmanager
def _status(msg: str):
    """Spinner that falls back to a simple print on encoding errors."""
    try:
        with console.status(msg, spinner="line"):
            yield
    except UnicodeEncodeError:
        console.print(msg)
        yield

BANNER = """
   ____  _____ _____ _   _ _____
  / __ \\/ ____|_   _| \\ | |_   _|
 | |  | | (___   | | |  \\| | | |
 | |  | |\\___ \\  | | | .   | | |
 | |__| |____) |_| |_| |\\  | | |
  \\____/|_____/|_____|_| \\_| |_|
               RECON
"""


def _run(coro):
    """Run an async coroutine from sync context."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.run(coro)


def _get_cache(no_cache: bool) -> ReconCache | None:
    if no_cache:
        return None
    return ReconCache()


def _print_banner() -> None:
    console.print(
        Panel(
            Text(BANNER, style="bold cyan", justify="center"),
            subtitle=f"v{__version__}",
            border_style="cyan",
        )
    )


def _write_report(report: FullReport, output: str | None) -> None:
    md = build_markdown(report)
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md, encoding="utf-8")
        console.print(f"\n[bold green]Report saved to:[/bold green] {path.resolve()}")
    else:
        console.print(f"\n[dim]Tip: use -o report.md to save the full report to a file[/dim]")


def _print_risk_table(report: FullReport) -> None:
    r = report.risk
    table = Table(
        title="Risk Score",
        show_header=True,
        title_style="bold white",
        border_style="bright_black",
    )
    table.add_column("Category", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Bar", min_width=20)

    def _bar(value: float, inverse: bool = False) -> str:
        display = value if not inverse else (100 - value)
        filled = int(display / 5)
        if display >= 70:
            color = "red" if not inverse else "green"
        elif display >= 40:
            color = "yellow"
        else:
            color = "green" if not inverse else "red"
        return f"[{color}]{'#' * filled}{'.' * (20 - filled)}[/{color}]"

    table.add_row("Overall Risk", f"[bold]{r.overall:.0f}/100[/bold]", _bar(r.overall))
    table.add_row("Exposure", f"{r.exposure:.0f}/100", _bar(r.exposure))
    table.add_row("Security Posture", f"{r.security_posture:.0f}/100", _bar(r.security_posture, inverse=True))
    table.add_row("Digital Footprint", f"{r.digital_footprint:.0f}/100", _bar(r.digital_footprint))
    console.print()
    console.print(table)

    if r.details:
        console.print()
        for d in r.details:
            console.print(f"  [dim]-[/dim] {d}")


# ── CLI ────────────────────────────────────────────────────────

@click.group()
@click.version_option(version=__version__, prog_name="osint-recon")
@click.option("--no-cache", is_flag=True, help="Disable result caching")
@click.option("-o", "--output", type=click.Path(), default=None, help="Save markdown report to file")
@click.pass_context
def app(ctx: click.Context, no_cache: bool, output: str | None) -> None:
    """osint-recon -- OSINT reconnaissance toolkit for domains, emails & usernames."""
    load_dotenv()
    ctx.ensure_object(dict)
    ctx.obj["no_cache"] = no_cache
    ctx.obj["output"] = output


@app.command()
@click.argument("target")
@click.pass_context
def domain(ctx: click.Context, target: str) -> None:
    """Reconnoiter a domain: subdomains, DNS, WHOIS, security headers."""
    _print_banner()
    console.print(f"[bold]Target:[/bold] {target}  [dim](domain)[/dim]\n")
    cache = _get_cache(ctx.obj["no_cache"])
    try:
        with _status("[bold cyan]Scanning domain...[/bold cyan]"):
            domain_report = _run(recon_domain(target, cache))

        dorks = [generate_for_domain(target)]
        report = FullReport(target=target, domain_report=domain_report, dorks=dorks)
        report.risk = scorer.score(report)

        _display_domain(domain_report)
        _print_risk_table(report)
        _write_report(report, ctx.obj["output"])
    finally:
        if cache:
            cache.close()


@app.command()
@click.argument("target")
@click.pass_context
def email(ctx: click.Context, target: str) -> None:
    """Reconnoiter an email: format, MX, breaches, Gravatar."""
    _print_banner()
    console.print(f"[bold]Target:[/bold] {target}  [dim](email)[/dim]\n")
    cache = _get_cache(ctx.obj["no_cache"])
    hibp_key = os.environ.get("HIBP_API_KEY") or None
    if not hibp_key:
        console.print("[yellow]Warning:[/yellow] HIBP_API_KEY not set — breach lookup disabled\n")
    try:
        with _status("[bold cyan]Scanning email...[/bold cyan]"):
            email_report = _run(recon_email(target, cache, hibp_key))

        dorks = [generate_for_email(target)]
        report = FullReport(target=target, email_report=email_report, dorks=dorks)
        report.risk = scorer.score(report)

        _display_email(email_report)
        _print_risk_table(report)
        _write_report(report, ctx.obj["output"])
    finally:
        if cache:
            cache.close()


@app.command()
@click.argument("target")
@click.pass_context
def username(ctx: click.Context, target: str) -> None:
    """Reconnoiter a username across ~20 platforms."""
    _print_banner()
    console.print(f"[bold]Target:[/bold] {target}  [dim](username)[/dim]\n")
    cache = _get_cache(ctx.obj["no_cache"])
    try:
        with _status("[bold cyan]Scanning platforms...[/bold cyan]"):
            username_report = _run(recon_username(target, cache))

        dorks = [generate_for_username(target)]
        report = FullReport(target=target, username_report=username_report, dorks=dorks)
        report.risk = scorer.score(report)

        _display_username(username_report)
        _print_risk_table(report)
        _write_report(report, ctx.obj["output"])
    finally:
        if cache:
            cache.close()


@app.command()
@click.argument("target")
@click.pass_context
def full(ctx: click.Context, target: str) -> None:
    """Full recon -- auto-detects target type and runs all applicable checks."""
    _print_banner()
    cache = _get_cache(ctx.obj["no_cache"])
    hibp_key = os.environ.get("HIBP_API_KEY") or None

    try:
        is_email = "@" in target
        is_domain = "." in target and not is_email
        target_type = "email" if is_email else "domain" if is_domain else "username"
        console.print(f"[bold]Target:[/bold] {target}  [dim](auto-detected: {target_type})[/dim]\n")

        if is_email and not hibp_key:
            console.print("[yellow]Warning:[/yellow] HIBP_API_KEY not set — breach lookup disabled\n")

        dorks = []

        async def _run_all():
            tasks = []
            if is_domain:
                tasks.append(("domain", recon_domain(target, cache)))
            if is_email:
                tasks.append(("email", recon_email(target, cache, hibp_key)))
            uname = target.split("@")[0] if is_email else target.split(".")[0] if is_domain else target
            tasks.append(("username", recon_username(uname, cache)))

            results = await asyncio.gather(*[t[1] for t in tasks])
            result_map = {tasks[i][0]: results[i] for i in range(len(tasks))}

            return (
                result_map.get("domain"),
                result_map.get("email"),
                result_map.get("username"),
                uname,
            )

        with _status("[bold cyan]Running full reconnaissance...[/bold cyan]"):
            domain_report, email_report, username_report, uname = _run(_run_all())

        if is_domain:
            dorks.append(generate_for_domain(target))
        if is_email:
            dorks.append(generate_for_email(target))
        dorks.append(generate_for_username(uname))

        report = FullReport(
            target=target,
            domain_report=domain_report,
            email_report=email_report,
            username_report=username_report,
            dorks=dorks,
        )
        report.risk = scorer.score(report)

        if domain_report:
            _display_domain(domain_report)
        if email_report:
            _display_email(email_report)
        if username_report:
            _display_username(username_report)

        _print_risk_table(report)
        _write_report(report, ctx.obj["output"])
    finally:
        if cache:
            cache.close()


# ── Display helpers ────────────────────────────────────────────

def _display_domain(dr) -> None:
    console.print(Panel("[bold]Domain Analysis[/bold]", border_style="green"))

    # Subdomains
    if dr.subdomains:
        table = Table(
            title=f"Subdomains ({len(dr.subdomains)})",
            title_style="bold",
            border_style="bright_black",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Hostname", style="cyan")
        table.add_column("Issuer", style="dim")
        for i, s in enumerate(dr.subdomains[:25], 1):
            table.add_row(str(i), s.hostname, s.issuer or "—")
        if len(dr.subdomains) > 25:
            table.add_row("", f"... +{len(dr.subdomains) - 25} more", "")
        console.print(table)
    else:
        console.print("  [dim]No subdomains found via crt.sh[/dim]")
    console.print()

    # DNS
    dns = dr.dns
    table = Table(title="DNS Records", title_style="bold", border_style="bright_black")
    table.add_column("Type", style="bold cyan", width=8)
    table.add_column("Values")
    for rtype, values in [("A", dns.a), ("AAAA", dns.aaaa), ("MX", dns.mx), ("NS", dns.ns)]:
        if values:
            table.add_row(rtype, "\n".join(values))
    if dns.spf:
        table.add_row("SPF", dns.spf)
    if dns.dmarc:
        table.add_row("DMARC", dns.dmarc)
    console.print(table)
    console.print()

    # WHOIS
    w = dr.whois
    table = Table(title="WHOIS", title_style="bold", border_style="bright_black", show_header=False)
    table.add_column("Field", style="bold", width=14)
    table.add_column("Value")
    table.add_row("Registrar", w.registrar or "Unknown")
    table.add_row("Created", str(w.creation_date or "Unknown"))
    table.add_row("Expires", str(w.expiration_date or "Unknown"))
    if w.registrant_name:
        table.add_row("Registrant", w.registrant_name)
    if w.registrant_org:
        table.add_row("Organization", w.registrant_org)
    console.print(table)
    console.print()

    # Security Headers
    sh = dr.security_headers
    table = Table(title="Security Headers", title_style="bold", border_style="bright_black")
    table.add_column("Header", width=30)
    table.add_column("Status", justify="center", width=10)
    for name, present in [
        ("Strict-Transport-Security", sh.hsts),
        ("Content-Security-Policy", sh.csp),
        ("X-Frame-Options", sh.x_frame_options),
        ("X-Content-Type-Options", sh.x_content_type_options),
        ("Referrer-Policy", sh.referrer_policy),
    ]:
        icon = "[bold green]PASS[/bold green]" if present else "[bold red]FAIL[/bold red]"
        table.add_row(name, icon)
    console.print(table)


def _display_email(er) -> None:
    console.print(Panel("[bold]Email Analysis[/bold]", border_style="green"))

    table = Table(show_header=False, border_style="bright_black")
    table.add_column("Field", style="bold", width=16)
    table.add_column("Value")
    table.add_row("Email", er.email)
    table.add_row(
        "Valid format",
        "[bold green]Yes[/bold green]" if er.valid_format else "[bold red]No[/bold red]",
    )
    table.add_row(
        "MX records",
        "[bold green]Yes[/bold green]" if er.mx_valid else "[bold red]No[/bold red]",
    )
    if er.gravatar_url:
        table.add_row("Gravatar", er.gravatar_url)
    console.print(table)
    console.print()

    if er.breaches:
        table = Table(
            title=f"Breaches ({len(er.breaches)})",
            title_style="bold red",
            border_style="red",
        )
        table.add_column("Name", style="bold")
        table.add_column("Date")
        table.add_column("Data Types", style="dim")
        for b in er.breaches:
            table.add_row(b.name, b.date or "—", ", ".join(b.data_classes[:4]))
        console.print(table)
    else:
        console.print("  [green]No breaches found[/green]")


def _display_username(ur) -> None:
    console.print(Panel("[bold]Username Presence[/bold]", border_style="green"))

    found = [r for r in ur.results if r.status == "found"]
    not_found = [r for r in ur.results if r.status == "not_found"]
    uncertain = [r for r in ur.results if r.status == "uncertain"]

    console.print(
        f"  [green]Found: {len(found)}[/green]  "
        f"[red]Not found: {len(not_found)}[/red]  "
        f"[yellow]Uncertain: {len(uncertain)}[/yellow]\n"
    )

    table = Table(border_style="bright_black")
    table.add_column("Platform", width=16)
    table.add_column("Status", justify="center", width=12)
    table.add_column("URL", style="dim")
    for r in sorted(ur.results, key=lambda x: (x.status != "found", x.status != "uncertain", x.platform)):
        status_map = {
            "found": "[bold green]Found[/bold green]",
            "not_found": "[red]Not Found[/red]",
            "uncertain": "[yellow]Uncertain[/yellow]",
        }
        table.add_row(r.platform, status_map[r.status], r.url)
    console.print(table)


if __name__ == "__main__":
    app()
