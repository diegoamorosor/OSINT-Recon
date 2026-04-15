<p align="center">
  <img src="https://i.imgur.com/gTrTqof.png" alt="CyberGuard-Password-Analyzer" />
</p>

<h1 align="center">OSINT Recon 🔍</h1>

![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)

**OSINT Recon** is a cross-platform CLI-based open-source intelligence reconnaissance tool that automates the process of gathering information about domains, emails, and usernames. It runs on both **Linux** and **Windows**, combining multiple OSINT techniques into a single command-line interface with automatic risk scoring and rich terminal output.

---

## 🤔 How Does It Work?

OSINT Recon performs passive reconnaissance by querying public data sources and APIs to collect intelligence about a given target. It supports three main target types and automatically detects which recon modules to apply.

The general process is as follows:

1. **Provide a target** (domain, email, or username).
2. **The tool runs the appropriate recon modules**:
    - If it's a domain, it queries subdomains, DNS, WHOIS, and security headers.
    - If it's an email, it validates format, checks MX records, and looks up breaches.
    - If it's a username, it checks presence across ~20 platforms.
3. **A risk score is calculated** based on exposure, security posture, and digital footprint.
4. **Results are displayed** in a rich terminal format and optionally saved as a Markdown report.

> ### Visual Example
> 
> _Run a full reconnaissance scan on a domain with a single command._

```bash
uv run osint-recon domain example.com
```

---

## 🚀 Advantages

- **Comprehensive**: Covers domains, emails, and usernames in a single tool.
- **Automated Risk Scoring**: Deterministic heuristic scoring gives you an instant security assessment.
- **Smart Caching**: SQLite-based TTL cache avoids redundant API calls.
- **Google Dorks**: Auto-generates targeted search queries for deeper investigation.
- **Beautiful Output**: Rich terminal tables, spinners, and colored display.

## ⚠️ Disadvantages

- **Passive Only**: Does not perform active scanning or intrusive testing.
- **API Dependence**: Some features (like HIBP breach lookup) require API keys for full functionality.

---

## 📊 Commands Overview

|Command|Description|Example|
|---|---|---|
|`domain <target>`|Subdomains, DNS, WHOIS, security headers|`osint-recon domain example.com`|
|`email <target>`|Format, MX, HIBP breaches, Gravatar|`osint-recon email user@example.com`|
|`username <target>`|Presence across ~20 platforms|`osint-recon username johndoe`|
|`full <target>`|Auto-detect & run all applicable checks|`osint-recon full example.com`|

---

## 🧩 Recon Modules

- **Domain Recon**: Subdomain enumeration via crt.sh, DNS record lookup, WHOIS data, and security header analysis.
- **Email Recon**: Format validation, MX record verification, Have I Been Pwned breach lookup, and Gravatar detection.
- **Username Recon**: Presence checking across ~20 platforms including GitHub, GitLab, Reddit, X, Instagram, and more.
- **Google Dorks**: Automatically generated search queries tailored to each target type for deeper OSINT research.

---

## 🛠️ Installation

```bash
# Clone and install
git clone <repo-url>
cd osint-recon
uv sync

# Optional: configure HIBP API key
cp .env.example .env
# Edit .env and add your HIBP_API_KEY
```

### Global Options

|Option|Description|
|---|---|
|`--no-cache`|Disable SQLite result caching|
|`-o, --output`|Save markdown report to file|
|`--version`|Show version|

### Environment Variables

|Variable|Required|Description|
|---|---|---|
|`HIBP_API_KEY`|No|Have I Been Pwned API key for breach lookups|

---

## 📝 Additional Notes

- OSINT Recon is designed for **ethical and authorized use only**. Always ensure you have proper authorization before performing reconnaissance on any target.
- The tool uses **passive techniques only** — it does not perform any active scanning, port scanning, or intrusive testing.
- **Fun Fact** 🤓 OSINT stands for Open-Source Intelligence, a discipline originating from military intelligence that now powers modern cybersecurity, journalism, and investigations.

---

## 🧪 Development

```bash
# Run tests
uv run pytest tests/ -v --asyncio-mode=auto

# Lint
uv run ruff check src/

# Format
uv run ruff format src/
```

### Tech Stack

- Python 3.12+
- click (CLI framework)
- httpx (async HTTP)
- rich (terminal formatting)
- pydantic v2 (data models)
- tldextract + python-whois + dnspython (OSINT queries)
- pytest + pytest-asyncio + respx (testing)

---

> ## 🎉 That's All!
> 
> I hope this tool helps you perform efficient and ethical OSINT reconnaissance!
