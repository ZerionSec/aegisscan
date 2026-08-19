# 🛡️ AegisScan

**Defensive Web Security Scanner**

A lightweight Python-based security assessment tool designed to identify common web security misconfigurations and provide actionable security recommendations.

Built for:
- Security learning
- Authorized assessments
- Defensive security research
- Local security labs
- Educational environments

> **Important:** This tool is intended **only** for educational use and authorized security assessments. Always obtain proper written permission before scanning any system you do not own.

---

## Overview

AegisScan performs a risk-based defensive assessment of web applications. It checks for common misconfigurations, missing security headers, weak TLS configurations, exposed sensitive files, insecure cookies, and more — then produces clear, actionable findings with remediation guidance.

---

## Features

| Category | Checks |
|----------|--------|
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Transport** | TLS version & cipher inspection, HTTP→HTTPS redirect |
| **Cookies** | Secure, HttpOnly, SameSite attributes |
| **CSP** | Detection of `unsafe-inline`, `unsafe-eval`, wildcards |
| **CORS** | Wildcard origin detection |
| **Exposure** | Common sensitive paths (`.env`, `.git`, backups, config files) |
| **Network** | Basic TCP port discovery for common & sensitive services |
| **Discovery** | Lightweight subdomain enumeration |
| **Fingerprinting** | Technology detection (CMS, servers, frameworks) |
| **Secrets** | Conservative pattern matching with automatic masking |
| **Reporting** | Text, JSON, and HTML reports with risk scoring |

---

## Architecture

```
AegisScan/
│
├── scanner.py              # Main scanner logic & CLI
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── docs/
│   ├── methodology.md
│   ├── installation.md
│   └── risk-scoring.md
│
├── tests/
│   └── test_scanner.py
│
├── reports/
│   └── .gitkeep
│
└── .github/
    └── workflows/
        └── python-tests.yml
```

---

## Installation

```bash
git clone https://github.com/ZerionSec/aegisscan.git
cd aegisscan
pip install -r requirements.txt
```

Requires **Python 3.8+**.

---

## Usage

### Basic scan (text output)

```bash
python scanner.py https://example.com
```

### Multiple targets

```bash
python scanner.py https://example.com https://test.example.com
```

### JSON report

```bash
python scanner.py https://example.com --json -o report.json
```

### HTML report

```bash
python scanner.py https://example.com --html -o report.html
```

### With proxy and custom rate limit

```bash
python scanner.py https://example.com --proxy http://127.0.0.1:8080 --rate-limit 0.5
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--json` | Output JSON report | — |
| `--html` | Output HTML report | — |
| `-o / --output` | Save report to file | stdout |
| `--proxy` | HTTP/HTTPS proxy | none |
| `--rate-limit` | Delay between requests (seconds) | 0.3 |
| `--timeout` | Request timeout (seconds) | 10 |

---

## Example Output

```
==============================================================================
  AegisScan v3.2
  Target: https://example.com
  Risk Score: 17/100
  Risk Level: LOW
  Timestamp: 2026-08-20T...
==============================================================================

[+] Finding Summary
    CRITICAL: 0
    HIGH: 0
    MEDIUM: 2
    LOW: 3
    INFO: 0

[+] Findings

  [MEDIUM] WS-HDR-001 - HSTS header missing
    Category: Security Headers
    Confidence: HIGH
    Score: +5
    Evidence: Strict-Transport-Security header is missing.
    Remediation: Configure HSTS after confirming the site is fully HTTPS-capable.
```

---

## Risk Scoring

AegisScan uses a simple additive scoring model (capped at 100):

| Severity | Points |
|----------|--------|
| CRITICAL | 20 |
| HIGH | 10 |
| MEDIUM | 5 |
| LOW | 1–2 |

**Risk Levels:**
- **CRITICAL** ≥ 70
- **HIGH** ≥ 50
- **MEDIUM** ≥ 25
- **LOW** < 25

This is a **project-specific indicator**, not a CVSS score.

See [docs/risk-scoring.md](docs/risk-scoring.md) for details.

---

## Security Checks

- Missing or weak security headers
- Insecure cookie attributes
- Weak or missing CSP directives
- Wildcard CORS policies
- Accessible sensitive files (`.env`, `.git/config`, backups, etc.)
- Exposed administrative/database ports
- Weak TLS protocols
- Missing HTTPS redirects
- Potential secrets in responses (masked in reports)
- Directory listing indicators
- Server banner disclosure

---

## Defensive Recommendations

Every finding includes a clear remediation suggestion. Typical recommendations include:

- Enforce HTTPS and HSTS
- Deploy a strict Content-Security-Policy
- Set Secure, HttpOnly, and SameSite on cookies
- Restrict CORS to trusted origins
- Remove sensitive files from the web root
- Limit exposure of administrative services
- Disable directory indexing
- Minimize server version disclosure

---

## Testing

```bash
pip install pytest
pytest tests/
```

---

## Limitations

- Not a full vulnerability scanner (no active exploitation)
- Subdomain discovery is limited to a small wordlist
- Port scanning is basic TCP connect
- Secret detection is conservative and pattern-based only
- Designed for authorized, low-impact assessments

---

## Legal & Authorized Testing Notice

**You must only use AegisScan against systems you own or have explicit written authorization to test.**

Unauthorized scanning may violate laws in your jurisdiction. The authors assume no liability for misuse.

This tool is provided for **defensive security education and authorized assessments only**.

---

## Roadmap

- [ ] Additional security header checks
- [ ] Configurable wordlists for paths and subdomains
- [ ] Export findings to SARIF
- [ ] Docker support
- [ ] Plugin architecture for custom checks

---

## Contributing

Contributions are welcome. Please open an issue or pull request. Keep the focus on **defensive** and **authorized** security assessment use cases.

---

## License

MIT License — see [LICENSE](LICENSE).

---

**AegisScan — Defensive Web Security Scanner**  
Lightweight Python toolkit for authorized web security assessment, misconfiguration detection, and risk analysis.
