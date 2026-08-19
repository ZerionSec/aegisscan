# 🛡️ AegisScan

**Defensive Web Security Scanner**

A lightweight Python-based security assessment tool designed to identify common web security misconfigurations and provide actionable security recommendations.

Built for:
- Security learning
- Authorized assessments
- Defensive security research
- Local security labs
- Educational environments

> **Important:** Use only on systems you own or have explicit written permission to test.

---

## Overview

AegisScan performs non-intrusive checks focused on defensive security posture:

- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- TLS protocol inspection
- Cookie security attributes
- CORS configuration review
- Common exposed-path detection
- Basic port & subdomain discovery
- Technology fingerprinting
- Conservative secret detection (with masking)
- Risk-based findings with remediation guidance
- Text / JSON / HTML reports

---

## Features

| Category              | Checks                                      |
|-----------------------|---------------------------------------------|
| Security Headers      | HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy |
| Transport Security    | TLS version, HTTPS redirect                 |
| Cookies               | Secure, HttpOnly, SameSite                  |
| CORS                  | Wildcard / overly permissive policies       |
| Information Exposure  | Sensitive paths, directory listing, banners |
| Network               | Common ports, basic subdomains              |
| Fingerprinting        | Technology signatures                       |
| Secrets               | Pattern-based detection with masking        |
| Reporting             | Text, JSON, HTML + risk score               |

---

## Architecture

```
AegisScan/
├── scanner.py              # Main scanner & CLI
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── methodology.md
│   ├── installation.md
│   └── risk-scoring.md
├── tests/
│   └── test_scanner.py
├── reports/                # Output directory
└── .github/workflows/
    └── python-tests.yml
```

---

## Installation

```bash
git clone https://github.com/ZerionSec/aegisscan.git
cd aegisscan
pip install -r requirements.txt
```

See [docs/installation.md](docs/installation.md) for more details.

---

## Usage

### Basic scan (text report)

```bash
python scanner.py https://example.com
```

### Multiple targets

```bash
python scanner.py https://target1.com https://target2.com
```

### JSON report

```bash
python scanner.py https://example.com --json -o report.json
```

### HTML report

```bash
python scanner.py https://example.com --html -o report.html
```

### Options

```
--proxy http://127.0.0.1:8080   # Route through proxy
--rate-limit 0.5                # Delay between requests (seconds)
--timeout 15                    # Request timeout
-o / --output FILE              # Save report to file
```

---

## Example Output (summary)

```
[*] Web Security Scanner v3.2
[*] Target: https://example.com

==============================================================
  Risk Score: 12/100
  Risk Level: LOW
==============================================================

[+] Finding Summary
    CRITICAL: 0
    HIGH: 0
    MEDIUM: 2
    LOW: 1
```

---

## Risk Scoring

AegisScan produces a **project-specific risk indicator** (0–100).  
It is **not** a CVSS score.

Details: [docs/risk-scoring.md](docs/risk-scoring.md)

---

## Security Checks & Defensive Recommendations

Every finding includes:

- Severity & confidence
- Evidence
- Concrete remediation guidance

The goal is to help defenders improve configuration, not to enable attacks.

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

---

## Limitations

- Lightweight / educational tool — not a full commercial scanner
- Port & subdomain discovery is intentionally limited
- Secret detection is heuristic
- Always validate findings manually

See [docs/methodology.md](docs/methodology.md)

---

## Legal & Authorized Testing Notice

**Use AegisScan only on systems you own or have explicit authorization to assess.**

Unauthorized scanning may violate laws and terms of service.  
The authors assume no liability for misuse.

---

## Roadmap

- [ ] Improved CSP analysis
- [ ] Additional passive checks
- [ ] Better HTML report styling
- [ ] Configuration file support
- [ ] Docker image

---

## Contributing

Pull requests and issues are welcome. Please keep the project focused on **defensive** and **authorized** use cases.

---

## License

MIT License — see [LICENSE](LICENSE)

---

**AegisScan — Defensive Web Security Scanner**  
Lightweight Python toolkit for authorized web security assessment, misconfiguration detection, and risk analysis.
