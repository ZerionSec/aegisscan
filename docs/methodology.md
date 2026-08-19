# Methodology

AegisScan follows a defensive, non-intrusive assessment approach.

## Principles

1. **Authorized use only** — Targets must be owned by the operator or covered by written permission.
2. **Low impact** — Rate limiting is enabled by default; no destructive or exploit-style tests are performed.
3. **Evidence-based findings** — Every issue is supported by observable evidence from the target response.
4. **Actionable remediation** — Findings include concrete recommendations that help improve security posture.

## Assessment Flow

1. **Baseline request** — Fetch the target URL and capture headers, cookies, and body.
2. **Transport security** — Inspect TLS version and cipher suite (HTTPS targets).
3. **Header & policy analysis** — Evaluate security headers, CSP, and CORS.
4. **Cookie review** — Check Secure, HttpOnly, and SameSite attributes.
5. **Path probing** — Check a limited set of common sensitive paths (non-destructive GET requests).
6. **Network discovery** — Lightweight TCP connect scans on common ports.
7. **Subdomain enumeration** — DNS resolution against a small wordlist.
8. **Technology fingerprinting** — Passive signature matching.
9. **Secret pattern matching** — Conservative regex with automatic masking of matched values.
10. **Risk scoring** — Aggregate findings into a project-specific risk score and level.

## Design Choices

- No authentication bypass attempts
- No payload injection or fuzzing
- No brute-force of credentials
- Secrets are never fully displayed in reports
- Rate limiting protects both the scanner operator and the target
