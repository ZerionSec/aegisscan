# Assessment Methodology

AegisScan performs **non-intrusive, defensive** checks only.

## Scope of Checks

1. **Security Headers** – HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
2. **TLS Inspection** – Protocol version and basic cipher information
3. **Cookie Security** – Secure, HttpOnly, SameSite attributes
4. **CORS Configuration** – Detection of overly permissive policies
5. **Exposed Paths** – Common sensitive files and directories (passive checks)
6. **Port Discovery** – Limited common ports (informational)
7. **Subdomain Discovery** – Basic wordlist resolution
8. **Technology Fingerprinting** – Passive signature matching
9. **Secret Detection** – Conservative pattern matching with masking

## Design Principles

- Rate limiting and configurable timeouts to avoid aggressive behavior
- No exploitation or active attack payloads
- Findings include remediation guidance
- Reports in text, JSON, and HTML formats

## Limitations

- Not a replacement for full penetration testing or professional audits
- Port and subdomain discovery is lightweight and incomplete by design
- Secret detection is heuristic and may produce false positives/negatives
- Always obtain proper authorization before scanning any target
