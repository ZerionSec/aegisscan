#!/usr/bin/env python3
"""
AegisScan — Defensive Web Security Scanner v3.2
Risk-Based Defensive Web Assessment

Features:
- Security headers
- TLS inspection
- Cookie security
- CSP evaluation
- Basic CORS assessment
- Common exposed-path checks
- TCP port discovery
- Basic subdomain discovery
- Technology fingerprinting
- Potential secret detection with masking
- Risk-based findings
- Text / JSON / HTML reports
- Multi-target scanning
- Proxy support
- Configurable timeout and rate limit

For educational use and authorized security assessments only.
"""

import argparse
import concurrent.futures
import html
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


# ============================================================
# CONFIGURATION
# ============================================================

VERSION = "3.2"
SCANNER_NAME = "AegisScan"

DEFAULT_TIMEOUT = 10
DEFAULT_RATE_LIMIT = 0.3
USER_AGENT = f"AegisScan/{VERSION}"

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5432,
    5900, 6379, 8080
]

SENSITIVE_PORTS = {
    22: "SSH",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

SUBDOMAIN_LIST = [
    "www",
    "mail",
    "ftp",
    "admin",
    "dev",
    "api",
    "test",
    "staging",
    "blog",
    "docs",
    "support",
    "portal",
    "app",
    "secure",
    "vpn",
    "git",
    "jenkins",
    "grafana",
    "kibana",
    "elastic",
    "redis",
    "mysql",
]

COMMON_PATHS = [
    "/robots.txt",
    "/.git/config",
    "/.env",
    "/.env.backup",
    "/backup.zip",
    "/backup.tar.gz",
    "/wp-config.php",
    "/config.php",
    "/admin",
    "/phpinfo.php",
    "/server-status",
    "/.htaccess",
    "/.htpasswd",
    "/cgi-bin/",
    "/logs/",
    "/error_log",
    "/.aws/credentials",
    "/package.json",
    "/composer.json",
    "/.gitignore",
]

TECH_SIGNATURES = {
    "WordPress": [
        "/wp-content/",
        "/wp-includes/",
        "wp-json",
    ],
    "Drupal": [
        "/misc/drupal.js",
        "Drupal",
    ],
    "Joomla": [
        "/media/system/js/",
        "Joomla!",
    ],
    "Laravel": [
        "laravel_session",
    ],
    "Django": [
        "/static/admin/",
        "csrftoken",
    ],
    "Nginx": [
        "server: nginx",
    ],
    "Apache": [
        "server: apache",
    ],
    "Microsoft IIS": [
        "server: microsoft-iis",
    ],
    "Cloudflare": [
        "cf-ray",
        "cloudflare",
    ],
}

# These patterns are intentionally conservative.
SECRET_PATTERNS = {
    "aws_access_key": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"
    ),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    ),
    "credential_assignment": re.compile(
        r"""(?ix)
        \b
        (?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|
        bearer|secret|password|passwd)
        \b
        \s*[:=]\s*
        ["']?
        ([A-Za-z0-9_./+=\-]{16,})
        ["']?
        """
    ),
}

SENSITIVE_PATH_MARKERS = (
    ".env",
    ".git/config",
    ".git/",
    "aws/credentials",
    "wp-config",
    ".htpasswd",
    ".htaccess",
)

NON_CRITICAL_PATH_MARKERS = (
    "robots.txt",
    ".gitignore",
    "package.json",
    "composer.json",
)


# ============================================================
# SCANNER
# ============================================================

class WebSecurityScanner:

    def __init__(
        self,
        target_url: str,
        proxy: Optional[str] = None,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.target = target_url.rstrip("/")
        self.parsed = urlparse(self.target)

        self.hostname = self.parsed.hostname
        self.port = (
            self.parsed.port
            or (443 if self.parsed.scheme == "https" else 80)
        )

        self.proxy = proxy
        self.rate_limit = max(0.0, rate_limit)
        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": USER_AGENT
        })

        if proxy:
            self.session.proxies.update({
                "http": proxy,
                "https": proxy,
            })

        self.raw_html = ""
        self.resp_headers: Dict[str, str] = {}

        self.results: Dict[str, Any] = {
            "scanner": {
                "name": SCANNER_NAME,
                "version": VERSION,
            },
            "target": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),

            "headers": {},
            "tls": {},
            "cookies": [],
            "csp": {},
            "cors": {},
            "exposed_files": [],
            "open_ports": [],
            "subdomains": [],
            "technologies": [],
            "secrets_found": [],

            "findings": [],

            "risk_score": 0,
            "risk_level": "LOW",

            "score_details": {},
        }

    # ========================================================
    # REQUEST HELPER
    # ========================================================

    def _sleep_rate_limit(self):
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

    def _request(self, method: str, url: str, **kwargs):
        """
        Centralized HTTP request function so rate limiting
        is applied consistently.
        """
        self._sleep_rate_limit()

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)

        return self.session.request(
            method,
            url,
            **kwargs
        )

    # ========================================================
    # FINDINGS
    # ========================================================

    def add_finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        confidence: str,
        score: int,
        evidence: str,
        remediation: str,
        category: str,
    ):
        finding = {
            "id": finding_id,
            "title": title,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "score": score,
            "evidence": evidence,
            "remediation": remediation,
        }

        self.results["findings"].append(finding)

    # ========================================================
    # HEADERS / COOKIES / CSP / CORS
    # ========================================================

    def check_headers_and_cookies(self):
        try:
            response = self._request(
                "GET",
                self.target,
                allow_redirects=True,
            )

            self.resp_headers = dict(response.headers)
            self.raw_html = response.text

            headers = response.headers

            self.results["headers"]["status_code"] = response.status_code

            for header in SECURITY_HEADERS:
                value = headers.get(header)

                self.results["headers"][header] = (
                    value if value else "MISSING"
                )

            # ------------------------------------------------
            # Cookies
            # ------------------------------------------------

            for cookie in response.cookies:

                httponly = (
                    cookie.has_nonstandard_attr("HttpOnly")
                    or bool(cookie._rest.get("HttpOnly"))
                )

                samesite = cookie.get_nonstandard_attr(
                    "SameSite",
                    "Not Set"
                )

                cookie_info = {
                    "name": cookie.name,
                    "secure": bool(cookie.secure),
                    "httponly": bool(httponly),
                    "samesite": samesite,
                }

                self.results["cookies"].append(cookie_info)

            # ------------------------------------------------
            # CSP
            # ------------------------------------------------

            csp = headers.get(
                "Content-Security-Policy",
                ""
            )

            if csp:
                self.results["csp"] = self._evaluate_csp(csp)
            else:
                self.results["csp"] = {
                    "status": "MISSING",
                    "issues": [],
                    "severity": "MEDIUM",
                }

            # ------------------------------------------------
            # CORS
            # ------------------------------------------------

            acao = headers.get(
                "Access-Control-Allow-Origin",
                ""
            )

            credentials = headers.get(
                "Access-Control-Allow-Credentials",
                ""
            )

            if acao == "*":
                self.results["cors"] = {
                    "status": "POTENTIAL_ISSUE",
                    "value": "*",
                    "credentials": credentials,
                    "note": (
                        "Wildcard CORS detected. "
                        "Impact depends on the resources and "
                        "authentication model."
                    ),
                }

            elif acao:
                self.results["cors"] = {
                    "status": "PRESENT",
                    "value": acao,
                    "credentials": credentials,
                }

            else:
                self.results["cors"] = {
                    "status": "MISSING"
                }

        except requests.RequestException as exc:
            self.results["headers"]["error"] = str(exc)

    # ========================================================
    # CSP
    # ========================================================

    def _evaluate_csp(self, csp: str) -> Dict[str, Any]:

        issues = []

        normalized = csp.lower()

        if "'unsafe-inline'" in normalized:
            issues.append(
                "'unsafe-inline' is allowed."
            )

        if "'unsafe-eval'" in normalized:
            issues.append(
                "'unsafe-eval' is allowed."
            )

        if "default-src *" in normalized:
            issues.append(
                "default-src uses a wildcard."
            )

        if (
            "default-src" not in normalized
            and "script-src" not in normalized
        ):
            issues.append(
                "No default-src or script-src directive detected."
            )

        severity = "OK"

        if len(issues) >= 2:
            severity = "HIGH"
        elif issues:
            severity = "MEDIUM"

        return {
            "status": "PRESENT",
            "raw": csp[:300],
            "issues": issues,
            "severity": severity,
        }

    # ========================================================
    # TLS
    # ========================================================

    def check_tls(self):

        if self.parsed.scheme != "https":
            self.results["tls"] = {
                "status": "NOT_APPLICABLE",
                "note": "Target URL uses HTTP.",
            }
            return

        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (self.hostname, self.port),
                timeout=self.timeout,
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=self.hostname,
                ) as tls_socket:

                    self.results["tls"] = {
                        "status": "OK",
                        "version": tls_socket.version(),
                        "cipher": tls_socket.cipher(),
                        "secure_protocol": (
                            tls_socket.version()
                            in ("TLSv1.2", "TLSv1.3")
                        ),
                    }

        except Exception as exc:
            self.results["tls"] = {
                "status": "ERROR",
                "error": str(exc),
                "secure_protocol": False,
            }

    # ========================================================
    # PORT DISCOVERY
    # ========================================================

    def check_ports(self):

        if not self.hostname:
            return

        open_ports = []

        def scan_port(port: int):

            try:
                with socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                ) as sock:

                    sock.settimeout(1.5)

                    result = sock.connect_ex(
                        (self.hostname, port)
                    )

                    if result == 0:
                        return port

            except OSError:
                pass

            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=10
        ) as executor:

            futures = [
                executor.submit(
                    scan_port,
                    port
                )
                for port in COMMON_PORTS
            ]

            for future in concurrent.futures.as_completed(
                futures
            ):

                result = future.result()

                if result:
                    open_ports.append(result)

        self.results["open_ports"] = sorted(open_ports)

    # ========================================================
    # SUBDOMAINS
    # ========================================================

    def check_subdomains(self):

        if not self.hostname:
            return

        found = []

        def resolve(subdomain):

            hostname = (
                f"{subdomain}.{self.hostname}"
            )

            try:
                socket.gethostbyname(hostname)
                return hostname

            except socket.gaierror:
                return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=10
        ) as executor:

            futures = [
                executor.submit(
                    resolve,
                    subdomain
                )
                for subdomain in SUBDOMAIN_LIST
            ]

            for future in concurrent.futures.as_completed(
                futures
            ):

                result = future.result()

                if result:
                    found.append(result)

        self.results["subdomains"] = sorted(
            set(found)
        )

    # ========================================================
    # TECHNOLOGY FINGERPRINTING
    # ========================================================

    def check_technologies(self):

        detected = []

        headers_lower = {
            key.lower(): value.lower()
            for key, value in self.resp_headers.items()
        }

        html_lower = self.raw_html.lower()

        for technology, signatures in TECH_SIGNATURES.items():

            for signature in signatures:

                signature = signature.lower()

                if signature.startswith("server:"):

                    server = headers_lower.get(
                        "server",
                        ""
                    )

                    expected = (
                        signature
                        .replace("server:", "")
                        .strip()
                    )

                    if expected in server:
                        detected.append(
                            technology
                        )
                        break

                elif (
                    signature in html_lower
                    or signature in str(headers_lower)
                ):

                    detected.append(
                        technology
                    )
                    break

        # Meta generator
        generator = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+'
            r'content=["\']([^"\']+)',
            self.raw_html,
            re.IGNORECASE,
        )

        if generator:
            detected.append(
                f"Generator: {generator.group(1)}"
            )

        self.results["technologies"] = sorted(
            set(detected)
        )

    # ========================================================
    # SECRET DETECTION
    # ========================================================

    @staticmethod
    def _mask_secret(value: str) -> str:

        if len(value) <= 8:
            return "*" * len(value)

        return (
            value[:4]
            + "*" * (len(value) - 8)
            + value[-4:]
        )

    def check_secrets(self):

        findings = []

        for secret_type, pattern in SECRET_PATTERNS.items():

            for match in pattern.finditer(
                self.raw_html
            ):

                full_match = match.group(0)

                # For credential assignment, mask
                # the captured value rather than
                # exposing it.
                if match.groups():
                    secret_value = match.group(1)

                    masked = self._mask_secret(
                        secret_value
                    )

                    display = full_match.replace(
                        secret_value,
                        masked
                    )

                else:
                    display = self._mask_secret(
                        full_match
                    )

                findings.append({
                    "type": secret_type,
                    "evidence": display,
                })

        # Deduplicate
        unique = []
        seen = set()

        for item in findings:

            key = (
                item["type"],
                item["evidence"]
            )

            if key not in seen:
                seen.add(key)
                unique.append(item)

        self.results["secrets_found"] = unique[:10]

    # ========================================================
    # EXPOSED PATHS
    # ========================================================

    def check_exposed_files(self):

        found = []

        def check_path(path):

            try:
                response = self._request(
                    "GET",
                    self.target + path,
                    allow_redirects=False,
                )

                return {
                    "path": path,
                    "status": response.status_code,
                    "size": len(response.content),
                    "accessible": (
                        response.status_code == 200
                    ),
                }

            except requests.RequestException:

                return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=5
        ) as executor:

            futures = {
                executor.submit(
                    check_path,
                    path
                ): path
                for path in COMMON_PATHS
            }

            for future in concurrent.futures.as_completed(
                futures
            ):

                result = future.result()

                if result and result["status"] in (
                    200,
                    403,
                ):
                    found.append(result)

        self.results["exposed_files"] = sorted(
            found,
            key=lambda x: x["path"]
        )

    # ========================================================
    # MISCONFIGURATIONS
    # ========================================================

    def check_misconfigurations(self):

        # ----------------------------------------------------
        # Directory listing
        # ----------------------------------------------------

        try:
            response = self._request(
                "GET",
                self.target + "/",
                allow_redirects=True,
            )

            body_lower = response.text.lower()

            if (
                "index of /" in body_lower
                or "parent directory" in body_lower
            ):

                self.add_finding(
                    finding_id="WS-DIR-001",
                    title="Directory listing detected",
                    category="Information Exposure",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    score=5,
                    evidence=(
                        "Directory listing indicators "
                        "were detected in the response."
                    ),
                    remediation=(
                        "Disable directory indexing unless "
                        "it is explicitly required."
                    ),
                )

        except requests.RequestException:
            pass

        # ----------------------------------------------------
        # Server banner
        # ----------------------------------------------------

        server = self.resp_headers.get(
            "Server",
            ""
        )

        if server:

            self.add_finding(
                finding_id="WS-INF-001",
                title="Server banner exposed",
                category="Information Exposure",
                severity="LOW",
                confidence="HIGH",
                score=2,
                evidence=f"Server: {server}",
                remediation=(
                    "Minimize unnecessary server "
                    "version disclosure."
                ),
            )

        # ----------------------------------------------------
        # HTTPS
        # ----------------------------------------------------

        if self.parsed.scheme == "http":

            try:

                response = self._request(
                    "GET",
                    self.target,
                    allow_redirects=False,
                )

                location = response.headers.get(
                    "Location",
                    ""
                )

                if not (
                    response.status_code
                    in (301, 302, 307, 308)
                    and location.lower().startswith(
                        "https://"
                    )
                ):

                    self.add_finding(
                        finding_id="WS-TLS-001",
                        title="HTTP endpoint does not redirect to HTTPS",
                        category="Transport Security",
                        severity="HIGH",
                        confidence="HIGH",
                        score=10,
                        evidence=(
                            f"HTTP response status: "
                            f"{response.status_code}; "
                            f"Location: {location or 'none'}"
                        ),
                        remediation=(
                            "Redirect HTTP requests to HTTPS "
                            "and enforce secure transport."
                        ),
                    )

            except requests.RequestException:
                pass

        # ----------------------------------------------------
        # Security headers
        # ----------------------------------------------------

        self._evaluate_security_headers()

        # ----------------------------------------------------
        # Cookies
        # ----------------------------------------------------

        self._evaluate_cookies()

        # ----------------------------------------------------
        # CSP
        # ----------------------------------------------------

        self._evaluate_csp_finding()

        # ----------------------------------------------------
        # CORS
        # ----------------------------------------------------

        self._evaluate_cors_finding()

        # ----------------------------------------------------
        # Sensitive files
        # ----------------------------------------------------

        self._evaluate_exposed_files()

        # ----------------------------------------------------
        # Sensitive ports
        # ----------------------------------------------------

        self._evaluate_ports()

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        self._evaluate_tls()

    # ========================================================
    # SECURITY HEADERS
    # ========================================================

    def _evaluate_security_headers(self):

        headers = self.results["headers"]

        if headers.get(
            "Strict-Transport-Security"
        ) == "MISSING":

            # Only meaningful when HTTPS is being used.
            if self.parsed.scheme == "https":

                self.add_finding(
                    finding_id="WS-HDR-001",
                    title="HSTS header missing",
                    category="Security Headers",
                    severity="MEDIUM",
                    confidence="HIGH",
                    score=5,
                    evidence=(
                        "Strict-Transport-Security "
                        "header is missing."
                    ),
                    remediation=(
                        "Configure HSTS after confirming "
                        "the site is fully HTTPS-capable."
                    ),
                )

        if headers.get(
            "Content-Security-Policy"
        ) == "MISSING":

            self.add_finding(
                finding_id="WS-HDR-002",
                title="Content Security Policy missing",
                category="Security Headers",
                severity="MEDIUM",
                confidence="HIGH",
                score=5,
                evidence=(
                    "Content-Security-Policy header "
                    "was not present."
                ),
                remediation=(
                    "Deploy a restrictive CSP appropriate "
                    "to the application's resources."
                ),
            )

        if headers.get(
            "X-Frame-Options"
        ) == "MISSING":

            self.add_finding(
                finding_id="WS-HDR-003",
                title="Clickjacking protection header missing",
                category="Security Headers",
                severity="MEDIUM",
                confidence="HIGH",
                score=5,
                evidence=(
                    "X-Frame-Options was not present."
                ),
                remediation=(
                    "Use X-Frame-Options or an appropriate "
                    "CSP frame-ancestors policy."
                ),
            )

        if headers.get(
            "X-Content-Type-Options"
        ) == "MISSING":

            self.add_finding(
                finding_id="WS-HDR-004",
                title="MIME sniffing protection missing",
                category="Security Headers",
                severity="LOW",
                confidence="HIGH",
                score=2,
                evidence=(
                    "X-Content-Type-Options was not present."
                ),
                remediation=(
                    "Set X-Content-Type-Options: nosniff."
                ),
            )

        if headers.get(
            "Referrer-Policy"
        ) == "MISSING":

            self.add_finding(
                finding_id="WS-HDR-005",
                title="Referrer-Policy missing",
                category="Security Headers",
                severity="LOW",
                confidence="HIGH",
                score=2,
                evidence=(
                    "Referrer-Policy was not present."
                ),
                remediation=(
                    "Configure an appropriate Referrer-Policy "
                    "for the application."
                ),
            )

        if headers.get(
            "Permissions-Policy"
        ) == "MISSING":

            self.add_finding(
                finding_id="WS-HDR-006",
                title="Permissions-Policy missing",
                category="Security Headers",
                severity="LOW",
                confidence="MEDIUM",
                score=2,
                evidence=(
                    "Permissions-Policy was not present."
                ),
                remediation=(
                    "Restrict unnecessary browser features "
                    "through Permissions-Policy."
                ),
            )

    # ========================================================
    # COOKIE FINDINGS
    # ========================================================

    def _evaluate_cookies(self):

        for cookie in self.results["cookies"]:

            problems = []

            if not cookie["secure"]:
                problems.append("Secure")

            if not cookie["httponly"]:
                problems.append("HttpOnly")

            if str(cookie["samesite"]).lower() in (
                "",
                "not set",
                "none",
            ):
                problems.append("SameSite")

            if not problems:
                continue

            self.add_finding(
                finding_id="WS-COOKIE-001",
                title=f"Cookie security attributes incomplete: {cookie['name']}",
                category="Cookies",
                severity="MEDIUM",
                confidence="HIGH",
                score=5,
                evidence=(
                    f"Missing or weak attributes: "
                    f"{', '.join(problems)}"
                ),
                remediation=(
                    "Review Secure, HttpOnly, and SameSite "
                    "attributes according to the cookie's purpose."
                ),
            )

    # ========================================================
    # CSP FINDING
    # ========================================================

    def _evaluate_csp_finding(self):

        csp = self.results["csp"]

        if not csp:
            return

        if csp.get("status") == "MISSING":
            return

        issues = csp.get("issues", [])

        if not issues:
            return

        severity = csp.get(
            "severity",
            "MEDIUM"
        )

        score = 5

        if severity == "HIGH":
            score = 10

        self.add_finding(
            finding_id="WS-CSP-001",
            title="CSP contains potentially weak directives",
            category="Content Security Policy",
            severity=severity,
            confidence="MEDIUM",
            score=score,
            evidence="; ".join(issues),
            remediation=(
                "Review CSP directives and minimize "
                "unsafe-inline, unsafe-eval, and wildcard sources."
            ),
        )

    # ========================================================
    # CORS FINDING
    # ========================================================

    def _evaluate_cors_finding(self):

        cors = self.results["cors"]

        if cors.get("status") != "POTENTIAL_ISSUE":
            return

        self.add_finding(
            finding_id="WS-CORS-001",
            title="Wildcard CORS policy detected",
            category="CORS",
            severity="LOW",
            confidence="MEDIUM",
            score=2,
            evidence=(
                "Access-Control-Allow-Origin: *"
            ),
            remediation=(
                "Use an explicit trusted origin list "
                "when cross-origin access needs restriction. "
                "Verify the affected resources and authentication model."
            ),
        )

    # ========================================================
    # EXPOSED FILE FINDINGS
    # ========================================================

    def _evaluate_exposed_files(self):

        for item in self.results["exposed_files"]:

            path = item["path"]

            if item["status"] != 200:
                continue

            if any(
                marker in path
                for marker in SENSITIVE_PATH_MARKERS
            ):

                self.add_finding(
                    finding_id="WS-FILE-001",
                    title="Potentially sensitive file accessible",
                    category="Information Exposure",
                    severity="CRITICAL",
                    confidence="HIGH",
                    score=20,
                    evidence=(
                        f"{path} returned HTTP 200 "
                        f"({item['size']} bytes)."
                    ),
                    remediation=(
                        "Remove the file from the web root or "
                        "deny web access. Rotate exposed credentials "
                        "if sensitive material was accessible."
                    ),
                )

            elif any(
                marker in path
                for marker in NON_CRITICAL_PATH_MARKERS
            ):

                self.add_finding(
                    finding_id="WS-FILE-002",
                    title="Non-sensitive file accessible",
                    category="Information Exposure",
                    severity="LOW",
                    confidence="HIGH",
                    score=1,
                    evidence=(
                        f"{path} returned HTTP 200."
                    ),
                    remediation=(
                        "Confirm that the resource is intentionally "
                        "publicly accessible."
                    ),
                )

    # ========================================================
    # PORT FINDINGS
    # ========================================================

    def _evaluate_ports(self):

        for port in self.results["open_ports"]:

            if port not in SENSITIVE_PORTS:
                continue

            service = SENSITIVE_PORTS[port]

            self.add_finding(
                finding_id="WS-NET-001",
                title=f"Potentially sensitive service exposed: {service}",
                category="Network Exposure",
                severity="MEDIUM",
                confidence="HIGH",
                score=5,
                evidence=(
                    f"TCP port {port} ({service}) "
                    f"accepted a connection."
                ),
                remediation=(
                    "Restrict administrative/database services "
                    "to trusted networks or VPN access where appropriate."
                ),
            )

    # ========================================================
    # TLS FINDINGS
    # ========================================================

    def _evaluate_tls(self):

        tls = self.results["tls"]

        if tls.get("status") == "NOT_APPLICABLE":
            return

        if tls.get("status") == "ERROR":

            self.add_finding(
                finding_id="WS-TLS-002",
                title="TLS inspection failed",
                category="Transport Security",
                severity="MEDIUM",
                confidence="LOW",
                score=5,
                evidence=tls.get(
                    "error",
                    "Unknown TLS error"
                ),
                remediation=(
                    "Verify TLS configuration and certificate "
                    "compatibility."
                ),
            )

            return

        if not tls.get("secure_protocol", False):

            self.add_finding(
                finding_id="WS-TLS-001",
                title="Weak TLS protocol detected",
                category="Transport Security",
                severity="HIGH",
                confidence="HIGH",
                score=10,
                evidence=(
                    f"Negotiated protocol: "
                    f"{tls.get('version', 'unknown')}"
                ),
                remediation=(
                    "Disable obsolete TLS protocols and "
                    "support TLS 1.2 or TLS 1.3."
                ),
            )

    # ========================================================
    # RISK SCORE
    # ========================================================

    def calculate_risk_score(self):

        findings = self.results["findings"]

        score = sum(
            int(finding.get("score", 0))
            for finding in findings
        )

        score = min(score, 100)

        # Severity counts
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        score_details = {}

        for finding in findings:

            severity = finding["severity"]

            if severity in severity_counts:
                severity_counts[severity] += 1

            finding_id = finding["id"]

            score_details[finding_id] = {
                "title": finding["title"],
                "severity": severity,
                "score": finding["score"],
            }

        if score >= 70:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        self.results["risk_score"] = score

        self.results["risk_level"] = risk_level

        self.results["score_details"] = score_details

        self.results["severity_counts"] = severity_counts

    # ========================================================
    # SCAN
    # ========================================================

    def scan(self):

        print(
            f"[*] {SCANNER_NAME} v{VERSION}"
        )

        print(
            f"[*] Target: {self.target}"
        )

        print()

        self.check_headers_and_cookies()
        self.check_tls()
        self.check_ports()
        self.check_subdomains()
        self.check_technologies()
        self.check_secrets()
        self.check_exposed_files()
        self.check_misconfigurations()

        # ----------------------------------------------------
        # Secret finding
        # ----------------------------------------------------

        if self.results["secrets_found"]:

            evidence = ", ".join(
                item["type"]
                for item in self.results[
                    "secrets_found"
                ]
            )

            self.add_finding(
                finding_id="WS-SECRET-001",
                title="Potential secret detected in response",
                category="Secret Detection",
                severity="CRITICAL",
                confidence="MEDIUM",
                score=20,
                evidence=(
                    f"Potential secret types: {evidence}. "
                    "Values are masked in reports."
                ),
                remediation=(
                    "Remove secrets from client-accessible content, "
                    "rotate affected credentials, and use a secure "
                    "server-side secret-management mechanism."
                ),
            )

        self.calculate_risk_score()

        return self.results

    # ========================================================
    # TEXT REPORT
    # ========================================================

    def report_text(self) -> str:

        out = []

        out.append("=" * 78)
        out.append(
            f"  {SCANNER_NAME} v{VERSION}"
        )
        out.append(
            f"  Target: {self.target}"
        )
        out.append(
            f"  Risk Score: "
            f"{self.results['risk_score']}/100"
        )
        out.append(
            f"  Risk Level: "
            f"{self.results['risk_level']}"
        )
        out.append(
            f"  Timestamp: "
            f"{self.results['timestamp']}"
        )
        out.append("=" * 78)

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        counts = self.results.get(
            "severity_counts",
            {}
        )

        out.append("\n[+] Finding Summary")

        for severity in (
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ):
            out.append(
                f"    {severity}: "
                f"{counts.get(severity, 0)}"
            )

        # ----------------------------------------------------
        # Score breakdown
        # ----------------------------------------------------

        out.append("\n[+] Risk Score Breakdown")

        if self.results["findings"]:

            sorted_findings = sorted(
                self.results["findings"],
                key=lambda item: item["score"],
                reverse=True,
            )

            for finding in sorted_findings:

                out.append(
                    f"    {finding['id']}: "
                    f"+{finding['score']} "
                    f"[{finding['severity']}] "
                    f"{finding['title']}"
                )

        else:
            out.append(
                "    No findings contributed to the score."
            )

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        out.append("\n[+] Findings")

        if not self.results["findings"]:

            out.append(
                "    No findings detected."
            )

        else:

            for finding in self.results["findings"]:

                out.append("")
                out.append(
                    f"  [{finding['severity']}] "
                    f"{finding['id']} - "
                    f"{finding['title']}"
                )

                out.append(
                    f"    Category: "
                    f"{finding['category']}"
                )

                out.append(
                    f"    Confidence: "
                    f"{finding['confidence']}"
                )

                out.append(
                    f"    Score: "
                    f"+{finding['score']}"
                )

                out.append(
                    f"    Evidence: "
                    f"{finding['evidence']}"
                )

                out.append(
                    f"    Remediation: "
                    f"{finding['remediation']}"
                )

        # ----------------------------------------------------
        # Headers
        # ----------------------------------------------------

        out.append("\n[+] Security Headers")

        for key, value in self.results[
            "headers"
        ].items():

            out.append(
                f"    {key}: {value}"
            )

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        out.append("\n[+] TLS")

        for key, value in self.results[
            "tls"
        ].items():

            out.append(
                f"    {key}: {value}"
            )

        # ----------------------------------------------------
        # Cookies
        # ----------------------------------------------------

        out.append("\n[+] Cookies")

        if self.results["cookies"]:

            for cookie in self.results[
                "cookies"
            ]:

                out.append(
                    f"    {cookie['name']}: "
                    f"Secure={cookie['secure']}, "
                    f"HttpOnly={cookie['httponly']}, "
                    f"SameSite={cookie['samesite']}"
                )

        else:

            out.append(
                "    No response cookies detected."
            )

        # ----------------------------------------------------
        # CORS
        # ----------------------------------------------------

        out.append("\n[+] CORS")

        out.append(
            f"    {self.results['cors']}"
        )

        # ----------------------------------------------------
        # Subdomains
        # ----------------------------------------------------

        out.append("\n[+] Discovered Subdomains")

        if self.results["subdomains"]:

            for subdomain in self.results[
                "subdomains"
            ]:

                out.append(
                    f"    {subdomain}"
                )

        else:

            out.append(
                "    None discovered."
            )

        # ----------------------------------------------------
        # Technologies
        # ----------------------------------------------------

        out.append("\n[+] Technologies")

        out.append(
            "    "
            + (
                ", ".join(
                    self.results["technologies"]
                )
                if self.results["technologies"]
                else "None detected."
            )
        )

        # ----------------------------------------------------
        # Ports
        # ----------------------------------------------------

        out.append("\n[+] Open Ports")

        out.append(
            "    "
            + (
                ", ".join(
                    map(
                        str,
                        self.results["open_ports"]
                    )
                )
                if self.results["open_ports"]
                else "None detected."
            )
        )

        # ----------------------------------------------------
        # Exposed paths
        # ----------------------------------------------------

        out.append("\n[+] Checked Paths")

        for item in self.results[
            "exposed_files"
        ]:

            state = (
                "ACCESSIBLE"
                if item["accessible"]
                else "PROTECTED/BLOCKED"
            )

            out.append(
                f"    {item['path']} -> "
                f"{item['status']} "
                f"({state})"
            )

        # ----------------------------------------------------
        # Secrets
        # ----------------------------------------------------

        out.append("\n[+] Potential Secrets")

        if self.results["secrets_found"]:

            for secret in self.results[
                "secrets_found"
            ]:

                out.append(
                    f"    {secret['type']}: "
                    f"{secret['evidence']}"
                )

        else:

            out.append(
                "    None detected."
            )

        out.append("\n" + "=" * 78)
        out.append(
            "[+] Scan complete."
        )
        out.append("=" * 78)

        return "\n".join(out)

    # ========================================================
    # JSON
    # ========================================================

    def report_json(self) -> str:

        return json.dumps(
            self.results,
            indent=2,
            ensure_ascii=False,
        )


# ============================================================
# HTML REPORT
# ============================================================

def complete_html_report(
    scanner: WebSecurityScanner
) -> str:

    def esc(value):
        return html.escape(str(value))

    score = scanner.results["risk_score"]

    if score >= 70:
        score_class = "critical"
    elif score >= 50:
        score_class = "high"
    elif score >= 25:
        score_class = "medium"
    else:
        score_class = "low"

    findings = scanner.results["findings"]

    finding_rows = ""

    for finding in sorted(
        findings,
        key=lambda x: x["score"],
        reverse=True,
    ):

        finding_rows += f"""
        <tr>
            <td>{esc(finding["id"])}</td>
            <td>{esc(finding["title"])}</td>
            <td>{esc(finding["severity"])}</td>
            <td>{esc(finding["confidence"])}</td>
            <td>+{esc(finding["score"])}</td>
            <td>{esc(finding["evidence"])}</td>
            <td>{esc(finding["remediation"])}</td>
        </tr>
        """

    if not finding_rows:

        finding_rows = """
        <tr>
            <td colspan="7">
                No findings detected.
            </td>
        </tr>
        """

    header_rows = ""

    for key, value in scanner.results[
        "headers"
    ].items():

        header_rows += f"""
        <tr>
            <td>{esc(key)}</td>
            <td>{esc(value)}</td>
        </tr>
        """

    cookie_rows = ""

    for cookie in scanner.results[
        "cookies"
    ]:

        cookie_rows += f"""
        <tr>
            <td>{esc(cookie["name"])}</td>
            <td>{'YES' if cookie["secure"] else 'NO'}</td>
            <td>{'YES' if cookie["httponly"] else 'NO'}</td>
            <td>{esc(cookie["samesite"])}</td>
        </tr>
        """

    file_rows = ""

    for item in scanner.results[
        "exposed_files"
    ]:

        state = (
            "Accessible"
            if item["accessible"]
            else "Protected/Blocked"
        )

        file_rows += f"""
        <tr>
            <td>{esc(item["path"])}</td>
            <td>{item["status"]}</td>
            <td>{item["size"]}</td>
            <td>{state}</td>
        </tr>
        """

    if not file_rows:
        file_rows = """
        <tr>
            <td colspan="4">
                No relevant paths returned 200/403.
            </td>
        </tr>
        """

    subdomains = "<br>".join(
        esc(x)
        for x in scanner.results[
            "subdomains"
        ]
    ) or "None"

    technologies = ", ".join(
        esc(x)
        for x in scanner.results[
            "technologies"
        ]
    ) or "None"

    ports = ", ".join(
        map(
            str,
            scanner.results[
                "open_ports"
            ],
        )
    ) or "None"

    return f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>AegisScan Security Assessment</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #f3f4f6;
    margin: 0;
    padding: 30px;
    color: #1f2937;
}}

.container {{
    max-width: 1200px;
    margin: auto;
    background: white;
    padding: 30px;
    border-radius: 12px;
}}

h1 {{
    margin-top: 0;
}}

h2 {{
    margin-top: 35px;
}}

.score {{
    display: inline-block;
    padding: 15px 25px;
    border-radius: 10px;
    color: white;
    font-size: 30px;
    font-weight: bold;
}}

.low {{
    background: #16a34a;
}}

.medium {{
    background: #d97706;
}}

.high {{
    background: #dc2626;
}}

.critical {{
    background: #7f1d1d;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}}

th {{
    background: #111827;
    color: white;
    padding: 10px;
    text-align: left;
}}

td {{
    border: 1px solid #d1d5db;
    padding: 9px;
    vertical-align: top;
}}

tr:nth-child(even) {{
    background: #f9fafb;
}}

.note {{
    background: #f3f4f6;
    padding: 12px;
    border-radius: 8px;
    margin-top: 15px;
}}

</style>

</head>

<body>

<div class="container">

<h1>🛡️ AegisScan Security Assessment Report</h1>

<p>
<strong>Scanner:</strong>
{esc(SCANNER_NAME)} v{esc(VERSION)}
<br>

<strong>Target:</strong>
{esc(scanner.target)}
<br>

<strong>Timestamp:</strong>
{esc(scanner.results["timestamp"])}
</p>

<h2>📊 Risk Score</h2>

<div class="score {score_class}">
{score}/100
</div>

<p>
<strong>Risk Level:</strong>
{esc(scanner.results["risk_level"])}
</p>

<div class="note">
This is a project-specific risk indicator and is
not a CVSS score.
</div>

<h2>⚠️ Findings</h2>

<table>

<tr>
<th>ID</th>
<th>Finding</th>
<th>Severity</th>
<th>Confidence</th>
<th>Score</th>
<th>Evidence</th>
<th>Remediation</th>
</tr>

{finding_rows}

</table>

<h2>📋 Security Headers</h2>

<table>

<tr>
<th>Header</th>
<th>Value</th>
</tr>

{header_rows}

</table>

<h2>🍪 Cookies</h2>

<table>

<tr>
<th>Name</th>
<th>Secure</th>
<th>HttpOnly</th>
<th>SameSite</th>
</tr>

{cookie_rows or '<tr><td colspan="4">None detected.</td></tr>'}

</table>

<h2>🔒 TLS</h2>

<table>

<tr>
<th>Property</th>
<th>Value</th>
</tr>

{
''.join(
    f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
    for k, v in scanner.results["tls"].items()
)
}

</table>

<h2>🌐 CORS</h2>

<p>
{esc(scanner.results["cors"])}
</p>

<h2>🌍 Open Ports</h2>

<p>
{ports}
</p>

<h2>🏷️ Subdomains</h2>

<p>
{subdomains}
</p>

<h2>🧠 Technologies</h2>

<p>
{technologies}
</p>

<h2>📂 Checked Paths</h2>

<table>

<tr>
<th>Path</th>
<th>Status</th>
<th>Size</th>
<th>Classification</th>
</tr>

{file_rows}

</table>

<h2>🔑 Potential Secrets</h2>

{
''.join(
    f"<p><strong>{esc(x['type'])}:</strong> "
    f"{esc(x['evidence'])}</p>"
    for x in scanner.results["secrets_found"]
)
or "<p>None detected.</p>"
}

<p style="margin-top:40px;color:#6b7280;">
Generated by {esc(SCANNER_NAME)} v{esc(VERSION)}
</p>

</div>

</body>

</html>
"""


# ============================================================
# MULTI-TARGET
# ============================================================

def scan_multiple(
    targets: List[str],
    proxy: Optional[str],
    rate_limit: float,
    output_format: str,
    output_file: Optional[str],
    timeout: int,
):

    reports = []
    json_reports = []

    for target in targets:

        scanner = WebSecurityScanner(
            target_url=target,
            proxy=proxy,
            rate_limit=rate_limit,
            timeout=timeout,
        )

        try:

            scanner.scan()

            if output_format == "json":

                json_reports.append(
                    scanner.results
                )

            elif output_format == "html":

                reports.append(
                    complete_html_report(
                        scanner
                    )
                )

            else:

                print(
                    scanner.report_text()
                )

                print(
                    "\n" + "-" * 78 + "\n"
                )

        except KeyboardInterrupt:

            print(
                "\n[!] Scan interrupted."
            )
            return

        except Exception as exc:

            print(
                f"[!] Error scanning "
                f"{target}: {exc}"
            )

    if output_format == "text":

        if output_file:
            print(
                "[!] Text mode prints to console. "
                "Use --json or --html for file output."
            )

        return

    if output_format == "json":

        final_output = json.dumps(
            json_reports,
            indent=2,
            ensure_ascii=False,
        )

    else:

        if len(reports) == 1:

            final_output = reports[0]

        else:

            body = ""

            for index, report in enumerate(
                reports,
                start=1,
            ):

                body += (
                    f"<hr>"
                    f"<h1>Target {index}</h1>"
                    f"{report}"
                )

            final_output = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Multi-Target Security Assessment</title>
</head>
<body>
{body}
</body>
</html>
"""

    if output_file:

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            file.write(
                final_output
            )

        print(
            f"[✓] Report saved to "
            f"{output_file}"
        )

    else:

        print(
            final_output
        )


# ============================================================
# CLI
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            f"{SCANNER_NAME} v{VERSION} "
            "- Risk-Based Defensive Assessment"
        )
    )

    parser.add_argument(
        "targets",
        nargs="+",
        help="Authorized target URL(s)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Generate JSON report",
    )

    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML report",
    )

    parser.add_argument(
        "--proxy",
        help=(
            "HTTP proxy, e.g. "
            "http://127.0.0.1:8080"
        ),
    )

    parser.add_argument(
        "--rate-limit",
        type=float,
        default=DEFAULT_RATE_LIMIT,
        help=(
            "Delay between HTTP requests "
            f"(default: {DEFAULT_RATE_LIMIT}s)"
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=(
            f"Request timeout in seconds "
            f"(default: {DEFAULT_TIMEOUT})"
        ),
    )

    parser.add_argument(
        "--output",
        "-o",
        help=(
            "Output report filename"
        ),
    )

    args = parser.parse_args()

    if args.json and args.html:

        parser.error(
            "Use either --json or --html, "
            "not both."
        )

    output_format = "text"

    if args.json:
        output_format = "json"

    elif args.html:
        output_format = "html"

    scan_multiple(
        targets=args.targets,
        proxy=args.proxy,
        rate_limit=args.rate_limit,
        output_format=output_format,
        output_file=args.output,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
