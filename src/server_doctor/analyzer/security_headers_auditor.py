"""Security Headers Auditor - Checks HTTP response headers from probe data."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class SecurityHeadersAuditor:
    """Auditor for HTTP security response headers in probe results."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.model.http_probes or not self.model.http_probes.results:
            return findings

        findings.extend(self._check_csp())
        findings.extend(self._check_hsts())
        findings.extend(self._check_x_frame_options())
        findings.extend(self._check_x_content_type_options())
        findings.extend(self._check_x_xss_protection())
        findings.extend(self._check_referrer_policy())
        findings.extend(self._check_permissions_policy())
        findings.extend(self._check_cache_control())
        return findings

    def _probe_results(self):
        return self.model.http_probes.results

    def _check_csp(self) -> list[Finding]:
        missing: list[str] = []
        weak: list[str] = []
        for r in self._probe_results():
            val = (r.headers.get("content-security-policy") or r.headers.get("Content-Security-Policy") or "").strip()
            if not val:
                missing.append(r.url)
            elif "unsafe-inline" in val or "unsafe-eval" in val or val == "*":
                weak.append(r.url)

        findings: list[Finding] = []
        if missing:
            findings.append(self._make_header_finding(
                "HDR-001", Severity.WARNING,
                "Content-Security-Policy header is missing",
                f"CSP header not found on {len(missing)} probe(s): {', '.join(missing[:5])}",
                missing,
                "Add a Content-Security-Policy header to mitigate XSS and data injection.",
                ["Increased risk of XSS and data injection attacks"],
            ))
        if weak:
            findings.append(self._make_header_finding(
                "HDR-002", Severity.INFO,
                "Content-Security-Policy uses permissive directives",
                f"CSP allows unsafe-inline/unsafe-eval on {len(weak)} probe(s): {', '.join(weak[:5])}",
                weak,
                "Restrict CSP by removing unsafe-inline and unsafe-eval where possible.",
                ["Weakened XSS protection"],
            ))
        return findings

    def _check_hsts(self) -> list[Finding]:
        missing: list[str] = []
        short_max_age: list[str] = []
        for r in self._probe_results():
            if not r.url.startswith("https://"):
                continue
            val = (r.headers.get("strict-transport-security") or r.headers.get("Strict-Transport-Security") or "").strip()
            if not val:
                missing.append(r.url)
            else:
                m = __import__("re").search(r"max-age=(\d+)", val)
                if m and int(m.group(1)) < 10886400:
                    short_max_age.append(r.url)

        findings: list[Finding] = []
        if missing:
            findings.append(self._make_header_finding(
                "HDR-003", Severity.WARNING,
                "Strict-Transport-Security header is missing on HTTPS",
                f"HSTS not found on {len(missing)} HTTPS probe(s): {', '.join(missing[:5])}",
                missing,
                "Add Strict-Transport-Security with a max-age of at least 1 year (31536000).",
                ["Users vulnerable to SSL-stripping attacks"],
            ))
        if short_max_age:
            findings.append(self._make_header_finding(
                "HDR-004", Severity.INFO,
                "HSTS max-age is too short",
                f"HSTS max-age < 10886400 on {len(short_max_age)} probe(s): {', '.join(short_max_age[:5])}",
                short_max_age,
                "Increase HSTS max-age to at least 31536000 (1 year).",
                ["Weakened HTTPS enforcement"],
            ))
        return findings

    def _check_x_frame_options(self) -> list[Finding]:
        missing: list[str] = []
        for r in self._probe_results():
            val = (r.headers.get("x-frame-options") or r.headers.get("X-Frame-Options") or "").strip()
            if not val:
                missing.append(r.url)

        if missing:
            return [self._make_header_finding(
                "HDR-005", Severity.INFO,
                "X-Frame-Options header is missing",
                f"X-Frame-Options not found on {len(missing)} probe(s): {', '.join(missing[:5])}",
                missing,
                "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
                ["Site may be embedded in iframes (clickjacking risk)"],
            )]
        return []

    def _check_x_content_type_options(self) -> list[Finding]:
        missing: list[str] = []
        for r in self._probe_results():
            val = (r.headers.get("x-content-type-options") or r.headers.get("X-Content-Type-Options") or "").strip()
            if not val:
                missing.append(r.url)

        if missing:
            return [self._make_header_finding(
                "HDR-006", Severity.INFO,
                "X-Content-Type-Options header is missing",
                f"X-Content-Type-Options not found on {len(missing)} probe(s): {', '.join(missing[:5])}",
                missing,
                "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
                ["Browser MIME-sniffing may lead to XSS vectors"],
            )]
        return []

    def _check_x_xss_protection(self) -> list[Finding]:
        missing: list[str] = []
        for r in self._probe_results():
            val = (r.headers.get("x-xss-protection") or r.headers.get("X-XSS-Protection") or "").strip()
            if not val:
                missing.append(r.url)

        if missing:
            return [self._make_header_finding(
                "HDR-007", Severity.INFO,
                "X-XSS-Protection header is missing",
                f"X-XSS-Protection not found on {len(missing)} probe(s): {', '.join(missing[:5])}",
                missing,
                "Add X-XSS-Protection: 1; mode=block (or rely on CSP for modern browsers).",
                ["Legacy browser XSS protection reduced"],
            )]
        return []

    def _check_referrer_policy(self) -> list[Finding]:
        missing: list[str] = []
        for r in self._probe_results():
            val = (r.headers.get("referrer-policy") or r.headers.get("Referrer-Policy") or "").strip()
            if not val:
                missing.append(r.url)

        if missing:
            return [self._make_header_finding(
                "HDR-008", Severity.INFO,
                "Referrer-Policy header is missing",
                f"Referrer-Policy not found on {len(missing)} probe(s): {', '.join(missing[:5])}",
                missing,
                "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer leakage.",
                ["Referrer URL may leak sensitive path information"],
            )]
        return []

    def _check_cache_control(self) -> list[Finding]:
        sensitive_paths = {"/.env", "/.git/config", "/composer.json", "/package.json", "/vendor", "/storage/logs"}
        no_cache: list[str] = []
        for r in self._probe_results():
            path = __import__("urllib.parse").urlparse(r.url).path.rstrip("/") or "/"
            if path not in sensitive_paths:
                continue
            val = (r.headers.get("cache-control") or r.headers.get("Cache-Control") or "").strip()
            if val and "no-store" not in val.lower():
                no_cache.append(r.url)

        if no_cache:
            return [self._make_header_finding(
                "HDR-009", Severity.WARNING,
                "Sensitive responses lack no-store cache directive",
                f"Cache-Control missing no-store on {len(no_cache)} sensitive path(s): {', '.join(no_cache[:5])}",
                no_cache,
                "Add Cache-Control: no-store for responses containing sensitive data.",
                ["Sensitive data may be cached in browser or proxy caches"],
            )]
        return []

    @staticmethod
    def _make_header_finding(
        rule_id: str, severity: Severity, condition: str, cause: str,
        urls: list[str], treatment: str, impact: list[str],
    ) -> Finding:
        return Finding(
            id=rule_id,
            severity=severity,
            confidence=0.85,
            condition=condition,
            cause=cause,
            evidence=[
                Evidence(
                    source_file="http probe",
                    line_number=0,
                    excerpt=urls[0] if len(urls) == 1 else f"{len(urls)} affected URLs: {', '.join(urls[:10])}",
                    command="curl -I -L " + (urls[0] if urls else ""),
                )
            ],
            treatment=treatment,
            impact=impact,
        )
