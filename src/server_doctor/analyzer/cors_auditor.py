"""CORS Auditor - Checks CORS misconfigurations from existing probe data."""

from urllib.parse import urlparse

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class CorsAuditor:
    """Auditor for CORS misconfiguration signals in HTTP probe results."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.model.http_probes or not self.model.http_probes.results:
            return findings

        findings.extend(self._check_wildcard_origin_with_credentials())
        findings.extend(self._check_permissive_origin())
        findings.extend(self._check_origin_reflection())
        return findings

    def _probe_results(self):
        return self.model.http_probes.results

    def _check_wildcard_origin_with_credentials(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self._probe_results():
            acao = (r.headers.get("access-control-allow-origin") or r.headers.get("Access-Control-Allow-Origin") or "").strip()
            acac = (r.headers.get("access-control-allow-credentials") or r.headers.get("Access-Control-Allow-Credentials") or "").strip()
            if acao == "*" and acac.lower() == "true":
                findings.append(Finding(
                    id="CORS-001",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    condition="Wildcard CORS origin with credentials enabled",
                    cause=f"{r.url} allows Access-Control-Allow-Origin: * with Allow-Credentials: true",
                    evidence=[Evidence(
                        source_file="http probe",
                        line_number=0,
                        excerpt=f"{r.url} => ACAO=* ACAC=true",
                        command=f"curl -I -L {r.url}",
                    )],
                    treatment=(
                        "Remove wildcard origin or disable Allow-Credentials. "
                        "Use explicit origin whitelist when credentials are needed."
                    ),
                    impact=[
                        "Any origin can make authenticated cross-origin requests",
                        "Credentials can be exfiltrated by arbitrary websites",
                    ],
                ))
        return findings

    def _check_permissive_origin(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self._probe_results():
            acao = (r.headers.get("access-control-allow-origin") or r.headers.get("Access-Control-Allow-Origin") or "").strip()
            if acao == "*":
                findings.append(Finding(
                    id="CORS-002",
                    severity=Severity.WARNING,
                    confidence=0.90,
                    condition="Wildcard CORS origin configured",
                    cause=f"{r.url} allows any origin via Access-Control-Allow-Origin: *",
                    evidence=[Evidence(
                        source_file="http probe",
                        line_number=0,
                        excerpt=f"{r.url} => ACAO=*",
                        command=f"curl -I -L {r.url}",
                    )],
                    treatment="Restrict Access-Control-Allow-Origin to specific trusted origins.",
                    impact=[
                        "Public API data can be read cross-origin by any site",
                        "Higher risk if combined with sensitive data endpoints",
                    ],
                ))
        return findings

    def _check_origin_reflection(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self._probe_results():
            acao = (r.headers.get("access-control-allow-origin") or r.headers.get("Access-Control-Allow-Origin") or "").strip()
            if not acao or acao == "*":
                continue
            origin = r.headers.get("origin") or ""
            if origin and acao == origin:
                findings.append(Finding(
                    id="CORS-003",
                    severity=Severity.WARNING,
                    confidence=0.85,
                    condition="CORS origin reflects request Origin header",
                    cause=f"{r.url} echoes Origin header value in Access-Control-Allow-Origin",
                    evidence=[Evidence(
                        source_file="http probe",
                        line_number=0,
                        excerpt=f"{r.url} => ACAO={acao} (echoed from Origin={origin})",
                        command=f"curl -I -L -H 'Origin: https://evil-example.com' {r.url}",
                    )],
                    treatment="Use a whitelist-based CORS policy instead of reflecting the Origin header.",
                    impact=[
                        "Attacker can craft arbitrary Origin to bypass CORS",
                        "Sensitive responses may be readable cross-origin",
                    ],
                ))
        return findings
