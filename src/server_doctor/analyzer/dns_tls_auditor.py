"""DNS, TLS, Cloudflare, and certbot diagnosis."""

from __future__ import annotations

import fnmatch

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import DnsTlsDomain, ServerModel, TLSCertificateStatus


class DnsTlsAuditor:
    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        for domain in self.model.dns_tls.domains:
            if domain.cloudflare_proxied:
                findings.append(_finding(
                    "DNS-TLS-002",
                    Severity.INFO,
                    "Cloudflare proxy detected",
                    f"{domain.domain} resolves to Cloudflare proxy ranges.",
                    domain,
                    "cloudflare_proxied=true",
                ))
            if (
                domain.scanned_public_ip
                and domain.a_records
                and domain.scanned_public_ip not in domain.a_records
                and not domain.cloudflare_proxied
            ):
                findings.append(_finding(
                    "DNS-TLS-001",
                    Severity.WARNING,
                    "DNS does not point to scanned server",
                    f"{domain.domain} does not resolve to {domain.scanned_public_ip}.",
                    domain,
                    f"A={','.join(domain.a_records)}",
                ))
            if (
                domain.certificate_sans
                and not cert_matches_domain(domain.domain, domain.certificate_sans)
            ):
                findings.append(_finding(
                    "DNS-TLS-004",
                    Severity.CRITICAL,
                    "Certificate name does not match domain",
                    f"Certificate SANs do not include {domain.domain}.",
                    domain,
                    f"SAN={','.join(domain.certificate_sans)}",
                ))
            if domain.certificate_days_remaining is not None and domain.certificate_days_remaining <= 14:
                if domain.certificate_days_remaining <= 3:
                    findings.append(_finding(
                        "DNS-TLS-005",
                        Severity.CRITICAL,
                        "TLS certificate expires critically soon",
                        f"Certificate expires in {domain.certificate_days_remaining} day(s).",
                        domain,
                        f"days_remaining={domain.certificate_days_remaining}",
                    ))
                elif domain.certificate_days_remaining <= 7:
                    findings.append(_finding(
                        "DNS-TLS-005",
                        Severity.WARNING,
                        "TLS certificate expires soon",
                        f"Certificate expires in {domain.certificate_days_remaining} day(s).",
                        domain,
                        f"days_remaining={domain.certificate_days_remaining}",
                    ))
                else:
                    findings.append(_finding(
                        "DNS-TLS-007",
                        Severity.WARNING,
                        "TLS certificate expires soon",
                        f"Certificate expires in {domain.certificate_days_remaining} day(s).",
                        domain,
                        f"days_remaining={domain.certificate_days_remaining}",
                    ))
            if domain.certbot_timer_enabled is False:
                findings.append(_finding(
                    "DNS-TLS-006",
                    Severity.WARNING,
                    "Certbot timer is disabled",
                    "Automatic certificate renewal timer is disabled.",
                    domain,
                    "certbot timer disabled",
                ))
        # Fallback: emit findings from TLS model certificates when domain-level
        # probe data is missing (e.g. server unreachable for external DNS probe).
        # Check if ANY domain already covered certificate expiry; if not, use TLS model.
        any_domain_covers_cert_expiry = any(
            domain.certificate_days_remaining is not None and domain.certificate_days_remaining <= 30
            for domain in self.model.dns_tls.domains
        )
        if not any_domain_covers_cert_expiry and self.model.tls.certificates:
            for cert in self.model.tls.certificates:
                self._maybe_emit_cert_finding(findings, cert)

        # Renewal cause diagnosis: when a cert is expiring within 14 days, check certbot
        if self._has_near_expiry_cert(findings):
            self._check_certbot_renewal_cause(findings)
        return findings

    def _has_near_expiry_cert(self, findings: list[Finding]) -> bool:
        return any(f.id == "DNS-TLS-005" or f.id == "DNS-TLS-007" for f in findings)

    def _check_certbot_renewal_cause(self, findings: list[Finding]) -> None:
        cb = self.model.certbot
        if not cb or cb.installed is False:
            return

        # DNS-TLS-006: certbot timer disabled (already emitted per-domain above,
        # but emit a consolidated one if domain-level data was missing)
        if cb.timer_active is False and cb.installed:
            if not any(f.id == "DNS-TLS-006" for f in findings):
                path_hint = ", ".join(cb.active_cert_paths[:2]) if cb.active_cert_paths else "unknown"
                findings.append(Finding(
                    id="DNS-TLS-006",
                    severity=Severity.WARNING,
                    confidence=0.85,
                    condition="Certbot timer is disabled",
                    cause="Automatic certificate renewal timer is disabled; certificates may not renew.",
                    evidence=[Evidence("certbot", 0, f"timer_active={cb.timer_active}; cert_paths={path_hint}")],
                    treatment="Enable the certbot timer: sudo systemctl enable --now certbot.timer",
                    impact=["TLS certificates may expire if not manually renewed"],
                ))

        # DNS-TLS-010: certbot dry-run suggests renewal would fail
        dry_run = (cb.renew_dry_run_output or "").lower()
        if dry_run and ("fail" in dry_run or "error" in dry_run):
            findings.append(Finding(
                id="DNS-TLS-010",
                severity=Severity.WARNING,
                confidence=0.82,
                condition="Certbot renewal dry-run indicates failure",
                cause="Certbot renew --dry-run returned errors; automatic renewal is likely to fail.",
                evidence=[Evidence("certbot", 0, f"dry_run_output: {dry_run[:300]}")],
                treatment="Run 'sudo certbot renew --dry-run' and fix errors before expiry.",
                impact=["Certificate may not renew automatically"],
            ))

        # DNS-TLS-011: port 80 not detected in Nginx
        port_80_open = False
        if self.model.nginx:
            for server in self.model.nginx.servers:
                for listen in server.listen:
                    if "80" in listen.split()[0]:
                        port_80_open = True
                        break
        if not port_80_open and cb.uses_letsencrypt_certs:
            findings.append(Finding(
                id="DNS-TLS-011",
                severity=Severity.WARNING,
                confidence=0.78,
                condition="Port 80 not detected in Nginx; ACME HTTP-01 challenge may be blocked",
                cause="Let's Encrypt HTTP-01 validation requires port 80 reachable.",
                evidence=[Evidence("nginx config", 0, "No listen 80 directive found in any server block")],
                treatment="Ensure port 80 is open and proxies /.well-known/acme-challenge/ to certbot.",
                impact=["Certificate renewal may fail if HTTP-01 challenge cannot complete"],
            ))

        # DNS-TLS-008: HTTP-01 challenge path not proxied
        has_acme_challenge_location = False
        if self.model.nginx:
            for server in self.model.nginx.servers:
                for loc in server.locations:
                    if ".well-known/acme-challenge" in loc.path:
                        has_acme_challenge_location = True
                        break
        if not has_acme_challenge_location and cb.uses_letsencrypt_certs and port_80_open:
            findings.append(Finding(
                id="DNS-TLS-008",
                severity=Severity.INFO,
                confidence=0.70,
                condition="HTTP-01 challenge path may not be proxied to certbot",
                cause="No location for /.well-known/acme-challenge/ found in Nginx config.",
                evidence=[Evidence("nginx config", 0, "No acme-challenge location block detected")],
                treatment="Add: location ~ /.well-known/acme-challenge { proxy_pass http://127.0.0.1:80; }",
                impact=["Automatic renewal may fail if HTTP-01 challenge cannot be served"],
            ))

        # Certbot appears healthy: emit positive note when timer active + renewal configs present
        has_renewal_configs = bool(cb.renewal_dir_listing and cb.renewal_dir_listing.strip())
        has_journal_errors = cb.journal_output and "error" in cb.journal_output.lower()
        if cb.timer_active and has_renewal_configs and not has_journal_errors:
            findings.append(Finding(
                id="DNS-TLS-012",
                severity=Severity.INFO,
                confidence=0.80,
                condition="Certbot renewal appears healthy",
                cause=(
                    f"Certbot timer is active, renewal configs exist"
                    f"{', '.join(cb.active_cert_paths[:2]) if cb.active_cert_paths else ''}, "
                    "and no recent journal errors detected."
                ),
                evidence=[Evidence(
                    "certbot", 0,
                    f"timer_active={cb.timer_active}; renewal_configs={'yes' if has_renewal_configs else 'no'}",
                )],
                treatment="No action needed; certbot appears configured for automatic renewal.",
                impact=[],
            ))

    def _maybe_emit_cert_finding(self, findings: list[Finding], cert: TLSCertificateStatus) -> None:
        if cert.days_remaining is not None and cert.days_remaining <= 30:
            if cert.days_remaining <= 3:
                findings.append(_cert_finding(
                    "DNS-TLS-005",
                    Severity.CRITICAL,
                    "TLS certificate expires critically soon",
                    f"Certificate at {cert.path} expires in {cert.days_remaining} day(s).",
                    cert,
                    f"days_remaining={cert.days_remaining}",
                ))
            elif cert.days_remaining <= 7:
                findings.append(_cert_finding(
                    "DNS-TLS-005",
                    Severity.WARNING,
                    "TLS certificate expires soon",
                    f"Certificate at {cert.path} expires in {cert.days_remaining} day(s).",
                    cert,
                    f"days_remaining={cert.days_remaining}",
                ))
            elif cert.days_remaining <= 14:
                findings.append(_cert_finding(
                    "DNS-TLS-007",
                    Severity.WARNING,
                    "TLS certificate expires soon",
                    f"Certificate at {cert.path} expires in {cert.days_remaining} day(s).",
                    cert,
                    f"days_remaining={cert.days_remaining}",
                ))
            elif cert.days_remaining <= 30:
                findings.append(_cert_finding(
                    "DNS-TLS-007",
                    Severity.INFO,
                    "TLS certificate expires soon",
                    f"Certificate at {cert.path} expires in {cert.days_remaining} day(s).",
                    cert,
                    f"days_remaining={cert.days_remaining}",
                ))


def cert_matches_domain(domain: str, sans: list[str]) -> bool:
    for san in sans:
        cleaned = san.removeprefix("DNS:")
        if fnmatch.fnmatch(domain, cleaned):
            return True
    return False


def _finding(rule_id, severity, condition, cause, domain: DnsTlsDomain, excerpt) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.88,
        condition=condition,
        cause=cause,
        evidence=[Evidence("dns/tls scan", 0, f"{domain.domain}: {excerpt}")],
        treatment="Review DNS, certificate, and certbot renewal configuration.",
        impact=["TLS availability or domain routing may be incorrect."],
    )


def _cert_finding(rule_id, severity, condition, cause, cert: TLSCertificateStatus, excerpt) -> Finding:
    subject = cert.subject or (cert.sans[0] if cert.sans else "unknown")
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.88,
        condition=condition,
        cause=cause,
        evidence=[Evidence("dns/tls scan", 0, f"{subject} ({cert.path}): {excerpt}")],
        treatment="Review DNS, certificate, and certbot renewal configuration.",
        impact=["TLS availability or domain routing may be incorrect."],
    )
