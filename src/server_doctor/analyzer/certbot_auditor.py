"""Certbot Auditor - Classifies certificate renewal risk with topology context."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class CertbotAuditor:
    """Auditor for certbot relevance and expiry-aware risk."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        if not hasattr(self.model, "certbot"):
            return findings

        c = self.model.certbot
        installed = bool(getattr(c, "installed", False))
        https_detected = bool(getattr(c, "https_detected", False))
        service_failed = bool(getattr(c, "service_failed", False))
        uses_letsencrypt_certs = bool(getattr(c, "uses_letsencrypt_certs", False))
        timer_active = bool(getattr(c, "timer_active", False))
        timer_enabled = bool(getattr(c, "timer_enabled", False))
        active_cert_paths = getattr(c, "active_cert_paths", []) or []
        renewal_owner = self._infer_renewal_owner()

        min_days_to_expiry = self._effective_days_to_expiry()

        if (installed is False) and https_detected and (min_days_to_expiry is None or min_days_to_expiry > 30):
            findings.append(
                Finding(
                    id="CERTBOT-3",
                    severity=Severity.INFO,
                    confidence=0.75,
                    condition="Certbot not installed, but HTTPS appears valid",
                    cause="Server has active HTTPS and no certbot binary detected.",
                    evidence=[
                        Evidence(
                            source_file="nginx-ssl",
                            line_number=1,
                            excerpt="HTTPS detected with non-certbot-managed renewal path",
                            command="nginx -T",
                        )
                    ],
                    treatment="Ensure your certificate renewal mechanism is documented (e.g., container-managed, acme.sh, CDN edge certs).",
                    impact=["Low immediate risk if certificate lifecycle is externally managed."],
                )
            )

        if not service_failed:
            return findings

        certbot_managed = renewal_owner == "certbot" or uses_letsencrypt_certs
        likely_cause, next_command = self._infer_certbot_failure_reason()
        if certbot_managed and min_days_to_expiry is not None and min_days_to_expiry <= 14:
            severity = Severity.CRITICAL
            condition = f"Certbot-managed renewal path is failing and certificate expires in {min_days_to_expiry} day(s)"
            impact = [
                "HTTPS outage risk due to certificate expiry",
                "User trust and availability impact",
            ]
            treatment = (
                "Exact fix playbook:\n"
                "1) Collect failure artifacts:\n"
                "   journalctl -u certbot.service -n 120 --no-pager\n"
                "   systemctl cat certbot.service certbot.timer\n"
                "   certbot certificates\n"
                "   ls -la /etc/letsencrypt/renewal\n"
                "2) Validate renewal path:\n"
                "   systemctl status certbot.service certbot.timer\n"
                "   certbot renew --dry-run\n"
                "3) Recover timer/workflow:\n"
                "   systemctl enable --now certbot.timer\n"
                f"Most likely cause: {likely_cause}\n"
                f"Next command: {next_command}"
            )
            finding_id = "CERTBOT-1"
        elif certbot_managed:
            severity = Severity.WARNING
            remaining = min_days_to_expiry if min_days_to_expiry is not None else "unknown"
            condition = (
                f"Certbot service is failing while certbot-managed TLS certs are in use "
                f"(expiry in {remaining} day(s))"
            )
            impact = ["Renewal drift may become an outage if ignored."]
            treatment = (
                "Repair certbot service/timer and validate renewals:\n"
                "    systemctl status certbot.service certbot.timer\n"
                "    certbot renew --dry-run"
            )
            finding_id = "CERTBOT-2"
        else:
            severity = Severity.WARNING
            condition = "Certbot service is failing, but active TLS certs do not appear certbot-managed"
            impact = ["Alert noise unless certbot is expected to manage renewal here."]
            treatment = "If unused, disable it safely: systemctl disable --now certbot.service certbot.timer"
            finding_id = "CERTBOT-4"

        findings.append(
            Finding(
                id=finding_id,
                severity=severity,
                confidence=0.9,
                condition=condition,
                cause="Service state indicates renewal workflow failure; risk depends on active certificate dependency.",
                    evidence=[
                        Evidence(
                            source_file="systemd",
                            line_number=1,
                            excerpt=(
                            f"certbot.service failed={service_failed}, timer_active={timer_active}, "
                            f"timer_enabled={timer_enabled}, letsencrypt_paths={len(active_cert_paths)}, "
                            f"renewal_owner={renewal_owner}"
                            ),
                            command="systemctl is-failed/is-active/is-enabled certbot.*",
                        )
                ] + self._artifact_evidence(),
                treatment=treatment,
                impact=impact,
            )
        )
        return findings

    def _infer_renewal_owner(self) -> str:
        certbot = getattr(self.model, "certbot", None)
        if not certbot:
            return "unknown"
        if certbot.installed and certbot.uses_letsencrypt_certs:
            return "certbot"
        if certbot.installed and (certbot.timer_enabled or certbot.timer_active):
            certs = getattr(getattr(self.model, "tls", None), "certificates", []) or []
            if any("let" in ((c.issuer or "").lower()) and "encrypt" in ((c.issuer or "").lower()) for c in certs):
                return "certbot"
        return "unknown"

    def _effective_days_to_expiry(self) -> int | None:
        """Use TLS status as source of truth, then fall back to certbot scanner value."""
        tls = getattr(self.model, "tls", None)
        tls_certs = getattr(tls, "certificates", []) if tls else []
        days = [c.days_remaining for c in tls_certs if isinstance(getattr(c, "days_remaining", None), int)]
        if days:
            return min(days)
        c = getattr(self.model, "certbot", None)
        raw = getattr(c, "min_days_to_expiry", None) if c else None
        return raw if isinstance(raw, int) else None

    def _artifact_evidence(self) -> list[Evidence]:
        c = getattr(self.model, "certbot", None)
        if not c:
            return []
        evidence: list[Evidence] = []
        if getattr(c, "renew_dry_run_output", None):
            evidence.append(
                Evidence(
                    source_file="certbot",
                    line_number=1,
                    excerpt=self._tail(getattr(c, "renew_dry_run_output", ""), 4),
                    command="certbot renew --dry-run",
                )
            )
        if getattr(c, "systemctl_status_output", None):
            evidence.append(
                Evidence(
                    source_file="systemd",
                    line_number=1,
                    excerpt=self._tail(getattr(c, "systemctl_status_output", ""), 4),
                    command="systemctl status certbot.service certbot.timer --no-pager -n 80",
                )
            )
        if getattr(c, "journal_output", None):
            evidence.append(
                Evidence(
                    source_file="journalctl",
                    line_number=1,
                    excerpt=self._tail(getattr(c, "journal_output", ""), 6),
                    command="journalctl -u certbot.service -n 120 --no-pager",
                )
            )
        return evidence

    def _infer_certbot_failure_reason(self) -> tuple[str, str]:
        c = getattr(self.model, "certbot", None)
        text = "\n".join(
            [
                getattr(c, "renew_dry_run_output", "") or "",
                getattr(c, "systemctl_status_output", "") or "",
                getattr(c, "journal_output", "") or "",
            ]
        ).lower()
        if "dns problem" in text or "nxdomain" in text:
            return ("DNS validation/challenge failure", "dig +short <domain> && certbot renew --dry-run")
        if "connection refused" in text or "timeout during connect" in text or "port 80" in text:
            return ("HTTP-01 challenge unreachable on port 80", "ss -tulpn | rg ':80' && ufw status")
        if "permission denied" in text or "could not bind" in text:
            return ("Permission or file ownership issue in certbot/nginx hooks", "sudo journalctl -u certbot.service -n 120 --no-pager")
        if "unauthorized" in text or "invalid response" in text:
            return ("ACME challenge response mismatch", "sudo certbot certificates && sudo certbot renew --dry-run")
        return ("certbot renewal workflow failure (inspect latest logs)", "sudo journalctl -u certbot.service -n 120 --no-pager")

    @staticmethod
    def _tail(text: str, lines: int) -> str:
        parts = [line.strip() for line in (text or "").splitlines() if line.strip()]
        if not parts:
            return ""
        return " | ".join(parts[-lines:])[:400]
