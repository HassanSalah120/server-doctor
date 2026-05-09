from __future__ import annotations

from dataclasses import dataclass

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding


@dataclass
@register_check
class CIPostureAuditor(BaseCheck):
    @property
    def category(self) -> str:
        return "devops"

    @property
    def requires_ssh(self) -> bool:
        return True

    def run(self, context: CheckContext) -> list[Finding]:
        if not context.ssh:
            return []

        sc = getattr(context.model, "supply_chain", None)
        if not sc or not getattr(sc, "enabled", False):
            return []

        findings: list[Finding] = []

        for repo in getattr(sc, "repos", []) or []:
            workflow_files = list(getattr(repo, "ci_workflows", []) or [])
            system_files = list(getattr(repo, "ci_system_files", []) or [])
            ci_files = workflow_files + system_files

            if not ci_files:
                continue

            combined = ""
            evidence: list[Evidence] = []

            for fp in ci_files[:12]:
                content = context.ssh.read_file(fp) or ""
                if not content:
                    continue
                combined += "\n" + content
                first_line = (content.splitlines()[:1] or [""])[0]
                evidence.append(Evidence(source_file=fp, line_number=1, excerpt=first_line[:180], command="cat"))

            blob = combined.lower()
            if not blob:
                continue

            def add_missing(rule_id: str, title: str, hint: str) -> None:
                findings.append(
                    Finding(
                        id=rule_id,
                        severity=Severity.WARNING,
                        confidence=0.75,
                        condition=title,
                        cause=f"CI config in {repo.path} does not appear to include {hint}.",
                        evidence=evidence or [Evidence(source_file=repo.path, line_number=1, excerpt="CI files detected but unreadable", command=None)],
                        treatment="Add this step to your CI pipeline and enforce it on PRs/main.",
                        impact=["Higher risk of shipping vulnerable or unsigned artifacts", "Reduced auditability of releases"],
                    )
                )

            # Secret scanning
            has_secret_scan = any(k in blob for k in ["gitleaks", "trufflehog", "secret scanning", "detect-secrets"])
            if not has_secret_scan:
                add_missing("SC-SECR-001", "CI missing secret scanning", "a secrets scanning step (gitleaks/trufflehog/etc.)")

            # SBOM
            has_sbom = any(k in blob for k in ["syft", "cyclonedx", "sbom", "spdx"])
            if not has_sbom:
                add_missing("SC-SBOM-001", "CI missing SBOM generation", "SBOM generation (syft/cyclonedx/spdx)")

            # Signing
            has_signing = any(k in blob for k in ["cosign", "sigstore", "sign the image", "attest"])
            if not has_signing:
                add_missing("SC-SIGN-001", "CI missing artifact/image signing", "artifact signing (cosign/sigstore)")

            # Provenance / SLSA
            has_provenance = any(k in blob for k in ["slsa", "provenance", "attestation", "in-toto"])
            if not has_provenance:
                add_missing("SC-PROV-001", "CI missing provenance (SLSA)", "provenance/attestations (SLSA/in-toto)")

        return findings
