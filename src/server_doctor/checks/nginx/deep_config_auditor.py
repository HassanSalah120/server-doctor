"""Registered wrapper for the deep Nginx auditor."""

from __future__ import annotations

from server_doctor.analyzer.nginx_deep_auditor import NginxDeepAuditor
from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.finding import Finding


@register_check
class DeepNginxConfigAuditor(BaseCheck):
    @property
    def category(self) -> str:
        return "security"

    @property
    def requires_ssh(self) -> bool:
        return False

    def run(self, context: CheckContext) -> list[Finding]:
        return NginxDeepAuditor(context.model).audit()
