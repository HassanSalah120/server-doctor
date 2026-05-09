"""Security Baseline Scanner - Collects common hardening/patch posture signals."""

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import SecurityBaselineModel


class SecurityBaselineScanner:
    """Scanner for SSH hardening and patch posture."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> SecurityBaselineModel:
        """Collect baseline hardening and patch indicators."""
        baseline = SecurityBaselineModel()
        self._collect_ssh_settings(baseline)
        self._collect_patch_posture(baseline)
        self._collect_reboot_required(baseline)
        return baseline

    def _collect_ssh_settings(self, baseline: SecurityBaselineModel) -> None:
        # Try effective SSHD config first (preferred).
        sshd_present = self.ssh.run("which sshd 2>/dev/null")
        if sshd_present.success:
            res = self.ssh.run("sshd -T 2>/dev/null | egrep '^(permitrootlogin|passwordauthentication) '")
            if res.success and res.stdout.strip():
                for line in res.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) < 2:
                        continue
                    key, value = parts[0].lower(), parts[1].lower()
                    if key == "permitrootlogin":
                        baseline.ssh_permit_root_login = value
                    elif key == "passwordauthentication":
                        baseline.ssh_password_authentication = value
                return

        # Fallback to raw file parse (best-effort, not fully effective config).
        cfg = self.ssh.read_file("/etc/ssh/sshd_config")
        if not cfg:
            return

        permit_root_login: str | None = None
        password_auth: str | None = None
        for line in cfg.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            parts = clean.split()
            if len(parts) < 2:
                continue
            key = parts[0].lower()
            value = parts[1].lower()
            if key == "permitrootlogin":
                permit_root_login = value
            elif key == "passwordauthentication":
                password_auth = value

        baseline.ssh_permit_root_login = permit_root_login
        baseline.ssh_password_authentication = password_auth

    def _collect_patch_posture(self, baseline: SecurityBaselineModel) -> None:
        if self.ssh.run("which apt 2>/dev/null").success:
            baseline.package_manager = "apt"
            self._collect_apt_updates(baseline)
            return
        if self.ssh.run("which dnf 2>/dev/null").success:
            baseline.package_manager = "dnf"
            self._collect_dnf_updates(baseline)
            return
        if self.ssh.run("which yum 2>/dev/null").success:
            baseline.package_manager = "yum"
            self._collect_yum_updates(baseline)

    def _collect_apt_updates(self, baseline: SecurityBaselineModel) -> None:
        res = self.ssh.run("apt list --upgradable 2>/dev/null")
        if not res.success:
            return

        lines = [l.strip() for l in res.stdout.splitlines() if l.strip() and not l.startswith("Listing...")]
        upgradable_lines = [l for l in lines if "upgradable from:" in l]
        baseline.pending_updates_total = len(upgradable_lines)
        baseline.pending_security_updates = sum(1 for l in upgradable_lines if "security" in l.lower())

    def _collect_dnf_updates(self, baseline: SecurityBaselineModel) -> None:
        total_res = self.ssh.run("dnf -q check-update 2>/dev/null || true")
        if total_res.stdout:
            pkg_lines = [
                l for l in total_res.stdout.splitlines()
                if l.strip() and not l.lower().startswith(("last metadata", "obsoleting", "security:"))
            ]
            baseline.pending_updates_total = sum(1 for l in pkg_lines if len(l.split()) >= 3)

        sec_res = self.ssh.run("dnf -q updateinfo list security 2>/dev/null || true")
        if sec_res.stdout:
            baseline.pending_security_updates = sum(
                1 for l in sec_res.stdout.splitlines() if l.strip() and "security" in l.lower()
            )

    def _collect_yum_updates(self, baseline: SecurityBaselineModel) -> None:
        total_res = self.ssh.run("yum -q check-update 2>/dev/null || true")
        if total_res.stdout:
            pkg_lines = [
                l for l in total_res.stdout.splitlines()
                if l.strip() and not l.lower().startswith(("loaded plugins", "obsoleting", "security:"))
            ]
            baseline.pending_updates_total = sum(1 for l in pkg_lines if len(l.split()) >= 3)

    def _collect_reboot_required(self, baseline: SecurityBaselineModel) -> None:
        res = self.ssh.run("test -f /var/run/reboot-required && echo yes || echo no")
        baseline.reboot_required = res.success and res.stdout.strip() == "yes"
