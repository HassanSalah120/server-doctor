"""Firewall Scanner - Detects local firewall presence and basic status.

This scanner identifies local firewall rules without claiming full network 
security (cloud/external firewalls are out of scope).
"""

from server_doctor.connector.ssh import SSHConnector


class FirewallScanner:
    """Scanner for local firewall status.

    Checks in order:
    1. ufw status
    2. nft list ruleset
    3. iptables -S
    """

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> str:
        """Backward-compatible firewall state scan."""
        return self.scan_details().get("state", "unknown")

    def scan_details(self) -> dict:
        """Perform firewall scan and return correlated posture details.

        Returns:
            {
              "state": "present|not_detected|unknown",
              "ufw_enabled": bool|None,
              "ufw_default_incoming": str|None,
              "rules": list[str],
            }
        """
        state = "not_detected"
        ufw_enabled: bool | None = None
        ufw_default_incoming: str | None = None
        rules: list[str] = []

        # 1. UFW details (highest signal for OPEN/BLOCKED correlation)
        if self.ssh.run("which ufw", timeout=4).success:
            res = self.ssh.run("ufw status numbered 2>/dev/null || ufw status 2>/dev/null", timeout=6)
            if res.success:
                out = res.stdout.strip()
                lower = out.lower()
                if "status: active" in lower:
                    state = "present"
                    ufw_enabled = True
                elif "status: inactive" in lower:
                    ufw_enabled = False
                parsed = self._parse_ufw_rules(out)
                if parsed:
                    rules.extend(parsed)
            verbose = self.ssh.run("ufw status verbose 2>/dev/null", timeout=6)
            if verbose.success and verbose.stdout:
                parsed_default = self._parse_ufw_default_incoming(verbose.stdout)
                if parsed_default:
                    ufw_default_incoming = parsed_default
                parsed_verbose_rules = self._parse_ufw_rules(verbose.stdout)
                if parsed_verbose_rules:
                    for rule in parsed_verbose_rules:
                        if rule not in rules:
                            rules.append(rule)

        # 2. NFT fallback (Modern Ubuntu/Debian)
        if state != "present" and self.ssh.run("which nft", timeout=4).success:
            res = self.ssh.run("nft list ruleset", timeout=4)
            if res.success and len(res.stdout.strip()) > 100:
                state = "present"

        # 3. Iptables fallback
        if state != "present" and self.ssh.run("which iptables", timeout=4).success:
            res = self.ssh.run("iptables -S", timeout=4)
            if res.success:
                lines = [l for l in res.stdout.strip().split("\n") if l and not l.startswith("-P ")]
                if len(lines) > 2:
                    state = "present"

        # 4. Fully unknown toolchain
        if (
            not self.ssh.run("which ufw", timeout=4).success
            and not self.ssh.run("which nft", timeout=4).success
            and not self.ssh.run("which iptables", timeout=4).success
        ):
            state = "unknown"

        return {
            "state": state,
            "ufw_enabled": ufw_enabled,
            "ufw_default_incoming": ufw_default_incoming,
            "rules": rules,
        }

    def _parse_ufw_rules(self, output: str) -> list[str]:
        """Extract compact rule lines from ufw status output."""
        rules: list[str] = []
        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            low = line.lower()
            if low.startswith("status:") or low.startswith("to ") or low.startswith("--"):
                continue
            if "allow" not in low and "deny" not in low and "reject" not in low:
                continue
            line = line.replace("[", "").replace("]", "")
            rules.append(" ".join(line.split()))
        return rules[:200]

    def _parse_ufw_default_incoming(self, output: str) -> str | None:
        """Extract default incoming policy from `ufw status verbose` output."""
        for raw in output.splitlines():
            line = raw.strip().lower()
            if not line.startswith("default:"):
                continue
            # Typical: "Default: deny (incoming), allow (outgoing), disabled (routed)"
            if "deny (incoming)" in line or "reject (incoming)" in line:
                return "deny"
            if "allow (incoming)" in line:
                return "allow"
            return "unknown"
        return None
