from types import SimpleNamespace

from server_doctor.scanner.firewall import FirewallScanner


class _FakeSSH:
    def run(self, cmd: str, timeout: int = 0):
        if "which ufw" in cmd:
            return SimpleNamespace(success=True, stdout="/usr/sbin/ufw")
        if "ufw status numbered" in cmd or "ufw status 2>/dev/null" in cmd:
            return SimpleNamespace(
                success=True,
                stdout=(
                    "Status: active\n"
                    "To                         Action      From\n"
                    "--                         ------      ----\n"
                    "22/tcp                     ALLOW       Anywhere\n"
                ),
            )
        if "ufw status verbose" in cmd:
            return SimpleNamespace(
                success=True,
                stdout=(
                    "Status: active\n"
                    "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
                ),
            )
        return SimpleNamespace(success=False, stdout="")


def test_firewall_scanner_parses_ufw_default_incoming():
    scanner = FirewallScanner(_FakeSSH())
    details = scanner.scan_details()
    assert details["state"] == "present"
    assert details["ufw_enabled"] is True
    assert details["ufw_default_incoming"] == "deny"
