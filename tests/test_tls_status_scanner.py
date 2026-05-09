from types import SimpleNamespace

from server_doctor.model.server import NginxInfo, ServerBlock
from server_doctor.scanner.tls_status import TLSStatusScanner


class _FakeSSH:
    def run(self, cmd: str, timeout: int = 0):
        if "openssl s_client" in cmd:
            return SimpleNamespace(
                success=True,
                stdout=(
                    "issuer=CN=Let's Encrypt\n"
                    "subject=CN=example.com\n"
                    "notAfter=May 10 12:34:56 2026 GMT\n"
                    "X509v3 Subject Alternative Name:\n"
                    "    DNS:example.com, DNS:www.example.com\n"
                ),
            )
        return SimpleNamespace(success=True, stdout="")


def test_tls_status_scanner_uses_live_sni_inspection():
    scanner = TLSStatusScanner(_FakeSSH())
    nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        servers=[
            ServerBlock(
                server_names=["example.com"],
                listen=["443 ssl"],
                ssl_enabled=True,
            )
        ],
    )
    tls = scanner.scan(nginx)
    assert tls.certificates
    cert = tls.certificates[0]
    assert cert.path.startswith("live://example.com@127.0.0.1:443")
    assert cert.issuer and "Let's Encrypt" in cert.issuer
    assert cert.parse_ok is True
