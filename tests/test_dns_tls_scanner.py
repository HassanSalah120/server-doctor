from server_doctor.model.server import NginxInfo, ServerBlock
from server_doctor.scanner.dns_tls import DnsTlsScanner


def test_dns_tls_scanner_collects_domains_from_nginx(monkeypatch):
    monkeypatch.setattr("server_doctor.scanner.dns_tls._resolve", lambda domain: ["127.0.0.1"])
    nginx = NginxInfo(
        version="1.24",
        config_path="/etc/nginx/nginx.conf",
        servers=[ServerBlock(server_names=["example.com"])],
    )

    model = DnsTlsScanner().scan(nginx)

    assert model.domains[0].domain == "example.com"
    assert model.domains[0].a_records == ["127.0.0.1"]
