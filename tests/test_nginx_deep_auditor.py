from server_doctor.analyzer.nginx_deep_auditor import NginxDeepAuditor
from server_doctor.model.server import NginxInfo, ServerBlock, ServerModel


def _server(name, listen):
    return ServerBlock(
        server_names=[name],
        listen=[listen],
        source_file="/etc/nginx/sites-enabled/app.conf",
        line_number=10,
    )


def test_duplicate_server_name_same_listen_emits():
    model = ServerModel(
        hostname="host",
        nginx=NginxInfo(
            version="1.24",
            config_path="/etc/nginx/nginx.conf",
            servers=[_server("example.com", "80"), _server("example.com", "80")],
        ),
    )

    findings = NginxDeepAuditor(model).audit()

    assert any(f.id == "NGX-DEEP-001" for f in findings)


def test_same_server_name_different_listen_does_not_emit():
    model = ServerModel(
        hostname="host",
        nginx=NginxInfo(
            version="1.24",
            config_path="/etc/nginx/nginx.conf",
            servers=[_server("example.com", "80"), _server("example.com", "443 ssl")],
        ),
    )

    assert not NginxDeepAuditor(model).audit()


def test_reverse_proxy_without_root_has_no_root_warning():
    server = _server("example.com", "80")
    server.locations[0:0] = []
    from server_doctor.model.server import LocationBlock

    server.locations.append(LocationBlock(path="/", proxy_pass="http://127.0.0.1:3000"))
    model = ServerModel(
        hostname="host",
        nginx=NginxInfo(version="1.24", config_path="/etc/nginx/nginx.conf", servers=[server]),
    )

    findings = NginxDeepAuditor(model).audit()

    assert not any(f.id == "NGX-DEEP-005" for f in findings)
