from server_doctor.analyzer.php_fpm_deep_auditor import PhpFpmDeepAuditor
from server_doctor.model.server import (
    LocationBlock,
    NginxInfo,
    PhpFpmDeepModel,
    ServerBlock,
    ServerModel,
)


def test_missing_unix_socket_emits_phpfpm_deep_001():
    server = ServerBlock(source_file="/etc/nginx/site", line_number=12)
    server.locations.append(
        LocationBlock(path="~ \\.php$", fastcgi_pass="unix:/run/php/php8.2-fpm.sock")
    )
    model = ServerModel(
        hostname="host",
        nginx=NginxInfo(version="1.24", config_path="/etc/nginx/nginx.conf", servers=[server]),
        php_fpm_deep=PhpFpmDeepModel(
            socket_exists={"/run/php/php8.2-fpm.sock": False}
        ),
    )

    findings = PhpFpmDeepAuditor(model).audit()

    assert [f.id for f in findings] == ["PHPFPM-DEEP-001"]
    assert findings[0].evidence


def test_tcp_fastcgi_pass_does_not_trigger_socket_missing():
    server = ServerBlock(source_file="/etc/nginx/site", line_number=12)
    server.locations.append(LocationBlock(path="~ \\.php$", fastcgi_pass="127.0.0.1:9000"))
    model = ServerModel(
        hostname="host",
        nginx=NginxInfo(version="1.24", config_path="/etc/nginx/nginx.conf", servers=[server]),
        php_fpm_deep=PhpFpmDeepModel(socket_exists={}),
    )

    assert not PhpFpmDeepAuditor(model).audit()


def test_missing_permission_data_produces_no_critical_permission_finding():
    server = ServerBlock(source_file="/etc/nginx/site", line_number=12)
    server.locations.append(
        LocationBlock(path="~ \\.php$", fastcgi_pass="unix:/run/php/php8.2-fpm.sock")
    )
    model = ServerModel(
        hostname="host",
        nginx=NginxInfo(version="1.24", config_path="/etc/nginx/nginx.conf", servers=[server]),
        php_fpm_deep=PhpFpmDeepModel(socket_exists={"/run/php/php8.2-fpm.sock": True}),
    )

    findings = PhpFpmDeepAuditor(model).audit()

    assert not any(f.id == "PHPFPM-DEEP-002" for f in findings)
