from server_doctor.analyzer.server_doctor import ServerDoctorAnalyzer
from server_doctor.model.server import LocationBlock, NginxInfo, ServerBlock, ServerModel


def test_duplicate_server_name_identical_blocks_downgraded_to_info():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    source_file="/etc/nginx/conf.d/a.conf",
                    line_number=10,
                    locations=[LocationBlock(path="/api", proxy_pass="http://127.0.0.1:3000")],
                ),
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    source_file="/etc/nginx/conf.d/b.conf",
                    line_number=20,
                    locations=[LocationBlock(path="/api", proxy_pass="http://127.0.0.1:3000")],
                ),
            ],
        ),
    )
    analyzer = ServerDoctorAnalyzer(model)
    findings = analyzer._check_duplicate_server_names()  # noqa: SLF001
    assert findings
    duplicate = findings[0]
    assert duplicate.severity.value == "info"
    assert "behaviorally equivalent" in duplicate.cause
    assert "blast radius" in duplicate.cause.lower()


def test_duplicate_server_name_includes_diff_correlation_for_shadowed_block():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    source_file="/etc/nginx/conf.d/a.conf",
                    line_number=10,
                    locations=[LocationBlock(path="/api", proxy_pass="http://127.0.0.1:3000")],
                ),
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    source_file="/etc/nginx/conf.d/b.conf",
                    line_number=20,
                    locations=[LocationBlock(path="/api", proxy_pass="http://127.0.0.1:8104")],
                ),
            ],
        ),
    )
    analyzer = ServerDoctorAnalyzer(model)
    findings = analyzer._check_duplicate_server_names()  # noqa: SLF001
    duplicate = findings[0]
    assert duplicate.severity.value == "warning"
    assert duplicate.correlation
    assert any("upstreams_delta" in item for item in duplicate.correlation)


def test_duplicate_server_name_listen_only_diff_is_info_cleanup():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    source_file="/etc/nginx/conf.d/a.conf",
                    line_number=10,
                    locations=[LocationBlock(path="/api", proxy_pass="http://127.0.0.1:3000")],
                ),
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl default_server"],
                    source_file="/etc/nginx/conf.d/b.conf",
                    line_number=20,
                    locations=[LocationBlock(path="/api", proxy_pass="http://127.0.0.1:3000")],
                ),
            ],
        ),
    )
    analyzer = ServerDoctorAnalyzer(model)
    findings = analyzer._check_duplicate_server_names()  # noqa: SLF001
    duplicate = findings[0]
    assert duplicate.severity.value == "info"
    assert "effectively identical" in duplicate.cause


def test_duplicate_server_name_prod_local_split_explained_when_info():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["localhost"],
                    listen=["443 ssl"],
                    source_file="/etc/nginx/conf.d/default.conf",
                    line_number=10,
                    locations=[LocationBlock(path="/", proxy_pass="http://frontend:80")],
                ),
                ServerBlock(
                    server_names=["localhost"],
                    listen=["443 ssl default_server"],
                    source_file="/etc/nginx/conf.d/default.local.conf",
                    line_number=20,
                    locations=[LocationBlock(path="/", proxy_pass="http://frontend:80")],
                ),
            ],
        ),
    )
    analyzer = ServerDoctorAnalyzer(model)
    finding = analyzer._check_duplicate_server_names()[0]  # noqa: SLF001
    assert finding.severity.value == "info"
    assert "production/local split" in finding.cause.lower()
    assert "optional cleanup" in finding.treatment.lower()


def test_duplicate_server_name_across_http_https_is_not_flagged():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["vote.schmobinquiz.de"],
                    listen=["80"],
                    source_file="/etc/nginx/conf.d/default.conf",
                    line_number=10,
                    locations=[LocationBlock(path="/", proxy_pass="http://frontend:80")],
                ),
                ServerBlock(
                    server_names=["vote.schmobinquiz.de"],
                    listen=["443 ssl http2"],
                    source_file="/etc/nginx/conf.d/default.conf",
                    line_number=40,
                    locations=[LocationBlock(path="/", proxy_pass="http://frontend:80")],
                ),
            ],
        ),
    )
    analyzer = ServerDoctorAnalyzer(model)
    findings = analyzer._check_duplicate_server_names()  # noqa: SLF001
    assert findings == []
