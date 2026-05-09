from server_doctor.engine.nginx_topology import build_nginx_topology


def test_laravel_domain_maps_to_block_root_and_php_fpm():
    model = {
        "nginx": {
            "servers": [
                {
                    "server_names": ["example.com"],
                    "root": "/var/www/app",
                    "source_file": "/etc/nginx/sites/app",
                    "locations": [
                        {
                            "path": "~ \\.php$",
                            "fastcgi_pass": "unix:/run/php/php8.2-fpm.sock",
                        }
                    ],
                }
            ]
        },
        "projects": [{"path": "/var/www/app", "name": "app", "type": "laravel"}],
    }

    nodes = build_nginx_topology(model)

    assert nodes[0].kind == "server_block"
    assert nodes[0].children[0].kind == "domain"
    # Project info is at server_block root metadata (no separate project child anymore)
    assert nodes[0].metadata.get("root") == "/var/www/app"
    php_locations = [child for child in nodes[0].children if child.kind == "location"]
    assert "unix:/run/php/php8.2-fpm.sock" in php_locations[0].label
    assert "→" in php_locations[0].label


def test_reverse_proxy_without_root_is_not_warning():
    model = {
        "nginx": {
            "servers": [
                {
                    "server_names": ["api.example.com"],
                    "locations": [{"path": "/", "proxy_pass": "http://127.0.0.1:3000"}],
                }
            ]
        }
    }

    nodes = build_nginx_topology(model)

    assert nodes[0].status == "ok"


def test_multiple_server_names_render_all_domains():
    model = {"nginx": {"servers": [{"server_names": ["a.test", "b.test"], "root": "/srv/app"}]}}

    nodes = build_nginx_topology(model)
    domains = [child.label for child in nodes[0].children if child.kind == "domain"]

    assert domains == ["a.test", "b.test"]
