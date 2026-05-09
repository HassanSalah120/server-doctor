"""DNS/TLS/Cloudflare/certbot scanner helpers."""

from __future__ import annotations

import ipaddress
import socket

from server_doctor.model.server import DnsTlsDomain, DnsTlsModel, NginxInfo


class DnsTlsScanner:
    def __init__(self, ssh=None) -> None:
        self.ssh = ssh

    def scan(self, nginx: NginxInfo | None = None) -> DnsTlsModel:
        model = DnsTlsModel(enabled=True)
        for domain in _domains(nginx):
            records = _resolve(domain)
            model.domains.append(
                DnsTlsDomain(
                    domain=domain,
                    a_records=[item for item in records if ":" not in item],
                    aaaa_records=[item for item in records if ":" in item],
                    cloudflare_proxied=any(_is_cloudflare_ip(item) for item in records),
                )
            )
        return model


def _domains(nginx: NginxInfo | None) -> list[str]:
    names: list[str] = []
    for server in getattr(nginx, "servers", []) or []:
        for name in server.server_names:
            if name and name != "_" and name not in names:
                names.append(name)
    return names


def _resolve(domain: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(domain, None)})
    except socket.gaierror:
        return []


def _is_cloudflare_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(
        ip in ipaddress.ip_network(network)
        for network in (
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "104.16.0.0/13",
            "172.64.0.0/13",
            "2606:4700::/32",
        )
    )
