from server_doctor.analyzer.dns_tls_auditor import DnsTlsAuditor
from server_doctor.model.server import DnsTlsDomain, DnsTlsModel, ServerModel


def test_cert_san_missing_domain_emits_mismatch():
    model = ServerModel(
        hostname="host",
        dns_tls=DnsTlsModel(
            domains=[
                DnsTlsDomain(domain="api.example.com", certificate_sans=["DNS:www.example.com"])
            ]
        ),
    )

    findings = DnsTlsAuditor(model).audit()

    assert findings[0].id == "DNS-TLS-004"


def test_wildcard_cert_matching_subdomain_does_not_emit():
    model = ServerModel(
        hostname="host",
        dns_tls=DnsTlsModel(
            domains=[
                DnsTlsDomain(domain="api.example.com", certificate_sans=["DNS:*.example.com"])
            ]
        ),
    )

    assert not DnsTlsAuditor(model).audit()


def test_cloudflare_proxy_is_info_not_warning_or_critical():
    model = ServerModel(
        hostname="host",
        dns_tls=DnsTlsModel(domains=[DnsTlsDomain(domain="example.com", cloudflare_proxied=True)]),
    )

    finding = DnsTlsAuditor(model).audit()[0]

    assert finding.id == "DNS-TLS-002"
    assert finding.severity.value == "info"
