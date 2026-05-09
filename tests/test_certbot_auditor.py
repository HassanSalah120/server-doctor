from server_doctor.analyzer.certbot_auditor import CertbotAuditor
from server_doctor.model.server import (
    CertbotModel,
    ServerModel,
    TLSCertificateStatus,
    TLSStatusModel,
)


def test_certbot_auditor_avoids_certbot4_when_owner_is_certbot():
    model = ServerModel(
        hostname="example.com",
        certbot=CertbotModel(
            installed=True,
            service_failed=True,
            timer_active=True,
            timer_enabled=True,
            uses_letsencrypt_certs=False,
            https_detected=True,
            min_days_to_expiry=45,
        ),
        tls=TLSStatusModel(
            certificates=[
                TLSCertificateStatus(
                    path="live://example.com@127.0.0.1:443",
                    issuer="CN=Let's Encrypt",
                    parse_ok=True,
                )
            ]
        ),
    )

    findings = CertbotAuditor(model).audit()
    assert findings
    assert any(f.id == "CERTBOT-2" for f in findings)
    assert not any(f.id == "CERTBOT-4" for f in findings)
    assert "certbot-managed" in findings[0].condition


def test_certbot_auditor_elevates_when_expiry_under_14_days():
    model = ServerModel(
        hostname="example.com",
        certbot=CertbotModel(
            installed=True,
            service_failed=True,
            timer_active=True,
            timer_enabled=True,
            uses_letsencrypt_certs=True,
            https_detected=True,
            min_days_to_expiry=7,
        ),
    )

    findings = CertbotAuditor(model).audit()
    critical = next(f for f in findings if f.id == "CERTBOT-1")
    assert critical.severity.value == "critical"
    assert "7 day(s)" in critical.condition


def test_certbot_auditor_known_days_over_14_stays_warning():
    model = ServerModel(
        hostname="example.com",
        certbot=CertbotModel(
            installed=True,
            service_failed=True,
            timer_active=True,
            timer_enabled=True,
            uses_letsencrypt_certs=True,
            https_detected=True,
            min_days_to_expiry=30,
        ),
    )
    findings = CertbotAuditor(model).audit()
    warning = next(f for f in findings if f.id == "CERTBOT-2")
    assert warning.severity.value == "warning"
    assert "30 day(s)" in warning.condition


def test_certbot_auditor_unknown_days_uses_unknown_text():
    model = ServerModel(
        hostname="example.com",
        certbot=CertbotModel(
            installed=True,
            service_failed=True,
            timer_active=True,
            timer_enabled=True,
            uses_letsencrypt_certs=True,
            https_detected=True,
            min_days_to_expiry=None,
        ),
    )
    findings = CertbotAuditor(model).audit()
    warning = next(f for f in findings if f.id == "CERTBOT-2")
    assert "unknown day(s)" in warning.condition
