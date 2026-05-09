from types import SimpleNamespace

from server_doctor.checks import CheckContext
from server_doctor.checks.firewall.firewall_recommendation import FirewallRecommendationAuditor
from server_doctor.model.server import ServerModel


def test_public_redis_endpoint_is_detected():
    model = ServerModel(hostname="web")
    model.network_surface = SimpleNamespace(
        endpoints=[SimpleNamespace(port=6379, protocol="tcp", is_public=True)]
    )

    findings = FirewallRecommendationAuditor().run(CheckContext(model=model))

    assert [f.id for f in findings] == ["FW-REC-003"]


def test_private_redis_endpoint_is_not_flagged():
    model = ServerModel(hostname="web")
    model.network_surface = SimpleNamespace(
        endpoints=[SimpleNamespace(port=6379, protocol="tcp", is_public=False)]
    )

    assert FirewallRecommendationAuditor().run(CheckContext(model=model)) == []


def test_firewall_data_unavailable_emits_no_false_critical():
    model = ServerModel(hostname="web")

    assert FirewallRecommendationAuditor().run(CheckContext(model=model)) == []
