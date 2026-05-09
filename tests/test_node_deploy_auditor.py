from types import SimpleNamespace

from server_doctor.checks import CheckContext
from server_doctor.checks.node.node_deploy_auditor import NodeDeployAuditor
from server_doctor.model.server import ServerModel


def test_node_root_process_is_detected():
    model = ServerModel(hostname="web")
    model.services.node_processes = [SimpleNamespace(pid=123, user="root")]

    findings = NodeDeployAuditor().run(CheckContext(model=model))

    assert [f.id for f in findings] == ["NODE-DEPLOY-003"]


def test_node_non_root_process_is_not_flagged():
    model = ServerModel(hostname="web")
    model.services.node_processes = [SimpleNamespace(pid=123, user="www-data")]

    assert NodeDeployAuditor().run(CheckContext(model=model)) == []


def test_missing_process_owner_does_not_crash_or_emit():
    model = ServerModel(hostname="web")
    model.services.node_processes = [SimpleNamespace(pid=123)]

    assert NodeDeployAuditor().run(CheckContext(model=model)) == []
