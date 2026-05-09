from server_doctor.checks import CheckContext
from server_doctor.checks.database.database_auditor import DatabaseAuditor
from server_doctor.model.server import ServerModel


def test_public_mysql_bind_is_detected():
    model = ServerModel(hostname="web")
    model.services.mysql_bind_addresses = ["0.0.0.0"]

    findings = DatabaseAuditor().run(CheckContext(model=model))

    assert [f.id for f in findings] == ["DB-001"]


def test_local_mysql_bind_is_not_flagged():
    model = ServerModel(hostname="web")
    model.services.mysql_bind_addresses = ["127.0.0.1"]

    assert DatabaseAuditor().run(CheckContext(model=model)) == []
