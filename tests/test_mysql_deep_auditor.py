from server_doctor.analyzer.mysql_deep_auditor import MySQLDeepAuditor
from server_doctor.model.server import MySQLDeepModel, ServerModel


def test_public_mysql_bind_emits():
    model = ServerModel(
        hostname="host",
        mysql_deep=MySQLDeepModel(installed=True, bind_addresses=["0.0.0.0"]),
    )

    assert MySQLDeepAuditor(model).audit()[0].id == "MYSQL-DEEP-001"


def test_local_mysql_bind_does_not_emit():
    model = ServerModel(
        hostname="host",
        mysql_deep=MySQLDeepModel(installed=True, bind_addresses=["127.0.0.1"]),
    )

    assert not MySQLDeepAuditor(model).audit()


def test_mysql_not_installed_does_not_emit_public_bind():
    model = ServerModel(
        hostname="host",
        mysql_deep=MySQLDeepModel(installed=False, bind_addresses=["0.0.0.0"]),
    )

    assert not MySQLDeepAuditor(model).audit()
