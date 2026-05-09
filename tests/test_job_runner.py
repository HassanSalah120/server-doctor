import time

import pytest

from server_doctor.storage.db import set_db_path, init_db
from server_doctor.storage.repositories import ServerRepository
from server_doctor.web.job_runner import ScanJobRunner


def _setup_db(tmp_path):
    dbfile = tmp_path / "test.db"
    set_db_path(str(dbfile))
    init_db()


def test_scan_job_records_ssh_key_error(tmp_path, monkeypatch):
    """When the SSH connector fails (e.g. missing key file) the job is marked
    as failed and the error message is logged.
    """
    _setup_db(tmp_path)

    # create server with bogus key path
    sid = ServerRepository().create(
        name="badhost", host="127.0.0.1", key_path="/does/not/exist"
    )
    runner = ScanJobRunner()

    # Patch the connector used by the runner so that connecting raises the
    # same error we expect from SSHConnector.connect() when a key is missing.
    class DummySSH:
        def __init__(self, config):
            pass

        def __enter__(self):
            raise ConnectionError("SSH key file not found: /does/not/exist")

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("server_doctor.web.job_runner.SSHConnector", DummySSH)

    # manually create the job and execute runner logic synchronously
    job_id = runner._job_repo.create(sid)
    runner._run_scan(job_id, sid)

    job = runner._job_repo.get_by_id(job_id)
    assert job is not None
    assert job.status == "failed"
    assert "SSH key file not found" in (job.summary or "")

    logs = runner._log_repo.get_by_job_id(job_id)
    assert any("SSH key file not found" in log.message for log in logs)


def test_authentication_fails_and_logs_username(tmp_path, monkeypatch):
    """When SSH authentication fails using password the error is recorded
    succinctly and the initial connection log includes the username."""
    _setup_db(tmp_path)

    sid = ServerRepository().create(
        name="badauth", host="1.2.3.4", username="tester", password="x"
    )
    runner = ScanJobRunner()

    # stub SSHConnector to raise AuthException inside context manager
    class DummySSH:
        def __init__(self, config):
            pass
        def __enter__(self):
            from paramiko.ssh_exception import AuthenticationException
            raise AuthenticationException("Authentication failed")
        def __exit__(self, *args):
            pass

    monkeypatch.setattr("server_doctor.web.job_runner.SSHConnector", DummySSH)

    job_id = runner._job_repo.create(sid)
    runner._run_scan(job_id, sid)

    job = runner._job_repo.get_by_id(job_id)
    assert job is not None
    assert job.status == "failed"
    # message should not repeat itself: runner prefixes error with "Scan failed:"
    assert job.summary is not None
    assert job.summary.count("Authentication failed") == 1
    assert job.summary.startswith("Scan failed:")

    logs = runner._log_repo.get_by_job_id(job_id)
    # first log entry after queued should show username
    assert any("Connecting to tester@1.2.3.4:22" in log.message for log in logs)
    # error log should also contain the same human-friendly text
    assert any("Authentication failed" in log.message for log in logs)


def test_run_scan_forces_devops_checks(tmp_path, monkeypatch):
    """Web scan jobs must always run diagnosis with DevOps checks enabled."""
    _setup_db(tmp_path)
    sid = ServerRepository().create(name="okhost", host="127.0.0.1")
    runner = ScanJobRunner()

    class DummySSH:
        def __init__(self, config):
            pass

        def __enter__(self):
            return object()

        def __exit__(self, *args):
            pass

    class DummyResult:
        def __init__(self):
            self.findings = []
            self.score = 100
            self.topology_snapshot = {}
            self.trend = None
            self.ws_inventory = []
            self.suppressed_findings = []
            self.waiver_source = None

    class DummyDiagnosis:
        correlations = []

        def to_dict(self):
            return {}

    captured: dict[str, object] = {}

    def fake_run_full_scan(ssh, log_fn=None, repo_scan_paths=None):
        captured["repo_scan_paths"] = repo_scan_paths
        return object()

    def fake_run_full_diagnosis(model, ssh, **kwargs):
        captured["devops_enabled"] = kwargs.get("devops_enabled")
        return DummyResult()

    monkeypatch.setattr("server_doctor.web.job_runner.SSHConnector", DummySSH)
    monkeypatch.setattr("server_doctor.pipeline.run_full_scan", fake_run_full_scan)
    monkeypatch.setattr("server_doctor.pipeline.run_full_diagnosis", fake_run_full_diagnosis)
    monkeypatch.setattr("server_doctor.web.job_runner.generate_diagnosis", lambda **kwargs: DummyDiagnosis())
    monkeypatch.setattr(runner, "_generate_report", lambda *args, **kwargs: "dummy-report.html")

    job_id = runner._job_repo.create(sid)
    runner._run_scan(job_id, sid, repo_scan_paths="/var/www")

    job = runner._job_repo.get_by_id(job_id)
    assert job is not None
    assert job.status == "success"
    assert captured.get("devops_enabled") is True
    assert captured.get("repo_scan_paths") == "/var/www"


def test_run_scan_passes_stored_key_passphrase(tmp_path, monkeypatch):
    _setup_db(tmp_path)
    sid = ServerRepository().create(
        name="keyhost",
        host="127.0.0.1",
        username="deploy",
        key_path=str(tmp_path / "id_ed25519"),
        key_passphrase_secret_ref="key-ref",
        key_passphrase_storage="keyring",
    )
    (tmp_path / "id_ed25519").write_text("dummy-key")
    runner = ScanJobRunner()
    captured: dict[str, object] = {}

    class DummySSH:
        def __init__(self, config):
            captured["passphrase"] = config.passphrase

        def __enter__(self):
            return object()

        def __exit__(self, *args):
            pass

    class DummyResult:
        findings = []
        score = 100
        topology_snapshot = {}
        trend = None
        ws_inventory = []
        suppressed_findings = []
        waiver_source = None

    class DummyDiagnosis:
        correlations = []

        def to_dict(self):
            return {}

    monkeypatch.setattr("server_doctor.web.job_runner.SSHConnector", DummySSH)
    monkeypatch.setattr(
        "server_doctor.web.job_runner.get_server_key_passphrase",
        lambda ref: "unlock-me",
    )
    monkeypatch.setattr("server_doctor.pipeline.run_full_scan", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        "server_doctor.pipeline.run_full_diagnosis",
        lambda *args, **kwargs: DummyResult(),
    )
    monkeypatch.setattr(
        "server_doctor.web.job_runner.generate_diagnosis",
        lambda **kwargs: DummyDiagnosis(),
    )
    monkeypatch.setattr(runner, "_generate_report", lambda *args, **kwargs: "dummy-report.html")

    job_id = runner._job_repo.create(sid)
    runner._run_scan(job_id, sid)

    assert captured["passphrase"] == "unlock-me"


def test_run_scan_one_time_key_passphrase_overrides_stored(tmp_path, monkeypatch):
    _setup_db(tmp_path)
    sid = ServerRepository().create(
        name="keyhost",
        host="127.0.0.1",
        key_path=str(tmp_path / "id_ed25519"),
        key_passphrase_secret_ref="key-ref",
        key_passphrase_storage="keyring",
    )
    (tmp_path / "id_ed25519").write_text("dummy-key")
    runner = ScanJobRunner()
    captured: dict[str, object] = {}

    class DummySSH:
        def __init__(self, config):
            captured["passphrase"] = config.passphrase

        def __enter__(self):
            return object()

        def __exit__(self, *args):
            pass

    class DummyResult:
        findings = []
        score = 100
        topology_snapshot = {}
        trend = None
        ws_inventory = []
        suppressed_findings = []
        waiver_source = None

    class DummyDiagnosis:
        correlations = []

        def to_dict(self):
            return {}

    monkeypatch.setattr("server_doctor.web.job_runner.SSHConnector", DummySSH)
    monkeypatch.setattr(
        "server_doctor.web.job_runner.get_server_key_passphrase",
        lambda ref: "stored-passphrase",
    )
    monkeypatch.setattr("server_doctor.pipeline.run_full_scan", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        "server_doctor.pipeline.run_full_diagnosis",
        lambda *args, **kwargs: DummyResult(),
    )
    monkeypatch.setattr(
        "server_doctor.web.job_runner.generate_diagnosis",
        lambda **kwargs: DummyDiagnosis(),
    )
    monkeypatch.setattr(runner, "_generate_report", lambda *args, **kwargs: "dummy-report.html")

    job_id = runner._job_repo.create(sid)
    runner._run_scan(job_id, sid, one_time_key_passphrase="one-time")

    assert captured["passphrase"] == "one-time"
