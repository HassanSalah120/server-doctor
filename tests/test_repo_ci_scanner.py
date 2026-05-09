"""Tests for RepoCIScanner dependency-manager detection and upgrade probes."""

from unittest.mock import MagicMock

from server_doctor.connector.ssh import CommandResult
from server_doctor.scanner.repo_ci import RepoCIScanner


def _result(command: str, stdout: str = "", stderr: str = "", exit_code: int = 0) -> CommandResult:
    return CommandResult(command=command, stdout=stdout, stderr=stderr, exit_code=exit_code)


def test_repo_ci_scanner_detects_npm_and_parses_outdated(mock_ssh_connector):
    scanner = RepoCIScanner(mock_ssh_connector)

    mock_ssh_connector.dir_exists.side_effect = lambda p: p in {"/repo"}
    mock_ssh_connector.file_exists.side_effect = lambda p: p in {"/repo/package.json"}
    mock_ssh_connector.list_dir.side_effect = lambda p: [] if p != "/repo" else ["package.json"]

    def run_side_effect(cmd, **kwargs):
        if cmd.startswith("find '/repo'"):
            return _result(cmd, "/repo/package.json\n/repo/package-lock.json\n")
        if "command -v npm" in cmd:
            return _result(cmd)
        if cmd.startswith("cd '/repo' && npm outdated --json"):
            return _result(
                cmd,
                stdout='{"express":{"current":"4.18.0","wanted":"4.21.2","latest":"5.1.0"},'
                '"dotenv":{"current":"16.0.0","wanted":"16.6.1","latest":"17.2.3"}}',
                exit_code=1,  # npm returns non-zero when outdated packages exist
            )
        if cmd.startswith("cd '/repo' && npm audit --omit=dev --json"):
            return _result(
                cmd,
                stdout=(
                    '{"metadata":{"vulnerabilities":{"info":0,"low":2,"moderate":3,'
                    '"high":5,"critical":0,"total":10}},'
                    '"vulnerabilities":{"lodash":{},"express":{}}}'
                ),
                exit_code=1,  # npm audit returns 1 when vulnerabilities are found
            )
        return _result(cmd, exit_code=1)

    mock_ssh_connector.run.side_effect = run_side_effect

    model = scanner.scan(["/repo"])
    assert model.repos
    repo = model.repos[0]
    npm_rows = [row for row in repo.dependency_managers if row.manager == "npm"]
    assert npm_rows
    npm = npm_rows[0]
    assert npm.status == "checked"
    assert npm.outdated_count == 2
    assert "express" in npm.sample
    assert npm.vulnerability_count == 10
    assert "high=5" in (npm.vulnerability_summary or "")


def test_repo_ci_scanner_marks_unavailable_and_unsupported_tools(mock_ssh_connector):
    scanner = RepoCIScanner(mock_ssh_connector)

    mock_ssh_connector.dir_exists.side_effect = lambda p: p in {"/repo2"}
    mock_ssh_connector.file_exists.side_effect = lambda p: p in {"/repo2/composer.json", "/repo2/build.xml"}
    mock_ssh_connector.list_dir.side_effect = lambda p: [] if p != "/repo2" else ["composer.json", "build.xml"]

    def run_side_effect(cmd, **kwargs):
        if cmd.startswith("find '/repo2'"):
            return _result(cmd, "/repo2/composer.json\n/repo2/build.xml\n")
        if "command -v composer" in cmd:
            return _result(cmd, exit_code=1)
        return _result(cmd, exit_code=1)

    mock_ssh_connector.run.side_effect = run_side_effect

    model = scanner.scan(["/repo2"])
    repo = model.repos[0]
    by_manager = {row.manager: row for row in repo.dependency_managers}

    assert by_manager["composer"].status == "unavailable"
    assert by_manager["ant"].status == "unsupported"


def test_repo_ci_scanner_respects_dependency_checks_flag(monkeypatch, mock_ssh_connector):
    monkeypatch.setenv("server_doctor_DEPENDENCY_CHECKS", "0")
    scanner = RepoCIScanner(mock_ssh_connector)

    mock_ssh_connector.dir_exists.side_effect = lambda p: p in {"/repo3"}
    mock_ssh_connector.file_exists.side_effect = lambda p: p in {"/repo3/package.json"}
    mock_ssh_connector.list_dir.side_effect = lambda p: [] if p != "/repo3" else ["package.json"]
    mock_ssh_connector.run.side_effect = lambda cmd, **kwargs: _result(
        cmd,
        "/repo3/package.json\n" if cmd.startswith("find '/repo3'") else "",
    )

    model = scanner.scan(["/repo3"])
    npm = next(row for row in model.repos[0].dependency_managers if row.manager == "npm")
    assert npm.status == "detected"
    assert npm.outdated_count is None


def test_repo_ci_scanner_parent_path_autodiscovery_does_not_error(mock_ssh_connector):
    scanner = RepoCIScanner(mock_ssh_connector)

    def dir_exists_side_effect(path):
        return path in {"/parent", "/parent/app1"}

    def file_exists_side_effect(path):
        return path in {"/parent/app1/package.json"}

    def list_dir_side_effect(path):
        if path == "/parent":
            return ["app1"]
        if path == "/parent/app1":
            return ["package.json"]
        return []

    def run_side_effect(cmd, **kwargs):
        if cmd.startswith("find '/parent/app1'"):
            return _result(cmd, "/parent/app1/package.json\n")
        if "command -v npm" in cmd:
            return _result(cmd, exit_code=1)
        return _result(cmd)

    mock_ssh_connector.dir_exists.side_effect = dir_exists_side_effect
    mock_ssh_connector.file_exists.side_effect = file_exists_side_effect
    mock_ssh_connector.list_dir.side_effect = list_dir_side_effect
    mock_ssh_connector.run.side_effect = run_side_effect

    model = scanner.scan(["/parent"])
    assert model.errors == []
    assert model.repos
    assert model.repos[0].path == "/parent/app1"
    assert any("Auto-discovered 1 repos in /parent" in note for note in model.notes)
