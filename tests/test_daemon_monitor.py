from __future__ import annotations

from server_doctor.daemon.monitor import MonitoringDaemon


def test_daemon_state_persists_runtime_fields(tmp_path):
    pid_file = str(tmp_path / "daemon.pid")

    daemon = MonitoringDaemon(pid_file=pid_file, interval=900, servers=["app-1"])
    daemon.started_at = "2026-03-04T10:00:00"
    daemon.last_scan = "2026-03-04T10:05:00"
    daemon.next_scan = "2026-03-04T10:20:00"
    daemon.scan_count = 3
    daemon.error_count = 1
    daemon.history = [
        {
            "timestamp": "2026-03-04T10:05:00",
            "server": "app-1",
            "status": "success",
            "new_findings": 2,
            "resolved_findings": 1,
            "findings_total": 5,
        }
    ]
    daemon._save_state()

    reloaded = MonitoringDaemon(pid_file=pid_file)
    info = reloaded.get_info()
    assert info["started_at"] == "2026-03-04T10:00:00"
    assert info["last_scan"] == "2026-03-04T10:05:00"
    assert info["next_scan"] == "2026-03-04T10:20:00"
    assert info["scan_count"] == 3
    assert info["error_count"] == 1
    assert info["interval"] == 900
    assert info["servers"] == ["app-1"]


def test_daemon_history_returns_recent_first(tmp_path):
    pid_file = str(tmp_path / "daemon.pid")
    daemon = MonitoringDaemon(pid_file=pid_file)
    daemon.history = [
        {"timestamp": "2026-03-04T10:00:00", "server": "a", "status": "success"},
        {"timestamp": "2026-03-04T10:10:00", "server": "b", "status": "error", "message": "timeout"},
    ]
    daemon._save_state()

    reloaded = MonitoringDaemon(pid_file=pid_file)
    events = reloaded.get_history(limit=1)
    assert len(events) == 1
    assert events[0]["server"] == "b"
    assert events[0]["status"] == "error"
