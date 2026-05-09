"""Scan history and trend diff support."""

from __future__ import annotations

import json
import re
from pathlib import Path

from server_doctor.model.finding import Finding
from server_doctor.engine.topology import diff_topology


class ScanHistoryStore:
    """Persists and compares scan snapshots per host."""

    def __init__(self, base_dir: str | Path | None = None, max_scans: int = 50) -> None:
        if base_dir is None:
            base_dir = Path.home() / ".server-doctor" / "history"
        self.base_dir = Path(base_dir).expanduser()
        self.max_scans = max_scans

    def compute_trend(
        self,
        host: str,
        findings: list[Finding],
        current_score: int,
        timestamp: str,
        current_topology: dict | None = None,
    ) -> dict:
        """Compute trend diff vs latest stored snapshot (without writing)."""
        latest = self.load_latest(host)
        current_items = self._serialize_findings(findings)
        current_by_key = {item["key"]: item for item in current_items}

        if not latest:
            return {
                "has_previous": False,
                "previous_timestamp": None,
                "current_timestamp": timestamp,
                "previous_score": None,
                "current_score": current_score,
                "score_delta": None,
                "new_findings": [],
                "resolved_findings": [],
                "topology_diff": diff_topology(None, current_topology) if current_topology is not None else None,
            }

        previous_items = latest.get("findings", [])
        previous_by_key = {item.get("key"): item for item in previous_items if item.get("key")}

        new_keys = sorted(set(current_by_key.keys()) - set(previous_by_key.keys()))
        resolved_keys = sorted(set(previous_by_key.keys()) - set(current_by_key.keys()))

        previous_score = int(latest.get("score", 0))
        return {
            "has_previous": True,
            "previous_timestamp": latest.get("timestamp"),
            "current_timestamp": timestamp,
            "previous_score": previous_score,
            "current_score": current_score,
            "score_delta": current_score - previous_score,
            "new_findings": [current_by_key[k] for k in new_keys],
            "resolved_findings": [previous_by_key[k] for k in resolved_keys],
            "topology_diff": (
                diff_topology(
                    latest.get("topology") if isinstance(latest.get("topology"), dict) else None,
                    current_topology,
                )
                if current_topology is not None
                else None
            ),
        }

    def append_scan(
        self,
        host: str,
        findings: list[Finding],
        score: int,
        timestamp: str,
        topology: dict | None = None,
    ) -> None:
        """Append current snapshot to host history."""
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            path = self._host_path(host)
            payload = self._load_payload(path)
            scans = payload.get("scans", [])
            entry = {
                "timestamp": timestamp,
                "score": int(score),
                "findings": self._serialize_findings(findings),
            }
            if topology is not None:
                entry["topology"] = topology
            scans.append(entry)
            payload["host"] = host
            payload["scans"] = scans[-self.max_scans :]
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            # Trend persistence must never break diagnosis flow.
            return

    def load_latest(self, host: str) -> dict | None:
        """Load latest snapshot for a host."""
        try:
            payload = self._load_payload(self._host_path(host))
            scans = payload.get("scans", [])
            if not scans:
                return None
            return scans[-1]
        except Exception:
            return None

    def _host_path(self, host: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", host.strip()) or "unknown-host"
        return self.base_dir / f"{safe}.json"

    @staticmethod
    def _load_payload(path: Path) -> dict:
        if not path.exists():
            return {"scans": []}
        return json.loads(path.read_text(encoding="utf-8"))

    def _serialize_findings(self, findings: list[Finding]) -> list[dict]:
        out: list[dict] = []
        for finding in findings:
            rule = finding.id.split("-")[0].upper()
            key = self._finding_key(rule, finding.condition)
            out.append(
                {
                    "key": key,
                    "id": finding.id,
                    "rule": rule,
                    "severity": finding.severity.value.upper(),
                    "condition": finding.condition,
                }
            )
        return out

    @staticmethod
    def _finding_key(rule: str, condition: str) -> str:
        normalized = " ".join(condition.strip().lower().split())
        return f"{rule}::{normalized}"
