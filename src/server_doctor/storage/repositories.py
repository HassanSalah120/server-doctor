"""Repository classes for CRUD operations on the storage layer.

All writes use explicit transactions. Read operations return
typed dataclass records.
"""

import json
import sqlite3
from datetime import datetime
from typing import Any

from server_doctor.storage.db import get_db
from server_doctor.storage.models import (
    AcceptedRiskRecord,
    CorrelationRecord,
    FindingRecord,
    FixAttemptRecord,
    JobLogRecord,
    LifecycleEventRecord,
    ScanJobRecord,
    ServerRecord,
)

_UNSET = object()


class ServerRepository:
    """CRUD operations for the servers table."""

    def create(
        self,
        name: str,
        host: str,
        port: int = 22,
        username: str = "root",
        password: str | None = None,
        password_secret_ref: str | None = None,
        password_storage: str = "legacy",
        key_path: str | None = None,
        key_passphrase_secret_ref: str | None = None,
        key_passphrase_storage: str = "none",
        tags: str = "",
    ) -> int:
        """Insert a new server record. Returns the new server ID."""
        db = get_db()
        cursor = db.execute(
            """INSERT INTO servers (
                   name, host, port, username, password, password_secret_ref,
                   password_storage, key_path, key_passphrase_secret_ref,
                   key_passphrase_storage, tags
               )
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                name,
                host,
                port,
                username,
                password,
                password_secret_ref,
                password_storage,
                key_path,
                key_passphrase_secret_ref,
                key_passphrase_storage,
                tags,
            ),
        )
        db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def get_all(self) -> list[ServerRecord]:
        """Return all servers ordered by creation date descending."""
        db = get_db()
        rows = db.execute(
            "SELECT * FROM servers ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_by_id(self, server_id: int) -> ServerRecord | None:
        """Return a server by ID, or None if not found."""
        db = get_db()
        row = db.execute(
            "SELECT * FROM servers WHERE id = ?", (server_id,)
        ).fetchone()
        return self._row_to_record(row) if row else None

    def delete(self, server_id: int) -> bool:
        """Delete a server by ID. Returns True if a row was deleted.

        If the server has dependent rows (scan jobs) the underlying
        SQLite engine will raise an :class:`sqlite3.IntegrityError` because
        of the foreign key constraint.  We catch that here and simply
        return ``False`` so callers can decide how to handle it.
        """
        db = get_db()
        try:
            db.execute("DELETE FROM accepted_risks WHERE server_id = ?", (server_id,))
            db.execute("DELETE FROM finding_lifecycle_events WHERE server_id = ?", (server_id,))
            cursor = db.execute("DELETE FROM servers WHERE id = ?", (server_id,))
            db.commit()
            return cursor.rowcount > 0
        except sqlite3.IntegrityError:
            # foreign key violation – dependent scan jobs exist
            return False

    def update(
        self,
        server_id: int,
        *,
        name: str | None = None,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: Any = _UNSET,
        password_secret_ref: Any = _UNSET,
        password_storage: str | None = None,
        key_path: Any = _UNSET,
        key_passphrase_secret_ref: Any = _UNSET,
        key_passphrase_storage: str | None = None,
        tags: str | None = None,
    ) -> bool:
        """Update a server record. Returns True if a row was updated.

        Notes:
            - Passing password=None will clear the stored password.
            - Passing key_path=None will clear the stored key path.
        """
        db = get_db()
        updates: list[str] = []
        params: list[Any] = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if host is not None:
            updates.append("host = ?")
            params.append(host)
        if port is not None:
            updates.append("port = ?")
            params.append(port)
        if username is not None:
            updates.append("username = ?")
            params.append(username)
        if password is not _UNSET:
            updates.append("password = ?")
            params.append(password)
        if password_secret_ref is not _UNSET:
            updates.append("password_secret_ref = ?")
            params.append(password_secret_ref)
        if password_storage is not None:
            updates.append("password_storage = ?")
            params.append(password_storage)
        if key_path is not _UNSET:
            updates.append("key_path = ?")
            params.append(key_path)
        if key_passphrase_secret_ref is not _UNSET:
            updates.append("key_passphrase_secret_ref = ?")
            params.append(key_passphrase_secret_ref)
        if key_passphrase_storage is not None:
            updates.append("key_passphrase_storage = ?")
            params.append(key_passphrase_storage)
        if tags is not None:
            updates.append("tags = ?")
            params.append(tags)

        if not updates:
            return False

        params.append(server_id)
        cursor = db.execute(
            f"UPDATE servers SET {', '.join(updates)} WHERE id = ?",
            params,
        )
        db.commit()
        return cursor.rowcount > 0

    @staticmethod
    def _row_to_record(row: Any) -> ServerRecord:
        row_map = dict(row)
        return ServerRecord(
            id=row["id"],
            name=row["name"],
            host=row["host"],
            port=row["port"],
            username=row["username"],
            password=row_map.get("password"),
            password_secret_ref=row_map.get("password_secret_ref"),
            password_storage=row_map.get("password_storage", "legacy") or "legacy",
            key_path=row["key_path"],
            key_passphrase_secret_ref=row_map.get("key_passphrase_secret_ref"),
            key_passphrase_storage=row_map.get("key_passphrase_storage", "none")
            or "none",
            tags=row["tags"] or "",
            created_at=row["created_at"] or "",
        )

class ScanJobRepository:
    """CRUD operations for the scan_jobs table."""

    def create(self, server_id: int, repo_scan_paths: str | None = None) -> int:
        """Create a new scan job with status=queued. Returns job ID."""
        db = get_db()
        cursor = db.execute(
            "INSERT INTO scan_jobs (server_id, repo_scan_paths, status) VALUES (?, ?, 'queued')",
            (server_id, repo_scan_paths),
        )
        db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def delete_by_server_id(self, server_id: int) -> int:
        """Delete all jobs tied to a specific server and return count.

        Because other tables (findings, job_logs, correlations) have
        foreign keys pointing to scan_jobs.id we must remove their
        rows first or SQLite will raise an IntegrityError.  This method
        therefore performs a simple manual cascade.
        """
        db = get_db()
        # fetch affected job ids
        rows = db.execute(
            "SELECT id FROM scan_jobs WHERE server_id = ?", (server_id,)
        ).fetchall()
        job_ids = [r["id"] for r in rows]
        if job_ids:
            # delete child tables
            placeholders = ",".join("?" for _ in job_ids)
            db.execute(f"DELETE FROM findings WHERE job_id IN ({placeholders})", job_ids)
            db.execute(f"DELETE FROM job_logs WHERE job_id IN ({placeholders})", job_ids)
            db.execute(f"DELETE FROM correlations WHERE job_id IN ({placeholders})", job_ids)
            db.execute(f"DELETE FROM fix_attempts WHERE job_id IN ({placeholders})", job_ids)
            db.execute(
                f"DELETE FROM finding_lifecycle_events WHERE job_id IN ({placeholders})",
                job_ids,
            )
            # finally delete jobs themselves
            cursor = db.execute(
                "DELETE FROM scan_jobs WHERE server_id = ?", (server_id,)
            )
            db.commit()
            return cursor.rowcount or 0
        return 0

    def update_status(
        self,
        job_id: int,
        status: str | None = None,
        *,
        score: int | None = None,
        summary: str | None = None,
        diagnosis_json: str | None = None,
        raw_report_path: str | None = None,
        error_message: str | None = None,
        progress: int | None = None,
        model_json: str | None = None,
        phases_json: str | None = None,
    ) -> None:
        """Update job status and optional result fields."""
        db = get_db()
        now = datetime.now().isoformat()

        updates = []
        params: list[Any] = []

        if status is not None:
            updates.append("status = ?")
            params.append(status)
            if status == "running":
                updates.append("started_at = ?")
                params.append(now)
            if status in ("success", "failed", "cancelled"):
                updates.append("finished_at = ?")
                params.append(now)

        if score is not None:
            updates.append("score = ?")
            params.append(score)
        if summary is not None:
            updates.append("summary = ?")
            params.append(summary)
        if diagnosis_json is not None:
            updates.append("diagnosis_json = ?")
            params.append(diagnosis_json)
        if raw_report_path is not None:
            updates.append("raw_report_path = ?")
            params.append(raw_report_path)
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if progress is not None:
            updates.append("progress = ?")
            params.append(progress)
        if model_json is not None:
            updates.append("model_json = ?")
            params.append(model_json)
        if phases_json is not None:
            updates.append("phases_json = ?")
            params.append(phases_json)

        if not updates:
            return

        params.append(job_id)
        db.execute(
            f"UPDATE scan_jobs SET {', '.join(updates)} WHERE id = ?",
            params,
        )
        db.commit()

    def get_all(self, limit: int = 50) -> list[ScanJobRecord]:
        """Return all jobs with server info, most recent first."""
        db = get_db()
        rows = db.execute(
            """SELECT j.*, s.name as server_name, s.host as server_host
               FROM scan_jobs j
               LEFT JOIN servers s ON j.server_id = s.id
               ORDER BY j.created_at DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_by_id(self, job_id: int) -> ScanJobRecord | None:
        """Return a job by ID with server info, or None."""
        db = get_db()
        row = db.execute(
            """SELECT j.*, s.name as server_name, s.host as server_host
               FROM scan_jobs j
               LEFT JOIN servers s ON j.server_id = s.id
               WHERE j.id = ?""",
            (job_id,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def get_by_server_id(self, server_id: int, limit: int = 10) -> list[ScanJobRecord]:
        """Return jobs for a specific server."""
        db = get_db()
        rows = db.execute(
            """SELECT j.*, s.name as server_name, s.host as server_host
               FROM scan_jobs j
               LEFT JOIN servers s ON j.server_id = s.id
               WHERE j.server_id = ?
               ORDER BY j.created_at DESC
               LIMIT ?""",
            (server_id, limit),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_latest_job(self) -> ScanJobRecord | None:
        """Return the most recent scan job."""
        db = get_db()
        row = db.execute(
            """SELECT j.*, s.name as server_name, s.host as server_host
               FROM scan_jobs j
               LEFT JOIN servers s ON j.server_id = s.id
               ORDER BY j.created_at DESC
               LIMIT 1""",
        ).fetchone()
        return self._row_to_record(row) if row else None

    @staticmethod
    def _row_to_record(row: Any) -> ScanJobRecord:
        row_map = dict(row)
        return ScanJobRecord(
            id=row["id"],
            server_id=row["server_id"],
            repo_scan_paths=row_map.get("repo_scan_paths"),
            status=row["status"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            score=row["score"],
            summary=row["summary"],
            diagnosis_json=row["diagnosis_json"],
            raw_report_path=row["raw_report_path"],
            error_message=row["error_message"],
            progress=row["progress"],
            model_json=row_map.get("model_json"),
            phases_json=row_map.get("phases_json", "[]"),
            created_at=row["created_at"] or "",
            server_name=row_map.get("server_name"),
            server_host=row_map.get("server_host"),
        )


class FindingRepository:
    """CRUD operations for the findings table."""

    def bulk_insert(self, job_id: int, findings: list[dict[str, Any]]) -> None:
        """Insert multiple finding records in a single transaction.

        Each dict should have: rule_id, severity, title, category,
        component, description, evidence_ref, evidence_json, recommendation.
        """
        db = get_db()
        db.executemany(
            """INSERT INTO findings (job_id, rule_id, category, component, severity, title,
                                     description, evidence_ref, evidence_json, recommendation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    job_id,
                    f.get("rule_id", "unknown"),
                    f.get("category"),
                    f.get("component"),
                    f.get("severity", "info"),
                    f.get("title", ""),
                    f.get("description"),
                    f.get("evidence_ref"),
                    f.get("evidence_json"),
                    f.get("recommendation"),
                )
                for f in findings
            ],
        )
        db.commit()

    def get_by_job_id(self, job_id: int) -> list[FindingRecord]:
        """Return all findings for a job."""
        db = get_db()
        rows = db.execute(
            "SELECT * FROM findings WHERE job_id = ? ORDER BY id",
            (job_id,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_by_id(self, finding_id: int) -> FindingRecord | None:
        """Return a finding by ID, or None if not found."""
        db = get_db()
        row = db.execute(
            "SELECT * FROM findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def get_by_severity(
        self, severity: str, job_id: int | None = None
    ) -> list[FindingRecord]:
        """Return findings filtered by severity, optionally by job."""
        db = get_db()
        if job_id is not None:
            rows = db.execute(
                "SELECT * FROM findings WHERE severity = ? AND job_id = ? ORDER BY id",
                (severity, job_id),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM findings WHERE severity = ? ORDER BY id",
                (severity,),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: Any) -> FindingRecord:
        return FindingRecord(
            id=row["id"],
            job_id=row["job_id"],
            rule_id=row["rule_id"],
            category=row["category"],
            component=row["component"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            evidence_ref=row["evidence_ref"],
            evidence_json=row["evidence_json"],
            recommendation=row["recommendation"],
            created_at=row["created_at"] or "",
        )


class JobLogRepository:
    """Append-only log storage for job progress."""

    def append(self, job_id: int, message: str) -> None:
        """Append a log message for a job."""
        db = get_db()
        db.execute(
            "INSERT INTO job_logs (job_id, message) VALUES (?, ?)",
            (job_id, message),
        )
        db.commit()

    def get_by_job_id(self, job_id: int, after_id: int = 0) -> list[JobLogRecord]:
        """Return logs for a job, optionally only those after a given ID.

        The after_id parameter supports efficient polling — clients can
        pass the last seen log ID to only get new entries.
        """
        db = get_db()
        rows = db.execute(
            "SELECT * FROM job_logs WHERE job_id = ? AND id > ? ORDER BY id",
            (job_id, after_id),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: Any) -> JobLogRecord:
        return JobLogRecord(
            id=row["id"],
            job_id=row["job_id"],
            timestamp=row["timestamp"] or "",
            message=row["message"],
        )


class CorrelationRepository:
    """CRUD operations for the correlations table."""

    def bulk_insert(self, job_id: int, correlations: list[dict[str, Any]]) -> None:
        """Insert multiple correlation records.

        Each dict should have: correlation_id, root_cause_hypothesis,
        blast_radius, confidence, supporting_rule_ids (list), fix_bundle (list).
        """
        db = get_db()
        db.executemany(
            """INSERT INTO correlations (job_id, correlation_id, root_cause_hypothesis,
                                         blast_radius, confidence, supporting_rule_ids,
                                         fix_bundle_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    job_id,
                    c.get("correlation_id", "unknown"),
                    c.get("root_cause_hypothesis"),
                    c.get("blast_radius"),
                    c.get("confidence", 0.0),
                    json.dumps(_normalize_supporting_rule_ids(c.get("supporting_rule_ids", []))),
                    json.dumps(c.get("fix_bundle", [])),
                )
                for c in correlations
            ],
        )
        db.commit()

    def get_by_job_id(self, job_id: int) -> list[CorrelationRecord]:
        """Return all correlations for a job."""
        db = get_db()
        rows = db.execute(
            "SELECT * FROM correlations WHERE job_id = ? ORDER BY id",
            (job_id,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: Any) -> CorrelationRecord:
        return CorrelationRecord(
            id=row["id"],
            job_id=row["job_id"],
            correlation_id=row["correlation_id"],
            root_cause_hypothesis=row["root_cause_hypothesis"],
            blast_radius=row["blast_radius"],
            confidence=row["confidence"],
            supporting_rule_ids=_normalize_supporting_rule_ids(row["supporting_rule_ids"]),
            fix_bundle_json=row["fix_bundle_json"],
            created_at=row["created_at"] or "",
        )


def _normalize_supporting_rule_ids(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(v) for v in parsed if str(v).strip()]
        except json.JSONDecodeError:
            pass
        return [part.strip() for part in text.split(",") if part.strip()]
    return [str(value)]


class FixAttemptRepository:
    """CRUD operations for validation/fix attempt history."""

    def create(
        self,
        *,
        finding_id: int,
        job_id: int,
        server_id: int,
        rule_id: str,
        action: str,
        status: str,
        command: str | None = None,
        expected: str | None = None,
        observed: str | None = None,
        error: str | None = None,
    ) -> int:
        db = get_db()
        cursor = db.execute(
            """INSERT INTO fix_attempts (
                   finding_id, job_id, server_id, rule_id, action, status,
                   command, expected, observed, error
               )
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id,
                job_id,
                server_id,
                rule_id,
                action,
                status,
                command,
                expected,
                observed,
                error,
            ),
        )
        db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def get_by_finding_id(self, finding_id: int) -> list[FixAttemptRecord]:
        db = get_db()
        rows = db.execute(
            "SELECT * FROM fix_attempts WHERE finding_id = ? ORDER BY id DESC",
            (finding_id,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: Any) -> FixAttemptRecord:
        return FixAttemptRecord(
            id=row["id"],
            finding_id=row["finding_id"],
            job_id=row["job_id"],
            server_id=row["server_id"],
            rule_id=row["rule_id"],
            action=row["action"],
            status=row["status"],
            command=row["command"],
            expected=row["expected"],
            observed=row["observed"],
            error=row["error"],
            created_at=row["created_at"] or "",
        )


class AcceptedRiskRepository:
    """CRUD operations for accepted-risk baseline entries."""

    def create(
        self,
        *,
        server_id: int,
        rule_id: str,
        reason: str,
        finding_title: str | None = None,
        accepted_by: str = "local-user",
        expires_at: str | None = None,
    ) -> int:
        db = get_db()
        cursor = db.execute(
            """INSERT INTO accepted_risks (
                   server_id, rule_id, finding_title, reason, accepted_by, expires_at
               )
               VALUES (?, ?, ?, ?, ?, ?)""",
            (server_id, rule_id, finding_title, reason, accepted_by, expires_at),
        )
        db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def get_by_server_id(self, server_id: int) -> list[AcceptedRiskRecord]:
        db = get_db()
        rows = db.execute(
            "SELECT * FROM accepted_risks WHERE server_id = ? ORDER BY id DESC",
            (server_id,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def is_accepted(
        self,
        *,
        server_id: int,
        rule_id: str,
        finding_title: str | None = None,
    ) -> bool:
        db = get_db()
        row = db.execute(
            """SELECT id FROM accepted_risks
               WHERE server_id = ?
                 AND rule_id = ?
                 AND (expires_at IS NULL OR expires_at >= date('now'))
                 AND (finding_title IS NULL OR finding_title = ?)
               LIMIT 1""",
            (server_id, rule_id, finding_title),
        ).fetchone()
        return row is not None

    @staticmethod
    def _row_to_record(row: Any) -> AcceptedRiskRecord:
        return AcceptedRiskRecord(
            id=row["id"],
            server_id=row["server_id"],
            rule_id=row["rule_id"],
            finding_title=row["finding_title"],
            reason=row["reason"],
            accepted_by=row["accepted_by"],
            expires_at=row["expires_at"],
            created_at=row["created_at"] or "",
        )


class LifecycleEventRepository:
    """Append-only finding lifecycle event storage."""

    def create(
        self,
        *,
        server_id: int,
        finding_fingerprint: str,
        rule_id: str,
        event_type: str,
        source: str,
        job_id: int | None = None,
        target: str | None = None,
        details: dict[str, Any] | None = None,
        idempotent: bool = False,
    ) -> int:
        db = get_db()
        details_json = json.dumps(details or {}, default=str)
        if idempotent:
            row = db.execute(
                """SELECT id FROM finding_lifecycle_events
                   WHERE server_id = ?
                     AND COALESCE(job_id, -1) = COALESCE(?, -1)
                     AND finding_fingerprint = ?
                     AND event_type = ?
                   LIMIT 1""",
                (server_id, job_id, finding_fingerprint, event_type),
            ).fetchone()
            if row:
                return int(row["id"])

        cursor = db.execute(
            """INSERT INTO finding_lifecycle_events (
                   server_id, job_id, finding_fingerprint, rule_id, target,
                   event_type, source, details_json
               )
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                server_id,
                job_id,
                finding_fingerprint,
                rule_id,
                target,
                event_type,
                source,
                details_json,
            ),
        )
        db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def get_by_fingerprint(
        self,
        server_id: int,
        finding_fingerprint: str,
    ) -> list[LifecycleEventRecord]:
        db = get_db()
        rows = db.execute(
            """SELECT * FROM finding_lifecycle_events
               WHERE server_id = ? AND finding_fingerprint = ?
               ORDER BY created_at, id""",
            (server_id, finding_fingerprint),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_by_server_id(self, server_id: int) -> list[LifecycleEventRecord]:
        db = get_db()
        rows = db.execute(
            """SELECT * FROM finding_lifecycle_events
               WHERE server_id = ?
               ORDER BY created_at, id""",
            (server_id,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: Any) -> LifecycleEventRecord:
        return LifecycleEventRecord(
            id=row["id"],
            server_id=row["server_id"],
            job_id=row["job_id"],
            finding_fingerprint=row["finding_fingerprint"],
            rule_id=row["rule_id"],
            target=row["target"],
            event_type=row["event_type"],
            source=row["source"],
            details_json=row["details_json"] or "{}",
            created_at=row["created_at"] or "",
        )
