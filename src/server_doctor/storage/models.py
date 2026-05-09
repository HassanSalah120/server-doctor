"""Data models and schema DDL for the storage layer.

Provides dataclass records for each table and the DDL constants
used by db.py to initialize the database.
"""

from dataclasses import dataclass, field
from typing import Any

# ─── Schema DDL ────────────────────────────────────────────────────────────────

SCHEMA_SERVERS = """
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT 'root',
    password TEXT,
    password_secret_ref TEXT,
    password_storage TEXT DEFAULT 'legacy',
    key_path TEXT,
    key_passphrase_secret_ref TEXT,
    key_passphrase_storage TEXT DEFAULT 'none',
    tags TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

SCHEMA_SCAN_JOBS = """
CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    repo_scan_paths TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    started_at TEXT,
    finished_at TEXT,
    score INTEGER,
    summary TEXT,
    diagnosis_json TEXT,
    raw_report_path TEXT,
    error_message TEXT,
    progress INTEGER NOT NULL DEFAULT 0,
    model_json TEXT,
    phases_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (server_id) REFERENCES servers(id)
);
"""

SCHEMA_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    category TEXT,
    component TEXT,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence_ref TEXT,
    evidence_json TEXT,
    recommendation TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
);
"""

SCHEMA_JOB_LOGS = """
CREATE TABLE IF NOT EXISTS job_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    message TEXT NOT NULL,
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
);
"""

SCHEMA_CORRELATIONS = """
CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    correlation_id TEXT NOT NULL,
    root_cause_hypothesis TEXT,
    blast_radius TEXT,
    confidence REAL,
    supporting_rule_ids TEXT,
    fix_bundle_json TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
);
"""

SCHEMA_FIX_ATTEMPTS = """
CREATE TABLE IF NOT EXISTS fix_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    job_id INTEGER NOT NULL,
    server_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'validate',
    status TEXT NOT NULL,
    command TEXT,
    expected TEXT,
    observed TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id),
    FOREIGN KEY (server_id) REFERENCES servers(id)
);
"""

SCHEMA_ACCEPTED_RISKS = """
CREATE TABLE IF NOT EXISTS accepted_risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    finding_title TEXT,
    reason TEXT NOT NULL,
    accepted_by TEXT NOT NULL DEFAULT 'local-user',
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (server_id) REFERENCES servers(id)
);
"""

SCHEMA_FINDING_LIFECYCLE_EVENTS = """
CREATE TABLE IF NOT EXISTS finding_lifecycle_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    job_id INTEGER,
    finding_fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    target TEXT,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    details_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (server_id) REFERENCES servers(id),
    FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
);
"""

ALL_SCHEMAS = [
    SCHEMA_SERVERS,
    SCHEMA_SCAN_JOBS,
    SCHEMA_FINDINGS,
    SCHEMA_JOB_LOGS,
    SCHEMA_CORRELATIONS,
    SCHEMA_FIX_ATTEMPTS,
    SCHEMA_ACCEPTED_RISKS,
    SCHEMA_FINDING_LIFECYCLE_EVENTS,
]


# ─── Record Dataclasses ───────────────────────────────────────────────────────


@dataclass
class ServerRecord:
    """A registered server."""

    id: int
    name: str
    host: str
    port: int = 22
    username: str = "root"
    password: str | None = None
    password_secret_ref: str | None = None
    password_storage: str = "legacy"
    key_path: str | None = None
    key_passphrase_secret_ref: str | None = None
    key_passphrase_storage: str = "none"
    tags: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password is not None or self.password_secret_ref is not None,
            "password_storage": self.password_storage,
            "key_path": self.key_path,
            "key_passphrase": self.key_passphrase_secret_ref is not None,
            "key_passphrase_storage": self.key_passphrase_storage,
            "tags": self.tags,
            "created_at": self.created_at,
        }


@dataclass
class ScanJobRecord:
    """A scan job entry."""

    id: int
    server_id: int
    repo_scan_paths: str | None = None
    status: str = "queued"
    started_at: str | None = None
    finished_at: str | None = None
    score: int | None = None
    summary: str | None = None
    diagnosis_json: str | None = None
    raw_report_path: str | None = None
    error_message: str | None = None
    progress: int = 0
    model_json: str | None = None
    phases_json: str | None = "[]"
    created_at: str = ""
    # Joined fields (optional, populated by repository)
    server_name: str | None = None
    server_host: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "server_id": self.server_id,
            "repo_scan_paths": self.repo_scan_paths,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "score": self.score,
            "summary": self.summary,
            "diagnosis_json": self.diagnosis_json,
            "raw_report_path": self.raw_report_path,
            "error_message": self.error_message,
            "progress": self.progress,
            "phases": self.phases,
            "created_at": self.created_at,
        }
        if self.server_name is not None:
            d["server_name"] = self.server_name
        if self.server_host is not None:
            d["server_host"] = self.server_host
        return d

    @property
    def phases(self) -> list[dict[str, Any]]:
        if not self.phases_json:
            return []
        try:
            parsed = __import__("json").loads(self.phases_json)
        except Exception:
            return []
        return parsed if isinstance(parsed, list) else []


@dataclass
class FindingRecord:
    """A stored finding from a scan job."""

    id: int
    job_id: int
    rule_id: str
    severity: str
    title: str
    category: str | None = None
    component: str | None = None
    description: str | None = None
    evidence_ref: str | None = None
    evidence_json: str | None = None
    recommendation: str | None = None
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "rule_id": self.rule_id,
            "category": self.category,
            "component": self.component,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence_ref": self.evidence_ref,
            "evidence_json": self.evidence_json,
            "recommendation": self.recommendation,
            "created_at": self.created_at,
        }


@dataclass
class JobLogRecord:
    """A log entry for a job."""

    id: int
    job_id: int
    timestamp: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "timestamp": self.timestamp,
            "message": self.message,
        }


@dataclass
class CorrelationRecord:
    """A synthesized finding / root cause analysis."""

    id: int
    job_id: int
    correlation_id: str
    root_cause_hypothesis: str | None = None
    blast_radius: str | None = None
    confidence: float = 0.0
    supporting_rule_ids: list[str] = field(default_factory=list)
    fix_bundle_json: str | None = None      # JSON array
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "correlation_id": self.correlation_id,
            "root_cause_hypothesis": self.root_cause_hypothesis,
            "blast_radius": self.blast_radius,
            "confidence": self.confidence,
            "supporting_rule_ids": self.supporting_rule_ids,
            "fix_bundle_json": self.fix_bundle_json,
            "created_at": self.created_at,
        }


@dataclass
class FixAttemptRecord:
    """Stored validation or fix attempt result."""

    id: int
    finding_id: int
    job_id: int
    server_id: int
    rule_id: str
    action: str = "validate"
    status: str = "unknown"
    command: str | None = None
    expected: str | None = None
    observed: str | None = None
    error: str | None = None
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "job_id": self.job_id,
            "server_id": self.server_id,
            "rule_id": self.rule_id,
            "action": self.action,
            "status": self.status,
            "command": self.command,
            "expected": self.expected,
            "observed": self.observed,
            "error": self.error,
            "created_at": self.created_at,
        }


@dataclass
class AcceptedRiskRecord:
    """Accepted-risk baseline decision for a server/rule/title."""

    id: int
    server_id: int
    rule_id: str
    finding_title: str | None
    reason: str
    accepted_by: str = "local-user"
    expires_at: str | None = None
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "server_id": self.server_id,
            "rule_id": self.rule_id,
            "finding_title": self.finding_title,
            "reason": self.reason,
            "accepted_by": self.accepted_by,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        }


@dataclass
class LifecycleEventRecord:
    """Lifecycle event for a stable finding fingerprint."""

    id: int
    server_id: int
    job_id: int | None
    finding_fingerprint: str
    rule_id: str
    target: str | None
    event_type: str
    source: str
    details_json: str = "{}"
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "server_id": self.server_id,
            "job_id": self.job_id,
            "finding_fingerprint": self.finding_fingerprint,
            "rule_id": self.rule_id,
            "target": self.target,
            "event_type": self.event_type,
            "source": self.source,
            "details_json": self.details_json,
            "created_at": self.created_at,
        }
