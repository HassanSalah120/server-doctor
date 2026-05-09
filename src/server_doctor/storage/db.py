"""SQLite database connection and initialization.

Thread safety: Uses threading.local for per-thread connections.
No check_same_thread=False — each thread gets its own connection.
All writes use explicit transactions.

DB location: ./data/server_doctor.db (created automatically).
"""

import sqlite3
import threading
from pathlib import Path

from server_doctor.storage.models import ALL_SCHEMAS

# Default database path (relative to CWD)
_DEFAULT_DB_DIR = Path("./data")
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "server_doctor.db"

# Thread-local storage for connections
_local = threading.local()

# Module-level DB path (can be overridden for testing)
_db_path: Path = _DEFAULT_DB_PATH


def set_db_path(path: Path | str) -> None:
    """Override the database path (useful for testing).

    Any existing thread-local connection is closed so subsequent calls
    to :func:`get_db` will open a connection against the new file.  This
    prevents stale connections from still pointing at the old database
    after tests switch paths.

    Must be called before :func:`init_db` or :func:`get_db`.
    """
    global _db_path
    # close any open connection on this thread
    conn = getattr(_local, "connection", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        _local.connection = None

    _db_path = Path(path)


def get_db_path() -> Path:
    """Return the current database file path."""
    return _db_path


def init_db() -> None:
    """Initialize the database: create directory, file, and all tables.

    Safe to call multiple times (uses CREATE TABLE IF NOT EXISTS).
    """
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(_db_path)
    try:
        for ddl in ALL_SCHEMAS:
            conn.execute(ddl)
        # Run migrations for schema updates
        _migrate_add_model_json(conn)
        _migrate_add_repo_scan_paths(conn)
        _migrate_add_server_secret_columns(conn)
        _migrate_add_scan_phases(conn)
        conn.commit()
    finally:
        conn.close()


def _migrate_add_model_json(conn: sqlite3.Connection) -> None:
    """Add model_json column to scan_jobs if missing (for existing DBs)."""
    cursor = conn.execute("PRAGMA table_info(scan_jobs)")
    columns = {row["name"] for row in cursor.fetchall()}
    if "model_json" not in columns:
        conn.execute("ALTER TABLE scan_jobs ADD COLUMN model_json TEXT")
        conn.commit()


def _migrate_add_repo_scan_paths(conn: sqlite3.Connection) -> None:
    """Add repo_scan_paths column to scan_jobs if missing."""
    cursor = conn.execute("PRAGMA table_info(scan_jobs)")
    columns = {row["name"] for row in cursor.fetchall()}
    if "repo_scan_paths" not in columns:
        conn.execute("ALTER TABLE scan_jobs ADD COLUMN repo_scan_paths TEXT")
        conn.commit()


def _migrate_add_server_secret_columns(conn: sqlite3.Connection) -> None:
    """Add keyring secret reference columns to servers if missing."""
    cursor = conn.execute("PRAGMA table_info(servers)")
    columns = {row["name"] for row in cursor.fetchall()}
    if "password_secret_ref" not in columns:
        conn.execute("ALTER TABLE servers ADD COLUMN password_secret_ref TEXT")
    if "password_storage" not in columns:
        conn.execute("ALTER TABLE servers ADD COLUMN password_storage TEXT DEFAULT 'legacy'")
    if "key_passphrase_secret_ref" not in columns:
        conn.execute("ALTER TABLE servers ADD COLUMN key_passphrase_secret_ref TEXT")
    if "key_passphrase_storage" not in columns:
        conn.execute("ALTER TABLE servers ADD COLUMN key_passphrase_storage TEXT DEFAULT 'none'")
    conn.commit()


def _migrate_add_scan_phases(conn: sqlite3.Connection) -> None:
    """Add phase log JSON column to scan_jobs if missing."""
    cursor = conn.execute("PRAGMA table_info(scan_jobs)")
    columns = {row["name"] for row in cursor.fetchall()}
    if "phases_json" not in columns:
        conn.execute("ALTER TABLE scan_jobs ADD COLUMN phases_json TEXT DEFAULT '[]'")
        conn.commit()


def get_db() -> sqlite3.Connection:
    """Get a thread-local database connection.

    Each thread gets its own connection via threading.local.
    Connections are reused within the same thread.
    Row factory is set to sqlite3.Row for dict-like access.
    """
    conn = getattr(_local, "connection", None)
    if conn is None:
        conn = _connect(_db_path)
        _local.connection = conn
    return conn


def close_db() -> None:
    """Close the thread-local connection (if any)."""
    conn = getattr(_local, "connection", None)
    if conn is not None:
        conn.close()
        _local.connection = None


def _connect(path: Path) -> sqlite3.Connection:
    """Create a new SQLite connection with preferred settings."""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn
