"""SQLite storage layer for ServerDoctor.

Provides persistent storage for servers, scan jobs, findings, and job logs.
DB file: ./data/server_doctor.db (auto-created on startup).
"""

from server_doctor.storage.db import get_db, init_db

__all__ = ["get_db", "init_db"]
