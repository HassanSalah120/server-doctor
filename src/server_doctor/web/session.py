"""
Session management for SSH connections.

Stores active SSH sessions and provides per-host mutex for safe apply operations.
Limitation: Sessions are lost on server restart.
"""

import threading
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Optional

from server_doctor.connector.ssh import SSHConnector, SSHConfig


@dataclass
class Session:
    """Active SSH session."""
    id: str
    ssh: SSHConnector
    host: str
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    
    def touch(self) -> None:
        """Update last_used timestamp."""
        self.last_used = datetime.now()
    
    def is_expired(self, timeout_minutes: int = 30) -> bool:
        """Check if session has expired."""
        return datetime.now() - self.last_used > timedelta(minutes=timeout_minutes)


class SessionStore:
    """Thread-safe session storage with per-host mutex.
    
    Provides:
    - SSH session storage by session ID
    - Per-host mutex to prevent concurrent apply operations
    
    Limitation: Sessions are lost when server restarts.
    """
    
    def __init__(self) -> None:
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()
        # Per-host mutex: only one apply operation per host at a time
        self._host_locks: Dict[str, threading.Lock] = {}
    
    def create_session(self, config: SSHConfig) -> str:
        """Create a new SSH session.
        
        Args:
            config: SSH connection configuration.
            
        Returns:
            Session ID.
            
        Raises:
            ConnectionError: If SSH connection fails.
        """
        ssh = SSHConnector(config)
        ssh.connect()
        
        session_id = secrets.token_urlsafe(16)
        session = Session(id=session_id, ssh=ssh, host=config.host)
        
        with self._lock:
            self._sessions[session_id] = session
            # Create host lock if not exists
            if config.host not in self._host_locks:
                self._host_locks[config.host] = threading.Lock()
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                if session.is_expired():
                    self._cleanup_session(session_id)
                    return None
                session.touch()
            return session
    
    def get_host_lock(self, host: str) -> threading.Lock:
        """Get mutex lock for a host.
        
        Used to ensure only one apply operation runs per host at a time.
        """
        with self._lock:
            if host not in self._host_locks:
                self._host_locks[host] = threading.Lock()
            return self._host_locks[host]
    
    def _cleanup_session(self, session_id: str) -> None:
        """Close and remove a session (must hold lock)."""
        session = self._sessions.pop(session_id, None)
        if session:
            try:
                session.ssh.disconnect()
            except Exception:
                pass  # Ignore disconnect errors
    
    def remove_session(self, session_id: str) -> None:
        """Remove a session."""
        with self._lock:
            self._cleanup_session(session_id)
    
    def cleanup_all(self) -> None:
        """Cleanup all sessions (for shutdown)."""
        with self._lock:
            for session_id in list(self._sessions.keys()):
                self._cleanup_session(session_id)
    
    def cleanup_expired(self) -> int:
        """Cleanup expired sessions and return count."""
        count = 0
        with self._lock:
            for session_id in list(self._sessions.keys()):
                session = self._sessions.get(session_id)
                if session and session.is_expired():
                    self._cleanup_session(session_id)
                    count += 1
        return count


# Global session store
session_store = SessionStore()
