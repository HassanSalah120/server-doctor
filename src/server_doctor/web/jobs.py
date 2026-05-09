"""
Job execution system for background operations.

Provides:
- Job queue with status tracking
- Background thread execution
- Append-only log streaming (via polling)

Limitation: Jobs are lost when server restarts.
"""

import threading
import secrets
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class JobStatus(str, Enum):
    """Job execution status."""
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class JobLog:
    """Single log entry."""
    timestamp: datetime
    level: str  # INFO, WARN, ERROR, SUCCESS
    message: str


@dataclass
class Job:
    """Background job with logging."""
    id: str
    status: JobStatus = JobStatus.QUEUED
    logs: List[JobLog] = field(default_factory=list)
    result: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def log(self, message: str, level: str = "INFO") -> None:
        """Add a log entry."""
        self.logs.append(JobLog(
            timestamp=datetime.now(),
            level=level,
            message=message
        ))
    
    def log_info(self, message: str) -> None:
        """Add info log."""
        self.log(message, "INFO")
    
    def log_warn(self, message: str) -> None:
        """Add warning log."""
        self.log(message, "WARN")
    
    def log_error(self, message: str) -> None:
        """Add error log."""
        self.log(message, "ERROR")
    
    def log_success(self, message: str) -> None:
        """Add success log."""
        self.log(message, "SUCCESS")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to API response dict."""
        return {
            "id": self.id,
            "status": self.status.value,
            "logs": [
                {
                    "timestamp": log.timestamp.isoformat(),
                    "level": log.level,
                    "message": log.message
                }
                for log in self.logs
            ],
            "result": self.result,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class JobExecutor:
    """Background job executor.
    
    Runs jobs in background threads and tracks status.
    """
    
    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()
    
    def create_job(self) -> Job:
        """Create a new job."""
        job_id = secrets.token_urlsafe(12)
        job = Job(id=job_id)
        
        with self._lock:
            self._jobs[job_id] = job
        
        return job
    
    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID."""
        with self._lock:
            return self._jobs.get(job_id)
    
    def run_in_background(
        self,
        job: Job,
        func: Callable[[Job], None],
        host_lock: Optional[threading.Lock] = None,
    ) -> None:
        """Run a function in background thread.
        
        Args:
            job: Job to track execution.
            func: Function to execute, receives job for logging.
            host_lock: Optional mutex to acquire before running.
        """
        def worker() -> None:
            # Acquire host lock if provided
            if host_lock:
                if not host_lock.acquire(blocking=False):
                    job.status = JobStatus.FAILED
                    job.log_error("Another apply operation is running on this host. Please wait.")
                    job.completed_at = datetime.now()
                    return
            
            try:
                job.status = JobStatus.RUNNING
                job.started_at = datetime.now()
                job.log_info("Job started")
                
                func(job)
                
                # Only set success if still running (not failed by func)
                if job.status == JobStatus.RUNNING:
                    job.status = JobStatus.SUCCESS
                    job.log_success("Job completed successfully")
                    
            except Exception as e:
                job.status = JobStatus.FAILED
                job.log_error(f"Job failed: {str(e)}")
                # Don't log full traceback to avoid leaking sensitive info
                
            finally:
                job.completed_at = datetime.now()
                if host_lock:
                    try:
                        host_lock.release()
                    except RuntimeError:
                        pass  # Lock wasn't held
        
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()


# Global job executor
job_executor = JobExecutor()
