"""Evidence dataclass - Every finding must have evidence."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"  # Will break functionality
    WARNING = "warning"  # May cause issues
    INFO = "info"  # Advisory, nice to fix


@dataclass(frozen=True)
class Evidence:
    """Every finding MUST have evidence. This builds trust.

    Without evidence (file path, line number, excerpt), users won't
    trust the diagnosis. This is what separates server-doctor from
    simple config linters.

    Attributes:
        source_file: Absolute path to the file containing the evidence.
        line_number: Line number where the issue was found.
        excerpt: The actual text/content that constitutes the evidence.
        command: Optional command that produced this evidence (e.g., 'nginx -T').
    """

    source_file: str
    line_number: int
    excerpt: str
    command: str | None = None

    def __str__(self) -> str:
        """Format evidence for display."""
        return f"{self.source_file}:{self.line_number}: {self.excerpt}"
