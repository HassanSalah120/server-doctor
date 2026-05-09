"""Finding dataclass - Diagnosis results with evidence."""

from dataclasses import dataclass, field

from server_doctor.model.evidence import Evidence, Severity


@dataclass
class Finding:
    """A diagnosis finding with evidence.

    Every Finding MUST have at least one Evidence entry.
    Findings without evidence should not be created.

    Attributes:
        severity: How critical this finding is.
        confidence: Certainty of this diagnosis (0.0 - 1.0).
        condition: Short description of the problem.
        cause: Why this problem exists.
        evidence: List of evidence supporting this finding. Never empty!
        treatment: Recommended fix.
        impact: What happens if this is ignored.
    """

    severity: Severity
    confidence: float  # 0.0 - 1.0
    condition: str
    cause: str
    id: str = "NGX000"  # Default placeholder
    derived_from: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    treatment: str = ""
    fix_commands: list[str] = field(default_factory=list)  # One-click fix commands
    impact: list[str] = field(default_factory=list)
    correlation: list = field(default_factory=list)  # list[CorrelationEvidence]

    def __post_init__(self) -> None:
        """Validate that evidence is not empty."""
        if not self.evidence:
            raise ValueError("Finding must have at least one Evidence entry")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")

    @property
    def severity_icon(self) -> str:
        """Get label for severity level."""
        icons = {
            Severity.CRITICAL: "[CRITICAL]",
            Severity.WARNING: "[WARNING]",
            Severity.INFO: "[INFO]",
        }
        return icons.get(self.severity, "[FINDING]")
