"""Actions package - Action layer with explicit contracts.

Each action declares:
- read_only: Whether it modifies the server
- requires_backup: Whether backup is mandatory
- rollback_support: Whether it can undo changes
- prerequisites: What must pass before action runs
"""

from server_doctor.actions.report import ReportAction
from server_doctor.actions.generate import GenerateAction
from server_doctor.actions.apply import ApplyAction

__all__ = ["ReportAction", "GenerateAction", "ApplyAction"]
