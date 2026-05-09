"""Base Reporter Interface."""

from abc import ABC, abstractmethod
from rich.console import Console
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class BaseReporter(ABC):
    """Abstract base class for all diagnostic reporters."""

    def __init__(self, console: Console, show_score: bool = False, show_explain: bool = False) -> None:
        self.console = console
        self.show_score = show_score
        self.show_explain = show_explain

    @abstractmethod
    def report_findings(self, findings: list[Finding]) -> int:
        """Report diagnosis findings to the console."""
        pass

    @abstractmethod
    def report_server_summary(self, model: ServerModel, findings: list[Finding] | None = None) -> None:
        """Display server summary."""
        pass

    @abstractmethod
    def report_wss_inventory(self, inventory: list) -> None:
        """Report WebSocket inventory."""
        pass
