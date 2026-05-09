"""Check plugin system for server-doctor.

This module provides the base infrastructure for modular checks.
Each check category (laravel, ports, security, etc.) exports a run() function.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from server_doctor.connector.ssh import SSHConnector
    from server_doctor.model.server import ServerModel
    from server_doctor.model.finding import Finding


@dataclass
class CheckContext:
    """Context passed to all check functions.
    
    Provides read-only access to model and optional SSH for additional commands.
    """
    model: "ServerModel"
    ssh: "SSHConnector | None" = None
    
    # Feature flags
    laravel_enabled: bool = False
    ports_enabled: bool = False
    security_enabled: bool = False
    phpfpm_enabled: bool = False
    performance_enabled: bool = False
    devops_enabled: bool = False
    node_enabled: bool = False
    ops_enabled: bool = False
    database_enabled: bool = False
    firewall_enabled: bool = False


class BaseCheck(ABC):
    """Abstract base class for all checks.
    
    Each check must implement:
    - run(context) -> list[Finding]
    """
    
    @property
    @abstractmethod
    def category(self) -> str:
        """Category name (e.g., 'laravel', 'ports', 'security')."""
        ...
    
    @property
    @abstractmethod
    def requires_ssh(self) -> bool:
        """Whether this check needs an active SSH connection."""
        ...
    
    @abstractmethod
    def run(self, context: CheckContext) -> list["Finding"]:
        """Run the check and return findings."""
        ...


# Registry of all available checks
_check_registry: list[type[BaseCheck]] = []


def register_check(check_class: type[BaseCheck]) -> type[BaseCheck]:
    """Decorator to register a check class."""
    _check_registry.append(check_class)
    return check_class


def get_all_checks() -> list[type[BaseCheck]]:
    """Get all registered check classes."""
    return _check_registry.copy()


def run_checks(context: CheckContext) -> list["Finding"]:
    """Run all applicable checks and return combined findings.
    
    Filters checks based on:
    - Feature flags in context
    - SSH availability for checks that require it
    """
    from server_doctor.model.finding import Finding
    
    findings: list[Finding] = []
    
    for check_class in _check_registry:
        check = check_class()
        
        # Skip checks that require SSH if not available
        if check.requires_ssh and context.ssh is None:
            continue
        
        # Check category-specific flags
        category = check.category
        if category == "laravel" and not context.laravel_enabled:
            continue
        if category == "ports" and not context.ports_enabled:
            continue
        if category == "security" and not context.security_enabled:
            continue
        if category == "phpfpm" and not context.phpfpm_enabled:
            continue
        if category == "performance" and not context.performance_enabled:
            continue
        if category == "devops" and not context.devops_enabled:
            continue
        if category == "node" and not context.node_enabled:
            continue
        if category == "ops" and not context.ops_enabled:
            continue
        if category == "database" and not context.database_enabled:
            continue
        if category == "firewall" and not context.firewall_enabled:
            continue
        
        # Run the check
        try:
            check_findings = check.run(context)
            findings.extend(check_findings)
        except Exception as e:
            # Log error but don't fail entire scan
            import logging
            logging.warning(f"Check {check.__class__.__name__} failed: {e}")
    
    return findings
