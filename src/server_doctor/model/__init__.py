"""Model package - Core data structures for server-doctor."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import (
    CertbotModel,
    DiskUsage,
    LocationBlock,
    NginxInfo,
    NetworkEndpoint,
    NetworkSurfaceModel,
    OSInfo,
    PHPInfo,
    ProjectInfo,
    ProjectType,
    SecurityBaselineModel,
    ServerBlock,
    ServerModel,
    TelemetryModel,
    VulnerabilityModel,
)

__all__ = [
    "Evidence",
    "CertbotModel",
    "DiskUsage",
    "Finding",
    "LocationBlock",
    "NginxInfo",
    "NetworkEndpoint",
    "NetworkSurfaceModel",
    "OSInfo",
    "PHPInfo",
    "ProjectInfo",
    "ProjectType",
    "SecurityBaselineModel",
    "ServerBlock",
    "ServerModel",
    "Severity",
    "TelemetryModel",
    "VulnerabilityModel",
]
