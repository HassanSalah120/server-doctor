"""Compatibility re-export for the canonical Nginx scanner."""

from server_doctor.scanner.server import NginxScanResult, NginxScanner

__all__ = ["NginxScanner", "NginxScanResult"]
