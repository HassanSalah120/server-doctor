"""Compatibility re-export for the runtime-first Nginx collector."""

from server_doctor.scanner.server_collector import CollectorResult, NginxCollector

__all__ = ["NginxCollector", "CollectorResult"]
