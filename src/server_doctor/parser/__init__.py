"""Parser package - Converts raw data into structured models.

Parsers do NOT run commands - they structure data from scanners.
Most importantly, they track line numbers for evidence.
"""

from server_doctor.parser.nginx_conf import NginxConfigParser

__all__ = ["NginxConfigParser"]
