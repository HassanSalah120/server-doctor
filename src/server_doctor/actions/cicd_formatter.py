"""CI/CD output formatter for server-doctor.

Provides machine-readable JSON output for integration with CI/CD pipelines,
GitHub Actions, GitLab CI, Jenkins, etc.
"""

import json
import sys
from dataclasses import asdict
from datetime import datetime
from typing import Any

from server_doctor.model.finding import Finding
from server_doctor.model.evidence import Severity


class CICDFormatter:
    """Format scan results for CI/CD consumption."""
    
    # Exit codes for pipeline integration
    EXIT_OK = 0
    EXIT_INFO = 0
    EXIT_WARNING = 1
    EXIT_CRITICAL = 2
    EXIT_ERROR = 3
    
    @staticmethod
    def format_findings(
        findings: list[Finding],
        server_id: int | None = None,
        server_name: str | None = None,
        scan_duration: float | None = None,
    ) -> dict[str, Any]:
        """Format findings as structured JSON for CI/CD."""
        
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        info = [f for f in findings if f.severity == Severity.INFO]
        
        # Calculate health score
        score = CICDFormatter._calculate_score(findings)
        
        result = {
            "version": "1.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "server": {
                "id": server_id,
                "name": server_name,
            } if server_id else None,
            "summary": {
                "total_findings": len(findings),
                "critical": len(critical),
                "warning": len(warnings),
                "info": len(info),
                "health_score": score,
                "passed": len(critical) == 0 and len(warnings) == 0,
            },
            "metrics": {
                "scan_duration_seconds": scan_duration,
            } if scan_duration else {},
            "findings": [
                {
                    "id": f.id,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "condition": f.condition,
                    "cause": f.cause,
                    "treatment": f.treatment,
                    "fix_commands": f.fix_commands,
                    "impact": f.impact,
                    "evidence": [
                        {
                            "source_file": e.source_file,
                            "line_number": e.line_number,
                            "excerpt": e.excerpt,
                            "command": e.command,
                        }
                        for e in f.evidence
                    ],
                }
                for f in findings
            ],
            "annotations": CICDFormatter._generate_annotations(findings),
        }
        
        return result
    
    @staticmethod
    def _calculate_score(findings: list[Finding]) -> int:
        """Calculate health score from 0-100."""
        if not findings:
            return 100
        
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        warnings = len([f for f in findings if f.severity == Severity.WARNING])
        info = len([f for f in findings if f.severity == Severity.INFO])
        
        # Penalty: -25 per critical, -10 per warning, -1 per info
        score = 100 - (critical * 25) - (warnings * 10) - (info * 1)
        return max(0, min(100, score))
    
    @staticmethod
    def _generate_annotations(findings: list[Finding]) -> list[dict[str, Any]]:
        """Generate GitHub/GitLab compatible annotations."""
        annotations = []
        
        for finding in findings:
            if finding.severity == Severity.INFO:
                continue  # Skip info in CI annotations
            
            for ev in finding.evidence[:2]:  # Max 2 annotations per finding
                if not ev.source_file:
                    continue
                
                annotations.append({
                    "path": ev.source_file,
                    "start_line": ev.line_number or 1,
                    "end_line": ev.line_number or 1,
                    "annotation_level": "failure" if finding.severity == Severity.CRITICAL else "warning",
                    "message": f"[{finding.id}] {finding.condition}: {finding.cause}",
                    "title": finding.id,
                    "raw_details": finding.treatment,
                })
        
        return annotations
    
    @staticmethod
    def get_exit_code(findings: list[Finding], fail_on_warning: bool = False) -> int:
        """Get appropriate exit code for CI/CD pipeline."""
        critical = any(f.severity == Severity.CRITICAL for f in findings)
        warning = any(f.severity == Severity.WARNING for f in findings)
        
        if critical:
            return CICDFormatter.EXIT_CRITICAL
        if warning and fail_on_warning:
            return CICDFormatter.EXIT_WARNING
        return CICDFormatter.EXIT_OK
    
    @classmethod
    def print_report(
        cls,
        findings: list[Finding],
        server_id: int | None = None,
        server_name: str | None = None,
        scan_duration: float | None = None,
        fail_on_warning: bool = False,
    ) -> int:
        """Print CI/CD report and return exit code."""
        result = cls.format_findings(findings, server_id, server_name, scan_duration)
        print(json.dumps(result, indent=2))
        return cls.get_exit_code(findings, fail_on_warning)


class SARIFFormatter:
    """Format results as SARIF for GitHub Advanced Security integration."""
    
    @staticmethod
    def format(findings: list[Finding], tool_name: str = "server-doctor") -> dict[str, Any]:
        """Format findings as SARIF output."""
        
        rules = {}
        results = []
        
        for finding in findings:
            # Create rule if not exists
            if finding.id not in rules:
                rules[finding.id] = {
                    "id": finding.id,
                    "name": finding.id,
                    "shortDescription": {"text": finding.condition},
                    "fullDescription": {"text": finding.cause},
                    "help": {"text": finding.treatment},
                    "defaultConfiguration": {
                        "level": "error" if finding.severity == Severity.CRITICAL 
                                else "warning" if finding.severity == Severity.WARNING
                                else "note"
                    },
                }
            
            # Create result
            locations = []
            for ev in finding.evidence:
                if ev.source_file:
                    locations.append({
                        "physicalLocation": {
                            "artifactLocation": {"uri": ev.source_file},
                            "region": {
                                "startLine": ev.line_number or 1,
                                "snippet": {"text": ev.excerpt or ""},
                            },
                        },
                    })
            
            results.append({
                "ruleId": finding.id,
                "level": "error" if finding.severity == Severity.CRITICAL 
                        else "warning" if finding.severity == Severity.WARNING
                        else "note",
                "message": {"text": f"{finding.condition}: {finding.cause}"},
                "locations": locations if locations else [{"physicalLocation": {"artifactLocation": {"uri": "nginx.conf"}}}],
            })
        
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }]
        }
    
    @classmethod
    def print_report(cls, findings: list[Finding]) -> None:
        """Print SARIF report to stdout."""
        result = cls.format(findings)
        print(json.dumps(result, indent=2))
