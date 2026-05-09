"""Notification integrations for server-doctor.

Supports Slack, email, and webhook notifications for scan results.
"""

import json
import logging
from typing import Any

import requests

from server_doctor.config import ConfigManager
from server_doctor.model.finding import Finding
from server_doctor.model.evidence import Severity


logger = logging.getLogger(__name__)


class NotificationManager:
    """Manage notifications to external systems."""
    
    def __init__(self, config_mgr: ConfigManager):
        self.config_mgr = config_mgr
        self.backends = self._load_backends()
    
    def _load_backends(self) -> list:
        """Load configured notification backends."""
        backends = []
        
        slack_config = self.config_mgr.get_notification("slack")
        if slack_config:
            backends.append(SlackNotifier(slack_config))
        
        webhook_config = self.config_mgr.get_notification("webhook")
        if webhook_config:
            backends.append(WebhookNotifier(webhook_config))
        
        return backends
    
    def send_notification(
        self,
        findings: list[Finding],
        server_name: str | None = None,
        only_critical: bool = False,
    ) -> bool:
        """Send notification to all configured backends.
        
        Returns True if all notifications succeeded.
        """
        if not self.backends:
            logger.debug("No notification backends configured")
            return False
        
        # Filter findings if needed
        if only_critical:
            findings = [f for f in findings if f.severity == Severity.CRITICAL]
        
        if not findings:
            logger.debug("No findings to notify about")
            return True
        
        success = True
        for backend in self.backends:
            try:
                backend.send(findings, server_name)
            except Exception as e:
                logger.error(f"Failed to send notification via {backend.__class__.__name__}: {e}")
                success = False
        
        return success


class SlackNotifier:
    """Send notifications to Slack via webhook."""
    
    def __init__(self, config: dict):
        self.webhook_url = config["webhook"]
        self.channel = config.get("channel")
        self.only_critical = config.get("only_critical", False)
    
    def send(
        self,
        findings: list[Finding],
        server_name: str | None = None,
    ) -> None:
        """Send findings to Slack."""
        
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        warnings = [f for f in findings if f.severity == Severity.WARNING]
        
        # Build message
        server = server_name or "unknown server"
        
        if critical:
            color = "danger"
            title = f"🚨 {len(critical)} Critical Issues Found on {server}"
        elif warnings:
            color = "warning"
            title = f"⚠️ {len(warnings)} Warnings on {server}"
        else:
            color = "good"
            title = f"✅ {server} scan completed"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": title,
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Critical:*\n{len(critical)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Warnings:*\n{len(warnings)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Info:*\n{len([f for f in findings if f.severity == Severity.INFO])}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total:*\n{len(findings)}"
                    }
                ]
            }
        ]
        
        # Add top 5 findings
        if critical or warnings:
            blocks.append({"type": "divider"})
            
            for finding in (critical + warnings)[:5]:
                emoji = "🚨" if finding.severity == Severity.CRITICAL else "⚠️"
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{emoji} *{finding.id}*: {finding.condition}\n"
                            f"_{finding.cause[:100]}..._\n"
                            f"*Fix:* {finding.treatment[:80]}..."
                        )
                    }
                })
        
        payload = {
            "blocks": blocks,
            "attachments": [{
                "color": color,
                "fallback": title,
            }]
        }
        
        if self.channel:
            payload["channel"] = self.channel
        
        response = requests.post(
            self.webhook_url,
            json=payload,
            timeout=30,
        )
        response.raise_for_status()


class WebhookNotifier:
    """Send notifications to generic webhook."""
    
    def __init__(self, config: dict):
        self.url = config["url"]
        self.headers = config.get("headers", {})
        self.method = config.get("method", "POST")
    
    def send(
        self,
        findings: list[Finding],
        server_name: str | None = None,
    ) -> None:
        """Send findings to webhook."""
        
        payload = {
            "server": server_name,
            "timestamp": json.dumps(datetime.utcnow().isoformat()),
            "summary": {
                "critical": len([f for f in findings if f.severity == Severity.CRITICAL]),
                "warning": len([f for f in findings if f.severity == Severity.WARNING]),
                "info": len([f for f in findings if f.severity == Severity.INFO]),
            },
            "findings": [
                {
                    "id": f.id,
                    "severity": f.severity.value,
                    "condition": f.condition,
                    "cause": f.cause,
                }
                for f in findings[:10]  # Limit to top 10
            ]
        }
        
        response = requests.request(
            self.method,
            self.url,
            json=payload,
            headers=self.headers,
            timeout=30,
        )
        response.raise_for_status()


from datetime import datetime
