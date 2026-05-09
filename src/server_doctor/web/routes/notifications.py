"""Notification routes for server-doctor web app.

Manages Slack, webhook, and email notifications.
"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from server_doctor.config import ConfigManager
from server_doctor.integrations.notifier import NotificationManager
from server_doctor.web.security import require_auth, require_csrf

router = APIRouter(prefix="/notifications", tags=["notifications"], dependencies=[Depends(require_auth)])


class SlackConfig(BaseModel):
    """Slack notification configuration."""
    webhook_url: str
    channel: str | None = None
    username: str = "server-doctor"
    icon_emoji: str = ":warning:"
    only_critical: bool = False
    enabled: bool = True


class WebhookConfig(BaseModel):
    """Generic webhook configuration."""
    url: str
    headers: dict[str, str] = {}
    events: list[str] = ["scan.completed", "finding.critical"]
    secret: str | None = None
    enabled: bool = True


class EmailConfig(BaseModel):
    """Email notification configuration."""
    smtp_host: str
    smtp_port: int = 587
    smtp_user: str
    smtp_password: str
    from_address: str
    to_addresses: list[str]
    use_tls: bool = True
    enabled: bool = True


class NotificationTestResult(BaseModel):
    """Notification test result."""
    success: bool
    message: str
    timestamp: str


@router.get("/config")
async def get_notification_config() -> dict[str, Any]:
    """Get all notification configurations."""
    config_mgr = ConfigManager()
    
    return {
        "slack": config_mgr.get_notification("slack"),
        "webhook": config_mgr.get_notification("webhook"),
        "email": config_mgr.get_notification("email"),
    }


@router.post("/slack", dependencies=[Depends(require_csrf)])
async def configure_slack(config: SlackConfig) -> SlackConfig:
    """Configure Slack notifications."""
    config_mgr = ConfigManager()
    config_mgr.set_notification("slack", config.dict())
    return config


@router.post("/webhook", dependencies=[Depends(require_csrf)])
async def configure_webhook(config: WebhookConfig) -> WebhookConfig:
    """Configure generic webhook notifications."""
    config_mgr = ConfigManager()
    config_mgr.set_notification("webhook", config.dict())
    return config


@router.post("/email", dependencies=[Depends(require_csrf)])
async def configure_email(config: EmailConfig) -> EmailConfig:
    """Configure email notifications."""
    config_mgr = ConfigManager()
    config_mgr.set_notification("email", config.dict())
    return config


@router.post("/test/{channel}", dependencies=[Depends(require_csrf)])
async def test_notification(channel: str) -> NotificationTestResult:
    """Send test notification to verify configuration."""
    config_mgr = ConfigManager()
    notifier = NotificationManager(config_mgr)
    
    from server_doctor.model.finding import Finding, Severity
    from server_doctor.model.evidence import Evidence
    
    test_finding = Finding(
        id="TEST-001",
        severity=Severity.WARNING,
        confidence=0.9,
        condition="Test notification from server-doctor",
        cause="This is a test to verify notification settings are working correctly.",
        evidence=[Evidence(
            source_file="test",
            line_number=1,
            excerpt="Test notification",
            command="manual test",
        )],
        treatment="No action required - this is just a test.",
        impact=["Verification that notifications are configured correctly"],
    )
    
    # Try to send to specific channel
    success = False
    message = ""
    
    try:
        if channel == "slack":
            slack_config = config_mgr.get_notification("slack")
            if not slack_config:
                return NotificationTestResult(
                    success=False,
                    message="Slack not configured",
                    timestamp=datetime.utcnow().isoformat(),
                )
            success = notifier.send_notification([test_finding], server_name="test-server")
            message = "Slack notification sent successfully" if success else "Failed to send Slack notification"
            
        elif channel == "webhook":
            webhook_config = config_mgr.get_notification("webhook")
            if not webhook_config:
                return NotificationTestResult(
                    success=False,
                    message="Webhook not configured",
                    timestamp=datetime.utcnow().isoformat(),
                )
            success = notifier.send_notification([test_finding], server_name="test-server")
            message = "Webhook notification sent successfully" if success else "Failed to send webhook notification"
            
        else:
            return NotificationTestResult(
                success=False,
                message=f"Unknown channel: {channel}",
                timestamp=datetime.utcnow().isoformat(),
            )
            
    except Exception as e:
        message = f"Error: {str(e)}"
    
    return NotificationTestResult(
        success=success,
        message=message,
        timestamp=datetime.utcnow().isoformat(),
    )


@router.delete("/config/{channel}", dependencies=[Depends(require_csrf)])
async def delete_notification_config(channel: str) -> dict[str, Any]:
    """Delete notification configuration."""
    config_mgr = ConfigManager()
    config_mgr.set_notification(channel, None)
    
    return {"deleted": True, "channel": channel}


@router.get("/history")
async def get_notification_history(limit: int = 20) -> list[dict[str, Any]]:
    """Get notification history."""
    # This would track notification history in a real implementation
    return []


@router.post("/trigger/{event}", dependencies=[Depends(require_csrf)])
async def trigger_notification(event: str, job_id: int | None = None) -> dict[str, Any]:
    """Manually trigger notification for an event."""
    config_mgr = ConfigManager()
    notifier = NotificationManager(config_mgr)
    
    # Get findings from job
    if job_id:
        from server_doctor.storage.repositories import ScanJobRepository
        job_repo = ScanJobRepository().get(job_id)
        if job_repo and job_repo.report:
            findings = job_repo.report.findings
            server_name = job_repo.server.name if job_repo.server else f"job-{job_id}"
            notifier.send_notification(findings, server_name=server_name)
    
    return {
        "triggered": True,
        "event": event,
        "job_id": job_id,
        "timestamp": datetime.utcnow().isoformat(),
    }
