"""Email notification service"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
import logging

from src.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending email notifications"""

    def __init__(self):
        self.host = settings.smtp_host
        self.port = settings.smtp_port
        self.username = settings.smtp_user
        self.password = settings.smtp_password
        self.from_address = settings.smtp_from
        self.use_tls = settings.smtp_tls

    @property
    def is_configured(self) -> bool:
        """Check if email service is configured"""
        return bool(self.username and self.password)

    async def send_email(
        self,
        to: List[str],
        subject: str,
        body: str,
        html_body: Optional[str] = None,
    ) -> bool:
        """Send an email notification"""
        if not self.is_configured:
            logger.warning("Email service not configured, skipping email")
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_address
            msg["To"] = ", ".join(to)

            # Add plain text body
            msg.attach(MIMEText(body, "plain"))

            # Add HTML body if provided
            if html_body:
                msg.attach(MIMEText(html_body, "html"))

            # Connect and send
            with smtplib.SMTP(self.host, self.port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.from_address, to, msg.as_string())

            logger.info(f"Email sent successfully to {to}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    async def send_alert_notification(
        self,
        to: List[str],
        alert_id: str,
        alert_title: str,
        alert_severity: str,
        alert_description: Optional[str] = None,
    ) -> bool:
        """Send alert notification email"""
        subject = f"[PySOAR Alert] [{alert_severity.upper()}] {alert_title}"

        body = f"""
A new alert has been created in PySOAR.

Alert ID: {alert_id}
Title: {alert_title}
Severity: {alert_severity.upper()}

Description:
{alert_description or 'No description provided'}

Please log in to PySOAR to review and respond to this alert.
        """

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        .container {{ font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }}
        .header {{ background: #1f2937; color: white; padding: 20px; text-align: center; }}
        .severity-critical {{ background: #dc2626; }}
        .severity-high {{ background: #ea580c; }}
        .severity-medium {{ background: #ca8a04; }}
        .severity-low {{ background: #2563eb; }}
        .content {{ padding: 20px; background: #f9fafb; }}
        .alert-info {{ background: white; padding: 15px; border-radius: 8px; margin: 10px 0; }}
        .label {{ color: #6b7280; font-size: 12px; text-transform: uppercase; }}
        .value {{ color: #111827; font-size: 14px; margin-top: 4px; }}
        .footer {{ padding: 20px; text-align: center; color: #6b7280; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header severity-{alert_severity.lower()}">
            <h2>New Alert: {alert_severity.upper()}</h2>
        </div>
        <div class="content">
            <div class="alert-info">
                <div class="label">Alert ID</div>
                <div class="value">{alert_id}</div>
            </div>
            <div class="alert-info">
                <div class="label">Title</div>
                <div class="value">{alert_title}</div>
            </div>
            <div class="alert-info">
                <div class="label">Description</div>
                <div class="value">{alert_description or 'No description provided'}</div>
            </div>
        </div>
        <div class="footer">
            This is an automated notification from PySOAR.
        </div>
    </div>
</body>
</html>
        """

        return await self.send_email(to, subject, body, html_body)

    async def send_incident_notification(
        self,
        to: List[str],
        incident_id: str,
        incident_title: str,
        incident_severity: str,
        alert_count: int = 0,
    ) -> bool:
        """Send incident notification email"""
        subject = f"[PySOAR Incident] [{incident_severity.upper()}] {incident_title}"

        body = f"""
A new incident has been created in PySOAR.

Incident ID: {incident_id}
Title: {incident_title}
Severity: {incident_severity.upper()}
Related Alerts: {alert_count}

Please log in to PySOAR to review and respond to this incident.
        """

        return await self.send_email(to, subject, body)

    async def send_playbook_notification(
        self,
        to: List[str],
        playbook_name: str,
        status: str,
        execution_id: str,
        error_message: Optional[str] = None,
    ) -> bool:
        """Send playbook execution notification"""
        if status == "completed":
            subject = f"[PySOAR] Playbook '{playbook_name}' completed successfully"
            body = f"The playbook '{playbook_name}' has completed successfully.\n\nExecution ID: {execution_id}"
        else:
            subject = f"[PySOAR] Playbook '{playbook_name}' failed"
            body = f"The playbook '{playbook_name}' has failed.\n\nExecution ID: {execution_id}\n\nError: {error_message or 'Unknown error'}"

        return await self.send_email(to, subject, body)


# Global email service instance
email_service = EmailService()
