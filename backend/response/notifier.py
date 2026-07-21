"""
AlertIQ 2.0 - Phase 5 Automatic Response: Email Notifications
--------------------------------------------------------------------
Sends an email alert for new incidents via SMTP. Configuration comes
from environment variables so credentials never live in code/config
files that might get committed:

    ALERTIQ_SMTP_HOST
    ALERTIQ_SMTP_PORT       (default 587)
    ALERTIQ_SMTP_USERNAME
    ALERTIQ_SMTP_PASSWORD
    ALERTIQ_SMTP_FROM       (default = SMTP_USERNAME)
    ALERTIQ_SMTP_TO         (comma-separated recipient list)
    ALERTIQ_SMTP_USE_TLS    ("true"/"false", default "true")

If ALERTIQ_SMTP_HOST is not set, notifications are logged instead of
sent (safe no-op default) - this keeps the feature usable/testable
without requiring real SMTP credentials, while being explicit that
nothing is actually being emailed.
"""
from __future__ import annotations

import logging
import os
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger("alertiq.response.notifier")


def _smtp_configured() -> bool:
    return bool(os.environ.get("ALERTIQ_SMTP_HOST"))


def send_incident_email(*, attack_type: str, severity: str, source_ip: str, destination_ip: str | None,
                         risk_score: int, explanation: str) -> dict:
    subject = f"[AlertIQ] {severity} - {attack_type} detected from {source_ip}"
    body = (
        f"AlertIQ 2.0 detected a {severity} severity incident.\n\n"
        f"Attack type: {attack_type}\n"
        f"Source IP: {source_ip}\n"
        f"Destination IP: {destination_ip or 'N/A'}\n"
        f"Risk score: {risk_score}/100\n\n"
        f"Explanation:\n{explanation}\n\n"
        f"Review in the AlertIQ SOC portal under Threats."
    )

    if not _smtp_configured():
        logger.info("[notification-log-only, SMTP not configured] %s", subject)
        return {"sent": False, "reason": "SMTP not configured (ALERTIQ_SMTP_HOST unset) - logged only"}

    host = os.environ["ALERTIQ_SMTP_HOST"]
    port = int(os.environ.get("ALERTIQ_SMTP_PORT", "587"))
    username = os.environ.get("ALERTIQ_SMTP_USERNAME")
    password = os.environ.get("ALERTIQ_SMTP_PASSWORD")
    from_addr = os.environ.get("ALERTIQ_SMTP_FROM", username or "alertiq@localhost")
    to_addrs = [a.strip() for a in os.environ.get("ALERTIQ_SMTP_TO", "").split(",") if a.strip()]
    use_tls = os.environ.get("ALERTIQ_SMTP_USE_TLS", "true").lower() == "true"

    if not to_addrs:
        return {"sent": False, "reason": "ALERTIQ_SMTP_TO has no recipients configured"}

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)

    try:
        with smtplib.SMTP(host, port, timeout=10) as server:
            if use_tls:
                server.starttls()
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
        logger.info("Sent incident email to %s: %s", to_addrs, subject)
        return {"sent": True, "recipients": to_addrs}
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to send incident email: %s", e)
        return {"sent": False, "reason": str(e)}
