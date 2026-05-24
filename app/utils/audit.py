"""
app/utils/audit.py — Centralised Audit Logging
===============================================
Every security-relevant event is recorded in the AuditLog table.
Satisfies SSDLC Phase 7 (Maintenance & Monitoring).
"""

from datetime import datetime, timezone
from flask import request
from app.extensions import db
from app.models import AuditLog


def log_event(action: str, user_id: int = None, resource: str = None,
              resource_id: int = None, details: str = None, status: str = 'success'):
    """
    Persist an audit event to the database.

    :param action:      Event type string (e.g. 'LOGIN_SUCCESS', 'STUDENT_CREATE').
    :param user_id:     ID of the acting user (None for anonymous events).
    :param resource:    Resource type (e.g. 'Student', 'User').
    :param resource_id: Primary key of the affected resource.
    :param details:     Free-text context (never include raw passwords or secrets).
    :param status:      'success' or 'failed'.
    """
    ip = request.remote_addr if request else None
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=resource_id,
        details=details,
        ip_address=ip,
        status=status,
        timestamp=datetime.now(timezone.utc),
    )
    db.session.add(entry)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
