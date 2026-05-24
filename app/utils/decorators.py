"""
app/utils/decorators.py — RBAC Access-Control Decorators
=========================================================
Implements Role-Based Access Control (RBAC) as view-layer decorators.
Every protected route must declare which role(s) may access it.

Principle of Least Privilege: users receive only the permissions their
role requires — no more.  (SSDLC Phase 3 — Secure Design)
"""

from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user


def role_required(*roles):
    """
    Decorator factory that restricts a view to one or more roles.

    Usage:
        @role_required('admin')
        @role_required('admin', 'teacher')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if current_user.role not in roles:
                abort(403)   # Forbidden — not an authorisation error we expose details of
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_2fa(f):
    """
    Ensures that the current session has completed 2FA verification.
    Redirects to the 2FA verification page if the token is absent.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import session
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if current_user.is_2fa_enabled and not session.get('2fa_verified'):
            flash("Please complete two-factor authentication.", "warning")
            return redirect(url_for('auth.verify_2fa'))
        return f(*args, **kwargs)
    return decorated_function
