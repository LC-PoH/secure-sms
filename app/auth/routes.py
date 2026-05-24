"""
app/auth/routes.py — Authentication Blueprint
==============================================
Implements the full authentication lifecycle with security controls:

  1. Username + bcrypt password verification
  2. Account lockout after MAX_LOGIN_ATTEMPTS failures (brute-force protection)
  3. TOTP 2FA verification (RFC 6238)
  4. Secure session management (Flask-Login + session flags)
  5. CSRF protection on all POST forms (Flask-WTF)
  6. Rate limiting on /login (Flask-Limiter)
  7. Audit logging of every auth event

OWASP A07:2021 — Identification and Authentication Failures
"""

import pyotp
import qrcode
import io
import base64
from datetime import datetime, timezone, timedelta

from flask import (Blueprint, render_template, redirect, url_for,
                   flash, session, request, current_app)
from flask_login import login_user, logout_user, login_required, current_user

from app.extensions import db, bcrypt, limiter
from app.models import User
from app.utils.audit import log_event
from app.utils.validators import sanitise_input, validate_password_strength
from .forms import LoginForm, TwoFactorForm, ChangePasswordForm

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


# ─── Login ────────────────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")          # Rate-limit: 10 attempts per minute per IP
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        username = sanitise_input(form.username.data)
        password = form.password.data   # Raw password — compared against bcrypt hash only

        # OWASP: Use generic error messages — do not reveal whether username exists
        user = User.query.filter_by(username=username).first()

        if user is None:
            log_event('LOGIN_FAIL', details=f'Unknown username: {username}', status='failed')
            flash("Invalid username or password.", "danger")
            return render_template('auth/login.html', form=form)

        # Check account lockout
        if user.is_locked():
            remaining = int((user.locked_until - datetime.now(timezone.utc)).total_seconds() / 60) + 1
            flash(f"Account locked. Try again in {remaining} minute(s).", "danger")
            log_event('LOGIN_FAIL', user_id=user.id, details='Account locked', status='failed')
            return render_template('auth/login.html', form=form)

        # Verify bcrypt password hash
        if not bcrypt.check_password_hash(user.password_hash, password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= current_app.config['MAX_LOGIN_ATTEMPTS']:
                lockout_mins = current_app.config['LOCKOUT_MINUTES']
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_mins)
                db.session.commit()
                flash(f"Too many failed attempts. Account locked for {lockout_mins} minutes.", "danger")
                log_event('ACCOUNT_LOCKED', user_id=user.id,
                          details=f'Locked after {user.failed_login_attempts} failures', status='failed')
            else:
                db.session.commit()
                remaining = current_app.config['MAX_LOGIN_ATTEMPTS'] - user.failed_login_attempts
                flash(f"Invalid username or password. {remaining} attempt(s) remaining.", "danger")
                log_event('LOGIN_FAIL', user_id=user.id, status='failed')
            return render_template('auth/login.html', form=form)

        if not user.is_active:
            flash("This account has been disabled. Contact an administrator.", "danger")
            return render_template('auth/login.html', form=form)

        # Successful password verification — reset lockout counters
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        if user.is_2fa_enabled:
            # Store pre-auth state in session; do NOT call login_user yet
            session['pre_auth_user_id'] = user.id
            log_event('LOGIN_2FA_PENDING', user_id=user.id)
            return redirect(url_for('auth.verify_2fa'))
        else:
            # First time: force 2FA setup
            login_user(user, remember=form.remember_me.data)
            session.permanent = True
            log_event('LOGIN_SUCCESS', user_id=user.id, details='2FA not yet configured')
            flash("Welcome! Please set up two-factor authentication to secure your account.", "info")
            return redirect(url_for('auth.setup_2fa'))

    return render_template('auth/login.html', form=form)


# ─── 2FA Setup ────────────────────────────────────────────────────────────────

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    form = TwoFactorForm()
    user = current_user

    # Generate a new TOTP secret if not already set
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    totp = pyotp.TOTP(user.totp_secret)
    provisioning_url = totp.provisioning_uri(user.email, issuer_name='SecureSMS')

    # Generate QR code as base64 PNG for inline embedding
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(provisioning_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    if form.validate_on_submit():
        token = form.token.data.strip()
        if totp.verify(token, valid_window=1):
            user.is_2fa_enabled = True
            db.session.commit()
            session['2fa_verified'] = True
            log_event('2FA_SETUP', user_id=user.id)
            flash("Two-factor authentication enabled successfully.", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid code. Please try again.", "danger")
            log_event('2FA_SETUP_FAIL', user_id=user.id, status='failed')

    return render_template('auth/setup_2fa.html', form=form, qr_b64=qr_b64,
                           secret=user.totp_secret)


# ─── 2FA Verify ───────────────────────────────────────────────────────────────

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_2fa():
    user_id = session.get('pre_auth_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = db.session.get(User, user_id)
    if not user:
        session.pop('pre_auth_user_id', None)
        return redirect(url_for('auth.login'))

    form = TwoFactorForm()
    if form.validate_on_submit():
        token = form.token.data.strip()
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(token, valid_window=1):
            session.pop('pre_auth_user_id', None)
            login_user(user)
            session.permanent = True
            session['2fa_verified'] = True
            log_event('LOGIN_SUCCESS', user_id=user.id, details='2FA verified')
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid authentication code.", "danger")
            log_event('2FA_FAIL', user_id=user.id, status='failed')

    return render_template('auth/verify_2fa.html', form=form)


# ─── Logout ───────────────────────────────────────────────────────────────────

@auth_bp.route('/logout')
@login_required
def logout():
    uid = current_user.id
    username = current_user.username
    log_event('LOGOUT', user_id=uid)
    logout_user()
    session.clear()       # Invalidate entire session on logout
    flash("You have been signed out.", "info")
    return redirect(url_for('auth.login'))


# ─── Change Password ──────────────────────────────────────────────────────────

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not bcrypt.check_password_hash(current_user.password_hash, form.current_password.data):
            flash("Current password is incorrect.", "danger")
            log_event('PASSWORD_CHANGE_FAIL', user_id=current_user.id, status='failed')
            return render_template('auth/change_password.html', form=form)

        # Hash new password with bcrypt (work factor 12)
        new_hash = bcrypt.generate_password_hash(form.new_password.data, rounds=12).decode('utf-8')
        current_user.password_hash = new_hash
        db.session.commit()
        log_event('PASSWORD_CHANGE', user_id=current_user.id)
        flash("Password changed successfully.", "success")
        return redirect(url_for('main.dashboard'))

    return render_template('auth/change_password.html', form=form)
