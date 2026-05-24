"""
config.py — Application Configuration
Implements secure defaults for all Flask extensions.
In production, all secrets MUST come from environment variables.
"""

import os
import secrets
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

# ─── Key Management ──────────────────────────────────────────────────────────
# AES-256 field encryption key (32 bytes). Generated once, saved to .key file.
# In production: load from HSM / AWS Secrets Manager / Azure Key Vault.

_KEY_FILE = os.path.join(basedir, '.encryption_key')


def _load_or_create_encryption_key() -> bytes:
    """Load the AES-256-GCM database-field encryption key from disk,
    or generate and persist a new one on first run."""
    env_key = os.environ.get('ENCRYPTION_KEY')
    if env_key:
        raw = bytes.fromhex(env_key)
        if len(raw) != 32:
            raise ValueError("ENCRYPTION_KEY must be 64 hex chars (256 bits).")
        return raw
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, 'rb') as fh:
            return fh.read()
    key = os.urandom(32)          # CSPRNG — 256-bit AES key
    with open(_KEY_FILE, 'wb') as fh:
        fh.write(key)
    return key


class Config:
    # ── Flask ────────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # ── Database ─────────────────────────────────────────────────────────────
    # Uses SMS_DATABASE_URL (not DATABASE_URL) to avoid conflicts with
    # other environment variables (e.g. Heroku / cloud providers).
    SQLALCHEMY_DATABASE_URI: str = (
        os.environ.get('SMS_DATABASE_URL') or
        'sqlite:///' + os.path.join(basedir, 'secure_sms.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── CSRF ─────────────────────────────────────────────────────────────────
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600       # tokens expire after 1 hour

    # ── Session cookies ───────────────────────────────────────────────────────
    # SESSION_COOKIE_SECURE = True should be set in production (requires HTTPS)
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False') == 'True'
    SESSION_COOKIE_HTTPONLY = True   # Deny JS access to session cookie
    SESSION_COOKIE_SAMESITE = 'Lax' # CSRF mitigation
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # Idle timeout

    # ── Rate limiting ─────────────────────────────────────────────────────────
    RATELIMIT_STORAGE_URL = 'memory://'
    RATELIMIT_DEFAULT = '200 per day'
    RATELIMIT_HEADERS_ENABLED = True

    # ── JWT (REST API) ────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = os.environ.get('JWT_SECRET_KEY') or secrets.token_hex(32)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'

    # ── Field encryption ──────────────────────────────────────────────────────
    ENCRYPTION_KEY: bytes = _load_or_create_encryption_key()

    # ── Account lockout policy ────────────────────────────────────────────────
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15

    # ── Password policy ───────────────────────────────────────────────────────
    MIN_PASSWORD_LENGTH = 12

    # ── Security headers (applied in app factory) ─────────────────────────────
    SECURITY_HEADERS = {
        'X-Frame-Options': 'SAMEORIGIN',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net data:;"
        ),
    }
