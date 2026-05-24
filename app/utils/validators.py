"""
app/utils/validators.py — Input Validation & XSS Sanitisation
==============================================================
All user-supplied input passes through sanitise_input() before being
stored or rendered.  Jinja2's autoescaping provides a second layer of
defence at render time.

OWASP A03:2021 — Injection
OWASP A07:2021 — Cross-Site Scripting (XSS)
"""

import re
import bleach

# Whitelist of HTML tags/attributes allowed in rich-text fields (none in this app)
ALLOWED_TAGS: list = []
ALLOWED_ATTRIBUTES: dict = {}


def sanitise_input(value: str) -> str:
    """
    Strip all HTML tags and encode dangerous characters.
    Uses the bleach library (OWASP-recommended for Python XSS prevention).

    :param value: Raw string from user input.
    :returns:     Sanitised, HTML-free string safe for DB storage.
    """
    if not value or not isinstance(value, str):
        return value
    # Remove all HTML tags — no HTML is expected in these fields
    cleaned = bleach.clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)
    return cleaned.strip()


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Enforce password policy (OWASP Authentication Cheat Sheet):
      - Minimum 12 characters
      - At least one uppercase letter
      - At least one lowercase letter
      - At least one digit
      - At least one special character

    :returns: (is_valid: bool, errors: list[str])
    """
    errors = []
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long.")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password):
        errors.append("Password must contain at least one special character.")
    return len(errors) == 0, errors


def validate_student_number(sn: str) -> bool:
    """Student numbers must be alphanumeric, 4-20 chars."""
    return bool(re.fullmatch(r'[A-Za-z0-9]{4,20}', sn or ''))
