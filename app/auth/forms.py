"""
app/auth/forms.py — WTForms with CSRF protection
=================================================
Every form that modifies server state includes a CSRF token (Flask-WTF).
All fields carry strict validators to prevent injection and bad data.

OWASP A04:2021 — Insecure Design (CSRF)
OWASP A03:2021 — Injection (input validation)
"""

from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, BooleanField,
                     SelectField, SubmitField)
from wtforms.validators import (DataRequired, Email, Length,
                                EqualTo, Regexp, ValidationError)
from app.utils.validators import validate_password_strength


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64),
        Regexp(r'^[\w.-]+$', message="Username may only contain letters, digits, dots and hyphens."),
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, max=128),
    ])
    remember_me = BooleanField('Keep me signed in')
    submit = SubmitField('Sign In')


class TwoFactorForm(FlaskForm):
    token = StringField('Authenticator Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message="Code must be exactly 6 digits."),
        Regexp(r'^\d{6}$', message="Code must be 6 numeric digits."),
    ])
    submit = SubmitField('Verify')


class CreateUserForm(FlaskForm):
    """Admin-only form to create a new user account."""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64),
        Regexp(r'^[\w.-]+$', message="Letters, digits, dots and hyphens only."),
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address."),
        Length(max=128),
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=12, max=128),
    ])
    confirm = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match."),
    ])
    role = SelectField('Role', choices=[
        ('admin', 'Admin'),
        ('teacher', 'Teacher'),
        ('student', 'Student'),
    ], validators=[DataRequired()])
    submit = SubmitField('Create Account')

    def validate_password(self, field):
        ok, errors = validate_password_strength(field.data)
        if not ok:
            raise ValidationError(' '.join(errors))


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=12, max=128),
    ])
    confirm = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message="Passwords must match."),
    ])
    submit = SubmitField('Change Password')

    def validate_new_password(self, field):
        ok, errors = validate_password_strength(field.data)
        if not ok:
            raise ValidationError(' '.join(errors))
