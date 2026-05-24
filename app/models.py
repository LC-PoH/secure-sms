"""
app/models.py — Database models
All PII fields (name, email, phone, grade) are stored AES-256-GCM encrypted.
No raw SQL anywhere — SQLAlchemy ORM prevents SQL Injection by design.
"""

from datetime import datetime, timezone
from flask_login import UserMixin
from app.extensions import db


class User(db.Model, UserMixin):
    """System users: Admin, Teacher, Student (role-based)."""
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)   # bcrypt hash
    role = db.Column(db.String(20), nullable=False, default='student')  # admin | teacher | student

    # 2FA (TOTP — RFC 6238)
    totp_secret = db.Column(db.String(64), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)

    # Account lockout (brute-force protection)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    # Account state
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relationships
    created_students = db.relationship('Student', backref='creator', lazy=True,
                                        foreign_keys='Student.created_by')
    taught_courses = db.relationship('Course', backref='teacher', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)

    def get_id(self):
        return str(self.id)

    def is_locked(self) -> bool:
        if self.locked_until and self.locked_until > datetime.now(timezone.utc):
            return True
        return False

    def __repr__(self):
        return f'<User {self.username} [{self.role}]>'


class Course(db.Model):
    """Academic course — links teachers to students."""
    __tablename__ = 'course'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    students = db.relationship('Student', backref='course', lazy=True)

    def __repr__(self):
        return f'<Course {self.code}>'


class Student(db.Model):
    """
    Student record — PII stored encrypted.
    student_number kept plaintext for indexing; all personal data is ciphertext.
    """
    __tablename__ = 'student'

    id = db.Column(db.Integer, primary_key=True)

    # Plaintext identifier (used for lookup — not PII)
    student_number = db.Column(db.String(20), unique=True, nullable=False, index=True)

    # AES-256-GCM encrypted PII fields (see app/utils/crypto.py)
    name_enc = db.Column(db.Text, nullable=False)
    email_enc = db.Column(db.Text, nullable=False)
    phone_enc = db.Column(db.Text, nullable=True)
    grade_enc = db.Column(db.Text, nullable=True)

    # Relations
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    created_at = db.Column(db.DateTime(timezone=True),
                           default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True),
                           default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Student {self.student_number}>'


class AuditLog(db.Model):
    """
    Immutable audit trail — every authentication and data-mutation event
    is recorded here for forensic review. Satisfies SSDLC Phase 7.
    """
    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)    # LOGIN_SUCCESS, LOGIN_FAIL, etc.
    resource = db.Column(db.String(50), nullable=True)   # Student, User, Course
    resource_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), default='success') # success | failed
    timestamp = db.Column(db.DateTime(timezone=True),
                          default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f'<AuditLog {self.action} @ {self.timestamp}>'
