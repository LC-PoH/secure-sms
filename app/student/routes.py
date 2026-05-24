"""
app/student/routes.py — Student Self-Service Portal
=====================================================
Students can view their own record only — strict ownership enforcement.
"""

from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.models import Student
from app.utils.crypto import decrypt_field
from app.utils.decorators import role_required, require_2fa
from flask import current_app

student_bp = Blueprint('student', __name__, url_prefix='/student')


@student_bp.route('/dashboard')
@login_required
@require_2fa
@role_required('student')
def dashboard():
    # Students can only view their OWN record — ownership enforced here
    # The student record's student_number matches their username by convention
    record = Student.query.filter_by(student_number=current_user.username.upper()).first()

    if not record:
        return render_template('student/dashboard.html', student=None)

    key = current_app.config['ENCRYPTION_KEY']
    student_data = {
        'student_number': record.student_number,
        'name': decrypt_field(record.name_enc, key),
        'email': decrypt_field(record.email_enc, key),
        'phone': decrypt_field(record.phone_enc, key) if record.phone_enc else '—',
        'grade': decrypt_field(record.grade_enc, key) if record.grade_enc else '—',
        'course': record.course.name if record.course else '—',
    }
    return render_template('student/dashboard.html', student=student_data)
