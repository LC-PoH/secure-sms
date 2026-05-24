"""
app/teacher/routes.py — Teacher Blueprint
==========================================
Teachers can create, view, update and delete student records in their courses.
All PII is encrypted before storage and decrypted on retrieval.

Security controls applied:
  - @login_required + @role_required('teacher','admin') — RBAC
  - @require_2fa — session-level 2FA check
  - sanitise_input() — XSS prevention on every field
  - encrypt_field() — AES-256-GCM PII encryption
  - SQLAlchemy ORM — no raw SQL (SQL injection prevention)
  - CSRF token on every form (Flask-WTF)
  - Audit log on every mutating operation
"""

from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, current_app, abort)
from flask_login import login_required, current_user

from app.extensions import db
from app.models import Student, Course, AuditLog
from app.utils.crypto import encrypt_field, decrypt_field
from app.utils.validators import sanitise_input, validate_student_number
from app.utils.decorators import role_required, require_2fa
from app.utils.audit import log_event
from .forms import StudentForm

teacher_bp = Blueprint('teacher', __name__, url_prefix='/teacher')


def _get_key():
    return current_app.config['ENCRYPTION_KEY']


def _decrypt_student(s: Student) -> dict:
    """Return a plain-dict of decrypted student fields for template rendering."""
    key = _get_key()
    return {
        'id': s.id,
        'student_number': s.student_number,
        'name': decrypt_field(s.name_enc, key),
        'email': decrypt_field(s.email_enc, key),
        'phone': decrypt_field(s.phone_enc, key) if s.phone_enc else '',
        'grade': decrypt_field(s.grade_enc, key) if s.grade_enc else '',
        'course': s.course.name if s.course else '—',
        'created_at': s.created_at,
    }


# ─── Student List ─────────────────────────────────────────────────────────────

@teacher_bp.route('/students')
@login_required
@require_2fa
@role_required('teacher', 'admin')
def students():
    # Teachers see only their courses' students; admins see all
    if current_user.role == 'admin':
        student_records = Student.query.order_by(Student.student_number).all()
    else:
        course_ids = [c.id for c in current_user.taught_courses]
        student_records = (Student.query
                           .filter(Student.course_id.in_(course_ids))
                           .order_by(Student.student_number).all())
    students_data = [_decrypt_student(s) for s in student_records]
    return render_template('teacher/students.html', students=students_data)


# ─── Add Student ──────────────────────────────────────────────────────────────

@teacher_bp.route('/students/new', methods=['GET', 'POST'])
@login_required
@require_2fa
@role_required('teacher', 'admin')
def add_student():
    form = StudentForm()
    # Populate course choices
    if current_user.role == 'admin':
        courses = Course.query.all()
    else:
        courses = current_user.taught_courses
    form.course_id.choices = [(0, '— No Course —')] + [(c.id, f"{c.code} — {c.name}") for c in courses]

    if form.validate_on_submit():
        sn = sanitise_input(form.student_number.data.upper())
        if not validate_student_number(sn):
            flash("Invalid student number format.", "danger")
            return render_template('teacher/add_student.html', form=form)

        if Student.query.filter_by(student_number=sn).first():
            flash("A student with that number already exists.", "danger")
            return render_template('teacher/add_student.html', form=form)

        key = _get_key()
        student = Student(
            student_number=sn,
            name_enc=encrypt_field(sanitise_input(form.name.data), key),
            email_enc=encrypt_field(sanitise_input(form.email.data.lower()), key),
            phone_enc=encrypt_field(sanitise_input(form.phone.data), key) if form.phone.data else None,
            grade_enc=encrypt_field(sanitise_input(form.grade.data), key) if form.grade.data else None,
            course_id=form.course_id.data or None,
            created_by=current_user.id,
        )
        db.session.add(student)
        db.session.commit()
        log_event('STUDENT_CREATE', user_id=current_user.id,
                  resource='Student', resource_id=student.id,
                  details=f'Student number: {sn}')
        flash(f"Student {sn} added successfully.", "success")
        return redirect(url_for('teacher.students'))

    return render_template('teacher/add_student.html', form=form)


# ─── Edit Student ─────────────────────────────────────────────────────────────

@teacher_bp.route('/students/<int:student_id>/edit', methods=['GET', 'POST'])
@login_required
@require_2fa
@role_required('teacher', 'admin')
def edit_student(student_id):
    student = db.session.get(Student, student_id)
    if not student:
        abort(404)

    # Teachers may only edit students in their courses
    if current_user.role == 'teacher':
        teacher_course_ids = [c.id for c in current_user.taught_courses]
        if student.course_id not in teacher_course_ids:
            abort(403)

    key = _get_key()
    form = StudentForm()
    if current_user.role == 'admin':
        courses = Course.query.all()
    else:
        courses = current_user.taught_courses
    form.course_id.choices = [(0, '— No Course —')] + [(c.id, f"{c.code} — {c.name}") for c in courses]

    if form.validate_on_submit():
        student.name_enc = encrypt_field(sanitise_input(form.name.data), key)
        student.email_enc = encrypt_field(sanitise_input(form.email.data.lower()), key)
        student.phone_enc = encrypt_field(sanitise_input(form.phone.data), key) if form.phone.data else None
        student.grade_enc = encrypt_field(sanitise_input(form.grade.data), key) if form.grade.data else None
        student.course_id = form.course_id.data or None
        db.session.commit()
        log_event('STUDENT_UPDATE', user_id=current_user.id,
                  resource='Student', resource_id=student.id)
        flash("Student record updated.", "success")
        return redirect(url_for('teacher.students'))

    # Pre-fill form with decrypted values on GET
    if request.method == 'GET':
        form.student_number.data = student.student_number
        form.name.data = decrypt_field(student.name_enc, key)
        form.email.data = decrypt_field(student.email_enc, key)
        form.phone.data = decrypt_field(student.phone_enc, key) if student.phone_enc else ''
        form.grade.data = decrypt_field(student.grade_enc, key) if student.grade_enc else ''
        form.course_id.data = student.course_id or 0

    return render_template('teacher/edit_student.html', form=form, student=student)


# ─── Delete Student ───────────────────────────────────────────────────────────

@teacher_bp.route('/students/<int:student_id>/delete', methods=['POST'])
@login_required
@require_2fa
@role_required('teacher', 'admin')
def delete_student(student_id):
    student = db.session.get(Student, student_id)
    if not student:
        abort(404)

    if current_user.role == 'teacher':
        teacher_course_ids = [c.id for c in current_user.taught_courses]
        if student.course_id not in teacher_course_ids:
            abort(403)

    sn = student.student_number
    db.session.delete(student)
    db.session.commit()
    log_event('STUDENT_DELETE', user_id=current_user.id,
              resource='Student', resource_id=student_id,
              details=f'Student number: {sn}')
    flash(f"Student {sn} deleted.", "warning")
    return redirect(url_for('teacher.students'))
