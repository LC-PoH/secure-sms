"""
app/admin/routes.py — Admin Blueprint
======================================
Admins can manage user accounts and view the full audit trail.

Security controls:
  - RBAC: @role_required('admin') — only admins may access these routes
  - @require_2fa — 2FA must be verified this session
  - CSRF protection on user creation/deletion forms
  - bcrypt password hashing on user creation
  - Audit logging on all admin actions
"""

from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, abort)
from flask_login import login_required, current_user

from app.extensions import db, bcrypt
from app.models import User, AuditLog, Course, Student
from app.utils.decorators import role_required, require_2fa
from app.utils.audit import log_event
from app.utils.validators import sanitise_input
from app.auth.forms import CreateUserForm

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# ─── Admin Dashboard ──────────────────────────────────────────────────────────

@admin_bp.route('/dashboard')
@login_required
@require_2fa
@role_required('admin')
def dashboard():
    stats = {
        'users': User.query.count(),
        'students': Student.query.count(),
        'courses': Course.query.count(),
        'audit_events': AuditLog.query.count(),
    }
    recent_logs = (AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all())
    return render_template('admin/dashboard.html', stats=stats, recent_logs=recent_logs)


# ─── User Management ──────────────────────────────────────────────────────────

@admin_bp.route('/users')
@login_required
@require_2fa
@role_required('admin')
def users():
    all_users = User.query.order_by(User.username).all()
    return render_template('admin/users.html', users=all_users)


@admin_bp.route('/users/new', methods=['GET', 'POST'])
@login_required
@require_2fa
@role_required('admin')
def create_user():
    form = CreateUserForm()
    if form.validate_on_submit():
        username = sanitise_input(form.username.data.strip())
        email = sanitise_input(form.email.data.strip().lower())

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template('admin/create_user.html', form=form)
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template('admin/create_user.html', form=form)

        # Hash with bcrypt, work factor 12 (OWASP recommended minimum)
        pw_hash = bcrypt.generate_password_hash(form.password.data, rounds=12).decode('utf-8')
        user = User(
            username=username,
            email=email,
            password_hash=pw_hash,
            role=form.role.data,
        )
        db.session.add(user)
        db.session.commit()
        log_event('USER_CREATE', user_id=current_user.id,
                  resource='User', resource_id=user.id,
                  details=f'Created {username} [{form.role.data}]')
        flash(f"User '{username}' created successfully.", "success")
        return redirect(url_for('admin.users'))

    return render_template('admin/create_user.html', form=form)


@admin_bp.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@login_required
@require_2fa
@role_required('admin')
def toggle_active(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for('admin.users'))
    user.is_active = not user.is_active
    db.session.commit()
    action = 'USER_ACTIVATE' if user.is_active else 'USER_DEACTIVATE'
    log_event(action, user_id=current_user.id, resource='User', resource_id=user.id)
    flash(f"User '{user.username}' {'activated' if user.is_active else 'deactivated'}.", "info")
    return redirect(url_for('admin.users'))


# ─── Audit Log ────────────────────────────────────────────────────────────────

@admin_bp.route('/audit')
@login_required
@require_2fa
@role_required('admin')
def audit():
    page = request.args.get('page', 1, type=int)
    logs = (AuditLog.query
            .order_by(AuditLog.timestamp.desc())
            .paginate(page=page, per_page=25, error_out=False))
    return render_template('admin/audit.html', logs=logs)


# ─── Course Management ────────────────────────────────────────────────────────

@admin_bp.route('/courses')
@login_required
@require_2fa
@role_required('admin')
def courses():
    all_courses = Course.query.order_by(Course.code).all()
    teachers = User.query.filter_by(role='teacher').order_by(User.username).all()
    return render_template('admin/courses.html', courses=all_courses, teachers=teachers)


@admin_bp.route('/courses/new', methods=['POST'])
@login_required
@require_2fa
@role_required('admin')
def create_course():
    name = sanitise_input(request.form.get('name', '').strip())
    code = sanitise_input(request.form.get('code', '').strip().upper())
    teacher_id = request.form.get('teacher_id', type=int)

    if not name or not code:
        flash("Course name and code are required.", "danger")
        return redirect(url_for('admin.courses'))

    if Course.query.filter_by(code=code).first():
        flash(f"Course code '{code}' already exists.", "danger")
        return redirect(url_for('admin.courses'))

    course = Course(name=name, code=code, teacher_id=teacher_id or None)
    db.session.add(course)
    db.session.commit()
    log_event('COURSE_CREATE', user_id=current_user.id,
              resource='Course', resource_id=course.id, details=f'{code} — {name}')
    flash(f"Course '{code}' created.", "success")
    return redirect(url_for('admin.courses'))
