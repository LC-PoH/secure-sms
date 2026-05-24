"""
app/api/routes.py — JWT-Protected REST API
===========================================
Provides a token-based API for integration with other systems.
All endpoints require a valid Bearer JWT token.

Security controls:
  - JWT authentication (Flask-JWT-Extended)
  - RBAC enforced at API level
  - Rate limiting: 30 requests per minute
  - Input validation on all POST data
  - CSRF exempted (stateless API — CSRF does not apply to Bearer-token auth)

OWASP API Security Top 10:
  API1 — Broken Object Level Authorisation: teachers only see their students
  API2 — Broken Authentication: JWT required on every endpoint
  API3 — Broken Object Property Level: only safe fields exposed in responses
  API5 — Broken Function Level Authorisation: role check on each route
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity
)
from app.extensions import db, bcrypt, limiter
from app.models import User, Student, Course
from app.utils.crypto import decrypt_field
from app.utils.validators import sanitise_input
from flask import current_app

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')


# ─── Token Endpoint ───────────────────────────────────────────────────────────

@api_bp.route('/token', methods=['POST'])
@limiter.limit("5 per minute")
def get_token():
    """
    POST /api/v1/token
    Body: { "username": "...", "password": "..." }
    Returns: { "access_token": "..." }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify(error="Request body must be JSON."), 400

    username = sanitise_input(data.get('username', ''))
    password = data.get('password', '')

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify(error="Invalid credentials."), 401

    if not user.is_active:
        return jsonify(error="Account disabled."), 403

    # Identity payload: { id, role }
    token = create_access_token(identity={'id': user.id, 'role': user.role})
    return jsonify(access_token=token), 200


# ─── Students Collection ──────────────────────────────────────────────────────

@api_bp.route('/students', methods=['GET'])
@jwt_required()
@limiter.limit("30 per minute")
def list_students():
    """
    GET /api/v1/students
    Returns decrypted student list (admin: all; teacher: own courses only).
    """
    identity = get_jwt_identity()
    role = identity.get('role')
    user_id = identity.get('id')
    key = current_app.config['ENCRYPTION_KEY']

    if role == 'admin':
        records = Student.query.all()
    elif role == 'teacher':
        user = db.session.get(User, user_id)
        course_ids = [c.id for c in user.taught_courses]
        records = Student.query.filter(Student.course_id.in_(course_ids)).all()
    else:
        return jsonify(error="Forbidden."), 403

    result = []
    for s in records:
        result.append({
            'id': s.id,
            'student_number': s.student_number,
            'name': decrypt_field(s.name_enc, key),
            'email': decrypt_field(s.email_enc, key),
            'grade': decrypt_field(s.grade_enc, key) if s.grade_enc else None,
            'course': s.course.code if s.course else None,
        })
    return jsonify(students=result), 200


# ─── Single Student ───────────────────────────────────────────────────────────

@api_bp.route('/students/<int:student_id>', methods=['GET'])
@jwt_required()
@limiter.limit("30 per minute")
def get_student(student_id):
    """GET /api/v1/students/<id>  — returns one decrypted student record."""
    identity = get_jwt_identity()
    role = identity.get('role')
    user_id = identity.get('id')
    key = current_app.config['ENCRYPTION_KEY']

    student = db.session.get(Student, student_id)
    if not student:
        return jsonify(error="Student not found."), 404

    # Object-level authorisation: teachers only access their courses' students
    if role == 'teacher':
        user = db.session.get(User, user_id)
        course_ids = [c.id for c in user.taught_courses]
        if student.course_id not in course_ids:
            return jsonify(error="Forbidden."), 403
    elif role not in ('admin',):
        return jsonify(error="Forbidden."), 403

    return jsonify({
        'id': student.id,
        'student_number': student.student_number,
        'name': decrypt_field(student.name_enc, key),
        'email': decrypt_field(student.email_enc, key),
        'phone': decrypt_field(student.phone_enc, key) if student.phone_enc else None,
        'grade': decrypt_field(student.grade_enc, key) if student.grade_enc else None,
        'course': student.course.code if student.course else None,
    }), 200
