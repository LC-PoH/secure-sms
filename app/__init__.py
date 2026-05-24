"""
app/__init__.py — Application Factory
======================================
Creates and configures the Flask application following the factory pattern.
All security extensions are initialised here.
"""

from flask import Flask, render_template, redirect, url_for, session
from flask_login import current_user

from config import Config
from app.extensions import db, login_manager, bcrypt, csrf, limiter, jwt


def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    # ── Initialise extensions ─────────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    jwt.init_app(app)

    # ── Flask-Login configuration ─────────────────────────────────────────────
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Please sign in to access this page."
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id: str):
        from app.models import User
        return db.session.get(User, int(user_id))

    # ── Security headers (applied to every response) ──────────────────────────
    @app.after_request
    def set_security_headers(response):
        for header, value in app.config.get('SECURITY_HEADERS', {}).items():
            response.headers[header] = value
        return response

    # ── Register blueprints ───────────────────────────────────────────────────
    from app.auth.routes import auth_bp
    from app.admin.routes import admin_bp
    from app.teacher.routes import teacher_bp
    from app.student.routes import student_bp
    from app.api.routes import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(teacher_bp)
    app.register_blueprint(student_bp)
    app.register_blueprint(api_bp)

    # JWT API routes are stateless — exempt from CSRF
    csrf.exempt(api_bp)

    # ── Main / Dashboard route ────────────────────────────────────────────────
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('main.dashboard'))
        return redirect(url_for('auth.login'))

    # Role-based dashboard router
    from flask import Blueprint as BP
    main_bp = BP('main', __name__)

    @main_bp.route('/dashboard')
    def dashboard():
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        # 2FA gate
        if current_user.is_2fa_enabled and not session.get('2fa_verified'):
            return redirect(url_for('auth.verify_2fa'))
        role = current_user.role
        if role == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif role == 'teacher':
            return redirect(url_for('teacher.students'))
        else:
            return redirect(url_for('student.dashboard'))

    app.register_blueprint(main_bp)

    # ── Error handlers ────────────────────────────────────────────────────────
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    # ── Create tables on first run ────────────────────────────────────────────
    with app.app_context():
        db.create_all()

    return app
