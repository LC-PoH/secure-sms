"""
seed.py — Populate the database with demo accounts and sample data.
Run ONCE after first install:  python seed.py

Demo Accounts:
  Admin   → username: admin      password: Admin@SecureSMS2024!
  Teacher → username: jsmith     password: Teacher@SecureSMS2024!
  Student → username: S10001     password: Student@SecureSMS2024!

WARNING: Change all passwords immediately in a real deployment.
"""

from app import create_app
from app.extensions import db, bcrypt
from app.models import User, Course, Student
from app.utils.crypto import encrypt_field
from flask import current_app


def seed():
    app = create_app()
    with app.app_context():
        key = current_app.config['ENCRYPTION_KEY']

        # ── Users ──────────────────────────────────────────────────────────────
        users_data = [
            {'username': 'admin',  'email': 'admin@sms.local',
             'password': 'Admin@SecureSMS2024!',  'role': 'admin'},
            {'username': 'jsmith', 'email': 'jsmith@sms.local',
             'password': 'Teacher@SecureSMS2024!', 'role': 'teacher'},
            {'username': 'mwang',  'email': 'mwang@sms.local',
             'password': 'Teacher@SecureSMS2024!', 'role': 'teacher'},
            {'username': 'S10001', 'email': 'alice@student.edu',
             'password': 'Student@SecureSMS2024!', 'role': 'student'},
            {'username': 'S10002', 'email': 'bob@student.edu',
             'password': 'Student@SecureSMS2024!', 'role': 'student'},
        ]

        created_users = {}
        for ud in users_data:
            if not User.query.filter_by(username=ud['username']).first():
                pw_hash = bcrypt.generate_password_hash(ud['password'], rounds=12).decode('utf-8')
                u = User(username=ud['username'], email=ud['email'],
                         password_hash=pw_hash, role=ud['role'])
                db.session.add(u)
                db.session.flush()
                created_users[ud['username']] = u
                print(f"  [+] Created user: {ud['username']} [{ud['role']}]")

        db.session.commit()

        # ── Courses ─────────────────────────────────────────────────────────────
        jsmith = User.query.filter_by(username='jsmith').first()
        mwang  = User.query.filter_by(username='mwang').first()

        courses_data = [
            {'code': 'ICT306', 'name': 'Advanced Cybersecurity',   'teacher': jsmith},
            {'code': 'ICT201', 'name': 'Network Fundamentals',     'teacher': jsmith},
            {'code': 'ICT410', 'name': 'Cloud Security',           'teacher': mwang},
        ]

        created_courses = {}
        for cd in courses_data:
            if not Course.query.filter_by(code=cd['code']).first():
                c = Course(code=cd['code'], name=cd['name'],
                           teacher_id=cd['teacher'].id if cd['teacher'] else None)
                db.session.add(c)
                db.session.flush()
                created_courses[cd['code']] = c
                print(f"  [+] Created course: {cd['code']} — {cd['name']}")

        db.session.commit()

        # ── Students ────────────────────────────────────────────────────────────
        ict306 = Course.query.filter_by(code='ICT306').first()
        admin_user = User.query.filter_by(username='admin').first()

        students_data = [
            {'sn': 'S10001', 'name': 'Alice Johnson',  'email': 'alice@student.edu',
             'phone': '+64 21 111 2222', 'grade': 'A',  'course': ict306},
            {'sn': 'S10002', 'name': 'Bob Nguyen',     'email': 'bob@student.edu',
             'phone': '+64 21 333 4444', 'grade': 'B+', 'course': ict306},
            {'sn': 'S10003', 'name': 'Carol Smith',    'email': 'carol@student.edu',
             'phone': '+64 21 555 6666', 'grade': 'A-', 'course': ict306},
        ]

        for sd in students_data:
            if not Student.query.filter_by(student_number=sd['sn']).first():
                s = Student(
                    student_number=sd['sn'],
                    name_enc=encrypt_field(sd['name'], key),
                    email_enc=encrypt_field(sd['email'], key),
                    phone_enc=encrypt_field(sd['phone'], key),
                    grade_enc=encrypt_field(sd['grade'], key),
                    course_id=sd['course'].id if sd['course'] else None,
                    created_by=admin_user.id,
                )
                db.session.add(s)
                print(f"  [+] Created student: {sd['sn']} — {sd['name']}")

        db.session.commit()

        print("\n" + "="*55)
        print("  SEED COMPLETE — Demo Accounts")
        print("="*55)
        print("  Role     | Username | Password")
        print("  ---------|----------|--------------------------")
        print("  Admin    | admin    | Admin@SecureSMS2024!")
        print("  Teacher  | jsmith   | Teacher@SecureSMS2024!")
        print("  Teacher  | mwang    | Teacher@SecureSMS2024!")
        print("  Student  | S10001   | Student@SecureSMS2024!")
        print("  Student  | S10002   | Student@SecureSMS2024!")
        print("="*55)
        print("  NOTE: 2FA setup is required on first login.")
        print("        Use Google Authenticator or Authy.\n")


if __name__ == '__main__':
    seed()
