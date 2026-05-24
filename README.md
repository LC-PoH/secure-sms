# SecureSMS — Secure Student Management System
### ICT306 Advanced Cybersecurity — Assessment 3

A Flask web application implementing **12 active security controls** following
the 7-phase Secure Software Development Lifecycle (SSDLC).

---

## Quick Start (3 steps)

### Step 1 — Install dependencies
```
cd "secure-sms"
pip install -r requirements.txt
```

### Step 2 — Seed the database with demo accounts
```
python seed.py
```

### Step 3 — Run the server
```
python run.py
```

Open your browser at: **http://127.0.0.1:5000**

---

## Demo Accounts

| Role    | Username | Password              | Access |
|---------|----------|-----------------------|--------|
| Admin   | admin    | Admin@SecureSMS2024!  | Full system |
| Teacher | jsmith   | Teacher@SecureSMS2024!| Own courses + students |
| Teacher | mwang    | Teacher@SecureSMS2024!| Own courses + students |
| Student | S10001   | Student@SecureSMS2024!| Own record only |
| Student | S10002   | Student@SecureSMS2024!| Own record only |

> **NOTE:** On first login, every account must scan the QR code and set up
> TOTP 2FA using **Google Authenticator** or **Authy**.

---

## Security Features Implemented

| Control | Technology | OWASP Category |
|---------|-----------|----------------|
| AES-256-GCM field encryption | `cryptography` AESGCM | A02 Cryptographic Failures |
| bcrypt password hashing (work factor 12) | `Flask-Bcrypt` | A02 |
| TOTP Two-Factor Authentication (RFC 6238) | `pyotp` + QR code | A07 Auth Failures |
| CSRF token on all forms | `Flask-WTF` | A01 Broken Access Control |
| SQL injection prevention | `SQLAlchemy` ORM | A03 Injection |
| XSS input sanitisation | `bleach` + Jinja2 auto-escape | A03 |
| Role-Based Access Control (Admin/Teacher/Student) | Custom decorators | A01 |
| Rate limiting (10 req/min on login) | `Flask-Limiter` | DoS protection |
| Account lockout (5 attempts → 15 min) | DB-backed lockout | A07 |
| HTTP security headers (CSP, X-Frame, etc.) | `after_request` hook | A05 |
| JWT REST API authentication | `Flask-JWT-Extended` | API Security |
| Immutable audit logging | `AuditLog` model | A09 Logging |

---

## REST API (JWT)

### Get a token
```
POST http://127.0.0.1:5000/api/v1/token
Content-Type: application/json

{"username": "admin", "password": "Admin@SecureSMS2024!"}
```

### List students
```
GET http://127.0.0.1:5000/api/v1/students
Authorization: Bearer <token>
```

### Get one student
```
GET http://127.0.0.1:5000/api/v1/students/1
Authorization: Bearer <token>
```

---

## Project Structure

```
secure-sms/
├── run.py                   Entry point
├── seed.py                  Demo data seeder
├── config.py                All security configuration
├── requirements.txt         Pinned dependencies
└── app/
    ├── __init__.py          App factory + blueprints
    ├── models.py            Database models (AES-encrypted PII)
    ├── utils/
    │   ├── crypto.py        AES-256-GCM encrypt/decrypt
    │   ├── validators.py    XSS sanitisation + password policy
    │   ├── decorators.py    RBAC + 2FA session decorators
    │   └── audit.py         Audit event logging
    ├── auth/                Login, 2FA setup/verify, logout
    ├── admin/               User + course management
    ├── teacher/             Student CRUD
    ├── student/             Self-service portal
    └── api/                 JWT REST API
```

---

## SSDLC Phases Covered

| Phase | Description | Implementation |
|-------|-------------|----------------|
| 1 | Security Requirements | `config.py` + report Section 3 |
| 2 | Threat Modelling | STRIDE analysis in report Section 4 |
| 3 | Secure Design | RBAC, encryption architecture, report Section 5 |
| 4 | Secure Implementation | All `app/` modules |
| 5 | Security Testing | Manual pen tests documented in report Section 7 |
| 6 | Secure Deployment | Production guide in report Section 8 |
| 7 | Maintenance & Monitoring | `AuditLog` + /admin/audit, report Section 9 |

---

