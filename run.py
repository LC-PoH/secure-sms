"""
run.py — Application Entry Point
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    # debug=False in production; use a WSGI server (gunicorn/waitress)
    app.run(host='127.0.0.1', port=5000, debug=False)
