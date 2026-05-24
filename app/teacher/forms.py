"""
app/teacher/forms.py — Student Management Forms
"""

from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp, Optional


class StudentForm(FlaskForm):
    student_number = StringField('Student Number', validators=[
        DataRequired(),
        Length(min=4, max=20),
        Regexp(r'^[A-Za-z0-9]+$', message="Student number must be alphanumeric."),
    ])
    name = StringField('Full Name', validators=[
        DataRequired(),
        Length(min=2, max=120),
        Regexp(r"^[A-Za-z\s'\-]+$", message="Name may only contain letters, spaces, hyphens and apostrophes."),
    ])
    email = StringField('Email Address', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address."),
        Length(max=128),
    ])
    phone = StringField('Phone Number', validators=[
        Optional(),
        Length(max=20),
        Regexp(r'^[\d\s\+\-\(\)]*$', message="Phone may only contain digits, spaces, +, -, ()."),
    ])
    grade = StringField('Grade / GPA', validators=[
        Optional(),
        Length(max=10),
        Regexp(r'^[A-F0-9\.\+\-]*$', message="Grade must be a letter grade or GPA value."),
    ])
    course_id = SelectField('Course', coerce=int, validators=[Optional()])
    submit = SubmitField('Save Student')
