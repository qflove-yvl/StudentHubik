from flask import flash
from flask import Flask, render_template, redirect, url_for, request
from flask import Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io
import os
import re
import socket


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')
app.config['ADMIN_EMAIL'] = os.getenv('ADMIN_EMAIL', 'admin@studenthubik.local').lower()
app.config['ADMIN_PASSWORD'] = os.getenv('ADMIN_PASSWORD', 'admin12345')


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    group_id = db.Column(db.Integer)

    is_verified = db.Column(db.Boolean, default=False)
    telegram = db.Column(db.String(100))


class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    code = db.Column(db.String(6))


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    teacher = db.relationship('User', backref='subjects')


class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'))
    grade = db.Column(db.Integer)

    student = db.relationship('User', foreign_keys=[student_id])
    subject = db.relationship('Subject')


def ensure_default_groups():
    if Group.query.count() == 0:
        for group_name in ['ИС-101', 'ИС-102', 'ИС-201']:
            db.session.add(Group(name=group_name))
        db.session.commit()


def ensure_admin_user():
    admin_email = app.config['ADMIN_EMAIL']
    existing_admin = User.query.filter_by(email=admin_email).first()
    if existing_admin:
        if existing_admin.role != 'admin':
            existing_admin.role = 'admin'
            existing_admin.is_verified = True
            db.session.commit()
        return

    db.session.add(
        User(
            name='Администратор',
            email=admin_email,
            password=generate_password_hash(app.config['ADMIN_PASSWORD']),
            role='admin',
            is_verified=True
        )
    )
    db.session.commit()


def ensure_teacher_subjects(teacher_id):
    defaults = ['Математика', 'Информатика', 'Английский']
    existing = {
        subject.name.lower()
        for subject in Subject.query.filter_by(teacher_id=teacher_id).all()
    }

    created = False
    for subject_name in defaults:
        if subject_name.lower() not in existing:
            db.session.add(Subject(name=subject_name, teacher_id=teacher_id))
            created = True

    if created:
        db.session.commit()


def normalize_group_name(group_name):
    return group_name.strip().upper()


def email_looks_real(email):
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return False

    domain = email.split('@')[-1]
    try:
        socket.getaddrinfo(domain, None)
    except socket.gaierror:
        return False

    return True


@app.before_request
def initialize_database():
    if app.config.get('DB_INITIALIZED'):
        return

    db.create_all()
    ensure_default_groups()
    ensure_admin_user()
    app.config['DB_INITIALIZED'] = True


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role')
        group_name = request.form.get('group_name', '').strip()

        if not name or not email or not password or not role:
            flash('Заполните все обязательные поля')
            return redirect(url_for('register'))

        if not email_looks_real(email):
            flash('Email выглядит некорректно или домен недоступен')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Пароли не совпадают')
            return redirect(url_for('register'))

        if role not in {'student', 'teacher'}:
            flash('Выберите корректную роль')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует')
            return redirect(url_for('register'))

        selected_group_id = None
        if role == 'student':
            if not group_name:
                flash('Для студента нужно указать группу')
                return redirect(url_for('register'))

            normalized_group = normalize_group_name(group_name)
            group = Group.query.filter_by(name=normalized_group).first()
            if not group:
                group = Group(name=normalized_group)
                db.session.add(group)
                db.session.flush()
            selected_group_id = group.id

        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            role=role,
            group_id=selected_group_id,
            is_verified=(role == 'student')
        )

        db.session.add(new_user)
        db.session.commit()

        if role == 'teacher':
            flash('Заявка преподавателя отправлена. Дождитесь одобрения администратора.')
        else:
            flash('Регистрация успешна. Теперь войдите в аккаунт.')

        return redirect(url_for('login', role=role))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    role = request.args.get('role', 'student')

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        selected_role = request.form.get('role')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if selected_role not in {'student', 'teacher', 'admin'}:
                selected_role = user.role

            if user.role != selected_role:
                flash('Вы пытаетесь войти не в ту роль')
                return redirect(url_for('login', role=user.role))

            if user.role == 'teacher' and not user.is_verified:
                flash('Доступ преподавателя ещё не одобрен администратором')
                return redirect(url_for('login', role='teacher'))

            login_user(user)

            if user.role == 'teacher':
                ensure_teacher_subjects(user.id)
                return redirect(url_for('teacher_dashboard'))
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('student_dashboard'))

        flash('Неверный email или пароль')

    return render_template('login.html', role=role)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'student':
        return redirect(url_for('student_dashboard'))

    if current_user.role == 'teacher':
        return redirect(url_for('teacher_dashboard'))

    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        telegram = request.form.get('telegram', '').strip()

        if not name:
            flash('Имя не может быть пустым')
            return redirect(url_for('profile'))

        current_user.name = name
        current_user.telegram = telegram
        db.session.commit()
        flash('Профиль обновлён')
        return redirect(url_for('profile'))

    return render_template('profile.html')


@app.route('/student')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('teacher_dashboard'))

    grades = Grade.query.filter_by(student_id=current_user.id).all()
    grade_values = [grade.grade for grade in grades]
    average_grade = round(sum(grade_values) / len(grade_values), 2) if grade_values else 0
    subject_count = len({grade.subject_id for grade in grades})
    best_grade = max(grade_values) if grade_values else '—'
    worst_grade = min(grade_values) if grade_values else '—'

    return render_template(
        'student_dashboard.html',
        grades=grades,
        average_grade=average_grade,
        subject_count=subject_count,
        best_grade=best_grade,
        worst_grade=worst_grade
    )


@app.route('/student/export-grades')
@login_required
def export_student_grades():
    if current_user.role != 'student':
        return redirect(url_for('teacher_dashboard'))

    grades = Grade.query.filter_by(student_id=current_user.id).all()

    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(['subject', 'grade'])
    for item in grades:
        writer.writerow([item.subject.name, item.grade])

    return Response(
        stream.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=my_grades.csv'}
    )


@app.route('/teacher', methods=['GET', 'POST'])
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        return redirect(url_for('student_dashboard'))

    ensure_teacher_subjects(current_user.id)

    students = User.query.filter_by(role='student').order_by(User.name).all()
    subjects = Subject.query.filter_by(teacher_id=current_user.id).order_by(Subject.name).all()

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        subject_id = request.form.get('subject_id')
        grade_value = request.form.get('value')

        if not student_id or not subject_id or not grade_value:
            flash('Заполните все поля для выставления оценки')
            return redirect(url_for('teacher_dashboard'))

        student = User.query.filter_by(id=student_id, role='student').first()
        subject = Subject.query.filter_by(id=subject_id, teacher_id=current_user.id).first()

        try:
            numeric_grade = int(grade_value)
        except (TypeError, ValueError):
            flash('Оценка должна быть числом')
            return redirect(url_for('teacher_dashboard'))

        if numeric_grade < 1 or numeric_grade > 5:
            flash('Оценка должна быть от 1 до 5')
            return redirect(url_for('teacher_dashboard'))

        if not student or not subject:
            flash('Выбраны некорректные студент или предмет')
            return redirect(url_for('teacher_dashboard'))

        existing_grade = Grade.query.filter_by(student_id=student.id, subject_id=subject.id).first()
        if existing_grade:
            existing_grade.grade = numeric_grade
            flash(f'Оценка обновлена: {student.name} / {subject.name} = {numeric_grade}')
        else:
            new_grade = Grade(student_id=student.id, subject_id=subject.id, grade=numeric_grade)
            db.session.add(new_grade)
            flash(f'Оценка выставлена: {student.name} / {subject.name} = {numeric_grade}')

        db.session.commit()
        return redirect(url_for('teacher_dashboard'))

    recent_grades = (
        Grade.query.join(Subject)
        .filter(Subject.teacher_id == current_user.id)
        .order_by(Grade.id.desc())
        .limit(10)
        .all()
    )

    return render_template(
        'teacher_dashboard.html',
        students=students,
        subjects=subjects,
        recent_grades=recent_grades
    )


@app.route('/teacher/subject', methods=['POST'])
@login_required
def create_subject():
    if current_user.role != 'teacher':
        return redirect(url_for('student_dashboard'))

    subject_name = request.form.get('subject_name', '').strip()
    if not subject_name:
        flash('Введите название предмета')
        return redirect(url_for('teacher_dashboard'))

    exists = Subject.query.filter_by(name=subject_name, teacher_id=current_user.id).first()
    if exists:
        flash('Такой предмет уже существует')
        return redirect(url_for('teacher_dashboard'))

    db.session.add(Subject(name=subject_name, teacher_id=current_user.id))
    db.session.commit()
    flash(f'Предмет «{subject_name}» добавлен')
    return redirect(url_for('teacher_dashboard'))


@app.route('/teacher/export-grades')
@login_required
def export_teacher_grades():
    if current_user.role != 'teacher':
        return redirect(url_for('student_dashboard'))

    grades = (
        Grade.query.join(Subject)
        .filter(Subject.teacher_id == current_user.id)
        .order_by(Grade.id.desc())
        .all()
    )

    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(['student', 'subject', 'grade'])
    for item in grades:
        writer.writerow([item.student.name, item.subject.name, item.grade])

    return Response(
        stream.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=teacher_grades.csv'}
    )


@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    pending_teachers = User.query.filter_by(role='teacher', is_verified=False).order_by(User.id.desc()).all()
    approved_teachers = User.query.filter_by(role='teacher', is_verified=True).order_by(User.id.desc()).all()
    students_count = User.query.filter_by(role='student').count()

    return render_template(
        'admin_dashboard.html',
        pending_teachers=pending_teachers,
        approved_teachers=approved_teachers,
        students_count=students_count
    )


@app.route('/admin/teacher/<int:user_id>/approve', methods=['POST'])
@login_required
def approve_teacher(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    teacher = User.query.filter_by(id=user_id, role='teacher').first()
    if not teacher:
        flash('Преподаватель не найден')
        return redirect(url_for('admin_dashboard'))

    teacher.is_verified = True
    db.session.commit()
    ensure_teacher_subjects(teacher.id)
    flash(f'Преподаватель {teacher.name} одобрен')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/teacher/<int:user_id>/reject', methods=['POST'])
@login_required
def reject_teacher(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    teacher = User.query.filter_by(id=user_id, role='teacher').first()
    if not teacher:
        flash('Преподаватель не найден')
        return redirect(url_for('admin_dashboard'))

    db.session.delete(teacher)
    db.session.commit()
    flash('Заявка преподавателя отклонена')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(debug=True)
