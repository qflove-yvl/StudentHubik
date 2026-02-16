from flask import flash
from flask import Flask, render_template, redirect, url_for, request
from flask import Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')


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


@app.before_request
def initialize_database():
    if app.config.get('DB_INITIALIZED'):
        return

    db.create_all()
    ensure_default_groups()
    app.config['DB_INITIALIZED'] = True


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    groups = Group.query.order_by(Group.name).all()

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role')
        group_id = request.form.get('group_id')

        if not name or not email or not password or not role:
            flash('Заполните все обязательные поля')
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
        if role == 'student' and group_id:
            selected_group = Group.query.get(group_id)
            if not selected_group:
                flash('Выбрана некорректная группа')
                return redirect(url_for('register'))
            selected_group_id = selected_group.id

        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            role=role,
            group_id=selected_group_id
        )

        db.session.add(new_user)
        db.session.commit()

        if role == 'teacher':
            ensure_teacher_subjects(new_user.id)

        flash('Регистрация успешна. Теперь войдите в аккаунт.')
        return redirect(url_for('login', role=role))

    return render_template('register.html', groups=groups)


@app.route('/login', methods=['GET', 'POST'])
def login():
    role = request.args.get('role', 'student')

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        selected_role = request.form.get('role', role)

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if user.role != selected_role:
                flash('Вы пытаетесь войти не в ту роль')
                return redirect(url_for('login', role=selected_role))

            login_user(user)

            if user.role == 'teacher':
                ensure_teacher_subjects(user.id)
                return redirect(url_for('teacher_dashboard'))
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

    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


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


if __name__ == '__main__':
    app.run(debug=True)
