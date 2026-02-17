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
    name = db.Column(db.String(150), nullable=False)
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

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.String(300))

    actor = db.relationship('User')



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
            name='Администратор Системы StudentHubik',
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


def email_looks_valid(email):
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email) is not None


def log_audit(action, details=''):
    actor_id = current_user.id if current_user.is_authenticated else None
    db.session.add(AuditLog(actor_id=actor_id, action=action, details=details[:300]))
    db.session.commit()


def password_matches(password_hash, password):
    try:
        return check_password_hash(password_hash, password)
    except ValueError:
        return False


def full_name_looks_valid(full_name):
    parts = [part for part in full_name.split(' ') if part]
    return len(parts) >= 3


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
    groups = Group.query.order_by(Group.name).all()

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

        if not full_name_looks_valid(name):
            flash('Введите полное ФИО (минимум 3 слова)')
            return redirect(url_for('register'))

        if not email_looks_valid(email):
            flash('Email введён некорректно')
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
                flash('Для студента нужно выбрать группу')
                return redirect(url_for('register'))

            normalized_group = normalize_group_name(group_name)
            group = Group.query.filter_by(name=normalized_group).first()
            if not group:
                flash('Такой группы нет в системе. Выберите из списка.')
                return redirect(url_for('register'))
            selected_group_id = group.id

        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            role=role,
            group_id=selected_group_id,
            is_verified=False
        )

        db.session.add(new_user)
        db.session.commit()

        if role == 'teacher':
            flash('Заявка преподавателя отправлена. Дождитесь одобрения администратора.')
        else:
            flash('Заявка студента отправлена. Дождитесь одобрения администратора.')

        return redirect(url_for('login', role=role))

    return render_template('register.html', groups=groups)


@app.route('/login', methods=['GET', 'POST'])
def login():
    role = request.args.get('role', 'student')

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        selected_role = request.form.get('role')

        user = User.query.filter_by(email=email).first()

        if user and password_matches(user.password, password):
            if selected_role not in {'student', 'teacher', 'admin'}:
                selected_role = user.role

            if user.role != selected_role:
                flash(f'Вы вошли как {user.role}, т.к. аккаунт зарегистрирован в этой роли')

            if user.role in {'student', 'teacher'} and not user.is_verified:
                flash('Ваша заявка ещё не одобрена администратором')
                return redirect(url_for('login', role=user.role))

            login_user(user)
            log_audit('login_success', f'user={user.email}, role={user.role}')

            if user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('student_dashboard'))

        log_audit('login_failed', f'email={email}, role={selected_role or role}')
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

        if not full_name_looks_valid(name):
            flash('Введите полное ФИО (минимум 3 слова)')
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

    students = User.query.filter_by(role='student', is_verified=True).order_by(User.name).all()
    subjects = Subject.query.filter_by(teacher_id=current_user.id).order_by(Subject.name).all()

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        subject_id = request.form.get('subject_id')
        grade_value = request.form.get('value')

        if not student_id or not subject_id or not grade_value:
            flash('Заполните все поля для выставления оценки')
            return redirect(url_for('teacher_dashboard'))

        student = User.query.filter_by(id=student_id, role='student', is_verified=True).first()
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
            log_audit('update_grade', f'student={student.id}, subject={subject.id}, grade={numeric_grade}')
            flash(f'Оценка обновлена: {student.name} / {subject.name} = {numeric_grade}')
        else:
            new_grade = Grade(student_id=student.id, subject_id=subject.id, grade=numeric_grade)
            db.session.add(new_grade)
            log_audit('create_grade', f'student={student.id}, subject={subject.id}, grade={numeric_grade}')
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
    pending_students = User.query.filter_by(role='student', is_verified=False).order_by(User.id.desc()).all()

    approved_teachers = User.query.filter_by(role='teacher', is_verified=True).order_by(User.id.desc()).all()
    approved_students = User.query.filter_by(role='student', is_verified=True).order_by(User.id.desc()).all()

    all_groups = Group.query.order_by(Group.name).all()
    all_subjects = Subject.query.order_by(Subject.name).all()
    recent_audit = AuditLog.query.order_by(AuditLog.id.desc()).limit(40).all()

    return render_template(
        'admin_dashboard.html',
        pending_teachers=pending_teachers,
        pending_students=pending_students,
        approved_teachers=approved_teachers,
        approved_students=approved_students,
        all_groups=all_groups,
        all_subjects=all_subjects,
        recent_audit=recent_audit
    )


@app.route('/admin/user/<int:user_id>/approve', methods=['POST'])
@login_required
def approve_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    user = User.query.filter(User.id == user_id, User.role.in_(['student', 'teacher'])).first()
    if not user:
        flash('Пользователь не найден')
        return redirect(url_for('admin_dashboard'))

    user.is_verified = True
    db.session.commit()

    log_audit('approve_user', f'id={user.id}, role={user.role}')
    flash(f'Пользователь {user.name} одобрен')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/reject', methods=['POST'])
@login_required
def reject_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    user = User.query.filter(User.id == user_id, User.role.in_(['student', 'teacher'])).first()
    if not user:
        flash('Пользователь не найден')
        return redirect(url_for('admin_dashboard'))

    Grade.query.filter_by(student_id=user.id).delete()
    if user.role == 'teacher':
        teacher_subject_ids = [s.id for s in Subject.query.filter_by(teacher_id=user.id).all()]
        if teacher_subject_ids:
            Grade.query.filter(Grade.subject_id.in_(teacher_subject_ids)).delete(synchronize_session=False)
            Subject.query.filter_by(teacher_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()
    log_audit('reject_user', f'id={user_id}')
    flash('Заявка отклонена и аккаунт удалён')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/student/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_student(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    student = User.query.filter_by(id=user_id, role='student').first()
    if not student:
        flash('Студент не найден')
        return redirect(url_for('admin_dashboard'))

    Grade.query.filter_by(student_id=student.id).delete()
    db.session.delete(student)
    db.session.commit()
    log_audit('delete_student', f'id={user_id}')
    flash('Аккаунт студента удалён')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/group', methods=['POST'])
@login_required
def admin_add_group():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    group_name = normalize_group_name(request.form.get('group_name', ''))
    if not group_name:
        flash('Введите название группы')
        return redirect(url_for('admin_dashboard'))

    if Group.query.filter_by(name=group_name).first():
        flash('Такая группа уже существует')
        return redirect(url_for('admin_dashboard'))

    db.session.add(Group(name=group_name))
    db.session.commit()
    log_audit('add_group', group_name)
    flash(f'Группа {group_name} добавлена')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/group/<int:group_id>/delete', methods=['POST'])
@login_required
def admin_delete_group(group_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    group = Group.query.get(group_id)
    if not group:
        flash('Группа не найдена')
        return redirect(url_for('admin_dashboard'))

    students_with_group = User.query.filter_by(role='student', group_id=group.id).count()
    if students_with_group > 0:
        flash('Нельзя удалить группу: в ней есть студенты')
        return redirect(url_for('admin_dashboard'))

    db.session.delete(group)
    db.session.commit()
    log_audit('delete_group', f'id={group_id}')
    flash('Группа удалена')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/teacher/<int:teacher_id>/subject', methods=['POST'])
@login_required
def admin_add_subject_for_teacher(teacher_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    teacher = User.query.filter_by(id=teacher_id, role='teacher').first()
    if not teacher:
        flash('Преподаватель не найден')
        return redirect(url_for('admin_dashboard'))

    subject_name = request.form.get('subject_name', '').strip()
    if not subject_name:
        flash('Введите название предмета')
        return redirect(url_for('admin_dashboard'))

    if Subject.query.filter_by(name=subject_name, teacher_id=teacher.id).first():
        flash('У преподавателя уже есть такой предмет')
        return redirect(url_for('admin_dashboard'))

    db.session.add(Subject(name=subject_name, teacher_id=teacher.id))
    db.session.commit()
    log_audit('add_subject', f'teacher={teacher.id}, subject={subject_name}')
    flash(f'Предмет {subject_name} назначен преподавателю {teacher.name}')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/subject/<int:subject_id>/delete', methods=['POST'])
@login_required
def admin_delete_subject(subject_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    subject = Subject.query.get(subject_id)
    if not subject:
        flash('Предмет не найден')
        return redirect(url_for('admin_dashboard'))

    Grade.query.filter_by(subject_id=subject.id).delete()
    db.session.delete(subject)
    db.session.commit()
    log_audit('delete_subject', f'id={subject_id}')
    flash('Предмет удалён')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/export-users')
@login_required
def export_all_users():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    users = User.query.order_by(User.id).all()

    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(['id', 'name', 'email', 'role', 'group_id', 'is_verified'])
    for user in users:
        writer.writerow([user.id, user.name, user.email, user.role, user.group_id or '', user.is_verified])

    return Response(
        stream.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=all_users.csv'}
    )


if __name__ == '__main__':
    app.run(debug=True)
