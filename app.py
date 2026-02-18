from flask import abort, flash
from flask import Flask, render_template, redirect, url_for, request, session
from flask import Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io
import os
import re
import secrets
from datetime import datetime, timedelta
import logging
import smtplib
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler

from sqlalchemy import func, inspect, text


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')
app.config['ADMIN_EMAIL'] = os.getenv('ADMIN_EMAIL', 'admin@studenthubik.local').lower()
app.config['ADMIN_PASSWORD'] = os.getenv('ADMIN_PASSWORD', 'admin12345')
app.config['LOGIN_MAX_ATTEMPTS'] = int(os.getenv('LOGIN_MAX_ATTEMPTS', '5'))
app.config['LOGIN_BLOCK_MINUTES'] = int(os.getenv('LOGIN_BLOCK_MINUTES', '10'))
app.config['PASSWORD_RESET_TOKEN_MINUTES'] = int(os.getenv('PASSWORD_RESET_TOKEN_MINUTES', '30'))
app.config['SMTP_HOST'] = os.getenv('SMTP_HOST', '')
app.config['SMTP_PORT'] = int(os.getenv('SMTP_PORT', '587'))
app.config['SMTP_USER'] = os.getenv('SMTP_USER', '')
app.config['SMTP_PASSWORD'] = os.getenv('SMTP_PASSWORD', '')
app.config['SMTP_FROM_EMAIL'] = os.getenv('SMTP_FROM_EMAIL', app.config['ADMIN_EMAIL'])


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
    theme = db.Column(db.String(10), default='dark')
    compact_mode = db.Column(db.Boolean, default=False)
    animations_enabled = db.Column(db.Boolean, default=True)


class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    code = db.Column(db.String(6))


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(120), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

    user = db.relationship('User')


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
    comment = db.Column(db.String(300), default='')
    graded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    student = db.relationship('User', foreign_keys=[student_id])
    subject = db.relationship('Subject')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    actor = db.relationship('User')



def ensure_default_groups():
    if Group.query.count() == 0:
        for group_name in ['ИС-101', 'ИС-102', 'ИС-201']:
            db.session.add(Group(name=group_name))
        db.session.commit()


def ensure_admin_user():
    admin_email = app.config['ADMIN_EMAIL']
    configured_password = app.config['ADMIN_PASSWORD']
    existing_admin = User.query.filter_by(email=admin_email).first()
    if existing_admin:
        changed = False
        if existing_admin.role != 'admin':
            existing_admin.role = 'admin'
            changed = True
        if not existing_admin.is_verified:
            existing_admin.is_verified = True
            changed = True
        # Синхронизируем пароль с конфигом, чтобы вход админа не ломался после правок ENV.
        if not password_matches(existing_admin.password, configured_password):
            existing_admin.password = generate_password_hash(configured_password)
            changed = True

        if changed:
            db.session.commit()
        return

    db.session.add(
        User(
            name='Администратор Системы StudentHubik',
            email=admin_email,
            password=generate_password_hash(configured_password),
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


def ensure_runtime_columns():
    inspector = inspect(db.engine)

    grade_columns = {column['name'] for column in inspector.get_columns('grade')}
    if 'comment' not in grade_columns:
        db.session.execute(text('ALTER TABLE grade ADD COLUMN comment VARCHAR(300) DEFAULT ""'))
    if 'graded_at' not in grade_columns:
        db.session.execute(text('ALTER TABLE grade ADD COLUMN graded_at DATETIME'))
        db.session.execute(text('UPDATE grade SET graded_at = CURRENT_TIMESTAMP WHERE graded_at IS NULL'))

    audit_columns = {column['name'] for column in inspector.get_columns('audit_log')}
    if 'created_at' not in audit_columns:
        db.session.execute(text('ALTER TABLE audit_log ADD COLUMN created_at DATETIME'))
        db.session.execute(text('UPDATE audit_log SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL'))

    user_columns = {column['name'] for column in inspector.get_columns('user')}
    if 'theme' not in user_columns:
        db.session.execute(text('ALTER TABLE user ADD COLUMN theme VARCHAR(10) DEFAULT "dark"'))
        db.session.execute(text("UPDATE user SET theme = 'dark' WHERE theme IS NULL OR theme = ''"))
    if 'compact_mode' not in user_columns:
        db.session.execute(text('ALTER TABLE user ADD COLUMN compact_mode BOOLEAN DEFAULT 0'))
        db.session.execute(text('UPDATE user SET compact_mode = 0 WHERE compact_mode IS NULL'))
    if 'animations_enabled' not in user_columns:
        db.session.execute(text('ALTER TABLE user ADD COLUMN animations_enabled BOOLEAN DEFAULT 1'))
        db.session.execute(text('UPDATE user SET animations_enabled = 1 WHERE animations_enabled IS NULL'))

    db.session.commit()


def normalize_group_name(group_name):
    return group_name.strip().upper()


def email_looks_valid(email):
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email) is not None


def log_audit(action, details='', should_commit=True):
    actor_id = current_user.id if current_user.is_authenticated else None
    db.session.add(AuditLog(actor_id=actor_id, action=action, details=details[:300], created_at=datetime.utcnow()))
    if should_commit:
        db.session.commit()


def password_matches(password_hash, password):
    try:
        return check_password_hash(password_hash, password)
    except ValueError:
        return False


def full_name_looks_valid(full_name):
    parts = [part for part in full_name.split(' ') if part]
    return len(parts) >= 3


def get_or_create_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


def is_login_rate_limited(identifier):
    attempts = app.config.setdefault('LOGIN_ATTEMPTS', {})
    state = attempts.get(identifier, {'count': 0, 'blocked_until': None})
    blocked_until = state.get('blocked_until')
    now = datetime.utcnow()

    if blocked_until and blocked_until > now:
        return True, int((blocked_until - now).total_seconds())

    if blocked_until and blocked_until <= now:
        attempts[identifier] = {'count': 0, 'blocked_until': None}

    return False, 0


def register_login_failure(identifier):
    attempts = app.config.setdefault('LOGIN_ATTEMPTS', {})
    state = attempts.get(identifier, {'count': 0, 'blocked_until': None})
    state['count'] += 1

    if state['count'] >= app.config['LOGIN_MAX_ATTEMPTS']:
        state['blocked_until'] = datetime.utcnow() + timedelta(minutes=app.config['LOGIN_BLOCK_MINUTES'])
        state['count'] = 0

    attempts[identifier] = state


def clear_login_failures(identifier):
    attempts = app.config.setdefault('LOGIN_ATTEMPTS', {})
    attempts.pop(identifier, None)




def send_password_reset_email(email_to, reset_link):
    smtp_host = app.config.get('SMTP_HOST')
    smtp_user = app.config.get('SMTP_USER')
    smtp_password = app.config.get('SMTP_PASSWORD')
    smtp_port = app.config.get('SMTP_PORT', 587)

    if not smtp_host or not smtp_user or not smtp_password:
        app.logger.warning('smtp_not_configured reset_link=%s', reset_link)
        return False

    message = EmailMessage()
    message['Subject'] = 'StudentHubik: восстановление пароля'
    message['From'] = app.config.get('SMTP_FROM_EMAIL')
    message['To'] = email_to
    message.set_content(
        f'Для восстановления пароля перейдите по ссылке\n{reset_link}\n\n'
        f'Ссылка действует {app.config.get("PASSWORD_RESET_TOKEN_MINUTES", 30)} минут.'
    )

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        smtp.starttls()
        smtp.login(smtp_user, smtp_password)
        smtp.send_message(message)

    return True


def build_student_subject_grade_rows(grades):
    by_subject = {}
    for item in grades:
        subject_name = item.subject.name if item.subject else '—'
        group = by_subject.setdefault(subject_name, {'grades': [], 'avg': None})
        group['grades'].append(item)

    result = []
    for subject_name, payload in sorted(by_subject.items(), key=lambda x: x[0].lower()):
        ordered = sorted(payload['grades'], key=lambda g: (g.graded_at or datetime.min, g.id))
        values = [g.grade for g in ordered]
        avg_value = round(sum(values) / len(values), 2) if values else 0
        result.append({'subject_name': subject_name, 'grades': ordered, 'avg': avg_value})

    return result




def apply_period_filter(query, period_value):
    now = datetime.utcnow()
    if period_value == 'week':
        return query.filter(Grade.graded_at >= now - timedelta(days=7))
    if period_value == 'month':
        return query.filter(Grade.graded_at >= now - timedelta(days=31))
    return query


def paginate_items(items, page, per_page):
    total = len(items)
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end], total, pages, page


def redirect_to_role_dashboard():
    if current_user.role == 'student':
        return redirect(url_for('student_dashboard'))
    if current_user.role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    if current_user.role in {'admin', 'curator'}:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('index'))


@app.context_processor
def inject_template_security():
    default_ui = {'theme': 'dark', 'compact': 'off', 'animations': 'on'}
    if current_user.is_authenticated:
        user_theme = getattr(current_user, 'theme', 'dark') or 'dark'
        user_compact = bool(getattr(current_user, 'compact_mode', False))
        user_animations = bool(getattr(current_user, 'animations_enabled', True))
        default_ui = {
            'theme': user_theme if user_theme in {'dark', 'light'} else 'dark',
            'compact': 'on' if user_compact else 'off',
            'animations': 'on' if user_animations else 'off'
        }

    return {
        'csrf_token': get_or_create_csrf_token(),
        'ui_settings': default_ui
    }


@app.before_request
def enforce_csrf_protection():
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return

    sent_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not sent_token or sent_token != session.get('csrf_token'):
        app.logger.warning('csrf_validation_failed path=%s ip=%s', request.path, request.remote_addr)
        abort(400)


@app.before_request
def initialize_database():
    if app.config.get('DB_INITIALIZED'):
        return

    db.create_all()
    ensure_runtime_columns()
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

        identifier = f"{request.remote_addr}:{email}"
        blocked, seconds_left = is_login_rate_limited(identifier)
        if blocked:
            flash(f'Слишком много попыток входа. Повторите через {max(1, seconds_left // 60)} мин.')
            return render_template('login.html', role=role)

        user = User.query.filter_by(email=email).first()

        if user and password_matches(user.password, password):
            if selected_role not in {'student', 'teacher', 'admin', 'curator'}:
                selected_role = user.role

            if user.role != selected_role:
                flash(f'Вы вошли как {user.role}, т.к. аккаунт зарегистрирован в этой роли')

            if user.role in {'student', 'teacher'} and not user.is_verified:
                flash('Ваша заявка ещё не одобрена администратором')
                return redirect(url_for('login', role=user.role))

            login_user(user)
            clear_login_failures(identifier)
            log_audit('login_success', f'user={user.email}, role={user.role}')

            if user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('student_dashboard'))

        register_login_failure(identifier)
        log_audit('login_failed', f'email={email}, role={selected_role or role}')
        flash('Неверный email или пароль')

    return render_template('login.html', role=role)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()

        if user:
            PasswordResetToken.query.filter_by(user_id=user.id, is_used=False).update({'is_used': True})
            token = secrets.token_urlsafe(36)
            expires_at = datetime.utcnow() + timedelta(minutes=app.config['PASSWORD_RESET_TOKEN_MINUTES'])
            db.session.add(PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at, is_used=False))
            db.session.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            sent = send_password_reset_email(user.email, reset_link)
            if not sent:
                app.logger.info('password_reset_link_for_%s: %s', user.email, reset_link)

        flash('Если email есть в системе, мы отправили ссылку для восстановления пароля.')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_entry = PasswordResetToken.query.filter_by(token=token, is_used=False).first()

    if not reset_entry or reset_entry.expires_at < datetime.utcnow():
        flash('Ссылка недействительна или истекла')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if len(password) < 6:
            flash('Пароль должен быть не короче 6 символов')
            return redirect(url_for('reset_password', token=token))

        if password != confirm_password:
            flash('Пароли не совпадают')
            return redirect(url_for('reset_password', token=token))

        reset_entry.user.password = generate_password_hash(password)
        reset_entry.is_used = True
        db.session.commit()
        log_audit('password_reset', f'user={reset_entry.user.email}')
        flash('Пароль успешно обновлён. Теперь войдите с новым паролем.')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/dashboard')
@login_required
def dashboard():
    return redirect_to_role_dashboard()


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


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        theme = request.form.get('theme', 'dark')
        compact_mode = request.form.get('compact_mode', 'off')
        animations_enabled = request.form.get('animations_enabled', 'on')

        current_user.theme = theme if theme in {'dark', 'light'} else 'dark'
        current_user.compact_mode = compact_mode == 'on'
        current_user.animations_enabled = animations_enabled != 'off'
        db.session.commit()
        flash('Настройки сохранены')
        return redirect(url_for('settings'))

    return render_template('settings.html')


@app.route('/support')
def support():
    return render_template('support.html', support_username='@cestlavieq')


@app.route('/student')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect_to_role_dashboard()

    period = request.args.get('period', 'all')
    page = request.args.get('page', 1, type=int)

    grades_query = Grade.query.filter_by(student_id=current_user.id)
    grades_query = apply_period_filter(grades_query, period)
    grades = grades_query.order_by(Grade.graded_at.desc(), Grade.id.desc()).all()

    grade_values = [grade.grade for grade in grades]
    average_grade = round(sum(grade_values) / len(grade_values), 2) if grade_values else 0
    subject_count = len({grade.subject_id for grade in grades})
    best_grade = max(grade_values) if grade_values else '—'
    worst_grade = min(grade_values) if grade_values else '—'

    subject_averages = (
        db.session.query(Subject.name, func.round(func.avg(Grade.grade), 2), func.count(Grade.id))
        .join(Grade, Grade.subject_id == Subject.id)
        .filter(Grade.student_id == current_user.id)
    )
    subject_averages = apply_period_filter(subject_averages, period)
    subject_averages = subject_averages.group_by(Subject.id, Subject.name).order_by(Subject.name).all()

    rows = build_student_subject_grade_rows(grades)
    subject_grade_rows, total_subject_rows, subject_pages, page = paginate_items(rows, page, 8)

    group_name = '—'
    if current_user.group_id:
        group = Group.query.get(current_user.group_id)
        if group:
            group_name = group.name

    return render_template(
        'student_dashboard.html',
        grades=grades,
        average_grade=average_grade,
        subject_count=subject_count,
        best_grade=best_grade,
        worst_grade=worst_grade,
        group_name=group_name,
        subject_averages=subject_averages,
        subject_grade_rows=subject_grade_rows,
        period=period,
        page=page,
        subject_pages=subject_pages,
        total_subject_rows=total_subject_rows
    )


@app.route('/student/export-grades')
@login_required
def export_student_grades():
    if current_user.role != 'student':
        return redirect_to_role_dashboard()

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
        return redirect_to_role_dashboard()

    students = User.query.filter_by(role='student', is_verified=True).order_by(User.name).all()
    groups_by_id = {group.id: group.name for group in Group.query.all()}
    subjects = Subject.query.filter_by(teacher_id=current_user.id).order_by(Subject.name).all()
    period = request.args.get('period', 'all')
    search_query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create_grade':
            student_id = request.form.get('student_id')
            subject_id = request.form.get('subject_id')
            grade_value = request.form.get('value')
            comment = request.form.get('comment', '').strip()

            if not student_id or not subject_id or not grade_value:
                flash('Заполните все поля для выставления оценки')
                return redirect(url_for('teacher_dashboard'))

            student = User.query.filter_by(id=student_id, role='student', is_verified=True).first()
            subject = Subject.query.filter_by(id=subject_id, teacher_id=current_user.id).first()

            if not student or not subject:
                flash('Выбраны некорректные студент или предмет')
                return redirect(url_for('teacher_dashboard'))

            try:
                numeric_grade = int(grade_value)
            except (TypeError, ValueError):
                flash('Оценка должна быть числом')
                return redirect(url_for('teacher_dashboard'))

            if numeric_grade < 1 or numeric_grade > 5:
                flash('Оценка должна быть от 1 до 5')
                return redirect(url_for('teacher_dashboard'))

            new_grade = Grade(
                student_id=student.id,
                subject_id=subject.id,
                grade=numeric_grade,
                comment=comment[:300],
                graded_at=datetime.utcnow()
            )
            db.session.add(new_grade)
            db.session.commit()
            log_audit('create_grade', f'grade_id={new_grade.id}, student={student.id}, subject={subject.id}, grade={numeric_grade}')
            flash(f'Оценка добавлена: {student.name} / {subject.name} = {numeric_grade}')
            return redirect(url_for('teacher_dashboard'))

        if action in {'update_grade', 'delete_grade'}:
            grade_id = request.form.get('grade_id')
            try:
                grade_id = int(grade_id)
            except (TypeError, ValueError):
                flash('Некорректная оценка')
                return redirect(url_for('teacher_dashboard'))

            grade_item = (
                Grade.query.join(Subject)
                .filter(Grade.id == grade_id, Subject.teacher_id == current_user.id)
                .first()
            )
            if not grade_item:
                flash('Оценка не найдена или недоступна')
                return redirect(url_for('teacher_dashboard'))

            if action == 'delete_grade':
                db.session.delete(grade_item)
                db.session.commit()
                log_audit('delete_grade', f'grade_id={grade_id}')
                flash('Оценка удалена')
                return redirect(url_for('teacher_dashboard'))

            grade_value = request.form.get('value')
            comment = request.form.get('comment', '').strip()
            if not grade_value:
                flash('Укажите оценку от 1 до 5')
                return redirect(url_for('teacher_dashboard'))

            try:
                numeric_grade = int(grade_value)
            except (TypeError, ValueError):
                flash('Оценка должна быть числом')
                return redirect(url_for('teacher_dashboard'))

            if numeric_grade < 1 or numeric_grade > 5:
                flash('Оценка должна быть от 1 до 5')
                return redirect(url_for('teacher_dashboard'))

            grade_item.grade = numeric_grade
            grade_item.comment = comment[:300]
            grade_item.graded_at = datetime.utcnow()
            db.session.commit()
            log_audit('update_grade', f'grade_id={grade_id}, grade={numeric_grade}')
            flash('Оценка обновлена')
            return redirect(url_for('teacher_dashboard'))

        flash('Некорректное действие')
        return redirect(url_for('teacher_dashboard'))

    recent_grades_query = (
        Grade.query.join(Subject).join(User, Grade.student_id == User.id)
        .filter(Subject.teacher_id == current_user.id)
    )
    recent_grades_query = apply_period_filter(recent_grades_query, period)
    if search_query:
        recent_grades_query = recent_grades_query.filter(
            (User.name.ilike(f'%{search_query}%')) |
            (Subject.name.ilike(f'%{search_query}%')) |
            (Grade.comment.ilike(f'%{search_query}%'))
        )

    total_recent_grades = recent_grades_query.count()
    per_page = 20
    recent_grades = (
        recent_grades_query
        .order_by(Grade.graded_at.desc(), Grade.id.desc())
        .offset((max(page, 1) - 1) * per_page)
        .limit(per_page)
        .all()
    )
    total_pages = max(1, (total_recent_grades + per_page - 1) // per_page)

    subject_averages = dict(
        db.session.query(Subject.id, func.round(func.avg(Grade.grade), 2))
        .outerjoin(Grade, Grade.subject_id == Subject.id)
        .filter(Subject.teacher_id == current_user.id)
        .group_by(Subject.id)
        .all()
    )

    return render_template(
        'teacher_dashboard.html',
        students=students,
        subjects=subjects,
        recent_grades=recent_grades,
        groups_by_id=groups_by_id,
        subject_averages=subject_averages,
        period=period,
        search_query=search_query,
        page=page,
        total_pages=total_pages,
        total_recent_grades=total_recent_grades
    )


@app.route('/teacher/export-grades')
@login_required
def export_teacher_grades():
    if current_user.role != 'teacher':
        return redirect_to_role_dashboard()

    grades = (
        Grade.query.join(Subject)
        .filter(Subject.teacher_id == current_user.id)
        .order_by(Grade.id.desc())
        .all()
    )

    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(['student', 'subject', 'grade', 'comment', 'graded_at'])
    for item in grades:
        writer.writerow([item.student.name, item.subject.name, item.grade, item.comment or '', item.graded_at.isoformat() if item.graded_at else ''])

    return Response(
        stream.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=teacher_grades.csv'}
    )


@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role not in {'admin', 'curator'}:
        return redirect(url_for('dashboard'))

    query = request.args.get('q', '').strip()
    role_filter = request.args.get('role', 'all')
    status_filter = request.args.get('status', 'pending')
    group_filter = request.args.get('group_id', 'all')

    users_query = User.query.filter(User.role.in_(['student', 'teacher']))
    if query:
        users_query = users_query.filter((User.name.ilike(f'%{query}%')) | (User.email.ilike(f'%{query}%')))
    if role_filter in {'student', 'teacher'}:
        users_query = users_query.filter(User.role == role_filter)
    if status_filter == 'pending':
        users_query = users_query.filter(User.is_verified.is_(False))
    elif status_filter == 'approved':
        users_query = users_query.filter(User.is_verified.is_(True))

    if group_filter != 'all':
        try:
            group_id = int(group_filter)
            users_query = users_query.filter(User.group_id == group_id)
        except ValueError:
            pass

    page = request.args.get('page', 1, type=int)
    per_page = 30
    total_filtered = users_query.count()
    filtered_users = users_query.order_by(User.id.desc()).offset((max(page, 1) - 1) * per_page).limit(per_page).all()

    pending_teachers = [u for u in filtered_users if u.role == 'teacher' and not u.is_verified]
    pending_students = [u for u in filtered_users if u.role == 'student' and not u.is_verified]

    approved_teachers = [u for u in filtered_users if u.role == 'teacher' and u.is_verified]
    approved_students = [u for u in filtered_users if u.role == 'student' and u.is_verified]
    total_pages = max(1, (total_filtered + per_page - 1) // per_page)

    all_groups = Group.query.order_by(Group.name).all()
    all_subjects = Subject.query.order_by(Subject.name).all()
    recent_audit = AuditLog.query.order_by(AuditLog.id.desc()).limit(40).all()

    return render_template(
        'admin_dashboard.html',
        pending_teachers=pending_teachers,
        pending_students=pending_students,
        approved_teachers=approved_teachers,
        approved_students=approved_students,
        groups_by_id={group.id: group.name for group in all_groups},
        query=query,
        role_filter=role_filter,
        status_filter=status_filter,
        group_filter=group_filter,
        all_groups=all_groups,
        all_subjects=all_subjects,
        recent_audit=recent_audit,
        can_manage=current_user.role == 'admin',
        page=page,
        total_pages=total_pages,
        total_filtered=total_filtered
    )


@app.route('/admin/users/bulk-action', methods=['POST'])
@login_required
def admin_bulk_user_action():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    redirect_params = {
        'q': request.form.get('q', ''),
        'role': request.form.get('role', 'all'),
        'status': request.form.get('status', 'pending'),
        'group_id': request.form.get('group_id', 'all')
    }

    action = request.form.get('bulk_action')
    selected_ids = request.form.getlist('selected_user_ids')
    if action not in {'approve', 'reject'}:
        flash('Некорректное массовое действие')
        return redirect(url_for('admin_dashboard', **redirect_params))

    valid_ids = []
    for user_id in selected_ids:
        try:
            valid_ids.append(int(user_id))
        except ValueError:
            continue

    if not valid_ids:
        flash('Выберите хотя бы одну заявку')
        return redirect(url_for('admin_dashboard', **redirect_params))

    users = User.query.filter(User.id.in_(valid_ids), User.role.in_(['student', 'teacher'])).all()
    processed = 0

    if action == 'approve':
        for user in users:
            user.is_verified = True
            processed += 1
            log_audit('approve_user_bulk', f'id={user.id}, role={user.role}', should_commit=False)
        db.session.commit()
        flash(f'Одобрено заявок: {processed}')
        return redirect(url_for('admin_dashboard', **redirect_params))

    for user in users:
        Grade.query.filter_by(student_id=user.id).delete()
        if user.role == 'teacher':
            teacher_subject_ids = [s.id for s in Subject.query.filter_by(teacher_id=user.id).all()]
            if teacher_subject_ids:
                Grade.query.filter(Grade.subject_id.in_(teacher_subject_ids)).delete(synchronize_session=False)
                Subject.query.filter_by(teacher_id=user.id).delete()

        db.session.delete(user)
        processed += 1
        log_audit('reject_user_bulk', f'id={user.id}, role={user.role}', should_commit=False)

    db.session.commit()
    flash(f'Отклонено и удалено заявок: {processed}')
    return redirect(url_for('admin_dashboard', **redirect_params))


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


@app.route('/admin/user/action', methods=['POST'])
@login_required
def admin_user_action():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    user_id = request.form.get('user_id')
    action = request.form.get('action')

    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        flash('Некорректный пользователь')
        return redirect(url_for('admin_dashboard'))

    user = User.query.filter(User.id == user_id, User.role.in_(['student', 'teacher'])).first()
    if not user:
        flash('Пользователь не найден')
        return redirect(url_for('admin_dashboard'))

    if action == 'approve':
        user.is_verified = True
        db.session.commit()
        log_audit('approve_user', f'id={user.id}, role={user.role}')
        flash(f'Пользователь {user.name} одобрен')
        return redirect(url_for('admin_dashboard'))

    if action == 'reject':
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

    flash('Некорректное действие')
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




@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline';"
    return response


@app.errorhandler(400)
def bad_request(_error):
    return render_template('error_400.html'), 400


@app.errorhandler(404)
def not_found(_error):
    return render_template('error_404.html'), 404


@app.errorhandler(500)
def server_error(error):
    app.logger.exception('server_error: %s', error)
    return render_template('error_500.html'), 500


if __name__ == '__main__':
    if not app.debug:
        log_handler = RotatingFileHandler('app.log', maxBytes=1024 * 1024, backupCount=3)
        log_handler.setLevel(logging.INFO)
        log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        if not app.logger.handlers:
            app.logger.addHandler(log_handler)
    app.logger.setLevel(logging.INFO)
    app.run(debug=True)
