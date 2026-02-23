from flask import abort, flash
from flask import Flask, render_template, redirect, url_for, request, session, send_from_directory
from flask import Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import csv
import io
import os
import re
import secrets
import shutil
from datetime import datetime, timedelta
import logging
import smtplib
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler

from sqlalchemy import func, inspect, text

try:
    import sentry_sdk
except ImportError:  # optional dependency in local dev
    sentry_sdk = None


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
app.config['SMTP_USE_TLS'] = os.getenv('SMTP_USE_TLS', '1') == '1'
app.config['SMTP_USE_SSL'] = os.getenv('SMTP_USE_SSL', '0') == '1'
app.config['SMTP_TIMEOUT_SECONDS'] = int(os.getenv('SMTP_TIMEOUT_SECONDS', '15'))
app.config['SENTRY_DSN'] = os.getenv('SENTRY_DSN', '')
app.config['ENVIRONMENT'] = os.getenv('ENVIRONMENT', 'development')
app.config['REQUIRE_STRONG_SECRET_IN_PROD'] = os.getenv('REQUIRE_STRONG_SECRET_IN_PROD', '1') == '1'
app.config['PASSWORD_RESET_MIN_INTERVAL_SECONDS'] = int(os.getenv('PASSWORD_RESET_MIN_INTERVAL_SECONDS', '60'))
app.config['DEBUG_SHOW_RESET_LINK_ON_EMAIL_FAIL'] = os.getenv('DEBUG_SHOW_RESET_LINK_ON_EMAIL_FAIL', '1') == '1'
app.config['SCHEDULE_UPLOAD_DIR'] = os.path.join(app.instance_path, 'schedules')
app.config['MAX_SCHEDULE_HISTORY'] = int(os.getenv('MAX_SCHEDULE_HISTORY', '20'))


db = SQLAlchemy(app)
migrate = Migrate(app, db)
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
    semester = db.Column(db.Integer, nullable=False, default=1)
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


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(255), unique=True, nullable=False, index=True)
    fail_count = db.Column(db.Integer, nullable=False, default=0)
    blocked_until = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.String(300), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User')


class ScheduleFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False, unique=True)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    uploaded_by = db.relationship('User')


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
    if 'semester' not in grade_columns:
        db.session.execute(text('ALTER TABLE grade ADD COLUMN semester INTEGER DEFAULT 1'))
        db.session.execute(text('UPDATE grade SET semester = 1 WHERE semester IS NULL OR semester < 1 OR semester > 2'))

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


def validate_runtime_config():
    if app.config.get('ENVIRONMENT') == 'production' and app.config.get('REQUIRE_STRONG_SECRET_IN_PROD'):
        secret_key = app.config.get('SECRET_KEY', '')
        if secret_key in {'', 'dev-key'} or len(secret_key) < 32:
            raise RuntimeError('Unsafe SECRET_KEY for production. Set a strong SECRET_KEY (>=32 chars).')


def init_error_monitoring():
    if sentry_sdk and app.config.get('SENTRY_DSN'):
        sentry_sdk.init(
            dsn=app.config['SENTRY_DSN'],
            environment=app.config.get('ENVIRONMENT', 'development'),
            traces_sample_rate=0.05
        )


def get_or_create_login_attempt(identifier):
    attempt = LoginAttempt.query.filter_by(identifier=identifier).first()
    if attempt:
        return attempt

    attempt = LoginAttempt(identifier=identifier, fail_count=0, blocked_until=None)
    db.session.add(attempt)
    db.session.flush()
    return attempt


def is_login_rate_limited(identifier):
    now = datetime.utcnow()
    attempt = LoginAttempt.query.filter_by(identifier=identifier).first()
    if not attempt:
        return False, 0

    if attempt.blocked_until and attempt.blocked_until > now:
        return True, int((attempt.blocked_until - now).total_seconds())

    if attempt.blocked_until and attempt.blocked_until <= now:
        attempt.blocked_until = None
        attempt.fail_count = 0
        db.session.commit()

    return False, 0


def register_login_failure(identifier):
    attempt = get_or_create_login_attempt(identifier)
    attempt.fail_count += 1

    if attempt.fail_count >= app.config['LOGIN_MAX_ATTEMPTS']:
        attempt.blocked_until = datetime.utcnow() + timedelta(minutes=app.config['LOGIN_BLOCK_MINUTES'])
        attempt.fail_count = 0

    db.session.commit()


def clear_login_failures(identifier):
    attempt = LoginAttempt.query.filter_by(identifier=identifier).first()
    if not attempt:
        return

    attempt.fail_count = 0
    attempt.blocked_until = None
    db.session.commit()


def send_password_reset_email(email_to, reset_link):
    smtp_host = app.config.get('SMTP_HOST')
    smtp_user = app.config.get('SMTP_USER')
    smtp_password = app.config.get('SMTP_PASSWORD')
    smtp_port = app.config.get('SMTP_PORT', 587)
    smtp_use_tls = app.config.get('SMTP_USE_TLS', True)
    smtp_use_ssl = app.config.get('SMTP_USE_SSL', False)
    smtp_timeout = app.config.get('SMTP_TIMEOUT_SECONDS', 15)

    if not smtp_host:
        app.logger.warning('smtp_not_configured reset_link=%s', reset_link)
        return False, 'smtp_not_configured'

    message = EmailMessage()
    message['Subject'] = 'StudentHubik: восстановление пароля'
    message['From'] = app.config.get('SMTP_FROM_EMAIL')
    message['To'] = email_to
    message.set_content(
        f'Для восстановления пароля перейдите по ссылке\n{reset_link}\n\n'
        f'Ссылка действует {app.config.get("PASSWORD_RESET_TOKEN_MINUTES", 30)} минут.'
    )

    try:
        if smtp_use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=smtp_timeout) as smtp:
                if smtp_user and smtp_password:
                    smtp.login(smtp_user, smtp_password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=smtp_timeout) as smtp:
                if smtp_use_tls:
                    smtp.starttls()
                if smtp_user and smtp_password:
                    smtp.login(smtp_user, smtp_password)
                smtp.send_message(message)
    except Exception as error:
        app.logger.exception('smtp_send_failed email=%s reason=%s', email_to, error)
        return False, str(error)

    return True, None


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






def resolve_semester_filter(raw_value):
    if raw_value in {'1', '2'}:
        return int(raw_value)
    return None


def get_semester_averages(grades):
    first = [g.grade for g in grades if g.semester == 1]
    second = [g.grade for g in grades if g.semester == 2]
    overall = [g.grade for g in grades]
    return {
        'semester_1_avg': round(sum(first) / len(first), 2) if first else 0,
        'semester_2_avg': round(sum(second) / len(second), 2) if second else 0,
        'course_avg': round(sum(overall) / len(overall), 2) if overall else 0
    }


def create_notification(user_id, title, message):
    db.session.add(Notification(user_id=user_id, title=title[:120], message=message[:300], is_read=False, created_at=datetime.utcnow()))


def get_unread_notifications_count(user_id):
    return Notification.query.filter_by(user_id=user_id, is_read=False).count()


def get_latest_schedule_file():
    return ScheduleFile.query.order_by(ScheduleFile.uploaded_at.desc(), ScheduleFile.id.desc()).first()


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

    unread_notifications = 0
    if current_user.is_authenticated:
        unread_notifications = get_unread_notifications_count(current_user.id)

    return {
        'csrf_token': get_or_create_csrf_token(),
        'ui_settings': default_ui,
        'unread_notifications': unread_notifications
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

    validate_runtime_config()
    os.makedirs(app.config.get('SCHEDULE_UPLOAD_DIR'), exist_ok=True)
    db.create_all()
    ensure_runtime_columns()
    ensure_default_groups()
    ensure_admin_user()
    stale_threshold = datetime.utcnow() - timedelta(days=30)
    LoginAttempt.query.filter(
        LoginAttempt.blocked_until.is_(None),
        LoginAttempt.fail_count == 0,
        LoginAttempt.updated_at < stale_threshold
    ).delete()
    db.session.commit()
    init_error_monitoring()
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

            remember_me = request.form.get('remember_me') == 'on'
            login_user(user, remember=remember_me)
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
            reset_entry = PasswordResetToken.query.filter_by(user_id=user.id, is_used=False).order_by(PasswordResetToken.id.desc()).first()
            now = datetime.utcnow()
            min_interval = app.config.get('PASSWORD_RESET_MIN_INTERVAL_SECONDS', 60)

            if reset_entry and reset_entry.expires_at >= now:
                token_created_at = reset_entry.expires_at - timedelta(minutes=app.config['PASSWORD_RESET_TOKEN_MINUTES'])
                if (now - token_created_at).total_seconds() < min_interval:
                    reset_link = url_for('reset_password', token=reset_entry.token, _external=True)
                    sent, send_reason = send_password_reset_email(user.email, reset_link)
                    if not sent:
                        app.logger.info('password_reset_link_for_%s: %s', user.email, reset_link)
                        if app.config.get('DEBUG_SHOW_RESET_LINK_ON_EMAIL_FAIL') and app.config.get('ENVIRONMENT') != 'production':
                            flash(f'Тестовый режим: отправка почты не удалась ({send_reason}). Ссылка: {reset_link}')
                    flash('Если email есть в системе, мы отправили ссылку для восстановления пароля.')
                    return redirect(url_for('login'))

            PasswordResetToken.query.filter_by(user_id=user.id, is_used=False).update({'is_used': True})
            token = secrets.token_urlsafe(36)
            expires_at = now + timedelta(minutes=app.config['PASSWORD_RESET_TOKEN_MINUTES'])
            db.session.add(PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at, is_used=False))
            db.session.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            sent, send_reason = send_password_reset_email(user.email, reset_link)
            if not sent:
                app.logger.info('password_reset_link_for_%s: %s', user.email, reset_link)
                if app.config.get('DEBUG_SHOW_RESET_LINK_ON_EMAIL_FAIL') and app.config.get('ENVIRONMENT') != 'production':
                    flash(f'Тестовый режим: отправка почты не удалась ({send_reason}). Ссылка: {reset_link}')

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


@app.route('/privacy')
def privacy_policy():
    return render_template('privacy.html')


@app.route('/terms')
def terms_of_use():
    return render_template('terms.html')


@app.route('/security-policy')
def security_policy():
    return render_template('security_policy.html')


@app.route('/notifications')
@login_required
def notifications_page():
    items = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc(), Notification.id.desc()).limit(120).all()
    return render_template('notifications.html', notifications=items)


@app.route('/notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first()
    if not notification:
        flash('Уведомление не найдено')
        return redirect(url_for('notifications_page'))

    notification.is_read = True
    db.session.commit()
    return redirect(url_for('notifications_page'))


@app.route('/schedule')
@login_required
def schedule_page():
    latest_schedule = get_latest_schedule_file()
    schedule_history = ScheduleFile.query.order_by(ScheduleFile.uploaded_at.desc(), ScheduleFile.id.desc()).limit(app.config.get('MAX_SCHEDULE_HISTORY', 20)).all()
    return render_template('schedule.html', latest_schedule=latest_schedule, schedule_history=schedule_history)


@app.route('/schedule/file/<int:file_id>')
@login_required
def download_schedule(file_id):
    schedule_file = ScheduleFile.query.get(file_id)
    if not schedule_file:
        flash('Файл расписания не найден')
        return redirect(url_for('schedule_page'))

    return send_from_directory(
        app.config.get('SCHEDULE_UPLOAD_DIR'),
        schedule_file.stored_name,
        as_attachment=True,
        download_name=schedule_file.original_name
    )


@app.route('/admin/schedule/upload', methods=['POST'])
@login_required
def admin_upload_schedule():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    schedule = request.files.get('schedule_file')
    if not schedule or not schedule.filename:
        flash('Выберите файл расписания')
        return redirect(url_for('admin_dashboard'))

    safe_name = secure_filename(schedule.filename)
    if not safe_name:
        flash('Некорректное имя файла')
        return redirect(url_for('admin_dashboard'))

    stamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    stored_name = f'{stamp}_{safe_name}'
    full_path = os.path.join(app.config.get('SCHEDULE_UPLOAD_DIR'), stored_name)
    schedule.save(full_path)

    db.session.add(ScheduleFile(
        original_name=schedule.filename,
        stored_name=stored_name,
        uploaded_by_id=current_user.id,
        uploaded_at=datetime.utcnow()
    ))
    db.session.commit()
    log_audit('upload_schedule', f'file={schedule.filename}')
    flash('Расписание загружено и доступно всем пользователям')
    return redirect(url_for('admin_dashboard'))


@app.route('/health')
def healthcheck():
    return {'status': 'ok', 'service': 'studenthubik'}, 200


@app.route('/ready')
def readiness_check():
    try:
        db.session.execute(text('SELECT 1'))
        return {'status': 'ready', 'database': 'ok'}, 200
    except Exception as error:
        app.logger.exception('readiness_check_failed: %s', error)
        return {'status': 'not_ready', 'database': 'error'}, 503


@app.route('/student')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect_to_role_dashboard()

    period = request.args.get('period', 'all')
    semester_filter = request.args.get('semester', 'all')
    page = request.args.get('page', 1, type=int)

    grades_query = Grade.query.filter_by(student_id=current_user.id)
    grades_query = apply_period_filter(grades_query, period)
    semester_value = resolve_semester_filter(semester_filter)
    if semester_value:
        grades_query = grades_query.filter(Grade.semester == semester_value)
    grades = grades_query.order_by(Grade.graded_at.desc(), Grade.id.desc()).all()

    grade_values = [grade.grade for grade in grades]
    average_grade = round(sum(grade_values) / len(grade_values), 2) if grade_values else 0
    all_student_grades = Grade.query.filter_by(student_id=current_user.id).all()
    semester_stats = get_semester_averages(all_student_grades)
    subject_count = len({grade.subject_id for grade in grades})
    best_grade = max(grade_values) if grade_values else '—'
    worst_grade = min(grade_values) if grade_values else '—'

    subject_averages = (
        db.session.query(Subject.name, func.round(func.avg(Grade.grade), 2), func.count(Grade.id))
        .join(Grade, Grade.subject_id == Subject.id)
        .filter(Grade.student_id == current_user.id)
    )
    subject_averages = apply_period_filter(subject_averages, period)
    if semester_value:
        subject_averages = subject_averages.filter(Grade.semester == semester_value)
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
        semester_filter=semester_filter,
        semester_stats=semester_stats,
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
    writer.writerow(['subject', 'grade', 'semester', 'graded_at'])
    for item in grades:
        writer.writerow([item.subject.name, item.grade, item.semester, item.graded_at.isoformat() if item.graded_at else ''])

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
    semester_filter = request.args.get('semester', 'all')
    semester_value = resolve_semester_filter(semester_filter)
    search_query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create_grade':
            student_id = request.form.get('student_id')
            subject_id = request.form.get('subject_id')
            grade_value = request.form.get('value')
            semester = request.form.get('semester', '1')
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

            if semester not in {'1', '2'}:
                flash('Семестр должен быть 1 или 2')
                return redirect(url_for('teacher_dashboard'))

            new_grade = Grade(
                student_id=student.id,
                subject_id=subject.id,
                grade=numeric_grade,
                comment=comment[:300],
                semester=int(semester),
                graded_at=datetime.utcnow()
            )
            db.session.add(new_grade)
            create_notification(student.id, 'Новая оценка', f'По предмету {subject.name} выставлена оценка {numeric_grade} (семестр {semester}).')
            db.session.commit()
            log_audit('create_grade', f'grade_id={new_grade.id}, student={student.id}, subject={subject.id}, grade={numeric_grade}, semester={semester}')
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
            semester = request.form.get('semester', '1')
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

            if semester not in {'1', '2'}:
                flash('Семестр должен быть 1 или 2')
                return redirect(url_for('teacher_dashboard'))

            grade_item.grade = numeric_grade
            grade_item.semester = int(semester)
            grade_item.comment = comment[:300]
            grade_item.graded_at = datetime.utcnow()
            db.session.commit()
            create_notification(grade_item.student_id, 'Оценка обновлена', f'Оценка по предмету {grade_item.subject.name} обновлена на {numeric_grade} (семестр {semester}).')
            log_audit('update_grade', f'grade_id={grade_id}, grade={numeric_grade}, semester={semester}')
            flash('Оценка обновлена')
            return redirect(url_for('teacher_dashboard'))

        flash('Некорректное действие')
        return redirect(url_for('teacher_dashboard'))

    recent_grades_query = (
        Grade.query.join(Subject).join(User, Grade.student_id == User.id)
        .filter(Subject.teacher_id == current_user.id)
    )
    recent_grades_query = apply_period_filter(recent_grades_query, period)
    if semester_value:
        recent_grades_query = recent_grades_query.filter(Grade.semester == semester_value)
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

    all_teacher_grades = Grade.query.join(Subject).filter(Subject.teacher_id == current_user.id).all()
    teacher_stats = get_semester_averages(all_teacher_grades)

    return render_template(
        'teacher_dashboard.html',
        students=students,
        subjects=subjects,
        recent_grades=recent_grades,
        groups_by_id=groups_by_id,
        subject_averages=subject_averages,
        period=period,
        semester_filter=semester_filter,
        search_query=search_query,
        teacher_stats=teacher_stats,
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
    writer.writerow(['student', 'subject', 'grade', 'semester', 'comment', 'graded_at'])
    for item in grades:
        writer.writerow([item.student.name, item.subject.name, item.grade, item.semester, item.comment or '', item.graded_at.isoformat() if item.graded_at else ''])

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
    latest_schedule = get_latest_schedule_file()

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
        latest_schedule=latest_schedule,
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




@app.route('/admin/backup-db')
@login_required
def admin_backup_db():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if not db_uri.startswith('sqlite:///'):
        flash('Автобэкап доступен только для SQLite в этой сборке')
        return redirect(url_for('admin_dashboard'))

    source_rel = db_uri.replace('sqlite:///', '', 1)
    source_path = os.path.join(app.root_path, source_rel)
    if not os.path.exists(source_path):
        source_path = os.path.join(app.instance_path, 'site.db')

    backup_dir = os.path.join(app.instance_path, 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    stamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    backup_name = f'site_{stamp}.db'
    backup_path = os.path.join(backup_dir, backup_name)
    shutil.copy2(source_path, backup_path)
    log_audit('backup_db', f'file={backup_name}')

    return send_from_directory(backup_dir, backup_name, as_attachment=True)


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
