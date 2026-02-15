from flask import flash
from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import random
from telegram import Bot
import os


TELEGRAM_TOKEN = "8356757725:AAHzphHvJ_mBGhSZYN8KrIL6RQ5axoatn7o"
bot = Bot(token=TELEGRAM_TOKEN)


app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'sqlite:///site.db'
)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ====== МОДЕЛЬ ПОЛЬЗОВАТЕЛЯ ======
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


# ====== МОДЕЛЬ ПРЕДМЕТА ======
class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    teacher = db.relationship('User', backref='subjects')


# ====== МОДЕЛЬ ОЦЕНКИ ======
class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'))
    grade = db.Column(db.Integer)

    student = db.relationship('User', foreign_keys=[student_id])
    subject = db.relationship('Subject')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ====== ГЛАВНАЯ СТРАНИЦА ======
@app.route('/')
def index():
    return render_template('index.html')


# ====== РЕГИСТРАЦИЯ ======
@app.route('/register', methods=['GET', 'POST'])
def register():
    groups = Group.query.all()

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        group_id = request.form.get('group_id')

        if not name or not email or not password or not role:
            flash("Заполните все поля")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Пользователь уже существует")
            return redirect(url_for('register'))

        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            role=role,
            group_id=group_id if role == 'student' else None
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Регистрация успешна")
        return redirect(url_for('login', role=role))

    return render_template('register.html', groups=groups)

# ====== ВХОД ======


@app.route('/login', methods=['GET', 'POST'])
def login():
    role = request.args.get('role')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        selected_role = request.form.get('role')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):

            # 🔥 ПРОВЕРКА РОЛИ
            if user.role != selected_role:
                flash("Вы пытаетесь войти не в ту роль")
                return redirect(url_for('login', role=selected_role))

            login_user(user)

            if user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))

        flash("Неверный email или пароль")

    return render_template("login.html", role=role)

# ====== КАБИНЕТ ======
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'student':
        grades = Grade.query.filter_by(student_id=current_user.id).all()
        return render_template('student_dashboard.html', grades=grades)

    if current_user.role == 'teacher':
        return redirect('/teacher')

    return redirect('/')




# ====== ВЫХОД ======
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/student')
@login_required
def student_dashboard():
    grades = Grade.query.filter_by(student_id=current_user.id).all()
    return render_template('student_dashboard.html', grades=grades)

@app.route('/teacher', methods=['GET', 'POST'])
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        return redirect('/dashboard')

    students = User.query.filter_by(role='student').all()
    subjects = Subject.query.filter_by(teacher_id=current_user.id).all()

    if request.method == 'POST':
        grade = Grade(
            student_id=request.form['student_id'],
            subject_id=request.form['subject_id'],
            grade=request.form['value']  # <-- исправлено
        )
        db.session.add(grade)
        db.session.commit()

    return render_template(
        'teacher_dashboard.html',
        students=students,
        subjects=subjects
    )

if __name__ == '__main__':
    app.run(debug=True)


