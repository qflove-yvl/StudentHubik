from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))


class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    code = db.Column(db.String(6))


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    teacher = db.relationship('User', backref='subjects')


class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject = db.Column(db.String(100))
    value = db.Column(db.Integer)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            role = request.form.get('role')
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')

            if len(password) < 6:
                flash('Пароль должен быть минимум 6 символов')
                return redirect(url_for('register'))

            if User.query.filter_by(email=email).first():
                flash('Пользователь с таким email уже существует')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password)

            if role == 'student':
                name = request.form.get('name', '').strip()
                group_name = request.form.get('group_name', '').strip()

                if not name or not group_name:
                    flash('Заполните все поля')
                    return redirect(url_for('register'))

                group = Group.query.filter_by(name=group_name).first()
                if not group:
                    group = Group(name=group_name)
                    db.session.add(group)
                    db.session.flush()

                new_user = User(
                    name=name,
                    email=email,
                    password=hashed_password,
                    role='student',
                    group_id=group.id,
                )

            elif role == 'teacher':
                surname = request.form.get('surname', '').strip()
                firstname = request.form.get('firstname', '').strip()
                patronymic = request.form.get('patronymic', '').strip()

                if not surname or not firstname:
                    flash('Введите ФИО полностью')
                    return redirect(url_for('register'))

                full_name = f'{surname} {firstname} {patronymic}'.strip()
                new_user = User(
                    name=full_name,
                    email=email,
                    password=hashed_password,
                    role='teacher',
                )
            else:
                flash('Некорректная роль')
                return redirect(url_for('register'))

            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация успешна!')
            return redirect(url_for('login'))

        except IntegrityError:
            db.session.rollback()
            flash('Ошибка базы данных')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    role = request.args.get('role')

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'teacher':
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
    return redirect('/')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/add_grade', methods=['POST'])
@login_required
def add_grade():
    if current_user.role != 'teacher':
        flash('Недостаточно прав для этой операции')
        return redirect(url_for('dashboard'))

    try:
        student_id = int(request.form.get('student_id', 0))
        subject_name = request.form.get('subject', '').strip()
        value = int(request.form.get('value', 0))

        if value < 2 or value > 5:
            flash('Оценка должна быть от 2 до 5')
            return redirect(url_for('teacher_dashboard'))

        if not subject_name:
            flash('Выберите предмет')
            return redirect(url_for('teacher_dashboard'))

        grade = Grade(
            student_id=student_id,
            teacher_id=current_user.id,
            subject=subject_name,
            value=value,
        )
        db.session.add(grade)
        db.session.commit()

        flash('Оценка добавлена')
        return redirect(url_for('teacher_dashboard'))

    except (TypeError, ValueError):
        flash('Проверьте корректность данных формы')
        return redirect(url_for('teacher_dashboard'))
    except Exception:
        db.session.rollback()
        flash('Ошибка при выставлении оценки')
        return redirect(url_for('teacher_dashboard'))


@app.route('/student')
@login_required
def student_dashboard():
    grades = Grade.query.filter_by(student_id=current_user.id).all()
    return render_template('student_dashboard.html', grades=grades)


@app.route('/teacher', methods=['GET'])
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        return redirect(url_for('dashboard'))

    students = User.query.filter_by(role='student').all()
    subjects = Subject.query.filter_by(teacher_id=current_user.id).all()

    return render_template('teacher_dashboard.html', students=students, subjects=subjects)


if __name__ == '__main__':
    app.run(debug=True)
