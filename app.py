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
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        telegram = request.form.get('telegram')
        groups = Group.query.all()

        user = User(
            name=name,
            email=email,
            password=password,
            role=role,
            telegram=telegram
        )

        db.session.add(user)
        db.session.commit()
        group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
        group = db.relationship('Group')

        code = str(random.randint(100000, 999999))
        verify = VerificationCode(user_id=user.id, code=code)
        db.session.add(verify)
        db.session.commit()
        if telegram:
            try:
                bot.send_message(
                    chat_id=f"@{telegram}",
                    text=f"Ваш код подтверждения: {code}"
                )
            except:
                print("Не удалось отправить сообщение в Telegram")

        print(f'КОД ПОДТВЕРЖДЕНИЯ ДЛЯ {email}: {code}')

        return redirect(url_for('verify', user_id=user.id))
        return render_template('register.html', groups=groups)

    return render_template('register.html')

@app.route('/verify/<int:user_id>', methods=['GET', 'POST'])
def verify(user_id):
    if request.method == 'POST':
        code = request.form['code']
        record = VerificationCode.query.filter_by(user_id=user_id, code=code).first()

        if record:
            user = User.query.get(user_id)
            user.is_verified = True
            db.session.delete(record)
            db.session.commit()
            return redirect(url_for('login'))

    return render_template('verify.html')

# ====== ВХОД ======
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        elif not user.is_verified:
            return "Аккаунт не подтверждён"

    return render_template('login.html')


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
            value=request.form['value']
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


