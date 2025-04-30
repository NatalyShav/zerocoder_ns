# app.py
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# Конфигурация базы данных SQLite
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Менеджер авторизации
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # перенаправление на страницу входа при доступе к защищённым ресурсам

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@app.route('/')
def index():
    if current_user.is_authenticated:
        return f"Привет, {current_user.username}"
    else:
        return "Привет! Пожалуйста, войдите."

@app.route('/register', methods=['GET', 'POST'])
def register():
    from forms import RegistrationForm
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Регистрация прошла успешно!', category="success")
        return redirect(url_for('login'))
    return render_template('register.html', title='Зарегистрироваться', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    from forms import LoginForm
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Неверная почта или пароль.', category="danger")
    return render_template('login.html', title='Войти', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    from forms import UpdateProfileForm
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.new_password.data != '':
            current_user.password = generate_password_hash(form.new_password.data, method='sha256')
        db.session.commit()
        flash('Ваш профиль обновлён!', category="success")
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('profile.html', title='Профиль', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # создаём таблицы БД
    app.run(debug=True)
