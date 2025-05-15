from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Создание экземпляра приложения Flask
app = Flask(__name__)

# Конфигурация базы данных SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'  # обязательно замените секретный ключ на уникальный
db = SQLAlchemy(app)


# Определение таблицы пользователей
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


# Основная страница
@app.route('/')
def index():
    return render_template('index.html')


# Страница регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Проверка наличия одинаковых пользователей и совпадения паролей
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Пользователь с таким именем уже зарегистрирован.", category='danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Пароли не совпадают.", category='danger')
            return redirect(url_for('register'))

        # Хешируем пароль перед сохранением
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Вы успешно зарегистрированы! Пожалуйста, войдите.", category='success')
        return redirect(url_for('login'))

    return render_template('register.html')


# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['current_user_id'] = user.id
            flash(f"Добро пожаловать, {user.username}!", category='success')
            return redirect(url_for('profile'))
        else:
            flash("Ошибка авторизации. Проверьте имя пользователя и пароль.", category='danger')
            return redirect(url_for('login'))

    return render_template('login.html')


# Профиль пользователя
@app.route('/profile')
def profile():
    logged_in = session.get('logged_in')
    if logged_in:
        user_id = session.get('current_user_id')
        current_user = User.query.get(user_id)
        return render_template('profile.html', current_user=current_user)
    else:
        return redirect(url_for('login'))


# Редактирование профиля
@app.route('/edit-profile', methods=['POST'])
def edit_profile():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))

    user_id = session.get('current_user_id')
    current_user = User.query.get(user_id)

    new_username = request.form.get('new_username')
    new_email = request.form.get('new_email')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    # Если введен новый пароль, убедитесь, что оба поля заполнены одинаково
    if new_password and new_password != confirm_new_password:
        flash("Новый пароль и подтверждение не совпадают.", category='danger')
        return redirect(url_for('profile'))

    # Обновление пароля, если указан новый
    if new_password:
        hashed_new_password = generate_password_hash(new_password)
        current_user.password = hashed_new_password

    # Обновляем имя пользователя и e-mail
    current_user.username = new_username
    current_user.email = new_email

    # Сохраняем изменения в базе данных
    db.session.commit()
    flash("Ваш профиль успешно обновлён!", category='success')
    return redirect(url_for('profile'))


# Выход пользователя
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('current_user_id', None)
    flash("Вы успешно вышли из аккаунта.", category='info')
    return redirect(url_for('index'))


# Инициализация базы данных и запуск приложения
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)