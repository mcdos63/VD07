from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash

# Инициализация приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Справочник стран
countries = [
    {
        "name": "Россия",
        "info": "Самая большая страна в мире по площади, расположена в Восточной Европе и Северной Азии.",
        "capital": "Москва",
        "map": "http://ostranah.ru/media/coats_of_arms/russia_coat_of_arms.jpg"
    },
    {
        "name": "США",
        "info": "Федеративная республика, состоящая из 50 штатов, третья по численности населения страна.",
        "capital": "Вашингтон",
        "map": "http://ostranah.ru/media/coats_of_arms/united_states_coat_of_arms.jpg"
    },
    {
        "name": "Китай",
        "info": "Самая населённая страна мира, известна своей древней культурой и быстрым экономическим ростом.",
        "capital": "Пекин",
        "map": "http://ostranah.ru/media/coats_of_arms/china_coat_of_arms.jpg"
    },
    {
        "name": "Индия",
        "info": "Вторая по численности населения страна, известна своим разнообразием культур и традиций.",
        "capital": "Нью-Дели",
        "map": "http://ostranah.ru/media/coats_of_arms/india_coat_of_arms.jpg"
    },
    {
        "name": "Бразилия",
        "info": "Крупнейшая страна Латинской Америки, знаменита своими карнавалами и природными богатствами.",
        "capital": "Бразилиа",
        "map": "http://ostranah.ru/media/coats_of_arms/brazil_coat_of_arms.jpg"
    },
    {
        "name": "Австралия",
        "info": "Единственная страна-континент, известна уникальной флорой и фауной.",
        "capital": "Канберра",
        "map": "http://ostranah.ru/media/coats_of_arms/australia_coat_of_arms.jpg"
    },
    {
        "name": "Германия",
        "info": "Одна из крупнейших экономик Европы, известна своей промышленностью и культурой.",
        "capital": "Берлин",
        "map": "http://ostranah.ru/media/coats_of_arms/germany_coat_of_arms.jpg"
    },
    {
        "name": "Франция",
        "info": "Страна моды и искусства, известна своей кухней и архитектурой.",
        "capital": "Париж",
        "map": "http://ostranah.ru/media/coats_of_arms/france_coat_of_arms.jpg"
    },
    {
        "name": "Япония",
        "info": "Страна высоких технологий, известна своей культурой самураев и аниме.",
        "capital": "Токио",
        "map": "http://ostranah.ru/media/coats_of_arms/japan_coat_of_arms.jpg"
    },
    {
        "name": "Канада",
        "info": "Вторая по площади страна в мире, известна своими живописными пейзажами.",
        "capital": "Оттава",
        "map": "http://ostranah.ru/media/coats_of_arms/canada_coat_of_arms.jpg"
    },
    {
        "name": "Италия",
        "info": "Страна с богатой историей, известна своими произведениями искусства и пиццей.",
        "capital": "Рим",
        "map": "http://ostranah.ru/media/coats_of_arms/italy_coat_of_arms.jpg"
    },
    {
        "name": "Испания",
        "info": "Страна фестивалей и фламенко, известна своими пляжами и архитектурой.",
        "capital": "Мадрид",
        "map": "http://ostranah.ru/media/coats_of_arms/spain_coat_of_arms.jpg"
    }
]

# Инициализация расширений
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Авторизуйтесь для доступа к закрытым страницам"
login_manager.login_message_category = "success"

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Загрузка пользователя для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Формы
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password', validators=[Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('password')])
    submit = SubmitField('Update Profile')

# Маршруты
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Такой Email уже использован.', 'danger')
                return redirect(url_for('register'))
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.flush()
            db.session.commit()
            flash('Пользователь зарегистрирован! Вы можете войти.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Ошибка при регистрации пользователя.', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            rm = True if request.form.get('remainme') else False
            login_user(user, remember=rm)
            flash(f'Успешная авторизация! Рады вас видеть, {user.username}!', 'success')
            return redirect(request.args.get("next") or url_for('home'))
        else:
            flash('Неправильное имя пользователя или пароль.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы.', 'info')
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.password.data:
            current_user.set_password(form.password.data)
        db.session.flush()
        db.session.commit()
        flash('Профиль успешно обновлен!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'POST':
        flash('Неправильное имя пользователя или пароль.', 'danger')
    return render_template('profile.html', form=form)

@app.errorhandler(404)
def pageNotFount(error):
    return render_template('page404.html', title="Страница не найдена")

@app.route("/about")
@login_required
def about():
    return render_template("countries.html", countries=countries)

# Создание базы данных
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)