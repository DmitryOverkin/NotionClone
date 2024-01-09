from flask import Flask, render_template, url_for, request, redirect, flash
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from PIL import Image


import os
import secrets
import time


DB_NAME = 'database.db'

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')


    def save_picture(self, form_picture):
        if form_picture and form_picture.filename != '':
            random_hex = secrets.token_hex(8)
            _, f_ext = os.path.splitext(form_picture.filename)
            picture_fn = random_hex + f_ext
            picture_path = os.path.join('static/images/profile_pics/', picture_fn)
        else:
            print("No file provided.")
        

        output_size = (125, 125)
        i = Image.open(form_picture)
        i.thumbnail(output_size)
        i.save(picture_path)

        self.image_file = picture_fn
        db.session.commit()






class RegistrationForm(FlaskForm):
    username = StringField('Имя:', validators=[DataRequired()])
    email = StringField('Email:', validators=[DataRequired() ,Email()])
    password = PasswordField('Пароль:', validators=[DataRequired()])
    confirm_password = PasswordField('Повторите пароль:', validators=[DataRequired(), EqualTo('password')])
    image_file = FileField('Загрузите ваш аватар', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Войти')

class LoginForm(FlaskForm):
    email = StringField('Email:', validators=[DataRequired() ,Email()])
    password = PasswordField('Пароль:', validators=[DataRequired()])
    submit = SubmitField('Войти')







def create_database(app):
    with app.app_context():
        if not os.path.exists(DB_NAME):
            db.create_all()
            print("[INFO] >> Database created")

create_database(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def get_avatar(user_id):
    user = User.query.get(int(user_id))
    if user and user.image_file:
        return url_for('static', filename=f'images/profile_pics/{user.image_file}')




@app.route('/')
@app.route('/home')
# @login_required
def home():

    return render_template('index.html', title='Home', current_user=current_user, get_avatar=get_avatar)





@app.route('/register', methods=['POST','GET'])
def register():
    form = RegistrationForm()

    user = User.query.filter_by(email=form.email.data).first()  

    if user:
        # Ошибка, пользователь с таким email уже существует
        flash('Пользователь с такой почтой уже существует!')
    else:
        # Создаем нового пользователя

        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)

            db.session.add(user)
            db.session.commit()

            if form.image_file.data:
                user.save_picture(form.image_file.data)
                db.session.commit()

            flash('Аккаунт успешно создан', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html', title='Регистрация', form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Упс, что-то пошло не так... Проверь данные для входа.', 'danger')

    return render_template('login.html', title='Вход', form=form)

@app.route('/logout')
@login_required 
def logout():
    logout_user()
    return redirect(url_for('login'))






if __name__ == '__main__':
    app.run(debug=True)