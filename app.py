from flask import Flask, render_template, request, redirect, url_for, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
from forms import RegistrationForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

client = MongoClient('mongodb://localhost:27017/')
db = client.flask_db
todos = db.todos
users = db.users

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

@app.route('/', methods=('GET', 'POST'))
def index():
    form = LoginForm()
    if form.validate_on_submit():
        user = users.find_one({'username': form.username.data})
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            login_user(User(user['username']))
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    all_todos = todos.find()
    return render_template('index.html', form=form, todos=all_todos)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = users.find_one({'username': form.username.data})
        if existing_user:
            flash('Username already exists', 'error')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            users.insert_one({'username': form.username.data, 'password': hashed_password})
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/<id>/delete/', methods=['POST'])
@login_required
def delete(id):
    todos.delete_one({"_id": ObjectId(id)})
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
