from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
from dotenv import load_dotenv

# SECRET KEYS
load_dotenv(f"{os.getcwd()}/{'.env'}")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")


app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_SECRET_KEY

# Configure Flask Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Create a user loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB with the UserMixin
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, login instead")
            return redirect(url_for('login'))
        # Hashing and salting password
        password_hashed_salted = generate_password_hash(
            request.form.get("password"),
            method="pbkdf2:sha256",
            salt_length=8,
        )
        new_user = User(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=password_hashed_salted
        )
        db.session.add(new_user)
        db.session.commit()

        # Login and authenticate user after adding details to database
        load_user(new_user)

        # return render_template("secrets.html", user=new_user)
        # Can redirect and get user's name for current_user
        return redirect(url_for("secrets"))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Find user by email entered
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        # Email does not exists or password incorrect
        if not user:
            flash("That email does not exists, please try again")
            return redirect(url_for('login'))
        # Check stored password hash against entered password hashed
        elif not check_password_hash(user.password, password):
            flash("Password incorrect,please try again")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for("secrets"))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    # Passing the name form the current_user
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have logged out")
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
