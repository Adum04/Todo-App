from flask import Flask, render_template, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SECRET DATABASE KEY")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=2)

# Enable CSRF protection
csrf = CSRFProtect(app)

# Initialize database
db = SQLAlchemy(app)


# Models
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    notes = db.relationship("Note", backref="user", lazy=True)


class Note(db.Model):
    __tablename__ = "note"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(2500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


# Forms
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class SignupForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(min=3, max=100)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Sign Up")


class NoteForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[DataRequired()])
    submit = SubmitField("Add Note")


# Routes
@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session["username"] = user.email
            session.permanent = True
            flash("Logged in successfully!", "success")
            return redirect(url_for("view_notes"))
        flash("Invalid email or password!", "danger")
    return render_template("login.html", form=form)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already exists!", "danger")
        else:
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(
                    form.password.data, method="pbkdf2:sha256"
                ),
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for("login"))
    return render_template("signup.html", form=form)


@app.route("/notes", methods=["GET", "POST"])
def view_notes():
    if "username" not in session:
        flash("You need to log in first!", "danger")
        return redirect(url_for("login"))
    user = User.query.filter_by(email=session["username"]).first()
    form = NoteForm()
    if form.validate_on_submit():
        new_note = Note(
            title=form.title.data, description=form.description.data, user_id=user.id
        )
        db.session.add(new_note)
        db.session.commit()
        flash("Note added successfully!", "success")
        return redirect(url_for("view_notes"))
    notes = Note.query.filter_by(user_id=user.id).all()
    return render_template("notes.html", notes=notes, form=form)


@app.route("/edit/<int:note_id>", methods=["GET", "POST"])
def edit_note(note_id):
    if "username" not in session:
        flash("You need to log in first!", "danger")
        return redirect(url_for("login"))
    note = Note.query.get_or_404(note_id)
    form = NoteForm(obj=note)
    if form.validate_on_submit():
        note.title = form.title.data
        note.description = form.description.data
        db.session.commit()
        flash("Note updated successfully!", "success")
        return redirect(url_for("view_notes"))
    return render_template("edit_note.html", form=form, note=note)


@app.route("/delete_note/<int:note_id>", methods=["POST"])
def delete_note(note_id):
    if "username" not in session:
        flash("You need to log in first!", "danger")
        return redirect(url_for("login"))
    note = Note.query.get_or_404(note_id)
    db.session.delete(note)
    db.session.commit()
    flash("Note deleted successfully!", "success")
    return redirect(url_for("view_notes"))


@app.route("/logout", methods=["POST"])
def logout():
    print("Logout route triggered")
    session.pop("username", None)
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# Initialize database
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run()
