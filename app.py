from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from functools import wraps
from werkzeug.security import generate_password_hash

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SECRET_KEY"] = "Your secret key"


db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

class User(db.Model, UserMixin):

    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

  




@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))



@app.route("/")
def home():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/courses")
@login_required
def courses():
    return render_template("courses.html")
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!", "success") 
            if current_user.role=="admin":
             return redirect(url_for("teacher_dashboard"))
            else:
                return redirect(url_for('dashboard'))
            # return render_template("dashboard.html")
        else:
            flash("Invalid credentials!", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        mobile = request.form.get("mobile")
        role = request.form.get("role")

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        # Check if the email already exists
        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        new_user = User(name=name, email=email, mobile=mobile,role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # This is class_id
    title = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    teacher = db.relationship('User', backref=db.backref('classes', lazy=True))

class Question(db.Model):
    ques_id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(200), nullable=False)
    option_a = db.Column(db.String(100), nullable=False)
    option_b = db.Column(db.String(100), nullable=False)
    option_c = db.Column(db.String(100), nullable=False)
    option_d = db.Column(db.String(100), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)  # A, B, C, or D
    class_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=False)  # Link to a class


@app.route("/student_dashboard")
@login_required
def student_dashboard():
    if current_user.role != "user":
        flash("Access denied!", "danger")
        return redirect(url_for("home"))

    classes = Classroom.query.all()  # Show all available classes
    return render_template("student_dashboard.html", classes=classes)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))

@app.route("/maths")
def maths():
    return render_template("quiz1.html")
@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/quiz1")
@login_required
def quiz1():
    return render_template("quiz1.html")

@app.route("/quiz2")
@login_required
def quiz2():
    return render_template("quiz2.html")

@app.route("/quiz3")
@login_required
def quiz3():
    return render_template("quiz3.html")


@app.route("/quiz4")
@login_required
def quiz4():
    return render_template("quiz4.html")

@app.route("/quiz5")
@login_required
def quiz5():
    return render_template("quiz5.html")

@app.route("/quiz6")
@login_required
def quiz6():
    return render_template("quiz6.html")

@app.route("/quiz7")
@login_required
def quiz7():
    return render_template("quiz7.html")




def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.role != 'admin':
            flash("Access denied!", "danger")
            return redirect(url_for("dashboard"))
        return func(*args, **kwargs)
    return wrapper


@app.route('/admin')
@login_required
@admin_required
def admin():
    return "Welcome to the admin panel!"


@app.route("/add_questions/<int:Questions_id>", methods=["GET", "POST"])
# @app.route("/add_questions", methods=["GET", "POST"])
@login_required
def add_questions(class_id):
    classroom = Classroom.query.get_or_404(class_id)

    if current_user.id != classroom.teacher_id:
        flash("You do not have permission to add questions to this class", "danger")
        return redirect(url_for("teacher_dashboard"))

    if request.method == "POST":
        question_text = request.form['question']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_option = request.form['correct_option']

        questions = Question(
            question_text=question_text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_option=correct_option,
            class_id=classroom.id
        )
        db.session.add(question)
        db.session.commit()

        flash("Question added successfully!", "success")
        return redirect(url_for("add_questions", class_id=class_id))

    questions = Question.query.filter_by(class_id=class_id).all()
    return render_template("add_questions.html", classroom=classroom, questions=questions)

@app.route("/take_quiz/<int:class_id>", methods=["GET", "POST"])
@login_required
def take_quiz(class_id):
    classroom = Classroom.query.get_or_404(class_id)
    questions = Question.query.filter_by(class_id=class_id).all()  

    if request.method == "POST":
        score = 0
        total_questions = len(questions)

        for question in questions:
            selected_answer = request.form.get(f"question_{question.id}")
            if selected_answer and selected_answer.upper() == question.correct_option:
                score += 1

        flash(f"You scored {score} out of {total_questions}!", "success")
        return redirect(url_for("student_dashboard"))

    return render_template("take_quiz.html", classroom=classroom, questions=questions)


@app.route("/teacher_dashboard", methods=["GET", "POST"])
@login_required
def teacher_dashboard():
    if current_user.role != "admin":
        flash("Access denied!", "danger")
        return redirect(url_for("home"))

    if request.method == "POST":
        title = request.form.get("title")
        classroom = Classroom(title=title, teacher_id=current_user.id)
        db.session.add(classroom)
        db.session.commit()
        flash("Classroom created successfully!", "success")
        return redirect(url_for("teacher_dashboard"))

    # Get classrooms created by the teacher
    classrooms = Classroom.query.filter_by(teacher_id=current_user.id).all()
    return render_template("teacher_dashboard.html", classrooms=classrooms)

@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash("Access Denied! Admins only.","danger")
        return redirect(url_for("dashboard"))
    return render_template("teacher_dashboard.html")


@app.route("/add_questions")
def add_question():
    render_template("add_questions.html")


if __name__ == "__main__":
    with app.app_context():
        #db.drop_all()
        db.create_all()
    app.run(debug=True)     
