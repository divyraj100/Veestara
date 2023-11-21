from flask import (
    Flask,
    render_template,
    url_for,
    request,
    make_response,
    redirect,
    flash,
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm
from wtforms import TextAreaField
from datetime import datetime
from passlib.hash import sha256_crypt
import secrets
import bleach

# from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)

# from werkzeug.utils import secure_filename
# from flask_wtf.csrf import CSRFProtect
# from bs4 import BeautifulSoup


secret_key = secrets.token_hex(16)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///articles.db"
app.config["SECRET_KEY"] = secret_key
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ckeditor = CKEditor(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

###


class ArticleForm(FlaskForm):
    Content = TextAreaField("Content")
    Title = TextAreaField("Title")


with app.app_context():
    db.create_all()


class User(UserMixin):
    def __init__(self, id):
        self.id = id


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


class Post(db.Model):
    Id = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    Title = db.Column(db.String(255), nullable=False)
    Content = db.Column(db.Text, nullable=False)
    ImageData = db.Column(db.LargeBinary, nullable=True)
    Category = db.Column(db.String(50), nullable=True)
    Date = db.Column(db.Date, nullable=False)
    Author = db.Column(db.String(50), nullable=True)
    URL = db.Column(db.String(255), nullable=True)


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


@app.route("/")
def index():
    articles = Post.query.order_by(Post.Date.desc()).all()
    return render_template("index.html", articles=articles)


@app.route("/article/<int:article_id>")
def article(article_id):
    try:
        article = Post.query.get(article_id)
        if article:
            ckeditor = False
            return render_template("article.html", article=article, ckeditor=ckeditor)
        else:
            return "Article not found", 404
    except Exception as e:
        return str(e), 500


@app.route("/about")
def about():
    return render_template("about.html")


# Admin Login


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        en_username = request.form.get("Username")
        en_password = request.form.get("Password")

        if en_username == "Deed" and sha256_crypt.verify(en_password, "drg1232"):
            user = User(1)
            login_user(user)
            flash("Login in successful", "success")
            return redirect("dashboard")

    return render_template("login.html")


@app.route("/register", methods=["POST","GET"])
def register():
    
    if request.method == "POST":
        
        en_username = request.form.get("Username")
        en_password = request.form.get("Password")
        
        # Check if the username already exists
        existing_user = Admin.query.filter_by(username=en_username).first()
        if existing_user:
            flash("Username already exists", "danger")
            return redirect(url_for("register"))
        
        pass_hash = sha256_crypt.using(rounds=5000).hash(en_password)
        
        new = Admin(username=en_username,password=pass_hash)
        
        db.session.add(new)
        db.session.commit()
        
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return "Admin dashboard"


@app.route("/logout")
def logout():
    logout_user()
    flash("You have been logout", "success")
    return redirect(url_for("login"))


# app and database setup code


@app.route("/create_article", methods=["POST", "GET"])
@login_required
def create_article():
    form = ArticleForm()
    Content = " "

    if request.method == "POST":
        id = request.form.get("Id")
        title = request.form.get("Title")
        content = request.form.get("Content")
        image = request.files.get("Image")
        category = request.form.get("Category")
        date_ = request.form.get("Date")
        url = request.form.get("URL")
        author = request.form.get("Author")
        action = request.form.get("action")

        if action == "create":
            content = bleach.clean(
                content,
                tags=["p", "a", "img"],
                attributes={"a": ["href", "title"], "img": ["src", "alt"]},
            )

            try:
                date = datetime.strptime(date_, "%Y-%m-%d").date()
            except ValueError:
                return "Invalid date format", 400

            new_article = Post(
                Id=id,
                Title=title,
                Content=content,
                Category=category,
                Date=date,
                URL=url,
                Author=author,
            )

            if image:
                new_article.ImageData = image.read()

            db.session.add(new_article)
            db.session.commit()
            return "Inserted"

        elif action == "update":
            articles = Post.query.filter_by(Id=id).all()

            if articles:
                for article in articles:
                    if content:
                        article.Content = content

                    if title:
                        article.Title = title

                    if url:
                        article.URL = url

                    if author:
                        article.Author = author

                    if date_:
                        date = datetime.strptime(date_, "%Y-%m-%d").date()
                        article.Date = date

                    if category:
                        article.Category = category

                    if image:
                        article.ImageData = image.read()

                    db.session.commit()
                return "updated", 200
            else:
                return "article not found", 400

        elif action == "delete":
            articles = Post.query.filter_by(Id=id).all()

            if articles:
                for article in articles:
                    db.session.delete(article)
                    db.session.commit()
                return "deleted", 200
            else:
                return "not deleted", 400

        elif action == "show":
            articles = Post.query.filter(Post.Id == id).all()

            if articles:
                article = articles[0]
                Content = article.Content

                form.Content.data = Content
    return render_template("insert_form.html", form=form)


@app.route("/database")
@login_required
def database():
    articles = Post.query.all()

    return render_template("dbtable.html", articles=articles)


@app.route("/display_image/<int:article_id>")
def display_image(article_id):
    article = Post.query.get(article_id)
    if article and article.ImageData:
        response = make_response(article.ImageData)
        response.headers[
            "Content-Type"
        ] = "image/jpeg"  # Change to the appropriate content type (e.g., image/png) if needed.
        return response
    return "Image not found", 404


if __name__ == "__main__":
    app.run(debug=True)