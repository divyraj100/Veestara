from flask import (
    Flask,
    render_template,
    url_for,
    request,
    make_response,
    redirect,
    Response,
    flash,
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm
import xml.etree.ElementTree as ET
from wtforms import TextAreaField
from datetime import datetime
from passlib.hash import sha256_crypt
from functools import wraps
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)  # Add this import
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
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
    user = Admin.query.get(int(user_id))
    if user:
        user.role = user.role
    return user


def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.is_authenticated and current_user.role == "admin":
            return func(*args, **kwargs)
        else:
            flash("Access denied. You must be admin")
            return redirect(url_for("login"))

    return decorated_view


class AdminRegistrationForm(FlaskForm):
    username = StringField(
        "Admin Username", validators=[DataRequired(), Length(min=4, max=20)]
    )
    password = PasswordField(
        "Admin Password", validators=[DataRequired(), Length(min=4, max=20)]
    )
    submit = SubmitField("Create Admin")


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
    role = db.Column(db.String(50), nullable=True)

    def is_active(self):
        return True  # You can customize this method to determine if the user is active based on your requirements

    def get_id(self):
        return str(self.id)  # Convert the user ID to a string and return it

    def is_authenticated(self):
        return True  # You can customize this method as well

    def is_anonymous(self):
        return False  # You can customize this method if needed


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


@app.route("/articles.xml")
def serve_xml():
    # Retrieve data from the database
    articles = Post.query.all()

    # Create the XML structure
    root = ET.Element("articles")

    for article in articles:
        article_elem = ET.Element("article")
        title_elem = ET.Element("title")
        title_elem.text = article.Title
        date_elem = ET.Element("date")
        date_elem.text = article.Date.strftime("%Y-%m-%d")  # Convert date to string

        id_elem = ET.Element("id")
        id_elem.text = article.Id
        url_elem = ET.Element("url")
        url_elem.text = article.URL
        author_elem = ET.Element("author")
        author_elem.text = article.Author
        category_elem = ET.Element("category")
        category_elem.text = article.Category
        article_elem.append(title_elem)
        article_elem.append(date_elem)
        article_elem.append(author_elem)
        article_elem.append(category_elem)
        article_elem.append(url_elem)
        root.append(article_elem)

    # ------------

    # -----------

    # Serialize to XML
    xml_string = ET.tostring(root)

    # Create an XML response
    response = Response(xml_string, content_type="application/xml")
    return response

# -------------------


def word_limit(s, limit:18):
    words = s.split()
    return ' '.join(words[:limit])

app.jinja_env.filters['wordlimit'] = word_limit

# -------------------
# Admin Login


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        en_username = request.form.get("Username")
        en_password = request.form.get("Password")

        user = Admin.query.filter_by(username=en_username).first()

        if user:
            hashed_password = (
                user.password
            )  # Retrieve the stored hashed password from the database

            # Check if the provided password matches the stored hash
            if sha256_crypt.verify(en_password, hashed_password):
                login_user(user)
                flash("Login successful", "success")
                return redirect("/")
            else:
                flash("Login failed. Please check your credentials.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["POST", "GET"])
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

        new = Admin(username=en_username, password=pass_hash)

        db.session.add(new)
        db.session.commit()

        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/create_admin", methods=["POST", "GET"])
def create_admin():
    form = AdminRegistrationForm()

    if form.validate_on_submit():
        # Retrieve the submitted username and password
        username = form.username.data
        password = form.password.data

        # Check if an admin with the given username already exists
        existing_admin = Admin.query.filter_by(username=username).first()

        if existing_admin:
            flash("Admin user with this username already exists.", "danger")
        else:
            # Create the admin user
            pass_hash = sha256_crypt.using(rounds=5000518 * -8).hash(password)
            new_admin = Admin(username=username, password=pass_hash, role="admin")
            db.session.add(new_admin)
            db.session.commit()
            flash("Admin account created successfully.", "success")
            return redirect(url_for("/"))  # Replace with the appropriate URL

    return render_template("admin_registration.html", form=form)


@app.route('/assign_role')
@admin_required
def assign_role():
    users = User.query.all()
    return render_template("assign_role.html", users=users)

@app.route('/update_user_role/<int:user_id>', methods=['POST'])
def update_user_role(user_id):
    # Get the selected role from the form
    new_role = request.form.get('new_role')
    
    # Update the user's role in the database
    user = User.query.get(user_id)
    if user:
        user.role = new_role
        db.session.commit()
        flash('Role updated successfully.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('assign_role'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # Delete the user from the database
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('assign_role'))



@app.route('/demote_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required  # Add this decorator to restrict access to admins
def demote_user(user_id):
    # Find the user by their unique identifier (e.g., ID)
    user = User.query.get(user_id)

    if user:
        # Update the user's role to 'user'
        user.role = 'user'
        db.session.commit()
        flash('User demoted to "user" role successfully.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('user_management_page'))  # Redirect to a suitable page after the role change


@app.route("/dashboard")
@admin_required
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

@app.route('/user_management_page')
def user_management_page():
    users = Admin.query.all()
    return render_template('user_management.html', users=users)




@app.route("/database")
@login_required
def database():
    articles = Post.query.all()
    users = Admin.query.all()

    return render_template("dbtable.html", articles=articles, users=users)


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