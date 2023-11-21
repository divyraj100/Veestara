from flask import (
    Flask,
    render_template,
    url_for,
    request,
    make_response,
    redirect,
    Response,
    session,
    flash,
)
import re
from sqlalchemy import or_
from flask import abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from wtforms import TextAreaField
import xml.etree.ElementTree as ET
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)  # Add this import
from datetime import datetime
import secrets
import bleach

# The rest of your code remains unchanged...


secret_key = secrets.token_hex(16)
admin_token = "your_admin_token_here"

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///articles.db"
app.config["SECRET_KEY"] = secret_key
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ckeditor = CKEditor(app)


class ArticleForm(FlaskForm):
    Content = TextAreaField("Content")
    Title = TextAreaField("Title")


with app.app_context():
    db.create_all()


class Post(db.Model):
    # __tablename__ = "articles"s
    Id = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    Title = db.Column(db.String(255), nullable=False)
    Content = db.Column(db.Text, nullable=False)
    ImageData = db.Column(db.LargeBinary, nullable=True)
    Category = db.Column(db.String(50), nullable=True)
    Date = db.Column(db.Date, nullable=False)
    Author = db.Column(db.String(50), nullable=True)
    URL = db.Column(db.String(255), nullable=True)


class Comment(db.Model):
    Id = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    Comment = db.Column(db.String(255), nullable=False)
    Name = db.Column(db.String(255), nullable=False)
    Mail = db.Column(db.String(255), nullable=False)
    IsApproved = db.Column(db.Boolean, default=False)
    IsDeleted = db.Column(db.Boolean, default=False)
    Page = db.Column(db.String(255))  # Add this field


def is_valid_email(email):
    # Define a regular expression pattern for a basic email validation
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email)


@app.route("/comment_dashboard", methods=["GET", "POST"])
def comment_dashboard():
    comments = Comment.query.all()
    if request.method == "POST":
        for key in request.form:
            action, comment_id = key.split("_")
            comment = Comment.query.get(int(comment_id))
            if action == "approve":
                comment.IsApproved = True
            elif action == "reject":
                if comment.IsApproved:
                    comment.IsApproved = False
                else:
                    # If the comment is already unapproved, delete it instead of toggling approval status.
                    db.session.delete(comment)
            elif action == "delete":
                db.session.delete(comment)
            elif action == "restore":
                comment.IsDeleted = False
            db.session.commit()
        # flash("Comment management actions applied.", "success")
        return redirect(url_for("comment_dashboard"))

    comments = Comment.query.all()
    return render_template("comment_dashboard.html", comments=comments)


@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
def delete_comment(comment_id):
    if request.method == "POST":
        # Check which action was triggered (approve, reject, or delete)
        for key in request.form:
            action, key_comment_id = key.split("_")
            if action == "delete" and int(key_comment_id) == comment_id:
                comment = Comment.query.get(comment_id)
                if comment:
                    # Delete the comment from the database
                    db.session.delete(comment)
                    db.session.commit()
                    flash("Comment deleted successfully.", "success")
                break  # Exit the loop after finding the matching comment

    # Redirect back to the comment dashboard after deletion
    return redirect(url_for("comment_dashboard"))


# ------------------------------
# Module for pages
# Module for pages
class Page(db.Model):
    # __tablename__ = "articles"s
    Id = db.Column(db.Integer, primary_key=True, unique=True, autoincrement=True)
    Title = db.Column(db.String(255), nullable=False)
    Content = db.Column(db.Text, nullable=False)
    ImageData = db.Column(db.LargeBinary, nullable=True)
    Date = db.Column(db.Date, nullable=False)
    URL = db.Column(db.String(255), nullable=True)


@app.route("/create_page", methods=["POST", "GET"])
def create_page():
    form = ArticleForm()
    # Title =  " "
    Content = " "

    if request.method == "POST":
        id = request.form.get("Id")
        title = request.form.get("Title")
        content = request.form.get("Content")
        image = request.files.get("Image")
        date_ = request.form.get("Date")
        url = request.form.get("URL")
        action = request.form.get("action")

        # Call the format_url function to format the URL
        url = format_url(url)

        if action == "create":
            # content = BeautifulSoup(content, "html.parser").get_text()
            content = bleach.clean(
                content,
                tags=["p", "a", "img"],
                attributes={"a": ["href", "title"], "img": ["src", "alt"]},
            )

            try:
                date = datetime.strptime(date_, "%Y-%m-%d").date()
            except ValueError:
                return "Invalid date format", 400

            new_article = Page(
                Title=title,
                Content=content,  # Set the category
                Date=date,
                URL=url,  # Set the URL
            )

            if image:
                new_article.ImageData = image.read()

            db.session.add(new_article)
            db.session.commit()
            return "Inserted"

        elif action == "update":
            pages = Page.query.filter_by(Id=id).all()
            # articles = Post.query.filter(Post.Id == id).first()

            if pages:
                for page in pages:
                    if content:
                        page.Content = content

                    if title:
                        page.Title = title

                    if url:
                        page.URL = url

                    if date_:
                        date = datetime.strptime(date_, "%Y-%m-%d").date()
                        page.Date = date

                    if image:
                        page.ImageData = image.read()

                    db.session.commit()
                return "updated", 200
            else:
                return "article not found", 400

            # article_id = request.form.get("Id")
            # article = Post.query.get(article_id)

            # if article:
            #     article.Title = title
            #     article.Content = content
            #     db.session.commit()
            #     return "Updated", 200
            # else:
            #     return "not found", 400

        elif action == "delete":
            pages = Page.query.filter_by(Id=id).all()

            if pages:
                for page in pages:
                    db.session.delete(page)
                    db.session.commit()
                return "deleted", 200
            else:
                return "not deleted", 400

        elif action == "show":
            # articles = Post.query.filter_by(Id=id).all()
            pages = Page.query.filter(Post.Id == id).all()

            if pages:
                page = pages[0]
                # Title = article.Title
                Content = page.Content

                # form.Title.data = Title
                form.Content.data = Content
    return render_template("create_page.html", form=form)


@app.route("/pages/<int:page_id>")
def view_full_page(page_id):
    # Retrieve the page content based on page_id from the database
    page = Page.query.get(page_id)

    if page:
        return render_template("pages.html", pages=page)
    else:
        # Handle the case where the page is not found (e.g., return a 404 page)
        return render_template("404.html"), 404


@app.route("/pagedatabase")
def pagedatabase():
    page = Page.query.all()

    return render_template("page_database.html", page=page)


@app.route("/pages")
def pages():
    page = Page.query.order_by(Page.Date.desc()).all()
    print(page)  # Add this line for debugging
    return render_template("page.html", page=page)


@app.route("/display_image_page/<int:page_id>")
def display_image_page(page_id):
    pages = Page.query.get(page_id)
    if pages and pages.ImageData:
        response = make_response(pages.ImageData)
        response.headers[
            "Content-Type"
        ] = "image/jpeg"  # Change to the appropriate content type (e.g., image/png) if needed.
        return response
    return "Image not found", 404


# ------------------------------


class AdminCreationForm(FlaskForm):
    username = StringField(
        "Admin Username", validators=[DataRequired(), Length(min=4, max=20)]
    )
    password = PasswordField("Admin Password", validators=[DataRequired()])
    submit = SubmitField("Create Admin")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(
        db.String(50), nullable=False
    )  # Store user roles, e.g., "admin" or "user"

    def is_active(self):
        return True  # You can customize this method to determine if the user is active based on your requirements

    def get_id(self):
        return str(self.id)  # Convert the user ID to a string and return it

    def is_authenticated(self):
        return True  # You can customize this method as well

    def is_anonymous(self):
        return False  # You can customize this method if needed


@app.route("/users")
@login_required  # Make it admin required if only admins should see this information
def users():
    users = User.query.all()  # Query all users from the User table
    return render_template("users.html", users=users)


# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"  # Set the login view


# Define the user_loader function to load a user from the database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------


@app.route("/sitemap.xml")
def serves_xml():
    # Retrieve data from the database
    articles = Post.query.all()
    pages = Page.query.all()  # Query all pages from the Page table

    # Create the XML structure
    root = ET.Element("sitemap")  # Use "sitemap" as the root element

    # Create a subelement for articles
    articles_elem = ET.Element("articles")
    root.append(articles_elem)

    for article in articles:
        article_elem = ET.Element("article")
        title_elem = ET.Element("title")
        title_elem.text = article.Title
        date_elem = ET.Element("date")
        date_elem.text = article.Date.strftime("%Y-%m-%d")
        author_elem = ET.Element("author")
        author_elem.text = article.Author
        category_elem = ET.Element("category")
        category_elem.text = article.Category
        url_elem = ET.Element("url")

        # Include the category name in the URL
        url_elem.text = (
            "https://www.veestara.com/"
            + article.Category.lower()
            + "/posts/"
            + format_url(article.Title)
        )

        article_elem.append(title_elem)
        article_elem.append(date_elem)
        article_elem.append(author_elem)
        article_elem.append(category_elem)
        article_elem.append(url_elem)
        articles_elem.append(article_elem)

    # Create a subelement for pages
    pages_elem = ET.Element("pages")
    root.append(pages_elem)

    for page in pages:
        page_elem = ET.Element("page")
        title_elem = ET.Element("title")
        title_elem.text = page.Title
        date_elem = ET.Element("date")
        date_elem.text = page.Date.strftime("%Y-%m-%d")
        url_elem = ET.Element("url")

        # Remove "pages" from the URL
        url_elem.text = "https://www.veestara.com/" + format_url(page.Title)

        page_elem.append(title_elem)
        page_elem.append(date_elem)
        page_elem.append(url_elem)
        pages_elem.append(page_elem)

        # Create a subelement for categories
        categories = [
            {"name": "astrology", "url": "/astrology"},
            {"name": "horoscope", "url": "/horoscope"},
            # Add more categories as needed
        ]

    for category_data in categories:
        category_elem = ET.Element("category")  # Corrected to <category>
        loc_elem = ET.Element("loc")
        loc_elem.text = (
            "https://veestara.com" + category_data["url"]
        )  # Replace with your domain
        category_elem.append(loc_elem)

        # Add a "name" subelement to include the category name
        name_elem = ET.Element("name")
        name_elem.text = category_data["name"]
        category_elem.append(name_elem)

        root.append(category_elem)

    # Serialize to XML
    xml_string = ET.tostring(root)

    # Create an XML response
    response = Response(xml_string, content_type="application/xml")
    return response


# -------------------


@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q")

    # Fetch articles from the database
    articles = Post.query.filter(
        or_(Post.Title.ilike(f"%{query}%"), Post.Content.ilike(f"%{query}%"))
    ).all()

    return render_template("search_results.html", results=articles, query=query)


@app.route("/landing-page")
def landing_page():
    return render_template("landingpage.html")

@app.route("/")
def home():
    return render_template("landingpage.html")

@app.route("/blogs")
def index():
    articles = Post.query.order_by(Post.Date.desc()).all()
    print(articles)  # Add this line for debugging
    return render_template("index.html", articles=articles)

# --------------------
# for adding the wordlimit to the gridcard


def word_limit(s, limit: 18):
    words = s.split()
    return " ".join(words[:limit])


app.jinja_env.filters["wordlimit"] = word_limit

# --------------------


# --------------------
# registration form
class RegistrationForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=4, max=20)]
    )
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Up")


@app.route("/register", methods=["GET", "POST"])
@login_required
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Securely hash the password before storing it in the database
        hashed_password = generate_password_hash(form.password.data, method="sha256")

        # Create a new user and store their information in the database
        new_user = User(
            username=form.username.data, password=hashed_password, role="user"
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Your account has been created! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


# --------------------


# ---------------


def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if "user_role" in session and session["user_role"] == "admin":
            return func(*args, **kwargs)
        else:
            flash(
                "Access denied. You must be an admin to perform this action.", "danger"
            )
            return redirect(url_for("login"))

    return decorated_view


# ---------------


@app.route("/create_admin", methods=["GET", "POST"])
def create_admin():
    form = AdminCreationForm()

    if form.validate_on_submit():
        # Retrieve the submitted username and password
        username = form.username.data
        password = form.password.data

        # Check if an admin with the given username already exists
        existing_admin = User.query.filter_by(username=username, role="admin").first()

        if existing_admin:
            flash("Admin user with this username already exists.", "danger")
        else:
            # Create the admin user
            hashed_password = generate_password_hash(password, method="sha256")
            new_admin = User(username=username, password=hashed_password, role="admin")
            db.session.add(new_admin)
            db.session.commit()
            flash("Admin account created successfully.", "success")
            return redirect(
                url_for("admin_dashboard")
            )  # Replace with the appropriate URL

    return render_template("admin_registration.html", form=form)


# --------------------


# --------------------
def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if "user_role" in session and session["user_role"] == "admin":
            return func(*args, **kwargs)
        else:
            return "Access denied. You must be an admin to perform this action.", 403

    return decorated_view


@app.route("/assign_role")
@admin_required
def assign_role():
    users = User.query.all()
    return render_template("assign_role.html", users=users)


@app.route("/update_user_role/<int:user_id>", methods=["POST"])
def update_user_role(user_id):
    # Get the selected role from the form
    new_role = request.form.get("new_role")

    # Update the user's role in the database
    user = User.query.get(user_id)
    if user:
        user.role = new_role
        db.session.commit()
        flash("Role updated successfully.", "success")
    else:
        flash("User not found.", "danger")

    return redirect(url_for("assign_role"))


@app.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    # Delete the user from the database
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully.", "success")
    else:
        flash("User not found.", "danger")

    return redirect(url_for("assign_role"))


@app.route("/demote_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required  # Add this decorator to restrict access to admins
def demote_user(user_id):
    # Find the user by their unique identifier (e.g., ID)
    user = User.query.get(user_id)

    if user:
        # Update the user's role to 'user'
        user.role = "user"
        db.session.commit()
        flash('User demoted to "user" role successfully.', "success")
    else:
        flash("User not found.", "danger")

    return redirect(
        url_for("user_management_page")
    )  # Redirect to a suitable page after the role change


# --------------------
# login
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


@login_manager.request_loader
def load_user_from_request(request):
    print("Trying to load user from request...")
    token = request.headers.get("Authorization")
    if token:
        # Try to load an admin user here
        admin = User.query.filter_by(username="admin").first()
        if admin:
            print("Admin user found.")
            return admin
        else:
            print("Admin user not found.")
    return None


# Define the user_loader function to load a user from the database
@login_manager.user_loader
def load_user(user_id):
    print(f"Trying to load user with ID {user_id}...")
    return User.query.get(int(user_id))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            # Print some debugging information
            if user.role == "admin":
                print("Admin user logged in.")
                session["user_role"] = "admin"
            flash("You are already login!", "success")
            return redirect(url_for("index"))
        else:
            flash("Login failed. Please check your credentials.", "danger")

    return render_template("login.html", form=form)


# --------------------


@app.route("/user_management_page")
def user_management_page():
    users = User.query.all()
    return render_template("user_management.html", users=users)


# --------------------


@app.route("/<category>")
def display_category(category):
    print(f"Category: {category}")
    articles = Post.query.filter_by(Category=category).all()
    print(f"Number of articles found: {len(articles)}")

    if not articles:
        # If no articles are found for the category, return a 404 error
        abort(404)

    return render_template("category.html", category=category, articles=articles)


@app.route("/categories")
def list_categories():
    # Define code to list all available categories
    categories = ["astrology", "horoscope"]  # Example categories
    return render_template("category.html", categories=categories)


@app.route("/<category>/<url>")
def display_blog_post(category, url):
    # Query the database to find the blog post based on the category and URL
    post = Post.query.filter_by(Category=category, URL=url).first()

    if post:
        return render_template("article.html", article=post, ckeditor=ckeditor)
    else:
        return "Blog post not found", 404




@app.route("/article/<int:article_id>", methods=["POST", "GET"])
def article(article_id):
    try:
        article = Post.query.get(article_id)

        if article:
            ckeditor = False

            if request.method == "POST":
                cmt = request.form.get("cmt_area")
                name = request.form.get("cmt_name")
                mail = request.form.get("cmt_mail")
                action = request.form.get("action")

                if action == "submit_Comment":
                    if is_valid_email(mail):
                        cmt = Comment(
                            Comment=cmt,
                            Name=name,
                            Mail=mail,
                            Page=f"article_{article_id}",
                        )
                        db.session.add(cmt)
                        db.session.commit()
                        flash("Comment inserted successfully", "success")
                    else:
                        flash("Invalid email format", "error")

            # Retrieve comments associated with the article, excluding deleted ones
            approved_comments = Comment.query.filter_by(
                IsApproved=True, Page=f"article_{article_id}", IsDeleted=False
            ).all()

            return render_template(
                "article.html",
                article=article,
                ckeditor=ckeditor,
                comments=approved_comments,
            )

        else:
            return "Article not found", 404

    except Exception as e:
        return str(e), 500


@app.route("/comments")
def comments():
    comments = Comment.query.all()  # Query all comments from the Comment table
    return render_template("cmt_database.html", comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/logout")
def logout():
    session.clear()  # Clear the user's session
    return redirect(url_for("login"))  # Redirect to the login page


# ---------------------------


def format_url(url):
    # Remove leading and trailing whitespace
    url = url.strip()

    # Replace spaces with hyphens
    url = url.replace(" ", "-")

    # Remove any consecutive hyphens
    url = re.sub("-+", "-", url)

    # Remove any non-alphanumeric characters except hyphen
    url = re.sub(r"[^a-zA-Z0-9-]", "", url)

    # Convert to lowercase
    url = url.lower()

    return url


# ---------------------------

# app and database setup code


@app.route("/create_article", methods=["POST", "GET"])
@login_required
def create_article():
    form = ArticleForm()
    # Title =  " "
    Content = " "
    pre_category = ["Astrology", "Horoscope"]

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

        # Call the format_url function to format the URL
        url = format_url(url)

        if action == "create":
            # content = BeautifulSoup(content, "html.parser").get_text()
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
                Title=title,
                Content=content,
                Category=category,  # Set the category
                Date=date,
                URL=url,  # Set the URL
                Author=author,
            )

            if image:
                new_article.ImageData = image.read()

            db.session.add(new_article)
            db.session.commit()
            return "Inserted"

        elif action == "update":
            articles = Post.query.filter_by(Id=id).all()
            # articles = Post.query.filter(Post.Id == id).first()

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

            # article_id = request.form.get("Id")
            # article = Post.query.get(article_id)

            # if article:
            #     article.Title = title
            #     article.Content = content
            #     db.session.commit()
            #     return "Updated", 200
            # else:
            #     return "not found", 400

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
            # articles = Post.query.filter_by(Id=id).all()
            articles = Post.query.filter(Post.Id == id).all()

            if articles:
                article = articles[0]
                # Title = article.Title
                Content = article.Content

                # form.Title.data = Title
                form.Content.data = Content
    return render_template("insert_form.html", form=form, pre_category=pre_category)


@app.route("/database")
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


# --------------
# Dashboard


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# --------------


if __name__ == "__main__":
    app.run(debug=True)
