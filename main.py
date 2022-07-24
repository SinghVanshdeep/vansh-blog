from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUser, Login, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.orm import relationship
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
gravatar = Gravatar(app, size=400, default="wavatar", force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL1", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)


# Table to store user credentials
class User(UserMixin, db.Model):  # parent table
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    passwd = db.Column(db.String(300), unique=True, nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


# so the relationship between the two tables is, One author can have many posts. So many posts can have one author.


# blog post table
class BlogPost(db.Model):  # child table
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))  # foreign key, this is a new column
    author = relationship("User", back_populates="posts")  # the relationship with the posts

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


# Comments Table
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)

    # User relationship One to Many
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="comments")

    # BlogPost relationship One to Many
    blog_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


# decorator to only allow certain routes for admin
def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return function(*args, **kwargs)
        else:
            abort(403)
    return wrapper_function


@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()

    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterUser()
    if register_form.validate_on_submit():
        # if email is already used
        if db.session.query(User).filter_by(email=register_form.email.data).first():  # so if it exists in db
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))

        # adding the entered user register info to the database
        hash_pass = generate_password_hash(register_form.passwd.data, 'pbkdf2:sha256', salt_length=8)
        new_user = User(
            name=register_form.name.data,
            email=register_form.email.data,
            passwd=hash_pass
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = Login()
    if login_form.validate_on_submit():
        user_data = db.session.query(User).filter_by(email=login_form.email.data).first()
        if user_data:
            check_pass = check_password_hash(user_data.passwd, login_form.passwd.data)
            if check_pass:
                login_user(user_data)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password incorrect, please try again.")
                return redirect(url_for("login"))
        else:
            flash("That email does not exist, please try again.")
            return redirect(url_for("login"))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = db.session.query(BlogPost).get(post_id)
    comment_request = db.session.query(Comment).all()
    if comment_form.validate_on_submit():  # so an attempt to submit a comment
        if current_user.is_authenticated:  # if the user is logged in, then save the comment
            new_comment = Comment(text=comment_form.body.data, author_id=current_user.id, blog_id=post_id)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))

        else:  # so if the user is not logged in
            flash("You need to login or be registered to comment")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, form=comment_form, comments=comment_request, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
