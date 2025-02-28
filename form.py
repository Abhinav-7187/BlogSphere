from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bootstrap import Bootstrap
from datetime import datetime
from flask_migrate import Migrate
from flask_login import UserMixin
import os
import secrets
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from app import PostForm, CommentForm, LoginForm, RegistrationForm  # Importing all form

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(16))  # JWT secret key

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
Bootstrap(app)
# Initialize Migrate
migrate = Migrate(app, db)


# Initialize LoginManager
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to 'login' for @login_required
login_manager.login_message_category = 'info'

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    posts = relationship('BlogPost', backref='author', lazy=True)
    comments = relationship('Comment', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
    

# Define the BlogPost model
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Foreign key to link to the User model
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Relationship to access comments related to this post
    comments = relationship('Comment', backref='post', lazy=True)
    
    def __repr__(self):
        return f"BlogPost('{self.title}', '{self.date_posted}')"
    

# Define the Comment model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_commented = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Foreign keys to link to User and BlogPost
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), nullable=False)
    
    def __repr__(self):
        return f"Comment('{self.content}', '{self.date_commented}')"
    

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    

# Define the form class using Flask-WTF
'''class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    accept_tos = BooleanField('I accept the Terms of Service', validators=[DataRequired()])
    submit = SubmitField('Sign Up')'''

# Login route
@app.route("/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            flash("Login successful!", "success")
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash("Login failed. Check email and password.", "danger")
    return render_template('login.html', form=form, title="Login")

# Logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# API Route for user signup
@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json()
    
    # Check if user already exists
    user = User.query.filter_by(email=data['email']).first()
    if user:
        return jsonify({"message": "User already exists"}), 400
    
    # Hash the password
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # Create a new user instance
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": f"Account created for {data['username']}!"}), 201

# API Route for user login
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):
        # Generate JWT token
        access_token = create_access_token(identity=user.email)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Login failed. Check email and password."}), 401

# User registration route
@app.route("/signup", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('login'))  # Redirect to login page after registration
    return render_template('register.html', form=form, title="Register")

# Home page route
@app.route("/home")
def home():
    posts = BlogPost.query.order_by(BlogPost.date_posted.desc()).all()
    return render_template('home.html', posts=posts)

# Route to create a new blog post
@app.route("/post/new", methods=["GET", "POST"])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = BlogPost(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', form=form, legend='New Post')

# Route to update an existing blog post
@app.route("/post/<int:post_id>/update", methods=["GET", "POST"])
@login_required
def update_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if post.author != current_user:
        flash('You are not authorized to update this post.', 'danger')
        return redirect(url_for('home'))
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title='Update Post', form=form, legend='Update Post')

# Route to delete a blog post
@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if post.author != current_user:
        flash('You are not authorized to delete this post.', 'danger')
        return redirect(url_for('home'))
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))

# Route to view a single post and its comments
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to be logged in to comment.', 'danger')
            return redirect(url_for('login'))
        comment = Comment(content=form.content.data, author=current_user, post=post)
        db.session.add(comment)
        db.session.commit()
        flash('Your comment has been added!', 'success')
        return redirect(url_for('post', post_id=post.id))
    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.date_commented.asc()).all()
    return render_template('post.html', title=post.title, post=post, form=form, comments=comments)


### Implement API Endpoints for Blog Operations

# Create a New Blog Post via API
@app.route("/api/posts", methods=["POST"])
@jwt_required()
def api_create_post():
    data = request.get_json()
    if not data or not 'title' in data or not 'content' in data:
        return jsonify({"message": "Title and content are required"}), 400
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    new_post = BlogPost(title=data['title'], content=data['content'], author=user)
    db.session.add(new_post)
    db.session.commit()
    return jsonify({"message": "Post created", "post_id": new_post.id}), 201

# Get All Blog Posts via API
@app.route("/api/posts", methods=["GET"])
def api_get_posts():
    posts = BlogPost.query.order_by(BlogPost.date_posted.desc()).all()
    output = []
    for post in posts:
        post_data = {
            "id": post.id,
            "title": post.title,
            "content": post.content,
            "date_posted": post.date_posted,
            "author": post.author.username
        }
        output.append(post_data)
    return jsonify({"posts": output}), 200

# Get Single Blog Post via API
@app.route("/api/posts/<int:post_id>", methods=["GET"])
def api_get_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    post_data = {
        "id": post.id,
        "title": post.title,
        "content": post.content,
        "date_posted": post.date_posted,
        "author": post.author.username
    }
    return jsonify(post_data), 200

# Update a Blog Post via API
@app.route("/api/posts/<int:post_id>", methods=["PUT"])
@jwt_required()
def api_update_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    current_user_email = get_jwt_identity()
    if post.author.email != current_user_email:
        return jsonify({"message": "Unauthorized"}), 403
    data = request.get_json()
    if 'title' in data:
        post.title = data['title']
    if 'content' in data:
        post.content = data['content']
    db.session.commit()
    return jsonify({"message": "Post updated"}), 200

# Delete a blog post via API
@app.route("/api/posts/<int:post_id>", methods=["DELETE"])
@jwt_required()
def api_delete_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    current_user_email = get_jwt_identity()
    if post.author.email != current_user_email:
        return jsonify({"message": "Unauthorized"}), 403
    db.session.delete(post)
    db.session.commit()
    return jsonify({"message": "Post deleted"}), 200

# Add a Comment via API
@app.route("/api/posts/<int:post_id>/comments", methods=["POST"])
@jwt_required()
def api_add_comment(post_id):
    post = BlogPost.query.get_or_404(post_id)
    data = request.get_json()
    if not data or not 'content' in data:
        return jsonify({"message": "Content is required"}), 400
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    comment = Comment(content=data['content'], author=user, post=post)
    db.session.add(comment)
    db.session.commit()
    return jsonify({"message": "Comment added", "comment_id": comment.id}), 201

# Get Comments for a Post via API
@app.route("/api/posts/<int:post_id>/comments", methods=["GET"])
def api_get_comments(post_id):
    post = BlogPost.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.date_commented.asc()).all()
    output = []
    for comment in comments:
        comment_data = {
            "id": comment.id,
            "content": comment.content,
            "date_commented": comment.date_commented,
            "author": comment.author.username
        }
        output.append(comment_data)
    return jsonify({"comments": output}), 200

if __name__ == "__main__":
    app.run(debug=True)