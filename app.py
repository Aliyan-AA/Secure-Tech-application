# Installation: pip install Flask flask_sqlalchemy flask-bcrypt cryptography
# Run: python app.py

from flask import Flask, request, session, redirect, url_for, render_template_string, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
import os
import re
import time
from datetime import datetime, timedelta

app = Flask(__name__)
# Secret key for sessions and security
app.config['SECRET_KEY'] = os.urandom(24)
# Database config - using SQLite for simplicity
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Maximum file upload size (2 MB)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
# File upload folder
app.config['UPLOAD_FOLDER'] = 'uploads'
# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Generate or load a key for symmetric encryption (Fernet)
# In production, keep this key secure and persistent
fernet_key = Fernet.generate_key()
cipher_suite = Fernet(fernet_key)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(150))
    # Example of sensitive data (e.g., credit card)
    credit_card_encrypted = db.Column(db.LargeBinary)
    
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(45))

db.create_all()

# Helper functions
def is_strong_password(password):
    """Enforce strong password: min 8 chars, at least one digit, one special symbol."""
    if len(password) < 8:
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[ !@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def log_action(user_id, action):
    """Log user actions with timestamp and IP."""
    ip = request.remote_addr or '0.0.0.0'
    entry = AuditLog(user_id=user_id, action=action, ip=ip)
    db.session.add(entry)
    db.session.commit()

def login_required(func):
    """Decorator to require login for certain routes."""
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

# Session management: expire after inactivity
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    if 'user_id' in session:
        now = time.time()
        last_active = session.get('last_activity', now)
        if now - last_active > 30 * 60:  # 30 minutes
            user_id = session.get('user_id')
            session.clear()
            flash('Session expired. Please log in again.')
            if user_id:
                log_action(user_id, 'session_expired')
            return redirect(url_for('login'))
        else:
            session['last_activity'] = now

# Routes
@app.route('/')
def index():
    if session.get('user_id'):
        user = User.query.get(session['user_id'])
        return render_template_string("""
        <h1>Welcome, {{user.username}}!</h1>
        <p><a href="{{ url_for('profile') }}">Profile</a> | 
           <a href="{{ url_for('upload') }}">Upload File</a> | 
           <a href="{{ url_for('logout') }}">Logout</a></p>
        """, user=user)
    else:
        return render_template_string("""
        <h1>Welcome to Secure FinTech App</h1>
        <p><a href="{{ url_for('login') }}">Login</a> or 
           <a href="{{ url_for('register') }}">Register</a></p>
        """)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('register'))
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include a digit and a special symbol.')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.')
            return redirect(url_for('register'))
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password_hash=pw_hash, email=email)
        db.session.add(user)
        db.session.commit()
        log_action(user.id, 'registered')
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template_string("""
    <h2>Register</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    <form method="post">
        Username: <input name="username" required><br>
        Email: <input name="email" type="email"><br>
        Password: <input name="password" type="password" required><br>
        <input type="submit" value="Register">
    </form>
    <p><a href="{{ url_for('login') }}">Already have an account? Login here.</a></p>
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Please enter username and password.')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['last_activity'] = time.time()
            session.permanent = True
            log_action(user.id, 'login')
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        flash('Invalid credentials.')
        return redirect(url_for('login'))
    return render_template_string("""
    <h2>Login</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    <form method="post">
        Username: <input name="username" required><br>
        Password: <input name="password" type="password" required><br>
        <input type="submit" value="Login">
    </form>
    <p><a href="{{ url_for('register') }}">No account? Register here.</a></p>
    """)

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    if user_id:
        log_action(user_id, 'logout')
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        credit_card = request.form.get('credit_card', '').strip()
        # Validate email format (simple check)
        if email and not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email address.')
            return redirect(url_for('profile'))
        user.email = email
        # Encrypt credit card if provided
        if credit_card:
            # Basic check: digits only
            if not re.fullmatch(r"\d{12,19}", credit_card):
                flash('Invalid credit card format.')
                return redirect(url_for('profile'))
            encrypted = cipher_suite.encrypt(credit_card.encode('utf-8'))
            user.credit_card_encrypted = encrypted
        db.session.commit()
        log_action(user.id, 'updated_profile')
        flash('Profile updated.')
        return redirect(url_for('profile'))
    # GET: display profile
    cc_masked = ''
    if user.credit_card_encrypted:
        try:
            decrypted = cipher_suite.decrypt(user.credit_card_encrypted).decode('utf-8')
            cc_masked = '****-****-****-' + decrypted[-4:]
        except:
            cc_masked = '[Error decrypting]'
    return render_template_string("""
    <h2>Profile for {{user.username}}</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    <form method="post">
        Email: <input name="email" value="{{user.email or ''}}"><br>
        Credit Card (numbers only): <input name="credit_card"><br>
        Current Card: {{ cc_masked }}<br>
        <input type="submit" value="Update Profile">
    </form>
    <p><a href="{{ url_for('index') }}">Home</a></p>
    """, user=user, cc_masked=cc_masked)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part.')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file.')
            return redirect(request.url)
        # Check file extension
        filename = secure_filename(file.filename)
        allowed_ext = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
        if not ('.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_ext):
            flash('File type not allowed.')
            return redirect(request.url)
        # Save file securely
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        log_action(session['user_id'], f'uploaded_file {filename}')
        flash('File uploaded successfully.')
        return redirect(url_for('upload'))
    # GET: show upload form
    return render_template_string("""
    <h2>Upload File</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" required><br>
        <input type="submit" value="Upload">
    </form>
    <p><a href="{{ url_for('index') }}">Home</a></p>
    """)

# Error handlers to avoid exposing internal details
@app.errorhandler(404)
def not_found(e):
    return "Page not found.", 404

@app.errorhandler(413)
def too_large(e):
    return "File too large. Max size is 2MB.", 413

@app.errorhandler(500)
def internal_error(e):
    return "An internal error occurred.", 500

if __name__ == '__main__':
    app.run()
