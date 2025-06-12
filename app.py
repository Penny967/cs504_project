import os
import sqlite3
import pyotp
import qrcode
import io
import base64
import re
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "your-secret-key-here")
DB_PATH = 'users.db'

# Admin configuration - these usernames will have admin access
ADMIN_USERS = ['admin', 'penny', 'administrator', 'root']

# Email validation regex pattern
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

def validate_email(email):
    """Validate email format using regex"""
    if not email:
        return False
    return EMAIL_REGEX.match(email) is not None

def clean_input(text):
    """Clean and sanitize user input"""
    if text:
        return text.strip()
    return text

def is_admin_user(username):
    """Check if user has admin privileges"""
    return username and username.lower() in [admin.lower() for admin in ADMIN_USERS]

def get_db():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    """Initialize database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    
    # Create users table with admin role
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            is_admin BOOLEAN DEFAULT 0,
            failed_login_attempts INTEGER DEFAULT 0
        )
    ''')
    
    # Create audit log table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            details TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def add_audit_log(user_id, action, ip_address, details=None):
    """Add audit log entry for security tracking"""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (user_id, action, ip_address, details) VALUES (?, ?, ?, ?)",
            (user_id, action, ip_address, details)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # Silent error handling to avoid breaking main functionality

# Initialize database on startup
initialize_database()

# =============================================================================
# Web Routes
# =============================================================================

@app.route("/")
def index():
    """Redirect to login page"""
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration with MFA setup"""
    if request.method == "POST":
        username = clean_input(request.form.get("username"))
        email = clean_input(request.form.get("email"))
        password = request.form.get("password")
        pin = request.form.get("pin")
        
        # Basic input validation
        if not username or not email or not password or not pin:
            flash("All fields are required.")
            return redirect(url_for("register"))
        
        # Email format validation
        if not validate_email(email):
            flash("Please enter a valid email address.")
            return redirect(url_for("register"))
        
        # PIN format validation (must be 4 digits)
        if not re.match(r'^\d{4}$', pin):
            flash("PIN must be exactly 4 digits.")
            return redirect(url_for("register"))
        
        # Password length validation
        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
            return redirect(url_for("register"))
        
        # Generate secure authentication data
        totp_secret = pyotp.random_base32()
        password_hash = generate_password_hash(password)
        pin_hash = generate_password_hash(pin)
        
        # Check if user should have admin privileges
        is_admin = is_admin_user(username)
        
        conn = get_db()
        try:
            # Use parameterized query to prevent SQL injection
            cursor = conn.execute(
                "INSERT INTO users (username, email, password_hash, pin_hash, totp_secret, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
                (username, email, password_hash, pin_hash, totp_secret, is_admin)
            )
            conn.commit()
            
            # Get new user ID correctly using cursor.lastrowid
            user_id = cursor.lastrowid
            add_audit_log(user_id, 'USER_REGISTERED', request.remote_addr or '127.0.0.1', 
                         f"Admin: {is_admin}")
            
        except sqlite3.IntegrityError as e:
            error_msg = str(e).lower()
            if 'username' in error_msg:
                flash("Username already exists.")
            elif 'email' in error_msg:
                flash("Email already exists.")
            else:
                flash("Registration failed. Please try again.")
            return redirect(url_for("register"))
        except Exception as e:
            flash("Registration failed due to system error.")
            return redirect(url_for("register"))
        finally:
            conn.close()
        
        # Generate QR code for TOTP setup
        try:
            uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="MFA-Demo")
            img = qrcode.make(uri)
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
            
            return render_template("show_qr.html", qr_code=img_b64)
        except Exception as e:
            flash(f"Registration successful! Please set up TOTP manually. Secret: {totp_secret}")
            return redirect(url_for("login"))
    
    return re