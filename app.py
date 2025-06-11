import os
import sqlite3
import pyotp
import qrcode
import io
import base64
import re
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import bleach

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default_secret")
DB_PATH = 'users.db'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Email validation regex
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

def validate_email(email):
    """Validate email format using regex"""
    return EMAIL_REGEX.match(email) is not None

def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if text:
        return bleach.clean(text.strip())
    return text

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    """Initialize database with enhanced security"""
    conn = sqlite3.connect(DB_PATH)
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
            details TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def log_audit(user_id, action, ip_address, details=None):
    """Log security-related events"""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO audit_log (user_id, action, ip_address, details) VALUES (?, ?, ?, ?)",
            (user_id, action, ip_address, details)
        )
        conn.commit()
        logger.info(f"Audit log: {action} for user {user_id} from {ip_address}")
    except Exception as e:
        logger.error(f"Failed to log audit: {e}")
    finally:
        conn.close()

with app.app_context():
    initialize_database()

@app.route("/")
def index():
    return redirect(url_for("login"))

# RESTful API Routes
@app.route("/api/users", methods=["GET"])
@require_auth
def api_get_users():
    """RESTful API: Get all users"""
    conn = get_db()
    try:
        users = conn.execute(
            "SELECT id, username, email, created_at, last_login, is_active FROM users"
        ).fetchall()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'created_at': user['created_at'],
                'last_login': user['last_login'],
                'is_active': bool(user['is_active'])
            })
        
        return jsonify({
            'success': True,
            'data': users_list,
            'count': len(users_list)
        })
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    finally:
        conn.close()

@app.route("/api/users/<int:user_id>", methods=["GET"])
@require_auth
def api_get_user(user_id):
    """RESTful API: Get specific user"""
    conn = get_db()
    try:
        # Use parameterized query to prevent SQL injection
        user = conn.execute(
            "SELECT id, username, email, created_at, last_login, is_active FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'data': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'created_at': user['created_at'],
                'last_login': user['last_login'],
                'is_active': bool(user['is_active'])
            }
        })
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    finally:
        conn.close()

@app.route("/api/users/<int:user_id>", methods=["PUT"])
@require_auth
def api_update_user(user_id):
    """RESTful API: Update user"""
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    # Validate email if provided
    if 'email' in data and not validate_email(data['email']):
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400
    
    conn = get_db()
    try:
        # Build dynamic update query safely
        update_fields = []
        params = []
        
        if 'username' in data:
            update_fields.append("username = ?")
            params.append(sanitize_input(data['username']))
        
        if 'email' in data:
            update_fields.append("email = ?")
            params.append(sanitize_input(data['email']))
        
        if 'is_active' in data:
            update_fields.append("is_active = ?")
            params.append(1 if data['is_active'] else 0)
        
        if not update_fields:
            return jsonify({'success': False, 'error': 'No valid fields to update'}), 400
        
        params.append(user_id)
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        
        cursor = conn.execute(query, params)
        
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        conn.commit()
        
        # Log the update
        log_audit(user_id, 'USER_UPDATED', request.remote_addr, f"Fields: {', '.join(data.keys())}")
        
        return jsonify({'success': True, 'message': 'User updated successfully'})
        
    except sqlite3.IntegrityError as e:
        if 'username' in str(e):
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
        elif 'email' in str(e):
            return jsonify({'success': False, 'error': 'Email already exists'}), 400
        else:
            return jsonify({'success': False, 'error': 'Database constraint violation'}), 400
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    finally:
        conn.close()

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_auth
def api_delete_user(user_id):
    """RESTful API: Delete user"""
    conn = get_db()
    try:
        cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        conn.commit()
        
        # Log the deletion
        log_audit(user_id, 'USER_DELETED', request.remote_addr)
        
        return jsonify({'success': True, 'message': 'User deleted successfully'})
        
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    finally:
        conn.close()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username"))
        email = sanitize_input(request.form.get("email"))
        password = request.form.get("password")
        pin = request.form.get("pin")
        
        # Validation
        if not username or not email or not password or not pin:
            flash("All fields are required.")
            return redirect(url_for("register"))
        
        # Email validation
        if not validate_email(email):
            flash("Please enter a valid email address.")
            return redirect(url_for("register"))
        
        # PIN validation
        if not re.match(r'^\d{4}$', pin):
            flash("PIN must be exactly 4 digits.")
            return redirect(url_for("register"))
        
        # Password validation
        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
            return redirect(url_for("register"))
        
        totp_secret = pyotp.random_base32()
        password_hash = generate_password_hash(password)
        pin_hash = generate_password_hash(pin)
        
        conn = get_db()
        try:
            # Use parameterized query to prevent SQL injection
            conn.execute(
                "INSERT INTO users (username, email, password_hash, pin_hash, totp_secret) VALUES (?, ?, ?, ?, ?)",
                (username, email, password_hash, pin_hash, totp_secret)
            )
            conn.commit()
            
            # Log registration
            user_id = conn.lastrowid
            log_audit(user_id, 'USER_REGISTERED', request.remote_addr)
            
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                flash("Username already exists.")
            elif 'email' in str(e):
                flash("Email already exists.")
            else:
                flash("Registration failed. Please try again.")
            return redirect(url_for("register"))
        finally:
            conn.close()
        
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="MFA-Demo")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf)
        img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        
        return render_template("show_qr.html", qr_code=img_b64)
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username"))
        password = request.form.get("password")
        pin = request.form.get("pin")
        totp_code = request.form.get("totp")
        
        if not all([username, password, pin, totp_code]):
            flash("All fields are required.")
            return redirect(url_for("login"))
        
        conn = get_db()
        try:
            # Use parameterized query to prevent SQL injection
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND is_active = 1",
                (username,)
            ).fetchone()
            
            if user:
                # Check for account lockout (basic protection)
                if user["failed_login_attempts"] >= 5:
                    flash("Account temporarily locked due to too many failed attempts.")
                    log_audit(user["id"], 'LOGIN_BLOCKED', request.remote_addr, "Account locked")
                    return redirect(url_for("login"))
                
                # Verify credentials
                if (check_password_hash(user["password_hash"], password) and 
                    check_password_hash(user["pin_hash"], pin)):
                    
                    totp = pyotp.TOTP(user["totp_secret"])
                    if totp.verify(totp_code):
                        # Successful login
                        session["user"] = username
                        session["user_id"] = user["id"]
                        
                        # Reset failed attempts and update last login
                        conn.execute(
                            "UPDATE users SET failed_login_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?",
                            (user["id"],)
                        )
                        conn.commit()
                        
                        log_audit(user["id"], 'LOGIN_SUCCESS', request.remote_addr)
                        return redirect(url_for("dashboard"))
                
                # Failed login
                conn.execute(
                    "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?",
                    (user["id"],)
                )
                conn.commit()
                log_audit(user["id"], 'LOGIN_FAILED', request.remote_addr)
            else:
                log_audit(None, 'LOGIN_FAILED', request.remote_addr, f"Unknown user: {username}")
        
        except Exception as e:
            logger.error(f"Login error: {e}")
        finally:
            conn.close()
        
        flash("Login failed.")
        return redirect(url_for("login"))
    
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["user"])

@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        log_audit(user_id, 'LOGOUT', request.remote_addr)
    
    session.pop("user", None)
    session.pop("user_id", None)
    flash("You have been logged out.")
    return redirect(url_for("login"))

@app.route("/admin")
@require_auth
def admin():
    conn = get_db()
    try:
        # Use parameterized query with proper ordering
        users = conn.execute(
            "SELECT id, username, email, created_at, last_login, is_active, failed_login_attempts FROM users ORDER BY id"
        ).fetchall()
        
        # Get audit logs for admin view
        audit_logs = conn.execute(
            """SELECT al.*, u.username 
               FROM audit_log al 
               LEFT JOIN users u ON al.user_id = u.id 
               ORDER BY al.timestamp DESC 
               LIMIT 50"""
        ).fetchall()
        
        return render_template("admin.html", users=users, audit_logs=audit_logs)
    finally:
        conn.close()

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)