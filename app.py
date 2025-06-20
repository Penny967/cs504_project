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
ADMIN_USERS = ['admin', 'penny', 'administrator', 'root']  # Add your admin usernames here

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

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
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
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = clean_input(request.form.get("username"))
        password = request.form.get("password")
        pin = request.form.get("pin")
        totp_code = request.form.get("totp")
        
        # Validate all required fields are provided
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
                # Check if account is locked due to failed attempts
                if user["failed_login_attempts"] >= 5:
                    flash("Account temporarily locked due to too many failed attempts.")
                    add_audit_log(user["id"], 'LOGIN_BLOCKED', request.remote_addr or '127.0.0.1', "Account locked")
                    return redirect(url_for("login"))
                
                # Verify password and PIN
                password_valid = check_password_hash(user["password_hash"], password)
                pin_valid = check_password_hash(user["pin_hash"], pin)
                
                if password_valid and pin_valid:
                    # Verify TOTP code
                    totp = pyotp.TOTP(user["totp_secret"])
                    if totp.verify(totp_code):
                        # Login successful
                        session["user"] = username
                        session["user_id"] = user["id"]
                        session["is_admin"] = user["is_admin"]
                        
                        # Reset failed attempts and update last login time
                        conn.execute(
                            "UPDATE users SET failed_login_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?",
                            (user["id"],)
                        )
                        conn.commit()
                        
                        add_audit_log(user["id"], 'LOGIN_SUCCESS', request.remote_addr or '127.0.0.1',
                                     f"Admin: {session['is_admin']}")
                        return redirect(url_for("dashboard"))
                
                # Login failed - increment failed attempts counter
                conn.execute(
                    "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?",
                    (user["id"],)
                )
                conn.commit()
                add_audit_log(user["id"], 'LOGIN_FAILED', request.remote_addr or '127.0.0.1')
            else:
                # Unknown user attempted login
                add_audit_log(None, 'LOGIN_FAILED', request.remote_addr or '127.0.0.1', f"Unknown user: {username}")
        
        except Exception as e:
            print(f"Exception occurred during login: {e}")  # Print the actual exception
            flash("Login system error. Please try again.")
        finally:
            conn.close()
        
        flash("Invalid credentials. Please try again.")
        return redirect(url_for("login"))
    
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["user"], is_admin=session.get("is_admin", False))

@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        add_audit_log(user_id, 'LOGOUT', request.remote_addr or '127.0.0.1')
    
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))

@app.route("/admin")
def admin():
    # First check if user is logged in
    if "user" not in session:
        flash("Please log in to access admin panel.")
        return redirect(url_for("login"))
    
    # SECURITY CHECK: Only allow admin users to access this page
    if not session.get("is_admin", False):
        flash("Access denied. Admin privileges required.")
        add_audit_log(session.get("user_id"), 'ADMIN_ACCESS_DENIED', 
                     request.remote_addr or '127.0.0.1', f"User: {session['user']}")
        return redirect(url_for("dashboard"))
    
    conn = get_db()
    try:
        # Get list of all users (only for admins)
        users = conn.execute(
            "SELECT id, username, email, created_at, last_login, is_active, is_admin, failed_login_attempts FROM users ORDER BY id"
        ).fetchall()
        
        # Get audit logs (latest 50 entries)
        audit_logs = conn.execute(
            """SELECT al.*, u.username 
               FROM audit_log al 
               LEFT JOIN users u ON al.user_id = u.id 
               ORDER BY al.timestamp DESC 
               LIMIT 50"""
        ).fetchall()
        
        add_audit_log(session.get("user_id"), 'ADMIN_ACCESS', 
                     request.remote_addr or '127.0.0.1', "Admin panel accessed")
        
        return render_template("admin.html", users=users, audit_logs=audit_logs)
    except Exception as e:
        flash("Error loading admin data.")
        return redirect(url_for("dashboard"))
    finally:
        conn.close()

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return redirect(url_for("login"))

@app.errorhandler(500)
def internal_error(error):
    return "Internal server error. Please try again later.", 500

@app.route("/debug")
def debug_info():
    import os
    import sqlite3
    
    result = {"database_exists": os.path.exists('users.db')}
    
    if os.path.exists('users.db'):
        try:
            conn = sqlite3.connect('users.db')
            users = conn.execute("SELECT COUNT(*) FROM users").fetchone()
            result["user_count"] = users[0]
            
            # Get User List
            user_list = conn.execute("SELECT username, email, password_hash FROM users").fetchall()
            result["users"] = [{"username": u[0], "email": u[1], "password_hash": u[2]} for u in user_list]
            
            conn.close()
        except Exception as e:
            result["error"] = str(e)
    
    return result

@app.route("/debug/status")
def debug_status():
    import os
    import sqlite3
    
    result = {}
    
    # check database
    if os.path.exists('users.db'):
        conn = sqlite3.connect('users.db')
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        user_list = conn.execute("SELECT username, created_at FROM users ORDER BY created_at DESC LIMIT 5").fetchall()
        
        result.update({
            "database_exists": True,
            "user_count": users[0],
            "recent_users": [{"username": u[0], "created_at": u[1]} for u in user_list]
        })
        conn.close()
    else:
        result["database_exists"] = False
    
    return result


@app.route("/api/users", methods=["GET"])
def api_get_users():
    """RESTful API: Get all users"""
    if "user" not in session:
        return jsonify({"success": False, "error": "Authentication required"}), 401
    
    conn = get_db()
    try:
        users = conn.execute(
            "SELECT id, username, email, created_at, last_login, is_active, is_admin, failed_login_attempts FROM users ORDER BY id"
        ).fetchall()
        
        users_list = []
        for user in users:
            users_list.append({
                "id": user["id"],
                "username": user["username"], 
                "email": user["email"],
                "created_at": user["created_at"],
                "last_login": user["last_login"],
                "is_active": bool(user["is_active"]),
                "is_admin": bool(user["is_admin"]),
                "failed_login_attempts": user["failed_login_attempts"]
            })
        
        return jsonify({
            "success": True,
            "data": users_list,
            "count": len(users_list)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()

@app.route("/api/users/<int:user_id>", methods=["GET"])
def api_get_user(user_id):
    """RESTful API: Get specific user by ID"""
    if "user" not in session:
        return jsonify({"success": False, "error": "Authentication required"}), 401
    
    conn = get_db()
    try:
        user = conn.execute(
            "SELECT id, username, email, created_at, last_login, is_active, is_admin, failed_login_attempts FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        return jsonify({
            "success": True,
            "data": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"], 
                "created_at": user["created_at"],
                "last_login": user["last_login"],
                "is_active": bool(user["is_active"]),
                "is_admin": bool(user["is_admin"]),
                "failed_login_attempts": user["failed_login_attempts"]
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()

@app.route("/api/users/<int:user_id>", methods=["PUT"])
def api_update_user(user_id):
    """RESTful API: Update user information"""
    if "user" not in session:
        return jsonify({"success": False, "error": "Authentication required"}), 401
    
    # only admin can revise data
    if not session.get("is_admin", False):
        return jsonify({"success": False, "error": "Admin privileges required"}), 403
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
    except Exception:
        return jsonify({"success": False, "error": "Invalid JSON format"}), 400
    
    conn = get_db()
    try:
        # check if user exist
        user = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        # verify email format
        if "email" in data and not validate_email(data["email"]):
            return jsonify({"success": False, "error": "Invalid email format"}), 400
        
        update_fields = []
        update_values = []
        
        if "username" in data:
            update_fields.append("username = ?")
            update_values.append(clean_input(data["username"]))
        
        if "email" in data:
            update_fields.append("email = ?")
            update_values.append(clean_input(data["email"]))
        
        if "is_active" in data:
            update_fields.append("is_active = ?")
            update_values.append(bool(data["is_active"]))
        
        if "is_admin" in data:
            update_fields.append("is_admin = ?")
            update_values.append(bool(data["is_admin"]))
        
        if update_fields:
            update_values.append(user_id)
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
            conn.execute(query, update_values)
            conn.commit()
            
            # record
            add_audit_log(session.get("user_id"), 'USER_UPDATED', 
                         request.remote_addr or '127.0.0.1', f"Updated user ID: {user_id}")
        
        return jsonify({"success": True, "message": "User updated successfully"})
    
    except sqlite3.IntegrityError as e:
        error_msg = str(e).lower()
        if 'username' in error_msg:
            return jsonify({"success": False, "error": "Username already exists"}), 400
        elif 'email' in error_msg:
            return jsonify({"success": False, "error": "Email already exists"}), 400
        else:
            return jsonify({"success": False, "error": "Database constraint violation"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def api_delete_user(user_id):
    """RESTful API: Delete user"""
    if "user" not in session:
        return jsonify({"success": False, "error": "Authentication required"}), 401
    
    # only admin can delete data
    if not session.get("is_admin", False):
        return jsonify({"success": False, "error": "Admin privileges required"}), 403
    
    conn = get_db()
    try:
        user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        
        if user_id == session.get("user_id"):
            return jsonify({"success": False, "error": "Cannot delete your own account"}), 400
        
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        
        add_audit_log(session.get("user_id"), 'USER_DELETED', 
                     request.remote_addr or '127.0.0.1', f"Deleted user: {user['username']}")
        
        return jsonify({"success": True, "message": "User deleted successfully"})
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        conn.close()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)