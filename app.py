import os
import sqlite3
import pyotp
import qrcode
import io
import base64
from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default_secret")
DB_PATH = 'users.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

with app.app_context():
    initialize_database()

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        pin = request.form["pin"]
        
        totp_secret = pyotp.random_base32()
        password_hash = generate_password_hash(password)
        pin_hash = generate_password_hash(pin)
        
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password_hash, pin_hash, totp_secret) VALUES (?, ?, ?, ?)",
                         (username, password_hash, pin_hash, totp_secret))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists.")
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
        username = request.form["username"]
        password = request.form["password"]
        pin = request.form["pin"]
        totp_code = request.form["totp"]
        
        conn = get_db()
        try:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            
            if user and check_password_hash(user["password_hash"], password) and \
               check_password_hash(user["pin_hash"], pin):
                totp = pyotp.TOTP(user["totp_secret"])
                if totp.verify(totp_code):
                    session["user"] = username
                    return redirect(url_for("dashboard"))
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
    session.pop("user", None)
    flash("You have been logged out.")
    return redirect(url_for("login"))

@app.route("/admin")
def admin():
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    return render_template("admin.html", users=users)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

