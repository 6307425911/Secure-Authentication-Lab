# Secure-Authentication-Lab
cybersecurity-fundamentals
secure-authentication-lab/
│
├── app.py
├── database.py
├── requirements.txt
├── .gitignore
├── README.md
│
├── templates/
│   ├── index.html
│   ├── register.html
│   └── login.html
│
└── static/
    └── style.css
import os
import sqlite3
import bcrypt
from flask import Flask, request, redirect, session, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "local-dev-only-change-me")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

DB = "users.db"

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL
        )
        """)

@app.route("/")
def home():
    if "user" in session:
        return f"Welcome, {session['user']}!"
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or len(username) > 50:
            return "Invalid username", 400

        if len(password) < 12:
            return "Password must be at least 12 characters", 400

        hashed = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        try:
            with sqlite3.connect(DB) as con:
                con.execute(
                    "INSERT INTO users(username,password_hash) VALUES (?,?)",
                    (username, hashed)
                )
            return redirect("/login")
        except sqlite3.IntegrityError:
            return "Username unavailable", 409

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        with sqlite3.connect(DB) as con:
            row = con.execute(
                "SELECT password_hash FROM users WHERE username=?",
                (username,)
            ).fetchone()

        if row and bcrypt.checkpw(
            password.encode("utf-8"), row[0]
        ):
            session.clear()
            session["user"] = username
            return redirect("/")

        return "Invalid username or password", 401

    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_db()export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
    app.run(host="127.0.0.1", port=5000, debug=False)
