import os
import io
import base64
import sqlite3
import hashlib
import json
from datetime import datetime
from functools import wraps

import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "certificates.db"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-before-production")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        certificate_id TEXT UNIQUE NOT NULL,
        student_name TEXT NOT NULL,
        course TEXT NOT NULL,
        institution TEXT DEFAULT '',
        issue_date TEXT NOT NULL,
        certificate_hash TEXT,
        block_hash TEXT
    );
    CREATE TABLE IF NOT EXISTS blocks (
        block_index INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        certificate_id TEXT NOT NULL,
        certificate_hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        block_hash TEXT NOT NULL
    );
    """)
    # Safely add columns when an older version of this project's database already exists.
    cert_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(certificates)").fetchall()
    }
    for column, definition in (
        ("institution", "TEXT DEFAULT ''"),
        ("certificate_hash", "TEXT"),
        ("block_hash", "TEXT"),
    ):
        if column not in cert_columns:
            conn.execute(f"ALTER TABLE certificates ADD COLUMN {column} {definition}")
    user_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }
    if "password_hash" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    conn.commit()
    # Ensure the chain has a persistent genesis block.
    exists = conn.execute("SELECT 1 FROM blocks WHERE block_index = 0").fetchone()
    if not exists:
        timestamp = "GENESIS"
        data = {"message": "Genesis Block"}
        previous_hash = "0"
        block_hash = hashlib.sha256(
            (str(0) + timestamp + json.dumps(data, sort_keys=True) + previous_hash).encode()
        ).hexdigest()
        conn.execute(
            "INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)",
            (0, timestamp, "", "", previous_hash, block_hash)
        )
        conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def make_block_hash(index, timestamp, certificate_id, certificate_hash, previous_hash):
    data = {"certificate_id": certificate_id, "certificate_hash": certificate_hash}
    text = str(index) + timestamp + json.dumps(data, sort_keys=True) + previous_hash
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def add_block(certificate_id, certificate_hash):
    conn = get_db()
    previous = conn.execute(
        "SELECT * FROM blocks ORDER BY block_index DESC LIMIT 1"
    ).fetchone()
    index = previous["block_index"] + 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    block_hash = make_block_hash(
        index, timestamp, certificate_id, certificate_hash, previous["block_hash"]
    )
    conn.execute(
        "INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)",
        (index, timestamp, certificate_id, certificate_hash, previous["block_hash"], block_hash)
    )
    conn.commit()
    conn.close()
    return block_hash


def verify_chain_and_certificate(certificate_id, certificate_hash):
    conn = get_db()
    blocks = conn.execute("SELECT * FROM blocks ORDER BY block_index").fetchall()
    conn.close()
    if not blocks:
        return False
    if blocks[0]["block_index"] != 0 or blocks[0]["previous_hash"] != "0":
        return False
    for i, block in enumerate(blocks):
        if i > 0 and block["previous_hash"] != blocks[i - 1]["block_hash"]:
            return False
        expected = make_block_hash(
            block["block_index"], block["timestamp"], block["certificate_id"],
            block["certificate_hash"], block["previous_hash"]
        ) if block["block_index"] > 0 else hashlib.sha256(
            (str(0) + "GENESIS" + json.dumps({"message": "Genesis Block"}, sort_keys=True) + "0").encode()
        ).hexdigest()
        if expected != block["block_hash"]:
            return False
    return any(
        b["certificate_id"] == certificate_id and b["certificate_hash"] == certificate_hash
        for b in blocks
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or not password:
            flash("Please fill in every field.")
            return render_template("register.html")
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, generate_password_hash(password))
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("This email is already registered. Please log in.")
            conn.close()
            return render_template("register.html")
        conn.close()
        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("issue"))
        flash("Invalid email or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("index"))


@app.route("/issue", methods=["GET", "POST"])
@login_required
def issue():
    if request.method == "POST":
        student_name = request.form.get("student_name", "").strip()
        course = request.form.get("course", "").strip()
        institution = request.form.get("institution", "").strip()
        if not student_name or not course:
            flash("Student name and course are required.")
            return redirect(url_for("issue"))

        issue_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        certificate_id = "CERT-" + os.urandom(6).hex().upper()
        payload = {
            "certificate_id": certificate_id,
            "student_name": student_name,
            "course": course,
            "institution": institution,
            "issue_date": issue_date,
        }
        certificate_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        block_hash = add_block(certificate_id, certificate_hash)
        conn = get_db()
        try:
            conn.execute("""
                INSERT INTO certificates
                (certificate_id, student_name, course, institution, issue_date, certificate_hash, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                certificate_id, student_name, course, institution,
                issue_date, certificate_hash, block_hash
            ))
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            app.logger.exception("Could not save certificate")
            flash("Certificate could not be saved. Please try again.")
            conn.close()
            return redirect(url_for("issue"))
        conn.close()

        verify_url = url_for("verify", certificate_id=certificate_id, _external=True)
        qr_image = qrcode.make(verify_url)
        buffer = io.BytesIO()
        qr_image.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode("ascii")
        return render_template(
            "result.html",
            certificate_id=certificate_id,
            student_name=student_name,
            course=course,
            institution=institution,
            issue_date=issue_date,
            certificate_hash=certificate_hash,
            block_hash=block_hash,
            qr_code=qr_code,
            verify_url=verify_url,
        )
    return render_template("issue.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    certificate_id = (
        request.form.get("certificate_id", "").strip()
        if request.method == "POST"
        else request.args.get("certificate_id", "").strip()
    )
    certificate = None
    message = None
    valid = False

    if certificate_id:
        conn = get_db()
        certificate = conn.execute(
            "SELECT * FROM certificates WHERE UPPER(certificate_id) = UPPER(?)",
            (certificate_id,)
        ).fetchone()
        conn.close()

        if certificate:
            valid = verify_chain_and_certificate(
                certificate["certificate_id"], certificate["certificate_hash"]
            )
            message = (
                "Certificate verified successfully. Hash and blockchain record are valid."
                if valid else
                "Certificate record found, but blockchain/hash verification failed."
            )
        else:
            message = "Certificate not found. Please enter the exact Certificate ID shown on the result page."

    return render_template(
        "verify.html",
        certificate=certificate,
        certificate_id=certificate_id,
        message=message,
        valid=valid,
    )


@app.route("/blockchain")
def blockchain_view():
    conn = get_db()
    blocks = conn.execute("SELECT * FROM blocks ORDER BY block_index").fetchall()
    conn.close()
    return render_template("blockchain.html", blocks=blocks)


@app.route("/health")
def health():
    return {"status": "ok"}


init_db()

if __name__ == "__main__":
    app.run(debug=True)
