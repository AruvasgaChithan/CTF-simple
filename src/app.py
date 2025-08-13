from flask import Flask, render_template, request, session, redirect, url_for, flash, send_from_directory
import os
import sqlite3
import subprocess
from datetime import datetime

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), '../templates'),
    static_folder=os.path.join(os.path.dirname(__file__), '../static')
)

app.secret_key = "super_secret_key"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLAGS_DIR = os.path.join(BASE_DIR, "flags")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "vuln.db")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ----------------------- helpers -----------------------

def load_flag(filename):
    try:
        with open(os.path.join(FLAGS_DIR, filename), "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "FLAG_NOT_FOUND"


def init_scores():
    if "scores" not in session:
        session["scores"] = {}
    if "total_score" not in session:
        session["total_score"] = 0


def award(challenge_name, flag_file):
    """Award points + flash flag if not already solved."""
    if not session["scores"].get(challenge_name, False):
        session["scores"][challenge_name] = True
        session["total_score"] += 100
    flash(f"Flag: {load_flag(flag_file)}", "success")


@app.route('/reset')
def reset():
    global solved_challenges
    solved_challenges.clear()
    # Optional: reset DB here too
    return "All challenges reset!"

# Ensure database exists at startup
def ensure_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    cur.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'supersecret')")
    conn.commit()
    conn.close()

# Create DB at startup
ensure_db()


def setup():
    ensure_db()


@app.context_processor
def inject_nav():
    return dict(total_score=session.get("total_score", 0))


# ----------------------- routes -----------------------

@app.route("/")
def index():
    init_scores()
    challenges = [
        {"name": "SQL Injection", "category": "Web Exploitation", "points": 100, "route": "sqli", "solved": session["scores"].get("SQL Injection", False)},
        {"name": "Cross-Site Scripting", "category": "Web Exploitation", "points": 100, "route": "xss", "solved": session["scores"].get("Cross-Site Scripting", False)},
        {"name": "Command Injection", "category": "Web Exploitation", "points": 100, "route": "cmd", "solved": session["scores"].get("Command Injection", False)},
        {"name": "Insecure File Upload", "category": "Web Exploitation", "points": 100, "route": "upload", "solved": session["scores"].get("Insecure File Upload", False)},
    ]
    return render_template("index.html", challenges=challenges)


# -------- SQL Injection (real vulnerable login bypass -> flag) --------
@app.route("/sqli", methods=["GET", "POST"])
def sqli():
    init_scores()
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        try:
            # INTENTIONALLY VULNERABLE: interpolate both username and password
            query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
            cur.execute(query)
            rows = cur.fetchall()
            result = f"Executed query: {query}<br>Result: {rows}"

            # If SQLi returns any rows → award flag
            if rows:
                award("SQL Injection", "flag1.txt")
        except Exception as e:
            result = f"SQL error: {e}"
        finally:
            conn.close()

    return render_template("sqli.html", result=result)

# -------- XSS (reflected; JS beacon awards flag) --------
@app.route("/xss", methods=["GET", "POST"])
def xss():
    init_scores()
    comment = None
    if request.method == "POST":
        # Store what user posts and reflect it UNSANITIZED in template (|safe in HTML)
        comment = request.form.get("comment", "")
    return render_template("xss.html", comment=comment)


@app.route("/xss/solve", methods=["GET"])
def xss_solve():
    # This endpoint is meant to be called by JS from an injected payload (beacon).
    init_scores()
    award("Cross-Site Scripting", "flag2.txt")
    # Return a tiny OK so fetch() doesn't error
    return ("OK", 200)


# -------- Command Injection (left as-is) --------
@app.route("/cmd", methods=["GET", "POST"])
def cmd():
    init_scores()
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        try:
            # VULNERABLE: passing user input directly to shell
            output = subprocess.check_output(host, shell=True, stderr=subprocess.STDOUT, timeout=3).decode()
            # (Flag logic unchanged per your request; keep your previous behavior/triggers here if any)
        except subprocess.CalledProcessError as e:
            output = e.output.decode()
        except Exception as e:
            output = str(e)
    return render_template("cmd.html", output=output)


# -------- Insecure File Upload (flag when served) --------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    init_scores()
    link = None
    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename:
            # No validation at all: path join, overwrite allowed
            save_as = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            filepath = os.path.join(UPLOAD_FOLDER, save_as)
            file.save(filepath)
            link = url_for("serve_upload", filename=save_as)
            flash(f"Uploaded. Access it here: <a href='{link}' class='link-light'>{link}</a>", "info")
    return render_template("upload.html", link=link)


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    # Award the flag the first time a user accesses their uploaded file.
    init_scores()
    # Use a simple per-file session marker to avoid spamming points
    key = f"seen_upload::{filename}"
    if not session.get(key):
        session[key] = True
        award("Insecure File Upload", "flag4.txt")
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)


# -------- Submit Flag (optional alternate path) --------
@app.route("/submit", methods=["GET", "POST"])
def submit():
    init_scores()
    if request.method == "POST":
        submitted_flag = request.form.get("flag", "").strip()
        flags = {
            "SQL Injection": load_flag("flag1.txt"),
            "Cross-Site Scripting": load_flag("flag2.txt"),
            "Command Injection": load_flag("flag3.txt"),
            "Insecure File Upload": load_flag("flag4.txt"),
        }
        matched = None
        for chall, flag in flags.items():
            if submitted_flag == flag:
                matched = chall
                break
        if matched:
            award(matched, f"flag{['SQL Injection','Cross-Site Scripting','Command Injection','Insecure File Upload'].index(matched)+1}.txt")
            flash(f"Correct flag for {matched}!", "success")
        else:
            flash("Incorrect flag!", "danger")
    return render_template("submit.html")


if __name__ == "__main__":
    # 0.0.0.0:80 to match your Docker run -p 8080:80 mapping
    app.run(host="0.0.0.0", port=80, debug=True)
