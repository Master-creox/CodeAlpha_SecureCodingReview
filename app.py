"""
notesapp — a deliberately VULNERABLE Flask + SQLite notes application.

CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review.

WARNING: This app is intentionally insecure. It is a teaching aid for
learning how to find and fix common web vulnerabilities. NEVER deploy it,
never point it at real user data, and run it only on your own machine
(localhost) while reviewing it.

Vulnerabilities planted (full audit in SECURE_CODING_REVIEW.md):
  F-01  SQL injection in the login query             (Critical)
  F-02  No authentication on the /admin route        (Critical)
  F-03  Stored cross-site scripting (XSS) in notes   (High)
  F-04  Weak password hashing — unsalted MD5         (High)
  F-05  Hardcoded Flask secret key                   (High)
  F-06  Insecure direct object reference (IDOR)      (High)
  F-07  Sensitive data written to logs               (Medium)
  F-08  Debug mode enabled                           (Medium)
  F-09  Missing security headers                     (Low)
"""

import hashlib
import logging
import sqlite3
import traceback

from flask import (
    Flask,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

app = Flask(__name__)

# F-05: Hardcoded secret key. Anyone who reads this file can forge sessions.
app.secret_key = "supersecret123"

DATABASE = "notes.db"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("notesapp")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def login_required(view):
    """Simple login guard used on most routes — but NOT on /admin (F-02)."""
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# ---------------------------------------------------------------------------
# Templates (kept inline so the whole app is one file)
# ---------------------------------------------------------------------------
BASE = """
<!doctype html>
<html>
<head><title>NotesApp</title></head>
<body>
  <h1>NotesApp</h1>
  {% if session.get('username') %}
    <p>Logged in as {{ session['username'] }} |
       <a href="/notes">My notes</a> | <a href="/logout">Logout</a></p>
  {% else %}
    <p><a href="/login">Login</a> | <a href="/register">Register</a></p>
  {% endif %}
  <hr>
  {{ body | safe }}
</body>
</html>
"""

FORM_TEMPLATE = """
<h2>{{ heading }}</h2>
<form method="post">
  <input name="username" placeholder="Username" required><br><br>
  <input name="password" type="password" placeholder="Password" required><br><br>
  <button type="submit">{{ button }}</button>
</form>
"""

NOTES_TEMPLATE = """
<h2>My notes</h2>
<form method="post" action="/notes/add">
  <input name="title" placeholder="Title" required><br><br>
  <textarea name="content" placeholder="Write a note..." required></textarea><br>
  <button type="submit">Add note</button>
</form>
<ul>
{% for note in notes %}
  <li><a href="/note/{{ note.id }}">{{ note.title }}</a></li>
{% endfor %}
</ul>
"""

NOTE_TEMPLATE = """
<h2>{{ note.title }}</h2>
<div>{{ note.content | safe }}</div>
<form method="post" action="/note/{{ note.id }}/delete">
  <button type="submit">Delete this note</button>
</form>
"""

ADMIN_TEMPLATE = """
<h2>Admin — all users</h2>
<table border="1">
  <tr><th>ID</th><th>Username</th><th>Password hash</th></tr>
{% for user in users %}
  <tr><td>{{ user.id }}</td><td>{{ user.username }}</td><td>{{ user.password_hash }}</td></tr>
{% endfor %}
</table>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("notes"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # F-04: Weak password hashing — fast, unsalted MD5.
        pw_hash = hashlib.md5(password.encode()).hexdigest()
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return render_template_string(BASE, body="<p>Username already taken.</p>")
        return redirect(url_for("login"))
    body = render_template_string(
        FORM_TEMPLATE, heading="Register", button="Create account"
    )
    return render_template_string(BASE, body=body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        pw_hash = hashlib.md5(password.encode()).hexdigest()
        db = get_db()
        # F-01: SQL injection — user input is pasted straight into the query.
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password_hash = '{pw_hash}'"
        )
        user = db.execute(query).fetchone()
        if user is None:
            # F-07: The plaintext password is written to the log file.
            logger.info("Login failed for user=%s password=%s", username, password)
            return render_template_string(BASE, body="<p>Invalid credentials.</p>")
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("notes"))
    body = render_template_string(
        FORM_TEMPLATE, heading="Login", button="Log in"
    )
    return render_template_string(BASE, body=body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/notes")
@login_required
def notes():
    db = get_db()
    rows = db.execute(
        "SELECT id, title FROM notes WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    body = render_template_string(NOTES_TEMPLATE, notes=rows)
    return render_template_string(BASE, body=body)


@app.route("/notes/add", methods=["POST"])
@login_required
def add_note():
    title = request.form["title"]
    content = request.form["content"]
    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (session["user_id"], title, content),
    )
    db.commit()
    return redirect(url_for("notes"))


@app.route("/note/<int:note_id>")
@login_required
def view_note(note_id):
    db = get_db()
    note = db.execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if note is None:
        return "Note not found", 404
    # F-06: IDOR — no check that this note belongs to the logged-in user.
    body = render_template_string(NOTE_TEMPLATE, note=note)
    return render_template_string(BASE, body=body)


@app.route("/note/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    db = get_db()
    # F-06: IDOR — deletes any note by id, regardless of who owns it.
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return redirect(url_for("notes"))


@app.route("/admin")
def admin():
    # F-02: No authentication at all — anyone can open /admin.
    db = get_db()
    users = db.execute(
        "SELECT id, username, password_hash FROM users"
    ).fetchall()
    body = render_template_string(ADMIN_TEMPLATE, users=users)
    return render_template_string(BASE, body=body)


@app.errorhandler(500)
def handle_500(error):
    # F-08 (part): the full traceback is sent to the browser.
    return "<h1>Server error</h1><pre>" + traceback.format_exc() + "</pre>", 500


if __name__ == "__main__":
    with app.app_context():
        init_db()
    # F-08: Debug mode enabled — interactive debugger + reloader in production.
    app.run(debug=True)
