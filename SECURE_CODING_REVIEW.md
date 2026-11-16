# Secure Coding Review — NotesApp (Flask + SQLite)

| Field | Detail |
|---|---|
| **Application reviewed** | `notesapp` — a small Flask + SQLite notes web app (`app.py`, ~295 lines) |
| **Language / stack** | Python 3, Flask 3.x, SQLite 3 |
| **Review date** | 15 November 2026 |
| **Reviewer** | Akash Kumar (CodeAlpha Cyber Security Internship — Task 3) |
| **Review method** | Manual source-code inspection (line-by-line) + black-box verification of the running app. Static analysis with Bandit was also run as a cross-check (see §6). |
| **Scope** | All routes, authentication, session handling, database access, output rendering, logging and deployment settings in `app.py` |
| **Note** | This application was written **intentionally vulnerable** as a teaching aid. The flaws below are planted on purpose — the app must never be deployed or pointed at real user data. |

---

## 1. Executive summary

The review found **9 security findings**: **2 Critical, 4 High, 2 Medium and 1 Low**.

The most serious problems are an **SQL injection in the login form** (F-01) and a **completely unprotected admin page** (F-02) — either one alone lets an unauthenticated attacker take over accounts or read every user's password hash. Stored cross-site scripting (F-03), unsalted MD5 password hashing (F-04), a hardcoded session secret (F-05) and missing ownership checks on notes (F-06) are all High severity and straightforward to exploit. The remaining findings (sensitive data in logs, debug mode, missing security headers) are lower severity but still need fixing before any real use.

Every finding below includes the exact file and line, the vulnerable code, the real-world impact, a working proof of concept, and a concrete fix with corrected code. **None of the fixes have been applied to `app.py`** — the app stays vulnerable on purpose so the flaws can be demonstrated; the fixes live in this report.

---

## 2. Summary of findings

| ID | Finding | Severity | CWE | OWASP Top 10 (2021) | Location |
|---|---|---|---|---|---|
| F-01 | SQL injection in login query | **Critical** | CWE-89 | A03 Injection | `app.py:199–202` |
| F-02 | Missing authentication on `/admin` | **Critical** | CWE-862 | A01 Broken Access Control | `app.py:273–275` |
| F-03 | Stored cross-site scripting (XSS) in notes | **High** | CWE-79 | A03 Injection | `app.py:143` |
| F-04 | Weak password hashing — unsalted MD5 | **High** | CWE-916 | A02 Cryptographic Failures | `app.py:174, 196` |
| F-05 | Hardcoded Flask secret key | **High** | CWE-798 | A02 / A07 | `app.py:41` |
| F-06 | Insecure direct object reference (IDOR) on notes | **High** | CWE-639 | A01 Broken Access Control | `app.py:251–258, 265–268` |
| F-07 | Sensitive data (plaintext password) written to logs | **Medium** | CWE-532 | A09 Logging Failures | `app.py:206` |
| F-08 | Debug mode enabled + tracebacks sent to the browser | **Medium** | CWE-489 / CWE-215 | A05 Misconfiguration | `app.py:287, 294` |
| F-09 | Missing security headers | **Low** | CWE-693 | A05 Misconfiguration | `app.py` (whole file) |

---

## 3. Detailed findings

### F-01 — SQL injection in the login query

- **Severity:** Critical
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **OWASP:** A03:2021 — Injection
- **Location:** `app.py:199–202` (`login()`)

**Vulnerable code:**

```python
# app.py:199-202
query = (
    f"SELECT * FROM users WHERE username = '{username}' "
    f"AND password_hash = '{pw_hash}'"
)
user = db.execute(query).fetchone()
```

The username (and the derived hash) are pasted directly into the SQL string with an f-string. There is no parameterisation and no escaping, so an attacker controls the structure of the query, not just its values.

**Impact:** Full authentication bypass and data theft. An attacker can log in as any user without knowing the password, and can extend the injection to dump the whole `users` table (usernames + password hashes) or the `notes` table.

**Proof of concept (verified against the running app):**

Log in with username `' OR '1'='1' -- ` and any password. The query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password_hash = '...'
```

The `--` comments out the password check, `'1'='1'` is always true, and the first user row is returned — the attacker is logged in as that user. Verified: the test login returned a redirect to `/notes` (authenticated).

**Remediation — use parameterised queries (placeholders), never string formatting:**

```python
# FIXED
user = db.execute(
    "SELECT * FROM users WHERE username = ? AND password_hash = ?",
    (username, pw_hash),
).fetchone()
```

With placeholders, the database treats the input as data only — quote characters in the username can no longer change the query. Apply the same rule everywhere a query is built; note that `register()`, `add_note()` and the note queries already use placeholders correctly, so only `login()` needs this fix.

---

### F-02 — Missing authentication on the `/admin` route

- **Severity:** Critical
- **CWE:** CWE-862 (Missing Authorization)
- **OWASP:** A01:2021 — Broken Access Control
- **Location:** `app.py:273–275` (`admin()`)

**Vulnerable code:**

```python
# app.py:273-275
@app.route("/admin")
def admin():
    # F-02: No authentication at all — anyone can open /admin.
    db = get_db()
    users = db.execute(
        "SELECT id, username, password_hash FROM users"
    ).fetchall()
```

Every other protected route uses the `@login_required` decorator, but `/admin` does not — and it does not even check for an admin role. It also dumps every user's password hash (see F-04), which makes the leak worse.

**Impact:** Anyone on the internet can open `http://host:5000/admin` with no login at all and read the full user list, including password hashes. Combined with the weak MD5 hashing (F-04), those hashes are quick to crack offline, giving the attacker real passwords.

**Proof of concept (verified):** `GET /admin` with a fresh, unauthenticated session returned HTTP 200 and the page contained the registered username `alice`.

**Remediation — require login AND an admin role:**

```python
# FIXED
from functools import wraps

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session or not session.get("is_admin"):
            return "Forbidden", 403
        return view(*args, **kwargs)
    return wrapped

@app.route("/admin")
@login_required
@admin_required
def admin():
    db = get_db()
    # FIXED: never show password hashes, even to an admin.
    users = db.execute("SELECT id, username FROM users").fetchall()
    ...
```

Also add an `is_admin` column to the `users` table (default `0`) and set it only for a real administrator. As a rule: **every route must declare its access requirement** — no route should be reachable by default.

---

### F-03 — Stored cross-site scripting (XSS) in notes

- **Severity:** High
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **OWASP:** A03:2021 — Injection
- **Location:** `app.py:143` (`NOTE_TEMPLATE`)

**Vulnerable code:**

```html
<!-- app.py:143 -->
<div>{{ note.content | safe }}</div>
```

The `| safe` filter tells Jinja2 **not** to escape the note content, so any HTML or JavaScript a user saves in a note is rendered as live code in every other user's browser when they open that note. Because notes are stored in the database, the payload persists — this is *stored* XSS.

**Impact:** An attacker saves a note containing `<script>…</script>` (or an `<img onerror=…>` payload). When a victim opens the note, the script runs in the victim's session and can steal their session cookie, read their notes, or perform actions as them (e.g. delete notes, change data). The victim only has to open a shared note — no click on a suspicious link is needed.

**Proof of concept (verified):** A note saved with content `<script>alert(1)</script>` was returned byte-for-byte in the HTML of `/note/1` — the script tag was not escaped.

**Remediation — remove `| safe` and let Jinja2 escape by default:**

```html
<!-- FIXED -->
<div>{{ note.content }}</div>
```

Jinja2 auto-escapes `{{ ... }}` output, turning `<script>` into harmless `&lt;script&gt;` text. Only mark content as safe if it was produced by a trusted sanitizer (e.g. `bleach.clean()` with an allow-list) — never for raw user input. The same applies to `{{ body | safe }}` in the base template: only pass it HTML the server itself generated.

---

### F-04 — Weak password hashing: unsalted MD5

- **Severity:** High
- **CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **OWASP:** A02:2021 — Cryptographic Failures
- **Location:** `app.py:174` (`register()`) and `app.py:196` (`login()`)

**Vulnerable code:**

```python
# app.py:174 and app.py:196
pw_hash = hashlib.md5(password.encode()).hexdigest()
```

MD5 is a fast, unsalted general-purpose hash — not a password hash. It was designed for checksums, not for protecting credentials.

**Impact:** MD5 is so fast that a single modern GPU can try tens of billions of MD5 hashes per second. Common passwords are cracked in seconds, and because there is no salt, identical passwords produce identical hashes and precomputed rainbow tables work against the whole database at once. Once the hashes leak (which F-02 makes trivial), most user passwords fall quickly.

**Remediation — use a slow, salted password hash (bcrypt / Argon2):**

```python
# FIXED — needs: pip install bcrypt
import bcrypt

# On registration:
pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# On login:
stored = user["password_hash"]
if not bcrypt.checkpw(password.encode(), stored.encode()):
    # invalid credentials
    ...
```

bcrypt (or Argon2id via `argon2-cffi`) is deliberately slow and generates a unique random salt per password, so rainbow tables are useless and brute force is expensive. Store the resulting hash string (it already embeds the salt and cost). **Never use MD5, SHA-1 or plain SHA-256 for passwords**, and never store passwords in plaintext.

---

### F-05 — Hardcoded Flask secret key

- **Severity:** High
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **OWASP:** A02:2021 — Cryptographic Failures
- **Location:** `app.py:41`

**Vulnerable code:**

```python
# app.py:41
app.secret_key = "supersecret123"
```

Flask signs the session cookie with this key. Because the key is written in the source code, anyone who can read the repository (or a leaked copy of the file) knows it.

**Impact:** With the secret key, an attacker can forge a valid session cookie for any user — including an admin — without ever logging in. Tools like `flask-unsign` make this a one-command attack. The hardcoded key also means every deployment of the app shares the same key, so one leak compromises all of them.

**Remediation — load the secret from the environment, with a strong random value:**

```python
# FIXED
import os
import secrets

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
```

Generate the production value once (`python -c "import secrets; print(secrets.token_hex(32))"`), store it as an environment variable on the server (or in a secrets manager), and **never commit it to git**. Rotate the key if it is ever exposed. Add `.env` / secrets files to `.gitignore`.

---

### F-06 — Insecure direct object reference (IDOR) on notes

- **Severity:** High
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **OWASP:** A01:2021 — Broken Access Control
- **Location:** `app.py:251–258` (`view_note()`) and `app.py:265–268` (`delete_note()`)

**Vulnerable code:**

```python
# app.py:253-258 — view
note = db.execute(
    "SELECT * FROM notes WHERE id = ?", (note_id,)
).fetchone()
if note is None:
    return "Note not found", 404
# ...no check that note["user_id"] == session["user_id"]...

# app.py:268 — delete
db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
```

Both routes check that the user is *logged in*, but never check that the note *belongs to them*. The note id comes straight from the URL, so any user can change the number and access someone else's note.

**Impact:** Any logged-in user can read, and delete, any other user's private notes simply by guessing or incrementing the id (`/note/1`, `/note/2`, …). Private data leaks and data loss follow with no exploit skill required.

**Proof of concept (verified):** User `bob` registered and logged in, then opened `/note/1` — a note owned by `alice` — and received HTTP 200 with alice's note content.

**Remediation — enforce ownership in the query itself:**

```python
# FIXED — view
note = db.execute(
    "SELECT * FROM notes WHERE id = ? AND user_id = ?",
    (note_id, session["user_id"]),
).fetchone()
if note is None:
    return "Note not found", 404

# FIXED — delete
cur = db.execute(
    "DELETE FROM notes WHERE id = ? AND user_id = ?",
    (note_id, session["user_id"]),
)
db.commit()
if cur.rowcount == 0:
    return "Note not found", 404
```

Filtering by `user_id` in the SQL makes the ownership check impossible to forget on any single route. General rule: **never trust an id from the URL — always verify the current user is allowed to touch that object.**

---

### F-07 — Sensitive data (plaintext password) written to logs

- **Severity:** Medium
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **OWASP:** A09:2021 — Security Logging and Monitoring Failures
- **Location:** `app.py:206` (`login()`)

**Vulnerable code:**

```python
# app.py:206
logger.info("Login failed for user=%s password=%s", username, password)
```

Every failed login writes the password the user just typed — in plaintext — to the application log.

**Impact:** Passwords end up in log files, which are often less protected than the database: they get shipped to log aggregators, backed up, pasted into support tickets, or read by anyone with server access. A user who mistypes their *real* password (or a password they reuse elsewhere) has now leaked it into a log. Log files also tend to live far longer than intended.

**Remediation — log the event, never the secret:**

```python
# FIXED
logger.warning("Login failed for user=%s", username)
```

Log *that* a login failed, the username, the time and the source IP if useful — but never a password, token, session id or other credential. The same rule applies to error messages shown to users and to exception tracebacks.

---

### F-08 — Debug mode enabled, and tracebacks sent to the browser

- **Severity:** Medium
- **CWE:** CWE-489 (Active Debug Code) / CWE-215 (Insertion of Sensitive Information Into Debugging Code)
- **OWASP:** A05:2021 — Security Misconfiguration
- **Location:** `app.py:294` (`app.run(debug=True)`) and `app.py:287` (500 handler)

**Vulnerable code:**

```python
# app.py:294
app.run(debug=True)

# app.py:287
return "<h1>Server error</h1><pre>" + traceback.format_exc() + "</pre>", 500
```

Flask's debug mode enables the interactive Werkzeug debugger and the reloader. The custom 500 handler additionally returns a full Python traceback to the browser.

**Impact:** The Werkzeug debugger in debug mode allows **remote code execution** — anyone who triggers an error can open the debugger console in the browser and run Python on the server (it is protected only by a PIN printed in the server log, which is often visible or guessable in shared environments). Even without the debugger, full tracebacks disclose file paths, installed package versions, variable values and internal logic that help an attacker plan the next step.

**Remediation — disable debug mode outside local development, and show a generic error page:**

```python
# FIXED
import os

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")  # never True in production

@app.errorhandler(500)
def handle_500(error):
    # FIXED: log the traceback server-side only; show users a generic page.
    logger.exception("Internal server error")
    return "Something went wrong. Please try again later.", 500
```

Keep `debug=True` only while developing on your own machine, and never expose a debug server to a network.

---

### F-09 — Missing security headers

- **Severity:** Low
- **CWE:** CWE-693 (Protection Mechanism Failure)
- **OWASP:** A05:2021 — Security Misconfiguration
- **Location:** `app.py` (whole file — no security headers are set anywhere)

**Vulnerable code:** There is no `@app.after_request` handler and no header configuration at all, so responses carry none of the standard protective headers.

**Impact:** Missing headers remove cheap, defence-in-depth protections:
- No `Content-Security-Policy` — the browser has no restriction on where scripts can load from, which makes XSS (F-03) easier to exploit.
- No `X-Content-Type-Options: nosniff` — browsers may guess content types and execute a file as script.
- No `X-Frame-Options` / `frame-ancestors` — the site can be embedded in a hidden iframe for clickjacking.
- No `Strict-Transport-Security` — no forced HTTPS (matters once the app is served over TLS).

**Remediation — set the headers on every response:**

```python
# FIXED
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # Only once the app is served over HTTPS:
    # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
```

Headers are not a substitute for fixing the underlying flaws, but they reduce the damage when a flaw is missed.

---

## 4. How the review was done

1. **Manual inspection (primary method).** Read `app.py` end to end (~295 lines): every route, every SQL statement, every template, the session/auth logic, logging and the run configuration. Each finding was traced from the user-controlled input (form field, URL id) to the place it is used unsafely (query, template, log line).
2. **Black-box verification.** Ran the app (Flask 3.1.3, Python 3.12) and confirmed the four exploitable findings against the live server:
   - SQL injection login bypass with `' OR '1'='1' -- ` → logged in without a password.
   - Stored XSS: a note containing `<script>alert(1)</script>` was returned unescaped.
   - `/admin` returned HTTP 200 with no login at all.
   - IDOR: user `bob` read user `alice`'s note at `/note/1`.
   All 8 automated smoke checks passed (see `README.md` → Testing).
3. **Static analysis (cross-check).** Bandit, a Python security linter, was run over the app (`pip install bandit && bandit -r app.py`) and found **5 issues that match the manual findings**: hardcoded password string `B105` at line 41 (F-05), weak MD5 hash `B324` at lines 174 and 196 (F-04), possible SQL injection `B608` at line 200 (F-01), and Flask debug mode `B201` at line 294 (F-08). Bandit does **not** catch the XSS, IDOR, missing-auth, logging or header issues — which is exactly why manual inspection was the primary method and the tool output is only a cross-check.

---

## 5. Secure-coding best practices (checklist)

Use this as a checklist for the next project, and for fixing this one:

| # | Practice | Why it matters |
|---|---|---|
| 1 | **Always use parameterised queries** (`?` placeholders) | Stops SQL injection entirely — input can never change the query |
| 2 | **Escape output by default; never use `\| safe` on user data** | Stops stored and reflected XSS |
| 3 | **Hash passwords with bcrypt / Argon2id (salted, slow)** | Makes stolen hashes expensive to crack; kills rainbow tables |
| 4 | **Keep secrets out of source code** (environment variables / secrets manager) | A leaked repo must not mean leaked credentials or forged sessions |
| 5 | **Check authorisation on every route, and ownership on every object id** | Login ≠ permission; an id in the URL is user input |
| 6 | **Never log passwords, tokens or session ids** | Logs are copied, backed up and read more widely than the database |
| 7 | **Disable debug mode in production; generic error pages only** | Debuggers and tracebacks hand attackers code execution and internals |
| 8 | **Set security headers on every response** | Cheap defence-in-depth (CSP, nosniff, frame options, HSTS) |
| 9 | **Validate and limit input** (types, lengths, allow-lists) | Reduces the attack surface before data reaches queries or templates |
| 10 | **Keep dependencies updated and run a scanner (Bandit / pip-audit) in CI** | Catches known-vulnerable libraries and the common flaw patterns early |

---

## 6. References

- OWASP Top 10 (2021) — https://owasp.org/www-project-top-ten/
- OWASP Cheat Sheet Series (SQL Injection Prevention, XSS Prevention, Password Storage, Authorization) — https://cheatsheetseries.owasp.org/
- CWE-89 (SQL Injection), CWE-79 (XSS), CWE-916 (Weak Password Hash), CWE-798 (Hard-coded Credentials), CWE-639 (IDOR), CWE-862 (Missing Authorization), CWE-532 (Sensitive Data in Logs), CWE-489 (Debug Code), CWE-693 (Missing Security Headers) — https://cwe.mitre.org/
- Flask security docs — https://flask.palletsprojects.com/en/stable/security/
- Bandit (Python security linter) — https://bandit.readthedocs.io/
