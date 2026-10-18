import os
import sqlite3
from urllib.parse import urlparse, unquote
import pg8000
from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, jsonify
)
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

load_dotenv()

app = Flask(__name__)
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "SECRET_KEY is missing. Set it in the environment or .env file."
    )
app.config["SECRET_KEY"] = secret_key
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "false").lower()
    in ("1", "true", "yes")
)
csrf = CSRFProtect(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "nscen.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

PROJECT_STATUSES = ["Planning", "In Progress", "Completed", "On Hold"]
TASK_STATUSES = ["Pending", "In Progress", "Completed"]

class PGRow(dict):
    pass

class PGCursor:
    def __init__(self, cursor):
        self.cursor = cursor

    @property
    def rowcount(self):
        return self.cursor.rowcount

    def execute(self, sql, params=()):
        self.cursor.execute(sql.replace("?", "%s"), params)
        return self

    def _row(self, values):
        if values is None:
            return None
        columns = [col[0] for col in self.cursor.description]
        return PGRow(zip(columns, values))

    def fetchone(self):
        return self._row(self.cursor.fetchone())

    def fetchall(self):
        return [self._row(row) for row in self.cursor.fetchall()]

class PGConnection:
    def __init__(self):
        parsed = urlparse(DATABASE_URL)
        self.conn = pg8000.connect(
            host=parsed.hostname,
            port=parsed.port or 5432,
            database=parsed.path.lstrip("/"),
            user=unquote(parsed.username or ""),
            password=unquote(parsed.password or ""),
            ssl_context=True,
            timeout=15,
        )

    def execute(self, sql, params=()):
        return PGCursor(self.conn.cursor()).execute(sql, params)

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()
        return False

def get_db():
    if DATABASE_URL:
        return PGConnection()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "error"


class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = str(user_id)
        self.username = username


def init_auth_db():
    if DATABASE_URL:
        # The PostgreSQL users table was created during migration.
        return

    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)


@login_manager.user_loader
def load_user(user_id):
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username FROM users WHERE id = ?",
                (int(user_id),)
            ).fetchone()
        if row:
            return User(row["id"], row["username"])
    except Exception:
        return None
    return None


init_auth_db()
login_manager.init_app(app)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT id, username, password_hash "
                "FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            login_user(User(user["id"], user["username"]))
            return redirect(url_for("dashboard"))

        flash("Username or password is incorrect.", "error")

    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def dashboard():
    with get_db() as conn:
        clients = conn.execute(
            "SELECT * FROM clients ORDER BY id DESC"
        ).fetchall()

        projects = conn.execute("""
            SELECT projects.*, clients.name AS client_name
            FROM projects
            LEFT JOIN clients ON projects.client_id = clients.id
            ORDER BY projects.id DESC
        """).fetchall()

        tasks = conn.execute("""
            SELECT tasks.*, projects.name AS project_name
            FROM tasks
            JOIN projects ON tasks.project_id = projects.id
            ORDER BY tasks.id DESC
        """).fetchall()

    return render_template(
        "index.html",
        clients=clients,
        projects=projects,
        project_statuses=PROJECT_STATUSES,
        tasks=tasks,
        task_statuses=TASK_STATUSES
    )


@app.post("/clients/add")
@login_required
def add_client():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    company = request.form.get("company", "").strip()

    if not name:
        flash("Client name is required.", "error")
        return redirect(url_for("dashboard"))

    if len(name) > 120 or len(email) > 254:
        flash("Name or email is too long.", "error")
        return redirect(url_for("dashboard"))

    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO clients (name, email, phone, company)
                VALUES (?, ?, ?, ?)
            """, (name, email, phone, company))
        flash("Client saved successfully.", "success")
    except Exception:
        app.logger.exception("Could not save client")
        flash("Could not save client.", "error")

    return redirect(url_for("dashboard"))


@app.post("/projects/add")
@login_required
def add_project():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    client_value = request.form.get("client_id", "").strip()
    status = request.form.get("status", "Planning").strip()
    budget_value = request.form.get("budget", "0").strip()
    deadline = request.form.get("deadline", "").strip()

    if not name or len(name) > 160:
        flash("Project name is required (maximum 160 characters).", "error")
        return redirect(url_for("dashboard"))

    if status not in PROJECT_STATUSES:
        flash("Invalid project status.", "error")
        return redirect(url_for("dashboard"))

    try:
        budget = float(budget_value or 0)
        if budget < 0 or budget > 1_000_000_000_000:
            raise ValueError
    except ValueError:
        flash("Enter a valid non-negative budget.", "error")
        return redirect(url_for("dashboard"))

    try:
        client_id = int(client_value) if client_value else None
        with get_db() as conn:
            if client_id is not None:
                exists = conn.execute(
                    "SELECT id FROM clients WHERE id = ?", (client_id,)
                ).fetchone()
                if not exists:
                    flash("Selected client was not found.", "error")
                    return redirect(url_for("dashboard"))

            conn.execute("""
                INSERT INTO projects
                    (client_id, name, description, status, budget, deadline)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                client_id, name, description, status, budget,
                deadline or None
            ))
        flash("Project saved successfully.", "success")
    except Exception:
        app.logger.exception("Could not save project")
        flash("Could not save project. Check the form and try again.", "error")

    return redirect(url_for("dashboard"))


@app.get("/health")
def health():
    return jsonify({"status": "ok", "app": "NScen Cloud Desk"})




@app.post("/tasks/add")
@login_required
def add_task():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    status = request.form.get("status", "Pending").strip()
    due_date = request.form.get("due_date", "").strip()
    project_id = request.form.get("project_id", type=int)

    if not title or len(title) > 160:
        flash("Task title দিন (সর্বোচ্চ 160 অক্ষর)।", "error")
        return redirect(url_for("dashboard"))

    if status not in TASK_STATUSES:
        flash("Invalid task status.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    project = conn.execute(
        "SELECT id FROM projects WHERE id = ?", (project_id,)
    ).fetchone()

    if not project:
        conn.close()
        flash("আগে একটি valid project নির্বাচন করুন।", "error")
        return redirect(url_for("dashboard"))

    conn.execute(
        """INSERT INTO tasks
           (project_id, title, description, status, due_date)
           VALUES (?, ?, ?, ?, ?)""",
        (project_id, title, description, status, due_date or None),
    )
    conn.commit()
    conn.close()

    flash("Task সফলভাবে যোগ হয়েছে।", "success")
    return redirect(url_for("dashboard"))


@app.post("/tasks/<int:task_id>/status")
@login_required
def update_task_status(task_id):
    status = request.form.get("status", "").strip()

    if status not in TASK_STATUSES:
        flash("Invalid task status.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cursor = conn.execute(
        "UPDATE tasks SET status = ? WHERE id = ?",
        (status, task_id),
    )
    conn.commit()
    updated = cursor.rowcount
    conn.close()

    if updated:
        flash("Task status আপডেট হয়েছে।", "success")
    else:
        flash("Task পাওয়া যায়নি।", "error")

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
