import hashlib
import hmac
import io
import mimetypes
import os
import secrets
import shutil
import sqlite3
import tempfile
import time
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import PurePosixPath

from Crypto.Cipher import DES3
from flask import Flask, jsonify, render_template, request, session, send_file
from werkzeug.utils import secure_filename

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("LOCKER_DB", os.path.join(APP_DIR, "locker.db"))
MOTHER_FOLDER = os.path.abspath(os.environ.get("LOCKER_MOTHER_FOLDER", os.path.join(APP_DIR, "AdminVault")))
ACCOUNT_STORAGE_LIMIT = 100_000_000
ADMIN_USERNAME = "Admin"
ADMIN_BOOTSTRAP_PASSWORD = "Admin2627"
PHILIPPINE_TZ = timezone(timedelta(hours=8))
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "") or secrets.token_hex(32)


@app.after_request
def disable_api_caching(response):
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response

# File keys live only in process memory; a server restart requires users to log in again.
session_keys = {}
session_users = {}


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    os.makedirs(MOTHER_FOLDER, exist_ok=True)
    with db() as con:
        con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, drive_folder TEXT NOT NULL, email TEXT, role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active', suspended_until TEXT, storage_limit_bytes INTEGER NOT NULL DEFAULT 100000000, recovery_hash BLOB, recovery_expires INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        user_columns = {row[1] for row in con.execute("PRAGMA table_info(users)")}
        for column, definition in (
            ("email", "TEXT"),
            ("role", "TEXT NOT NULL DEFAULT 'user'"),
            ("status", "TEXT NOT NULL DEFAULT 'active'"),
            ("suspended_until", "TEXT"),
            ("storage_limit_bytes", "INTEGER NOT NULL DEFAULT 100000000"),
            ("recovery_hash", "BLOB"),
            ("recovery_expires", "INTEGER"),
            ("created_at", "TEXT"),
        ):
            if column not in user_columns:
                con.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        con.execute("UPDATE users SET created_at=COALESCE(created_at,CURRENT_TIMESTAMP)")
        con.execute("CREATE TABLE IF NOT EXISTS activity_logs (id INTEGER PRIMARY KEY, actor_user_id INTEGER, actor_name TEXT, target_user_id INTEGER, target_name TEXT, event TEXT NOT NULL, detail TEXT, ip_address TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        con.execute("CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL, parent_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(parent_id) REFERENCES folders(id), UNIQUE(user_id,parent_id,name))")
        folder_columns = {row[1] for row in con.execute("PRAGMA table_info(folders)")}
        if "disk_name" not in folder_columns:
            con.execute("ALTER TABLE folders ADD COLUMN disk_name TEXT")
        con.execute("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL, drive_id TEXT NOT NULL, iv BLOB NOT NULL, mac BLOB NOT NULL, folder_id INTEGER, storage_bytes INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(folder_id) REFERENCES folders(id))")
        file_columns = {row[1] for row in con.execute("PRAGMA table_info(files)")}
        if "folder_id" not in file_columns:
            con.execute("ALTER TABLE files ADD COLUMN folder_id INTEGER")
        if "storage_bytes" not in file_columns:
            con.execute("ALTER TABLE files ADD COLUMN storage_bytes INTEGER NOT NULL DEFAULT 0")
        # Migrate existing accounts to their local folders if the app was previously
        # configured for Drive or the folder path has changed.
        for user in con.execute("SELECT id, username, drive_folder FROM users").fetchall():
            folder = user_folder(user["username"], user["id"])
            os.makedirs(folder, exist_ok=True)
            if user["drive_folder"] != folder:
                con.execute("UPDATE users SET drive_folder=? WHERE id=?", (folder, user["id"]))
            root = con.execute("SELECT id FROM folders WHERE user_id=? AND parent_id IS NULL", (user["id"],)).fetchone()
            if not root:
                cur = con.execute("INSERT INTO folders(user_id,name,parent_id) VALUES(?,?,NULL)", (user["id"], ""))
                root_id = cur.lastrowid
            else:
                root_id = root["id"]
            con.execute("UPDATE files SET folder_id=? WHERE user_id=? AND folder_id IS NULL", (root_id, user["id"]))
            for item in con.execute("SELECT id,name,parent_id,disk_name FROM folders WHERE user_id=? ORDER BY id", (user["id"],)).fetchall():
                disk_name = item["disk_name"]
                if item["parent_id"] is None:
                    disk_name = ""
                elif not disk_name:
                    disk_name = safe_folder_name(item["name"], item["id"])
                    con.execute("UPDATE folders SET disk_name=? WHERE id=?", (disk_name, item["id"]))
                parent = folder if item["parent_id"] is None else folder_disk_path(con, user["id"], item["parent_id"])
                os.makedirs(os.path.join(parent, disk_name) if disk_name else parent, exist_ok=True)
            base = os.path.realpath(folder)
            for file in con.execute("SELECT id,drive_id,folder_id,storage_bytes FROM files WHERE user_id=?", (user["id"],)).fetchall():
                source = os.path.realpath(file["drive_id"])
                try:
                    is_local = os.path.commonpath((base, source)) == base
                except ValueError:
                    is_local = False
                if not is_local or not os.path.isfile(source):
                    if file["storage_bytes"]:
                        con.execute("UPDATE files SET storage_bytes=0 WHERE id=?", (file["id"],))
                    continue
                destination = os.path.join(folder_disk_path(con, user["id"], file["folder_id"]), os.path.basename(source))
                if source != os.path.realpath(destination):
                    os.replace(source, destination)
                    con.execute("UPDATE files SET drive_id=? WHERE id=?", (destination, file["id"]))
                stored_size = os.path.getsize(destination)
                if stored_size != file["storage_bytes"]:
                    con.execute("UPDATE files SET storage_bytes=? WHERE id=?", (stored_size, file["id"]))
        admin = con.execute("SELECT id,role FROM users WHERE username=?", (ADMIN_USERNAME,)).fetchone()
        if not admin:
            salt = secrets.token_bytes(16)
            password_hash = hashlib.pbkdf2_hmac("sha256", ADMIN_BOOTSTRAP_PASSWORD.encode(), salt, 300_000)
            cur = con.execute("INSERT INTO users(username,salt,password_hash,drive_folder,role,status,storage_limit_bytes,created_at) VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)", (ADMIN_USERNAME, salt, password_hash, "", "admin", "active", ACCOUNT_STORAGE_LIMIT))
            uid = cur.lastrowid
            folder = user_folder(ADMIN_USERNAME, uid)
            os.makedirs(folder, exist_ok=True)
            con.execute("UPDATE users SET drive_folder=? WHERE id=?", (folder, uid))
            con.execute("INSERT INTO folders(user_id,name,parent_id,disk_name) VALUES(?,?,NULL,?)", (uid, "", ""))
        elif admin["role"] != "admin":
            salt = secrets.token_bytes(16)
            password_hash = hashlib.pbkdf2_hmac("sha256", ADMIN_BOOTSTRAP_PASSWORD.encode(), salt, 300_000)
            con.execute("UPDATE users SET role='admin',status='active',salt=?,password_hash=? WHERE id=?", (salt, password_hash, admin["id"]))


def user_folder(username, user_id):
    safe_name = secure_filename(username)[:40] or "user"
    return os.path.join(MOTHER_FOLDER, f"{safe_name}_{user_id}")


def safe_folder_name(name, folder_id):
    # Folder names are validated for new folders; this fallback also handles
    # legacy names that may contain characters rejected by Windows paths.
    safe = "".join("_" if char in '<>:"/\\|?*' or ord(char) < 32 else char for char in name).rstrip(" .")
    if safe.upper().split(".", 1)[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        safe = ""
    return safe[:100].rstrip(" .") or f"Folder_{folder_id}"


def folder_disk_path(con, user_id, folder_id):
    user = con.execute("SELECT drive_folder FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        raise ValueError("Locker not found.")
    base = os.path.realpath(user["drive_folder"])
    parts = []
    folder = con.execute("SELECT id,name,parent_id,disk_name FROM folders WHERE id=? AND user_id=?", (folder_id, user_id)).fetchone()
    while folder and folder["parent_id"] is not None:
        parts.append(folder["disk_name"] or safe_folder_name(folder["name"], folder["id"]))
        folder = con.execute("SELECT id,name,parent_id,disk_name FROM folders WHERE id=? AND user_id=?", (folder["parent_id"], user_id)).fetchone()
    path = os.path.realpath(os.path.join(base, *reversed(parts)))
    if os.path.commonpath((base, path)) != base:
        raise ValueError("Folder is outside your locker folder.")
    return path


def remove_storage_tree(path):
    """Remove a locker directory, retrying Windows read-only entries once."""
    def make_writable_and_retry(function, target, _error_info):
        os.chmod(target, 0o700)
        function(target)

    shutil.rmtree(path, onerror=make_writable_and_retry)


def derive_keys(password, salt):
    material = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 300_000, dklen=56)
    enc = DES3.adjust_key_parity(material[:24])
    return enc, material[24:56]


def add_audit(con, event, actor_id=None, target_id=None, detail=""):
    actor = con.execute("SELECT username FROM users WHERE id=?", (actor_id,)).fetchone() if actor_id else None
    target = con.execute("SELECT username FROM users WHERE id=?", (target_id,)).fetchone() if target_id else None
    con.execute(
        "INSERT INTO activity_logs(actor_user_id,actor_name,target_user_id,target_name,event,detail,ip_address) VALUES(?,?,?,?,?,?,?)",
        (actor_id, actor["username"] if actor else None, target_id, target["username"] if target else None, event, detail, request.remote_addr),
    )


def expire_suspensions(con, user_id=None):
    """Reactivate accounts whose timed suspension has elapsed."""
    condition = "AND id=?" if user_id is not None else ""
    params = (user_id,) if user_id is not None else ()
    expired = con.execute(
        f"SELECT id FROM users WHERE status='suspended' AND suspended_until IS NOT NULL AND suspended_until<=datetime('now') {condition}",
        params,
    ).fetchall()
    for user in expired:
        con.execute("UPDATE users SET status='active',suspended_until=NULL WHERE id=?", (user["id"],))
        add_audit(con, "account_suspension_expired", target_id=user["id"], detail="Timed suspension ended")


def audit_event(event, actor_id=None, target_id=None, detail=""):
    with db() as con:
        add_audit(con, event, actor_id, target_id, detail)


def require_login(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return jsonify(error="Please log in first."), 401
        if session_users.get(session.get("sid")) != user_id:
            session.clear()
            return jsonify(error="Your session expired. Please log in again."), 401
        with db() as con:
            expire_suspensions(con, user_id)
            user = con.execute("SELECT role,status FROM users WHERE id=?", (user_id,)).fetchone()
        if not user or user["status"] != "active":
            session_keys.pop(session.get("sid"), None)
            session_users.pop(session.get("sid"), None)
            session.clear()
            return jsonify(error="This account is not active. Please contact an administrator."), 403
        session["role"] = user["role"]
        return fn(*args, **kwargs)
    return wrapped


def require_admin(fn):
    @wraps(fn)
    @require_login
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify(error="Administrator access required."), 403
        return fn(*args, **kwargs)
    return wrapped


@app.get("/")
def home():
    if session.get("user_id") and session.get("role") == "admin":
        return render_template("admin.html")
    return render_template("index.html")


@app.get("/admin")
@require_login
def admin_home():
    if session.get("role") != "admin":
        return render_template("index.html"), 403
    return render_template("admin.html")


@app.get("/api/me")
def me():
    if not session.get("user_id"):
        return jsonify(user=None)
    with db() as con:
        expire_suspensions(con, session["user_id"])
        user = con.execute("SELECT username,role,status FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not user or user["status"] != "active" or session_users.get(session.get("sid")) != session.get("user_id"):
        session_keys.pop(session.get("sid"), None)
        session_users.pop(session.get("sid"), None)
        session.clear()
        return jsonify(user=None)
    return jsonify(user={"username": user["username"], "role": user["role"], "uid": session["user_id"]})


@app.post("/api/signup")
def signup():
    data = request.get_json(silent=True) or {}
    username, password = str(data.get("username", "")).strip(), str(data.get("password", ""))
    email = str(data.get("email", "")).strip().lower() or None
    if not 3 <= len(username) <= 40 or len(password) < 8 or not any(char.isascii() and char.isdigit() for char in password) or not any(not (char.isascii() and char.isalnum()) for char in password):
        return jsonify(error="Use a 3-40 character username and a password with at least 8 characters, one number, and one special character."), 400
    if email and (len(email) > 254 or "@" not in email):
        return jsonify(error="Enter a valid email address."), 400
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 300_000)
    try:
        with db() as con:
            cur = con.execute("INSERT INTO users(username,salt,password_hash,drive_folder,email,created_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)", (username, salt, password_hash, "", email))
            uid = cur.lastrowid
            folder = user_folder(username, uid)
            os.makedirs(folder, exist_ok=True)
            con.execute("UPDATE users SET drive_folder=? WHERE id=?", (folder, uid))
            con.execute("INSERT INTO folders(user_id,name,parent_id) VALUES(?,?,NULL)", (uid, ""))
            add_audit(con, "account_created", uid, uid)
    except sqlite3.IntegrityError:
        return jsonify(error="That username is already taken."), 409
    except Exception as exc:
        return jsonify(error=f"Could not create your local locker folder: {exc}"), 500
    session.clear()
    session["user_id"] = uid
    session["sid"] = secrets.token_urlsafe(24)
    session_keys[session["sid"]] = derive_keys(password, salt)
    session_users[session["sid"]] = uid
    session["role"] = "user"
    return jsonify(user={"username": username, "role": "user", "uid": uid})


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username, password = str(data.get("username", "")).strip(), str(data.get("password", ""))
    with db() as con:
        expire_suspensions(con)
        user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user or not hmac.compare_digest(user["password_hash"], hashlib.pbkdf2_hmac("sha256", password.encode(), user["salt"], 300_000)):
        audit_event("login_failed", target_id=user["id"] if user else None, detail=username)
        return jsonify(error="Incorrect username or password."), 401
    if user["status"] != "active":
        audit_event("login_blocked", target_id=user["id"], detail=user["status"])
        if user["status"] == "suspended":
            suspended_until = user["suspended_until"]
            if suspended_until:
                try:
                    expiry = datetime.strptime(suspended_until, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone(PHILIPPINE_TZ).strftime("%B %d, %Y at %I:%M %p PHT").replace(" 0", " ")
                except ValueError:
                    expiry = suspended_until + " PHT"
                return jsonify(error=f"Your account is suspended until {expiry}. You can sign in again after that time."), 403
            return jsonify(error="Your account is suspended. Please contact an administrator for details."), 403
        return jsonify(error="This account is not active. Please contact an administrator."), 403
    session.clear()
    session["user_id"] = user["id"]
    session["sid"] = secrets.token_urlsafe(24)
    session_keys[session["sid"]] = derive_keys(password, user["salt"])
    session_users[session["sid"]] = user["id"]
    session["role"] = user["role"]
    audit_event("login_success", actor_id=user["id"])
    return jsonify(user={"username": username, "role": user["role"], "uid": user["id"]})


@app.post("/api/logout")
def logout():
    if session.get("user_id"):
        audit_event("logout", actor_id=session["user_id"])
    session_keys.pop(session.get("sid"), None)
    session_users.pop(session.get("sid"), None)
    session.clear()
    return jsonify(ok=True)


@app.get("/api/admin/summary")
@require_admin
def admin_summary():
    with db() as con:
        expire_suspensions(con)
        summary = con.execute("""
            SELECT COUNT(*) AS users,
                   COALESCE(SUM((SELECT COALESCE(SUM(storage_bytes),0) FROM files f WHERE f.user_id=u.id)),0) AS used_bytes,
                   COALESCE(SUM(storage_limit_bytes),0) AS quota_bytes
            FROM users u WHERE role='user'
        """).fetchone()
        active = con.execute("SELECT COUNT(*) FROM users WHERE role='user' AND status='active'").fetchone()[0]
        events = con.execute("SELECT id,actor_name,target_name,event,detail,ip_address,created_at FROM activity_logs ORDER BY id DESC LIMIT 12").fetchall()
    return jsonify(users=summary["users"], active_users=active, used_bytes=summary["used_bytes"], quota_bytes=summary["quota_bytes"], recent=[dict(row) for row in events])


@app.get("/api/admin/users")
@require_admin
def admin_users():
    query = str(request.args.get("q", "")).strip()
    with db() as con:
        expire_suspensions(con)
        rows = con.execute("""
            SELECT u.id,u.username,u.email,u.role,u.status,u.suspended_until,u.storage_limit_bytes,u.created_at,
                   COALESCE((SELECT SUM(storage_bytes) FROM files f WHERE f.user_id=u.id),0) AS used_bytes,
                   (SELECT COUNT(*) FROM files f WHERE f.user_id=u.id) AS file_count
            FROM users u WHERE u.role='user' AND (?='' OR u.username LIKE ? OR COALESCE(u.email,'') LIKE ?)
            ORDER BY u.username COLLATE NOCASE
        """, (query, f"%{query}%", f"%{query}%")).fetchall()
    return jsonify(users=[dict(row) for row in rows])


@app.get("/api/admin/users/<int:user_id>/folders")
@require_admin
def admin_user_folders(user_id):
    with db() as con:
        user = con.execute("SELECT id,username FROM users WHERE id=? AND role='user'", (user_id,)).fetchone()
        if not user:
            return jsonify(error="User account not found."), 404
        folders = con.execute("SELECT id,name,parent_id FROM folders WHERE user_id=? ORDER BY id", (user_id,)).fetchall()
        files = con.execute("SELECT id,name,folder_id,storage_bytes FROM files WHERE user_id=? ORDER BY name", (user_id,)).fetchall()
    return jsonify(username=user["username"], folders=[dict(row) for row in folders], files=[dict(row) for row in files])


@app.patch("/api/admin/users/<int:user_id>/status")
@require_admin
def admin_user_status(user_id):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in ("active", "deactivated", "suspended"):
        return jsonify(error="Choose active, deactivated, or suspended."), 400
    suspension_days = None
    suspended_until = None
    if status == "suspended":
        try:
            suspension_days = int(data.get("suspension_days"))
        except (TypeError, ValueError):
            return jsonify(error="Enter how many days the account should be suspended."), 400
        if not 1 <= suspension_days <= 3650:
            return jsonify(error="Suspension must be between 1 and 3,650 days."), 400
        suspended_until = (datetime.now(timezone.utc) + timedelta(days=suspension_days)).strftime("%Y-%m-%d %H:%M:%S")
    with db() as con:
        user = con.execute("SELECT id,role,status FROM users WHERE id=?", (user_id,)).fetchone()
        if not user or user["role"] != "user":
            return jsonify(error="User account not found or cannot be managed."), 404
        con.execute("UPDATE users SET status=?,suspended_until=? WHERE id=?", (status, suspended_until, user_id))
        expiry_detail = datetime.strptime(suspended_until, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).astimezone(PHILIPPINE_TZ).strftime("%B %d, %Y at %I:%M %p PHT").replace(" 0", " ") if suspended_until else ""
        detail = f"Suspended for {suspension_days} days, until {expiry_detail}" if status == "suspended" else status
        add_audit(con, "account_status_changed", session["user_id"], user_id, detail)
    if status != "active":
        for sid, uid in list(session_users.items()):
            if uid == user_id:
                session_users.pop(sid, None)
                session_keys.pop(sid, None)
    return jsonify(ok=True, suspended_until=suspended_until)


@app.patch("/api/admin/users/<int:user_id>/quota")
@require_admin
def admin_user_quota(user_id):
    data = request.get_json(silent=True) or {}
    try:
        megabytes = float(data.get("limit_mb"))
    except (TypeError, ValueError):
        return jsonify(error="Enter a quota in megabytes."), 400
    if not 1 <= megabytes <= 100_000:
        return jsonify(error="Quota must be between 1 MB and 100,000 MB."), 400
    limit_bytes = int(megabytes * 1_000_000)
    with db() as con:
        user = con.execute("SELECT id,role FROM users WHERE id=?", (user_id,)).fetchone()
        if not user or user["role"] != "user":
            return jsonify(error="User account not found or cannot be managed."), 404
        con.execute("UPDATE users SET storage_limit_bytes=? WHERE id=?", (limit_bytes, user_id))
        add_audit(con, "storage_quota_changed", session["user_id"], user_id, f"{megabytes:g} MB")
    return jsonify(ok=True, limit_bytes=limit_bytes)


@app.post("/api/admin/users/<int:user_id>/recovery")
@require_admin
def admin_issue_recovery(user_id):
    with db() as con:
        user = con.execute("SELECT id,role FROM users WHERE id=?", (user_id,)).fetchone()
        if not user or user["role"] != "user":
            return jsonify(error="User account not found or cannot be managed."), 404
        code = secrets.token_urlsafe(24)
        expires = int(time.time()) + 3600
        code_hash = hashlib.sha256(code.encode()).digest()
        con.execute("UPDATE users SET recovery_hash=?,recovery_expires=? WHERE id=?", (code_hash, expires, user_id))
        add_audit(con, "recovery_code_issued", session["user_id"], user_id, "Expires in 1 hour")
    return jsonify(recovery_code=code, expires_at=expires, expires_in_seconds=3600)


@app.delete("/api/admin/users/<int:user_id>")
@require_admin
def admin_delete_user(user_id):
    with db() as con:
        user = con.execute("SELECT id,username,role,drive_folder FROM users WHERE id=?", (user_id,)).fetchone()
        if not user or user["role"] != "user":
            return jsonify(error="User account not found or cannot be deleted."), 404
        mother = os.path.realpath(MOTHER_FOLDER)
        path = os.path.realpath(user["drive_folder"])
        if not os.path.isdir(mother):
            return jsonify(error="The configured storage share is unavailable. Reconnect it and restart Mariae Vault."), 503
        warning = None
        try:
            account_is_in_storage = os.path.commonpath((mother, path)) == mother
        except ValueError:
            account_is_in_storage = False
        # A moved vault can leave old database paths pointing at the previous
        # PC. In that case use the canonical account directory in the share.
        # The fallback is constructed from the configured root, a sanitized
        # username, and the numeric account ID, so it cannot escape the share.
        storage_path = path if account_is_in_storage else user_folder(user["username"], user_id)
        try:
            if os.path.isdir(storage_path):
                remove_storage_tree(storage_path)
        except OSError as exc:
            return jsonify(error=f"Could not delete the account folder on the storage share: {exc}"), 500
        if not account_is_in_storage and os.path.isdir(path):
            warning = "The account was deleted and its folder on the configured share was removed. An old folder may remain at its previous location."
        detail = "Account and stored files permanently removed" if warning is None else "Account deleted; old storage folder was outside the configured share"
        add_audit(con, "account_deleted", session["user_id"], user_id, detail)
        con.execute("DELETE FROM files WHERE user_id=?", (user_id,))
        con.execute("DELETE FROM folders WHERE user_id=?", (user_id,))
        con.execute("DELETE FROM users WHERE id=?", (user_id,))
    for sid, uid in list(session_users.items()):
        if uid == user_id:
            session_users.pop(sid, None)
            session_keys.pop(sid, None)
    return jsonify(ok=True, warning=warning)


@app.get("/api/admin/logs")
@require_admin
def admin_logs():
    with db() as con:
        events = con.execute("SELECT id,actor_name,target_name,event,detail,ip_address,created_at FROM activity_logs ORDER BY id DESC LIMIT 300").fetchall()
        security = con.execute("""
            SELECT COALESCE(target_name,detail) AS username,ip_address,COUNT(*) AS failures,MAX(created_at) AS last_attempt
            FROM activity_logs WHERE event IN ('login_failed','login_blocked') AND created_at>=datetime('now','-15 minutes')
            GROUP BY COALESCE(target_name,detail),ip_address HAVING COUNT(*)>=5 ORDER BY failures DESC
        """).fetchall()
    return jsonify(events=[dict(row) for row in events], security_events=[dict(row) for row in security])


def write_backup_archive(archive_path):
    with tempfile.TemporaryDirectory(prefix="mariae-vault-backup-") as workspace:
        database_copy = os.path.join(workspace, "locker.db")
        source = sqlite3.connect(DB_PATH)
        target = sqlite3.connect(database_copy)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(database_copy, "locker.db")
            for root, _, filenames in os.walk(MOTHER_FOLDER, followlinks=False):
                for filename in filenames:
                    path = os.path.join(root, filename)
                    if os.path.isfile(path) and not os.path.islink(path):
                        relative = os.path.relpath(path, MOTHER_FOLDER).replace(os.sep, "/")
                        archive.write(path, f"vault/{relative}")


@app.get("/api/admin/backup")
@require_admin
def admin_backup():
    audit_event("backup_created", actor_id=session["user_id"])
    workspace = tempfile.mkdtemp(prefix="mariae-vault-download-")
    archive_path = os.path.join(workspace, "mariae-vault-backup.zip")
    try:
        write_backup_archive(archive_path)
        response = send_file(archive_path, as_attachment=True, download_name=f"mariae-vault-backup-{int(time.time())}.zip", mimetype="application/zip")
        response.call_on_close(lambda: shutil.rmtree(workspace, ignore_errors=True))
        return response
    except Exception:
        shutil.rmtree(workspace, ignore_errors=True)
        raise


@app.post("/api/admin/restore")
@require_admin
def admin_restore():
    uploaded = request.files.get("backup")
    if not uploaded or not uploaded.filename:
        return jsonify(error="Choose a Mariae Vault backup archive."), 400
    workspace = tempfile.mkdtemp(prefix="mariae-vault-restore-", dir=os.path.dirname(os.path.realpath(MOTHER_FOLDER)))
    staged_database = os.path.join(workspace, "locker.db")
    staged_vault = os.path.join(workspace, "vault")
    os.makedirs(staged_vault)
    current_database = os.path.join(workspace, "current.db")
    old_vault = os.path.join(workspace, "previous-vault")
    new_vault = os.path.join(workspace, "restored-vault")
    preserve_workspace = False
    try:
        with zipfile.ZipFile(uploaded.stream) as archive:
            found_database = False
            for member in archive.infolist():
                raw_name = member.filename
                path = PurePosixPath(raw_name)
                reserved_names = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
                unsafe_parts = any(":" in part or part.endswith((".", " ")) or part.upper().split(".", 1)[0] in reserved_names for part in path.parts)
                if "\\" in raw_name or path.is_absolute() or ".." in path.parts or unsafe_parts:
                    return jsonify(error="Backup contains an unsafe file path."), 400
                if member.is_dir():
                    continue
                mode = (member.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    return jsonify(error="Backup archives cannot contain symbolic links."), 400
                if raw_name == "locker.db":
                    destination = staged_database
                    found_database = True
                elif raw_name.startswith("vault/") and len(path.parts) > 1:
                    destination = os.path.join(staged_vault, *path.parts[1:])
                else:
                    return jsonify(error="Backup contains an unexpected file."), 400
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                with archive.open(member) as source, open(destination, "xb") as target:
                    shutil.copyfileobj(source, target)
        if not found_database:
            return jsonify(error="Backup is missing locker.db."), 400
        staged = sqlite3.connect(staged_database)
        staged.row_factory = sqlite3.Row
        try:
            if staged.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                return jsonify(error="Backup database failed its integrity check."), 400
            required = {row[0] for row in staged.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"users", "folders", "files", "activity_logs"}.issubset(required):
                return jsonify(error="This backup does not contain a complete Mariae Vault database."), 400
            users = staged.execute("SELECT id,username FROM users").fetchall()
            if not users:
                return jsonify(error="Backup has no user accounts."), 400
            if not staged.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone():
                return jsonify(error="Backup does not include an administrator account."), 400
            for user in users:
                staged_user_root = os.path.join(staged_vault, os.path.basename(user_folder(user["username"], user["id"])))
                staged.execute("UPDATE users SET drive_folder=? WHERE id=?", (user_folder(user["username"], user["id"]), user["id"]))
                os.makedirs(staged_user_root, exist_ok=True)
            for folder in staged.execute("SELECT id,user_id FROM folders").fetchall():
                live_folder_path = folder_disk_path(staged, folder["user_id"], folder["id"])
                relative_folder_path = os.path.relpath(live_folder_path, MOTHER_FOLDER)
                os.makedirs(os.path.join(staged_vault, relative_folder_path), exist_ok=True)
            for file in staged.execute("SELECT id,user_id,folder_id,drive_id FROM files").fetchall():
                folder_path = folder_disk_path(staged, file["user_id"], file["folder_id"])
                stored_name = os.path.basename(file["drive_id"])
                if not stored_name or stored_name in (".", "..") or any(char in stored_name for char in '<>:"/\\|?*'):
                    return jsonify(error="Backup contains an invalid stored-file path."), 400
                stored_path = os.path.realpath(os.path.join(folder_path, stored_name))
                if os.path.commonpath((folder_path, stored_path)) != folder_path:
                    return jsonify(error="Backup contains a stored file outside its account folder."), 400
                staged_file_path = os.path.join(staged_vault, os.path.relpath(stored_path, MOTHER_FOLDER))
                if not os.path.isfile(staged_file_path):
                    return jsonify(error="Backup is missing one or more encrypted user files."), 400
                staged.execute("UPDATE files SET drive_id=? WHERE id=?", (stored_path, file["id"]))
            staged.commit()
        finally:
            staged.close()
        live_source = sqlite3.connect(DB_PATH)
        backup_copy = sqlite3.connect(current_database)
        try:
            live_source.backup(backup_copy)
        finally:
            backup_copy.close()
            live_source.close()
        old_moved = False
        restored_vault = False
        try:
            if os.path.exists(MOTHER_FOLDER):
                os.replace(MOTHER_FOLDER, old_vault)
                old_moved = True
            os.replace(staged_vault, MOTHER_FOLDER)
            restored_vault = True
            restored = sqlite3.connect(staged_database)
            live = sqlite3.connect(DB_PATH)
            try:
                restored.backup(live)
            finally:
                live.close()
                restored.close()
        except Exception:
            try:
                if restored_vault and os.path.exists(MOTHER_FOLDER):
                    os.replace(MOTHER_FOLDER, new_vault)
                if old_moved and os.path.exists(old_vault):
                    os.replace(old_vault, MOTHER_FOLDER)
                original = sqlite3.connect(current_database)
                live = sqlite3.connect(DB_PATH)
                try:
                    original.backup(live)
                finally:
                    live.close()
                    original.close()
            except Exception as rollback_error:
                preserve_workspace = True
                return jsonify(error=f"Restore and rollback both failed. Recovery files were preserved at {workspace}. {rollback_error}"), 500
            raise
        with db() as con:
            con.execute("INSERT INTO activity_logs(actor_name,event,detail,ip_address) VALUES(?,?,?,?)", (ADMIN_USERNAME, "system_restored", "System restored from backup archive", request.remote_addr))
        session_keys.clear()
        session_users.clear()
        session.clear()
        return jsonify(ok=True, message="Restore completed. Log in again to continue.")
    except (zipfile.BadZipFile, OSError, sqlite3.DatabaseError, ValueError) as exc:
        return jsonify(error=f"Restore failed: {exc}"), 400
    finally:
        if not preserve_workspace:
            shutil.rmtree(workspace, ignore_errors=True)


@app.post("/api/recover")
def recover_account():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    recovery_code = str(data.get("recovery_code", "")).strip()
    new_password = str(data.get("new_password", ""))
    if len(new_password) < 8:
        return jsonify(error="Use a password of at least 8 characters."), 400
    with db() as con:
        user = con.execute("SELECT id,recovery_hash,recovery_expires FROM users WHERE username=?", (username,)).fetchone()
        valid = bool(user and user["recovery_hash"] and user["recovery_expires"] and user["recovery_expires"] >= int(time.time()) and hmac.compare_digest(user["recovery_hash"], hashlib.sha256(recovery_code.encode()).digest()))
        if not valid:
            add_audit(con, "recovery_failed", target_id=user["id"] if user else None, detail=username)
            return jsonify(error="The recovery code is invalid or expired."), 400
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac("sha256", new_password.encode(), salt, 300_000)
        con.execute("UPDATE users SET salt=?,password_hash=?,recovery_hash=NULL,recovery_expires=NULL WHERE id=?", (salt, password_hash, user["id"]))
        add_audit(con, "password_recovered", target_id=user["id"])
    for sid, uid in list(session_users.items()):
        if uid == user["id"]:
            session_users.pop(sid, None)
            session_keys.pop(sid, None)
    return jsonify(ok=True)


@app.get("/api/files")
@require_login
def files():
    folder_id = request.args.get("folder_id", type=int)
    with db() as con:
        root = con.execute("SELECT id FROM folders WHERE user_id=? AND parent_id IS NULL", (session["user_id"],)).fetchone()
        folder_id = folder_id or root["id"]
        folder = con.execute("SELECT id FROM folders WHERE id=? AND user_id=?", (folder_id, session["user_id"])).fetchone()
        if not folder:
            return jsonify(error="Folder not found."), 404
        rows = con.execute("SELECT id,name FROM files WHERE user_id=? AND folder_id=? ORDER BY name", (session["user_id"], folder_id)).fetchall()
        children = con.execute("SELECT id,name FROM folders WHERE user_id=? AND parent_id=? ORDER BY name", (session["user_id"], folder_id)).fetchall()
    return jsonify(files=[dict(row) for row in rows], folders=[dict(row) for row in children], folder_id=folder_id)


@app.get("/api/storage")
@require_login
def storage_usage():
    with db() as con:
        used = con.execute("SELECT COALESCE(SUM(storage_bytes),0) FROM files WHERE user_id=?", (session["user_id"],)).fetchone()[0]
        limit = con.execute("SELECT storage_limit_bytes FROM users WHERE id=?", (session["user_id"],)).fetchone()[0]
    return jsonify(used_bytes=used, limit_bytes=limit, available_bytes=max(0, limit - used))


@app.get("/api/folders")
@require_login
def list_folders():
    with db() as con:
        rows = con.execute("SELECT id,name,parent_id FROM folders WHERE user_id=? ORDER BY id", (session["user_id"],)).fetchall()
    return jsonify(folders=[dict(row) for row in rows])


@app.post("/api/folders")
@require_login
def create_folder():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    parent_id = data.get("parent_id")
    invalid_chars = '<>:"/\\|?*'
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if not name or len(name) > 100 or name in (".", "..") or name[-1:] in (".", " ") or any(char in invalid_chars or ord(char) < 32 for char in name) or name.upper().split(".", 1)[0] in reserved:
        return jsonify(error="Use a folder name up to 100 characters without reserved characters."), 400
    with db() as con:
        parent = con.execute("SELECT id FROM folders WHERE id=? AND user_id=?", (parent_id, session["user_id"])).fetchone()
        if not parent:
            return jsonify(error="Parent folder not found."), 404
        try:
            cur = con.execute("INSERT INTO folders(user_id,name,parent_id,disk_name) VALUES(?,?,?,?)", (session["user_id"], name, parent_id, ""))
            folder_id = cur.lastrowid
            con.execute("UPDATE folders SET disk_name=? WHERE id=?", (name, folder_id))
            os.mkdir(os.path.join(folder_disk_path(con, session["user_id"], parent_id), name))
            add_audit(con, "folder_created", session["user_id"], session["user_id"], name)
        except sqlite3.IntegrityError:
            return jsonify(error="A folder with that name already exists here."), 409
        except OSError as exc:
            if "folder_id" in locals():
                con.execute("DELETE FROM folders WHERE id=?", (folder_id,))
            return jsonify(error=f"Could not create the folder on disk: {exc}"), 500
    return jsonify(id=cur.lastrowid, name=name), 201


@app.delete("/api/folders/<int:folder_id>")
@require_login
def delete_folder(folder_id):
    with db() as con:
        folder = con.execute("SELECT id,parent_id FROM folders WHERE id=? AND user_id=?", (folder_id, session["user_id"])).fetchone()
        if not folder:
            return jsonify(error="Folder not found."), 404
        if folder["parent_id"] is None:
            return jsonify(error="The locker root folder cannot be deleted."), 400
        rows = con.execute("""
            WITH RECURSIVE subtree(id) AS (
                SELECT id FROM folders WHERE id=? AND user_id=?
                UNION ALL
                SELECT child.id FROM folders child JOIN subtree parent ON child.parent_id=parent.id
                WHERE child.user_id=?
            ) SELECT id FROM subtree
        """, (folder_id, session["user_id"], session["user_id"])).fetchall()
        folder_ids = [row["id"] for row in rows]
        path = folder_disk_path(con, session["user_id"], folder_id)
        user_path = os.path.realpath(con.execute("SELECT drive_folder FROM users WHERE id=?", (session["user_id"],)).fetchone()[0])
        if os.path.commonpath((user_path, path)) != user_path:
            return jsonify(error="Folder is outside your locker folder."), 403
        if not os.path.isdir(user_path):
            return jsonify(error="The configured storage share is unavailable. Reconnect it and restart Mariae Vault."), 503
        try:
            if os.path.isdir(path):
                remove_storage_tree(path)
        except OSError as exc:
            return jsonify(error=f"Could not delete the folder on the storage share: {exc}"), 500
        add_audit(con, "folder_deleted", session["user_id"], session["user_id"], f"folder_id={folder_id}; nested folders/files removed")
        placeholders = ",".join("?" for _ in folder_ids)
        con.execute(f"DELETE FROM files WHERE user_id=? AND folder_id IN ({placeholders})", [session["user_id"], *folder_ids])
        con.execute(f"DELETE FROM folders WHERE user_id=? AND id IN ({placeholders})", [session["user_id"], *folder_ids])
    return jsonify(ok=True)


@app.post("/api/files")
@require_login
def upload():
    uploaded = request.files.get("file")
    keys = session_keys.get(session.get("sid"))
    if not uploaded or not uploaded.filename or not keys:
        return jsonify(error="Choose a file and log in again."), 400
    folder_id = request.form.get("folder_id", type=int)
    content = None
    try:
        try:
            uploaded.stream.seek(0, os.SEEK_END)
            content_size = uploaded.stream.tell()
            uploaded.stream.seek(0)
        except (AttributeError, OSError):
            content = uploaded.read()
            content_size = len(content)
        expected_storage = 45 + ((content_size // 8) + 1) * 8
        with db() as con:
            con.execute("BEGIN IMMEDIATE")
            valid_folder = con.execute("SELECT id FROM folders WHERE id=? AND user_id=?", (folder_id, session["user_id"])).fetchone()
            if not valid_folder:
                return jsonify(error="Choose a valid destination folder."), 400
            used = con.execute("SELECT COALESCE(SUM(storage_bytes),0) FROM files WHERE user_id=?", (session["user_id"],)).fetchone()[0]
            limit = con.execute("SELECT storage_limit_bytes FROM users WHERE id=?", (session["user_id"],)).fetchone()[0]
            if used + expected_storage > limit:
                remaining = max(0, limit - used)
                return jsonify(error=f"This upload exceeds your remaining storage. {remaining / 1_000_000:.1f} MB available."), 413
            if content is None:
                content = uploaded.read()
            iv = secrets.token_bytes(8)
            pad = 8 - (len(content) % 8)
            encrypted = DES3.new(keys[0], DES3.MODE_CBC, iv).encrypt(content + bytes([pad]) * pad)
            mac = hmac.new(keys[1], iv + encrypted, hashlib.sha256).digest()
            stored_size = 45 + len(encrypted)
            if used + stored_size > limit:
                remaining = max(0, limit - used)
                return jsonify(error=f"This upload exceeds your remaining storage. {remaining / 1_000_000:.1f} MB available."), 413
            folder = folder_disk_path(con, session["user_id"], folder_id)
            cur = con.execute("INSERT INTO files(user_id,name,drive_id,iv,mac,folder_id,storage_bytes) VALUES(?,?,?,?,?,?,?)", (session["user_id"], secure_filename(uploaded.filename) or "download", "", iv, mac, folder_id, stored_size))
            file_id = cur.lastrowid
            encrypted_path = os.path.join(folder, f"{file_id}_{secrets.token_hex(8)}.mvlt")
            with open(encrypted_path, "xb") as local_file:
                local_file.write(b"MVLT1" + iv + mac + encrypted)
            con.execute("UPDATE files SET drive_id=? WHERE id=?", (encrypted_path, file_id))
            add_audit(con, "file_uploaded", actor_id=session["user_id"], detail=f"{secure_filename(uploaded.filename) or 'download'} ({stored_size} bytes)")
        return jsonify(id=file_id, name=secure_filename(uploaded.filename) or "download"), 201
    except Exception as exc:
        if "encrypted_path" in locals() and os.path.exists(encrypted_path):
            try:
                os.remove(encrypted_path)
            except OSError:
                pass
        return jsonify(error=f"Local upload failed. {exc}"), 500


@app.get("/api/files/<int:file_id>")
@require_login
def download(file_id):
    return serve_file(file_id, False)


@app.get("/api/files/<int:file_id>/preview")
@require_login
def preview(file_id):
    return serve_file(file_id, True)


def serve_file(file_id, inline):
    keys = session_keys.get(session.get("sid"))
    with db() as con:
        row = con.execute("SELECT name,drive_id,iv,mac FROM files WHERE id=? AND user_id=?", (file_id, session["user_id"])).fetchone()
    if not row:
        return jsonify(error="File not found."), 404
    if not keys:
        return jsonify(error="Please log in again."), 401
    try:
        with db() as con:
            folder = con.execute("SELECT drive_folder FROM users WHERE id=?", (session["user_id"],)).fetchone()[0]
        path = os.path.realpath(row["drive_id"])
        if os.path.commonpath((os.path.realpath(folder), path)) != os.path.realpath(folder):
            return jsonify(error="File is outside your locker folder."), 403
        with open(path, "rb") as local_file:
            blob = local_file.read()
        if len(blob) < 45 or blob[:5] != b"MVLT1":
            raise ValueError("Invalid encrypted file.")
        iv, mac, encrypted = blob[5:13], blob[13:45], blob[45:]
        if not hmac.compare_digest(mac, hmac.new(keys[1], iv + encrypted, hashlib.sha256).digest()):
            raise ValueError("File integrity check failed. This file may belong to another account or be damaged.")
        plain = DES3.new(keys[0], DES3.MODE_CBC, iv).decrypt(encrypted)
        pad = plain[-1]
        if not 1 <= pad <= 8 or plain[-pad:] != bytes([pad]) * pad:
            raise ValueError("Invalid encrypted file padding.")
        response = send_file(io.BytesIO(plain[:-pad]), as_attachment=not inline, download_name=row["name"], mimetype=mimetypes.guess_type(row["name"])[0] or "application/octet-stream")
        audit_event("file_previewed" if inline else "file_downloaded", actor_id=session["user_id"], detail=row["name"])
        if inline:
            response.headers["Content-Security-Policy"] = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:;"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    except FileNotFoundError:
        return jsonify(error="The encrypted file is missing from local storage."), 404
    except Exception as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/files/<int:file_id>/move")
@require_login
def move_file(file_id):
    data = request.get_json(silent=True) or {}
    folder_id = data.get("folder_id")
    with db() as con:
        target = con.execute("SELECT id FROM folders WHERE id=? AND user_id=?", (folder_id, session["user_id"])).fetchone()
        if not target:
            return jsonify(error="Destination folder not found."), 404
        row = con.execute("SELECT drive_id,folder_id FROM files WHERE id=? AND user_id=?", (file_id, session["user_id"])).fetchone()
        if not row:
            return jsonify(error="File not found."), 404
        if row["folder_id"] == folder_id:
            return jsonify(ok=True)
        source = os.path.realpath(row["drive_id"])
        user_path = os.path.realpath(con.execute("SELECT drive_folder FROM users WHERE id=?", (session["user_id"],)).fetchone()[0])
        if os.path.commonpath((user_path, source)) != user_path:
            return jsonify(error="File is outside your locker folder."), 403
        destination = os.path.join(folder_disk_path(con, session["user_id"], folder_id), os.path.basename(source))
        os.replace(source, destination)
        con.execute("UPDATE files SET folder_id=?,drive_id=? WHERE id=? AND user_id=?", (folder_id, destination, file_id, session["user_id"]))
        add_audit(con, "file_moved", session["user_id"], session["user_id"], f"file_id={file_id}; folder_id={folder_id}")
    return jsonify(ok=True)


@app.post("/api/files/<int:file_id>/copy")
@require_login
def copy_file(file_id):
    data = request.get_json(silent=True) or {}
    folder_id = data.get("folder_id")
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT * FROM files WHERE id=? AND user_id=?", (file_id, session["user_id"])).fetchone()
        target = con.execute("SELECT id FROM folders WHERE id=? AND user_id=?", (folder_id, session["user_id"])).fetchone()
        if not row or not target:
            return jsonify(error="File or destination folder not found."), 404
        used = con.execute("SELECT COALESCE(SUM(storage_bytes),0) FROM files WHERE user_id=?", (session["user_id"],)).fetchone()[0]
        limit = con.execute("SELECT storage_limit_bytes FROM users WHERE id=?", (session["user_id"],)).fetchone()[0]
        if used + row["storage_bytes"] > limit:
            return jsonify(error=f"Copying this file would exceed your account storage limit. {max(0, limit - used) / 1_000_000:.1f} MB available."), 413
        user_path = con.execute("SELECT drive_folder FROM users WHERE id=?", (session["user_id"],)).fetchone()[0]
        source = os.path.realpath(row["drive_id"])
        if os.path.commonpath((os.path.realpath(user_path), source)) != os.path.realpath(user_path):
            return jsonify(error="File is outside your locker folder."), 403
        new_id = con.execute("INSERT INTO files(user_id,name,drive_id,iv,mac,folder_id,storage_bytes) VALUES(?,?,?,?,?,?,?)", (session["user_id"], row["name"], "", row["iv"], row["mac"], folder_id, row["storage_bytes"])).lastrowid
        dest = os.path.join(folder_disk_path(con, session["user_id"], folder_id), f"{new_id}_{secrets.token_hex(8)}.mvlt")
        with open(source, "rb") as src, open(dest, "xb") as dst:
            dst.write(src.read())
        con.execute("UPDATE files SET drive_id=? WHERE id=?", (dest, new_id))
        add_audit(con, "file_copied", actor_id=session["user_id"], detail=f"{row['name']} -> folder {folder_id}")
    return jsonify(ok=True), 201


@app.delete("/api/files/<int:file_id>")
@require_login
def delete_file(file_id):
    with db() as con:
        row = con.execute(
            "SELECT drive_id,name FROM files WHERE id=? AND user_id=?",
            (file_id, session["user_id"]),
        ).fetchone()
        if not row:
            return jsonify(error="File not found."), 404
        folder = con.execute(
            "SELECT drive_folder FROM users WHERE id=?", (session["user_id"],)
        ).fetchone()[0]
        path = os.path.realpath(row["drive_id"])
        if os.path.commonpath((os.path.realpath(folder), path)) != os.path.realpath(folder):
            return jsonify(error="File is outside your locker folder."), 403
        if os.path.exists(path):
            os.remove(path)
        con.execute("DELETE FROM files WHERE id=? AND user_id=?", (file_id, session["user_id"]))
        add_audit(con, "file_deleted", session["user_id"], session["user_id"], row["name"])
    return jsonify(ok=True)


init_db()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("LOCKER_HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
