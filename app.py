import os, sqlite3, time, secrets, string, threading
from datetime import timedelta
from flask import Flask, request, render_template, redirect, url_for, jsonify, session, Response, stream_with_context, send_from_directory, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from vps import create_vps_container, destroy_vps, suspend_vps, unsuspend_vps, regen_sshx, get_container_stats, build_logs_stream, can_create_vps, can_allocate_disk, add_port_forward, remove_port_forward, list_port_forwards, MAX_TOTAL_VPS, get_host_capacity, start_vps, stop_vps, reinstall_vps, get_vps_status, sync_status
from monitor import start_monitor
import queue_manager as queue
import node_mesh
import ip_intel

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# BUG FIX: the old code did `app.secret_key = secrets.token_hex(32)` fresh on
# every launch — that silently invalidates every session cookie (including
# "remember me") on every single restart, so "stay logged in" could never
# actually work. Now the key is generated once and persisted to disk, so it
# survives restarts. Set FLASK_SECRET_KEY yourself instead if you'd rather
# manage it explicitly (e.g. across multiple app instances).
SECRET_KEY_FILE = "secret.key"
if os.environ.get("FLASK_SECRET_KEY"):
    app.secret_key = os.environ["FLASK_SECRET_KEY"]
elif os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE) as f:
        app.secret_key = f.read().strip()
else:
    _key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(_key)
    app.secret_key = _key

app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=30)

DB = "panel.db"
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Public IP of this node — shown to users so they know what address to give
# players/clients connecting to their forwarded ports.
PUBLIC_IPV4 = os.environ.get("PUBLIC_IPV4", "")
MAX_FORWARDS_PER_VPS = 3

# Ceiling for admin-granted custom-spec VPSes (separate from the standard
# 60GB/4-core/80GB default everyone else gets via the normal Create VPS flow).
ADMIN_MAX_RAM_GB = 160
ADMIN_MAX_CPU_CORES = 20
ADMIN_MAX_DISK_GB = 500

# Simple per-IP debounce so rapid re-clicking "Create VPS" can't queue-spam.
_last_create_click = {}
CREATE_DEBOUNCE_SECONDS = 10

# Per-VPS debounce for start/stop/reinstall so a user can't spam these
# (each hits LXD directly, and reinstall in particular is expensive/destructive).
_last_power_action = {}
POWER_DEBOUNCE_SECONDS = 10
REINSTALL_DEBOUNCE_SECONDS = 60

# Standard per-user disk quota. Kept as one constant so the pre-flight
# budget check in vps_create() and the actual container creation in
# _build_vps() can never drift apart.
STANDARD_VPS_DISK_GB = 80


def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        signup_ip TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        recovery_code_hash TEXT,
        recovery_code_shown INTEGER DEFAULT 0,
        youtube_verified INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        container_id TEXT NOT NULL,
        ssh_command TEXT,
        status TEXT DEFAULT 'creating',
        creator_ip TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_regen INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        stars INTEGER NOT NULL,
        comment TEXT,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS port_forwards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vps_id INTEGER NOT NULL,
        device_name TEXT NOT NULL,
        host_port INTEGER NOT NULL,
        container_port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(vps_id) REFERENCES vps(id)
    );
    CREATE TABLE IF NOT EXISTS youtube_verifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        google_sub TEXT UNIQUE NOT NULL,
        channel_id TEXT,
        verified_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS broadcast (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        message TEXT,
        active INTEGER DEFAULT 0,
        updated_at INTEGER
    );
    """)
    # Single-row table (id is CHECK'd to 1) — seed it once so later
    # UPDATE ... WHERE id=1 always has a row to hit.
    db.execute("INSERT OR IGNORE INTO broadcast(id, message, active, updated_at) VALUES(1, '', 0, 0)")
    # Migrate older DBs where vps.user_id had a UNIQUE constraint (one VPS
    # per user) — admins can now grant multiple VPSes per user, so that
    # constraint has to go. SQLite can't ALTER a column's constraints
    # directly; rebuild the table instead, preserving all existing rows.
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='vps'").fetchone()
    if row and row["sql"] and "UNIQUE" in row["sql"].upper():
        db.executescript("""
        ALTER TABLE vps RENAME TO vps_old;
        CREATE TABLE vps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            container_id TEXT NOT NULL,
            ssh_command TEXT,
            status TEXT DEFAULT 'creating',
            creator_ip TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_regen INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        INSERT INTO vps SELECT * FROM vps_old;
        DROP TABLE vps_old;
        """)
    # Best-effort migration for DBs created before these columns existed.
    for stmt in [
        "ALTER TABLE users ADD COLUMN recovery_code_hash TEXT",
        "ALTER TABLE users ADD COLUMN recovery_code_shown INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN youtube_verified INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN is_vpn_signup INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN vpn_provider TEXT",
    ]:
        try:
            db.execute(stmt)
        except sqlite3.OperationalError:
            pass  # column already exists
    db.commit()
    node_mesh.init_mesh_tables(db)
    db.close()


@app.context_processor
def inject_broadcast():
    """Makes broadcast_message available in every template (base.html reads
    it to show/hide the site-wide banner) without every single route having
    to fetch and pass it individually."""
    db = get_db()
    row = db.execute("SELECT message, active FROM broadcast WHERE id=1").fetchone()
    db.close()
    return dict(broadcast_message=row["message"] if row and row["active"] and row["message"] else None)


class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.is_admin = bool(row["is_admin"])
        self.youtube_verified = bool(row["youtube_verified"]) if row["youtube_verified"] is not None else False


@login_manager.user_loader
def load_user(uid):
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return User(row) if row else None


def generate_recovery_code(length=6):
    """6-character alphanumeric, ambiguous characters (0/O, 1/I) excluded so
    it's easy to read/type back accurately."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


@app.route("/bg/<path:filename>")
def serve_background(filename):
    """
    Serves images out of templates/ directly, since that folder isn't
    normally web-accessible (Flask only serves static/ over HTTP by default).
    This bypasses that by manually streaming the file from disk.
    """
    return send_from_directory("templates", filename)


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        ip = request.remote_addr

        if not u or not p:
            return render_template("register.html", error="Fill both fields")

        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
            return render_template("register.html", error="Username taken")

        # Flagged for the admin panel only — registration itself is never
        # blocked by this, just the ability to actually create a VPS (see
        # vps_create()).
        is_vpn, vpn_label = ip_intel.is_vpn_or_proxy(ip)

        db.execute("""INSERT INTO users(username,password,signup_ip,created_at,is_vpn_signup,vpn_provider)
                     VALUES(?,?,?,?,?,?)""",
                   (u, generate_password_hash(p), ip, int(time.time()), int(is_vpn), vpn_label))
        db.commit()
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row and check_password_hash(row["password"], p):
            login_user(User(row), remember=True)

            # First successful login ever — generate the one-time recovery
            # code, hash it (never stored in plaintext), mark it shown so it
            # can never be displayed again after this single page load.
            if not row["recovery_code_shown"]:
                code = generate_recovery_code()
                db.execute("UPDATE users SET recovery_code_hash=?, recovery_code_shown=1 WHERE id=?",
                           (generate_password_hash(code), row["id"]))
                db.commit()
                session["show_recovery_code"] = code
                return redirect(url_for("recovery_code_display"))

            return redirect(url_for("admin" if row["is_admin"] else "dashboard"))
        return render_template("login.html", error="Bad credentials")
    return render_template("login.html")


@app.route("/recovery-code")
@login_required
def recovery_code_display():
    # Popped immediately so a page refresh (or anyone else with this session)
    # can't see it a second time — it only exists in the session for this one
    # redirect-then-render, never persisted anywhere in plaintext.
    code = session.pop("show_recovery_code", None)
    if not code:
        return redirect(url_for("dashboard"))
    return render_template("recovery_code.html", code=code)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        code = request.form.get("code", "").strip().upper()
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()

        if not row or not row["recovery_code_hash"] or not check_password_hash(row["recovery_code_hash"], code):
            return render_template("forgot_password.html", error="Username and recovery code don't match.")

        session["reset_user_id"] = row["id"]
        return redirect(url_for("reset_password"))
    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    uid = session.get("reset_user_id")
    if not uid:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        if not new_password or len(new_password) < 6:
            return render_template("reset_password.html", error="Password must be at least 6 characters.")
        db = get_db()
        db.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new_password), uid))
        db.commit()
        session.pop("reset_user_id", None)
        return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/account/delete", methods=["GET", "POST"])
@login_required
def delete_account():
    if request.method == "POST":
        code = request.form.get("code", "").strip().upper()
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id=?", (current_user.id,)).fetchone()

        if not row or not row["recovery_code_hash"] or not check_password_hash(row["recovery_code_hash"], code):
            return render_template("delete_account.html", error="Incorrect recovery code.")

        # Tear down ALL of their VPSes (a user can now have more than one,
        # granted via the admin panel) and clean up everything tied to this
        # account. Container teardown failure doesn't block account deletion
        # — an already-gone/broken container shouldn't leave someone stuck.
        all_vps = db.execute("SELECT * FROM vps WHERE user_id=?", (current_user.id,)).fetchall()
        for vps in all_vps:
            try:
                destroy_vps(vps["container_id"])
            except Exception as e:
                print(f"[DELETE ACCOUNT] Container teardown failed (continuing anyway): {e}")
            db.execute("DELETE FROM port_forwards WHERE vps_id=?", (vps["id"],))
        db.execute("DELETE FROM vps WHERE user_id=?", (current_user.id,))

        db.execute("DELETE FROM feedback WHERE user_id=?", (current_user.id,))
        db.execute("DELETE FROM users WHERE id=?", (current_user.id,))
        db.commit()

        logout_user()
        flash("Your account has been permanently deleted.")
        return redirect(url_for("login"))

    return render_template("delete_account.html")


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    all_vps = db.execute("SELECT * FROM vps WHERE user_id=? ORDER BY created_at ASC",
                          (current_user.id,)).fetchall()

    selected_id = request.args.get("vps_id", type=int)
    vps = None
    if selected_id:
        vps = next((v for v in all_vps if v["id"] == selected_id), None)
    if not vps and all_vps:
        vps = all_vps[0]

    # Catch a container that silently drifted out of sync with the DB (host
    # reboot, OOM kill, crash, manual `lxc stop`) so Start/Stop always
    # reflect reality instead of a stale DB row.
    if vps and vps["status"] in ("running", "stopped"):
        real_status = sync_status(vps["container_id"], vps["status"])
        if real_status != vps["status"]:
            db.execute("UPDATE vps SET status=? WHERE id=?", (real_status, vps["id"]))
            db.commit()
            vps = db.execute("SELECT * FROM vps WHERE id=?", (vps["id"],)).fetchone()

    feedback_rows = db.execute("""SELECT feedback.*, users.username FROM feedback
                                  JOIN users ON users.id = feedback.user_id
                                  ORDER BY feedback.created_at DESC LIMIT 20""").fetchall()
    queue_pos = queue.get_position(vps["id"]) if vps and vps["status"] in ("queued", "creating") else 0
    can_feedback = bool(vps and vps["status"] == "running" and vps["ssh_command"])
    forwards = db.execute("SELECT * FROM port_forwards WHERE vps_id=?", (vps["id"],)).fetchall() if vps else []
    can_forward = bool(vps and vps["status"] == "running")
    return render_template("dashboard.html", vps=vps, all_vps=all_vps, feedback_rows=feedback_rows,
                            queue_pos=queue_pos, slot_seconds=queue.SLOT_SECONDS,
                            can_feedback=can_feedback, forwards=forwards,
                            can_forward=can_forward, public_ip=PUBLIC_IPV4,
                            max_forwards=MAX_FORWARDS_PER_VPS)


@app.route("/vps/create", methods=["POST"])
@login_required
def vps_create():
    db = get_db()
    ip = request.remote_addr

    if db.execute("SELECT 1 FROM vps WHERE user_id=?", (current_user.id,)).fetchone():
        return "You already have a VPS", 403
    if db.execute("SELECT 1 FROM vps WHERE creator_ip=?", (ip,)).fetchone():
        return "This IP already owns a VPS", 403
    user_row = db.execute("SELECT signup_ip FROM users WHERE id=?", (current_user.id,)).fetchone()
    if db.execute("SELECT 1 FROM vps WHERE creator_ip=?", (user_row["signup_ip"],)).fetchone():
        return "Your signup IP already owns a VPS", 403

    # Live check — blocks creation outright while a VPN/proxy is on, on top
    # of the is_vpn_signup flag recorded at registration time (which only
    # informs the admin panel, doesn't block anything by itself).
    is_vpn, vpn_label = ip_intel.is_vpn_or_proxy(ip)
    if is_vpn:
        return f"VPN/proxy detected ({vpn_label}) — disable it and try again to create a VPS.", 403

    # Same "one VPS per IP" rule, extended across every node this one is
    # paired with — see node_mesh.py for the fail-open-per-peer tradeoff.
    found_elsewhere, other_node_url = node_mesh.check_ip_across_mesh(db, ip)
    if found_elsewhere:
        return f"This IP already owns a VPS on another node in the network ({other_node_url})", 403

    allowed, current = can_create_vps()
    if not allowed:
        return "NODE IS FULL!! PLEASE WAIT FOR ANOTHER NODE BEING DEPLOYED BY DXD", 503

    disk_allowed, disk_allocated, disk_budget, disk_reason = can_allocate_disk(STANDARD_VPS_DISK_GB)
    if not disk_allowed:
        return disk_reason or (
            f"Disk budget reached ({disk_allocated}/{disk_budget} GB used). "
            f"No new VPS can be created until space frees up — try again later."
        ), 503

    now = int(time.time())
    last_click = _last_create_click.get(ip, 0)
    if now - last_click < CREATE_DEBOUNCE_SECONDS:
        return "Please wait a few seconds before trying again.", 429
    _last_create_click[ip] = now

    cur = db.execute("INSERT INTO vps(user_id,container_id,creator_ip,created_at,status) VALUES(?,?,?,?,?)",
                      (current_user.id, "pending", ip, now, "queued"))
    db.commit()
    vps_id = cur.lastrowid

    queue.enqueue(current_user.id, vps_id)
    return redirect(url_for("vps_view", vps_id=vps_id))


def _build_vps(vps_id, user_id):
    """Called by the queue worker — one at a time, 15s apart. Marks 'creating'
    the moment it's actually dequeued and starts building, then 'running' or
    'failed' at the end. Never marks 'running' unless the sshx session is
    confirmed working (create_vps_container now raises instead of returning
    a null ssh_command)."""
    db = get_db()
    db.execute("UPDATE vps SET status='creating' WHERE id=?", (vps_id,))
    db.commit()
    db.close()
    try:
        cid, ssh = create_vps_container(f"vps-{user_id}", cpu_limit=4, ram_limit_mb=61440, disk_limit_gb=STANDARD_VPS_DISK_GB)
        db = get_db()
        db.execute("UPDATE vps SET container_id=?, ssh_command=?, status='running' WHERE id=?",
                   (cid, ssh, vps_id))
        db.commit()
        db.close()
    except Exception as e:
        db = get_db()
        db.execute("UPDATE vps SET status='failed', ssh_command=? WHERE id=?", (str(e), vps_id))
        db.commit()
        db.close()


def _build_vps_custom(vps_id, user_id, cpu_cores, ram_mb, disk_gb):
    """Same as _build_vps but with admin-specified specs, used for manually
    granted high-tier VPSes. Runs immediately in its own thread rather than
    going through the shared queue — an admin action, not a public signup,
    so it doesn't need to wait in line behind other builds."""
    db = get_db()
    db.execute("UPDATE vps SET status='creating' WHERE id=?", (vps_id,))
    db.commit()
    db.close()
    try:
        cid, ssh = create_vps_container(f"vps-{user_id}", cpu_limit=cpu_cores, ram_limit_mb=ram_mb, disk_limit_gb=disk_gb)
        db = get_db()
        db.execute("UPDATE vps SET container_id=?, ssh_command=?, status='running' WHERE id=?",
                   (cid, ssh, vps_id))
        db.commit()
        db.close()
    except Exception as e:
        db = get_db()
        db.execute("UPDATE vps SET status='failed', ssh_command=? WHERE id=?", (str(e), vps_id))
        db.commit()
        db.close()


@app.route("/vps/<int:vps_id>")
@login_required
def vps_view(vps_id):
    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return "Not found", 404
    if vps["status"] in ("running", "stopped"):
        real_status = sync_status(vps["container_id"], vps["status"])
        if real_status != vps["status"]:
            db.execute("UPDATE vps SET status=? WHERE id=?", (real_status, vps_id))
            db.commit()
            vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    queue_pos = queue.get_position(vps_id) if vps["status"] in ("queued", "creating") else 0
    return render_template("vps_view.html", vps=vps, queue_pos=queue_pos, slot_seconds=queue.SLOT_SECONDS)


@app.route("/vps/<int:vps_id>/queue_status")
@login_required
def vps_queue_status(vps_id):
    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return jsonify({"error": "no"}), 404
    pos = queue.get_position(vps_id)
    return jsonify({
        "status": vps["status"],
        "position": pos,
        "eta_seconds": pos * queue.SLOT_SECONDS if pos else 0,
        "ssh_command": vps["ssh_command"],
    })


@app.route("/vps/<int:vps_id>/dismiss", methods=["POST"])
@login_required
def vps_dismiss(vps_id):
    """Lets a user clear a failed build so they can try Create VPS again
    (the schema only allows one VPS row per user)."""
    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or vps["user_id"] != current_user.id:
        return "Not found", 404
    if vps["status"] != "failed":
        return "Only a failed build can be dismissed", 400
    db.execute("DELETE FROM vps WHERE id=?", (vps_id,))
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/vps/<int:vps_id>/logs")
@login_required
def vps_logs(vps_id):
    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return "Not found", 404

    @stream_with_context
    def gen():
        # container_id starts as the literal string "pending" until _build_vps()
        # is actually dequeued and finishes — poll the DB until it's replaced,
        # or the build fails. Wait generously since a deep queue can take a while
        # (queue depth * 15s pacing).
        cid = vps["container_id"]
        waited = 0
        max_wait = 600
        while cid == "pending" and waited < max_wait:
            time.sleep(2)
            waited += 2
            row = get_db().execute("SELECT container_id, status FROM vps WHERE id=?", (vps_id,)).fetchone()
            if not row:
                yield "data: VPS record no longer exists.\n\n"
                yield "data: [DONE]\n\n"
                return
            cid = row["container_id"]
            if row["status"] == "failed":
                yield f"data: Build failed: {cid}\n\n"
                yield "data: [DONE]\n\n"
                return

        if cid == "pending":
            yield "data: Build is taking too long, check back later.\n\n"
            yield "data: [DONE]\n\n"
            return

        for line in build_logs_stream(cid):
            yield f"data: {line}\n\n"
        yield "data: [DONE]\n\n"
    return Response(gen(), mimetype="text/event-stream")


@app.route("/vps/<int:vps_id>/stats")
@login_required
def vps_stats(vps_id):
    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return jsonify({"error": "no"}), 404
    if vps["status"] != "running":
        return jsonify({"error": "not running", "status": vps["status"]})
    try:
        return jsonify(get_container_stats(vps["container_id"], vps["created_at"]))
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/vps/<int:vps_id>/regen_ssh", methods=["POST"])
@login_required
def regen_ssh(vps_id):
    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps:
        flash("VPS not found")
        return redirect(url_for("dashboard"))
    if vps["user_id"] != current_user.id and not current_user.is_admin:
        flash("Not your VPS")
        return redirect(url_for("dashboard"))
    if vps["status"] != "running":
        flash("VPS must be running")
        return redirect(url_for("vps_view", vps_id=vps_id))
    if time.time() - vps["last_regen"] < 30:
        flash("Wait 30s between regens")
        return redirect(url_for("vps_view", vps_id=vps_id))
    try:
        # Note: this invalidates the old sshx link — anyone using the
        # previous URL (including the user's own open tab) loses access.
        new_url = regen_sshx(vps["container_id"])
        if not new_url:
            flash("Could not start a new terminal session")
            return redirect(url_for("vps_view", vps_id=vps_id))
        db.execute("UPDATE vps SET ssh_command=?, last_regen=? WHERE id=?",
                   (new_url, int(time.time()), vps_id))
        db.commit()
        flash("New terminal link generated")
    except Exception as e:
        flash(f"Failed to regenerate: {e}")
    return redirect(url_for("vps_view", vps_id=vps_id))


@app.route("/vps/<int:vps_id>/power/<action>", methods=["POST"])
@login_required
def vps_power(vps_id, action):
    if action not in ("start", "stop", "reinstall"):
        return "Unknown action", 400

    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps:
        flash("VPS not found")
        return redirect(url_for("dashboard"))
    if vps["user_id"] != current_user.id and not current_user.is_admin:
        flash("Not your VPS")
        return redirect(url_for("dashboard"))

    # Reconcile against reality first — e.g. don't refuse "start" just
    # because the DB still says "running" after the container actually
    # crashed or the host rebooted.
    if vps["status"] in ("running", "stopped"):
        real_status = sync_status(vps["container_id"], vps["status"])
        if real_status != vps["status"]:
            db.execute("UPDATE vps SET status=? WHERE id=?", (real_status, vps_id))
            db.commit()
            vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()

    debounce = REINSTALL_DEBOUNCE_SECONDS if action == "reinstall" else POWER_DEBOUNCE_SECONDS
    now = time.time()
    if now - _last_power_action.get(vps_id, 0) < debounce:
        flash("Please wait a bit before trying that again.")
        return redirect(url_for("dashboard", vps_id=vps_id))
    _last_power_action[vps_id] = now

    if action == "start":
        if vps["status"] != "stopped":
            flash("VPS must be stopped to start it")
            return redirect(url_for("dashboard", vps_id=vps_id))
        try:
            result = start_vps(vps["container_id"])
            if "error" in result:
                flash(f"Failed to start: {result['error']}")
            else:
                db.execute("UPDATE vps SET status='running' WHERE id=?", (vps_id,))
                db.commit()
                flash("VPS started")
        except Exception as e:
            flash(f"Failed to start: {e}")

    elif action == "stop":
        if vps["status"] != "running":
            flash("VPS must be running to stop it")
            return redirect(url_for("dashboard", vps_id=vps_id))
        try:
            result = stop_vps(vps["container_id"])
            if "error" in result:
                flash(f"Failed to stop: {result['error']}")
            else:
                db.execute("UPDATE vps SET status='stopped' WHERE id=?", (vps_id,))
                db.commit()
                flash("VPS stopped")
        except Exception as e:
            flash(f"Failed to stop: {e}")

    elif action == "reinstall":
        if vps["status"] not in ("running", "stopped", "failed"):
            flash("VPS can't be reinstalled while it's queued or already building")
            return redirect(url_for("dashboard", vps_id=vps_id))
        # Forwards point at devices on the container that's about to be
        # destroyed — meaningless (and would error on removal) against
        # whatever gets created in its place, so drop them now.
        db.execute("DELETE FROM port_forwards WHERE vps_id=?", (vps_id,))
        db.execute("UPDATE vps SET status='creating', ssh_command=NULL WHERE id=?", (vps_id,))
        db.commit()
        threading.Thread(
            target=_reinstall_vps_worker,
            args=(vps_id, vps["container_id"], f"vps-{vps['user_id']}"),
            daemon=True,
        ).start()
        flash("Reinstalling your VPS — this can take a minute or two.")

    return redirect(url_for("dashboard", vps_id=vps_id))


def _reinstall_vps_worker(vps_id, old_container_id, username):
    """Background worker for the 'reinstall' action — deletes the old
    container and builds a fresh one with the same specs, then updates the
    DB row. Mirrors _build_vps()'s failure handling: marks 'failed' with
    the error stashed in ssh_command rather than leaving the VPS stuck in
    'creating' forever."""
    try:
        new_cid, new_ssh = reinstall_vps(old_container_id, username)
        db = get_db()
        db.execute("UPDATE vps SET container_id=?, ssh_command=?, status='running' WHERE id=?",
                   (new_cid, new_ssh, vps_id))
        db.commit()
        db.close()
    except Exception as e:
        db = get_db()
        db.execute("UPDATE vps SET status='failed', ssh_command=? WHERE id=?", (str(e), vps_id))
        db.commit()
        db.close()


@app.route("/feedback", methods=["POST"])
@login_required
def submit_feedback():
    db = get_db()
    vps = db.execute(
        "SELECT * FROM vps WHERE user_id=? AND status='running' AND ssh_command IS NOT NULL LIMIT 1",
        (current_user.id,)
    ).fetchone()
    if not vps:
        return "You need at least one running VPS with working terminal access to leave feedback", 403

    try:
        stars = int(request.form.get("stars", 0))
    except ValueError:
        stars = 0
    if stars < 1 or stars > 5:
        return "Pick a star rating from 1 to 5", 400

    comment = request.form.get("comment", "").strip()[:500]
    db.execute("INSERT INTO feedback(user_id,stars,comment,created_at) VALUES(?,?,?,?)",
               (current_user.id, stars, comment, int(time.time())))
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/vps/<int:vps_id>/forward", methods=["POST"])
@login_required
def add_forward(vps_id):
    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or vps["user_id"] != current_user.id:
        return "Not found", 404
    if vps["status"] != "running":
        return "VPS must be running to add a port forward", 400

    count = db.execute("SELECT COUNT(*) c FROM port_forwards WHERE vps_id=?", (vps_id,)).fetchone()["c"]
    if count >= MAX_FORWARDS_PER_VPS:
        return f"Max {MAX_FORWARDS_PER_VPS} port forwards per VPS", 400

    try:
        container_port = int(request.form.get("container_port", 0))
    except ValueError:
        container_port = 0
    protocol = request.form.get("protocol", "tcp").lower()
    if protocol not in ("tcp", "udp"):
        return "Protocol must be tcp or udp", 400
    if container_port < 1 or container_port > 65535:
        return "Invalid container port", 400

    preferred_raw = request.form.get("host_port", "").strip()
    preferred_port = int(preferred_raw) if preferred_raw.isdigit() else None

    try:
        host_port, device_name = add_port_forward(vps["container_id"], container_port, protocol, preferred_port)
    except Exception as e:
        return f"Failed to add port forward: {e}", 500

    db.execute("""INSERT INTO port_forwards(vps_id,device_name,host_port,container_port,protocol,created_at)
                 VALUES(?,?,?,?,?,?)""",
               (vps_id, device_name, host_port, container_port, protocol, int(time.time())))
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/vps/<int:vps_id>/forward/<int:fwd_id>/delete", methods=["POST"])
@login_required
def delete_forward(vps_id, fwd_id):
    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or vps["user_id"] != current_user.id:
        return "Not found", 404
    fwd = db.execute("SELECT * FROM port_forwards WHERE id=? AND vps_id=?", (fwd_id, vps_id)).fetchone()
    if not fwd:
        return "Not found", 404
    try:
        remove_port_forward(vps["container_id"], fwd["device_name"])
    except Exception as e:
        return f"Failed to remove forward: {e}", 500
    db.execute("DELETE FROM port_forwards WHERE id=?", (fwd_id,))
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        return "Forbidden", 403
    db = get_db()
    rows = db.execute("""SELECT vps.*, users.username FROM vps
                         JOIN users ON users.id = vps.user_id""").fetchall()
    users = db.execute(
        "SELECT id, username, signup_ip, is_admin, created_at, recovery_code_shown, is_vpn_signup, vpn_provider FROM users"
    ).fetchall()
    queue_entries = queue.peek_all()
    host = get_host_capacity()
    broadcast = db.execute("SELECT message, active FROM broadcast WHERE id=1").fetchone()
    return render_template("admin.html", vpses=rows, users=users,
                            queue_length=queue.queue_length(), queue_entries=queue_entries,
                            host=host, broadcast=broadcast)


@app.route("/admin/broadcast", methods=["POST"])
@login_required
def admin_broadcast_set():
    """'Message All' — posts a site-wide banner shown to every user on
    every page (rendered via the broadcast_message context processor into
    base.html). Only one message is active at a time; posting a new one
    replaces whatever was there before."""
    if not current_user.is_admin:
        return "Forbidden", 403
    message = request.form.get("message", "").strip()[:500]
    if not message:
        flash("Message can't be empty")
        return redirect(url_for("admin"))
    db = get_db()
    db.execute("UPDATE broadcast SET message=?, active=1, updated_at=? WHERE id=1",
               (message, int(time.time())))
    db.commit()
    flash("Message posted to all users")
    return redirect(url_for("admin"))


@app.route("/admin/broadcast/clear", methods=["POST"])
@login_required
def admin_broadcast_clear():
    """'Stop Message' — hides the banner for everyone. Keeps the last
    message text in the DB (just flips active off) so re-posting the same
    thing later doesn't require retyping it — see the admin.html form,
    which prefills from the last message."""
    if not current_user.is_admin:
        return "Forbidden", 403
    db = get_db()
    db.execute("UPDATE broadcast SET active=0 WHERE id=1")
    db.commit()
    flash("Message removed")
    return redirect(url_for("admin"))


@app.route("/admin/grant-vps", methods=["POST"])
@login_required
def admin_grant_vps():
    if not current_user.is_admin:
        return "Forbidden", 403

    db = get_db()
    username = request.form.get("username", "").strip()

    try:
        ram_gb = int(request.form.get("ram_gb", 0))
        cpu_cores = int(request.form.get("cpu_cores", 0))
        disk_gb = int(request.form.get("disk_gb", 0))
    except ValueError:
        return "RAM/CPU/Disk must be numbers", 400

    if not username:
        return "Username required", 400
    if not (1 <= ram_gb <= ADMIN_MAX_RAM_GB):
        return f"RAM must be between 1 and {ADMIN_MAX_RAM_GB} GB", 400
    if not (1 <= cpu_cores <= ADMIN_MAX_CPU_CORES):
        return f"CPU must be between 1 and {ADMIN_MAX_CPU_CORES} cores", 400
    if not (1 <= disk_gb <= ADMIN_MAX_DISK_GB):
        return f"Disk must be between 1 and {ADMIN_MAX_DISK_GB} GB", 400

    # Refuse rather than silently under-deliver — LXD/LXCFS will clamp what
    # the container actually sees to the host's real capacity if you ask for
    # more than physically exists, without erroring. Better to tell the admin
    # the truth now than have them discover a "104GB" VPS is actually 64GB.
    host = get_host_capacity()
    if cpu_cores > host["cpu_cores"]:
        return (f"This host only has {host['cpu_cores']} CPU cores total — requesting {cpu_cores} "
                f"would silently get clamped down by LXD, not actually delivered. Lower the request."), 400
    if ram_gb * 1024 > host["ram_mb"]:
        return (f"This host only has {host['ram_mb'] // 1024}GB RAM total — requesting {ram_gb}GB "
                f"would silently get clamped down by LXD, not actually delivered. Lower the request."), 400

    # Disk is checked against the 6TB panel-wide BUDGET, not the host's real
    # physical disk — the real disk (~11TB) is currently unreliable as an
    # allocation ceiling since something already overran its expected usage
    # on it. This is a hard business-rule cap, separate from the physical
    # clamp checks above.
    disk_allowed, disk_allocated, disk_budget, disk_reason = can_allocate_disk(disk_gb)
    if not disk_allowed:
        return disk_reason or (
            f"Disk budget reached ({disk_allocated}/{disk_budget} GB used across all VPSes) — "
            f"granting {disk_gb}GB would exceed the panel's 6TB total disk budget. Free up space first."
        ), 400

    target = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not target:
        return "No user with that username", 404
    # No "already has a VPS" block here on purpose — this is the ONE path
    # that's allowed to give a user a second (or third...) VPS. Self-service
    # creation (vps_create()) still enforces one-per-user.

    allowed, current = can_create_vps()
    if not allowed:
        return "NODE IS FULL!! PLEASE WAIT FOR ANOTHER NODE BEING DEPLOYED BY DXD", 503

    cur = db.execute("INSERT INTO vps(user_id,container_id,creator_ip,created_at,status) VALUES(?,?,?,?,?)",
                      (target["id"], "pending", "admin-grant", int(time.time()), "creating"))
    db.commit()
    vps_id = cur.lastrowid  # NOT a SELECT WHERE user_id=? lookup — a user can now
    # have multiple VPS rows, which would make that query ambiguous and risk
    # grabbing the wrong (pre-existing) VPS instead of the one just inserted.

    threading.Thread(
        target=_build_vps_custom,
        args=(vps_id, target["id"], cpu_cores, ram_gb * 1024, disk_gb),
        daemon=True,
    ).start()

    return redirect(url_for("admin"))


@app.route("/admin/vps/<int:vps_id>/<action>", methods=["POST"])
@login_required
def admin_vps_action(vps_id, action):
    if not current_user.is_admin:
        return "Forbidden", 403
    db = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps:
        return "Not found", 404
    if action == "suspend":
        suspend_vps(vps["container_id"])
        db.execute("UPDATE vps SET status='suspended' WHERE id=?", (vps_id,))
    elif action == "unsuspend":
        unsuspend_vps(vps["container_id"])
        db.execute("UPDATE vps SET status='running' WHERE id=?", (vps_id,))
    elif action == "delete":
        destroy_vps(vps["container_id"])
        # Clean up rows that reference this vps_id — nothing reuses
        # AUTOINCREMENT ids so these can't collide with a future VPS, but
        # they'd otherwise sit in the DB forever pointing at nothing.
        db.execute("DELETE FROM port_forwards WHERE vps_id=?", (vps_id,))
        db.execute("DELETE FROM vps WHERE id=?", (vps_id,))
    db.commit()
    return redirect(url_for("admin"))


@app.route("/admin/nodes", methods=["GET", "POST"])
@login_required
def admin_nodes():
    if not current_user.is_admin:
        return "Forbidden", 403
    db = get_db()
    result = None
    if request.method == "POST":
        remote_url = request.form.get("remote_url", "").strip()
        remote_code = request.form.get("remote_code", "").strip()
        if not remote_url or not remote_code:
            result = (False, "Enter both the remote node's URL and its 8-digit code.")
        else:
            result = node_mesh.pair_with_node(db, remote_url, remote_code)
    nodes = node_mesh.list_nodes(db)
    return render_template("admin_nodes.html", nodes=nodes, result=result,
                            my_code=node_mesh.NODE_CODE, my_url=node_mesh.NODE_PUBLIC_URL,
                            max_vps=MAX_TOTAL_VPS)


# --- Internal mesh API — called BY other nodes, not by browsers/users ---

@app.route("/api/node/pair", methods=["POST"])
def api_node_pair():
    """
    Another node's admin is trying to connect to THIS node. Authenticated
    purely by knowing this node's live NODE_CODE (see node_mesh.py's
    docstring for the trust model this relies on).
    """
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    requester_url = data.get("my_url", "")
    db = get_db()
    ok, result = node_mesh.accept_pairing(db, code, requester_url)
    if not ok:
        return jsonify({"error": result}), 403
    return jsonify({"shared_secret": result})


@app.route("/api/node/check_ip")
def api_node_check_ip():
    """Called by a paired node asking whether the given IP already owns a
    VPS on THIS node. Requires a valid shared secret from a prior pairing."""
    db = get_db()
    peer_url = request.headers.get("X-Node-Url", "")
    peer_secret = request.headers.get("X-Node-Secret", "")
    if not node_mesh.verify_peer_secret(db, peer_url, peer_secret):
        return jsonify({"error": "unauthorized"}), 403

    ip = request.args.get("ip", "")
    if not ip:
        return jsonify({"error": "missing ip"}), 400

    has_vps = bool(db.execute("SELECT 1 FROM vps WHERE creator_ip=?", (ip,)).fetchone())
    if not has_vps:
        # Also cover "signed up from this IP, VPS created from elsewhere" —
        # same logic vps_create() already applies locally.
        has_vps = bool(db.execute(
            "SELECT 1 FROM vps JOIN users ON users.id = vps.user_id WHERE users.signup_ip=?", (ip,)
        ).fetchone())
    return jsonify({"has_vps": has_vps})


@app.route("/api/notifications/latest")
@login_required
def api_notifications_latest():
    """Polled from base.html to drive the browser Notification + in-page
    banner when e.g. a new node connects. See node_mesh.py's docstring for
    why this isn't real background push."""
    since = request.args.get("since", type=int, default=0)
    db = get_db()
    rows = db.execute(
        "SELECT id, message, created_at FROM notifications WHERE created_at > ? ORDER BY created_at ASC LIMIT 20",
        (since,)
    ).fetchall()
    return jsonify({"notifications": [dict(r) for r in rows], "now": int(time.time())})


if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print(f" NODE PAIRING CODE: {node_mesh.NODE_CODE}")
    print(" Give this code to another node's admin so THEY")
    print(" can connect their node to this one (or vice versa)")
    print(" from their /admin/nodes page.")
    if node_mesh.NODE_PUBLIC_URL:
        print(f" Public URL: {node_mesh.NODE_PUBLIC_URL}")
    else:
        print(" WARNING: NODE_PUBLIC_URL is not set — this node cannot")
        print(" be paired with (or pair out to) another node until it is.")
    print("=" * 50)
    start_monitor()
    queue.start_queue_worker(_build_vps)
    app.run(host="0.0.0.0", port=5000, threaded=True)
