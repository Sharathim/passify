import os
import sqlite3
import hashlib
import secrets
import string
import time
import json
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict, deque
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    g,
    session,
    redirect,
    url_for,
    flash,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import re

# Configuration
DATABASE = "otp.db"
OTP_LENGTH_DEFAULT = 12
OTP_LENGTH_MAX = 64
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_urlsafe(32))

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Rate limiting setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Security tracking
suspicious_ips = defaultdict(lambda: {"count": 0, "hour": -1, "blocked_until": 0})
generation_patterns = defaultdict(deque)
session_start_times = {}
failed_login_attempts = defaultdict(lambda: {"count": 0, "last_attempt": 0})

# Whitelist for allowed user agents (basic bot detection)
ALLOWED_USER_AGENTS = re.compile(r"(Mozilla|Chrome|Safari|Firefox|Edge)", re.IGNORECASE)


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()

    # OTP table
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            length INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            client_ip TEXT,
            user_agent TEXT
        )
    """
    )

    # Users table for authentication
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT,
            is_active INTEGER DEFAULT 1,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """
    )

    # Sessions table
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            client_ip TEXT,
            user_agent TEXT,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """
    )

    # Security logs table
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            client_ip TEXT,
            user_agent TEXT,
            details TEXT,
            severity TEXT DEFAULT 'INFO'
        )
    """
    )

    db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db:
        db.close()


def log_security_event(event_type, details="", severity="INFO"):
    """Log security events for monitoring"""
    db = get_db()
    client_ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")

    db.execute(
        """
        INSERT INTO security_logs (timestamp, event_type, client_ip, user_agent, details, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
        (
            datetime.utcnow().isoformat(),
            event_type,
            client_ip,
            user_agent,
            details,
            severity,
        ),
    )
    db.commit()


def get_client_ip():
    """Get real client IP address"""
    return request.environ.get(
        "HTTP_X_REAL_IP",
        request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr),
    )


def validate_request():
    """Basic request validation to filter obvious bots"""
    user_agent = request.headers.get("User-Agent", "")

    # Check for missing or suspicious user agent
    if not user_agent or not ALLOWED_USER_AGENTS.search(user_agent):
        log_security_event("SUSPICIOUS_USER_AGENT", f"User-Agent: {user_agent}", "WARN")
        return False

    # Check for bot indicators
    bot_indicators = ["bot", "crawler", "spider", "scraper", "curl", "wget"]
    if any(indicator in user_agent.lower() for indicator in bot_indicators):
        log_security_event("BOT_DETECTED", f"User-Agent: {user_agent}", "WARN")
        return False

    # Check for required headers on POST requests
    if request.method == "POST":
        if not request.headers.get("Content-Type"):
            log_security_event("MISSING_CONTENT_TYPE", "", "WARN")
            return False

    return True


def check_suspicious_activity():
    """Check for suspicious IP activity"""
    client_ip = get_client_ip()
    current_hour = datetime.now().hour
    current_time = time.time()

    # Check if IP is currently blocked
    if suspicious_ips[client_ip]["blocked_until"] > current_time:
        return False

    # Reset counter if new hour
    if suspicious_ips[client_ip]["hour"] != current_hour:
        suspicious_ips[client_ip] = {
            "count": 1,
            "hour": current_hour,
            "blocked_until": 0,
        }
    else:
        suspicious_ips[client_ip]["count"] += 1

    # Block if too many requests
    if suspicious_ips[client_ip]["count"] > 100:  # 100 requests per hour
        suspicious_ips[client_ip]["blocked_until"] = (
            current_time + 3600
        )  # Block for 1 hour
        log_security_event(
            "IP_BLOCKED",
            f"IP: {client_ip}, Requests: {suspicious_ips[client_ip]['count']}",
            "HIGH",
        )
        return False

    return True


def detect_bot_pattern(client_ip, length, sets):
    """Detect repetitive bot-like patterns"""
    pattern_key = f"{client_ip}:{length}:{hash(str(sorted(sets.items())))}"
    current_time = time.time()

    # Clean old patterns (older than 1 hour)
    while (
        generation_patterns[pattern_key]
        and current_time - generation_patterns[pattern_key][0] > 3600
    ):
        generation_patterns[pattern_key].popleft()

    generation_patterns[pattern_key].append(current_time)

    # Check if same pattern repeated too often
    if len(generation_patterns[pattern_key]) > 20:  # 20 identical requests per hour
        log_security_event("BOT_PATTERN_DETECTED", f"Pattern: {pattern_key}", "HIGH")
        return True

    return False


def check_honeypot():
    """Check honeypot field"""
    if request.is_json:
        data = request.get_json()
        if data and data.get("honeypot"):
            log_security_event("HONEYPOT_TRIGGERED", "", "HIGH")
            return False
    return True


def require_auth(f):
    """Decorator to require authentication"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        # Validate session
        if not validate_session():
            session.clear()
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


def validate_session():
    """Validate current session"""
    if "user_id" not in session or "session_token" not in session:
        return False

    db = get_db()
    cur = db.execute(
        """
        SELECT s.*, u.is_active, u.locked_until FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_id = ? AND s.is_active = 1 AND s.expires_at > ?
    """,
        (session["session_token"], datetime.utcnow().isoformat()),
    )

    session_data = cur.fetchone()
    if not session_data:
        return False

    # Check if user is locked
    if session_data["locked_until"]:
        lock_time = datetime.fromisoformat(session_data["locked_until"])
        if lock_time > datetime.utcnow():
            return False

    return session_data["is_active"] == 1


def create_session(user_id):
    """Create a new session"""
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=24)  # 24 hour session

    db = get_db()
    db.execute(
        """
        INSERT INTO sessions (session_id, user_id, created_at, expires_at, client_ip, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
        (
            session_id,
            user_id,
            datetime.utcnow().isoformat(),
            expires_at.isoformat(),
            get_client_ip(),
            request.headers.get("User-Agent", ""),
        ),
    )
    db.commit()

    session["user_id"] = user_id
    session["session_token"] = session_id
    return session_id


# Security middleware
@app.before_request
def security_middleware():
    # Skip security checks for login/register pages
    if request.endpoint in ["login", "register", "static"]:
        return

    # Validate request
    if not validate_request():
        return jsonify({"error": "Invalid request"}), 403

    # Check suspicious activity
    if not check_suspicious_activity():
        return jsonify({"error": "Rate limit exceeded"}), 429

    # Check honeypot
    if not check_honeypot():
        return jsonify({"error": "Invalid request"}), 403


with app.app_context():
    init_db()


# Authentication routes
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("login.html")

        client_ip = get_client_ip()

        # Check for too many failed attempts
        if failed_login_attempts[client_ip]["count"] >= 5:
            time_diff = time.time() - failed_login_attempts[client_ip]["last_attempt"]
            if time_diff < 300:  # 5 minutes lockout
                flash("Too many failed attempts. Try again later.", "error")
                return render_template("login.html")
            else:
                failed_login_attempts[client_ip] = {"count": 0, "last_attempt": 0}

        db = get_db()
        cur = db.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
        )
        user = cur.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            # Check if user is locked
            if user["locked_until"]:
                lock_time = datetime.fromisoformat(user["locked_until"])
                if lock_time > datetime.utcnow():
                    flash("Account is temporarily locked", "error")
                    return render_template("login.html")

            # Reset failed attempts for this user
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )

            # Update last login
            db.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), user["id"]),
            )
            db.commit()

            # Create session
            create_session(user["id"])

            # Reset IP failed attempts
            failed_login_attempts[client_ip] = {"count": 0, "last_attempt": 0}

            log_security_event("LOGIN_SUCCESS", f"User: {username}")
            return redirect(url_for("index"))
        else:
            # Record failed attempt
            failed_login_attempts[client_ip]["count"] += 1
            failed_login_attempts[client_ip]["last_attempt"] = time.time()

            if user:  # User exists but wrong password
                new_failed_count = user["failed_attempts"] + 1
                locked_until = None

                if new_failed_count >= 5:  # Lock account after 5 failed attempts
                    locked_until = (
                        datetime.utcnow() + timedelta(minutes=30)
                    ).isoformat()

                db.execute(
                    """
                    UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?
                """,
                    (new_failed_count, locked_until, user["id"]),
                )
                db.commit()

            log_security_event("LOGIN_FAILED", f"Username: {username}", "WARN")
            flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()

        # Validation
        if not username or len(username) < 3:
            flash("Username must be at least 3 characters", "error")
            return render_template("register.html")

        if not password or len(password) < 8:
            flash("Password must be at least 8 characters", "error")
            return render_template("register.html")

        # Check password strength
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)", password):
            flash("Password must contain uppercase, lowercase, and numbers", "error")
            return render_template("register.html")

        db = get_db()

        # Check if username exists
        cur = db.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            flash("Username already exists", "error")
            return render_template("register.html")

        # Create user
        password_hash = generate_password_hash(password)
        try:
            cur = db.execute(
                """
                INSERT INTO users (username, password_hash, email, created_at)
                VALUES (?, ?, ?, ?)
            """,
                (username, password_hash, email, datetime.utcnow().isoformat()),
            )
            db.commit()

            log_security_event("USER_REGISTERED", f"Username: {username}")
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            flash("Error creating account", "error")
            log_security_event(
                "REGISTRATION_ERROR", f"Username: {username}, Error: {str(e)}", "ERROR"
            )

    return render_template("register.html")


@app.route("/logout")
def logout():
    if "session_token" in session:
        # Deactivate session in database
        db = get_db()
        db.execute(
            "UPDATE sessions SET is_active = 0 WHERE session_id = ?",
            (session["session_token"],),
        )
        db.commit()

    session.clear()
    return redirect(url_for("login"))


# Main application routes
@app.route("/", methods=["GET"])
@require_auth
def index():
    # Create session tracking for timing validation
    session_id = secrets.token_urlsafe(16)
    session_start_times[session_id] = time.time()
    return render_template("index.html", session_id=session_id)


def generate_otp(length, sets, strict=True):
    charsets = []
    if sets.get("uppercase"):
        charsets.append(string.ascii_uppercase)
    if sets.get("lowercase"):
        charsets.append(string.ascii_lowercase)
    if sets.get("digits"):
        charsets.append(string.digits)
    if sets.get("special"):
        charsets.append(SPECIAL_CHARS)

    if not charsets:
        raise ValueError("No character sets selected.")

    all_chars = "".join(charsets)
    if strict and length >= len(charsets):
        # Ensure at least one char from each set
        otp = [secrets.choice(cs) for cs in charsets]
        otp += [secrets.choice(all_chars) for _ in range(length - len(charsets))]
        secrets.SystemRandom().shuffle(otp)
        return "".join(otp)
    else:
        return "".join(secrets.choice(all_chars) for _ in range(length))


def hash_otp(otp):
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def store_otp_hash(otp_hash, length):
    db = get_db()
    client_ip = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")

    db.execute(
        """
        INSERT INTO otps (hash, timestamp, length, used, client_ip, user_agent) 
        VALUES (?, ?, ?, 0, ?, ?)
    """,
        (otp_hash, datetime.utcnow().isoformat(), length, client_ip, user_agent),
    )
    db.commit()


def otp_hash_exists(otp_hash):
    db = get_db()
    cur = db.execute("SELECT id FROM otps WHERE hash = ?", (otp_hash,))
    return cur.fetchone() is not None


def mark_otp_used(otp_hash):
    db = get_db()
    db.execute("UPDATE otps SET used = 1 WHERE hash = ?", (otp_hash,))
    db.commit()


@app.route("/api/generate", methods=["POST"])
@limiter.limit("10 per minute")
@require_auth
def api_generate():
    try:
        req = request.get_json(force=True)

        # Timing validation
        session_id = req.get("session_id")
        if session_id in session_start_times:
            time_diff = time.time() - session_start_times[session_id]
            if time_diff < 1:  # Request too fast, likely automated
                log_security_event(
                    "FAST_REQUEST_DETECTED", f"Time diff: {time_diff}", "WARN"
                )
                return jsonify({"error": "Request too fast"}), 429
            # Clean up old session
            del session_start_times[session_id]

        length = int(req.get("length", OTP_LENGTH_DEFAULT))
        strict = bool(req.get("strict", True))
        sets = req.get(
            "sets",
            {
                "uppercase": True,
                "lowercase": True,
                "digits": True,
                "special": True,
            },
        )

        if not (4 <= length <= OTP_LENGTH_MAX):
            return jsonify({"error": f"Length must be 4-{OTP_LENGTH_MAX}"}), 400

    except Exception:
        return jsonify({"error": "Invalid request data"}), 400

    if not any(sets.values()):
        return jsonify({"error": "At least one character set must be selected."}), 400

    # Check for bot patterns
    client_ip = get_client_ip()
    if detect_bot_pattern(client_ip, length, sets):
        return jsonify({"error": "Suspicious activity detected"}), 429

    # Generate OTP with collision detection
    for attempt in range(10):  # Increased attempts
        try:
            otp = generate_otp(length, sets, strict)
        except Exception as e:
            log_security_event("OTP_GENERATION_ERROR", str(e), "ERROR")
            return jsonify({"error": str(e)}), 400

        otp_hash = hash_otp(otp)
        if not otp_hash_exists(otp_hash):
            store_otp_hash(otp_hash, length)
            db = get_db()
            cur = db.execute("SELECT COUNT(*) FROM otps")
            total_count = cur.fetchone()[0]

            log_security_event(
                "OTP_GENERATED", f"Length: {length}, User: {session.get('user_id')}"
            )
            return jsonify({"otp": otp, "length": length, "total_count": total_count})

    log_security_event("OTP_GENERATION_FAILED", "Too many collisions", "WARN")
    return jsonify({"error": "Failed to generate unique OTP, try again"}), 500


@app.route("/api/consume", methods=["POST"])
@limiter.limit("20 per minute")
@require_auth
def api_consume():
    req = request.get_json(force=True)
    otp = req.get("otp", "")
    if not otp:
        return jsonify({"error": "No OTP provided"}), 400

    otp_hash = hash_otp(otp)
    db = get_db()
    cur = db.execute("SELECT used FROM otps WHERE hash = ?", (otp_hash,))
    row = cur.fetchone()

    if not row:
        log_security_event("OTP_NOT_FOUND", "", "WARN")
        return jsonify({"error": "OTP not found"}), 404

    if row["used"]:
        log_security_event("OTP_ALREADY_USED", "", "WARN")
        return jsonify({"error": "OTP already marked used"}), 400

    mark_otp_used(otp_hash)
    log_security_event("OTP_CONSUMED", f"User: {session.get('user_id')}")
    return jsonify({"ok": True})


@app.route("/api/metrics")
@require_auth
def api_metrics():
    db = get_db()
    cur = db.execute("SELECT COUNT(*) FROM otps")
    total_count = cur.fetchone()[0]
    return jsonify({"total_count": total_count})


# Admin routes (optional)
@app.route("/admin/logs")
@require_auth
def admin_logs():
    # Only show to admin users (you can add role-based access)
    db = get_db()
    cur = db.execute(
        """
        SELECT * FROM security_logs 
        ORDER BY timestamp DESC LIMIT 100
    """
    )
    logs = cur.fetchall()
    return jsonify([dict(log) for log in logs])


@app.after_request
def set_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )

    # Only set no-cache for sensitive endpoints
    if request.endpoint in ["api_generate", "api_consume", "login", "register"]:
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, proxy-revalidate"
        )
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


if __name__ == "__main__":
    # Create default admin user if none exists
    with app.app_context():
        db = get_db()
        cur = db.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            admin_password = secrets.token_urlsafe(12)
            password_hash = generate_password_hash(admin_password)
            db.execute(
                """
                INSERT INTO users (username, password_hash, email, created_at)
                VALUES (?, ?, ?, ?)
            """,
                (
                    "admin",
                    password_hash,
                    "admin@localhost",
                    datetime.utcnow().isoformat(),
                ),
            )
            db.commit()
            print(f"\n🔐 Default admin account created:")
            print(f"Username: admin")
            print(f"Password: {admin_password}")
            print(f"Please change this password after first login!\n")

    app.run(debug=False, host="127.0.0.1", port=5003)
