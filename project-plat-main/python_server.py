import os
import re
import sqlite3
import base64
import hashlib
import hmac
import secrets
import json
import smtplib
from datetime import datetime, timedelta
from pathlib import Path
from email.message import EmailMessage

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"
SESSION_SECRET = os.getenv(
    "SESSION_SECRET", "replace-this-in-production-with-long-random-secret"
)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@vss.local").strip().lower()
ADMIN_INVITE_CODE = os.getenv("ADMIN_INVITE_CODE", "ADMIN123").strip()
ADMIN_INVITE_CODE_NORMALIZED = ADMIN_INVITE_CODE.upper()
SESSION_HTTPS_ONLY = os.getenv("NODE_ENV", "development") == "production"
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "465").strip())
SMTP_USER = (os.getenv("SMTP_USER") or os.getenv("GMAIL_ADDRESS") or "").strip()
SMTP_PASS = (os.getenv("SMTP_PASS") or os.getenv("GMAIL_APP_PASSWORD") or "").strip()
SMTP_FROM = (os.getenv("SMTP_FROM") or SMTP_USER or "").strip()
AUTH_MFA_ENABLED = os.getenv("AUTH_MFA_ENABLED", "true").strip().lower() != "false"
AUTH_LOCKOUT_MAX_ATTEMPTS = max(int(os.getenv("AUTH_LOCKOUT_MAX_ATTEMPTS", "5")), 3)
AUTH_LOCKOUT_MINUTES = max(int(os.getenv("AUTH_LOCKOUT_MINUTES", "15")), 5)
AUTH_MFA_EMAIL_ACTIVE = AUTH_MFA_ENABLED and bool(SMTP_USER and SMTP_PASS and SMTP_FROM)

app = FastAPI(title="Virtual Support System API (Python)")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="vss.sid",
    same_site="lax",
    https_only=SESSION_HTTPS_ONLY,
    max_age=60 * 60 * 24,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response


class SignUpPayload(BaseModel):
    fullName: str
    role: str = "student"
    adminCode: str | None = None
    email: str
    password: str


class SignInPayload(BaseModel):
    email: str
    password: str


class SignInMfaPayload(BaseModel):
    code: str


class ChatPayload(BaseModel):
    message: str


class AttendanceMarkPayload(BaseModel):
    status: str
    date: str | None = None


class UserRolePayload(BaseModel):
    role: str


class TicketStatusPayload(BaseModel):
    status: str


class ForgotPasswordPayload(BaseModel):
    email: str


class ResetPasswordPayload(BaseModel):
    email: str
    code: str
    password: str


class VerifyEmailPayload(BaseModel):
    email: str
    code: str


class MaterialCreatePayload(BaseModel):
    title: str
    description: str = ""


def normalize_email(value: str) -> str:
    return value.strip().lower()


def is_valid_email(value: str) -> bool:
    return re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", value) is not None


def sanitize_text(value: str, max_len: int = 255) -> str:
    return re.sub(r"[\x00-\x1F\x7F]", " ", str(value or "")).strip()[:max_len]


def is_valid_name(name: str) -> bool:
    return re.match(r"^[A-Za-z][A-Za-z\s.'-]{1,79}$", name or "") is not None


def is_strong_password(password: str) -> bool:
    return (
        isinstance(password, str)
        and len(password) >= 8
        and re.search(r"[a-z]", password) is not None
        and re.search(r"[A-Z]", password) is not None
        and re.search(r"[0-9]", password) is not None
        and re.search(r"[^A-Za-z0-9]", password) is not None
    )


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 260000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("utf-8"),
        base64.b64encode(dk).decode("utf-8"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iter_str, salt_b64, hash_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


def generate_nlp_reply(input_text: str, history: list | None = None) -> str:
    text = str(input_text or "").strip()
    lower = text.lower()
    ticket_match = re.search(r"\b(?:ticket|case|ref)\s*#?\s*([a-z0-9-]{4,})\b", text, re.I)
    history = history or []
    last_user = None
    for item in reversed(history):
        if item.get("role") == "user":
            last_user = item.get("content", "")
            break

    if not text:
        return "Please type your question so I can help."
    if re.search(r"\b(hi|hello|hey|good morning|good afternoon)\b", lower):
        return "Hello. I am your AI support assistant. How can I help you today?"
    if re.search(r"\b(password|reset|forgot)\b", lower):
        return "For password concerns, please contact your administrator for account assistance."
    if re.search(r"\b(hour|open|schedule|time)\b", lower):
        return "Support is available Monday to Friday, 8:00 AM to 6:00 PM (local time)."
    if re.search(r"\b(price|pricing|plan|subscription)\b", lower):
        return "Pricing depends on your selected support package. I can connect you to sales for exact plan details."
    if ticket_match:
        return f"I found your reference {ticket_match.group(1)}. For status updates, please share your registered email or contact live support."
    if re.search(r"\b(thank|thanks)\b", lower):
        return "You are welcome. If you need anything else, I am here."
    if re.search(r"^\s*(who are you|what can you do)\s*\??$", text, re.I):
        return "I am your virtual assistant. I can handle general questions and also help with support workflows like tickets, attendance, and account concerns."
    if re.search(r"^(explain|define|summarize|compare|how|why|what|when|where)\b", lower):
        return "Good question. I can give a concise explanation. If you want, I can also provide step-by-step details or a simpler version."
    if last_user and "more" in lower:
        return f'Continuing from your last topic: "{last_user}". Tell me if you want a short answer, detailed answer, or examples.'
    return "I can help with open questions too. Share your topic clearly, and I will answer directly with practical steps when needed."


def trim_chat_history(history: list, max_items: int = 12) -> list:
    if not isinstance(history, list):
        return []
    out = []
    for item in history[-max_items:]:
        role = "assistant" if item.get("role") == "assistant" else "user"
        content = str(item.get("content", ""))[:1000]
        out.append({"role": role, "content": content})
    return out


def get_welcome_message() -> dict:
    return {
        "role": "assistant",
        "content": "Hello. I can handle open-ended conversations. Ask anything, and I will keep context across messages.",
    }


def can_use_attendance(request: Request) -> bool:
    user_id = request.session.get("user_id")
    if not user_id:
        return False
    role = str(request.session.get("role", "")).strip().lower()
    email = str(request.session.get("email", "")).strip().lower()
    if role == "administrator" or email == ADMIN_EMAIL:
        return True
    return role == "professor"


def is_professor_session(request: Request) -> bool:
    if not request.session.get("user_id"):
        return False
    return str(request.session.get("role", "")).strip().lower() == "professor"


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              full_name TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              role TEXT NOT NULL DEFAULT 'student',
              email_verified INTEGER NOT NULL DEFAULT 0,
              password_hash TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        cols = conn.execute("PRAGMA table_info(users)").fetchall()
        if not any(col["name"] == "role" for col in cols):
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'")
        if not any(col["name"] == "email_verified" for col in cols):
            conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_chain (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_type TEXT NOT NULL,
              user_email TEXT,
              payload_json TEXT NOT NULL,
              prev_hash TEXT NOT NULL,
              entry_hash TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attendance_records (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_email TEXT NOT NULL,
              attendance_date TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('present','late','absent')),
              created_at TEXT NOT NULL,
              UNIQUE(user_email, attendance_date)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_settings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_email TEXT NOT NULL UNIQUE,
              notifications_enabled INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS support_tickets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              public_id TEXT NOT NULL UNIQUE,
              user_email TEXT NOT NULL,
              subject TEXT NOT NULL,
              description TEXT NOT NULL,
              priority TEXT NOT NULL CHECK(priority IN ('low','medium','high')),
              status TEXT NOT NULL CHECK(status IN ('open','in_progress','resolved')) DEFAULT 'open',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS material_activities (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              title TEXT NOT NULL,
              description TEXT NOT NULL,
              created_by_email TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS quizzes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              title TEXT NOT NULL,
              description TEXT NOT NULL,
              quiz_type TEXT NOT NULL DEFAULT 'quiz',
              created_by_email TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_email TEXT NOT NULL,
              token_hash TEXT NOT NULL UNIQUE,
              expires_at TEXT NOT NULL,
              used INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_verification_codes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_email TEXT NOT NULL,
              code_hash TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              used INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_email TEXT NOT NULL UNIQUE,
              failed_attempts INTEGER NOT NULL DEFAULT 0,
              locked_until TEXT,
              updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_mfa_codes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_email TEXT NOT NULL,
              code_hash TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              used INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_last_audit_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["entry_hash"] if row else "GENESIS"


def append_audit_event(conn: sqlite3.Connection, event_type: str, user_email: str, payload: dict):
    prev_hash = get_last_audit_hash(conn)
    created_at = datetime.utcnow().isoformat()
    payload_json = json.dumps(payload or {}, separators=(",", ":"), sort_keys=True)
    entry_hash = sha256_hex(
        f"{prev_hash}|{event_type}|{user_email or ''}|{payload_json}|{created_at}"
    )
    conn.execute(
        "INSERT INTO audit_chain (event_type, user_email, payload_json, prev_hash, entry_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (event_type, user_email, payload_json, prev_hash, entry_hash, created_at),
    )
    return entry_hash


def verify_audit_rows(rows) -> bool:
    prev = "GENESIS"
    for row in rows:
        expected = sha256_hex(
            f"{prev}|{row['event_type']}|{row['user_email'] or ''}|{row['payload_json']}|{row['created_at']}"
        )
        if row["prev_hash"] != prev or row["entry_hash"] != expected:
            return False
        prev = row["entry_hash"]
    return True


def get_attendance_summary(conn: sqlite3.Connection, attendance_date: str) -> dict:
    total_row = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()
    rows = conn.execute(
        "SELECT status, COUNT(*) AS count FROM attendance_records WHERE attendance_date = ? GROUP BY status",
        (attendance_date,),
    ).fetchall()

    counts = {"present": 0, "late": 0, "absent": 0}
    for row in rows:
        status = row["status"]
        if status in counts:
            counts[status] = row["count"]

    total_students = total_row["total"] if total_row else 0
    computed_absent = max(total_students - counts["present"] - counts["late"], 0)
    absent = counts["absent"] if counts["absent"] > 0 else computed_absent

    return {
        "date": attendance_date,
        "totalStudents": total_students,
        "present": counts["present"],
        "late": counts["late"],
        "absent": absent,
    }


def upsert_attendance(
    conn: sqlite3.Connection, user_email: str, attendance_date: str, status: str
) -> None:
    conn.execute(
        """
        INSERT INTO attendance_records (user_email, attendance_date, status, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_email, attendance_date) DO UPDATE SET
          status = excluded.status,
          created_at = excluded.created_at
        """,
        (user_email, attendance_date, status, datetime.utcnow().isoformat()),
    )
    conn.commit()


def list_attendance_by_date(conn: sqlite3.Connection, attendance_date: str):
    return conn.execute(
        """
        SELECT
          ar.user_email,
          ar.status,
          ar.created_at,
          u.full_name
        FROM attendance_records ar
        LEFT JOIN users u ON u.email = ar.user_email
        WHERE ar.attendance_date = ?
        ORDER BY ar.user_email ASC
        """,
        (attendance_date,),
    ).fetchall()


def build_notifications(
    user_email: str,
    attendance_summary: dict,
    chain_valid: bool,
    tickets,
    role: str = "",
    activities: list | None = None,
) -> dict:
    now = datetime.utcnow().isoformat()
    base = int(datetime.utcnow().timestamp())
    seq = 0

    def make_id(prefix: str) -> str:
        nonlocal seq
        seq += 1
        return f"{prefix}-{base}-{seq}"

    actionable = [
        t
        for t in (tickets or [])
        if str(t["status"]).lower() not in {"resolved", "closed"}
    ]
    high_open = [t for t in actionable if str(t["priority"]).lower() == "high"]
    medium_open = [t for t in actionable if str(t["priority"]).lower() == "medium"]
    low_open = [t for t in actionable if str(t["priority"]).lower() == "low"]
    stale_open = []
    for t in actionable:
        try:
            created = datetime.fromisoformat(str(t["created_at"]).replace("Z", "+00:00"))
        except Exception:
            continue
        if (datetime.utcnow() - created.replace(tzinfo=None)).total_seconds() >= 48 * 3600:
            stale_open.append(t)

    notifications = [
        {
            "id": make_id("welcome"),
            "level": "info",
            "title": "Welcome back",
            "message": f"Signed in as {user_email}.",
            "createdAt": now,
            "actionPath": None,
            "actionLabel": None,
        }
    ]

    if high_open:
        top = high_open[0]
        top_id = top["public_id"] if "public_id" in top.keys() else "your oldest open ticket"
        notifications.append(
            {
                "id": make_id("priority-high"),
                "level": "warning",
                "title": "High Priority First",
                "message": f"{len(high_open)} high-priority ticket(s) need action. Start with {top_id}.",
                "createdAt": now,
                "actionPath": "tickets.html",
                "actionLabel": "Open Tickets",
            }
        )
    elif medium_open:
        notifications.append(
            {
                "id": make_id("priority-medium"),
                "level": "info",
                "title": "Next Priority Queue",
                "message": f"{len(medium_open)} medium-priority ticket(s) are pending.",
                "createdAt": now,
                "actionPath": "tickets.html",
                "actionLabel": "Review Tickets",
            }
        )
    elif low_open:
        notifications.append(
            {
                "id": make_id("priority-low"),
                "level": "info",
                "title": "Low Priority Follow-up",
                "message": f"{len(low_open)} low-priority ticket(s) are still open.",
                "createdAt": now,
                "actionPath": "tickets.html",
                "actionLabel": "Check Tickets",
            }
        )
    else:
        notifications.append(
            {
                "id": make_id("priority-clear"),
                "level": "success",
                "title": "Priority Queue Clear",
                "message": "No open tickets in your queue.",
                "createdAt": now,
                "actionPath": "tickets.html",
                "actionLabel": "View Tickets",
            }
        )

    if stale_open:
        notifications.append(
            {
                "id": make_id("stale-open"),
                "level": "warning",
                "title": "Overdue Follow-up",
                "message": f"{len(stale_open)} open ticket(s) are older than 48 hours.",
                "createdAt": now,
                "actionPath": "tickets.html",
                "actionLabel": "Prioritize Now",
            }
        )

    if not chain_valid:
        notifications.append(
            {
                "id": make_id("audit"),
                "level": "warning",
                "title": "Audit Integrity Alert",
                "message": "Blockchain audit chain check failed. Please review admin verification.",
                "createdAt": now,
                "actionPath": "admin.html",
                "actionLabel": "Open Admin Verify",
            }
        )

    if attendance_summary.get("absent", 0) > 0:
        notifications.append(
            {
                "id": make_id("attendance"),
                "level": "warning",
                "title": "Attendance Update",
                "message": f"{attendance_summary['absent']} students are marked absent today.",
                "createdAt": now,
                "actionPath": "attendance.html",
                "actionLabel": "Open Attendance",
            }
        )
    else:
        notifications.append(
            {
                "id": make_id("attendance-good"),
                "level": "success",
                "title": "Attendance Update",
                "message": "No absences recorded for today.",
                "createdAt": now,
                "actionPath": "attendance.html",
                "actionLabel": "Open Attendance",
            }
        )

    role_lower = (role or "").strip().lower()
    activities_list = activities or []
    if role_lower == "student" and activities_list:
        count = len(activities_list)
        latest = activities_list[0] if activities_list else {}
        latest_title = (latest.get("title") or "New activity").strip() or "New activity"
        if count == 1:
            msg = f"New activity from your professor: {latest_title}"
        else:
            msg = f"You have {count} activities from your professor. Latest: {latest_title}"
        notifications.append(
            {
                "id": make_id("activities"),
                "level": "info",
                "title": "New Activities",
                "message": msg,
                "createdAt": now,
                "actionPath": "material.html",
                "actionLabel": "View Activities"
            }
        )
        
        # Quiz notifications
        quizzes_list = [a for a in activities_list if a.get("type") == "quiz"]
        if quizzes_list:
            q = quizzes_list[0]
            notifications.append({"id": make_id("quizzes"), "level": "info", "title": "New Quizzes", "message": f"New quiz from your professor: {q.get('title', 'Quiz')}", "createdAt": now, "actionPath": "material.html", "actionLabel": "View Quizzes"})
        
        # Exam notifications
        exams_list = [a for a in activities_list if a.get("type") == "exam"]
        if exams_list:
            e = exams_list[0]
            notifications.append({"id": make_id("exams"), "level": "info", "title": "New Exams", "message": f"New exam from your professor: {e.get('title', 'Exam')}", "createdAt": now, "actionPath": "material.html", "actionLabel": "View Exams"})

    unread = len([n for n in notifications if n.get("level") != "success"])
    return {
        "totalReminders": len(notifications),
        "unreadReminders": unread,
        "unreadCount": unread,
        "notifications": notifications,
    }


def get_notification_setting(conn: sqlite3.Connection, user_email: str) -> bool:
    row = conn.execute(
        "SELECT notifications_enabled FROM user_settings WHERE user_email = ?",
        (user_email,),
    ).fetchone()
    return bool(row and row["notifications_enabled"] == 1)


def set_notification_setting(conn: sqlite3.Connection, user_email: str, enabled: bool) -> None:
    conn.execute(
        """
        INSERT INTO user_settings (user_email, notifications_enabled, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_email) DO UPDATE SET
          notifications_enabled = excluded.notifications_enabled,
          updated_at = excluded.updated_at
        """,
        (user_email, 1 if enabled else 0, datetime.utcnow().isoformat()),
    )
    conn.commit()


def update_user_password_by_email(
    conn: sqlite3.Connection, user_email: str, password_hash: str
) -> bool:
    cur = conn.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (password_hash, user_email),
    )
    conn.commit()
    return cur.rowcount > 0


def create_password_reset_code(conn: sqlite3.Connection, user_email: str) -> str:
    raw_code = f"{secrets.randbelow(900000) + 100000}"
    token_hash = sha256_hex(raw_code)
    created_at = datetime.utcnow().isoformat()
    expires_at = datetime.utcfromtimestamp(datetime.utcnow().timestamp() + 600).isoformat()
    conn.execute(
        "UPDATE password_reset_tokens SET used = 1 WHERE user_email = ? AND used = 0",
        (user_email,),
    )
    conn.execute(
        """
        INSERT INTO password_reset_tokens (user_email, token_hash, expires_at, used, created_at)
        VALUES (?, ?, ?, 0, ?)
        """,
        (user_email, token_hash, expires_at, created_at),
    )
    conn.commit()
    return raw_code


def get_valid_password_reset(conn: sqlite3.Connection, user_email: str, raw_code: str):
    token_hash = sha256_hex(str(raw_code or "").strip())
    now = datetime.utcnow().isoformat()
    return conn.execute(
        """
        SELECT id, user_email, expires_at, used
        FROM password_reset_tokens
        WHERE user_email = ? AND token_hash = ? AND used = 0 AND expires_at > ?
        LIMIT 1
        """,
        (user_email, token_hash, now),
    ).fetchone()


def mark_password_reset_used(conn: sqlite3.Connection, token_id: int) -> None:
    conn.execute("UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (token_id,))
    conn.commit()


def send_password_reset_email(to_email: str, code: str) -> bool:
    if not SMTP_USER or not SMTP_PASS or not SMTP_FROM:
        return False
    msg = EmailMessage()
    msg["Subject"] = "Virtual Support Password Reset Code"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(f"Your password reset code is: {code}. It expires in 10 minutes.")
    msg.add_alternative(
        f"<p>Your password reset code is: <strong>{code}</strong></p><p>It expires in 10 minutes.</p>",
        subtype="html",
    )
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)
    return True


def send_verification_code_email(to_email: str, code: str) -> bool:
    if not SMTP_USER or not SMTP_PASS or not SMTP_FROM:
        return False
    msg = EmailMessage()
    msg["Subject"] = "Virtual Support Email Verification Code"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(f"Your verification code is: {code}. It expires in 10 minutes.")
    msg.add_alternative(
        f"<p>Your verification code is: <strong>{code}</strong></p><p>It expires in 10 minutes.</p>",
        subtype="html",
    )
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)
    return True


def create_verification_code(conn: sqlite3.Connection, user_email: str) -> str:
    raw_code = f"{secrets.randbelow(900000) + 100000}"
    code_hash = sha256_hex(raw_code)
    created_at = datetime.utcnow().isoformat()
    expires_at = datetime.utcfromtimestamp(datetime.utcnow().timestamp() + 600).isoformat()
    conn.execute(
        "UPDATE email_verification_codes SET used = 1 WHERE user_email = ? AND used = 0",
        (user_email,),
    )
    conn.execute(
        """
        INSERT INTO email_verification_codes (user_email, code_hash, expires_at, used, created_at)
        VALUES (?, ?, ?, 0, ?)
        """,
        (user_email, code_hash, expires_at, created_at),
    )
    conn.commit()
    return raw_code


def get_valid_verification_code(conn: sqlite3.Connection, user_email: str, raw_code: str):
    code_hash = sha256_hex(str(raw_code or "").strip())
    now = datetime.utcnow().isoformat()
    return conn.execute(
        """
        SELECT id, user_email, expires_at, used
        FROM email_verification_codes
        WHERE user_email = ? AND code_hash = ? AND used = 0 AND expires_at > ?
        LIMIT 1
        """,
        (user_email, code_hash, now),
    ).fetchone()


def mark_verification_code_used(conn: sqlite3.Connection, code_id: int) -> None:
    conn.execute("UPDATE email_verification_codes SET used = 1 WHERE id = ?", (code_id,))
    conn.commit()


def set_email_verified(conn: sqlite3.Connection, user_email: str) -> bool:
    cur = conn.execute("UPDATE users SET email_verified = 1 WHERE email = ?", (user_email,))
    conn.commit()
    return cur.rowcount > 0


def get_login_attempt(conn: sqlite3.Connection, user_email: str):
    return conn.execute(
        "SELECT user_email, failed_attempts, locked_until, updated_at FROM login_attempts WHERE user_email = ?",
        (user_email,),
    ).fetchone()


def clear_login_attempt(conn: sqlite3.Connection, user_email: str) -> None:
    conn.execute("DELETE FROM login_attempts WHERE user_email = ?", (user_email,))
    conn.commit()


def get_lockout_seconds(row) -> int:
    if not row or not row["locked_until"]:
        return 0
    try:
        locked_until = datetime.fromisoformat(str(row["locked_until"]).replace("Z", "+00:00"))
    except Exception:
        return 0
    seconds = int((locked_until.replace(tzinfo=None) - datetime.utcnow()).total_seconds())
    return max(seconds, 0)


def record_failed_login(conn: sqlite3.Connection, user_email: str):
    row = get_login_attempt(conn, user_email)
    failed = int(row["failed_attempts"] or 0) + 1 if row else 1
    locked_until = None
    if failed >= AUTH_LOCKOUT_MAX_ATTEMPTS:
        locked_until = (datetime.utcnow() + timedelta(minutes=AUTH_LOCKOUT_MINUTES)).isoformat()
    conn.execute(
        """
        INSERT INTO login_attempts (user_email, failed_attempts, locked_until, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_email) DO UPDATE SET
          failed_attempts = excluded.failed_attempts,
          locked_until = excluded.locked_until,
          updated_at = excluded.updated_at
        """,
        (user_email, failed, locked_until, datetime.utcnow().isoformat()),
    )
    conn.commit()
    return {"failed": failed, "lockedUntil": locked_until}


def create_login_mfa_code(conn: sqlite3.Connection, user_email: str) -> str:
    raw_code = f"{secrets.randbelow(900000) + 100000}"
    code_hash = sha256_hex(raw_code)
    created_at = datetime.utcnow().isoformat()
    expires_at = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    conn.execute("UPDATE login_mfa_codes SET used = 1 WHERE user_email = ? AND used = 0", (user_email,))
    conn.execute(
        """
        INSERT INTO login_mfa_codes (user_email, code_hash, expires_at, used, created_at)
        VALUES (?, ?, ?, 0, ?)
        """,
        (user_email, code_hash, expires_at, created_at),
    )
    conn.commit()
    return raw_code


def get_valid_login_mfa_code(conn: sqlite3.Connection, user_email: str, raw_code: str):
    code_hash = sha256_hex(str(raw_code or "").strip())
    now = datetime.utcnow().isoformat()
    return conn.execute(
        """
        SELECT id, user_email, expires_at, used
        FROM login_mfa_codes
        WHERE user_email = ? AND code_hash = ? AND used = 0 AND expires_at > ?
        LIMIT 1
        """,
        (user_email, code_hash, now),
    ).fetchone()


def mark_login_mfa_used(conn: sqlite3.Connection, code_id: int) -> None:
    conn.execute("UPDATE login_mfa_codes SET used = 1 WHERE id = ?", (code_id,))
    conn.commit()


def send_login_mfa_email(to_email: str, code: str) -> bool:
    if not SMTP_USER or not SMTP_PASS or not SMTP_FROM:
        return False
    msg = EmailMessage()
    msg["Subject"] = "Virtual Support Login Verification Code"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(f"Your login verification code is: {code}. It expires in 10 minutes.")
    msg.add_alternative(
        f"<p>Your login verification code is: <strong>{code}</strong></p><p>It expires in 10 minutes.</p>",
        subtype="html",
    )
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)
    return True


def send_signin_alert_email(to_email: str) -> bool:
    if not SMTP_USER or not SMTP_PASS or not SMTP_FROM:
        return False
    when = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    msg = EmailMessage()
    msg["Subject"] = "Virtual Support Sign-in Alert"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        f"Your account signed in at {when}. If this was not you, reset your password immediately."
    )
    msg.add_alternative(
        f"<p>Your account signed in at <strong>{when}</strong>.</p><p>If this was not you, reset your password immediately.</p>",
        subtype="html",
    )
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)
    return True


def finalize_signed_in_session(request: Request, user) -> None:
    request.session.clear()
    request.session["user_id"] = user["id"]
    request.session["email"] = user["email"]
    request.session["role"] = user["role"] or "student"


def make_ticket_id() -> str:
    return f"TKT-{secrets.token_hex(3).upper()}"


def categorize_ticket_priority(subject: str, description: str) -> str:
    text = f"{subject or ''} {description or ''}".lower()
    high_hints = [
        "urgent",
        "emergency",
        "cannot login",
        "can not login",
        "system down",
        "payment failed",
        "security",
        "breach",
        "critical",
    ]
    medium_hints = ["error", "failed", "issue", "problem", "delay", "not working", "unable"]
    if any(k in text for k in high_hints):
        return "high"
    if any(k in text for k in medium_hints):
        return "medium"
    return "low"


def create_ticket(
    conn: sqlite3.Connection, user_email: str, subject: str, description: str, priority: str
) -> str:
    public_id = make_ticket_id()
    now = datetime.utcnow().isoformat()
    conn.execute(
        """
        INSERT INTO support_tickets (public_id, user_email, subject, description, priority, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
        """,
        (public_id, user_email, subject, description, priority, now, now),
    )
    conn.commit()
    return public_id


def list_tickets_by_email(conn: sqlite3.Connection, user_email: str):
    return conn.execute(
        """
        SELECT public_id, subject, description, priority, status, created_at, updated_at
        FROM support_tickets
        WHERE user_email = ?
        ORDER BY id DESC
        """,
        (user_email,),
    ).fetchall()


def list_all_users(conn: sqlite3.Connection):
    return conn.execute(
        """
        SELECT id, full_name, email, role, created_at
        FROM users
        ORDER BY id DESC
        """
    ).fetchall()


def update_user_role_by_id(conn: sqlite3.Connection, user_id: int, role: str) -> bool:
    cur = conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    return cur.rowcount > 0


def list_all_tickets(conn: sqlite3.Connection):
    return conn.execute(
        """
        SELECT public_id, user_email, subject, description, priority, status, created_at, updated_at
        FROM support_tickets
        ORDER BY id DESC
        """
    ).fetchall()


def get_ticket_by_public_id(conn: sqlite3.Connection, public_id: str):
    return conn.execute(
        """
        SELECT id, public_id, user_email, subject, description, priority, status, created_at, updated_at
        FROM support_tickets
        WHERE public_id = ?
        """,
        (public_id,),
    ).fetchone()


def update_ticket_status(conn: sqlite3.Connection, public_id: str, status: str) -> bool:
    now = datetime.utcnow().isoformat()
    cur = conn.execute(
        "UPDATE support_tickets SET status = ?, updated_at = ? WHERE public_id = ?",
        (status, now, public_id),
    )
    conn.commit()
    return cur.rowcount > 0


def list_material_activities(conn: sqlite3.Connection):
    return conn.execute(
        """
        SELECT id, title, description, created_by_email, created_at
        FROM material_activities
        ORDER BY id DESC
        """
    ).fetchall()


def create_material_activity(
    conn: sqlite3.Connection, title: str, description: str, created_by_email: str
) -> dict:
    now = datetime.utcnow().isoformat()
    cur = conn.execute(
        """
        INSERT INTO material_activities (title, description, created_by_email, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (sanitize_text(title, 255), sanitize_text(description or "", 2000), created_by_email, now),
    )
    conn.commit()
    return {"id": cur.lastrowid, "createdAt": now}


def delete_material_activity(conn: sqlite3.Connection, activity_id: int, created_by_email: str) -> bool:
    cur = conn.execute(
        "DELETE FROM material_activities WHERE id = ? AND created_by_email = ?",
        (activity_id, created_by_email),
    )
    conn.commit()
    return cur.rowcount > 0


def list_quizzes(conn: sqlite3.Connection):
    return conn.execute(
        """
        SELECT id, title, description, quiz_type, created_by_email, created_at
        FROM quizzes
        ORDER BY id DESC
        """
    ).fetchall()


def create_quiz(
    conn: sqlite3.Connection, title: str, description: str, quiz_type: str, created_by_email: str
) -> dict:
    now = datetime.utcnow().isoformat()
    cur = conn.execute(
        """
        INSERT INTO quizzes (title, description, quiz_type, created_by_email, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (sanitize_text(title, 255), sanitize_text(description or "", 2000), quiz_type or 'quiz', created_by_email, now),
    )
    conn.commit()
    return {"id": cur.lastrowid, "createdAt": now}


def delete_quiz(conn: sqlite3.Connection, quiz_id: int, created_by_email: str) -> bool:
    cur = conn.execute(
        "DELETE FROM quizzes WHERE id = ? AND created_by_email = ?",
        (quiz_id, created_by_email),
    )
    conn.commit()
    return cur.rowcount > 0


@app.on_event("startup")
def startup_event() -> None:
    init_db()


@app.post("/api/auth/signup")
def signup(payload: SignUpPayload, request: Request):
    full_name = sanitize_text(payload.fullName, 80)
    role = (payload.role or "student").strip().lower()
    admin_code = sanitize_text(payload.adminCode or "", 64)
    normalized_admin_code = admin_code.upper()
    email = normalize_email(payload.email)
    password = payload.password
    allowed_roles = {"student", "professor", "administrator"}

    if not is_valid_name(full_name):
        raise HTTPException(
            status_code=400,
            detail="Full name must be 2-80 letters and valid symbols only.",
        )
    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail="Invalid role value.")
    if role == "administrator" and normalized_admin_code != ADMIN_INVITE_CODE_NORMALIZED:
        raise HTTPException(
            status_code=403,
            detail="Invalid admin access code. For local demo, default is ADMIN123 unless changed in .env.",
        )
    if not is_valid_email(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if not is_strong_password(password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8+ chars with upper/lowercase, number, and symbol.",
        )

    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="This email is already registered.")

        password_hash = hash_password(password)
        cursor = conn.execute(
            "INSERT INTO users (full_name, email, role, email_verified, password_hash, created_at) VALUES (?, ?, ?, 1, ?, ?)",
            (full_name, email, role, password_hash, datetime.utcnow().isoformat()),
        )
        conn.commit()

        user_id = cursor.lastrowid
        append_audit_event(
            conn,
            "signup",
            email,
            {"fullName": full_name, "userId": user_id, "role": role},
        )
        conn.commit()

    return {
        "message": "Account created successfully.",
    }


@app.post("/api/auth/signin")
def signin(payload: SignInPayload, request: Request):
    email = normalize_email(payload.email)
    password = payload.password

    if not is_valid_email(email) or len(password) < 8:
        raise HTTPException(status_code=400, detail="Invalid email or password format.")

    with get_conn() as conn:
        attempt = get_login_attempt(conn, email)
        lockout_seconds = get_lockout_seconds(attempt)
        if lockout_seconds > 0:
            raise HTTPException(
                status_code=429,
                detail=f"Account temporarily locked. Try again in {lockout_seconds} seconds.",
            )
        user = conn.execute(
            "SELECT id, email, role, email_verified, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

    if not user:
        with get_conn() as conn:
            record_failed_login(conn, email)
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not verify_password(password, user["password_hash"]):
        with get_conn() as conn:
            result = record_failed_login(conn, email)
            append_audit_event(conn, "signin_failed", email, {"failedAttempts": result["failed"]})
            if result["lockedUntil"]:
                retry_after = max(
                    int((datetime.fromisoformat(result["lockedUntil"]) - datetime.utcnow()).total_seconds()),
                    0,
                )
                append_audit_event(conn, "signin_locked", email, {"retryAfterSeconds": retry_after})
            conn.commit()
        if result["lockedUntil"]:
            retry_after = max(
                int((datetime.fromisoformat(result["lockedUntil"]) - datetime.utcnow()).total_seconds()),
                0,
            )
            raise HTTPException(
                status_code=429,
                detail=f"Account temporarily locked. Try again in {retry_after} seconds.",
            )
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    with get_conn() as conn:
        clear_login_attempt(conn, email)
        user_role = str(user["role"] or "student").strip().lower()
        if AUTH_MFA_EMAIL_ACTIVE and user_role != "professor":
            code = create_login_mfa_code(conn, email)
            email_sent = False
            try:
                email_sent = send_login_mfa_email(email, code)
            except Exception:
                email_sent = False
            request.session.clear()
            request.session["pending_auth"] = {
                "user_id": user["id"],
                "email": user["email"],
                "role": user["role"] or "student",
                "created_at": datetime.utcnow().isoformat(),
            }
            append_audit_event(conn, "signin_mfa_challenge", user["email"], {"emailSent": email_sent})
            conn.commit()
            return {
                "message": "Enter the 6-digit verification code to complete sign in.",
                "mfaRequired": True,
                "emailSent": email_sent,
                "verificationCode": None if email_sent else code,
            }
        finalize_signed_in_session(request, user)
        signin_alert_sent = False
        try:
            signin_alert_sent = send_signin_alert_email(user["email"])
        except Exception:
            signin_alert_sent = False
        append_audit_event(conn, "signin", user["email"], {"userId": user["id"], "role": user["role"] or "student"})
        append_audit_event(conn, "signin_alert", user["email"], {"emailSent": signin_alert_sent})
        conn.commit()
    return {"message": "Sign in successful."}


@app.post("/api/auth/signin/verify-mfa")
def signin_verify_mfa(payload: SignInMfaPayload, request: Request):
    pending = request.session.get("pending_auth") or {}
    if not pending or not pending.get("email") or not pending.get("user_id"):
        raise HTTPException(status_code=400, detail="No pending sign-in. Please sign in again.")
    code = sanitize_text(payload.code, 16)
    if not re.match(r"^\d{6}$", code):
        raise HTTPException(status_code=400, detail="Verification code must be 6 digits.")
    with get_conn() as conn:
        valid = get_valid_login_mfa_code(conn, pending["email"], code)
        if not valid:
            raise HTTPException(status_code=401, detail="Invalid or expired verification code.")
        mark_login_mfa_used(conn, valid["id"])
        user = conn.execute(
            "SELECT id, email, role FROM users WHERE id = ?",
            (int(pending["user_id"]),),
        ).fetchone()
        if not user or user["email"] != pending["email"]:
            raise HTTPException(status_code=401, detail="User session invalid. Please sign in again.")
        finalize_signed_in_session(request, user)
        signin_alert_sent = False
        try:
            signin_alert_sent = send_signin_alert_email(user["email"])
        except Exception:
            signin_alert_sent = False
        append_audit_event(
            conn,
            "signin",
            user["email"],
            {"userId": user["id"], "role": user["role"] or "student", "mfa": True},
        )
        append_audit_event(conn, "signin_alert", user["email"], {"emailSent": signin_alert_sent})
        conn.commit()
    return {"message": "Sign in successful."}


@app.post("/api/auth/verify-email")
def verify_email(payload: VerifyEmailPayload, request: Request):
    raise HTTPException(status_code=404, detail="Email verification is disabled.")


@app.post("/api/auth/resend-verification")
def resend_verification(payload: ForgotPasswordPayload):
    raise HTTPException(status_code=404, detail="Email verification is disabled.")


@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordPayload, request: Request):
    raise HTTPException(status_code=404, detail="Forgot password is disabled.")


@app.post("/api/auth/reset-password")
def reset_password(payload: ResetPasswordPayload):
    raise HTTPException(status_code=404, detail="Forgot password is disabled.")


@app.get("/api/auth/me")
def me(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    with get_conn() as conn:
        user = conn.execute(
            "SELECT id, full_name, email, role, email_verified FROM users WHERE id = ?", (user_id,)
        ).fetchone()

    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {
        "id": user["id"],
        "fullName": user["full_name"],
        "email": user["email"],
        "role": user["role"] or "student",
        "emailVerified": int(user["email_verified"] or 0) == 1,
    }


@app.post("/api/auth/logout")
def logout(request: Request):
    email = request.session.get("email")
    if email:
        with get_conn() as conn:
            append_audit_event(conn, "logout", email, {})
            conn.commit()
    request.session.clear()
    return {"message": "Logged out."}


@app.get("/api/audit/my")
def my_audit(request: Request):
    email = request.session.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Unauthorized")

    with get_conn() as conn:
        all_rows = conn.execute(
            "SELECT id, event_type, user_email, payload_json, prev_hash, entry_hash, created_at FROM audit_chain ORDER BY id ASC"
        ).fetchall()
        rows = [row for row in all_rows if row["user_email"] == email]

    chain_valid = verify_audit_rows(all_rows)
    return {
        "chainValid": chain_valid,
        "records": [
            {
                "id": row["id"],
                "eventType": row["event_type"],
                "createdAt": row["created_at"],
                "entryHash": row["entry_hash"],
            }
            for row in rows
        ],
    }


@app.get("/api/audit/admin/full")
def admin_audit_full(request: Request):
    email = request.session.get("email", "").strip().lower()
    role = request.session.get("role", "")
    if role != "administrator" and email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access required.")

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, event_type, user_email, payload_json, prev_hash, entry_hash, created_at FROM audit_chain ORDER BY id ASC"
        ).fetchall()

    chain_valid = verify_audit_rows(rows)
    return {
        "chainValid": chain_valid,
        "totalRecords": len(rows),
        "records": [
            {
                "id": row["id"],
                "eventType": row["event_type"],
                "userEmail": row["user_email"],
                "createdAt": row["created_at"],
                "prevHash": row["prev_hash"],
                "entryHash": row["entry_hash"],
            }
            for row in rows
        ],
    }


@app.get("/api/admin/users")
def admin_users(request: Request):
    email = request.session.get("email", "").strip().lower()
    role = request.session.get("role", "")
    if role != "administrator" and email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access required.")

    with get_conn() as conn:
        rows = list_all_users(conn)
    return {
        "users": [
            {
                "id": row["id"],
                "fullName": row["full_name"],
                "email": row["email"],
                "role": row["role"] or "student",
                "createdAt": row["created_at"],
            }
            for row in rows
        ]
    }


@app.patch("/api/admin/users/{user_id}/role")
def admin_update_user_role(user_id: int, payload: UserRolePayload, request: Request):
    email = request.session.get("email", "").strip().lower()
    role = request.session.get("role", "")
    if role != "administrator" and email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access required.")

    next_role = str(payload.role or "").strip().lower()
    if next_role not in ("student", "professor", "administrator"):
        raise HTTPException(status_code=400, detail="Invalid role value.")

    with get_conn() as conn:
        changed = update_user_role_by_id(conn, user_id, next_role)
        if not changed:
            raise HTTPException(status_code=404, detail="User not found.")
        append_audit_event(
            conn,
            "admin_user_role_updated",
            email or None,
            {"userId": user_id, "role": next_role},
        )
        conn.commit()
    return {"message": "User role updated."}


@app.get("/api/admin/tickets")
def admin_tickets(request: Request):
    email = request.session.get("email", "").strip().lower()
    role = request.session.get("role", "")
    if role != "administrator" and email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access required.")

    with get_conn() as conn:
        rows = list_all_tickets(conn)
    return {
        "tickets": [
            {
                "ticketId": row["public_id"],
                "userEmail": row["user_email"],
                "subject": row["subject"],
                "description": row["description"],
                "priority": row["priority"],
                "status": row["status"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }
            for row in rows
        ]
    }


@app.patch("/api/admin/tickets/{ticket_id}/status")
def admin_update_ticket_status(ticket_id: str, payload: TicketStatusPayload, request: Request):
    email = request.session.get("email", "").strip().lower()
    role = request.session.get("role", "")
    if role != "administrator" and email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access required.")

    next_status = payload.status.strip().lower()
    if next_status not in ("open", "in_progress", "resolved"):
        raise HTTPException(status_code=400, detail="Invalid status value.")

    with get_conn() as conn:
        changed = update_ticket_status(conn, ticket_id, next_status)
        if not changed:
            raise HTTPException(status_code=404, detail="Ticket not found.")
        append_audit_event(
            conn,
            "admin_ticket_status_updated",
            email or None,
            {"ticketId": ticket_id, "status": next_status},
        )
        conn.commit()
    return {"message": "Ticket status updated."}


@app.delete("/api/admin/tickets/{ticket_id}")
def admin_delete_ticket(ticket_id: str, request: Request):
    email = request.session.get("email", "").strip().lower()
    role = request.session.get("role", "")
    if role != "administrator" and email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access required.")

    with get_conn() as conn:
        # Check if ticket exists
        ticket = conn.execute(
            "SELECT id, subject, user_email FROM support_tickets WHERE public_id = ?",
            (ticket_id,)
        ).fetchone()
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found.")
        
        # Delete the ticket
        conn.execute("DELETE FROM support_tickets WHERE public_id = ?", (ticket_id,))
        append_audit_event(
            conn,
            "admin_ticket_deleted",
            email or None,
            {"ticketId": ticket_id, "subject": ticket[1], "userEmail": ticket[2]},
        )
        conn.commit()
    return {"message": "Ticket removed."}


@app.get("/api/attendance/summary")
def attendance_summary(request: Request, date: str | None = None):
    if not request.session.get("user_id"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not can_use_attendance(request):
        raise HTTPException(
            status_code=403,
            detail="Attendance is restricted to professors and administrators.",
        )

    attendance_date = date or datetime.utcnow().date().isoformat()
    with get_conn() as conn:
        return get_attendance_summary(conn, attendance_date)


@app.post("/api/attendance/mark")
def attendance_mark(payload: AttendanceMarkPayload, request: Request):
    email = request.session.get("email")
    user_id = request.session.get("user_id")
    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not can_use_attendance(request):
        raise HTTPException(
            status_code=403,
            detail="Only professors and administrators can mark attendance.",
        )

    status = payload.status.strip().lower()
    attendance_date = (payload.date or datetime.utcnow().date().isoformat()).strip()
    if status not in ("present", "late", "absent"):
        raise HTTPException(status_code=400, detail="Invalid attendance status.")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", attendance_date):
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")

    with get_conn() as conn:
        upsert_attendance(conn, email, attendance_date, status)
        append_audit_event(
            conn,
            "attendance_marked",
            email,
            {"date": attendance_date, "status": status},
        )
        conn.commit()
    return {"message": "Attendance saved.", "date": attendance_date, "status": status}


@app.get("/api/attendance/today")
def attendance_today(request: Request, date: str | None = None):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not can_use_attendance(request):
        raise HTTPException(
            status_code=403,
            detail="Attendance is restricted to professors and administrators.",
        )

    attendance_date = (date or datetime.utcnow().date().isoformat()).strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", attendance_date):
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")

    with get_conn() as conn:
        summary = get_attendance_summary(conn, attendance_date)
        rows = list_attendance_by_date(conn, attendance_date)

    return {
        "date": attendance_date,
        "summary": summary,
        "records": [
            {
                "fullName": row["full_name"] or "-",
                "userEmail": row["user_email"],
                "status": row["status"],
                "createdAt": row["created_at"],
            }
            for row in rows
        ],
    }


@app.get("/api/material")
def material_list(request: Request):
    if not request.session.get("user_id"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    role = str(request.session.get("role", "")).strip().lower()
    if role not in ("professor", "student"):
        raise HTTPException(
            status_code=403,
            detail="Material and activities are for professors and students only.",
        )
    with get_conn() as conn:
        rows = list_material_activities(conn)
    return {
        "activities": [
            {
                "id": row["id"],
                "title": row["title"],
                "description": row["description"] or "",
                "createdByEmail": row["created_by_email"],
                "createdAt": row["created_at"],
            }
            for row in rows
        ]
    }


@app.post("/api/material")
def material_create(payload: MaterialCreatePayload, request: Request):
    if not request.session.get("user_id") or not request.session.get("email"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not is_professor_session(request):
        raise HTTPException(
            status_code=403,
            detail="Material and activities are for professors only.",
        )
    title = (payload.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required.")
    with get_conn() as conn:
        result = create_material_activity(
            conn, title, payload.description or "", request.session["email"]
        )
        append_audit_event(
            conn,
            "material_activity_created",
            request.session["email"],
            {"id": result["id"], "title": title},
        )
        conn.commit()
    return {
        "message": "Activity created.",
        "id": result["id"],
        "createdAt": result["createdAt"],
    }


@app.delete("/api/material/{activity_id}")
def material_delete(activity_id: int, request: Request):
    if not request.session.get("user_id") or not request.session.get("email"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not is_professor_session(request):
        raise HTTPException(
            status_code=403,
            detail="Material and activities are for professors only.",
        )
    if not isinstance(activity_id, int) or activity_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid activity id.")
    with get_conn() as conn:
        deleted = delete_material_activity(conn, activity_id, request.session["email"])
        if not deleted:
            raise HTTPException(
                status_code=404,
                detail="Activity not found or you can only delete your own.",
            )
        append_audit_event(conn, "material_activity_deleted", request.session["email"], {"id": activity_id})
        conn.commit()
    return {"message": "Activity deleted."}


@app.get("/api/quiz")
def quiz_list(request: Request):
    if not request.session.get("user_id") or not request.session.get("email"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    role = (request.session.get("role") or "student").lower()
    if role != "professor" and role != "student":
        raise HTTPException(
            status_code=403,
            detail="Quizzes and exams are for professors and students only.",
        )
    with get_conn() as conn:
        rows = list_quizzes(conn)
    return {
        "quizzes": [
            {
                "id": row["id"],
                "title": row["title"],
                "description": row["description"] or "",
                "quizType": row["quiz_type"],
                "createdByEmail": row["created_by_email"],
                "createdAt": row["created_at"],
            }
            for row in rows
        ]
    }


@app.post("/api/quiz")
def quiz_create(request: Request, payload: dict):
    if not request.session.get("user_id") or not request.session.get("email"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not is_professor_session(request):
        raise HTTPException(
            status_code=403,
            detail="Quizzes and exams are for professors only.",
        )
    title = (payload.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required.")
    description = payload.get("description", "")
    quiz_type = payload.get("quizType", "quiz")
    with get_conn() as conn:
        result = create_quiz(
            conn, title, description, quiz_type, request.session["email"]
        )
        append_audit_event(
            conn, "quiz_created", request.session["email"],
            {"id": result["id"], "title": title, "quizType": quiz_type}
        )
        conn.commit()
    return {
        "message": "Quiz/Exam created.",
        "id": result["id"],
        "createdAt": result["createdAt"],
    }


@app.delete("/api/quiz/{quiz_id}")
def quiz_delete(quiz_id: int, request: Request):
    if not request.session.get("user_id") or not request.session.get("email"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not is_professor_session(request):
        raise HTTPException(
            status_code=403,
            detail="Quizzes and exams are for professors only.",
        )
    if not isinstance(quiz_id, int) or quiz_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid quiz id.")
    with get_conn() as conn:
        deleted = delete_quiz(conn, quiz_id, request.session["email"])
        if not deleted:
            raise HTTPException(
                status_code=404,
                detail="Quiz not found or you can only delete your own.",
            )
        append_audit_event(conn, "quiz_deleted", request.session["email"], {"id": quiz_id})
        conn.commit()
    return {"message": "Quiz deleted."}


@app.get("/api/notifications")
def notifications(request: Request):
    email = request.session.get("email")
    user_id = request.session.get("user_id")
    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Unauthorized")

    today = datetime.utcnow().date().isoformat()
    with get_conn() as conn:
        enabled = get_notification_setting(conn, email)
        if not enabled:
            return {
                "enabled": False,
                "totalReminders": 0,
                "unreadReminders": 0,
                "unreadCount": 0,
                "notifications": [],
            }
        user_row = conn.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        role = (user_row["role"] or "student") if user_row else "student"
        attendance = get_attendance_summary(conn, today)
        tickets = list_tickets_by_email(conn, email)
        activities = list_material_activities(conn) if role == "student" else []
        quizzes = list_quizzes(conn) if role == "student" else []
        activities_for_notif = [
            {"title": r["title"], "createdAt": r["created_at"], "type": "activity"}
            for r in activities
        ]
        quizzes_for_notif = [
            {"title": r["title"], "createdAt": r["created_at"], "type": r["quiz_type"]}
            for r in quizzes
        ]
        all_materials = activities_for_notif + quizzes_for_notif
        rows = conn.execute(
            "SELECT id, event_type, user_email, payload_json, prev_hash, entry_hash, created_at FROM audit_chain ORDER BY id ASC"
        ).fetchall()
    chain_valid = verify_audit_rows(rows)
    payload = build_notifications(
        email, attendance, chain_valid, tickets,
        role=role,
        activities=all_materials,
    )
    payload["enabled"] = True
    return payload


@app.get("/api/settings/notifications")
def get_notifications_setting(request: Request):
    email = request.session.get("email")
    user_id = request.session.get("user_id")
    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Unauthorized")
    with get_conn() as conn:
        enabled = get_notification_setting(conn, email)
    return {"enabled": enabled}


class NotificationSettingPayload(BaseModel):
    enabled: bool


class CreateTicketPayload(BaseModel):
    subject: str
    description: str
    priority: str


@app.post("/api/settings/notifications")
def set_notifications_setting(payload: NotificationSettingPayload, request: Request):
    email = request.session.get("email")
    user_id = request.session.get("user_id")
    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Unauthorized")
    with get_conn() as conn:
        set_notification_setting(conn, email, payload.enabled)
    return {"enabled": payload.enabled}


@app.post("/api/tickets")
def create_ticket_api(payload: CreateTicketPayload, request: Request):
    email = request.session.get("email")
    user_id = request.session.get("user_id")
    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Unauthorized")

    subject = sanitize_text(payload.subject, 160)
    description = sanitize_text(payload.description, 2000)
    requested_priority = (payload.priority or "").strip().lower()
    inferred_priority = categorize_ticket_priority(subject, description)
    priority = (
        requested_priority if requested_priority in ("low", "medium", "high") else inferred_priority
    )
    if len(subject) < 4:
        raise HTTPException(status_code=400, detail="Subject must be at least 4 characters.")
    if len(description) < 10:
        raise HTTPException(status_code=400, detail="Description must be at least 10 characters.")
    if priority not in ("low", "medium", "high"):
        raise HTTPException(status_code=400, detail="Invalid priority value.")

    with get_conn() as conn:
        ticket_id = create_ticket(conn, email, subject, description, priority)
        append_audit_event(
            conn,
            "ticket_created",
            email,
            {"ticketId": ticket_id, "priority": priority},
        )
        conn.commit()

    return {
        "message": "Ticket created successfully.",
        "ticketId": ticket_id,
        "priority": priority,
        "categorizedBy": "manual"
        if requested_priority in ("low", "medium", "high")
        else "system",
    }


@app.get("/api/tickets/my")
def my_tickets(request: Request):
    email = request.session.get("email")
    user_id = request.session.get("user_id")
    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Unauthorized")
    with get_conn() as conn:
        rows = list_tickets_by_email(conn, email)
    return {
        "tickets": [
            {
                "ticketId": row["public_id"],
                "subject": row["subject"],
                "description": row["description"],
                "priority": row["priority"],
                "status": row["status"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }
            for row in rows
        ]
    }


@app.patch("/api/tickets/{ticket_id}/status")
def update_ticket_status_api(ticket_id: str, payload: TicketStatusPayload, request: Request):
    email = request.session.get("email", "")
    user_id = request.session.get("user_id")
    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Unauthorized")
    next_status = payload.status.strip().lower()
    if next_status not in ("open", "in_progress", "resolved"):
        raise HTTPException(status_code=400, detail="Invalid status value.")

    with get_conn() as conn:
        ticket = get_ticket_by_public_id(conn, ticket_id)
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found.")
        is_owner = ticket["user_email"] == email
        is_admin = email.strip().lower() == ADMIN_EMAIL
        if not is_owner and not is_admin:
            raise HTTPException(status_code=403, detail="Forbidden.")

        changed = update_ticket_status(conn, ticket_id, next_status)
        if not changed:
            raise HTTPException(status_code=404, detail="Ticket not found.")
        append_audit_event(
            conn,
            "ticket_status_updated",
            email,
            {"ticketId": ticket_id, "status": next_status},
        )
        conn.commit()
    return {"message": "Ticket status updated."}


@app.get("/api/blockchain/ticker")
def blockchain_ticker(request: Request, limit: int = 12):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")
    safe_limit = min(max(limit, 1), 50)
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, event_type, user_email, created_at, entry_hash
            FROM audit_chain
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return {
        "events": [
            {
                "id": row["id"],
                "eventType": row["event_type"],
                "userEmail": row["user_email"],
                "createdAt": row["created_at"],
                "hash": row["entry_hash"],
            }
            for row in rows
        ]
    }


@app.post("/api/chat")
def chat(payload: ChatPayload, request: Request):
    message = str(payload.message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message is required.")
    history = request.session.get("chat_history", [])
    history = trim_chat_history(history)
    reply = generate_nlp_reply(message, history)
    request.session["chat_history"] = trim_chat_history(
        history + [{"role": "user", "content": message}, {"role": "assistant", "content": reply}]
    )
    return {"reply": reply, "history": request.session["chat_history"]}


@app.get("/api/chat/history")
def chat_history(request: Request):
    history = trim_chat_history(request.session.get("chat_history", []))
    if len(history) == 0:
        return {"history": [get_welcome_message()]}
    return {"history": history}


@app.delete("/api/chat/history")
def clear_chat_history(request: Request):
    request.session["chat_history"] = []
    return {"message": "Chat history cleared."}


@app.get("/")
def root():
    return FileResponse(BASE_DIR / "index.html")


# Serve existing frontend files (index.html, dashboard.html, css, js, etc.)
app.mount("/", StaticFiles(directory=BASE_DIR, html=True), name="static")
