import os
import re
import sqlite3
import base64
import hashlib
import hmac
import secrets
import json
import smtplib
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from email.message import EmailMessage

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
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

app = FastAPI(title="Virtual Support System API (Python - NLP Based)")

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


class CreateTicketPayload(BaseModel):
    subject: str
    description: str
    priority: str


class NotificationSettingPayload(BaseModel):
    enabled: bool


class QuizCreatePayload(BaseModel):
    title: str
    description: str = ""
    quizType: str = "quiz"


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


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def trim_chat_history(history: list, max_items: int = 20) -> list:
    if not isinstance(history, list):
        return []
    out = []
    for item in history[-max_items:]:
        role = "assistant" if item.get("role") == "assistant" else "user"
        content = str(item.get("content", ""))[:3000]
        out.append({"role": role, "content": content})
    return out


def get_welcome_message() -> dict:
    return {
        "role": "assistant",
        "content": "Hello. I am your NLP-based virtual support assistant. Ask anything and I will respond based on detected keywords and intent.",
    }


def get_last_audit_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1").fetchone()
    return row["entry_hash"] if row else "GENESIS"


def append_audit_event(conn: sqlite3.Connection, event_type: str, user_email: str | None, payload: dict):
    prev_hash = get_last_audit_hash(conn)
    created_at = datetime.utcnow().isoformat()
    payload_json = json.dumps(payload or {}, separators=(",", ":"), sort_keys=True)
    entry_hash = sha256_hex(
        f"{prev_hash}|{event_type}|{user_email or ''}|{payload_json}|{created_at}"
    )
    conn.execute(
        """
        INSERT INTO audit_chain (event_type, user_email, payload_json, prev_hash, entry_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
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


def finalize_signed_in_session(request: Request, user) -> None:
    request.session.clear()
    request.session["user_id"] = user["id"]
    request.session["email"] = user["email"]
    request.session["role"] = user["role"] or "student"


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


def make_ticket_id() -> str:
    return f"TKT-{secrets.token_hex(3).upper()}"


def categorize_ticket_priority(subject: str, description: str) -> str:
    text = f"{subject or ''} {description or ''}".lower()
    high_hints = [
        "urgent", "emergency", "cannot login", "can not login",
        "system down", "payment failed", "security", "breach", "critical",
    ]
    medium_hints = ["error", "failed", "issue", "problem", "delay", "not working", "unable"]
    if any(k in text for k in high_hints):
        return "high"
    if any(k in text for k in medium_hints):
        return "medium"
    return "low"


def create_ticket(conn: sqlite3.Connection, user_email: str, subject: str, description: str, priority: str) -> str:
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


def create_material_activity(conn: sqlite3.Connection, title: str, description: str, created_by_email: str) -> dict:
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


def create_quiz(conn: sqlite3.Connection, title: str, description: str, quiz_type: str, created_by_email: str) -> dict:
    now = datetime.utcnow().isoformat()
    cur = conn.execute(
        """
        INSERT INTO quizzes (title, description, quiz_type, created_by_email, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (sanitize_text(title, 255), sanitize_text(description or "", 2000), quiz_type or "quiz", created_by_email, now),
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


def upsert_attendance(conn: sqlite3.Connection, user_email: str, attendance_date: str, status: str) -> None:
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
        t for t in (tickets or [])
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
        latest = activities_list[0]
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
                "actionLabel": "View Activities",
            }
        )

        quizzes_list = [a for a in activities_list if a.get("type") == "quiz"]
        if quizzes_list:
            q = quizzes_list[0]
            notifications.append(
                {
                    "id": make_id("quizzes"),
                    "level": "info",
                    "title": "New Quizzes",
                    "message": f"New quiz from your professor: {q.get('title', 'Quiz')}",
                    "createdAt": now,
                    "actionPath": "material.html",
                    "actionLabel": "View Quizzes",
                }
            )

        exams_list = [a for a in activities_list if a.get("type") == "exam"]
        if exams_list:
            e = exams_list[0]
            notifications.append(
                {
                    "id": make_id("exams"),
                    "level": "info",
                    "title": "New Exams",
                    "message": f"New exam from your professor: {e.get('title', 'Exam')}",
                    "createdAt": now,
                    "actionPath": "material.html",
                    "actionLabel": "View Exams",
                }
            )

    unread = len([n for n in notifications if n.get("level") != "success"])
    return {
        "totalReminders": len(notifications),
        "unreadReminders": unread,
        "unreadCount": unread,
        "notifications": notifications,
    }


def tokenize_text(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z0-9']+", str(text or "").lower())


def extract_last_user_topic(history: list | None = None) -> str:
    history = history or []
    for item in reversed(history):
        if item.get("role") == "user":
            topic = extract_topic_from_text(item.get("content", ""))
            if topic:
                return topic
    return ""


def extract_topic_from_text(text: str) -> str:
    text = str(text or "").strip()
    lower = text.lower()

    patterns = [
        r"(?:what is|who is|define|explain|tell me about)\s+(.+)",
        r"(?:how does|how do|how can|how to)\s+(.+)",
        r"(?:difference between|compare)\s+(.+)",
        r"(?:create|write|make|generate)\s+(.+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, lower)
        if match:
            topic = match.group(1).strip(" ?.!")
            return topic[:120]

    words = tokenize_text(text)
    if not words:
        return ""
    return " ".join(words[:6])


def get_intent_scores(text: str) -> dict:
    lower = str(text or "").lower()
    tokens = set(tokenize_text(lower))

    intent_map = {
        "greeting": {
            "phrases": ["hello", "hi", "hey", "good morning", "good afternoon", "good evening"],
            "keywords": {"hello", "hi", "hey", "morning", "afternoon", "evening"},
        },
        "identity": {
            "phrases": ["who are you", "what can you do", "what do you do"],
            "keywords": {"who", "what", "can", "do", "assistant", "system"},
        },
        "attendance": {
            "phrases": ["attendance", "mark attendance", "present", "late", "absent"],
            "keywords": {"attendance", "present", "late", "absent"},
        },
        "tickets": {
            "phrases": ["ticket", "support ticket", "issue", "concern", "complaint", "problem"],
            "keywords": {"ticket", "support", "issue", "concern", "complaint", "problem"},
        },
        "materials": {
            "phrases": ["material", "activity", "lesson", "quiz", "exam", "study guide"],
            "keywords": {"material", "activity", "lesson", "quiz", "exam", "study", "guide"},
        },
        "account": {
            "phrases": ["password", "forgot password", "reset password", "login problem", "cannot login"],
            "keywords": {"password", "forgot", "reset", "login", "account"},
        },
        "writing": {
            "phrases": ["rewrite", "improve grammar", "write", "essay", "email", "caption", "message"],
            "keywords": {"rewrite", "grammar", "write", "essay", "email", "caption", "message"},
        },
        "programming": {
            "phrases": ["python", "code", "programming", "debug", "function", "loop", "recursion"],
            "keywords": {"python", "code", "programming", "debug", "function", "loop", "recursion", "bug"},
        },
        "thesis_nlp": {
            "phrases": ["nlp", "natural language processing", "thesis", "methodology", "system"],
            "keywords": {"nlp", "natural", "language", "processing", "thesis", "methodology", "system"},
        },
        "how_to": {
            "phrases": ["how to", "how do i", "how can i", "steps to"],
            "keywords": {"how", "steps"},
        },
        "definition": {
            "phrases": ["what is", "define", "meaning of", "explain"],
            "keywords": {"what", "define", "meaning", "explain"},
        },
        "comparison": {
            "phrases": ["difference between", "compare", "vs", "versus"],
            "keywords": {"difference", "compare", "vs", "versus"},
        },
        "thanks": {
            "phrases": ["thanks", "thank you"],
            "keywords": {"thanks", "thank", "appreciate"},
        },
        "follow_up": {
            "phrases": ["more", "explain more", "continue", "tell me more", "give example", "simplify"],
            "keywords": {"more", "continue", "example", "simplify"},
        },
    }

    scores = {}
    for intent, config in intent_map.items():
        score = 0

        for phrase in config["phrases"]:
            if phrase in lower:
                score += 3

        for keyword in config["keywords"]:
            if keyword in tokens:
                score += 1

        scores[intent] = score

    return scores


def detect_primary_intent(text: str) -> str:
    scores = get_intent_scores(text)
    best_intent = max(scores, key=scores.get)
    if scores[best_intent] <= 0:
        return "general"
    return best_intent


def format_steps(topic: str) -> str:
    return (
        f"Here is a simple step-by-step explanation for {topic}:\n\n"
        f"1. Understand the basic idea of {topic}.\n"
        f"2. Identify the main parts or process involved.\n"
        f"3. Apply it using a simple example.\n"
        f"4. Review the result and refine your understanding.\n\n"
        f"If you want, ask me to make it simpler, more detailed, or give an example about {topic}."
    )


def format_definition(topic: str) -> str:
    return (
        f"{topic.capitalize()} is a concept or topic that can be understood by looking at its purpose, main parts, and how it is used in practice.\n\n"
        f"If you want, I can explain {topic} in a simpler way, give an example, or make it step by step."
    )


def format_comparison(topic: str) -> str:
    parts = re.split(r"\bvs\b|\bversus\b|\bdifference between\b|\bcompare\b", topic, flags=re.I)
    cleaned = [p.strip(" ,.?") for p in parts if p.strip(" ,.?")]
    if len(cleaned) >= 2:
        a = cleaned[0]
        b = cleaned[1]
        return (
            f"Here is a simple comparison between {a} and {b}:\n\n"
            f"- {a}: usually focuses on its own role, features, or purpose.\n"
            f"- {b}: differs in function, structure, or use depending on the context.\n\n"
            f"If you want, send the exact two terms again and I will compare them more specifically."
        )
    return "Please send the two things you want me to compare, and I will explain their differences clearly."


def programming_reply(text: str) -> str:
    lower = text.lower()

    if "recursion" in lower:
        return (
            "Recursion is a programming technique where a function calls itself to solve a problem in smaller parts.\n\n"
            "Python example:\n"
            "def factorial(n):\n"
            "    if n == 0:\n"
            "        return 1\n"
            "    return n * factorial(n - 1)\n\n"
            "In this example, the function keeps calling itself until it reaches the base case, which is n == 0."
        )

    if "loop" in lower:
        return (
            "A loop is used to repeat a block of code.\n\n"
            "Python example:\n"
            "for i in range(3):\n"
            "    print(i)\n\n"
            "This prints numbers from 0 to 2."
        )

    if "function" in lower:
        return (
            "A function is a reusable block of code that performs a specific task.\n\n"
            "Python example:\n"
            "def greet(name):\n"
            "    return f'Hello, {name}'\n\n"
            "Functions help organize and reuse code."
        )

    if "debug" in lower or "bug" in lower or "error" in lower:
        return (
            "Debugging means finding and fixing problems in code.\n\n"
            "A simple debugging process is:\n"
            "1. Read the error message.\n"
            "2. Find the line where the error happened.\n"
            "3. Check variable names, syntax, and logic.\n"
            "4. Test again after fixing."
        )

    return (
        "I can help with programming topics like variables, conditions, loops, functions, recursion, debugging, and basic code examples."
    )


def materials_reply() -> str:
    return (
        "The system allows professors to create and manage learning materials, classroom activities, quizzes, and exams. "
        "Students can view the posted academic content through their account."
    )


def tickets_reply() -> str:
    return (
        "You can create a support ticket by providing a subject, description, and priority. "
        "The system can also categorize concern priority using keyword-based logic."
    )


def attendance_reply() -> str:
    return (
        "The attendance module allows authorized users such as professors or administrators to mark users as present, late, or absent and review attendance summaries."
    )


def account_reply() -> str:
    return (
        "For password or account concerns, please use the system recovery options if available or contact the administrator for assistance."
    )


def writing_reply() -> str:
    return (
        "I can help rewrite text, improve grammar, simplify writing, shorten sentences, make messages more formal, or make them sound more natural."
    )


def thesis_nlp_reply() -> str:
    return (
        "This system uses Natural Language Processing or NLP through keyword matching, intent detection, context-aware follow-up handling, and predefined response generation to interpret user input and provide relevant replies."
    )


def build_general_response(text: str, history: list | None = None) -> str:
    lower = str(text or "").lower()
    topic = extract_topic_from_text(text)
    last_topic = extract_last_user_topic(history)

    if re.search(r"\bwhat is\b|\bdefine\b|\bmeaning\b|\bexplain\b", lower):
        return format_definition(topic or last_topic or "this topic")

    if re.search(r"\bhow to\b|\bhow do i\b|\bhow can i\b|\bsteps\b", lower):
        return format_steps(topic or last_topic or "this process")

    if re.search(r"\bcompare\b|\bdifference between\b|\bvs\b|\bversus\b", lower):
        return format_comparison(topic or text)

    if re.search(r"\bwhy\b", lower):
        return (
            f"The reason usually depends on the context of {topic or 'the topic you asked about'}. "
            f"In general, the best way to explain it is to look at its purpose, cause, and effect. "
            f"Send the exact topic again and I will explain it more specifically."
        )

    if re.search(r"\bexample\b", lower):
        return (
            f"Sure. I can give an example about {topic or last_topic or 'that topic'}. "
            f"Please send the exact subject again so I can make the example more accurate."
        )

    return (
        "I understand your question. I can answer many common topics using NLP-based intent detection and response logic, "
        "but I work best when your message is specific. Try asking for an explanation, steps, comparison, example, or help about the system features."
    )


def generate_nlp_reply(input_text: str, history: list | None = None, role: str = "guest") -> str:
    text = str(input_text or "").strip()
    lower = text.lower()
    history = history or []
    role = str(role or "guest").strip().lower()

    last_user = None
    for item in reversed(history):
        if item.get("role") == "user":
            last_user = item.get("content", "")
            break

    role_label = {
        "student": "student",
        "professor": "professor",
        "administrator": "administrator",
        "admin": "administrator",
    }.get(role, "user")

    if not text:
        return "Please type your question so I can help."

    if re.search(r"\b(hi|hello|hey|good morning|good afternoon|good evening)\b", lower):
        return f"Hello. I am your NLP-based virtual support assistant for {role_label}s. How can I help you today?"

    if re.search(r"\b(who are you|what can you do)\b", lower):
        base = (
            "I am an NLP-based virtual support assistant. "
            "I can answer common questions, explain concepts, and help users navigate the system."
        )

        if role == "student":
            return base + " As a student, you can ask me about materials, quizzes, exams, attendance, writing help, and programming topics."
        if role == "professor":
            return base + " As a professor, you can ask me about materials, quizzes, exams, attendance, classroom tasks, writing help, and programming topics."
        if role in ("administrator", "admin"):
            return base + " As an administrator, you can ask me about users, roles, ticket management, audit logs, attendance access, and system-related concerns."
        return base

    if re.search(r"\b(nlp|natural language processing|thesis|methodology|system)\b", lower):
        return (
            "This chatbot uses Natural Language Processing or NLP through keyword matching, intent detection, "
            "context-aware follow-up handling, and predefined response generation to interpret user input and provide relevant replies."
        )

    if re.search(r"\b(attendance|present|late|absent)\b", lower):
        if role in ("professor", "administrator", "admin"):
            return "You can use the attendance module to mark users as present, late, or absent and review attendance summaries by date."
        return "As a student, attendance information is managed by authorized users such as professors or administrators."

    if re.search(r"\b(ticket|support|issue|problem|concern|complaint)\b", lower):
        if role in ("administrator", "admin"):
            return "You can review all support tickets, update ticket status, and manage ticket resolution through the admin panel."
        return (
            "You can create a support ticket by entering a subject, description, and priority. "
            "The system can also categorize some concerns automatically based on keywords."
        )

    if re.search(r"\b(material|activity|lesson|quiz|exam|study guide)\b", lower):
        if role == "professor":
            return "As a professor, you can create and manage learning materials, activities, quizzes, and exams for students."
        if role == "student":
            return "As a student, you can view materials, activities, quizzes, and exams posted by your professor."
        if role in ("administrator", "admin"):
            return "The system supports academic content such as materials, activities, quizzes, and exams, mainly for professor and student use."
        return "The system supports materials, activities, quizzes, and exams for academic use."

    if re.search(r"\b(user|users|role|roles|admin|administrator)\b", lower):
        if role in ("administrator", "admin"):
            return "As an administrator, you can manage users, review account roles, update user roles, and monitor system records."
        return "User and role management is restricted to administrators."

    if re.search(r"\b(audit|blockchain|hash|integrity|logs)\b", lower):
        if role in ("administrator", "admin"):
            return "You can review audit logs and verify the integrity of recorded system events through the audit and blockchain-related modules."
        return "You can view your own audit-related records, while full audit access is restricted to administrators."

    if re.search(r"\b(password|reset password|forgot password|account problem|login problem|cannot login|can't login)\b", lower):
        return "For password or login concerns, please use the available recovery options in the system or contact the administrator for assistance."

    if re.search(r"\b(write|rewrite|grammar|essay|message|email|caption)\b", lower):
        return "I can help rewrite text, improve grammar, simplify writing, shorten sentences, or make your message clearer and more natural."

    if re.search(r"\b(python|programming|code|coding|function|loop|recursion|debug)\b", lower):
        if "recursion" in lower:
            return (
                "Recursion is a programming technique where a function calls itself to solve a problem in smaller parts.\n\n"
                "Example in Python:\n"
                "def factorial(n):\n"
                "    if n == 0:\n"
                "        return 1\n"
                "    return n * factorial(n - 1)\n\n"
                "In this example, the function keeps calling itself until it reaches the base case, which is n == 0."
            )
        if "loop" in lower:
            return (
                "A loop repeats a block of code.\n\n"
                "Example in Python:\n"
                "for i in range(3):\n"
                "    print(i)\n\n"
                "This prints 0, 1, and 2."
            )
        return "I can help explain programming concepts such as variables, conditions, loops, functions, recursion, debugging, and basic Python examples."

    if re.search(r"\b(thank|thanks)\b", lower):
        return "You are welcome. Let me know if you need more help."

    if last_user and re.search(r"\b(more|continue|explain more|elaborate|simplify|example)\b", lower):
        return f'You are asking for more details about: "{last_user}". Please send the exact topic again and I will continue the explanation.'

    if re.search(r"\b(what is|define|meaning of|explain)\b", lower):
        return "I can explain that, but I work best when the topic is specific. Please send the exact concept, feature, or process you want me to explain."

    if re.search(r"\b(how to|how do i|how can i|steps)\b", lower):
        return "I can give step-by-step guidance. Please send the exact task you want to do in the system."

    if re.search(r"\b(compare|difference between|vs|versus)\b", lower):
        return "I can compare the two items clearly. Please send the exact two terms or features you want me to compare."

    return (
        f"I understand your message as a {role_label}. "
        "Please ask a more specific question about attendance, tickets, materials, quizzes, exams, account concerns, writing help, programming, audit logs, or system features."
    )


def get_suggested_replies(message: str, reply: str) -> list[str]:
    text = str(message or "").lower()
    reply_lower = str(reply or "").lower()

    if re.search(r"\b(code|python|programming|function|loop|recursion|debug|error)\b", text):
        return [
            "Explain it simply",
            "Give a code example",
            "Show step by step",
            "What is the output?",
            "How do I fix errors?",
        ]

    if re.search(r"\b(quiz|exam|lesson|activity|study guide)\b", text):
        return [
            "Make it easier",
            "Make it harder",
            "Add answer key",
            "Turn it into multiple choice",
            "Make a lesson outline",
        ]

    if re.search(r"\b(write|rewrite|essay|message|email|grammar|caption)\b", text):
        return [
            "Make it more natural",
            "Make it shorter",
            "Make it formal",
            "Fix grammar only",
            "Make it persuasive",
        ]

    if re.search(r"\b(attendance|ticket|support|account|password)\b", text):
        return [
            "Explain the process",
            "Show step by step",
            "Who can access it?",
            "What does the system do?",
            "Summarize it",
        ]

    if re.search(r"\b(explain|what is|define|how|why|compare)\b", text) or "explain" in reply_lower:
        return [
            "Explain it simply",
            "Give an example",
            "Show step by step",
            "Compare it",
            "Summarize it",
        ]

    return [
        "Explain more",
        "Give an example",
        "Make it simpler",
        "Show step by step",
        "Summarize it",
    ]


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
        raise HTTPException(status_code=400, detail="Full name must be 2-80 letters and valid symbols only.")
    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail="Invalid role value.")
    if role == "administrator" and normalized_admin_code != ADMIN_INVITE_CODE_NORMALIZED:
        raise HTTPException(
            status_code=403,
            detail="Invalid admin access code. For local demo, default is ADMIN123 unless changed in environment variables.",
        )
    if not is_valid_email(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if not is_strong_password(password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8+ chars with upper/lowercase, number, and symbol.",
        )

    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="This email is already registered.")

        password_hash = hash_password(password)
        cursor = conn.execute(
            """
            INSERT INTO users (full_name, email, role, email_verified, password_hash, created_at)
            VALUES (?, ?, ?, 1, ?, ?)
            """,
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

    return {"message": "Account created successfully."}


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
            "SELECT id, email, role, email_verified, password_hash FROM users WHERE email = ?",
            (email,),
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
            "SELECT id, full_name, email, role, email_verified FROM users WHERE id = ?",
            (user_id,),
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
            email,
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
            email,
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
        ticket = conn.execute(
            "SELECT id, subject, user_email FROM support_tickets WHERE public_id = ?",
            (ticket_id,),
        ).fetchone()
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found.")

        conn.execute("DELETE FROM support_tickets WHERE public_id = ?", (ticket_id,))
        append_audit_event(
            conn,
            "admin_ticket_deleted",
            email,
            {"ticketId": ticket_id, "subject": ticket["subject"], "userEmail": ticket["user_email"]},
        )
        conn.commit()

    return {"message": "Ticket removed."}


@app.get("/api/attendance/summary")
def attendance_summary(request: Request, date: str | None = None):
    if not request.session.get("user_id"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not can_use_attendance(request):
        raise HTTPException(status_code=403, detail="Attendance is restricted to professors and administrators.")

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
        raise HTTPException(status_code=403, detail="Only professors and administrators can mark attendance.")

    status = payload.status.strip().lower()
    attendance_date = (payload.date or datetime.utcnow().date().isoformat()).strip()
    if status not in ("present", "late", "absent"):
        raise HTTPException(status_code=400, detail="Invalid attendance status.")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", attendance_date):
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")

    with get_conn() as conn:
        upsert_attendance(conn, email, attendance_date, status)
        append_audit_event(conn, "attendance_marked", email, {"date": attendance_date, "status": status})
        conn.commit()

    return {"message": "Attendance saved.", "date": attendance_date, "status": status}


@app.get("/api/attendance/today")
def attendance_today(request: Request, date: str | None = None):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not can_use_attendance(request):
        raise HTTPException(status_code=403, detail="Attendance is restricted to professors and administrators.")

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
        raise HTTPException(status_code=403, detail="Material and activities are for professors and students only.")

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
        raise HTTPException(status_code=403, detail="Material and activities are for professors only.")

    title = (payload.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required.")

    with get_conn() as conn:
        result = create_material_activity(conn, title, payload.description or "", request.session["email"])
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
        raise HTTPException(status_code=403, detail="Material and activities are for professors only.")
    if activity_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid activity id.")

    with get_conn() as conn:
        deleted = delete_material_activity(conn, activity_id, request.session["email"])
        if not deleted:
            raise HTTPException(status_code=404, detail="Activity not found or you can only delete your own.")
        append_audit_event(conn, "material_activity_deleted", request.session["email"], {"id": activity_id})
        conn.commit()

    return {"message": "Activity deleted."}


@app.get("/api/quiz")
def quiz_list(request: Request):
    if not request.session.get("user_id") or not request.session.get("email"):
        raise HTTPException(status_code=401, detail="Unauthorized")

    role = (request.session.get("role") or "student").lower()
    if role not in ("professor", "student"):
        raise HTTPException(status_code=403, detail="Quizzes and exams are for professors and students only.")

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
def quiz_create(payload: QuizCreatePayload, request: Request):
    if not request.session.get("user_id") or not request.session.get("email"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not is_professor_session(request):
        raise HTTPException(status_code=403, detail="Quizzes and exams are for professors only.")

    title = (payload.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required.")

    quiz_type = (payload.quizType or "quiz").strip().lower()
    if quiz_type not in ("quiz", "exam"):
        raise HTTPException(status_code=400, detail="quizType must be quiz or exam.")

    with get_conn() as conn:
        result = create_quiz(conn, title, payload.description or "", quiz_type, request.session["email"])
        append_audit_event(
            conn,
            "quiz_created",
            request.session["email"],
            {"id": result["id"], "title": title, "quizType": quiz_type},
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
        raise HTTPException(status_code=403, detail="Quizzes and exams are for professors only.")
    if quiz_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid quiz id.")

    with get_conn() as conn:
        deleted = delete_quiz(conn, quiz_id, request.session["email"])
        if not deleted:
            raise HTTPException(status_code=404, detail="Quiz not found or you can only delete your own.")
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

        user_row = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
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
        email,
        attendance,
        chain_valid,
        tickets,
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
    priority = requested_priority if requested_priority in ("low", "medium", "high") else inferred_priority

    if len(subject) < 4:
        raise HTTPException(status_code=400, detail="Subject must be at least 4 characters.")
    if len(description) < 10:
        raise HTTPException(status_code=400, detail="Description must be at least 10 characters.")
    if priority not in ("low", "medium", "high"):
        raise HTTPException(status_code=400, detail="Invalid priority value.")

    with get_conn() as conn:
        ticket_id = create_ticket(conn, email, subject, description, priority)
        append_audit_event(conn, "ticket_created", email, {"ticketId": ticket_id, "priority": priority})
        conn.commit()

    return {
        "message": "Ticket created successfully.",
        "ticketId": ticket_id,
        "priority": priority,
        "categorizedBy": "manual" if requested_priority in ("low", "medium", "high") else "system",
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

        append_audit_event(conn, "ticket_status_updated", email, {"ticketId": ticket_id, "status": next_status})
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
async def chat(payload: ChatPayload, request: Request):
    message = str(payload.message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message is required.")

    print("CHAT ENDPOINT CALLED", flush=True)
    print("User message:", message, flush=True)

    history = trim_chat_history(request.session.get("chat_history", []), 20)
    user_role = str(request.session.get("role", "guest")).strip().lower()

    reply = generate_nlp_reply(message, history, user_role)
    source = "nlp"

    print("REPLY SOURCE:", source, flush=True)
    print("USER ROLE:", user_role, flush=True)

    request.session["chat_history"] = trim_chat_history(
        history + [
            {"role": "user", "content": message},
            {"role": "assistant", "content": reply},
        ],
        20,
    )

    return {
        "reply": reply,
        "history": request.session["chat_history"],
        "source": source,
        "role": user_role,
        "suggestions": get_suggested_replies(message, reply),
    }

    return {
        "reply": reply,
        "history": request.session["chat_history"],
        "source": source,
        "suggestions": get_suggested_replies(message, reply),
    }


@app.post("/api/chat/stream")
async def chat_stream(payload: ChatPayload, request: Request):
    message = str(payload.message or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message is required.")

    print("CHAT STREAM ENDPOINT CALLED", flush=True)
    print("User message:", message, flush=True)

    history = trim_chat_history(request.session.get("chat_history", []), 20)
    user_role = str(request.session.get("role", "guest")).strip().lower()

    reply = generate_nlp_reply(message, history, user_role)
    source = "nlp"

    print("REPLY SOURCE:", source, flush=True)
    print("USER ROLE:", user_role, flush=True)

    request.session["chat_history"] = trim_chat_history(
        history + [
            {"role": "user", "content": message},
            {"role": "assistant", "content": reply},
        ],
        20,
    )

    suggestions = get_suggested_replies(message, reply)

    async def event_generator():
        for ch in reply:
            yield f"event: delta\ndata: {json.dumps({'text': ch})}\n\n"
            await asyncio.sleep(0.006)
        yield f"event: done\ndata: {json.dumps({'reply': reply, 'suggestions': suggestions, 'source': source, 'role': user_role})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/chat/history")
def chat_history(request: Request):
    history = trim_chat_history(request.session.get("chat_history", []), 20)

    if len(history) == 0:
        return {
            "history": [get_welcome_message()],
            "suggestions": [
                "What can you do?",
                "Explain recursion simply",
                "Help me write a quiz",
            ],
        }

    last_assistant = ""
    for item in reversed(history):
        if item.get("role") == "assistant":
            last_assistant = item.get("content", "")
            break

    return {
        "history": history,
        "suggestions": get_suggested_replies("", last_assistant),
    }


@app.delete("/api/chat/history")
def clear_chat_history(request: Request):
    request.session["chat_history"] = []
    return {
        "message": "Chat history cleared.",
        "suggestions": [
            "What can you do?",
            "Explain recursion simply",
            "Create a quiz about Python",
        ],
    }


@app.get("/")
def root():
    return FileResponse(BASE_DIR / "index.html")


app.mount("/", StaticFiles(directory=BASE_DIR, html=True), name="static")