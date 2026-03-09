# Virtual Support System (Secure Auth)

This project now uses a secure backend and database:

- Backend: Node.js + Express
- Database: SQLite (`app.db`)
- Auth Security: `bcrypt` password hashing, session cookies, rate limiting, Helmet
- Optional login MFA (6-digit code), account lockout policy, and audit logging

It also includes a Python version:

- Backend: Python + FastAPI
- Database: SQLite (`app.db`)
- Auth Security: PBKDF2-SHA256 password hashing, signed session cookies

## 1. Install dependencies

```bash
npm install
```

## 2. Configure environment

Copy `.env.example` to `.env` and set a strong `SESSION_SECRET`.
Set `ADMIN_EMAIL` to the account email that can open full-chain verification.
Set `ADMIN_INVITE_CODE` for secure Administrator sign-up.
Optional (Node backend): set `OPENAI_API_KEY` and `OPENAI_MODEL` for LLM-powered open-ended chat.
For email-based MFA delivery, set:
- `SMTP_HOST=smtp.gmail.com`
- `SMTP_PORT=465`
- `SMTP_USER=yourgmail@gmail.com`
- `SMTP_PASS=<Google App Password>`
- `SMTP_FROM=yourgmail@gmail.com`
Security toggles:
- `AUTH_MFA_ENABLED=true`
- `AUTH_LOCKOUT_MAX_ATTEMPTS=5`
- `AUTH_LOCKOUT_MINUTES=15`

Note: Use a Google App Password (not your normal Gmail password).

## 3. Run the server

```bash
npm start
```

Open:

`http://localhost:3000`

## API Endpoints

- `POST /api/auth/signup`
- `POST /api/auth/signin`
- `POST /api/auth/signin/verify-mfa`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `GET /api/audit/my`
- `GET /api/audit/admin/full` (admin only)
- `POST /api/chat` (guest and signed-in sessions)
- `GET /api/chat/history`
- `DELETE /api/chat/history`
- `GET /api/admin/users` (admin only)
- `PATCH /api/admin/users/:userId/role` (admin only)
- `GET /api/admin/tickets` (admin only)
- `PATCH /api/admin/tickets/:ticketId/status` (admin only)
- Sign-up supports roles: `student`, `professor`, `administrator` (`administrator` requires `adminCode`)
- `POST /api/tickets`
- `GET /api/tickets/my`
- `PATCH /api/tickets/:ticketId/status` (Node) / `PATCH /api/tickets/{ticket_id}/status` (Python)
- `GET /api/blockchain/ticker`
- `GET /api/attendance/summary`
- `POST /api/attendance/mark`
- `GET /api/attendance/today`

## Python Version (FastAPI)

## 2. Run Python server

```bash
uvicorn python_server:app --reload --port 3000
```

Open:

`http://localhost:3000`

## Blockchain Compiler

- Ganache
- Remix IDE
- Smart Contract (Solidity)

## Notes

- Frontend now calls backend APIs for sign-up/sign-in.
- Dashboard requires a valid server session.
- Do not use default session secrets in production.
- Admin verification page: `http://localhost:3000/admin.html`
- Threat model file: `SECURITY_THREAT_MODEL.md`
