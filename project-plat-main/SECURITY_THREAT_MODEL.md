# Security Threat Model (STRIDE)

## Scope
- App: Virtual Support System (Node.js + SQLite)
- Assets: user credentials, sessions, ticket data, attendance data, audit chain
- Entry points: auth endpoints, ticket endpoints, attendance endpoints, chat endpoint, admin endpoints

## Threats And Mitigations

### 1. Spoofing
- Threat: attacker logs in as another user by guessing password.
- Mitigations:
- `bcrypt` password hashing.
- Rate limiting on auth routes.
- Account lockout after repeated failures.
- Optional MFA challenge at sign-in (`/api/auth/signin/verify-mfa`).

### 2. Tampering
- Threat: attacker alters audit or operational records.
- Mitigations:
- Parameterized SQL queries.
- Blockchain-style audit chain (`prev_hash`, `entry_hash`) with verification endpoint.
- Role checks for admin-only actions.

### 3. Repudiation
- Threat: user denies security-sensitive actions.
- Mitigations:
- Audit events for signup, signin, failed signin, lockout, ticket updates, attendance updates.
- Timestamped immutable audit rows.

### 4. Information Disclosure
- Threat: exposure of session tokens, credentials, or private records.
- Mitigations:
- Session cookies with `HttpOnly`, `SameSite`, `Secure` (production).
- Helmet security headers and CSP.
- Generic auth failure messages to reduce account enumeration.
- No plaintext password storage.

### 5. Denial Of Service
- Threat: brute force and abusive request floods.
- Mitigations:
- Global auth rate limit.
- Lockout window with retry timeout.
- Request body size cap (`100kb`).

### 6. Elevation Of Privilege
- Threat: user escalates role or accesses admin actions.
- Mitigations:
- Server-side role authorization checks.
- Protected admin routes.
- Admin invite code gate for administrator signup.

## Residual Risks
- SQLite data is not encrypted at rest by default.
- Email MFA depends on SMTP configuration.
- Backup encryption and key rotation policy not yet automated.

## Next Controls To Reach Higher Assurance
- Encrypt backups and sensitive fields.
- Add automated security tests (auth brute-force, input fuzzing).
- Add secret management and key rotation process.
- Add periodic dependency vulnerability scanning in CI.
