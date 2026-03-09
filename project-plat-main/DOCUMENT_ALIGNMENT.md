# Document-Based Alignment (Face Recognition Excluded)

This system implementation is aligned to:
`Virtual-Support-System-with-Face-Recognition-and-NLP-Integration-Group.pdf`

## Explicit Scope Decision
- Face recognition is intentionally **excluded** from this implementation.
- All retained features are based on NLP, support workflow, attendance, role access, and secure logging.

## Implemented Features Aligned to the Document

1. NLP-based communication (text and voice)
- AI NLP chat page with open-ended Q&A.
- Voice-to-text input integrated in AI NLP Support Assistant.

2. Automated ticket organization/categorization
- Ticket priority can be auto-inferred from issue content (`low`, `medium`, `high`) when manual priority is not provided.
- Manual priority is still supported.

3. Proactive reminders and updates
- Notification panel with priority reminders.
- Includes total and unread reminder counters.

4. Attendance management
- Attendance summary and daily records.
- Access restricted to professor/administrator roles.

5. Secure record management and audit trail
- Hash-linked event logging (`prev_hash`, `entry_hash`) for integrity checks.
- User and admin audit views available.

6. Role-based access control
- Role-aware permissions for admin and attendance modules.

7. Security implementation
- Password hashing and session security.
- Rate limiting and account lockout.
- Optional MFA flow depending on email/SMTP configuration.

## Implementation Note
- Current “blockchain” behavior is implemented as a blockchain-style immutable audit chain in application/database layer.
- It is not an on-chain Ethereum deployment in the current codebase.
