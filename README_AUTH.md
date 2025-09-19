Auth overview

- Login: POST /api/auth/login with { email, password } returns { access_token, token_type, expires_in_minutes }.
- Use Authorization: Bearer <token> for protected routes.
- Logout: POST /api/auth/logout (Authorization header required) revokes current token.
- Token lifetime defaults to 7 days; override via env ACCESS_TOKEN_EXPIRE_MINUTES.

Notes

- This setup uses a token blacklist table for logout. Ensure DB migrations/tables are created (app startup creates metadata).
- For production, store hashed passwords and use HTTPS.

## Password Reset Flow (Email OTP)

Endpoints:

1. POST /api/auth/password/forgot
	Payload: { "email": "user@example.com" }
	- Generates a 6-digit code (invalidates prior active codes)
	- Persists to `otps` table with 10 minute expiry
	- Emails code if ENABLE_EMAIL_NOTIFICATIONS=1
	- Always returns a generic success message to prevent email enumeration.

2. POST /api/auth/password/reset
	Payload: { "email": "user@example.com", "code": "123456", "newPassword": "newPass123" }
	- Validates unused, unexpired code
	- Updates user.password (plaintext in this demo – replace with hashing)
	- Marks OTP used and sends confirmation email

Config:
- ENABLE_EMAIL_NOTIFICATIONS (default 1)
- EMAIL_BACKEND=console (development) or smtp

Frontend:
- /forgot-password page handles request + reset steps
- Services: requestPasswordReset, resetPassword in src/services/auth.js

Security recommendations (future):
- Hash passwords (bcrypt/argon2)
- Rate limit /password/forgot
- Lock account or add captcha after multiple failed reset attempts
- Invalidate user sessions after password change
