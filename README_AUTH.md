Auth overview

- Login: POST /api/auth/login with { email, password } returns { access_token, token_type, expires_in_minutes }.
- Use Authorization: Bearer <token> for protected routes.
- Logout: POST /api/auth/logout (Authorization header required) revokes current token.
- Token lifetime defaults to 7 days; override via env ACCESS_TOKEN_EXPIRE_MINUTES.

Notes

- This setup uses a token blacklist table for logout. Ensure DB migrations/tables are created (app startup creates metadata).
- For production, store hashed passwords and use HTTPS.
