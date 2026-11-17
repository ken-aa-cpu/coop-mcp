# Security & Sandbox Architecture

Exposing your local machine to a remote AI over HTTPS requires strict defense-in-depth:

## 1. OAuth 2.1 + PKCE Authentication
- Always keep `COOP_REQUIRE_OAUTH=true` when exposing CoopMCP through a public tunnel.
- Static `?key=` authentication is automatically **rejected** on `/mcp` whenever OAuth is enabled.
- Supports PKCE `S256`, CSRF-protected PBKDF2-HMAC-SHA256 login forms, IP brute-force lockout, and two redirect modes (`COOP_OAUTH_REDIRECT_MODE`):
  - **Strict Mode (Default)**: Only allows HTTPS callbacks to built-in **Gemini** (`gemini.google.com`, `oauth-redirect.googleusercontent.com`, `vertexaisearch.cloud.google.com`) and **Claude** (`claude.ai`, `claude.com`) hosts, plus optional `COOP_OAUTH_ALLOWED_REDIRECT_HOSTS`.
  - **Permissive Mode (Use at your own risk)**: Accepts any HTTPS callback URI (`permissive`) so third-party MCP clients can connect without manual allowlisting; always inspect the callback host displayed on the login prompt before signing in.

## 2. Loopback-Only Settings UI & Control Plane
- `/ui`, `/api/ui/*`, `/health`, and `/admin/revoke` strictly verify:
  1. Direct loopback peer IP (`127.0.0.1` or `::1`),
  2. **Zero proxy/forwarding headers** (`X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded`, `X-Real-IP`),
  3. Loopback `Origin` and valid `X-Coop-Local-Key` (`MCP_SECRET_KEY`).
- Public tunnels **cannot** reach your Settings UI or `/api/ui/*`.
- Password hashes, Admin PIN hashes, JWT secrets, and imported plugin secrets are never sent back in `GET /api/ui/state`.

## 3. Two-Tier Filesystem & Terminal Sandbox
- **Locked (Default)**: Reads limited to `COOP_READ_ROOTS`; writes confined to `COOP_WRITE_ROOT`; sensitive files (`.env`, `credentials.json`, SSH keys) blocked; shell execution disabled.
- **Admin Unlocked (PIN-gated, max 1 hour)**: `coop_unlock_system(pin)` verifies your PBKDF2-hashed PIN and issues a non-renewable 1-hour `admin_token`. Click **Lock & Revoke** in the tray or Settings UI anytime to bump the epoch and invalidate all active tokens immediately.

## 4. Soft Step Advisories (Non-Blocking)
- `plugin_batch_call` warns the AI client via a non-blocking `advisory` field when exceeding `COOP_SOFT_STEP_WARNING` (default `25`), instead of aborting mid-task.
- High-frequency call loops also emit sliding-window advisories to encourage step consolidation.
