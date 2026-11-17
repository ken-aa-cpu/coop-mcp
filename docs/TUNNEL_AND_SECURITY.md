# Remote Tunnel & Fixed-Domain Security Guide

CoopMCP connects remote Web and Mobile AI clients (such as Gemini Web/Mobile) to your local Windows PC over an **outbound HTTPS tunnel**. Because your PC initiates the outbound connection, **you do not need a static home IP or router port forwarding**, and it works behind dynamic IPs and carrier-grade NAT (CGNAT).

---

## 1. Choosing a Tunnel Mode

| Mode | URL Stability | Cost | Best For |
| --- | --- | --- | --- |
| **Quick Tunnel** (`cloudflared tunnel --url ...`) | Rotates on every restart | Free, no account | Quick local evaluation |
| **Tailscale Funnel** (`tailscale funnel 8089`) | **Permanent fixed `.ts.net` URL** | Free personal tier | Easiest zero-VPS fixed URL |
| **ngrok Static Domain** (`ngrok http --domain=...`) | **Permanent fixed `.ngrok-free.app` URL** | Free tier (1 static domain) | Fast setup (note: browser interstitial on first OAuth visit) |
| **Cloudflare Named Tunnel** (`cloudflared tunnel run --token ...`) | **Permanent custom domain** (`mcp.yourdomain.com`) | Domain registration only | Best stability, speed, and zero interstitials |
| **SSH Reverse Tunnel + VPS + Caddy** | **Permanent VPS / `.sslip.io` / custom domain** | Own VPS | Full self-hosted control |

### Example: Fixed Free URL with Tailscale Funnel
1. Install Tailscale and enable **Funnel** in your Tailscale ACL policy.
2. In CoopMCP Settings UI (`Tunnel & Domain`), set `COOP_TUNNEL_MODE=none` and `PUBLIC_URL=https://<machine>.<tailnet>.ts.net`.
3. Run `tailscale funnel --bg 8089`. Your Gemini MCP connection stays bound across PC reboots and IP changes.

### Example: Fixed Custom Domain with Cloudflare Named Tunnel
1. Add your domain to Cloudflare DNS and create a Zero Trust Tunnel pointing to `http://127.0.0.1:8089`.
2. In CoopMCP Settings UI, set `COOP_TUNNEL_MODE=none` and `PUBLIC_URL=https://mcp.yourdomain.com`.
3. Run `cloudflared tunnel run --token <YOUR_TUNNEL_TOKEN>` (or install it as a Windows service).

---

## 2. Mandatory Security Guardrails

Exposing a gateway to the public internet requires strict isolation. CoopMCP enforces the following layers:

1. **Always keep OAuth 2.1 + PKCE enabled (`COOP_REQUIRE_OAUTH=true`)**
   - Public `/mcp` endpoints reject static `?key=` query strings whenever OAuth is enabled, preventing URL leakage in browser history or proxy logs.
   - Login uses PBKDF2-HMAC-SHA256 password verification, CSRF tokens, IP rate-limiting, and configurable OAuth redirect policies (`COOP_OAUTH_REDIRECT_MODE=strict|permissive`):
     - `strict` (recommended default): restricts callbacks to built-in **Gemini** & **Claude** hosts plus `COOP_OAUTH_ALLOWED_REDIRECT_HOSTS`.
     - `permissive` (use at your own risk): accepts any HTTPS callback URL (and loopback `http://127.0.0.1|localhost`) for other MCP clients; always verify the callback host displayed on the login page before approving.
2. **Loopback-Only Settings UI & Control Plane (`/ui`, `/api/ui/*`, `/health`, `/admin/revoke`)**
   - Every local management route checks direct loopback peer IP (`127.0.0.1` / `::1`) **and rejects any request containing proxy headers** (`X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded`, `X-Real-IP`).
   - Browser requests also require a loopback `Origin` and `X-Coop-Local-Key` (`MCP_SECRET_KEY`), blocking remote tunnels and cross-site browser attacks from reading or changing settings.
   - Password hashes, Admin PIN hashes, JWT secrets, and imported plugin credentials are **never returned** in plaintext over `/api/ui/state`.
3. **Opt-In Local MCP Discovery**
   - Scanning desktop AI configs (`Claude Desktop`, `Cursor`, `Windsurf`, `VS Code`, `Gemini`) or local folders only **previews** candidates. Nothing is exposed until you explicitly select and import it into `apps.json`.
   - Powerful local tools (shell, unrestricted filesystem, browser automation) should be marked **Require Admin PIN Unlock** (`require_admin_unlock: true`) so remote AI clients cannot invoke them without your 1-hour PIN elevation token.
4. **Two-Tier Sandbox & Instant Revocation**
   - Keep `COOP_READ_ROOTS` and `COOP_WRITE_ROOT` scoped to dedicated workspace directories.
   - Use the chick system tray (`Lock Sandbox & Revoke Admin Tokens`) or Settings UI button to immediately invalidate all issued 1-hour `admin_token` JWTs.
