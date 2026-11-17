# Changelog

## v0.1.0 — Initial Public Release

### Highlights
- **Sandboxed HTTPS MCP Gateway (`/mcp`)**: Single Streamable HTTP endpoint built for remote AI clients (Gemini Web & Mobile, etc.).
- **Self-Hosted OAuth 2.1 + PKCE**: PBKDF2-HMAC-SHA256 login page (`zh-Hant` / `en` / `ja`), CSRF protection, IP rate-limiting, and strict redirect URI allowlisting.
- **Two-Tier Sandbox & 1-Hour PIN Elevation**: Default read/write path isolation (`COOP_READ_ROOTS` / `COOP_WRITE_ROOT`), sensitive-file blocking, and temporary PIN-gated terminal/full-PC unlock with instant tray epoch revocation.
- **Lazy Multi-Transport Plugin Router**: On-demand `stdio`, `http`, and `sse` MCP workers with idle reaping, per-plugin `require_admin_unlock` gating, and non-blocking soft step consumption advisories (`COOP_SOFT_STEP_WARNING`).
- **Trilingual Loopback-Only Settings UI (`/ui`)**: Local Web Dashboard (`zh-Hant` / `en` / `ja`) strictly restricted to unproxied `127.0.0.1` / `::1` requests (`X-Forwarded-*` rejected).
- **Opt-In Local MCP Discovery & ArtCraft Ecosystem**: Scans existing AI client configs (`Claude Desktop`, `Cursor`, `Windsurf`, `VS Code`, `Gemini`), starter templates, and [ArtCraft](https://getartcraft.com/) `*-cli` apps with native sandbox flags + SoundCraft/FilmCraft timeline summaries.
- **Hardened Blender Bridge**: Loopback TCP bridge with AST + restricted-builtins Python sandbox and auto-headless background fallback.
- **Windows One-Click Launchers & Docker Support**: `CoopMCP.bat`, `Open_Settings_UI.bat`, chick system tray controller, and verified `Dockerfile`.
