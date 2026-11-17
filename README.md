# CoopMCP 🐤

> **A sandboxed HTTPS MCP gateway, OAuth 2.1 login gate, and lazy stdio/HTTP/SSE plugin router connecting remote AI clients (Gemini, Claude, and other MCP clients) to your local PC.**

CoopMCP keeps your AI assistant safely inside the "coop" (a read/write path sandbox) by default, lazily wakes up local `stdio` MCP plugins or Blender only when needed, and requires explicit PIN-gated elevation for temporary full-PC or terminal access.

## Features

- **Single HTTPS Streamable HTTP Endpoint (`/mcp`)**: Designed for remote Web/Mobile MCP clients, with built-in CORS and `.well-known/oauth-protected-resource` discovery.
- **Self-Hosted OAuth 2.1 + PKCE + Two Redirect Modes**: PBKDF2-HMAC-SHA256 login page (`zh-Hant` / `en` / `ja`), CSRF protection, JWT Bearer/Refresh tokens, and configurable redirect policy:
  - **Strict Mode (Default, Recommended)**: Allows only official **Gemini** and **Claude** OAuth callback hosts plus custom entries in `COOP_OAUTH_ALLOWED_REDIRECT_HOSTS`.
  - **Permissive Mode (Use at your own risk)**: Accepts any HTTPS redirect URI (`COOP_OAUTH_REDIRECT_MODE=permissive`) for third-party MCP clients.
- **Two-Tier Sandbox & 1-Hour PIN Elevation**:
  - **Locked (Default)**: Reads confined to `COOP_READ_ROOTS`, writes confined to `COOP_WRITE_ROOT`, sensitive files (`.env`, keys) blocked, terminal disabled.
  - **Admin Unlocked (PIN-gated, max 1h)**: Non-renewable `admin_token` with instant epoch-based revocation from the system tray.
- **Lazy Stdio / HTTP / SSE Plugin Router (`apps.json`)**: Starts local `stdio` MCP tools on demand (`plugin_list_tools`, `plugin_call_tool`, `plugin_batch_call`) or bridges local `http`/`sse` MCP endpoints, with soft consumption advisories above `COOP_SOFT_STEP_WARNING` (no forced crash) and automatic idle shutdown.
- **Opt-In Local MCP Discovery & Trilingual Settings UI (`zh-Hant` / `en` / `ja`)**: Loopback-only Web Dashboard (`/ui`, opened from the tray icon) to configure sandbox paths, credentials, fixed-domain tunnels, and selectively import existing MCP configs from Claude Desktop, Cursor, Windsurf, VS Code, or Gemini.
- **Hardened Blender Bridge (`blender_addon/coop_blender_mcp.py`)**: Loopback TCP bridge with optional token auth, AST + restricted-builtins sandbox for `execute_code`, auto-headless fallback, and automatic PNG `ImageContent` preview compression.
- **Windows System Tray Controller (`tray_app.py`)**: Chick mascot icon, tunnel supervisor (`cloudflared`, `ssh` reverse tunnel, or `ngrok`), quick-copy MCP URL, Settings UI launcher, and one-click admin token revocation.

## Quick Start

### Option A: Double-Click on Windows (No CLI Required)

1. Double-click **`CoopMCP.bat`** (auto-installs `.venv` via `uv` on first run, starts the Chick system tray icon, and opens the trilingual **Settings UI** in your browser).
2. In the Settings UI (`Sandbox & Security`), set your OAuth login password and Admin PIN, then save and restart the gateway from the tray menu.
3. Anytime later, double-click **`Open_Settings_UI.bat`** (or right-click the Chick tray icon → **Open Settings UI**).

### Option B: PowerShell / CLI

```powershell
# 1. Install dependencies (Python >= 3.11)
uv sync --extra dev

# 2. Configure environment
Copy-Item .env.example .env

# 3. Set OAuth login password and Admin unlock PIN (stored as PBKDF2-SHA256 hashes)
uv run python set_oauth_password.py
uv run python set_oauth_password.py --pin

# 4. Launch Windows System Tray (or run start_mcp.ps1)
uv run pythonw tray_app.py
```

### Connecting from Gemini, Claude, or Other Remote MCP Clients

1. Configure your HTTPS tunnel (`PUBLIC_URL` + `COOP_TUNNEL_MODE` in `.env` or Settings UI).
2. Copy the endpoint URL (`https://your-domain/mcp`) from the tray menu or Settings UI.
3. Add it as a custom remote MCP connector in **Gemini** (`Settings → Connected Apps`), **Claude** (`Settings → Connectors`), or another OAuth-capable MCP client.
4. Choose your **OAuth Redirect Policy** in **Sandbox & Security**:
   - **Strict (Default)**: Built-in allowlist for Gemini (`gemini.google.com`, `oauth-redirect.googleusercontent.com`) and Claude (`claude.ai`, `claude.com`), plus any custom hostnames you add.
   - **Permissive (At your own risk)**: Allows any HTTPS redirect URI for other MCP clients.

### Adding Local Plugins (`apps.json`) & Recommended ArtCraft Ecosystem

Copy [apps.example.json](apps.example.json) to `apps.json`, or use the Settings UI (**Plugins & Local MCPs → Discover Local MCPs**) to scan and import existing configs from Claude Desktop, Cursor, Windsurf, VS Code, or Gemini.

#### Recommended Open-Source Suite: [ArtCraft](https://getartcraft.com/)

CoopMCP pairs cleanly with **[ArtCraft](https://getartcraft.com/)** — an open-source, pure-Rust creative and office software suite (`WordCraft`, `DeckCraft`, `GridCraft`, `PhotoCraft`, `VectorCraft`, `FigCraft`, `AniCraft`, `SoundCraft`, `FilmCraft`, `CADCraft`, `SolidCraft`, etc.) that ships with built-in CLI MCP servers (`*-cli mcp`).

- If ArtCraft is installed on `PATH` or in a local folder, run **Folder Scan** in the Settings UI on your ArtCraft directory.
- CoopMCP uses [presets/artcraft.json](presets/artcraft.json) to automatically recognize installed ArtCraft binaries and apply each app's native sandbox flags (`--automation-read-root`, `--allow-path`, `--headless`, etc.), plus seconds-based timeline/waveform summaries for SoundCraft & FilmCraft.

## Running Tests

```powershell
uv run python tests/run_all.py
```

## Architecture, Fixed Domains & Security

- [docs/TUNNEL_AND_SECURITY.md](docs/TUNNEL_AND_SECURITY.md): Guide for permanent fixed HTTPS URLs (Tailscale Funnel, ngrok static domain, Cloudflare Named Tunnel, SSH+VPS) and security guardrails.
- [docs/RUST_CORE_EVALUATION.md](docs/RUST_CORE_EVALUATION.md): Notes on splitting into **Rust Core + Python Stdio Plugins**.

## License

[MIT](LICENSE)
