# CoopMCP 🐤

> **A sandboxed HTTPS MCP gateway, OAuth 2.1 login gate, and lazy stdio plugin router connecting remote AI clients (Gemini Web & Mobile, etc.) to your local Windows PC.**

CoopMCP keeps your AI assistant safely inside the "coop" (a read/write path sandbox) by default, lazily wakes up local `stdio` MCP plugins or Blender only when needed, and requires explicit PIN-gated elevation for temporary full-PC or terminal access.

## Features

- **Single HTTPS Streamable HTTP Endpoint (`/mcp`)**: Designed for remote Web/Mobile MCP clients, with built-in CORS and `.well-known/oauth-protected-resource` discovery.
- **Self-Hosted OAuth 2.1 + PKCE + Rate Limiting**: PBKDF2-HMAC-SHA256 login page, CSRF protection, strict redirect URI allowlist, and JWT Bearer/Refresh tokens (or optional static key mode for private setups).
- **Two-Tier Sandbox & 1-Hour PIN Elevation**:
  - **Locked (Default)**: Reads confined to `COOP_READ_ROOTS`, writes confined to `COOP_WRITE_ROOT`, sensitive files (`.env`, keys) blocked, terminal disabled.
  - **Admin Unlocked (PIN-gated, max 1h)**: Non-renewable `admin_token` with instant epoch-based revocation from the system tray.
- **Lazy Stdio Plugin Router (`apps.json`)**: Starts local `stdio` MCP tools on demand (`plugin_list_tools`, `plugin_call_tool`, `plugin_batch_call`) and shuts them down after idle timeout.
- **Hardened Blender Bridge (`blender_addon/coop_blender_mcp.py`)**: Loopback TCP bridge with optional token auth, AST + restricted-builtins sandbox for `execute_code`, auto-headless fallback, and automatic PNG `ImageContent` preview compression.
- **Windows System Tray Controller (`tray_app.py`)**: Chick mascot icon, tunnel supervisor (`cloudflared`, `ssh` reverse tunnel, or `ngrok`), quick-copy MCP URL, and one-click admin token revocation.

## Quick Start

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

### Connecting from Gemini Web / Mobile

1. Configure your HTTPS tunnel (`PUBLIC_URL` + `COOP_TUNNEL_MODE=cloudflared|ssh|ngrok` in `.env`).
2. Copy the endpoint URL (`https://your-domain/mcp`) from the tray menu.
3. Add it in **Gemini Settings → Connected Apps / MCP Servers**. When prompted, enter the password you configured in step 3.

### Adding Local Plugins (`apps.json`)

Copy [apps.example.json](apps.example.json) to `apps.json` and add any `stdio` MCP servers (Python `uvx`, Node `npx`, or local CLI executables supporting `mcp`). CoopMCP will launch them lazily on first tool call and reap idle workers automatically.

## Running Tests

```powershell
uv run python tests/run_all.py
```

## Architecture & Rust Core Evaluation

See [docs/RUST_CORE_EVALUATION.md](docs/RUST_CORE_EVALUATION.md) for notes on the **Rust Core + Python Plugin** split.

## License

[MIT](LICENSE)
