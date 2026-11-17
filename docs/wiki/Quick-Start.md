# Quick Start

## Option A: Windows Double-Click (Recommended for Most Users)

1. Download or clone the repository.
2. Double-click **`CoopMCP.bat`**:
   - Automatically installs dependencies via `uv sync --extra dev` on first launch.
   - Starts the Chick system tray controller silently in the background.
   - Opens the trilingual **Settings UI** (`http://127.0.0.1:8089/ui`) in your browser.
3. In **Sandbox & Security**, set:
   - **OAuth Login Password** (min 8 characters) — used when connecting from Gemini, Claude, or other remote MCP clients.
   - **Admin Unlock PIN** (min 4 characters) — optional second-layer PIN for temporary terminal access.
   - **OAuth Redirect Policy** — choose **Strict Allowlist** (Gemini + Claude + custom hosts) or **Allow Any HTTPS Redirect (Use at your own risk)**.
4. Configure your tunnel in **Tunnel & Domain**, save, and click **Restart Gateway** from the chick tray icon.
5. Anytime later, double-click **`Open_Settings_UI.bat`** or right-click the chick tray icon → **Open Settings UI**.

> **Note**: Until you configure an OAuth password, `/mcp` stays locked (`503 Service Unavailable`) while `/ui` remains accessible locally so you can finish setup safely.

---

## Option B: Command Line / Linux / Docker

```powershell
uv sync --extra dev
Copy-Item .env.example .env
uv run python set_oauth_password.py
uv run python set_oauth_password.py --pin
uv run python server.py
```

Or verify everything inside Docker:

```powershell
docker build -t coop-mcp:test .
docker run --rm coop-mcp:test
```

---

## Connecting from Gemini, Claude, or Other Remote MCP Clients

1. Copy the **MCP Endpoint URL** (`https://your-domain/mcp`) from the Settings UI or tray menu.
2. Add it in **Gemini Settings → Connected Apps**, **Claude Settings → Connectors**, or any remote MCP client supporting OAuth 2.1 + PKCE (leave Client Secret empty for DCR / standard OAuth).
3. Complete the CoopMCP password prompt in the OAuth popup.
