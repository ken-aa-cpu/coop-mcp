# Rust (Core) + Python (Plugin) Architecture Evaluation

This note evaluates splitting **CoopMCP** into a **Rust Core** binary paired with **Python Plugins**, based on the current Python codebase.

## 1. Module-by-Module Split

| Responsibility | Current Python Module | Rust Core (`coop-core`) Fit | Notes |
| --- | --- | --- | --- |
| HTTPS Streamable HTTP + OAuth 2.1 + PKCE | `server.py`, `oauth_provider.py` | **Excellent** (`axum` + `tokio` + `jsonwebtoken`) | Single native binary, ~10–15 MB RAM, zero GIL contention. |
| Path Sandbox & Text/File Search | `files_tools.py` | **Excellent** (`dunce`, `walkdir`, `ignore`, `image`) | Orders-of-magnitude faster file/regex search and cleaner canonicalization. |
| PIN Gate, Epoch Revocation & Shell Runner | `admin_privilege.py` | **Excellent** (`tokio::process`, `pbkdf2`) | Native `CREATE_NO_WINDOW`, timeouts, and JWT epoch checks. |
| Tray Icon, Tunnel Supervisor & Idle Reaper | `tray_app.py`, `plugin_router.py` | **Very Good** (`tray-icon` + `tokio`) | Collapses `tray_app.py` + `server.py` into one executable. |
| App Bridges & Custom Automation | `blender_addon/`, custom tools | **Keep in Python / Stdio Plugins** | `bpy` runs inside Blender's Python; rapid scripting/AI libs belong in Python. |

## 2. How Rust Core Should Talk to Python Plugins

### Option A: Stdio MCP / JSON-RPC Child Processes (Recommended)
Rust Core acts as the **MCP Gateway & Router**, spawning Python (or Node/Go/Rust) plugins lazily over `stdin`/`stdout` (exactly how `plugin_router.py` already works!).

- **Why this wins on Windows**:
  - **No `PyO3` / `python3xx.dll` ABI lock-in**: Users don't break when their system Python, `uv` venv, or Blender Python version differs.
  - **Fault isolation**: A crashing or memory-leaking Python plugin never takes down the Rust Gateway or Windows Tray.
  - **Language agnostic**: Any standard MCP `stdio` server works out of the box via `apps.json`.

### Option B: Embedded Python via `PyO3` (Not Recommended)
Embedding CPython inside Rust Core couples the `.exe` to a specific `python3xx.dll`, complicates async/GIL scheduling, and still cannot host tools like Blender (which embeds its own Python runtime).

## 3. Practical Verdict

- **Feasible?** Yes — `CoopMCP`'s architecture already separates Core (auth, sandbox, HTTP, process supervision) from Plugins (lazy `stdio` MCP workers & Blender TCP bridge).
- **Worth doing?**
  - **Yes**, if the goal is **zero-setup distribution** (a single ~15 MB `coop-mcp.exe` anyone can double-click without installing `uv` or Python) and sub-20 MB background memory usage.
  - **Skip/defer**, if the goal is rapid personal iteration — pure Python moves 3–5x faster when experimenting with new MCP spec details and tool schemas, and network/tunnel latency dominates HTTP overhead anyway.
