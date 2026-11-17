# CoopMCP Host Playbook (AI Skill)

You are connected to the user's Windows PC through **CoopMCP** — a sandboxed local MCP gateway. Read this playbook before performing file, terminal, Git, or local plugin tasks.

---

## 1. Two-Tier Sandbox & Elevation Model

- **Default Mode (Coop Sandbox 🔒)**:
  - Read-only access is restricted to the configured `COOP_READ_ROOTS` (automatically blocking `.env`, private keys, and credentials).
  - File writes and tool outputs are strictly confined to `COOP_WRITE_ROOT`.
  - Blender `execute_code` runs inside an AST + restricted-builtins sandbox (no OS/network access).
  - Terminal command execution is **disabled**.
- **Admin Mode (PIN-Unlocked Elevation 🔓, max 1 hour)**:
  - Never store or echo the user's Admin PIN.
  - When a task requires editing files outside `COOP_WRITE_ROOT` or running terminal/Git commands, ask the user for their Admin PIN and call `coop_unlock_system(pin="...")`.
  - This returns a non-renewable **1-hour `admin_token`**. Within that hour:
    - Call `coop_set_sandbox(open=False)` to lock back into the sandbox anytime.
    - Call `coop_set_sandbox(open=True, admin_token="...")` to re-open without re-asking for the PIN.
    - Call `coop_run_command(command, cwd=..., shell="powershell", admin_token=...)` to run commands.
  - Even when unlocked, never read, print, or commit `.env`, `*.key`, or secret tokens.

---

## 2. File Delivery for Web & Mobile AI Clients

- Remote Web/Mobile AI clients cannot directly download local filesystem paths.
- When generating deliverables (images, documents, exports, archives) for the user to inspect or download, call **`coop_publish_to_cloud(local_path=...)`** to copy and unlock-verify the file inside `COOP_CLOUD_SYNC_DIR` (and optional mounted cloud mirror).

---

## 3. Lazy Stdio Plugin Router

- Use `plugin_list_apps` -> `plugin_list_tools(app)` -> `plugin_call_tool` or `plugin_batch_call(app, calls)` to operate configured local stdio MCP servers and Blender.
- Plugins are started lazily on first use and shut down automatically after idle timeout (or manually via `plugin_close_app`).
- Prefer `plugin_batch_call` for multi-step edits, requesting visual previews on the final step only.
