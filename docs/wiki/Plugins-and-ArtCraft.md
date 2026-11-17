# Plugins & ArtCraft Integration

CoopMCP acts as a lazy router for local `stdio`, `http`, and `sse` MCP servers, plus a hardened Blender bridge.

## Discovering & Importing Local MCPs (Opt-In)

Open **Settings UI → Plugins & Local MCPs → Discover Local MCPs**:
- Scans standard config files for **Claude Desktop**, **Cursor**, **Windsurf**, **VS Code**, and **Gemini / Antigravity**.
- Lists starter `uvx` / `npx` templates (`sqlite`, `fetch`, `git`, `memory`).
- **Opt-in only**: Secrets are masked during preview and nothing is exposed until you check and import it into `apps.json`.
- Toggle **PIN Required** (`require_admin_unlock: true`) on any powerful plugin (e.g. shell or unrestricted filesystem) so remote AI clients cannot run it without your 1-hour Admin unlock.

## Pairing with ArtCraft

**[ArtCraft](https://getartcraft.com/)** is an open-source, pure-Rust creative and office software suite (`WordCraft`, `DeckCraft`, `GridCraft`, `PhotoCraft`, `VectorCraft`, `FigCraft`, `AniCraft`, `SoundCraft`, `FilmCraft`, `CADCraft`, `SolidCraft`, etc.) with built-in `*-cli mcp` servers.

1. Install ArtCraft locally or place its CLI binaries on `PATH`.
2. In CoopMCP Settings UI, enter your ArtCraft folder under **Optional Folder Scan** and click **Scan**.
3. CoopMCP matches binaries against `presets/artcraft.json` and automatically fills in each app's native sandbox flags (`--automation-read-root`, `--allow-path`, `--headless`, etc.) plus seconds-based timeline/waveform summaries for SoundCraft and FilmCraft.

## Hardened Blender Bridge

Load `blender_addon/coop_blender_mcp.py` in Blender (or let CoopMCP auto-launch headless Blender on demand):
- Loopback-only TCP (`127.0.0.1:9877` / `9878`) with optional `COOP_BLENDER_TOKEN`.
- AST + restricted-builtins Python sandbox on `execute_code` (blocks `os`, `subprocess`, `open`, dunder escapes).
- Automatically compresses viewport/camera renders into PNG `ImageContent` previews.
