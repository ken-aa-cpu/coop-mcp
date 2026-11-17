# CoopMCP Wiki 🐤

Welcome to the **CoopMCP** documentation!

CoopMCP is a sandboxed HTTPS MCP gateway, self-hosted OAuth 2.1 login server, and lazy local plugin router designed to connect **remote Web & Mobile AI clients** (such as Gemini, Claude, and other MCP clients) safely to your personal computer.

## Why CoopMCP?

- **Built for Remote Web/Mobile AI**: Single Streamable HTTP endpoint (`/mcp`) with OAuth 2.1 + PKCE, CORS, and `.well-known` discovery.
- **Keep AI Inside the Coop**: Default read/write path isolation keeps generated files in your designated output folder and blocks `.env` / private keys.
- **PIN-Gated Admin Elevation**: Need terminal or full-PC edits? Unlock temporarily (up to 1 hour) with your Admin PIN and revoke instantly from the chick system tray.
- **Lazy Plugin Router**: Wakes up local `stdio` / `http` / `sse` MCP servers and Blender only when needed, shutting them down when idle.
- **Trilingual Settings UI (`zh-Hant` / `en` / `ja`)**: Configure credentials, tunnels, and local MCP discovery in a loopback-only Web Dashboard.

## Wiki Navigation

1. [[Quick-Start]] — Double-click Windows launch, CLI setup, and connecting Gemini.
2. [[Fixed-Domain-Tunnels]] — How to get a permanent HTTPS URL without a static home IP.
3. [[Security-and-Sandbox]] — OAuth 2.1, loopback-only `/ui`, PIN elevation, and plugin gating.
4. [[Plugins-and-ArtCraft]] — Importing existing local MCPs and pairing with [ArtCraft](https://getartcraft.com/).
