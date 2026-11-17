# Fixed-Domain Tunnels (No Static Home IP Required)

CoopMCP uses **outbound reverse tunnels**: your PC initiates the connection outward, so it works behind dynamic residential IPs and carrier-grade NAT (CGNAT) without opening router ports.

## Comparing Tunnel Options

| Mode | URL Stability | Cost | Best For |
| --- | --- | --- | --- |
| **cloudflared Quick Tunnel** | New random URL on restart | Free, no account | Quick 5-minute trial |
| **Tailscale Funnel** | **Permanent `.ts.net` HTTPS URL** | Free personal tier | Easiest zero-VPS fixed URL |
| **ngrok Static Domain** | **Permanent `.ngrok-free.app` URL** | Free tier (1 static domain) | Fast setup (first OAuth load shows ngrok interstitial) |
| **Cloudflare Named Tunnel** | **Permanent custom domain** (`mcp.example.com`) | Domain registration only | Best reliability & speed |
| **SSH Reverse Tunnel + VPS** | **Permanent VPS / `.sslip.io` domain** | Own VPS | Full self-hosted control |

## Setup Recipes

### 1. Tailscale Funnel (Zero VPS, Zero Domain Purchase)
1. Install Tailscale and enable Funnel in your Tailscale ACLs.
2. Run `tailscale funnel --bg 8089`.
3. In CoopMCP Settings UI (**Tunnel & Domain**), select `none`, set **Public HTTPS Base URL** to `https://<machine>.<tailnet>.ts.net`, save, and restart.

### 2. Cloudflare Named Tunnel (Zero VPS, Custom Domain)
1. Add your domain to Cloudflare DNS and create a Zero Trust Tunnel routing to `http://127.0.0.1:8089`.
2. Run `cloudflared tunnel run --token <YOUR_TOKEN>`.
3. In CoopMCP Settings UI, select `none`, set **Public HTTPS Base URL** to `https://mcp.yourdomain.com`, save, and restart.
