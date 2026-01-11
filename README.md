# Plex OIDC Bridge

A lightweight OIDC (OpenID Connect) Provider that uses Plex for authentication. Designed specifically to bridge Plex users into identity flows like **Cloudflare Access**, **Tailscale**, or any other OIDC-compatible client.

## Features

- **Plex Authentication**: Users sign in via the standard Plex OAuth PIN flow.
- **OIDC Discovery**: Fully compliant `/.well-known/openid-configuration`.
- **JWKS Endpoint**: Automatically manages RSA signing keys for JWT verification.
- **Cloudflare Compatible**: Specifically tested with Cloudflare Access for homelab and media server security
- **Stable Identity**: Uses Plex `uuid` as the `sub` (subject) claim for stability, with email fallback.
- **Test Mode**: Optional built-in verification flow (`/test`) to verify the login process.

## Quick Start

### 1. Build & Run locally
```bash
# Build the binary
go build -o plex-bridge .

# Set your external URL (important for OIDC redirects)
export PUBLIC_URL="http://localhost:8080"
export ENABLE_TEST_ENDPOINTS="true"
export ALLOWED_REDIRECT_URIS="http://localhost:8080/test/callback"
export TRUST_PROXY_HEADERS="true"

# Start the bridge
./plex-bridge
```

### 2. Verify with Test Mode
Open your browser to `http://localhost:8080/test`. 
This will walk you through a complete Plex login and display the resulting OIDC claims (Email, Username, UUID, etc.).

## Docker Deployment

The recommended way to run this in a homelab is using Docker or Docker Compose.

### Running with Docker CLI
```bash
docker build -t plex-oidc-bridge .

docker run -d \
  -p 8080:8080 \
  -e PUBLIC_URL="https://auth.example.com" \
  -e ALLOWED_REDIRECT_URIS="https://example.com/callback,https://another.com/redirect" \
  -e TRUST_PROXY_HEADERS="true" \
  -v ./config:/app/config \
  --name plex-bridge \
  plex-oidc-bridge
```

### Running with Docker Compose
```yaml
services:
  plex-bridge:
    image: ghcr.io/blacktirion/plex-oidc-bridge:latest
    container_name: plex-auth-bridge
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config
    environment:
      - PUBLIC_URL=https://auth.example.com
      - PORT=8080
      - ALLOWED_REDIRECT_URIS=https://example.com/callback,https://another.com/redirect
      - TRUST_PROXY_HEADERS=true
    restart: unless-stopped
```

## First Run & Setup

On the first run, the bridge will generate an OIDC Client ID and Secret if you don't provide them. 
**Secrets are never printed to logs for security reasons.** Retrieve your credentials from the configuration file:

```bash
# View the generated Client ID and Secret
cat config/clients.json
```

You will see output like this, which you can copy/paste into Cloudflare Access or your identity platform of choice:

```json
{
  "client_id": "AbCdEfGhIjKlMnOpQrStUvWx",
  "client_secret": "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
}
```

Your OIDC endpoints are:
- **Auth URL**: `https://auth.example.com/authorize`
- **Token URL**: `https://auth.example.com/token`
- **JWKS URL (Certs)**: `https://auth.example.com/.well-known/jwks.json`
- **Discovery URL**: `https://auth.example.com/.well-known/openid-configuration`

## Configuration Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `PUBLIC_URL` | Env (Required) | - | The public HTTPS URL where this bridge is accessible (e.g., `https://auth.example.com`). The server will not start if this is unset. Used for discovery endpoints and OIDC redirects. |
| `PORT` | Env (Optional) | `8080` | The internal port the bridge listens on. |
| `ENABLE_TEST_ENDPOINTS` | Env (Optional) | `false` | Set to `"true"` to enable the `/test` debugging endpoints. |
| `ALLOWED_REDIRECT_URIS` | Env (Required) | *(none)* | Comma-separated whitelist of allowed `redirect_uri` values (must be `https`). If not set, authorization requests are rejected. |
| `TRUST_PROXY_HEADERS` | Env (Optional) | `false` | Set to `"true"` only if running behind a trusted reverse proxy (Cloudflare Tunnel, nginx, etc.). When enabled, rate limiting uses `X-Forwarded-For` and `X-Real-IP` headers instead of direct connection IP. |
| `SESSION_TTL_MINUTES` | Env (Optional) | `10` | TTL for Plex/OIDC session (PIN) state before it expires. |
| `AUTH_CODE_TTL_MINUTES` | Env (Optional) | `10` | TTL for issued authorization codes before they expire. |
| `OIDC_CLIENT_ID` | Env (Optional) | Generated | If set, forces the specific Client ID. If not set, one is generated and saved to `/app/config/clients.json`. |
| `OIDC_CLIENT_SECRET` | Env (Optional) | Generated | If set, forces the specific Client Secret. |

### Persistence
The bridge stores generated keys and configuration in `/app/config`. You should mount this volume to persist your RSA signing keys and Client credentials.
- `oidc.key`: The RSA private key for signing tokens.
- `clients.json`: Stores the generated Client ID and Secret.

### How Parameters Work
- **`PUBLIC_URL`**: This tells the bridge how to construct its own URLs. If you are using a Cloudflare Tunnel or Reverse Proxy, set this to your public domain.

## Cloudflare Access Configuration

To use this bridge with Cloudflare Access/Zero Trust:

1.  **Identity Provider**: Add a new **Generic OIDC** provider.
2.  **Get Your Credentials**: Retrieve your Client ID and Secret from `config/clients.json` (never from logs).
3.  **Configuration**:
    *   **Name**: Plex
    *   **App ID**: `<Client ID from config/clients.json>`
    *   **App Secret**: `<Client Secret from config/clients.json>`
    *   **Auth URL**: `https://your-bridge-url.com/authorize`
    *   **Token URL**: `https://your-bridge-url.com/token`
    *   **Certificate URL**: `https://your-bridge-url.com/.well-known/jwks.json`
4.  **Scopes**: Ensure `openid`, `email`, and `profile` are requested.

## License

MIT
