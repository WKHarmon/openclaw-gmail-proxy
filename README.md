# Agent Authorization Gateway

General-purpose authorization gateway that brokers access to multiple resource types on behalf of AI agents. Access is tiered, time-limited, and requires out-of-band human approval via Signal.

Currently supported providers:

- **Gmail** — read-only email access (OAuth, via Gmail API)
- **SSH** — certificate-based SSH access (via OpenBao/Vault SSH CA)

## Authentication

- **API Key** (required): Include `Authorization: Bearer <API_KEY>` header on all `/api/*` requests. The `/health` and `/approve/*` endpoints do not require the API key.
- **Cloudflare Access** (optional): If deployed behind Cloudflare Access, include `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers (service token from Cloudflare Zero Trust).

The API key is stored in Vault at `secret/your-project/authorization-gateway` (field: `api_key`). The gateway loads it at startup.

> **Note:** If not behind a reverse proxy with TLS, the gateway should only be exposed on a trusted internal network. The API key is transmitted in the clear without TLS.

## Approval Flow

When the agent requests elevated access via `POST /api/grants/request`, the approver receives a Signal message with an approve/deny prompt. They can reply via Signal or tap a link.

The agent can either:
- **Poll** `GET /api/grants/:id` until `status` changes from `pending`
- **Receive a callback** — the gateway automatically fires a POST to the configured callback URL on approval or denial (see [Callback](#grant-approval-callback) below). Set `callback: false` in the grant request to suppress this.

## Grant Management

These endpoints are shared across all resource types.

### `POST /api/grants/request`

Request elevated access. Sends a Signal notification to the approver.

Request body (common fields):
```json
{
  "resourceType": "gmail",
  "level": 1,
  "description": "Read flight confirmation",
  "durationMinutes": 10,
  "callback": true,
  "callbackSessionKey": "sess_abc123"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resourceType` | string | no | `"gmail"` (default) or `"ssh"` |
| `level` | int | yes | 1, 2, or 3 |
| `description` | string | yes | Human-readable reason (shown to approver) |
| `durationMinutes` | int | no | Requested duration (capped at 1440). Defaults vary by provider and level |
| `callback` | bool | no | Set to false to suppress callback on approval/denial (default: true) |
| `callbackSessionKey` | string | no | Opaque session key included in callback payload for routing to the requesting session |

Additional fields for Gmail grants:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `messageId` | string | Level 1 only | Gmail message ID |
| `query` | string | Level 2 only | Gmail search query |

Additional fields for SSH grants:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host` | string | Level 1 only | Target hostname (must be in config) |
| `principal` | string | Level 1 (optional), Level 3 (required) | Unix username for the certificate |
| `hostGroup` | string | Level 2 only | Host group name (must be in config) |
| `role` | string | no | Vault SSH role override (defaults to host/group config) |

Response:
```json
{
  "grantId": "g_11155f2e244bc44e",
  "status": "pending",
  "level": 1,
  "resourceType": "gmail",
  "durationMinutes": 10,
  "message": "Approval request sent. Poll GET /api/grants/g_11155f2e244bc44e for status."
}
```

### `GET /api/grants/:id`

Check grant status. Use this to poll if callbacks are suppressed.

Response:
```json
{
  "id": "g_11155f2e244bc44e",
  "level": 1,
  "status": "active",
  "resource_type": "gmail",
  "message_id": "abc123",
  "query": null,
  "description": "Read flight confirmation",
  "created_at": "2026-03-23T19:36:45.143218+00:00",
  "approved_at": "2026-03-23T19:37:01.964774+00:00",
  "expires_at": "2026-03-23T19:42:01.964774+00:00",
  "duration_minutes": 10
}
```

Possible `status` values: `pending`, `active`, `consumed` (provider-specific; for example Gmail Level 1 after the first body read), `expired`, `denied`, `revoked`.

### `GET /api/grants/active`

List all currently active (approved, not expired) grants.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `resourceType` | string | — | Optional filter: `"gmail"` or `"ssh"`. Omit to list all. |

Response:
```json
{
  "grants": [{ ... }, { ... }]
}
```

### `DELETE /api/grants/:id`

Revoke a grant early.

Response:
```json
{
  "grantId": "g_11155f2e244bc44e",
  "status": "revoked"
}
```

### Grant Approval Callback

The callback URL and authentication are configured server-side in `config.json`, not per-request. When a grant is approved or denied, the gateway automatically POSTs to the configured URL unless the grant request set `callback: false`.

- The callback URL is set in `config.json` under `callback.url`
- If `callback.cf_auth` is `true` in config, the gateway includes `CF-Access-Client-Id` and `CF-Access-Client-Secret` headers on the callback (credentials loaded from Vault)
- A Bearer token is loaded from Vault (path configured in `callback.hooks_token_vault_path`, field: `hooks_token`) and sent as `Authorization: Bearer <token>`

Callback request:
```json
POST <callback.url>
Content-Type: application/json
Authorization: Bearer <hooks_token>

{
  "grantId": "g_11155f2e244bc44e",
  "resourceType": "gmail",
  "level": 1,
  "status": "active",
  "expiresAt": "2026-03-23T19:42:01.964774+00:00"
}
```

For denials, `status` is `"denied"` and `expiresAt` is omitted.

---

## Gmail Provider

### Access Tiers

| Level | Access | Approval | Default Duration |
|-------|--------|----------|-----------------|
| 0 | Metadata, labels, profile, attachment list, thread list | None | Always on |
| 1 | Single message body + attachments | Signal reply or tap link | 5 min (single read, then consumed) |
| 2 | Messages matching a query, threads, history | Signal reply or tap link | 30 min |
| 3 | Full gmail.readonly | Signal reply or tap link | 15 min |

All levels can request durations up to 24 hours (1440 minutes).

### API Reference

Base URL: `https://approval.your-domain.com`

#### Level 0 — Always Available (no grant needed)

##### `GET /api/profile`

Returns the connected Gmail account info.

Response:
```json
{
  "emailAddress": "user@example.com",
  "messagesTotal": 432994,
  "threadsTotal": 333637,
  "historyId": "64398558"
}
```

##### `GET /api/emails`

Search/list emails. Returns metadata only.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `q` | string | `""` | Gmail search query (same syntax as Gmail search box) |
| `maxResults` | int | 20 | Max results per page (1-100) |
| `labelIds` | string | — | Comma-separated label IDs to filter by |
| `pageToken` | string | — | Pagination token from previous response |

Response:
```json
{
  "messages": [
    {
      "id": "19d17350285fe802",
      "threadId": "19d17350285fe802",
      "labelIds": ["UNREAD", "IMPORTANT", "CATEGORY_UPDATES"],
      "from": "United Airlines <notifications@united.com>",
      "to": "user@example.com",
      "subject": "Flight Confirmation",
      "date": "Sun, 22 Mar 2026 20:20:41 +0000 (UTC)",
      "internalDate": "1774210841000"
    }
  ],
  "nextPageToken": "...",
  "resultSizeEstimate": 201
}
```

##### `GET /api/emails/:id`

Get a single email. Always returns metadata. Returns `body` and `attachments` only if an active grant covers this message.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `override_sensitive` | bool | false | Override sensitive pattern redaction |

Response (no grant):
```json
{
  "metadata": { "id": "...", "from": "...", "subject": "...", ... },
  "attachments": [{"filename": "doc.pdf", "mimeType": "application/pdf", "size": 45032, "partId": "2"}],
  "access": "metadata_only",
  "body": null,
  "hint": "POST /api/grants/request to request read access."
}
```

Response (with grant):
```json
{
  "metadata": { ... },
  "attachments": [{"attachmentId": "ANGjd...", "filename": "doc.pdf", "mimeType": "application/pdf", "size": 45032, "partId": "2"}],
  "access": "level2",
  "grant": "g_11155f2e244bc44e",
  "body": "Full email body text..."
}
```

Note: `attachmentId` is only included when a grant is active (needed for download). Without a grant, only filename/size/mimeType metadata is returned.

Response (sensitive match, no override):
```json
{
  "metadata": { ... },
  "access": "level1",
  "grant": "g_...",
  "body": "[REDACTED — matches sensitive pattern: bank statement]",
  "sensitive": true
}
```

##### `GET /api/labels`

List all Gmail labels with message/thread counts.

Response:
```json
{
  "labels": [
    {
      "id": "INBOX",
      "name": "INBOX",
      "type": "system",
      "messagesTotal": 1234,
      "messagesUnread": 5,
      "threadsTotal": 800,
      "threadsUnread": 3
    }
  ]
}
```

##### `GET /api/labels/:id`

Get a single label's details (same shape as items in the list above).

##### `GET /api/emails/:id/attachments`

List attachment metadata for a message. No grant needed — does not return content.

Response:
```json
{
  "messageId": "19d17350285fe802",
  "attachments": [
    {
      "attachmentId": "ANGjd...",
      "filename": "receipt.pdf",
      "mimeType": "application/pdf",
      "size": 45032,
      "partId": "2"
    }
  ]
}
```

##### `GET /api/threads`

Search/list threads. Same query params as `GET /api/emails`.

Response:
```json
{
  "threads": [
    {
      "id": "thread123",
      "historyId": "..."
    }
  ],
  "nextPageToken": "...",
  "resultSizeEstimate": 42
}
```

#### Grant-Gated Endpoints

##### `GET /api/emails/:messageId/attachments/:attachmentId`

Downloads the attachment binary. Returns the raw file with correct `Content-Type` and `Content-Disposition` headers.

Requires a grant covering the parent message. Sensitive patterns on the parent message are checked — blocked unless `?override_sensitive=true` is passed.

Works with consumed Level 1 grants within the expiry window (so you can read the body and then download attachments in the same session).

##### `GET /api/threads/:id`

Returns all messages in a thread. Metadata is always returned for every message. Bodies are included only for messages covered by an active grant. Does **not** consume Level 1 grants.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `override_sensitive` | bool | false | Override sensitive pattern redaction |

Response:
```json
{
  "id": "thread123",
  "messages": [
    {
      "metadata": { "id": "msg1", "from": "...", "subject": "...", ... },
      "access": "metadata_only",
      "body": null
    },
    {
      "metadata": { "id": "msg2", ... },
      "attachments": [...],
      "access": "level2",
      "grant": "g_abc123",
      "body": "Email body text..."
    }
  ]
}
```

##### `GET /api/history`

Incremental changes since a given `historyId`. Requires an active Level 2 or 3 grant.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `startHistoryId` | string | **required** | Get this from `GET /api/profile` |
| `historyTypes` | string | — | Comma-separated: `messageAdded`, `messageDeleted`, `labelAdded`, `labelRemoved` |
| `labelId` | string | — | Filter to changes affecting this label |
| `maxResults` | int | 100 | Max results (1-500) |
| `pageToken` | string | — | Pagination token |

Response:
```json
{
  "history": [...],
  "nextPageToken": "...",
  "historyId": "64398600"
}
```

Returns 404 if `startHistoryId` is too old or invalid.

### Sensitive Email Filtering

Emails matching patterns in `sensitive_patterns.json` have their bodies replaced with a redaction notice, even with an active grant. Any grant level can override with `?override_sensitive=true`. Attachment downloads are also blocked for sensitive messages unless overridden.

### Level 1 Grant Lifecycle

Level 1 grants have a special "single read" semantic:

1. Grant is created with `status: pending`
2. Approver approves -> `status: active`, timer starts
3. First `GET /api/emails/:id` that returns a body -> `status: consumed`
4. After consumption, the grant is still valid for **attachment downloads** until it expires
5. `GET /api/threads/:id` does **not** consume Level 1 grants
6. Grant expires when the timer runs out -> `status: expired`

---

## SSH Provider

Certificate-based SSH access via OpenBao (Vault) SSH secrets engine. The gateway signs ephemeral user certificates scoped to specific hosts, host groups, or principals.

### Access Tiers

| Level | Access | Approval | Default Duration |
|-------|--------|----------|-----------------|
| 0 | List configured hosts and host groups | None | Always on |
| 1 | Single host certificate | Signal reply or tap link | 5 min |
| 2 | Host group certificate | Signal reply or tap link | 30 min |
| 3 | Broad principal access | Signal reply or tap link | 15 min |

SSH grants are not consumed when a certificate is issued. The certificate itself is short-lived, but you can issue another certificate from the same still-active grant until the grant expires.

### SSH API Reference

#### Level 0 — Always Available (no grant needed)

##### `GET /api/ssh/hosts`

List configured SSH hosts and host groups.

Response:
```json
{
  "hosts": {
    "web-prod-1": {
      "principals": ["deploy"],
      "role": "agent-ssh-deploy",
      "description": "Production web server"
    }
  },
  "hostGroups": {
    "production": {
      "tag": "production",
      "role": "agent-ssh-deploy",
      "description": "All production servers",
      "min_level": 2
    }
  }
}
```

#### Grant-Gated Endpoint

##### `POST /api/ssh/credentials`

Issue a signed SSH certificate using an active SSH grant.

Request body:
```json
{
  "grantId": "g_11155f2e244bc44e",
  "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `grantId` | string | yes | An active SSH grant ID |
| `publicKey` | string | yes | The agent's SSH public key (e.g. `ssh-ed25519 ...`) |

Response:
```json
{
  "signedKey": "ssh-ed25519-cert-v01@openssh.com AAAAC3...",
  "serial": "abc123456",
  "validBefore": "2026-03-23T19:42:01.964774+00:00"
}
```

The agent writes `signedKey` to a `-cert.pub` file alongside its private key, then connects normally:

```bash
ssh -i /path/to/key -o CertificateFile=/path/to/key-cert.pub deploy@web-prod-1
```

#### Level 1 SSH Grant Lifecycle

Level 1 SSH grants have a renewable-within-window semantic:

1. Grant is created with `status: pending`
2. Approver approves -> `status: active`, timer starts
3. Any number of `POST /api/ssh/credentials` calls may issue fresh short-lived certs while the grant remains active
4. Grant expires when the timer runs out -> `status: expired`

### SSH Grant Request Examples

**Level 1 — single host:**
```json
{
  "resourceType": "ssh",
  "level": 1,
  "host": "web-prod-1",
  "principal": "deploy",
  "description": "Deploy latest release to web-prod-1"
}
```

**Level 2 — host group:**
```json
{
  "resourceType": "ssh",
  "level": 2,
  "hostGroup": "production",
  "principal": "deploy",
  "description": "Rolling restart across production"
}
```

**Level 3 — broad principal access:**
```json
{
  "resourceType": "ssh",
  "level": 3,
  "principal": "deploy",
  "description": "Emergency infrastructure investigation",
  "durationMinutes": 30
}
```

---

## Audit Log

### `GET /api/audit`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `since` | string | — | ISO timestamp — only return entries after this time |
| `limit` | int | 50 | Max entries (1-500) |

Response:
```json
{
  "entries": [
    {"ts": "2026-03-23T19:37:01Z", "action": "grant_approved", "grantId": "g_...", ...},
    {"ts": "2026-03-23T19:36:45Z", "action": "grant_requested", ...}
  ]
}
```

Entries are returned newest-first.

## Health Check

```
GET /health
```

Does not require the API key. Returns `{"status": "ok"}`.

---

## Configuration

Copy `config.json.example` to `config.json` and fill in your values:

```bash
cp config.json.example config.json
```

Key fields:

| Field | Description |
|-------|-------------|
| `gmail_account` | The Gmail address the gateway will access |
| `agent_name` | Display name for the AI agent (shown in Signal notifications) |
| `approver_name` | Display name for the human approver |
| `vault_path` | Vault path for Gmail OAuth credentials (client_id, client_secret, tokens) |
| `vault_api_key_path` | Vault path where the shared API key is stored |
| `signal.api_url` | URL for the signal-cli-rest-api container |
| `signal.sender` | Signal phone number registered to the gateway |
| `signal.approver` | Signal phone number of the human approver |
| `signal.webhook_token` | Token for authenticating Signal webhook callbacks. **Must be URL-safe** — generate with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. Set the same value in the `RECEIVE_WEBHOOK_URL` query string in `docker-compose.yml`. |
| `approval_url_base` | Public URL of the gateway (used in approval links) |
| `callback.url` | URL to POST grant status on approval/denial |
| `callback.cf_auth` | Include CF Access headers on callbacks (bool) |
| `callback.hooks_token_vault_path` | Vault path for the hooks Bearer token (field: `hooks_token`) |
| `providers.ssh.enabled` | Enable the SSH provider (bool) |
| `providers.ssh.vault_ssh_mount` | Vault mount point for the SSH secrets engine (default: `"ssh"`) |
| `providers.ssh.hosts` | Map of hostname to `{principals, role, description}` |
| `providers.ssh.host_groups` | Map of group name to `{tag, role, description, min_level}` |
| `providers.ssh.roles` | Map of Vault SSH role name to `{allowed_principals, default_extensions}` |
| `providers.ssh.defaults` | Default TTLs: `level1_ttl_minutes`, `level2_ttl_minutes`, `level3_ttl_minutes` |

See `config.json.example` for the full schema including rate limits, default grant durations, SSH provider configuration, and sensitive pattern configuration.

---

## Setup

### 1. Google Cloud OAuth (Gmail provider)

1. Create a project in [Google Cloud Console](https://console.cloud.google.com/)
2. Enable the Gmail API
3. Create OAuth 2.0 credentials (Desktop application type)
4. Add `user@example.com` as a test user (if app is in testing mode)

### 2. Store Client Credentials in Vault

```bash
export VAULT_ADDR=https://vault.your-domain.com:8200
export VAULT_ROLE_ID=...
export VAULT_SECRET_ID=...
bao kv put secret/agent/authorization-gateway \
  client_id="YOUR_CLIENT_ID" \
  client_secret="YOUR_CLIENT_SECRET"
```

### 3. Generate Shared API Key

Both the agent and the authorization gateway need a shared API key. Generate one and store it in Vault:

```bash
bao kv put secret/your-project/authorization-gateway \
  api_key="$(openssl rand -base64 32)"
```

The gateway loads this key from Vault at startup. The agent reads it via its own AppRole access to the same Vault path.

### 4. Register Signal Number

The compose file includes a `signal-api` container (bbernhard/signal-cli-rest-api). No ports are exposed — use `docker exec` for setup:

```bash
# Register (may require captcha — see https://signalcaptchas.org/registration/generate.html)
docker exec signal-api curl -s -X POST "http://localhost:8080/v1/register/+1XXXXXXXXXX"
# Verify with SMS code:
docker exec signal-api curl -s -X POST "http://localhost:8080/v1/register/+1XXXXXXXXXX/verify/CODE"
```

### 5. Run OAuth Setup (Gmail provider)

Run on a machine with a browser (not on a headless server). SSH-tunnel port 8090 if the Vault server is remote:

```bash
# If running remotely, start the tunnel in a separate terminal:
ssh -L 8090:localhost:8090 user@your-server.example.com

# Set Vault credentials
export VAULT_ADDR=https://vault.your-domain.com:8200
export VAULT_ROLE_ID=...
export VAULT_SECRET_ID=...

# Install and run in a venv
python3 -m venv .venv
source .venv/bin/activate
pip install httpx google-auth-oauthlib
SSL_CERT_FILE=./certs/vault-ca.pem python setup_oauth.py
```

### 6. SSH Setup (SSH provider)

#### OpenBao SSH Secrets Engine

Enable the SSH secrets engine, configure the CA, and create roles:

```bash
export VAULT_ADDR=https://vault.your-domain.com:8200
export VAULT_ROLE_ID=...
export VAULT_SECRET_ID=...

# Enable the SSH secrets engine
bao secrets enable ssh

# Generate a CA key pair (or import your own)
bao write ssh/config/ca generate_signing_key=true

# Retrieve the public key (you will need this on target hosts)
bao read -field=public_key ssh/config/ca > trusted-user-ca-keys.pem

# Create a signing role
bao write ssh/roles/agent-ssh-deploy \
  key_type=ca \
  allowed_users="deploy,agent" \
  default_user="deploy" \
  ttl=5m \
  max_ttl=24h \
  default_extensions='{"permit-pty": ""}' \
  allow_user_certificates=true
```

Create a Vault policy for the gateway:

```hcl
# Allow signing SSH keys
path "ssh/sign/agent-ssh-deploy" {
  capabilities = ["create", "update"]
}

# Allow listing roles (optional, for validation)
path "ssh/roles" {
  capabilities = ["list"]
}
```

#### Target Host Setup

On each target host, configure the SSH daemon to trust certificates signed by the CA:

```bash
# Copy the CA public key to the target host
scp trusted-user-ca-keys.pem root@web-prod-1:/etc/ssh/trusted-user-ca-keys.pem

# Add to /etc/ssh/sshd_config:
#   TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem

# Restart sshd
systemctl restart sshd
```

#### Config.json SSH Section

Add the SSH provider configuration to `config.json`:

```json
{
  "providers": {
    "ssh": {
      "enabled": true,
      "vault_ssh_mount": "ssh",
      "roles": {
        "agent-ssh-deploy": {
          "allowed_principals": ["deploy", "agent"],
          "default_extensions": {"permit-pty": ""}
        }
      },
      "hosts": {
        "web-prod-1": {
          "principals": ["deploy"],
          "role": "agent-ssh-deploy",
          "description": "Production web server"
        }
      },
      "host_groups": {
        "production": {
          "tag": "production",
          "role": "agent-ssh-deploy",
          "description": "All production servers",
          "min_level": 2
        }
      },
      "defaults": {
        "level1_ttl_minutes": 5,
        "level2_ttl_minutes": 30,
        "level3_ttl_minutes": 15
      }
    }
  }
}
```

### 7. Create `.env` File

```bash
cp .env.example .env
# Edit with your VAULT_ADDR, VAULT_ROLE_ID, and VAULT_SECRET_ID
```

### 8. Deploy

```bash
ssh user@your-server.example.com
cd ~/agent-authorization-gateway
docker compose up -d --build
```

### 9. Reverse Proxy / Cloudflare Tunnel (Optional)

This step is only needed if exposing the gateway over the internet. On a trusted internal network, agents can connect directly to the gateway on port 18795.

> **Warning:** Without TLS (from Cloudflare, Caddy, nginx, or another reverse proxy), API keys and approval tokens are transmitted in the clear.

**Cloudflare Tunnel example:** The authorization-gateway container joins your cloudflared Docker network (e.g., `cloudflared_default`). Add a public hostname in the Cloudflare Zero Trust dashboard:

- **Hostname**: `approval.your-domain.com`
- **Service**: `http://authorization-gateway:18795`

Protect with a Cloudflare Access policy. Create a service token for the agent to use.

## Architecture

```
Agent ──(CF Tunnel / direct)──> Authorization Gateway (:18795)
                                  │
                                  ├──OAuth──> Gmail API
                                  │
                                  ├──SSH CA sign──> Vault/OpenBao SSH secrets engine
                                  │
                                  ├──HTTP──> signal-api container ──> approver's phone
                                  │           (send notification + poll replies)
                                  │
                                  ├──HTTPS──> approver's browser (approval page)
                                  │
                                  ├──HTTP──> Vault (AppRole auth -> secrets)
                                  │
                                  └──HTTPS──> callback URL (configured, on grant approval/denial)
```
