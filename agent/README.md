# Agent Integration

This directory contains the agent-side integration for the Authorization Gateway.

## Files

- **`SKILL.md`** — Agent skill file. Drop this into your workspace skills directory (e.g. `~/.agent/workspace/skills/authorization-gateway/SKILL.md`). The agent reads this to understand the API, auth, access tiers, and usage patterns for both Gmail and SSH providers.
- **`grant-callback.js`** — Hook transform. Drop this into your agent hooks transforms directory (e.g. `~/.agent/hooks/transforms/grant-callback.js`). Handles approval/denial callbacks from the gateway and resumes the agent session automatically. Supports both Gmail and SSH grant types.
- **`gmail-grant.js`** — Legacy hook transform (Gmail-only). Kept for backward compatibility. New deployments should use `grant-callback.js` instead.

## Setup

### 1. Install the skill

```bash
mkdir -p ~/.agent/workspace/skills/authorization-gateway
cp agent/SKILL.md ~/.agent/workspace/skills/authorization-gateway/SKILL.md
```

The checked-in `agent/SKILL.md` is intentionally generic. Keep repository copies free of instance-specific values such as your real gateway hostname, email address, Vault path, callback session key, agent hook path, or local skill metadata/frontmatter.

If your agent runtime needs local customization, merge those settings into the installed copy **after** copying the file into your workspace. That keeps the repo reusable while still letting each deployment adapt the skill to its own environment.

### 2. Install the hook transform

```bash
cp agent/grant-callback.js ~/.agent/hooks/transforms/grant-callback.js
```

### 3. Register the hook in `agent.json`

Add an entry to the `hooks.mappings` array in your agent config (`~/.agent/agent.json`):

```json
{
  "id": "grant-callback",
  "match": { "path": "/grant-callback" },
  "deliver": false,
  "transform": { "module": "grant-callback.js" }
}
```

**Important:** `deliver: false` is required. The transform uses `action: 'wake'` to inject a system event directly into the main session. Without `deliver: false`, the agent will also spawn a run that produces a confusing response on your messaging channel.

Then restart the agent gateway for the new mapping to take effect.

### 4. Configure callback credentials in the gateway (optional)

If your agent instance is behind Cloudflare Access, the gateway needs CF Access credentials to reach your agent hooks endpoint when firing grant callbacks. Store them in the gateway's Vault path:

```bash
bao kv patch secret/agent/authorization-gateway \
  CF-Access-Client-Id="<your-cf-service-token-client-id>" \
  CF-Access-Client-Secret="<your-cf-service-token-client-secret>"
```

The service token needs access to the Cloudflare Access application protecting your agent instance.

If your agent instance is not behind Cloudflare Access, you can skip this step.

### 5. Verify

Make a grant request:

```json
{
  "level": 1,
  "messageId": "...",
  "description": "Test callback",
  "callbackSessionKey": "agent:main:main"
}
```

Approve it on the approver's phone — your agent session should wake automatically.

## How It Works

```
Agent requests grant (Gmail or SSH)
  -> Gateway sends Signal notification to the approver
    -> The approver approves on phone
      -> Gateway POSTs to /hooks/grant-callback
        -> Agent hook transform wakes agent session
          -> Agent resumes task with active grant
```

No polling required. The callback is fire-and-forget from the gateway's perspective; the agent handles routing to the right session.
