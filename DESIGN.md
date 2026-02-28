# Auth Sidecar Proxy — Design Document

*Draft: 2026-02-20 · Author: Gareth (admin agent) + Richard*
*Status: Approved concept · Ready for prototyping*

## Problem

Agents in Docker containers need to call third-party APIs (GitHub, Vercel, GCP, etc.) but the current options all leak credentials into the agent's context:

1. **Env vars** — visible to any `exec` call, lost on compaction, agent "forgets" them
2. **Files in workspace** — readable, writable, end up in MEMORY.md
3. **Pasted in chat** — in prompt history forever, survives compaction as context

All three mean a prompt injection can extract the credential. No amount of "don't show the token" instruction fixes this — the agent has the secret, so it can be exfiltrated.

The LLM model API keys are already handled correctly: the Gateway makes those calls on the host, tokens never enter containers. This proposal extends that pattern to **all** authenticated HTTP traffic from agents.

## Design Principles

1. **Tokens never enter the container** — not in env, not on disk, not in prompts
2. **One process, one config** — not N MCP servers per service
3. **Agents keep using bare CLIs** — `gh`, `vercel`, `gcloud`, `curl` all work unchanged
4. **Per-agent scoping** — PA gets GitHub access to repo X, TeslaCoil gets repo Y
5. **Auth ceremony happens outside the agent** — human authorises via browser/CLI on host

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Docker Network (internal, no internet)         │
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ PA Agent  │  │ TeslaCoil│  │ Moltbook │      │
│  │ container │  │ container│  │ container│      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│       │              │              │            │
│       └──────────┬───┴──────────────┘            │
│                  │                               │
│                  ▼                               │
│         ┌────────────────┐                       │
│         │  Auth Sidecar  │                       │
│         │  (proxy)       │                       │
│         │                │                       │
│         │ • Identifies   │                       │
│         │   calling agent│                       │
│         │   by source IP │                       │
│         │                │                       │
│         │ • Looks up     │                       │
│         │   credential   │                       │
│         │   from vault   │                       │
│         │                │                       │
│         │ • Injects auth │                       │
│         │   header       │                       │
│         │                │                       │
│         │ • Forwards to  │──────► Internet       │
│         │   upstream API │                       │
│         └────────────────┘                       │
│                                                  │
└──────────────────────────────────────────────────┘

Vault (age-encrypted on host)
  └── github-pa.token
  └── github-teslacoil.token
  └── vercel-teslacoil.token
  └── gcp-sa-metalumna.json
```

## How It Works

### 1. Container HTTP routing

Each agent container is configured with:
```
HTTP_PROXY=http://auth-sidecar:3100
HTTPS_PROXY=http://auth-sidecar:3100
```

All outbound HTTP from the container routes through the sidecar. The agent doesn't know or care — `gh`, `curl`, `vercel` all respect standard proxy env vars.

### 2. Agent identification

Each agent container has a fixed IP on the Docker network (or a unique hostname). The sidecar maps source IP → agent ID:

```
172.20.0.10 → pa
172.20.0.11 → teslacoil
172.20.0.12 → moltbook
```

This is reliable because Docker assigns IPs per container on the internal network. No tokens or headers needed for agent identification.

### 3. Credential injection

The sidecar matches the request destination + agent ID against its credential config:

```yaml
rules:
  - match:
      host: "api.github.com"
      agent: "pa"
    credential: github-pa
    inject:
      header: "Authorization"
      value: "Bearer {{token}}"

  - match:
      host: "api.github.com"
      agent: "teslacoil"
    credential: github-teslacoil
    inject:
      header: "Authorization"
      value: "Bearer {{token}}"

  - match:
      host: "api.vercel.com"
      agent: "teslacoil"
    credential: vercel-teslacoil
    inject:
      header: "Authorization"
      value: "Bearer {{token}}"

  # Default: pass through without credentials (or block)
  default: passthrough  # or "deny"
```

### 4. Credential storage

Tokens are stored in the age-encrypted vault from #12839:
```bash
openclaw vault add github-pa --token ghp_xxxx
openclaw vault add github-teslacoil --token ghp_yyyy
```

Sidecar decrypts vault at startup, holds credentials in memory. Never written to disk in plaintext. Never exposed to any container.

### 5. What the agent experiences

Before (current):
```bash
# Agent needs to know the token
export GITHUB_TOKEN=ghp_xxxx
gh pr list --repo owner/pa-repo
```

After (with sidecar):
```bash
# Agent just uses the CLI. Proxy adds auth automatically.
gh pr list --repo owner/pa-repo
# Works. Agent never sees a token.
```

## Reactive Auth Flow (Key UX Feature)

The most important UX property: **when an agent needs auth it doesn't have, the system handles it — not the agent.**

### The flow

```
1. Agent runs:  gh pr list --repo owner/new-repo
2. Request hits sidecar → no matching credential for this agent + destination
3. Sidecar returns 403 to agent with structured error:
   "AUTH_REQUIRED: github (api.github.com) for agent pa"
4. Agent sees this, tells Richard: "I need GitHub access to owner/new-repo"
5. Simultaneously, sidecar notifies Richard directly (WhatsApp/webchat):

   🔐 Auth request from PA
   Service: GitHub (api.github.com)
   Repo: owner/new-repo
   
   [Approve with read-only] [Approve with read-write] [Deny]

6. Richard taps "Approve with read-only"
7. Sidecar either:
   a. Creates a fine-grained PAT scoped to that repo (via GitHub API/device flow)
   b. Or prompts Richard to paste a token if the platform doesn't support automation
8. Token encrypted into vault, proxy rule added
9. Agent retries automatically — works.
```

### Key principles

- **Agent never solves auth problems.** It gets a clear error and can tell the user. The system does the rest.
- **Scope is explicit.** Richard sees exactly what's being requested and chooses the permission level. No "grant all GitHub access because it's easier."
- **Incremental grants.** Agent starts with zero access. Each new service/repo is an explicit approval. Permissions accumulate in the vault config, auditable at any time.
- **Existing auth, new scope.** If PA already has GitHub access but needs a new repo, the sidecar detects this and offers to extend the existing PAT's scope (or create a second one) rather than starting from scratch.
- **No round-tripping.** Agent doesn't try to `gh auth login`, paste tokens in chat, write to MEMORY.md, or any other workaround. The system catches the need and handles it in one human interaction.

### What Richard sees day-to-day

```
🔐 PA needs GitHub access to owner/new-repo
  [Read-only] [Read-write] [Deny]

🔐 TeslaCoil needs Vercel access
  [Approve] [Deny]

🔐 Metalumna needs GCP Cloud Run (project: metalumna-prod)
  [Viewer] [Editor] [Deny]
```

One tap. Done. Agent retries. No CLI gymnastics, no tokens in chat.

## GitHub App as Auth Backend

Instead of per-agent PATs (manual, long-lived, can't be created via API), use a single GitHub App as the credential backend for all agents.

### One-time setup (~10 mins)

1. Create a GitHub App at github.com/settings/apps/new
   - Name: "OpenClaw Agent" (or similar)
   - Permissions: Repository → Contents: Read & Write (extend as needed)
   - No webhook needed, private app
2. Generate a private key (.pem) → encrypt into vault
3. Install the App on repos as needed (UI or API)

### How it works with the sidecar

```
Agent config (openclaw.json):
  test-agent:
    github:
      repos: ["skarard/test-repo"]
      permissions: contents:write

  teslacoil:
    github:
      repos: ["skarard/teslacoil"]
      permissions: contents:write, issues:write
```

When agent hits api.github.com:
1. Sidecar identifies agent by container IP
2. Looks up agent's allowed repos
3. Creates JWT from App private key (in vault, never leaves host)
4. Generates installation token via GitHub API, scoped to only that agent's repos
5. Injects token into request
6. Token expires in 1 hour, auto-regenerated as needed

### Why this is better than PATs

| Property | Fine-grained PAT | GitHub App |
|----------|:-:|:-:|
| Created programmatically | ❌ | ✅ |
| Per-repo scoping | ✅ | ✅ |
| Short-lived tokens | ❌ (90 days) | ✅ (1 hour) |
| Revoke per-agent | Manual | Automatic (stop generating) |
| Add new repo | Create new PAT in browser | Install App on repo (API or one click) |
| Private key leaves host | N/A | ❌ (stays in vault) |

### Agent creation flow

```
openclaw agents create my-agent --git skarard/my-repo
  → Checks GitHub App is installed on skarard/my-repo
  → If not: installs it (or prompts approval)
  → Adds repo to agent's sidecar config
  → Agent boots, git just works
```

One GitHub App for all agents. Sidecar handles per-agent repo scoping. Adding a new agent+repo is one command, no browser needed.

### Generalising this pattern

GitHub App is the model for how all service auth should work:
- **One credential on the host** (private key, OAuth refresh token, SA key)
- **Sidecar generates short-lived scoped tokens per request**
- **Agent never sees the long-lived credential**
- **Per-agent policy is config, not credential management**

Other platforms that support similar patterns:
- **GCP**: Service account key → short-lived access tokens via `generateAccessToken`
- **AWS**: IAM role → STS `AssumeRole` with session policies
- **Vercel**: No equivalent yet — stuck with long-lived tokens for now

## Auth Ceremony — Getting Tokens Into the Vault

This is the hard part. Every platform does auth differently. The reactive flow above is the UX wrapper — below is how each platform actually creates the credential.

### Tier 1: Static tokens (simplest)

Platforms where you manually create a token on a web UI:
- GitHub fine-grained PATs
- Vercel tokens
- Most API keys

Flow:
```
1. Richard creates token in browser (github.com/settings/tokens)
2. Runs: openclaw vault add github-pa --token ghp_xxxx
3. Token encrypted into vault, sidecar config updated
4. Agent never sees it
```

Token never passes through WhatsApp or any agent prompt.

### Tier 2: Device auth flow (better UX)

Platforms that support OAuth device flow (GitHub, some Google services):
```
1. Run: openclaw vault auth github --agent pa --scope repo:owner/repo
2. CLI shows: "Go to github.com/login/device and enter code: ABCD-1234"
3. Richard authorises on phone/laptop
4. CLI receives token via backend callback
5. Token encrypted into vault automatically
```

Best UX. Token never displayed. Scope can be restricted at the OAuth app level.

### Tier 3: Service accounts (GCP, AWS)

```
1. Run: openclaw vault auth gcp --agent metalumna-website
2. CLI creates a service account via gcloud (or guides through it)
3. Downloads key JSON, encrypts into vault
4. Assigns IAM roles per Richard's approval
```

Scriptable but needs Richard's GCP/AWS credentials for the initial setup.

### Tier 4: OAuth web flow (fallback)

For platforms with only web OAuth:
```
1. Run: openclaw vault auth <provider> --agent <agent>
2. Sidecar starts a local callback server
3. Opens browser with OAuth URL
4. User authorises, redirect lands on localhost
5. Token captured and encrypted into vault
```

## CLI Integration

### `gh` CLI specifics

`gh` uses `~/.config/gh/hosts.yml` for auth. Options:
- **Proxy approach (preferred):** `gh` respects `HTTPS_PROXY`. Sidecar injects the `Authorization` header. `gh` sends its own token too but sidecar can strip/replace it.
- **Config mount:** Mount a read-only `hosts.yml` with a dummy token. Actual auth happens at the proxy.

### `gcloud` CLI specifics

`gcloud` uses Application Default Credentials or service account JSON:
- **Proxy approach:** `gcloud` respects `HTTPS_PROXY`. Sidecar injects OAuth bearer token.
- **ADC file:** Mount a read-only ADC JSON. But this puts the credential on disk in the container (defeats the purpose). Proxy approach is better.

### `vercel` CLI specifics

`vercel` stores auth in `~/.vercel/auth.json`:
- **Proxy approach:** Respects `HTTPS_PROXY`. Sidecar handles auth.

### Direct `curl`

Works automatically:
```bash
# Inside container
curl https://api.github.com/repos/owner/repo/issues
# Proxy adds: Authorization: Bearer ghp_xxxx
```

## Per-Agent Scoping

The sidecar config defines which agents can reach which services:

```yaml
rules:
  - match: { host: "api.github.com", agent: "pa" }
    credential: github-pa    # PAT scoped to pa repos only

  - match: { host: "api.github.com", agent: "teslacoil" }
    credential: github-tc    # PAT scoped to teslacoil repos only

  - match: { host: "api.github.com", agent: "moltbook" }
    action: deny             # Moltbook has no GitHub access

  - match: { host: "api.vercel.com", agent: "teslacoil" }
    credential: vercel-tc

  - match: { host: "*.googleapis.com", agent: "metalumna-website" }
    credential: gcp-metalumna  # SA scoped to metalumna project
```

An agent can only access services it's explicitly granted. No credential = no access. **Fail closed.**

## Security Properties

| Property | Status |
|----------|--------|
| Token in container env | ❌ Never |
| Token in prompt context | ❌ Never |
| Token survives compaction | ✅ N/A — agent doesn't hold it |
| Prompt injection can extract token | ❌ Impossible — token not in agent's address space |
| Per-agent credential scoping | ✅ Config-driven |
| Per-repo/per-project scoping | ✅ Via fine-grained PATs / SAs |
| Token rotation | ✅ Update vault, restart sidecar |
| Audit log | ✅ Sidecar logs which agent called which API |

## Relationship to Existing Work

| Issue/PR | What it does | Relationship |
|----------|-------------|--------------|
| #14411 | Credential broker concept | Parent issue. This implements the "process isolation" path |
| #12839 | Vault proxy for LLM providers | Same vault + sidecar pattern. Extend to agent HTTP traffic |
| #15756 | Strip apiKey from prompt | Complementary. Handles LLM key leak in prompt context |
| #19728 | apiKeyFile support | Complementary. Keeps keys out of config files |

## Open Questions

1. **TLS interception:** The sidecar is an HTTP proxy terminating HTTPS. Need to either:
   - Use HTTP CONNECT + inject headers post-TLS (complex)
   - Have the sidecar terminate TLS with its own CA cert trusted by containers (simpler, more invasive)
   - Use destination-specific proxy ports like #12839 does (each upstream gets a port, agent hits `http://sidecar:3101` for GitHub which proxies to `https://api.github.com`)

2. **CLI tools that don't respect HTTP_PROXY:** Some tools bypass proxy settings. Mitigation: Docker network has no direct internet route. If you can't go through the proxy, you can't go at all.

3. **Token refresh:** OAuth tokens expire. Sidecar needs to handle refresh flows autonomously, or alert when manual re-auth is needed.

4. **WebSocket traffic:** Some APIs use WebSockets (Slack, etc.). Proxy needs to handle upgrades.

5. **Default policy:** `passthrough` (allow unauthenticated requests) vs `deny` (block anything without a matching rule). Deny is more secure but breaks things like pip/npm/apt inside containers.

## Agent Onboarding UX

The auth sidecar shouldn't be a standalone feature — it should be woven into agent creation. Today, setting up a sandboxed agent is 6+ manual steps. The goal is one command.

### Dream CLI

```bash
openclaw agents create pa \
  --sandbox docker \
  --bind whatsapp:dm:+447948309251 \
  --tools github vercel gcloud \
  --auth github:read:owner/pa-repo \
  --auth vercel \
  --auth gcp:viewer:project-id
```

This should:
1. Create the agent workspace with bootstrap files (AGENTS.md, SOUL.md, etc.)
2. Configure sandbox in openclaw.json
3. Set up message routing binding
4. **Build a Docker image with the requested CLIs installed** (`gh`, `vercel`, `gcloud`)
5. **Provision scoped credentials** — device flow for GitHub, token for Vercel, SA for GCP
6. **Configure proxy rules** in the sidecar so each CLI just works
7. Set up auth-profiles.json for LLM access (inheriting from gateway or creating new)

### Declarative agent toolchain

Each agent declares the tools/services it needs. This can live in the agent config:

```json
{
  "id": "pa",
  "sandbox": { "mode": "all", "scope": "agent" },
  "toolchain": {
    "cli": ["gh", "vercel", "node", "python3"],
    "services": {
      "github": { "scope": "repo:owner/pa-repo", "access": "read-write" },
      "vercel": { "scope": "team:my-team" },
      "gcp": { "project": "pa-project", "role": "viewer" }
    }
  }
}
```

**Docker image generation:**
The `cli` list drives the Dockerfile. OpenClaw maintains base images with common tools, and layers agent-specific CLIs on top:

```dockerfile
FROM openclaw-sandbox:bookworm-slim
# Auto-generated from toolchain.cli
RUN apt-get install -y python3 nodejs
RUN npm install -g vercel
RUN gh extension install ...  # if needed
```

Or better — a shared base with tool layers cached across agents, so adding `vercel` to a second agent is instant.

**Service auth is automatic:**
The `services` block drives the vault + sidecar config. When the image is built:
- If credentials exist in the vault for this agent+service → proxy rule created, done
- If not → auth ceremony triggered (device flow, token paste, SA creation)
- Agent starts with everything wired up. Zero auth friction on first run.

### Progressive Setup — Auth Follows the Work

The wizard-at-creation model is wrong for most agents. You don't know what services you need on day one. The agent discovers its needs as it works.

**Example: Full lifecycle of a dev agent**

```
Day 1: "Build me a landing page for metalumna"

Agent: Sure. Let me set up the project.
  → git init, scaffold Next.js, start building
  → No auth needed. Works immediately.

Day 1 (later): "Push this to GitHub"

Agent: I need GitHub access to create a repo.
  🔐 GitHub auth request from metalumna-website
     Action: Create repo "metalumna/website"
     [Read-write to metalumna org] [Deny]
  → Richard taps approve
  → Device flow, fine-grained PAT scoped to metalumna org
  → git remote add, push. Done.

Day 3: "It's ready, deploy it"

Agent: I need Vercel access to create a project.
  🔐 Vercel auth request from metalumna-website
     Action: Create project, link to metalumna/website
     [Approve] [Deny]
  → Richard approves, pastes Vercel token
  → vercel project created, linked to GitHub repo
  → First deploy runs

Agent: Your domain metalumna.com is on GoDaddy.
  DNS records needed:
    CNAME www → cname.vercel-dns.com
    A     @   → 76.76.21.21

  → Here's the direct link to your GoDaddy DNS page:
    https://dcc.godaddy.com/manage/metalumna.com/dns
  → Want me to set up a Vercel domain alias too?

Day 7: "Add analytics"

Agent: I need Supabase access for the analytics backend.
  🔐 Supabase auth request from metalumna-website
     Project: metalumna-prod
     [Approve] [Deny]
  → One tap. Wired up.
```

**What makes this work:**

1. **Zero auth on creation.** Agent starts with nothing. It can code locally, no permissions needed.
2. **Auth is triggered by action, not anticipation.** The moment the agent tries something that needs credentials, the flow kicks in.
3. **Context-aware prompts.** The system doesn't just say "needs GitHub" — it says "wants to create repo metalumna/website in the metalumna org with read-write access." Richard knows exactly what he's approving.
4. **Service detection is smart.** Agent detects DNS provider from whois/NS records, generates the right instructions with direct links. Not "go configure DNS somewhere" but "here's the GoDaddy page, here are the exact records."
5. **Permissions accumulate naturally.** By the end of the project, the agent has exactly the permissions it used — nothing more. The vault config is an audit trail of what the agent actually needed.

**The sidecar enables this pattern.** Without it, the agent has to stop and say "I need a token, please paste it." With it, the system intercepts the failed request, prompts the human, provisions the credential, and the agent retries — ideally without the human needing to context-switch out of the conversation.

### Auth inheritance

When creating a new agent, you should be able to inherit credentials from the gateway or another agent:

```bash
openclaw agents create teslacoil-staging \
  --inherit-auth teslacoil \
  --auth github:read:owner/teslacoil-staging
```

This copies the relevant vault entries (re-encrypted for the new agent's scope) and creates matching proxy rules. Useful for:
- Staging/dev clones of existing agents
- Splitting an agent into sub-agents with the same service access
- Quick prototyping before scoping down permissions

Inheritance is a **copy**, not a reference — changing the parent's credentials doesn't affect the child.

### What the human experiences

**Creating a new agent:**
```
$ openclaw agents create pa --tools github vercel

Creating agent "pa"...
✓ Workspace created at ~/agents/pa
✓ Sandbox configured (Docker, agent scope)
✓ Docker image building... (gh, vercel, node)

🔐 GitHub auth needed for agent "pa"
  → Opening device flow: go to github.com/login/device
  → Enter code: ABCD-1234
  → Waiting for approval...
  ✓ Token received (scope: user, repo)
  → Want to restrict to specific repos? [Y/n]
  → Enter repos (comma-separated): owner/pa-repo
  ✓ Fine-grained PAT created, encrypted in vault

🔐 Vercel auth needed for agent "pa"  
  → Paste a Vercel token (from vercel.com/account/tokens):
  ✓ Token encrypted in vault

✓ Proxy rules configured
✓ Agent "pa" ready. Send a message to test.
```

**Adding a service to an existing agent:**
```
$ openclaw agents add-service pa --service supabase

🔐 Supabase auth needed for agent "pa"
  → Paste a Supabase service key:
  ✓ Token encrypted in vault
  ✓ Proxy rule added for *.supabase.co → agent pa
  ✓ No container rebuild needed (HTTP proxy handles it)
```

Adding a new service doesn't require rebuilding the Docker image (the proxy handles auth injection). Only adding new CLIs triggers a rebuild.

### Hot Container Upgrades

When an agent needs a new CLI tool mid-session, the system should handle it without downtime:

```
Agent: I need ffmpeg to process this video.
  → Gateway detects ffmpeg not in container
  → Builds new image layer: apt-get install ffmpeg (or prebuild binary)
  → Spins up new container from new image
  → Mounts same workspace (workspace is external volume)
  → Migrates session to new container
  → Kills old container
  → Agent continues — ffmpeg is available
```

**Key design decisions:**

1. **Layered images.** Base image has common tools. Agent-specific tools are layers on top. Adding `ffmpeg` is one layer, cached and reusable across agents. This means most "installs" are just pulling a cached layer, not building from scratch.

2. **Prebuild binaries over apt.** `apt-get install build-essential` takes minutes. A static binary or pre-compiled layer takes seconds. The system should prefer:
   - Pre-built tool layers (maintained by OpenClaw or community) → seconds
   - Binary downloads (GitHub releases, etc.) → seconds
   - apt/pip install → slow but fallback

3. **Gateway handles changeover.** The Gateway is the session owner. It:
   - Pauses tool dispatch to old container
   - Starts new container with same workspace mount + network config
   - Verifies new container is healthy
   - Resumes tool dispatch to new container
   - Kills old container
   - Agent and user see zero downtime — at most a brief pause in tool execution

4. **Workspace is always external.** The workspace volume is mounted, not baked into the image. Container is stateless except for installed tools. This is what makes hot swaps safe — no state lives in the container.

5. **Rollback on failure.** If the new container fails to start (bad image, missing deps), Gateway keeps using the old one and reports the failure. Agent never breaks.

**What the agent experiences:**
```
Agent: Running ffmpeg -i video.mp4 ...
  → "ffmpeg: command not found"
Agent: I need ffmpeg installed.
  → System: "Installing ffmpeg for agent pa..."
  → (5 seconds while new container builds + starts)
  → System: "Ready."
Agent: Running ffmpeg -i video.mp4 ...
  → Works.
```

**What Richard experiences:**
Nothing. Or optionally a notification:
```
🔧 PA container upgraded
  + ffmpeg (prebuild layer, 12MB)
  Downtime: 0s
```

## Implementation Plan

### Phase 1: Proxy core
- HTTP(S) proxy that identifies agent by source IP
- Credential injection based on destination host + agent
- Integrates with existing vault from #12839
- Docker network isolation (containers can't bypass proxy)

### Phase 2: CLI integration
- `openclaw vault proxy add` — add a proxy rule for an agent
- `openclaw vault proxy status` — show which agents have access to what
- Container setup automation (HTTP_PROXY env, network config)

### Phase 3: Auth ceremonies
- `openclaw vault auth github` — device flow + fine-grained PAT creation
- `openclaw vault auth gcp` — service account creation
- Generic OAuth web flow fallback

### Phase 4: Ecosystem
- Audit logging
- Token rotation alerts
- Dashboard integration (which agents are calling which APIs)

---

## Core Thesis

> The model forgets every session. The container remembers.
>
> AI promises "I'll learn what you need." This is what that looks like at the infrastructure level — the agent's container gets more robust for its specific task, built up action by action with human approval at each step. After a month: the image has exactly the tools it used, the vault has exactly the credentials it needed, the proxy rules are exactly the services it called. No over-provisioning, no guessing upfront. The infrastructure is a record of what the agent learned it needed.

---

*References: #14411, #12839, #15756, #19728, MCP Authorization Spec (2025-03-26)*
