# openclaw-auth-proxy

Auth sidecar proxy for OpenClaw sandboxed agents.

Agents in Docker containers need to call third-party APIs (GitHub, Vercel, GCP, etc.) without credentials ever entering the container. This proxy sits between agents and the internet, injecting auth headers and enforcing route-level policy.

## Core Principles

1. **Tokens never enter the container** — not in env, not on disk, not in prompts
2. **Default deny** — agents can only reach explicitly permitted hosts + routes
3. **Route-level policy** — control what agents can *do*, not just what they can *reach*
4. **Agents use bare CLIs** — `gh`, `curl`, `vercel` work unchanged via `HTTP_PROXY`

## Architecture

```
┌──────────────────────────────────────────┐
│  Docker Network (--internal, no internet) │
│                                           │
│  ┌──────────┐  ┌──────────┐              │
│  │ Agent A   │  │ Agent B   │             │
│  │ container │  │ container │             │
│  └────┬──────┘  └────┬──────┘            │
│       └──────┬───────┘                    │
│              ▼                             │
│     ┌─────────────────┐                   │
│     │  Auth Proxy      │                  │
│     │                  │                  │
│     │ • Agent ID by IP │                  │
│     │ • Route policy   │──── Internet     │
│     │ • Credential     │                  │
│     │   injection      │                  │
│     └─────────────────┘                   │
└──────────────────────────────────────────┘
```

## Network Enforcement

Three things make it work:

1. `docker network create --internal agent-net` — no internet for containers
2. Proxy on both `agent-net` + `bridge` — sole exit point
3. `HTTP_PROXY` / `HTTPS_PROXY` env on containers — CLIs route through proxy

The `--internal` flag is the enforcement. `HTTP_PROXY` is the convenience. Even tools that ignore proxy settings can't reach the internet — there's no route.

## Route Policy

The proxy isn't just an auth injector — it's a policy layer. You define what each agent can *do* per API:

```yaml
rules:
  - agent: pa
    host: api.github.com
    credential: github-pa
    routes:
      - method: GET
        path: "/**"
      - method: POST
        path: "/repos/*/issues"
      - method: PATCH
        path: "/repos/*/issues/*"
      # no DELETE — PA can't delete anything

  - agent: teslacoil
    host: api.github.com
    credential: github-tc
    routes:
      - method: [GET, POST, PATCH]
        path: "/repos/skarard/teslacoil/**"
      # scoped to one repo, no DELETE

default: deny
```

This is **stronger than platform-level scoping**. GitHub fine-grained PATs can't say "read-write except no deletes." The proxy can.

Only `api.github.com` is allowed, not `github.com`. Agents can't hit web login pages through the proxy. Combined with `--internal` network, there's no path to web UIs.

## Credential Backend

Integrates with OpenClaw's existing secrets manager. The proxy resolves credentials from the same backend (env, file, exec) — supports 1Password, HashiCorp Vault, sops, age-encrypted files.

Credentials resolved at startup into memory. Never written to disk. Never exposed to containers.

## Security Properties

| Property | Status |
|----------|--------|
| Token in container env | ❌ Never |
| Token in agent prompt | ❌ Never |
| Prompt injection can extract token | ❌ Impossible |
| Agent can auth via web UI | ❌ Blocked by network + host allowlist |
| Per-agent credential scoping | ✅ Config-driven |
| Per-route method restrictions | ✅ Policy layer |
| Default policy | Deny (fail closed) |
| Audit log | ✅ Every request logged with agent ID |

## Status

Early development. See [DESIGN.md](./DESIGN.md) for the full design document.

## License

MIT
