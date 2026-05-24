# Mistral Vibe parity

This repo's hooks target Claude Code. If you also use [Mistral Vibe
(`vibe`)](https://github.com/mistralai/mistral-vibe) as a coding
agent, you'll want the same posture: every network call routed
through `safe-fetch`, every fetched response wrapped in
`<UNTRUSTED-WEB>` tags so the same Layer-4 rule applies.

**Vibe has no PreToolUse hook type.** It ships only
`POST_AGENT_TURN` hooks (verified at
`vibe/core/hooks/models.py:HookType`), which is too late to block a
fetch. So we cannot port these shell hooks 1:1.

The good news: Vibe's tool-permission model is declarative TOML, with
a sufficiently expressive `permission` / `allowlist` / `denylist`
schema. That's the entire enforcement surface — and it's enough.

## Target config

Edit `~/.vibe/config.toml`:

```toml
[tools.web_fetch]
permission = "never"

[tools.web_search]
permission = "never"

[tools.bash]
permission = "ask"
allowlist = [
    # ... existing entries ...
    "safe-fetch",
]
denylist = [
    # ... existing entries ...
    "curl", "wget", "wget2",
    "http", "https", "httpie", "xh", "curlie",
    "aria2c",
    "lynx", "links", "w3m", "elinks",
]
```

The `ToolPermission` enum supports `ALWAYS`, `NEVER`, `ASK`
(`vibe/core/tools/base.py:ToolPermission`). Setting `permission` to
`"never"` is a hard block.

## What you get

| Layer | Claude (hooks) | Vibe (TOML) |
|-------|----------------|-------------|
| WebFetch tool | `injection-gate-webfetch.sh` — hard-block | `[tools.web_fetch].permission = "never"` |
| Bash fetchers | `injection-gate-bash.sh` Stage 1 — block | `[tools.bash].denylist` (fetcher binaries) |
| safe-fetch egress | Allowlisted via host check | `[tools.bash].allowlist = ["safe-fetch", ...]` |
| web_search | (Claude has none) | `[tools.web_search].permission = "never"` |
| Inline interpreter fetches | `injection-gate-bash.sh` Stage A — block | Partial — `python` / `python3` in Vibe's `denylist_standalone` blocks the bare invocation; extend with `node`/`php`/`perl`/`ruby` for full parity |
| Marker-dir forgery | `injection-gate-bash.sh` Stage 0 — block | n/a (no marker workflow on the Vibe side) |

## What you do NOT get

Vibe's denylist matches command names, not arbitrary regex on the
raw command text. `bash -c 'curl …'` is not caught (the denylist
sees `bash`, not `curl`). On the Claude side, the Stage A interpreter
detector catches `python -c "import urllib …"` — Vibe has no
equivalent. Closing those routes inside Vibe needs upstream patches,
not config.

## Keeping them in sync

If you add a domain to the Claude allowlist
(`hooks/injection-gate-webfetch.sh` + `hooks/injection-gate-bash.sh`),
also add it to wherever Vibe's `safe-fetch` invocation expects
trusted hosts. The two configs do not share a source today.

## Why not contribute the hooks to Vibe upstream?

Until Vibe ships a PreToolUse hook type, shell hooks can't run at
the right moment. The TOML config IS the right primitive. If Vibe
gains a PreToolUse type, mirroring this repo's hook design becomes
straightforward — that's a separate upstream PR for the day it
lands.
