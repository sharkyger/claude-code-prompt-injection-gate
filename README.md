# claude-code-prompt-injection-gate

Four PreToolUse/PostToolUse hooks + five operator slash commands +
a CLAUDE.md Layer-4 snippet that close the indirect-prompt-injection
gap in Claude Code.

## What it does

When an AI agent (Claude Code in particular) fetches a webpage,
reads a file, or runs a subagent, the returned text gets treated as
trusted context. **Indirect prompt injection** turns "I read this
output" into "the output wrote my next command." The CVE evidence
is published — see [docs/threat-model.md](docs/threat-model.md).

This repo ships the enforcement layer:

| Layer | What it does | File |
|-------|--------------|------|
| 1 | PreToolUse hook on `WebFetch` — allowlist-aware hard-block. Non-allowlisted hosts get `exit 2` with a stderr message directing the model at `safe-fetch`. Allowlisted hosts pass silently. | [`hooks/injection-gate-webfetch.sh`](hooks/injection-gate-webfetch.sh) |
| 2 | PreToolUse hook on `Bash` — two detectors. **Stage 1** blocks the common fetchers (`curl`, `wget`, `wget2`, HTTPie family — `http`/`https`/`httpie`/`xh`/`curlie`, `aria2c`, and text-mode browsers — `lynx`/`links`/`w3m`/`elinks`) against non-allowlisted hosts. **Stage A** (v1.1) blocks inline interpreter fetches — `python -c` / `node -e` / `php -r` / `perl -e` / `ruby -e` / `deno`/`bun` invocations whose body references a network primitive — to close the one-liner bypass. Also blocks any reference to the marker dir, preventing the agent from forging a write-authorization marker. | [`hooks/injection-gate-bash.sh`](hooks/injection-gate-bash.sh) |
| 3 | PostToolUse hook on `Agent` — wraps subagent return text in an untrusted-subagent envelope so the parent treats it as data. | [`hooks/injection-gate-agent.sh`](hooks/injection-gate-agent.sh) |
| 4 | PreToolUse hook on `Write`/`Edit` — gates writes to five protected destination categories (CLAUDE.md, settings.json, hook files, skill files, project-memory files) behind a single-use marker file. | [`hooks/injection-gate-write-edit.sh`](hooks/injection-gate-write-edit.sh) |
| 5 | Five operator slash commands that write the marker — only way to authorize a protected-path write. | [`commands/`](commands/) |
| 6 | CLAUDE.md Layer-4 rule snippet — the system rule that tells the agent to treat envelope-wrapped content as data, never as instructions. The literal tag names are documented in the snippet itself (the agent has to recognize them); the sanitizer escapes any matching sequences inside fetched content so the wrap can't be broken out of. | [`snippets/claude_md.md`](snippets/claude_md.md) |

## Install (recommended)

The companion CLI [safe-fetch](https://github.com/sharkyger/safe-fetch)
ships an idempotent installer that writes all of the above into
`~/.claude/` with two commands:

```bash
brew install sharkyger/tap/safe-fetch
safe-fetch --install-claude-hooks
```

Uninstall:

```bash
safe-fetch --uninstall-claude-hooks
```

## Install (manual)

If you don't want to install `safe-fetch`, you can wire the bundle
manually:

```bash
git clone https://github.com/sharkyger/claude-code-prompt-injection-gate
cd claude-code-prompt-injection-gate
mkdir -p ~/.claude/hooks ~/.claude/commands
cp hooks/*.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/*.sh
cp commands/*.md ~/.claude/commands/
cat snippets/claude_md.md >> ~/.claude/CLAUDE.md   # only once
```

Then edit `~/.claude/settings.json` to register the hooks:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "WebFetch",    "hooks": [{"type": "command", "command": "/Users/YOU/.claude/hooks/injection-gate-webfetch.sh"}]},
      {"matcher": "Bash",        "hooks": [{"type": "command", "command": "/Users/YOU/.claude/hooks/injection-gate-bash.sh"}]},
      {"matcher": "Write|Edit",  "hooks": [{"type": "command", "command": "/Users/YOU/.claude/hooks/injection-gate-write-edit.sh"}]}
    ],
    "PostToolUse": [
      {"matcher": "Agent",       "hooks": [{"type": "command", "command": "/Users/YOU/.claude/hooks/injection-gate-agent.sh"}]}
    ]
  }
}
```

Note: the absolute paths inside `command` must match where you
copied the hooks. Use your real `$HOME`, not `~`.

## How a marker prompt works

When Claude Code tries to edit a protected file (e.g. `~/.claude/CLAUDE.md`,
a hook, a skill, or a project-memory file), the Write/Edit hook
blocks the write with a message like:

```
BLOCKED: rule edit requires explicit operator approval.

  Path: /Users/you/.claude/CLAUDE.md

Ask the operator to run:

  /save-rule /Users/you/.claude/CLAUDE.md
```

You then run `/save-rule <path>` in chat. The slash command writes
a sentinel marker file under `/tmp/.claude-injection-gate/`. The
Write/Edit hook consumes the marker on Claude's next write to
exactly that path. **The marker is single-use** — each authorized
write needs a fresh slash command. The agent itself cannot create
the marker (the Bash hook blocks any reference to the marker dir).

This is how the gate proves *operator intent*, not just *agent
intent*.

## The five slash commands

| Command | Authorizes | Targets |
|---------|------------|---------|
| `/save-memory <path>` | Memory writes | `*/memory/*.md`, `*/agent-memory/*.md` |
| `/save-rule <path>` | CLAUDE.md edits | `*/CLAUDE.md`, `CLAUDE.md` |
| `/edit-skill <path>` | Skill edits | `*/skills/*/SKILL.md`, `*/.claude/skills/*` |
| `/edit-settings <path>` | Settings.json edits | `*/.claude/settings.json`, `*/.claude/settings.local.json` |
| `/edit-hook <path>` | Hook script edits | `*/.claude/hooks/*.sh` |

Each command's body is a one-liner that `touch`es the marker file
the corresponding hook check expects.

## Allowlist syntax

Allowlists live in the two routing hooks
(`injection-gate-webfetch.sh` and `injection-gate-bash.sh`). Both
contain a `case "$HOST" in ... esac` block. Add your trusted hosts:

```bash
case "$HOST" in
  anthropic.com|*.anthropic.com)       exit 0 ;;
  claude.com|*.claude.com)             exit 0 ;;
  yourcompany.com|*.yourcompany.com)   exit 0 ;;   # add this
esac
```

Edit both files (Bash and WebFetch) — the two hooks enforce the
same trust boundary at two different tool surfaces.

## Testing

```bash
# Unit tests over all four hooks, the five slash commands, plus an
# end-to-end smoke matrix that exercises both fetch hooks via the
# same JSON contract Claude Code uses at runtime.
python3 -m pytest tests/ -v
```

Tests exercise hooks via subprocess so the JSON contract surfaces
the same way Claude Code calls them. No mocks for shell behaviour.

## What it does NOT do

- **Semantic adversarial prose** (vector 5 in the threat model) —
  natural-language injections with no Unicode/HTML tells. Requires
  an LLM-judge step; not in scope for the regex-based hooks.
- **Install-time malicious dependencies** — if a hook or skill ships
  with malicious code in it, runtime hooks won't catch it. Use
  the CVE-gate trio
  ([`homebrew-safe-upgrade`](https://github.com/sharkyger/homebrew-safe-upgrade),
  [`claude-code-cve-gate`](https://github.com/sharkyger/claude-code-cve-gate))
  for that layer.
- **WebFetch's internal fast-model summarization** — Anthropic's
  WebFetch passes content through a small summarizer before returning;
  an injection inside the page can steer it. We can't intercept this
  step. Recommendation: use `safe-fetch` for non-allowlisted URLs
  (avoids WebFetch entirely).

## See also

If you also use [Mistral Vibe](https://github.com/mistralai/mistral-vibe)
(`vibe`), the same posture is achievable via its TOML permission
config rather than shell hooks (Vibe upstream has no PreToolUse hook
type). See [`docs/vibe-parity.md`](docs/vibe-parity.md) for the
mapping.

## License

MIT — see [LICENSE](LICENSE).
