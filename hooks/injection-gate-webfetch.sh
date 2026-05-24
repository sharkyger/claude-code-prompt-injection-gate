#!/bin/bash
# PreToolUse hook on WebFetch — allowlist-aware hard-block.
#
# Allowlisted URLs (first-party Anthropic + your own domains) pass
# through silently. Non-allowlisted URLs are HARD-BLOCKED (exit 2,
# message to stderr) and the model is directed to use safe-fetch via
# Bash, which runs the fetch inside a Docker-isolated sandbox and
# wraps the response in <UNTRUSTED-WEB> tags so the Layer-4 rule
# applies.
#
# Edit the allowlist case statement below to add trusted domains;
# keep it in sync with .claude/hooks/injection-gate-bash.sh so a host
# is treated identically by both tools.
#
# See https://github.com/sharkyger/claude-code-prompt-injection-gate
# for the threat model and allowlist guidance.

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')

if [ "$TOOL" != "WebFetch" ]; then
  exit 0
fi

URL=$(echo "$INPUT" | jq -r '.tool_input.url // empty')
if [ -z "$URL" ]; then
  exit 0
fi

HOST=$(echo "$URL" | sed -E 's|^[a-zA-Z]+://([^/]+).*|\1|' | tr '[:upper:]' '[:lower:]')

case "$HOST" in
  anthropic.com|www.anthropic.com|docs.anthropic.com|support.anthropic.com|console.anthropic.com)
    exit 0 ;;
  code.claude.com|platform.claude.com|claude.com|www.claude.com)
    exit 0 ;;
esac

cat >&2 <<MSG
BLOCKED: WebFetch URL is not on the first-party allowlist.

  URL:  ${URL}
  Host: ${HOST}

Use safe-fetch instead — runs inside a Docker-isolated sandbox and
returns the response wrapped in <UNTRUSTED-WEB> tags so the Layer-4
prompt-injection rule applies:

  safe-fetch ${URL}

Invoke it via the Bash tool. The companion Bash hook treats safe-fetch
as the approved network egress path; raw curl/wget/http/wget2/etc.
against non-allowlisted hosts are also blocked.

If the URL is genuinely trustworthy (first-party docs, your own
infra), extend the allowlist in BOTH files (keep them in sync):

  hooks/injection-gate-webfetch.sh
  hooks/injection-gate-bash.sh

See https://github.com/sharkyger/claude-code-prompt-injection-gate
for the threat model and allowlist syntax.
MSG
exit 2
