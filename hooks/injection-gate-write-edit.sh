#!/bin/bash
# PreToolUse hook on Write/Edit — single-use marker-file gate for the
# five protected destination categories.
#
# Categorization (case statement below):
#   - rule     → CLAUDE.md
#   - settings → .claude/settings.json + settings.local.json
#   - hook     → .claude/hooks/*.sh
#   - skill    → skills/*/SKILL.md, .claude/skills/*
#   - memory   → */memory/*.md, */agent-memory/*.md
#   - other    → pass (exit 0); unprotected
#
# Marker semantics mirror .claude/hooks/mark-code-review.sh:
#   - Marker dir:  /tmp/.claude-injection-gate/
#   - Marker name: {category}-{sha256_first_16(abs_path)}
#   - Touched by the corresponding /save-* or /edit-* slash command;
#     consumed (rm) by this hook on a matching Write/Edit.
#   - sha256(abs_path) binds the marker to the EXACT path AND category
#     so a marker for path A cannot unlock a write to path B.
#
# Why marker-file pattern (and not, say, an in-process flag):
#   - The agent cannot forge the marker — only the slash command body
#     (executed by the harness, not by the agent's tool call) writes it.
#   - It matches the prior art the user already trusts
#     (mark-code-review.sh / require-code-review.sh).
#
# See docs/roadmaps/injection-gate-pillar.md Part 5 MVP items 5-7 and
# Part 6 Q3 (marker-file pattern locked in second brainstorm).

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')

case "$TOOL" in
  Write|Edit) ;;
  *) exit 0 ;;
esac

PATH_RAW=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
if [ -z "$PATH_RAW" ]; then
  exit 0
fi

# Categorize. The patterns are deliberately path-suffix oriented so
# they catch the protected files regardless of where the repo lives.
CATEGORY=""
SLASH_CMD=""
case "$PATH_RAW" in
  */CLAUDE.md|CLAUDE.md)
    CATEGORY="rule"
    SLASH_CMD="/save-rule"
    ;;
  */.claude/settings.json|*/.claude/settings.local.json)
    CATEGORY="settings"
    SLASH_CMD="/edit-settings"
    ;;
  */.claude/hooks/*.sh)
    CATEGORY="hook"
    SLASH_CMD="/edit-hook"
    ;;
  */skills/*/SKILL.md|*/.claude/skills/*)
    CATEGORY="skill"
    SLASH_CMD="/edit-skill"
    ;;
  */memory/*.md|*/agent-memory/*.md)
    CATEGORY="memory"
    SLASH_CMD="/save-memory"
    ;;
  *)
    # Unprotected path — pass through.
    exit 0
    ;;
esac

# Compute the marker key. Must match the slash command's hash exactly.
HASH=$(printf '%s' "$PATH_RAW" | shasum -a 256 | cut -c1-16)
MARKER="/tmp/.claude-injection-gate/${CATEGORY}-${HASH}"

if [ ! -f "$MARKER" ]; then
  cat >&2 <<MSG
BLOCKED: ${CATEGORY} edit requires explicit operator approval.

  Path: ${PATH_RAW}

Ask the operator to run:

  ${SLASH_CMD} ${PATH_RAW}

This writes a single-use marker that authorizes the next Write/Edit
to exactly this path. The marker is consumed on first matching write
so each authorized edit is one-shot.

Why this exists: prompt-injected content could otherwise steer the
agent into poisoning CLAUDE.md / a hook / a skill / settings.json /
project memory. See docs/roadmaps/injection-gate-pillar.md Part 1.
MSG
  exit 2
fi

# Marker present — consume it and allow the write.
rm -f "$MARKER"
exit 0
