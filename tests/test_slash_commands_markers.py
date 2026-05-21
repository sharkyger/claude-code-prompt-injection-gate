"""Tests for the 5 marker-writing slash commands (Session B PR-2).

Each ``.claude/commands/{name}.md`` file is a Claude Code slash command.
The body contains a ``!``-prefixed shell line that touches a marker
file under ``/tmp/.claude-injection-gate/``. The matching Write/Edit
hook consumes the marker on the operator's next Write/Edit to the same
path.

These tests verify the file is structurally valid (frontmatter,
allowed-tools restriction) and that the shell body, with ``$ARGUMENTS``
substituted, actually creates the marker that the hook will accept.
The round-trip pass (slash command writes marker → hook consumes it)
is the contract that prevents the agent from forging the marker
itself.

See ``docs/roadmaps/injection-gate-pillar.md`` Part 5 MVP items 6-7
and Part 8 Session-B step 6.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
COMMANDS_DIR = REPO_ROOT / ".claude" / "commands"
HOOK = REPO_ROOT / ".claude" / "hooks" / "injection-gate-write-edit.sh"
MARKER_DIR = Path("/tmp/.claude-injection-gate")  # noqa: S108 — protocol path


# (filename, category, sample-absolute-path-for-this-category)
SLASH_COMMANDS = [
    ("save-memory.md", "memory", "/Users/sample/.claude/projects/X/memory/test.md"),
    ("save-rule.md", "rule", "/Users/sample/repo/CLAUDE.md"),
    ("edit-settings.md", "settings", "/Users/sample/repo/.claude/settings.json"),
    ("edit-hook.md", "hook", "/Users/sample/repo/.claude/hooks/example.sh"),
    ("edit-skill.md", "skill", "/Users/sample/repo/skills/example/SKILL.md"),
]


@pytest.fixture(autouse=True)
def _clean_markers():
    if MARKER_DIR.exists():
        shutil.rmtree(MARKER_DIR)
    yield
    if MARKER_DIR.exists():
        shutil.rmtree(MARKER_DIR)


def _frontmatter(md_file: Path) -> str:
    text = md_file.read_text()
    assert text.startswith("---"), f"{md_file.name} must start with YAML frontmatter"
    end = text.find("---", 3)
    assert end != -1, f"{md_file.name} frontmatter not closed"
    return text[3:end]


def _extract_shell_block(md_file: Path) -> str:
    """Return the single !-prefixed shell command in the body."""
    text = md_file.read_text()
    match = re.search(r"^!(.+)$", text, re.MULTILINE)
    if not match:
        raise AssertionError(f"No !-prefixed shell line in {md_file.name}")
    return match.group(1).strip()


def _expected_marker(category: str, abs_path: str) -> Path:
    h = hashlib.sha256(abs_path.encode()).hexdigest()[:16]
    return MARKER_DIR / f"{category}-{h}"


# ── structural checks ───────────────────────────────────────────────


@pytest.mark.parametrize("filename,category,fixture_path", SLASH_COMMANDS)
class TestSlashCommandShape:
    def test_file_exists(self, filename, category, fixture_path):
        assert (COMMANDS_DIR / filename).is_file()

    def test_frontmatter_has_description(self, filename, category, fixture_path):
        fm = _frontmatter(COMMANDS_DIR / filename)
        assert "description:" in fm

    def test_frontmatter_has_argument_hint(self, filename, category, fixture_path):
        fm = _frontmatter(COMMANDS_DIR / filename)
        assert "argument-hint:" in fm

    def test_frontmatter_restricts_allowed_tools(self, filename, category, fixture_path):
        # Each command must whitelist only the tools it actually needs
        # (mkdir/touch/shasum). Without this, Claude Code's tool prompts
        # could grant broader Bash access than the marker write needs.
        fm = _frontmatter(COMMANDS_DIR / filename)
        assert "allowed-tools:" in fm
        # No broad Bash() wildcard.
        assert "Bash(*)" not in fm
        assert "Bash:*" not in fm

    def test_shell_block_present(self, filename, category, fixture_path):
        cmd = _extract_shell_block(COMMANDS_DIR / filename)
        assert cmd, "shell block is empty"
        # Must reference the marker dir; must not reference dangerous ops.
        assert "/tmp/.claude-injection-gate" in cmd  # noqa: S108 — protocol path
        for forbidden in ("rm ", "curl ", "wget ", "ssh ", "scp ", "eval ", "sudo "):
            assert forbidden not in cmd, f"shell block contains {forbidden!r}"


# ── functional: shell block writes the expected marker ───────────────


@pytest.mark.parametrize("filename,category,fixture_path", SLASH_COMMANDS)
class TestSlashCommandMarkerWrite:
    def test_shell_block_creates_expected_marker(self, filename, category, fixture_path):
        cmd = _extract_shell_block(COMMANDS_DIR / filename)
        # Claude Code substitutes $ARGUMENTS textually before exec.
        cmd_with_args = cmd.replace("$ARGUMENTS", fixture_path)
        result = subprocess.run(
            ["bash", "-c", cmd_with_args],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        assert result.returncode == 0, f"shell block failed: {result.stderr}"
        expected = _expected_marker(category, fixture_path)
        assert expected.exists(), (
            f"expected marker {expected.name} not created. "
            f"Got: {[p.name for p in MARKER_DIR.glob('*')] if MARKER_DIR.exists() else 'no marker dir'}"
        )


# ── round-trip: marker written by slash command satisfies the hook ──


@pytest.mark.parametrize("filename,category,fixture_path", SLASH_COMMANDS)
class TestSlashCommandRoundTrip:
    """End-to-end: invoke slash command's shell body, then call the
    Write/Edit hook on the same path — must pass and consume the marker.

    This is the contract that distinguishes a real operator approval
    from an injected one. The agent can't forge the marker because the
    hash binds it to the absolute path AND category, both of which the
    Write/Edit hook re-computes from the tool input.
    """

    def test_marker_written_by_slash_command_satisfies_hook(self, filename, category, fixture_path):
        cmd = _extract_shell_block(COMMANDS_DIR / filename)
        subprocess.run(
            ["bash", "-c", cmd.replace("$ARGUMENTS", fixture_path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        # Now invoke the Write/Edit hook on the same path
        hook_result = subprocess.run(
            ["bash", str(HOOK)],
            input=json.dumps(
                {
                    "tool_name": "Write",
                    "tool_input": {"file_path": fixture_path},
                }
            ),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert hook_result.returncode == 0, f"hook rejected a write authorized by {filename}: {hook_result.stderr}"
        # Marker should have been consumed
        assert not _expected_marker(category, fixture_path).exists()
