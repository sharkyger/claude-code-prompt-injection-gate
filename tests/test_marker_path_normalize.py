"""Tests for slash-command-side path normalization in the marker write step.

The five marker-writing slash commands (``/save-memory``, ``/save-rule``,
``/edit-settings``, ``/edit-hook``, ``/edit-skill``) hash a path string
and write a marker file the corresponding Write/Edit hook consumes on
the operator's next matching write. The path that lands in the hash
must match the path the hook itself hashes — otherwise the marker
authorizes the wrong write and the gate blocks even an approved edit.

These tests pin the normalization the slash commands apply: collapse
*all* whitespace (leading, trailing, internal), expanduser, abspath.
Any variant the operator might type — line-wrapped path with stray
space, trailing space, ``~`` prefix, ``./`` redundancy — must collapse
to the same canonical string the hook later sees, so the SHA256-first-16
hash matches.

See ``test_slash_commands_markers.py`` for the broader structural and
round-trip checks on the same slash commands.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
COMMANDS_DIR = REPO_ROOT / "commands"
ALL_COMMANDS = ["save-memory.md", "save-rule.md", "edit-hook.md", "edit-settings.md", "edit-skill.md"]

CANONICAL_PATH = "/Users/example/.claude/projects/X/memory/notes.md"


def normalize(raw: str) -> str:
    """Mirror the slash command's path normalization expression.

    See ``commands/save-memory.md`` (and the four siblings) — the body
    invokes ``python3 -c ...os.path.abspath(os.path.expanduser(
    "".join(sys.argv[1].split())))``. This function captures that exact
    expression so unit tests don't need to subprocess to bash for every
    variant.
    """
    # os.path.* mirrors the slash command's bash one-liner verbatim;
    # switching to pathlib here would silently drift from the bash
    # semantics on edge cases (e.g. non-existent paths, symlink handling).
    return os.path.abspath(os.path.expanduser("".join(raw.split())))  # noqa: PTH100, PTH111


def hash16(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


@pytest.fixture
def canonical_hash() -> str:
    return hash16(CANONICAL_PATH)


class TestWhitespaceVariants:
    """All whitespace variants must collapse to the same canonical hash."""

    def test_trailing_space(self, canonical_hash: str) -> None:
        assert hash16(normalize(CANONICAL_PATH + "  ")) == canonical_hash

    def test_leading_space(self, canonical_hash: str) -> None:
        assert hash16(normalize("  " + CANONICAL_PATH)) == canonical_hash

    def test_trailing_newline(self, canonical_hash: str) -> None:
        assert hash16(normalize(CANONICAL_PATH + "\n")) == canonical_hash

    def test_internal_space_from_unwrapped_paste(self, canonical_hash: str) -> None:
        """Operator pasted a line-wrapped path and the wrap-fix typo'd a space."""
        broken = "/Users/example/.claude/projects/X/memory /notes.md"
        canonical = "/Users/example/.claude/projects/X/memory/notes.md"
        assert hash16(normalize(broken)) == hash16(canonical)

    def test_multiple_internal_spaces(self) -> None:
        broken = "/Users/example/  .claude/   projects/X/memory/notes.md"
        canonical = "/Users/example/.claude/projects/X/memory/notes.md"
        assert hash16(normalize(broken)) == hash16(canonical)

    def test_internal_tabs_and_newlines(self) -> None:
        broken = "/Users/example/\t.claude/\nprojects/X/memory/notes.md"
        canonical = "/Users/example/.claude/projects/X/memory/notes.md"
        assert hash16(normalize(broken)) == hash16(canonical)


class TestPathFormVariants:
    """Path-form variants must also normalize to the canonical form."""

    def test_dot_segment(self, canonical_hash: str) -> None:
        with_dot = "/Users/example/./.claude/projects/X/memory/notes.md"
        assert hash16(normalize(with_dot)) == canonical_hash

    def test_double_slashes(self, canonical_hash: str) -> None:
        with_double = "/Users/example//.claude/projects/X/memory/notes.md"
        assert hash16(normalize(with_double)) == canonical_hash

    def test_expanduser(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """~ expansion uses HOME at hash time. The slash command and the hook
        both run in the same operator environment so HOME is consistent."""
        monkeypatch.setenv("HOME", "/Users/example")
        assert normalize("~/.claude/projects/X/memory/notes.md") == (
            "/Users/example/.claude/projects/X/memory/notes.md"
        )


class TestBashExpressionMatchesPythonFunction:
    """The unit-tested Python function must produce the same output as the
    actual bash one-liner the slash command invokes. Pin them together so
    one cannot drift from the other."""

    @pytest.mark.parametrize(
        "variant",
        [
            CANONICAL_PATH,
            CANONICAL_PATH + "  ",
            "  " + CANONICAL_PATH,
            "/Users/example/.claude/projects/X/memory /notes.md",
            "/Users/example/./.claude/projects/X/memory/notes.md",
        ],
    )
    def test_bash_matches_python(self, variant: str) -> None:
        bash_output = subprocess.run(
            [
                "python3",
                "-c",
                'import sys,os; print(os.path.abspath(os.path.expanduser("".join(sys.argv[1].split()))))',
                variant,
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert bash_output == normalize(variant)


class TestAllFiveSlashCommandsCarryNormalization:
    """Every slash command must include the normalization. A drop-back to
    the un-normalized form would silently regress the fix."""

    @pytest.mark.parametrize("cmd", ALL_COMMANDS)
    def test_command_uses_normalize_expression(self, cmd: str) -> None:
        body = (COMMANDS_DIR / cmd).read_text()
        assert "os.path.abspath" in body, f"{cmd} missing abspath normalization"
        assert "os.path.expanduser" in body, f"{cmd} missing expanduser normalization"
        assert ".split()" in body, f"{cmd} missing whitespace-collapse via split()"

    @pytest.mark.parametrize("cmd", ALL_COMMANDS)
    def test_command_hashes_normalized_path_not_arguments(self, cmd: str) -> None:
        """Regression guard: the original buggy form hashed $ARGUMENTS directly.
        After the fix, the hash must be computed over $NORM (the normalized form)."""
        body = (COMMANDS_DIR / cmd).read_text()
        assert "$NORM" in body, f"{cmd} no longer references $NORM in the body"
        # The shasum pipeline must consume $NORM, not $ARGUMENTS.
        assert 'printf \'%s\' "$NORM" | shasum' in body, (
            f"{cmd} must hash $NORM, not $ARGUMENTS"
        )

    @pytest.mark.parametrize("cmd", ALL_COMMANDS)
    def test_command_allows_python3(self, cmd: str) -> None:
        body = (COMMANDS_DIR / cmd).read_text()
        assert "Bash(python3:*)" in body, f"{cmd} missing python3 in allowed-tools"
