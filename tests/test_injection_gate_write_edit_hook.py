"""Tests for the Write/Edit injection-gate marker hook (Session B PR-2).

PreToolUse on Write or Edit. Categorizes the target path into one of
five protected destinations (memory, rule, settings, hook, skill) and
requires a single-use marker file written by the matching slash
command (``/save-memory``, ``/save-rule``, ``/edit-settings``,
``/edit-hook``, ``/edit-skill``). Unprotected paths pass through.

Marker semantics mirror ``mark-code-review.sh``: a marker is a sentinel
file under ``/tmp/.claude-injection-gate/``, touched by the slash
command and ``rm``-consumed by the hook on a matching Write/Edit.
Marker name = ``{category}-{sha256_first_16(abs_path)}`` so a marker
for path A cannot unlock a write to path B (or to a same-category
sibling).

See ``docs/roadmaps/injection-gate-pillar.md`` Part 5 MVP items 5-7
and Part 8 Session-B steps 5-7.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).parent.parent / ".claude" / "hooks" / "injection-gate-write-edit.sh"
MARKER_DIR = Path("/tmp/.claude-injection-gate")  # noqa: S108 — protocol path, mirrors mark-code-review.sh


@pytest.fixture(autouse=True)
def _clean_markers():
    """Empty the marker dir before and after each test for isolation."""
    if MARKER_DIR.exists():
        shutil.rmtree(MARKER_DIR)
    yield
    if MARKER_DIR.exists():
        shutil.rmtree(MARKER_DIR)


def run_hook(payload: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def write(path: str) -> dict:
    return {"tool_name": "Write", "tool_input": {"file_path": path}}


def edit(path: str) -> dict:
    return {"tool_name": "Edit", "tool_input": {"file_path": path}}


def marker_key(category: str, abs_path: str) -> str:
    h = hashlib.sha256(abs_path.encode()).hexdigest()[:16]
    return f"{category}-{h}"


def write_marker(category: str, abs_path: str) -> Path:
    MARKER_DIR.mkdir(parents=True, exist_ok=True)
    marker = MARKER_DIR / marker_key(category, abs_path)
    marker.touch()
    return marker


# Realistic-looking absolute paths. The hook works on path PATTERNS, not
# on actual file existence — we never touch these in tests.
PROTECTED_CASES = [
    ("rule", "/Users/sample/repo/CLAUDE.md", "save-rule"),
    ("settings", "/Users/sample/repo/.claude/settings.json", "edit-settings"),
    ("hook", "/Users/sample/repo/.claude/hooks/example.sh", "edit-hook"),
    ("skill", "/Users/sample/repo/skills/example/SKILL.md", "edit-skill"),
    ("memory", "/Users/sample/.claude/projects/sample-proj/memory/example.md", "save-memory"),
]


# ── block / pass / consume — five categories ─────────────────────────


@pytest.mark.parametrize("category,path,slash_cmd", PROTECTED_CASES)
class TestProtectedPathGate:
    def test_blocks_write_without_marker(self, category, path, slash_cmd):
        r = run_hook(write(path))
        assert r.returncode == 2
        assert "BLOCKED" in r.stderr
        assert path in r.stderr
        assert slash_cmd in r.stderr

    def test_blocks_edit_without_marker(self, category, path, slash_cmd):
        # Edit must be gated the same as Write.
        r = run_hook(edit(path))
        assert r.returncode == 2
        assert slash_cmd in r.stderr

    def test_passes_with_marker(self, category, path, slash_cmd):
        write_marker(category, path)
        r = run_hook(write(path))
        assert r.returncode == 0

    def test_marker_consumed_on_first_use(self, category, path, slash_cmd):
        marker = write_marker(category, path)
        assert marker.exists()
        r = run_hook(write(path))
        assert r.returncode == 0
        assert not marker.exists(), "marker should be removed after consumption"
        # Second attempt without a fresh marker must block.
        r2 = run_hook(write(path))
        assert r2.returncode == 2


# ── unprotected paths pass through ───────────────────────────────────


class TestUnprotectedPaths:
    def test_random_tmp_path_passes(self):
        r = run_hook(write("/tmp/random-output.txt"))  # noqa: S108 — fixture string
        assert r.returncode == 0
        assert r.stderr == ""

    def test_repo_source_file_passes(self):
        r = run_hook(write("/Users/sample/repo/scripts/foo.py"))
        assert r.returncode == 0

    def test_repo_test_file_passes(self):
        r = run_hook(write("/Users/sample/repo/tests/test_foo.py"))
        assert r.returncode == 0

    def test_repo_docs_file_passes(self):
        r = run_hook(write("/Users/sample/repo/docs/some-doc.md"))
        assert r.returncode == 0


# ── non-Write/Edit tools are no-ops ──────────────────────────────────


class TestOtherTools:
    def test_read_tool_noop_even_on_protected_path(self):
        # Reading a protected file is fine; only writes are gated.
        r = run_hook(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/Users/sample/repo/CLAUDE.md"},
            }
        )
        assert r.returncode == 0
        assert r.stderr == ""

    def test_bash_tool_noop(self):
        r = run_hook({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        assert r.returncode == 0

    def test_empty_file_path_noop(self):
        r = run_hook({"tool_name": "Write", "tool_input": {}})
        assert r.returncode == 0


# ── path-cross safety ────────────────────────────────────────────────


class TestPathCrossSafety:
    """A marker is bound to a specific absolute path AND category.

    A marker written for one path/category MUST NOT unlock a write to a
    different path, nor to a sibling file in the same category. The
    sha256(abs_path) key enforces this mechanically.
    """

    def test_memory_marker_does_not_unlock_rule(self):
        write_marker("memory", "/Users/sample/.claude/projects/X/memory/a.md")
        r = run_hook(write("/Users/sample/repo/CLAUDE.md"))
        assert r.returncode == 2

    def test_marker_for_path_a_does_not_unlock_path_b_in_same_category(self):
        write_marker("memory", "/Users/sample/.claude/projects/X/memory/a.md")
        r = run_hook(write("/Users/sample/.claude/projects/X/memory/b.md"))
        assert r.returncode == 2

    def test_hook_marker_does_not_unlock_skill(self):
        write_marker("hook", "/Users/sample/repo/.claude/hooks/a.sh")
        r = run_hook(write("/Users/sample/repo/skills/x/SKILL.md"))
        assert r.returncode == 2

    def test_wrong_category_marker_for_same_path_does_not_unlock(self):
        # A skill-category marker for /repo/CLAUDE.md (which is a
        # rule-category path) must not unlock it.
        write_marker("skill", "/Users/sample/repo/CLAUDE.md")
        r = run_hook(write("/Users/sample/repo/CLAUDE.md"))
        assert r.returncode == 2
