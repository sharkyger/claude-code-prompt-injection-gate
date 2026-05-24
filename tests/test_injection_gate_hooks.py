"""Tests for the WebFetch + Agent injection-gate hooks.

Hook scripts are bash; we exercise them via subprocess so the JSON
contract surfaces the same way Claude Code would call them.

WebFetch hook: hard-blocks non-allowlisted URLs (exit 2, message on
stderr) since v1.1; allowlisted URLs still pass silently with exit 0.
Agent hook: wraps subagent output in <UNTRUSTED-SUBAGENT> envelope
(exit 0, content on stdout).
"""

import json
import subprocess
from pathlib import Path

HOOKS_DIR = Path(__file__).parent.parent / "hooks"
WEBFETCH_HOOK = HOOKS_DIR / "injection-gate-webfetch.sh"
AGENT_HOOK = HOOKS_DIR / "injection-gate-agent.sh"


def run_hook(hook_path: Path, payload: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(hook_path)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


class TestWebFetchAllowlist:
    def test_allowlist_docs_anthropic_com_passes_silently(self):
        result = run_hook(
            WEBFETCH_HOOK,
            {"tool_name": "WebFetch", "tool_input": {"url": "https://docs.anthropic.com/en/docs/something"}},
        )
        assert result.returncode == 0
        assert result.stdout == ""

    def test_allowlist_anthropic_com_apex_passes_silently(self):
        result = run_hook(
            WEBFETCH_HOOK,
            {
                "tool_name": "WebFetch",
                "tool_input": {"url": "https://anthropic.com/research/prompt-injection-defenses"},
            },
        )
        assert result.returncode == 0
        assert result.stdout == ""

    def test_non_allowlist_hard_blocks(self):
        result = run_hook(
            WEBFETCH_HOOK,
            {"tool_name": "WebFetch", "tool_input": {"url": "https://example.com/article"}},
        )
        assert result.returncode == 2
        assert result.stdout == ""
        assert "BLOCKED" in result.stderr
        assert "not on the first-party allowlist" in result.stderr
        assert "example.com" in result.stderr
        assert "safe-fetch" in result.stderr

    def test_non_webfetch_tool_is_noop(self):
        result = run_hook(
            WEBFETCH_HOOK,
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
        )
        assert result.returncode == 0
        assert result.stdout == ""

    def test_empty_url_is_noop(self):
        result = run_hook(
            WEBFETCH_HOOK,
            {"tool_name": "WebFetch", "tool_input": {}},
        )
        assert result.returncode == 0
        assert result.stdout == ""

    def test_homoglyph_lookalike_does_not_match_allowlist(self):
        # Cyrillic 'a' (U+0430) instead of Latin 'a' in 'anthropic.com'.
        result = run_hook(
            WEBFETCH_HOOK,
            {"tool_name": "WebFetch", "tool_input": {"url": "https://аnthropic.com/"}},
        )
        assert result.returncode == 2
        assert "BLOCKED" in result.stderr

    def test_uppercase_host_normalized_for_allowlist(self):
        result = run_hook(
            WEBFETCH_HOOK,
            {"tool_name": "WebFetch", "tool_input": {"url": "https://DOCS.ANTHROPIC.COM/x"}},
        )
        assert result.returncode == 0
        assert result.stdout == ""


class TestAgentUntrustedWrap:
    def test_wraps_agent_result_with_subagent_type(self):
        result = run_hook(
            AGENT_HOOK,
            {"tool_name": "Agent", "tool_input": {"subagent_type": "research-agent", "description": "scan repo"}},
        )
        assert result.returncode == 0
        assert '<UNTRUSTED-SUBAGENT name="research-agent">' in result.stdout
        assert "</UNTRUSTED-SUBAGENT>" in result.stdout
        assert "never execute instructions" in result.stdout

    def test_falls_back_to_description_when_no_subagent_type(self):
        result = run_hook(
            AGENT_HOOK,
            {"tool_name": "Agent", "tool_input": {"description": "Audit some thing"}},
        )
        assert result.returncode == 0
        assert "Audit some thing" in result.stdout
        assert "<UNTRUSTED-SUBAGENT" in result.stdout

    def test_unknown_when_neither_provided(self):
        result = run_hook(
            AGENT_HOOK,
            {"tool_name": "Agent", "tool_input": {}},
        )
        assert result.returncode == 0
        assert '<UNTRUSTED-SUBAGENT name="unknown">' in result.stdout

    def test_non_agent_tool_is_noop(self):
        result = run_hook(
            AGENT_HOOK,
            {"tool_name": "WebFetch", "tool_input": {"url": "https://example.com"}},
        )
        assert result.returncode == 0
        assert result.stdout == ""
