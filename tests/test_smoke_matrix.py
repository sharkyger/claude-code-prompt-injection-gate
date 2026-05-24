"""End-to-end exit-code matrix for the fetch-related hooks.

This is the integration-level smoke check that exercises both the
WebFetch hook and the Bash hook through the same JSON contract Claude
Code uses at runtime. It's parametrized rather than asserting one
behavior per test method, so a regression in either hook surfaces as
a single failing parameter set with a useful label.

Coverage rationale (per hook):

* **WebFetch hook**: allowlisted host passes, non-allowlisted host
  hard-blocks (returncode == 2). Confirms the v1.1 hard-block.
* **Bash hook**: expanded fetcher set blocked on non-allowlisted,
  ``safe-fetch`` passes through (it is the approved egress path),
  allowlisted host passes, ``rtk proxy <fetcher>`` blocked, false-
  positive shields hold (man/echo/curl --version).
* **Bash hook Stage A**: inline interpreter fetch blocks; benign
  ``python3 -c "print(...)"`` passes; rtk-wrapped interpreter blocks.

These cases mirror the 20-row hand-rolled smoke harness shipped in
operator installs; they're consolidated here so CI verifies the
behavior on every push.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

HOOKS_DIR = Path(__file__).parent.parent / "hooks"
WEBFETCH_HOOK = HOOKS_DIR / "injection-gate-webfetch.sh"
BASH_HOOK = HOOKS_DIR / "injection-gate-bash.sh"


def _run(hook: Path, payload: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(hook)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _webfetch(url: str) -> dict:
    return {"tool_name": "WebFetch", "tool_input": {"url": url}}


def _bash(command: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


# (label, hook, payload, expected_returncode)
WEBFETCH_CASES = [
    ("webfetch_allowlisted_anthropic_apex",   _webfetch("https://anthropic.com/x"),              0),
    ("webfetch_allowlisted_docs_anthropic",   _webfetch("https://docs.anthropic.com/anything"), 0),
    ("webfetch_allowlisted_claude_com",       _webfetch("https://claude.com/x"),                 0),
    ("webfetch_non_allowlisted_example",      _webfetch("https://example.com/x"),                2),
    ("webfetch_non_allowlisted_github",       _webfetch("https://github.com/x/y"),               2),
]

BASH_FETCHER_CASES = [
    ("bash_curl_non_allowlisted",             _bash("curl https://example.com/"),                 2),
    ("bash_safe_fetch_approved_path",         _bash("safe-fetch https://example.com/"),           0),
    ("bash_httpie_http",                      _bash("http https://example.com/"),                 2),
    ("bash_httpie_xh",                        _bash("xh https://example.com/"),                   2),
    ("bash_aria2c",                           _bash("aria2c https://example.com/file.tar"),       2),
    ("bash_lynx_dump",                        _bash("lynx -dump https://example.com/"),           2),
    ("bash_w3m_dump",                         _bash("w3m -dump https://example.com/"),            2),
    ("bash_curl_allowlisted_anthropic",       _bash("curl https://anthropic.com/x"),              0),
    ("bash_curl_allowlisted_docs",            _bash("wget https://docs.anthropic.com/x"),         0),
    ("bash_rtk_proxy_curl_blocked",           _bash("rtk proxy curl https://example.com/"),       2),
    ("bash_man_curl_false_positive_shield",   _bash("man curl"),                                  0),
    ("bash_curl_version_no_url",              _bash("curl --version"),                            0),
    ("bash_echo_about_curl_passes",           _bash("echo curl is a fetcher"),                    0),
]

BASH_INTERPRETER_CASES = [
    ("bash_python_c_urllib_blocked",
        _bash("python3 -c \"import urllib.request; urllib.request.urlopen('https://x.com')\""),  2),
    ("bash_python_c_print_passes",
        _bash("python3 -c \"print('hello')\""),                                                  0),
    ("bash_node_e_fetch_blocked",
        _bash("node -e \"fetch('https://x.com').then(r=>r.text())\""),                           2),
    ("bash_php_r_curl_init_blocked",
        _bash("php -r \"$c=curl_init('https://x.com');\""),                                      2),
    ("bash_perl_e_lwp_blocked",
        _bash("perl -e \"use LWP::Simple; get('https://x.com');\""),                             2),
    ("bash_ruby_e_net_http_blocked",
        _bash("ruby -e \"require 'net/http'; Net::HTTP.get(URI('https://x.com'))\""),            2),
]

ALL_CASES = (
    [(label, WEBFETCH_HOOK, payload, expected) for label, payload, expected in WEBFETCH_CASES]
    + [(label, BASH_HOOK, payload, expected) for label, payload, expected in BASH_FETCHER_CASES]
    + [(label, BASH_HOOK, payload, expected) for label, payload, expected in BASH_INTERPRETER_CASES]
)


@pytest.mark.parametrize(
    ("label", "hook", "payload", "expected"),
    ALL_CASES,
    ids=[c[0] for c in ALL_CASES],
)
def test_exit_code_matrix(label: str, hook: Path, payload: dict, expected: int):
    result = _run(hook, payload)
    assert result.returncode == expected, (
        f"{label}: expected exit {expected}, got {result.returncode}\n"
        f"stderr: {result.stderr}\nstdout: {result.stdout}"
    )
