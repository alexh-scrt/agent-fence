"""Tests for agent_fence.cli module.

Verifies the Click-based CLI commands: 'agent_fence run' and
'agent_fence show-policy'.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from typing import Any

import pytest
from click.testing import CliRunner

from agent_fence.cli import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_script(tmp_path, content: str, name: str = "agent.py") -> str:
    """Write a Python script to tmp_path and return its path."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(p)


def write_policy(tmp_path, content: str, name: str = "policy.yaml") -> str:
    """Write a YAML policy file to tmp_path and return its path."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(p)


MINIMAL_POLICY = """
    name: test-policy
    enforcement_mode: block
    audit_log:
      enabled: true
      path: "-"
      level: debug
    filesystem:
      enabled: true
      blocked_operations:
        - os.remove
        - shutil.rmtree
      allowed_operations:
        - os.listdir
        - os.getcwd
      strict_whitelist: false
    network:
      enabled: false
    subprocess:
      enabled: false
    env:
      enabled: false
"""


# ---------------------------------------------------------------------------
# CLI: top-level group
# ---------------------------------------------------------------------------


class TestCLIGroup:
    """Tests for the main CLI group."""

    def test_main_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "run" in result.output

    def test_main_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0

    def test_run_subcommand_exists(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["run", "--help"])
        assert result.exit_code == 0
        assert "SCRIPT" in result.output

    def test_show_policy_subcommand_exists(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["show-policy", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# CLI: run command – basic execution
# ---------------------------------------------------------------------------


class TestRunCommand:
    """Tests for the 'agent_fence run' command."""

    def test_run_simple_script(self, tmp_path: Any) -> None:
        """A simple script that does nothing should exit 0."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(tmp_path, "# no-op script\n")

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--policy", policy_path, script_path])
        assert result.exit_code == 0, result.output

    def test_run_script_with_print(self, tmp_path: Any) -> None:
        """Script output should appear in the output."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(tmp_path, "print('hello from agent')\n")

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--policy", policy_path, script_path])
        assert result.exit_code == 0, result.output
        assert "hello from agent" in result.output

    def test_run_script_nonexistent_raises(self, tmp_path: Any) -> None:
        """Running a non-existent script should fail with exit code != 0."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "--policy", policy_path, "/nonexistent/agent.py"],
        )
        assert result.exit_code != 0

    def test_run_without_policy_uses_defaults(self, tmp_path: Any) -> None:
        """Omitting --policy should not crash (uses built-in defaults)."""
        script_path = write_script(tmp_path, "x = 1 + 1\n")

        runner = CliRunner()
        result = runner.invoke(main, ["run", script_path])
        # May or may not find default_policy.yaml, but should not error on missing file
        assert result.exit_code == 0, result.output

    def test_run_policy_violation_exits_with_code_2(self, tmp_path: Any) -> None:
        """A PolicyViolation inside the sandbox should exit with code 2."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(
            tmp_path,
            """
            import os
            os.remove("/tmp/nonexistent_file_agent_fence_test")
            """,
        )

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--policy", policy_path, script_path])
        assert result.exit_code == 2

    def test_run_policy_violation_message_in_stderr(self, tmp_path: Any) -> None:
        """PolicyViolation message should appear in stderr output."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(
            tmp_path,
            """
            import os
            os.remove("/tmp/nonexistent_file_agent_fence_test")
            """,
        )

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(main, ["run", "--policy", policy_path, script_path])
        assert result.exit_code == 2
        # Message should appear in stderr or mixed output
        combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
        assert "BLOCKED" in combined or "os.remove" in combined

    def test_run_mode_log_only_override(self, tmp_path: Any) -> None:
        """--mode log_only should not raise even on blocked operations."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(
            tmp_path,
            """
            import os
            # os.remove is blocked in MINIMAL_POLICY, but log_only overrides
            try:
                os.remove("/tmp/nonexistent_agent_fence_test_xyz")
            except OSError:
                pass  # File not found is OK
            """,
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "--policy", policy_path, "--mode", "log_only", script_path],
        )
        assert result.exit_code == 0, result.output

    def test_run_script_sys_exit_0(self, tmp_path: Any) -> None:
        """sys.exit(0) inside script should result in exit code 0."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(
            tmp_path,
            """
            import sys
            sys.exit(0)
            """,
        )

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--policy", policy_path, script_path])
        assert result.exit_code == 0

    def test_run_script_sys_exit_nonzero(self, tmp_path: Any) -> None:
        """sys.exit(1) inside script should result in exit code 1."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(
            tmp_path,
            """
            import sys
            sys.exit(1)
            """,
        )

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--policy", policy_path, script_path])
        assert result.exit_code == 1

    def test_run_invalid_policy_file_exits_nonzero(self, tmp_path: Any) -> None:
        """An invalid YAML policy should produce a non-zero exit."""
        bad_policy = write_policy(tmp_path, "- not: a: valid: policy\n")
        script_path = write_script(tmp_path, "pass\n")

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--policy", bad_policy, script_path])
        assert result.exit_code != 0

    def test_run_nonexistent_policy_file_exits_nonzero(self, tmp_path: Any) -> None:
        """A missing policy file should produce a non-zero exit."""
        script_path = write_script(tmp_path, "pass\n")

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "--policy", "/nonexistent/policy.yaml", script_path],
        )
        assert result.exit_code != 0

    def test_run_verbose_flag(self, tmp_path: Any) -> None:
        """--verbose flag should not cause a crash."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(tmp_path, "x = 42\n")

        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main,
            ["run", "--policy", policy_path, "--verbose", script_path],
        )
        assert result.exit_code == 0

    def test_run_script_receives_args(self, tmp_path: Any) -> None:
        """Script arguments should be accessible via sys.argv."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(
            tmp_path,
            """
            import sys
            # sys.argv[0] is the script path; rest are the forwarded args
            print('args:', sys.argv[1:])
            """,
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "--policy", policy_path, script_path, "--foo", "bar"],
        )
        assert result.exit_code == 0, result.output
        assert "--foo" in result.output
        assert "bar" in result.output

    def test_run_script_allowed_operation_works(self, tmp_path: Any) -> None:
        """An allowed operation (os.getcwd) should execute without exception."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(
            tmp_path,
            """
            import os
            cwd = os.getcwd()
            print('cwd:', cwd)
            """,
        )

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--policy", policy_path, script_path])
        assert result.exit_code == 0, result.output
        assert "cwd:" in result.output


# ---------------------------------------------------------------------------
# CLI: show-policy command
# ---------------------------------------------------------------------------


class TestShowPolicyCommand:
    """Tests for the 'agent_fence show-policy' command."""

    def test_show_policy_with_file(self, tmp_path: Any) -> None:
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)

        runner = CliRunner()
        result = runner.invoke(main, ["show-policy", policy_path])
        assert result.exit_code == 0, result.output

    def test_show_policy_output_is_json(self, tmp_path: Any) -> None:
        """Output should be valid JSON."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)

        runner = CliRunner()
        result = runner.invoke(main, ["show-policy", policy_path])
        assert result.exit_code == 0, result.output

        # Output should be parseable JSON
        data = json.loads(result.output)
        assert isinstance(data, dict)
        assert data["name"] == "test-policy"

    def test_show_policy_without_file_uses_defaults(self) -> None:
        """Without a file, default policy is displayed."""
        runner = CliRunner()
        result = runner.invoke(main, ["show-policy"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "name" in data
        assert "enforcement_mode" in data

    def test_show_policy_nonexistent_file_exits_nonzero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["show-policy", "/nonexistent/policy.yaml"])
        assert result.exit_code != 0

    def test_show_policy_contains_all_sections(self, tmp_path: Any) -> None:
        """Output should include all major policy sections."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)

        runner = CliRunner()
        result = runner.invoke(main, ["show-policy", policy_path])
        data = json.loads(result.output)

        assert "filesystem" in data
        assert "network" in data
        assert "subprocess" in data
        assert "env" in data
        assert "audit_log" in data


# ---------------------------------------------------------------------------
# CLI: --log override
# ---------------------------------------------------------------------------


class TestRunLogOverride:
    """Tests for the --log flag."""

    def test_log_stdout_flag(self, tmp_path: Any) -> None:
        """--log - should write audit log to stdout without crashing."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        script_path = write_script(
            tmp_path,
            """
            import os
            os.getcwd()
            """,
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "--policy", policy_path, "--log", "-", script_path],
        )
        assert result.exit_code == 0, result.output

    def test_log_file_override(self, tmp_path: Any) -> None:
        """--log <path> should write audit entries to the specified file."""
        policy_path = write_policy(tmp_path, MINIMAL_POLICY)
        log_path = str(tmp_path / "custom_audit.jsonl")
        script_path = write_script(
            tmp_path,
            """
            import os
            os.getcwd()
            """,
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", "--policy", policy_path, "--log", log_path, script_path],
        )
        assert result.exit_code == 0, result.output
        assert os.path.exists(log_path), "Audit log file should have been created"

        with open(log_path, encoding="utf-8") as fh:
            lines = [line.strip() for line in fh if line.strip()]
        assert len(lines) >= 1
        entry = json.loads(lines[0])
        assert "action" in entry
        assert "decision" in entry
