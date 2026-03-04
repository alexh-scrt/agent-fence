"""Unit tests for agent_fence.exceptions module.

Verifies that PolicyViolation and RateLimitExceeded are constructed correctly,
have the expected attributes, and produce useful string representations.
"""

import pytest

from agent_fence.exceptions import (
    AgentFenceError,
    PolicyViolation,
    RateLimitExceeded,
)


class TestAgentFenceError:
    """Tests for the AgentFenceError base exception."""

    def test_is_exception(self) -> None:
        """AgentFenceError must be a subclass of Exception."""
        assert issubclass(AgentFenceError, Exception)

    def test_can_be_raised_and_caught(self) -> None:
        """AgentFenceError can be raised and caught generically."""
        with pytest.raises(AgentFenceError):
            raise AgentFenceError("base error")


class TestPolicyViolation:
    """Tests for PolicyViolation."""

    def test_is_agent_fence_error(self) -> None:
        """PolicyViolation must inherit from AgentFenceError."""
        assert issubclass(PolicyViolation, AgentFenceError)

    def test_basic_attributes(self) -> None:
        """Constructor stores action, operation, args, kwargs, detail."""
        exc = PolicyViolation(
            action="filesystem",
            operation="os.remove",
            args=("/etc/passwd",),
            kwargs={},
            detail="path not in write whitelist",
        )
        assert exc.action == "filesystem"
        assert exc.operation == "os.remove"
        assert exc.args == ("/etc/passwd",)
        assert exc.kwargs == {}
        assert exc.detail == "path not in write whitelist"

    def test_message_contains_operation(self) -> None:
        """String representation includes the operation name."""
        exc = PolicyViolation(action="network", operation="requests.get")
        assert "requests.get" in str(exc)

    def test_message_contains_detail_when_provided(self) -> None:
        """Detail string is appended to the exception message."""
        exc = PolicyViolation(
            action="subprocess",
            operation="subprocess.run",
            detail="command not in whitelist",
        )
        assert "command not in whitelist" in str(exc)

    def test_message_without_detail(self) -> None:
        """Message is still meaningful when no detail is supplied."""
        exc = PolicyViolation(action="env", operation="os.getenv")
        assert "os.getenv" in str(exc)
        assert exc.detail is None

    def test_defaults_for_args_and_kwargs(self) -> None:
        """args defaults to empty tuple; kwargs defaults to empty dict."""
        exc = PolicyViolation(action="filesystem", operation="shutil.rmtree")
        assert exc.args == ()
        assert exc.kwargs == {}

    def test_can_be_raised_and_caught_as_agent_fence_error(self) -> None:
        """PolicyViolation can be caught as AgentFenceError."""
        with pytest.raises(AgentFenceError):
            raise PolicyViolation(action="network", operation="requests.post")

    def test_can_be_raised_and_caught_specifically(self) -> None:
        """PolicyViolation can be caught by its own type."""
        with pytest.raises(PolicyViolation) as exc_info:
            raise PolicyViolation(
                action="filesystem",
                operation="os.unlink",
                args=("/tmp/test.txt",),
            )
        assert exc_info.value.operation == "os.unlink"


class TestRateLimitExceeded:
    """Tests for RateLimitExceeded."""

    def test_is_agent_fence_error(self) -> None:
        """RateLimitExceeded must inherit from AgentFenceError."""
        assert issubclass(RateLimitExceeded, AgentFenceError)

    def test_basic_attributes(self) -> None:
        """Constructor stores action, operation, limit, window_seconds, detail."""
        exc = RateLimitExceeded(
            action="network",
            operation="requests.get",
            limit=60.0,
            window_seconds=60.0,
            detail="burst cap reached",
        )
        assert exc.action == "network"
        assert exc.operation == "requests.get"
        assert exc.limit == 60.0
        assert exc.window_seconds == 60.0
        assert exc.detail == "burst cap reached"

    def test_message_contains_operation(self) -> None:
        """String representation includes the operation name."""
        exc = RateLimitExceeded(
            action="network",
            operation="urllib.request.urlopen",
            limit=10,
            window_seconds=30,
        )
        assert "urllib.request.urlopen" in str(exc)

    def test_message_contains_limit_and_window(self) -> None:
        """Message includes the limit and window values."""
        exc = RateLimitExceeded(
            action="subprocess",
            operation="subprocess.run",
            limit=5,
            window_seconds=60,
        )
        msg = str(exc)
        assert "5" in msg
        assert "60" in msg

    def test_message_contains_detail_when_provided(self) -> None:
        """Detail is appended when supplied."""
        exc = RateLimitExceeded(
            action="network",
            operation="requests.get",
            limit=10,
            window_seconds=60,
            detail="token bucket empty",
        )
        assert "token bucket empty" in str(exc)

    def test_no_detail_by_default(self) -> None:
        """detail is None when not provided."""
        exc = RateLimitExceeded(
            action="network",
            operation="requests.get",
            limit=10,
            window_seconds=60,
        )
        assert exc.detail is None

    def test_can_be_caught_as_agent_fence_error(self) -> None:
        """RateLimitExceeded can be caught as AgentFenceError."""
        with pytest.raises(AgentFenceError):
            raise RateLimitExceeded(
                action="network",
                operation="requests.get",
                limit=10,
                window_seconds=60,
            )

    def test_policy_violation_and_rate_limit_are_distinct(self) -> None:
        """The two exception types are not interchangeable."""
        rate_exc = RateLimitExceeded(
            action="network",
            operation="requests.get",
            limit=10,
            window_seconds=60,
        )
        assert not isinstance(rate_exc, PolicyViolation)

        policy_exc = PolicyViolation(action="network", operation="requests.get")
        assert not isinstance(policy_exc, RateLimitExceeded)
