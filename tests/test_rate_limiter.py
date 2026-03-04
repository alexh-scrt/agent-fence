"""Unit tests for agent_fence.rate_limiter module.

Covers:
- Token-bucket initialisation from policy
- Normal (within-limit) calls pass through
- Calls exceeding the limit raise RateLimitExceeded
- Bucket refill over time
- Burst behaviour (capacity == calls)
- Reset functionality
- Categories without rate limits are never throttled
- available_tokens query
- Thread safety (basic)
"""

from __future__ import annotations

import threading
import time
from typing import List
from unittest.mock import patch

import pytest

from agent_fence.exceptions import RateLimitExceeded
from agent_fence.policy import Policy, policy_from_dict
from agent_fence.rate_limiter import RateLimiter, _BucketState, _make_bucket


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_limiter(**overrides) -> RateLimiter:
    """Return a RateLimiter built from a policy with *overrides* applied."""
    return RateLimiter(policy_from_dict(overrides))


def limiter_with_network_limit(calls: int, window_seconds: float) -> RateLimiter:
    """Return a RateLimiter with a specific network rate limit."""
    policy = policy_from_dict({
        "network": {
            "rate_limit": {"calls": calls, "window_seconds": window_seconds}
        }
    })
    return RateLimiter(policy)


def limiter_with_subprocess_limit(calls: int, window_seconds: float) -> RateLimiter:
    """Return a RateLimiter with a specific subprocess rate limit."""
    policy = policy_from_dict({
        "subprocess": {
            "rate_limit": {"calls": calls, "window_seconds": window_seconds}
        }
    })
    return RateLimiter(policy)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestRateLimiterInit:
    """Tests for RateLimiter construction and bucket initialisation."""

    def test_creates_network_bucket(self) -> None:
        limiter = limiter_with_network_limit(10, 60)
        assert "network" in limiter._buckets

    def test_creates_subprocess_bucket(self) -> None:
        limiter = limiter_with_subprocess_limit(5, 60)
        assert "subprocess" in limiter._buckets

    def test_network_bucket_capacity(self) -> None:
        limiter = limiter_with_network_limit(20, 60)
        assert limiter._buckets["network"].capacity == 20.0

    def test_network_bucket_starts_full(self) -> None:
        limiter = limiter_with_network_limit(10, 60)
        bucket = limiter._buckets["network"]
        assert bucket.tokens == bucket.capacity

    def test_network_bucket_refill_rate(self) -> None:
        """refill_rate == calls / window_seconds."""
        limiter = limiter_with_network_limit(60, 60)
        bucket = limiter._buckets["network"]
        assert abs(bucket.refill_rate - 1.0) < 1e-9

    def test_accepts_policy_object_directly(self) -> None:
        policy = Policy()  # Default policy
        limiter = RateLimiter(policy)
        # Default policy has network.rate_limit.calls == 60
        assert "network" in limiter._buckets


# ---------------------------------------------------------------------------
# Within-limit calls pass through
# ---------------------------------------------------------------------------


class TestRateLimiterAllowed:
    """Tests that calls within the rate limit are permitted."""

    def test_single_call_within_limit(self) -> None:
        limiter = limiter_with_network_limit(5, 60)
        # Should not raise
        limiter.check("network", "requests.get")

    def test_all_tokens_consumed_without_exception(self) -> None:
        calls = 5
        limiter = limiter_with_network_limit(calls, 60)
        for _ in range(calls):
            limiter.check("network", "requests.get")  # should not raise

    def test_subprocess_within_limit(self) -> None:
        limiter = limiter_with_subprocess_limit(3, 60)
        for _ in range(3):
            limiter.check("subprocess", "subprocess.run")

    def test_unconfigured_category_never_throttled(self) -> None:
        """filesystem and env have no rate limit; should never raise."""
        limiter = RateLimiter(Policy())
        # Call thousands of times; no exception expected.
        for _ in range(1000):
            limiter.check("filesystem", "os.remove")
            limiter.check("env", "os.getenv")


# ---------------------------------------------------------------------------
# Exceeding the limit raises RateLimitExceeded
# ---------------------------------------------------------------------------


class TestRateLimiterExceeded:
    """Tests that exhausting the bucket raises RateLimitExceeded."""

    def test_exceeding_network_limit_raises(self) -> None:
        limiter = limiter_with_network_limit(3, 60)
        for _ in range(3):
            limiter.check("network", "requests.get")

        with pytest.raises(RateLimitExceeded):
            limiter.check("network", "requests.get")

    def test_exception_has_correct_action(self) -> None:
        limiter = limiter_with_network_limit(1, 60)
        limiter.check("network", "requests.get")

        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check("network", "requests.get")

        assert exc_info.value.action == "network"

    def test_exception_has_correct_operation(self) -> None:
        limiter = limiter_with_network_limit(1, 60)
        limiter.check("network", "requests.post")

        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check("network", "requests.post")

        assert exc_info.value.operation == "requests.post"

    def test_exception_has_correct_limit(self) -> None:
        limiter = limiter_with_network_limit(2, 60)
        for _ in range(2):
            limiter.check("network", "requests.get")

        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check("network", "requests.get")

        assert exc_info.value.limit == 2

    def test_exception_has_correct_window(self) -> None:
        limiter = limiter_with_network_limit(1, 30)
        limiter.check("network", "requests.get")

        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check("network", "requests.get")

        assert exc_info.value.window_seconds == 30.0

    def test_exception_is_agent_fence_error(self) -> None:
        from agent_fence.exceptions import AgentFenceError
        limiter = limiter_with_network_limit(1, 60)
        limiter.check("network", "requests.get")

        with pytest.raises(AgentFenceError):
            limiter.check("network", "requests.get")

    def test_subprocess_exceeding_limit_raises(self) -> None:
        limiter = limiter_with_subprocess_limit(2, 60)
        limiter.check("subprocess", "subprocess.run")
        limiter.check("subprocess", "subprocess.run")

        with pytest.raises(RateLimitExceeded):
            limiter.check("subprocess", "subprocess.run")

    def test_one_over_limit_raises(self) -> None:
        """Exactly one call over the limit raises."""
        calls = 10
        limiter = limiter_with_network_limit(calls, 600)
        for _ in range(calls):
            limiter.check("network", "requests.get")

        with pytest.raises(RateLimitExceeded):
            limiter.check("network", "requests.get")

    def test_blocked_category_does_not_affect_other_category(self) -> None:
        """Exhausting the network bucket does not affect subprocess."""
        policy = policy_from_dict({
            "network": {"rate_limit": {"calls": 1, "window_seconds": 60}},
            "subprocess": {"rate_limit": {"calls": 5, "window_seconds": 60}},
        })
        limiter = RateLimiter(policy)
        limiter.check("network", "requests.get")

        with pytest.raises(RateLimitExceeded):
            limiter.check("network", "requests.get")

        # subprocess should still work
        limiter.check("subprocess", "subprocess.run")


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


class TestRateLimiterReset:
    """Tests for the reset() method."""

    def test_reset_specific_category_refills_bucket(self) -> None:
        limiter = limiter_with_network_limit(2, 60)
        limiter.check("network", "requests.get")
        limiter.check("network", "requests.get")

        # Bucket exhausted; reset it.
        limiter.reset("network")

        # Should now work again
        limiter.check("network", "requests.get")

    def test_reset_all_categories(self) -> None:
        policy = policy_from_dict({
            "network": {"rate_limit": {"calls": 1, "window_seconds": 60}},
            "subprocess": {"rate_limit": {"calls": 1, "window_seconds": 60}},
        })
        limiter = RateLimiter(policy)
        limiter.check("network", "requests.get")
        limiter.check("subprocess", "subprocess.run")

        limiter.reset()  # Reset all

        limiter.check("network", "requests.get")
        limiter.check("subprocess", "subprocess.run")

    def test_reset_nonexistent_category_does_not_raise(self) -> None:
        limiter = RateLimiter(Policy())
        limiter.reset("filesystem")  # No bucket; should be silent

    def test_reset_restores_full_capacity(self) -> None:
        calls = 5
        limiter = limiter_with_network_limit(calls, 60)
        # Drain entirely
        for _ in range(calls):
            limiter.check("network", "requests.get")

        limiter.reset("network")
        assert limiter.available_tokens("network") == float(calls)


# ---------------------------------------------------------------------------
# available_tokens
# ---------------------------------------------------------------------------


class TestAvailableTokens:
    """Tests for the available_tokens() query method."""

    def test_full_bucket_returns_capacity(self) -> None:
        limiter = limiter_with_network_limit(10, 60)
        assert limiter.available_tokens("network") == 10.0

    def test_tokens_decrease_after_check(self) -> None:
        limiter = limiter_with_network_limit(10, 60)
        limiter.check("network", "requests.get")
        assert limiter.available_tokens("network") == 9.0

    def test_tokens_reach_zero(self) -> None:
        calls = 3
        limiter = limiter_with_network_limit(calls, 60)
        for _ in range(calls):
            limiter.check("network", "requests.get")
        tokens = limiter.available_tokens("network")
        assert tokens < 1.0

    def test_unconfigured_category_returns_infinity(self) -> None:
        limiter = RateLimiter(Policy())
        assert limiter.available_tokens("filesystem") == float("inf")
        assert limiter.available_tokens("env") == float("inf")


# ---------------------------------------------------------------------------
# Token refill over time
# ---------------------------------------------------------------------------


class TestRateLimiterRefill:
    """Tests that tokens are replenished as time passes."""

    def test_tokens_refilled_after_time_passes(self) -> None:
        """Use a mocked monotonic clock to test refill without sleeping."""
        limiter = limiter_with_network_limit(10, 10)  # 1 token/second
        # Drain 5 tokens
        for _ in range(5):
            limiter.check("network", "requests.get")

        bucket = limiter._buckets["network"]
        original_last_refill = bucket.last_refill

        # Simulate 5 seconds passing by manipulating last_refill
        bucket.last_refill = original_last_refill - 5.0

        # Now available_tokens should have refilled ~5 tokens
        tokens = limiter.available_tokens("network")
        # After draining 5 and waiting 5s at 1 token/s, expect ~10 tokens
        assert tokens >= 9.0  # Allow small floating-point tolerance

    def test_tokens_do_not_exceed_capacity_during_refill(self) -> None:
        """Tokens must be capped at capacity even after a long wait."""
        limiter = limiter_with_network_limit(5, 1)  # 5 tokens/second
        bucket = limiter._buckets["network"]

        # Drain the bucket
        for _ in range(5):
            limiter.check("network", "requests.get")

        # Simulate 1000 seconds of waiting
        bucket.last_refill -= 1000.0

        tokens = limiter.available_tokens("network")
        assert tokens == 5.0  # Capped at capacity

    def test_refill_allows_calls_after_wait(self) -> None:
        """After sufficient refill time, previously-blocked calls succeed."""
        limiter = limiter_with_network_limit(1, 1)  # 1 token per second
        limiter.check("network", "requests.get")  # Consume the only token

        bucket = limiter._buckets["network"]
        # Simulate 1.5 seconds passing
        bucket.last_refill -= 1.5

        # Should succeed now
        limiter.check("network", "requests.get")


# ---------------------------------------------------------------------------
# _BucketState unit tests
# ---------------------------------------------------------------------------


class TestBucketState:
    """Low-level tests for _BucketState behaviour."""

    def test_initial_tokens_equal_capacity(self) -> None:
        from agent_fence.policy import RateLimitConfig
        config = RateLimitConfig(calls=10, window_seconds=60)
        bucket = _make_bucket(config)
        assert bucket.tokens == bucket.capacity == 10.0

    def test_consume_reduces_tokens(self) -> None:
        from agent_fence.policy import RateLimitConfig
        bucket = _make_bucket(RateLimitConfig(calls=5, window_seconds=60))
        result = bucket.consume()
        assert result is True
        assert bucket.tokens == 4.0

    def test_consume_returns_false_when_empty(self) -> None:
        from agent_fence.policy import RateLimitConfig
        bucket = _make_bucket(RateLimitConfig(calls=1, window_seconds=60))
        assert bucket.consume() is True
        assert bucket.consume() is False

    def test_refill_adds_tokens(self) -> None:
        from agent_fence.policy import RateLimitConfig
        bucket = _make_bucket(RateLimitConfig(calls=10, window_seconds=10))
        # Drain 5 tokens
        for _ in range(5):
            bucket.consume()
        assert bucket.tokens == 5.0

        # Simulate 5 seconds: refill_rate = 10/10 = 1 token/s -> +5 tokens
        future = bucket.last_refill + 5.0
        bucket.refill(future)
        assert bucket.tokens == 10.0  # Capped at capacity

    def test_refill_does_not_exceed_capacity(self) -> None:
        from agent_fence.policy import RateLimitConfig
        bucket = _make_bucket(RateLimitConfig(calls=5, window_seconds=1))
        future = bucket.last_refill + 1000.0
        bucket.refill(future)
        assert bucket.tokens == 5.0

    def test_refill_with_past_time_does_nothing(self) -> None:
        """Passing a time in the past should not reduce tokens."""
        from agent_fence.policy import RateLimitConfig
        bucket = _make_bucket(RateLimitConfig(calls=5, window_seconds=60))
        past = bucket.last_refill - 10.0
        bucket.refill(past)
        # elapsed < 0, so no change
        assert bucket.tokens == 5.0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestRateLimiterThreadSafety:
    """Basic thread-safety check for concurrent access."""

    def test_concurrent_checks_do_not_exceed_capacity(self) -> None:
        """Under concurrent load, total allowed calls must not exceed capacity."""
        calls_limit = 50
        limiter = limiter_with_network_limit(calls_limit, 3600)

        allowed: List[int] = []
        blocked: List[int] = []
        lock = threading.Lock()

        def worker() -> None:
            try:
                limiter.check("network", "requests.get")
                with lock:
                    allowed.append(1)
            except RateLimitExceeded:
                with lock:
                    blocked.append(1)

        threads = [threading.Thread(target=worker) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Allowed calls must never exceed the bucket capacity
        assert len(allowed) <= calls_limit
        assert len(allowed) + len(blocked) == 100
