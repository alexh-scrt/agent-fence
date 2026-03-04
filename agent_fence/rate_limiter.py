"""Token-bucket rate limiter for AgentFence action categories.

This module implements a thread-safe token-bucket algorithm that enforces
per-category call-frequency limits defined in a ``Policy``.  When the bucket
for a given category is empty the ``RateLimiter.check`` method raises
``RateLimitExceeded``.

Token-bucket algorithm
----------------------
The bucket for each category holds up to ``calls`` tokens.  Tokens are
replenished continuously at a rate of ``calls / window_seconds`` tokens
per second.  Each intercepted call consumes one token.  If no token is
available the call is rejected.

Typical usage
-------------
::

    from agent_fence.rate_limiter import RateLimiter
    from agent_fence.policy import Policy

    policy = Policy()
    limiter = RateLimiter(policy)

    # Inside an interceptor:
    limiter.check(action="network", operation="requests.get")
    # Raises RateLimitExceeded if the network bucket is exhausted.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from agent_fence.exceptions import RateLimitExceeded
from agent_fence.policy import Policy, RateLimitConfig

# ---------------------------------------------------------------------------
# Internal bucket state
# ---------------------------------------------------------------------------


@dataclass
class _BucketState:
    """Mutable state for a single token-bucket.

    Attributes
    ----------
    capacity:
        Maximum number of tokens the bucket can hold (== ``calls`` from config).
    tokens:
        Current number of available tokens (float for sub-second precision).
    refill_rate:
        Tokens added per second (``capacity / window_seconds``).
    last_refill:
        Monotonic timestamp of the last refill calculation.
    lock:
        Per-bucket lock for thread safety.
    """

    capacity: float
    tokens: float
    refill_rate: float  # tokens per second
    last_refill: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def refill(self, now: float) -> None:
        """Add tokens proportional to elapsed time since last refill.

        Parameters
        ----------
        now:
            Current monotonic time in seconds.
        """
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.refill_rate,
            )
            self.last_refill = now

    def consume(self) -> bool:
        """Attempt to consume one token.

        Returns
        -------
        bool
            ``True`` if a token was successfully consumed; ``False`` if the
            bucket was empty.
        """
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe token-bucket rate limiter for AgentFence action categories.

    One bucket is maintained per action category that has a ``rate_limit``
    configured in the policy.  Categories without a rate-limit config are
    never throttled.

    Parameters
    ----------
    policy:
        The active ``Policy`` instance.  Rate limits are read from
        ``policy.network.rate_limit``, ``policy.subprocess.rate_limit``,
        and optionally ``policy.filesystem`` / ``policy.env`` if they ever
        gain rate-limit support.

    Examples
    --------
    ::

        from agent_fence.policy import Policy
        from agent_fence.rate_limiter import RateLimiter

        policy = Policy()
        limiter = RateLimiter(policy)

        for i in range(61):
            try:
                limiter.check("network", "requests.get")
            except RateLimitExceeded:
                print(f"Blocked on call {i}")
                break
    """

    # Mapping from action category name to the attribute on Policy that
    # holds the RateLimitConfig (or None if not applicable).
    _CATEGORY_RATE_LIMIT_ATTRS: Dict[str, str] = {
        "network": "rate_limit",
        "subprocess": "rate_limit",
    }

    def __init__(self, policy: Policy) -> None:
        """Initialise the RateLimiter.

        Parameters
        ----------
        policy:
            The active policy whose per-category rate limits are used.
        """
        self.policy = policy
        self._buckets: Dict[str, _BucketState] = {}
        self._global_lock = threading.Lock()
        self._initialise_buckets()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _initialise_buckets(self) -> None:
        """Create token buckets for all rate-limited categories."""
        category_configs: Dict[str, Optional[RateLimitConfig]] = {
            "network": getattr(self.policy.network, "rate_limit", None),
            "subprocess": getattr(self.policy.subprocess, "rate_limit", None),
        }
        for category, config in category_configs.items():
            if config is not None:
                self._buckets[category] = _make_bucket(config)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, action: str, operation: str) -> None:
        """Check whether *operation* is within the rate limit for *action*.

        If a rate limit is configured for *action* and the token bucket is
        exhausted, ``RateLimitExceeded`` is raised.  If no rate limit is
        configured for *action* the call is a no-op.

        Parameters
        ----------
        action:
            Action category to check (``"network"``, ``"subprocess"``,
            ``"filesystem"``, ``"env"``).
        operation:
            Fully-qualified name of the intercepted callable (used in the
            exception message).

        Raises
        ------
        RateLimitExceeded
            If the token bucket for *action* is empty.
        """
        bucket = self._buckets.get(action)
        if bucket is None:
            # No rate limit configured for this category.
            return

        now = time.monotonic()
        with bucket.lock:
            bucket.refill(now)
            allowed = bucket.consume()

        if not allowed:
            config = self._get_config_for(action)
            raise RateLimitExceeded(
                action=action,
                operation=operation,
                limit=config.calls if config else 0,
                window_seconds=config.window_seconds if config else 0.0,
                detail="token bucket exhausted",
            )

    def reset(self, action: Optional[str] = None) -> None:
        """Refill token bucket(s) to maximum capacity.

        Useful between test cases or to manually reset limits.

        Parameters
        ----------
        action:
            Specific category to reset.  If ``None`` all buckets are reset.
        """
        if action is not None:
            bucket = self._buckets.get(action)
            if bucket is not None:
                with bucket.lock:
                    bucket.tokens = bucket.capacity
                    bucket.last_refill = time.monotonic()
        else:
            for bkt in self._buckets.values():
                with bkt.lock:
                    bkt.tokens = bkt.capacity
                    bkt.last_refill = time.monotonic()

    def available_tokens(self, action: str) -> float:
        """Return the current token count for *action* (after refill).

        Parameters
        ----------
        action:
            The action category to query.

        Returns
        -------
        float
            Current number of available tokens, or ``float('inf')`` if no
            rate limit is configured for *action*.
        """
        bucket = self._buckets.get(action)
        if bucket is None:
            return float("inf")
        now = time.monotonic()
        with bucket.lock:
            bucket.refill(now)
            return bucket.tokens

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_config_for(self, action: str) -> Optional[RateLimitConfig]:
        """Return the ``RateLimitConfig`` for *action*, or ``None``."""
        sub_policy_map = {
            "network": self.policy.network,
            "subprocess": self.policy.subprocess,
        }
        sub = sub_policy_map.get(action)
        if sub is None:
            return None
        return getattr(sub, "rate_limit", None)


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _make_bucket(config: RateLimitConfig) -> _BucketState:
    """Create a fully-charged ``_BucketState`` from a ``RateLimitConfig``.

    Parameters
    ----------
    config:
        Rate-limit configuration specifying capacity and window.

    Returns
    -------
    _BucketState
        A new bucket with ``tokens == capacity``.
    """
    capacity = float(config.calls)
    refill_rate = capacity / config.window_seconds
    return _BucketState(
        capacity=capacity,
        tokens=capacity,
        refill_rate=refill_rate,
        last_refill=time.monotonic(),
    )
