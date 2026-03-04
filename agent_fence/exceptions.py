"""Custom exceptions for the AgentFence sandboxing library.

These exceptions are raised when the active policy blocks an agent action
or when a configured rate limit is exceeded.  Both inherit from a common
base class so callers can catch either specifically or generically.
"""

from __future__ import annotations

from typing import Any, Optional


class AgentFenceError(Exception):
    """Base exception for all AgentFence errors.

    All library-specific exceptions derive from this class so that
    downstream code can catch any AgentFence error with a single
    ``except AgentFenceError`` clause if desired.
    """


class PolicyViolation(AgentFenceError):
    """Raised when an agent attempts an action that the active policy blocks.

    Attributes
    ----------
    action : str
        The category of the blocked action (e.g. ``"filesystem"``,
        ``"network"``, ``"subprocess"``, ``"env"``).
    operation : str
        The specific operation that was blocked (e.g. ``"os.remove"``,
        ``"requests.get"``).
    args : tuple
        Positional arguments that were passed to the blocked call.
    kwargs : dict
        Keyword arguments that were passed to the blocked call.
    detail : str or None
        Optional human-readable explanation of why the action was blocked.

    Example
    -------
    ::

        try:
            with Sandbox(policy):
                os.remove("/etc/passwd")
        except PolicyViolation as exc:
            print(f"Blocked: {exc.operation} – {exc.detail}")
    """

    def __init__(
        self,
        action: str,
        operation: str,
        args: tuple[Any, ...] = (),
        kwargs: Optional[dict[str, Any]] = None,
        detail: Optional[str] = None,
    ) -> None:
        """Initialise a PolicyViolation.

        Parameters
        ----------
        action:
            High-level action category (``"filesystem"``, ``"network"``,
            ``"subprocess"``, or ``"env"``).
        operation:
            Fully-qualified name of the blocked callable
            (e.g. ``"os.remove"``).
        args:
            Positional arguments supplied to the blocked callable.
        kwargs:
            Keyword arguments supplied to the blocked callable.
        detail:
            Optional human-readable explanation appended to the exception
            message.
        """
        self.action = action
        self.operation = operation
        self.args = args
        self.kwargs = kwargs if kwargs is not None else {}
        self.detail = detail

        parts = [f"Policy violation: '{operation}' is not permitted"]
        if detail:
            parts.append(f" – {detail}")
        super().__init__("".join(parts))

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"PolicyViolation(action={self.action!r}, "
            f"operation={self.operation!r}, "
            f"detail={self.detail!r})"
        )


class RateLimitExceeded(AgentFenceError):
    """Raised when an agent exceeds the configured call-rate for an action category.

    Attributes
    ----------
    action : str
        The action category whose rate limit was exceeded.
    operation : str
        The specific operation that triggered the rate-limit check.
    limit : int or float
        The configured maximum number of calls allowed in the time window.
    window_seconds : float
        The length of the rate-limiting window in seconds.
    detail : str or None
        Optional human-readable explanation.

    Example
    -------
    ::

        try:
            with Sandbox(policy):
                for _ in range(1000):
                    requests.get("https://api.example.com")
        except RateLimitExceeded as exc:
            print(f"Rate limit hit for {exc.action}: {exc.limit} calls/{exc.window_seconds}s")
    """

    def __init__(
        self,
        action: str,
        operation: str,
        limit: float,
        window_seconds: float,
        detail: Optional[str] = None,
    ) -> None:
        """Initialise a RateLimitExceeded exception.

        Parameters
        ----------
        action:
            High-level action category (``"filesystem"``, ``"network"``,
            ``"subprocess"``, or ``"env"``).
        operation:
            Fully-qualified name of the rate-limited callable.
        limit:
            Configured maximum number of calls in the time window.
        window_seconds:
            Duration of the rate-limiting window in seconds.
        detail:
            Optional human-readable explanation appended to the message.
        """
        self.action = action
        self.operation = operation
        self.limit = limit
        self.window_seconds = window_seconds
        self.detail = detail

        msg = (
            f"Rate limit exceeded for '{operation}' "
            f"(category: '{action}'): "
            f"max {limit} calls per {window_seconds}s"
        )
        if detail:
            msg += f" – {detail}"
        super().__init__(msg)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"RateLimitExceeded(action={self.action!r}, "
            f"operation={self.operation!r}, "
            f"limit={self.limit!r}, "
            f"window_seconds={self.window_seconds!r})"
        )
