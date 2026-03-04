"""Structured JSON audit logger for AgentFence.

This module provides the ``AuditLogger`` class that records every intercepted
agent action as a JSON Lines entry.  Each entry captures the timestamp,
policy name, action category, operation name, arguments, enforcement decision,
reason, and optionally the caller's stack frame.

Typical usage
-------------
::

    from agent_fence.audit_log import AuditLogger
    from agent_fence.policy import Policy

    policy = Policy()
    logger = AuditLogger(policy)
    logger.open()

    logger.log(
        action="network",
        operation="requests.get",
        args=("https://api.openai.com",),
        kwargs={},
        decision="allow",
        reason="domain in whitelist",
    )

    logger.close()

The logger can also be used as a context manager::

    with AuditLogger(policy) as log:
        log.log(action="filesystem", operation="os.remove",
                args=("/etc/passwd",), kwargs={},
                decision="block", reason="operation in blocked_operations")
"""

from __future__ import annotations

import inspect
import io
import json
import logging
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, IO, List, Optional, Tuple

from agent_fence.policy import Policy

# ---------------------------------------------------------------------------
# Module-level stdlib logger (separate from the audit trail)
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Log-level mapping
# ---------------------------------------------------------------------------

_LEVEL_MAP: Dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

_DECISION_TO_LEVEL: Dict[str, str] = {
    "allow": "info",
    "block": "warning",
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _safe_serialise(obj: Any) -> Any:
    """Attempt to make *obj* JSON-serialisable.

    Tuples become lists; arbitrary objects become their ``repr`` string.
    This ensures the JSON serialiser never raises ``TypeError`` on unusual
    argument types passed through intercepted callables.
    """
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    if isinstance(obj, dict):
        return {str(k): _safe_serialise(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe_serialise(item) for item in obj]
    # Fallback: repr
    try:
        return repr(obj)
    except Exception:  # noqa: BLE001
        return "<unserializable>"


def _get_caller_frame(depth: int = 5) -> Optional[Dict[str, Any]]:
    """Walk the call stack to find the outermost non-AgentFence frame.

    Parameters
    ----------
    depth:
        Maximum number of frames to examine.

    Returns
    -------
    dict or None
        A mapping with ``filename``, ``lineno``, and ``function`` keys,
        or ``None`` if no suitable frame is found.
    """
    try:
        stack = inspect.stack()
        pkg_prefix = "agent_fence"
        for frame_info in stack[2:2 + depth]:
            filename: str = frame_info.filename or ""
            # Skip frames that belong to the agent_fence package itself.
            if pkg_prefix in filename.replace("\\", "/"):
                continue
            return {
                "filename": filename,
                "lineno": frame_info.lineno,
                "function": frame_info.function,
            }
        # If all frames belong to agent_fence, return the innermost one
        # outside this file.
        if len(stack) > 2:
            frame_info = stack[2]
            return {
                "filename": frame_info.filename or "",
                "lineno": frame_info.lineno,
                "function": frame_info.function,
            }
    except Exception:  # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


class AuditLogger:
    """Structured JSON Lines audit logger for AgentFence interceptors.

    Records every intercepted action as a single JSON object per line to
    the configured output destination (file path or stdout).

    Parameters
    ----------
    policy:
        The active ``Policy`` instance.  The ``audit_log`` sub-policy
        controls logging behaviour.

    Attributes
    ----------
    policy:
        Reference to the active policy.
    enabled:
        Whether the logger is active (mirrors ``policy.audit_log.enabled``).

    Examples
    --------
    File-based::

        with AuditLogger(policy) as logger:
            logger.log(action="network", operation="requests.get",
                       args=("https://example.com",), kwargs={},
                       decision="allow", reason="domain whitelisted")

    In-memory (for testing)::

        buf = io.StringIO()
        logger = AuditLogger(policy, stream=buf)
        logger.open()
        logger.log(action="env", operation="os.getenv",
                   args=("SECRET",), kwargs={},
                   decision="block", reason="var in blocklist")
        logger.close()
        buf.seek(0)
        entry = json.loads(buf.readline())
    """

    def __init__(
        self,
        policy: Policy,
        stream: Optional[IO[str]] = None,
    ) -> None:
        """Initialise the AuditLogger.

        Parameters
        ----------
        policy:
            The active policy whose ``audit_log`` section is used.
        stream:
            Optional pre-opened text stream.  When provided, no file is
            opened or closed by ``open()`` / ``close()``.  Useful for
            testing or when the caller manages the stream lifetime.
        """
        self.policy = policy
        self._stream = stream
        self._owned_stream: bool = False
        self._min_level: int = _LEVEL_MAP.get(
            policy.audit_log.level, logging.INFO
        )
        self.enabled: bool = policy.audit_log.enabled

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> "AuditLogger":
        """Open the audit log output destination.

        If a *stream* was supplied at construction time, this is a no-op.
        Otherwise the configured path is opened for appending.  Use
        ``"-"`` as the path to write to stdout.

        Returns
        -------
        AuditLogger
            *self*, so ``open()`` can be chained.

        Raises
        ------
        OSError
            If the log file cannot be opened.
        """
        if self._stream is not None:
            # Stream supplied externally; we don't own it.
            return self
        if not self.enabled:
            return self

        path = self.policy.audit_log.path
        if path == "-":
            self._stream = sys.stdout
            self._owned_stream = False
        else:
            try:
                self._stream = open(path, "a", encoding="utf-8")  # noqa: WPS515
                self._owned_stream = True
            except OSError as exc:
                _log.error("AuditLogger: failed to open log file %r: %s", path, exc)
                raise
        return self

    def close(self) -> None:
        """Close the audit log output destination.

        Only closes the stream if it was opened by ``open()`` (i.e. not
        an externally-supplied stream or stdout).
        """
        if self._owned_stream and self._stream is not None:
            try:
                self._stream.flush()
                self._stream.close()
            except OSError as exc:  # pragma: no cover
                _log.warning("AuditLogger: error closing log stream: %s", exc)
            finally:
                self._stream = None
                self._owned_stream = False

    def __enter__(self) -> "AuditLogger":
        """Enter the context manager, opening the log destination."""
        return self.open()

    def __exit__(
        self,
        exc_type: Any,
        exc_val: Any,
        exc_tb: Any,
    ) -> None:
        """Exit the context manager, closing the log destination."""
        self.close()

    # ------------------------------------------------------------------
    # Core logging method
    # ------------------------------------------------------------------

    def log(
        self,
        action: str,
        operation: str,
        args: Tuple[Any, ...],
        kwargs: Dict[str, Any],
        decision: str,
        reason: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write a single audit log entry.

        Parameters
        ----------
        action:
            High-level action category (``"filesystem"``, ``"network"``,
            ``"subprocess"``, ``"env"``).
        operation:
            Fully-qualified name of the intercepted callable
            (e.g. ``"requests.get"``).
        args:
            Positional arguments passed to the intercepted call.
        kwargs:
            Keyword arguments passed to the intercepted call.
        decision:
            ``"allow"`` if the call was permitted, ``"block"`` if it was
            denied.
        reason:
            Human-readable explanation of the enforcement decision.
        extra:
            Optional additional fields to merge into the log entry.

        Notes
        -----
        If the logger is disabled or the entry's level is below the
        configured minimum, the call is silently ignored.
        """
        if not self.enabled:
            return

        # Determine the effective log level for this entry.
        entry_level_name = _DECISION_TO_LEVEL.get(decision, "info")
        entry_level = _LEVEL_MAP.get(entry_level_name, logging.INFO)
        if entry_level < self._min_level:
            return

        entry: Dict[str, Any] = {
            "timestamp": _utc_now_iso(),
            "policy": self.policy.name,
            "action": action,
            "operation": operation,
            "args": _safe_serialise(args),
            "kwargs": _safe_serialise(kwargs),
            "decision": decision,
            "reason": reason,
        }

        if self.policy.audit_log.include_stack_frame:
            entry["stack_frame"] = _get_caller_frame()

        if extra:
            entry.update(extra)

        self._write_entry(entry)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_entry(self, entry: Dict[str, Any]) -> None:
        """Serialise *entry* to JSON and write it to the output stream."""
        if self._stream is None:
            # Log destination is not open; emit a warning and skip.
            _log.warning(
                "AuditLogger: attempted to write entry but stream is not open. "
                "Call open() first."
            )
            return
        try:
            line = json.dumps(entry, default=str, ensure_ascii=False)
            self._stream.write(line + "\n")
            self._stream.flush()
        except (OSError, ValueError) as exc:  # pragma: no cover
            _log.error("AuditLogger: failed to write audit entry: %s", exc)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def log_allow(
        self,
        action: str,
        operation: str,
        args: Tuple[Any, ...],
        kwargs: Dict[str, Any],
        reason: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Shorthand for ``log(..., decision='allow', ...)``."""
        self.log(
            action=action,
            operation=operation,
            args=args,
            kwargs=kwargs,
            decision="allow",
            reason=reason,
            extra=extra,
        )

    def log_block(
        self,
        action: str,
        operation: str,
        args: Tuple[Any, ...],
        kwargs: Dict[str, Any],
        reason: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Shorthand for ``log(..., decision='block', ...)``."""
        self.log(
            action=action,
            operation=operation,
            args=args,
            kwargs=kwargs,
            decision="block",
            reason=reason,
            extra=extra,
        )
