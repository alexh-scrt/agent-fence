"""Core Sandbox context manager for AgentFence.

This module implements the ``Sandbox`` context manager that monkey-patches
stdlib functions (``os``, ``shutil``, ``subprocess``, ``urllib``, and
``requests``) according to the active policy, using interceptor functions
from ``agent_fence.interceptors``.

The sandbox is re-entrant: nesting ``Sandbox`` instances with different
policies is supported, though not recommended. Each ``Sandbox.__enter__``
installs its own set of patches and ``__exit__`` restores exactly the
originals it saved.

Typical usage
-------------
::

    from agent_fence import Sandbox, load_policy

    policy = load_policy("my_policy.yaml")
    with Sandbox(policy):
        import os
        os.remove("/tmp/file.txt")   # blocked or allowed per policy

Or with an audit-log stream override (useful in tests)::

    import io
    from agent_fence.sandbox import Sandbox
    from agent_fence.policy import Policy

    buf = io.StringIO()
    with Sandbox(Policy(), audit_stream=buf):
        ...
"""

from __future__ import annotations

import io
import logging
import os
import shutil
import subprocess
import sys
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from agent_fence.audit_log import AuditLogger
from agent_fence.interceptors import (
    make_env_read_interceptor,
    make_env_write_interceptor,
    make_filesystem_interceptor,
    make_network_interceptor,
    make_subprocess_interceptor,
)
from agent_fence.policy import Policy
from agent_fence.rate_limiter import RateLimiter

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patch descriptor
# ---------------------------------------------------------------------------


class _Patch:
    """Describes a single monkey-patch to apply and later restore.

    Attributes
    ----------
    target_module:
        The module object whose attribute will be patched.
    attr:
        Name of the attribute on *target_module*.
    replacement:
        The replacement callable to install.
    original:
        The original callable that will be restored on exit (populated
        during ``_apply``).
    """

    def __init__(
        self,
        target_module: Any,
        attr: str,
        replacement: Callable[..., Any],
    ) -> None:
        self.target_module = target_module
        self.attr = attr
        self.replacement = replacement
        self.original: Optional[Callable[..., Any]] = None

    def apply(self) -> None:
        """Install the replacement, saving the original."""
        self.original = getattr(self.target_module, self.attr, None)
        setattr(self.target_module, self.attr, self.replacement)

    def restore(self) -> None:
        """Restore the original callable."""
        if self.original is not None:
            setattr(self.target_module, self.attr, self.original)
        # If original was None the attribute didn't exist before; leave as-is.


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------


class Sandbox:
    """Context manager that enforces an AgentFence policy via monkey-patching.

    When entered, the sandbox:

    1. Opens an ``AuditLogger`` writing to the configured destination (or
       *audit_stream* if supplied).
    2. Creates a ``RateLimiter`` pre-loaded from the policy.
    3. Builds per-operation interceptors for all patched operations.
    4. Monkey-patches ``os``, ``shutil``, ``subprocess``, ``urllib.request``,
       and optionally ``requests`` (if installed).

    When exited (normally or via exception), all patches are reverted and the
    audit log is closed.

    Parameters
    ----------
    policy:
        The active ``Policy`` instance.  Use ``load_policy()`` to obtain one
        from a YAML file.
    audit_stream:
        Optional pre-opened ``IO[str]`` stream to receive audit log output.
        When provided, the ``audit_log.path`` in the policy is ignored.
        Primarily useful in tests.

    Examples
    --------
    Basic usage::

        from agent_fence import Sandbox, load_policy

        policy = load_policy("policy.yaml")
        with Sandbox(policy):
            import os
            os.remove("/tmp/safe.txt")   # subject to policy

    In-memory audit log for tests::

        import io
        from agent_fence.sandbox import Sandbox
        from agent_fence.policy import Policy

        buf = io.StringIO()
        policy = Policy()
        with Sandbox(policy, audit_stream=buf):
            ...
        buf.seek(0)
        for line in buf:
            print(line)
    """

    def __init__(
        self,
        policy: Policy,
        audit_stream: Optional[io.IOBase] = None,
    ) -> None:
        """Initialise the Sandbox.

        Parameters
        ----------
        policy:
            Policy to enforce.
        audit_stream:
            Optional stream for audit log output (overrides policy path).
        """
        self.policy = policy
        self._audit_stream = audit_stream
        self._audit_logger: Optional[AuditLogger] = None
        self._rate_limiter: Optional[RateLimiter] = None
        self._patches: List[_Patch] = []
        self._active = False

    # ------------------------------------------------------------------
    # Context-manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "Sandbox":
        """Activate the sandbox: open logger, build interceptors, apply patches.

        Returns
        -------
        Sandbox
            *self*, so the sandbox object can be bound in a ``with ... as``
            clause.

        Raises
        ------
        RuntimeError
            If the sandbox is already active (double-entry on the same
            instance).
        """
        if self._active:
            raise RuntimeError(
                "Sandbox is already active. Use a new Sandbox instance for nesting."
            )

        # --- Open audit logger ---
        self._audit_logger = AuditLogger(self.policy, stream=self._audit_stream)  # type: ignore[arg-type]
        self._audit_logger.open()

        # --- Create rate limiter ---
        self._rate_limiter = RateLimiter(self.policy)

        # --- Build and apply patches ---
        self._patches = self._build_patches()
        for patch in self._patches:
            try:
                patch.apply()
            except Exception as exc:  # pragma: no cover
                _log.warning(
                    "Sandbox: failed to apply patch %s.%s: %s",
                    getattr(patch.target_module, "__name__", repr(patch.target_module)),
                    patch.attr,
                    exc,
                )

        self._active = True
        _log.debug(
            "Sandbox activated with policy %r (%d patches applied)",
            self.policy.name,
            len(self._patches),
        )
        return self

    def __exit__(
        self,
        exc_type: Any,
        exc_val: Any,
        exc_tb: Any,
    ) -> None:
        """Deactivate the sandbox: restore all patches and close the audit log.

        This method is always called, even if an exception was raised inside
        the ``with`` block. The exception is propagated unchanged.
        """
        # Restore patches in reverse order
        for patch in reversed(self._patches):
            try:
                patch.restore()
            except Exception as exc:  # pragma: no cover
                _log.warning(
                    "Sandbox: failed to restore patch %s.%s: %s",
                    getattr(patch.target_module, "__name__", repr(patch.target_module)),
                    patch.attr,
                    exc,
                )

        self._patches = []

        # Close audit logger
        if self._audit_logger is not None:
            try:
                self._audit_logger.close()
            except Exception as exc:  # pragma: no cover
                _log.warning("Sandbox: error closing audit logger: %s", exc)
            self._audit_logger = None

        self._rate_limiter = None
        self._active = False
        _log.debug("Sandbox deactivated for policy %r", self.policy.name)

    # ------------------------------------------------------------------
    # Patch construction
    # ------------------------------------------------------------------

    def _build_patches(self) -> List[_Patch]:
        """Build the complete list of patches to apply.

        Returns
        -------
        list of _Patch
            All patches for filesystem, network, subprocess, and env
            operations that are currently enabled in the policy.
        """
        assert self._audit_logger is not None
        assert self._rate_limiter is not None

        patches: List[_Patch] = []

        patches.extend(self._filesystem_patches())
        patches.extend(self._subprocess_patches())
        patches.extend(self._env_patches())
        patches.extend(self._network_patches())

        return patches

    # ------------------------------------------------------------------
    # Filesystem patches
    # ------------------------------------------------------------------

    def _filesystem_patches(self) -> List[_Patch]:
        """Build patches for filesystem operations."""
        if not self.policy.filesystem.enabled:
            return []

        assert self._audit_logger is not None
        assert self._rate_limiter is not None

        al = self._audit_logger
        rl = self._rate_limiter
        policy = self.policy

        def _make_fs(op: str, module: Any, attr: str, access: str = "write") -> _Patch:
            original = getattr(module, attr)
            interceptor = make_filesystem_interceptor(
                policy=policy,
                audit_logger=al,
                rate_limiter=rl,
                operation=op,
                original_fn=original,
                access_type=access,
            )
            return _Patch(module, attr, interceptor)

        result: List[_Patch] = [
            # Write/mutating operations
            _make_fs("os.remove", os, "remove", "write"),
            _make_fs("os.unlink", os, "unlink", "write"),
            _make_fs("os.rmdir", os, "rmdir", "write"),
            _make_fs("os.makedirs", os, "makedirs", "write"),
            _make_fs("os.mkdir", os, "mkdir", "write"),
            _make_fs("os.rename", os, "rename", "write"),
            _make_fs("os.replace", os, "replace", "write"),
            _make_fs("shutil.rmtree", shutil, "rmtree", "write"),
            _make_fs("shutil.move", shutil, "move", "write"),
            _make_fs("shutil.copy", shutil, "copy", "write"),
            _make_fs("shutil.copy2", shutil, "copy2", "write"),
            _make_fs("shutil.copyfile", shutil, "copyfile", "write"),
            _make_fs("shutil.copytree", shutil, "copytree", "write"),
            # Read operations
            _make_fs("os.listdir", os, "listdir", "read"),
            _make_fs("os.scandir", os, "scandir", "read"),
            _make_fs("os.stat", os, "stat", "read"),
            _make_fs("os.lstat", os, "lstat", "read"),
            _make_fs("os.access", os, "access", "read"),
            _make_fs("os.getcwd", os, "getcwd", "read"),
            _make_fs("os.walk", os, "walk", "read"),
        ]

        # os.path functions live in the os.path module (posixpath/ntpath)
        import os.path as osp

        result += [
            _make_fs("os.path.exists", osp, "exists", "read"),
            _make_fs("os.path.isfile", osp, "isfile", "read"),
            _make_fs("os.path.isdir", osp, "isdir", "read"),
            _make_fs("os.path.getsize", osp, "getsize", "read"),
        ]

        # Also patch os.truncate if available (POSIX)
        if hasattr(os, "truncate"):
            result.append(_make_fs("os.truncate", os, "truncate", "write"))

        return result

    # ------------------------------------------------------------------
    # Subprocess patches
    # ------------------------------------------------------------------

    def _subprocess_patches(self) -> List[_Patch]:
        """Build patches for subprocess operations."""
        if not self.policy.subprocess.enabled:
            return []

        assert self._audit_logger is not None
        assert self._rate_limiter is not None

        al = self._audit_logger
        rl = self._rate_limiter
        policy = self.policy

        def _make_sp(op: str, attr: str) -> _Patch:
            original = getattr(subprocess, attr)
            interceptor = make_subprocess_interceptor(
                policy=policy,
                audit_logger=al,
                rate_limiter=rl,
                operation=op,
                original_fn=original,
            )
            return _Patch(subprocess, attr, interceptor)

        return [
            _make_sp("subprocess.run", "run"),
            _make_sp("subprocess.call", "call"),
            _make_sp("subprocess.check_call", "check_call"),
            _make_sp("subprocess.check_output", "check_output"),
            _make_sp("subprocess.Popen", "Popen"),
        ]

    # ------------------------------------------------------------------
    # Environment variable patches
    # ------------------------------------------------------------------

    def _env_patches(self) -> List[_Patch]:
        """Build patches for environment variable operations."""
        if not self.policy.env.enabled:
            return []

        assert self._audit_logger is not None
        assert self._rate_limiter is not None

        al = self._audit_logger
        rl = self._rate_limiter
        policy = self.policy

        patches: List[_Patch] = []

        # os.getenv
        original_getenv = os.getenv
        patches.append(_Patch(
            os, "getenv",
            make_env_read_interceptor(
                policy=policy,
                audit_logger=al,
                rate_limiter=rl,
                operation="os.getenv",
                original_fn=original_getenv,
            ),
        ))

        # os.putenv
        if hasattr(os, "putenv"):
            original_putenv = os.putenv
            patches.append(_Patch(
                os, "putenv",
                make_env_write_interceptor(
                    policy=policy,
                    audit_logger=al,
                    rate_limiter=rl,
                    operation="os.putenv",
                    original_fn=original_putenv,
                ),
            ))

        # os.unsetenv
        if hasattr(os, "unsetenv"):
            original_unsetenv = os.unsetenv
            patches.append(_Patch(
                os, "unsetenv",
                make_env_write_interceptor(
                    policy=policy,
                    audit_logger=al,
                    rate_limiter=rl,
                    operation="os.unsetenv",
                    original_fn=original_unsetenv,
                ),
            ))

        # os.environ is a Mapping-like object; we wrap it with a proxy
        environ_proxy = _EnvironProxy(
            policy=policy,
            audit_logger=al,
            rate_limiter=rl,
        )
        patches.append(_EnvironPatch(environ_proxy))

        return patches

    # ------------------------------------------------------------------
    # Network patches
    # ------------------------------------------------------------------

    def _network_patches(self) -> List[_Patch]:
        """Build patches for network operations."""
        if not self.policy.network.enabled:
            return []

        assert self._audit_logger is not None
        assert self._rate_limiter is not None

        al = self._audit_logger
        rl = self._rate_limiter
        policy = self.policy

        patches: List[_Patch] = []

        # urllib.request.urlopen
        original_urlopen = urllib.request.urlopen
        patches.append(_Patch(
            urllib.request, "urlopen",
            make_network_interceptor(
                policy=policy,
                audit_logger=al,
                rate_limiter=rl,
                operation="urllib.request.urlopen",
                original_fn=original_urlopen,
            ),
        ))

        # urllib.request.urlretrieve
        if hasattr(urllib.request, "urlretrieve"):
            original_urlretrieve = urllib.request.urlretrieve
            patches.append(_Patch(
                urllib.request, "urlretrieve",
                make_network_interceptor(
                    policy=policy,
                    audit_logger=al,
                    rate_limiter=rl,
                    operation="urllib.request.urlretrieve",
                    original_fn=original_urlretrieve,
                ),
            ))

        # requests (optional dependency; skip gracefully if not installed)
        try:
            import requests as _requests

            _request_methods: List[Tuple[str, str]] = [
                ("get", "requests.get"),
                ("post", "requests.post"),
                ("put", "requests.put"),
                ("delete", "requests.delete"),
                ("patch", "requests.patch"),
                ("head", "requests.head"),
                ("options", "requests.options"),
                ("request", "requests.request"),
            ]

            for attr, op in _request_methods:
                if hasattr(_requests, attr):
                    original = getattr(_requests, attr)
                    interceptor = make_network_interceptor(
                        policy=policy,
                        audit_logger=al,
                        rate_limiter=rl,
                        operation=op,
                        original_fn=original,
                    )
                    patches.append(_Patch(_requests, attr, interceptor))

        except ImportError:
            _log.debug("Sandbox: 'requests' library not installed; skipping patches.")

        return patches


# ---------------------------------------------------------------------------
# _EnvironProxy and _EnvironPatch
# ---------------------------------------------------------------------------


class _EnvironProxy:
    """Proxy for ``os.environ`` that intercepts reads and writes.

    This proxy wraps ``os.environ`` and delegates all attribute access to the
    underlying mapping, intercepting only ``__getitem__``, ``get``,
    ``__setitem__``, ``__delitem__``, ``pop``, and ``update``.

    Note: this proxy replaces ``os.environ`` in-place. When the sandbox
    exits, ``_EnvironPatch.restore()`` puts back the original mapping.
    """

    def __init__(
        self,
        policy: Policy,
        audit_logger: AuditLogger,
        rate_limiter: RateLimiter,
    ) -> None:
        # Use object.__setattr__ to avoid triggering our own __setattr__
        object.__setattr__(self, "_policy", policy)
        object.__setattr__(self, "_audit_logger", audit_logger)
        object.__setattr__(self, "_rate_limiter", rate_limiter)
        object.__setattr__(self, "_real_environ", os.environ)

        env_policy = policy.env
        object.__setattr__(self, "_env_policy", env_policy)

        # Build read/write interceptors for common operations
        real_environ = os.environ

        _read_fn = make_env_read_interceptor(
            policy=policy,
            audit_logger=audit_logger,
            rate_limiter=rate_limiter,
            operation="os.environ.__getitem__",
            original_fn=real_environ.__getitem__,
        )
        object.__setattr__(self, "_read_interceptor", _read_fn)

        _get_fn = make_env_read_interceptor(
            policy=policy,
            audit_logger=audit_logger,
            rate_limiter=rate_limiter,
            operation="os.environ.get",
            original_fn=real_environ.get,
        )
        object.__setattr__(self, "_get_interceptor", _get_fn)

        _setitem_fn = make_env_write_interceptor(
            policy=policy,
            audit_logger=audit_logger,
            rate_limiter=rate_limiter,
            operation="os.environ.__setitem__",
            original_fn=real_environ.__setitem__,
        )
        object.__setattr__(self, "_setitem_interceptor", _setitem_fn)

        _delitem_fn = make_env_write_interceptor(
            policy=policy,
            audit_logger=audit_logger,
            rate_limiter=rate_limiter,
            operation="os.environ.__delitem__",
            original_fn=real_environ.__delitem__,
        )
        object.__setattr__(self, "_delitem_interceptor", _delitem_fn)

        _update_fn = make_env_write_interceptor(
            policy=policy,
            audit_logger=audit_logger,
            rate_limiter=rate_limiter,
            operation="os.environ.update",
            original_fn=real_environ.update,
        )
        object.__setattr__(self, "_update_interceptor", _update_fn)

        _pop_fn = make_env_write_interceptor(
            policy=policy,
            audit_logger=audit_logger,
            rate_limiter=rate_limiter,
            operation="os.environ.pop",
            original_fn=real_environ.pop,
        )
        object.__setattr__(self, "_pop_interceptor", _pop_fn)

    def __getitem__(self, key: str) -> str:
        return object.__getattribute__(self, "_read_interceptor")(key)

    def get(self, key: str, default: Any = None) -> Any:
        return object.__getattribute__(self, "_get_interceptor")(key, default)

    def __setitem__(self, key: str, value: str) -> None:
        object.__getattribute__(self, "_setitem_interceptor")(key, value)

    def __delitem__(self, key: str) -> None:
        object.__getattribute__(self, "_delitem_interceptor")(key)

    def update(self, *args: Any, **kwargs: Any) -> None:
        object.__getattribute__(self, "_update_interceptor")(*args, **kwargs)

    def pop(self, *args: Any, **kwargs: Any) -> Any:
        return object.__getattribute__(self, "_pop_interceptor")(*args, **kwargs)

    # Delegate everything else to the real environ
    def __contains__(self, key: object) -> bool:
        return object.__getattribute__(self, "_real_environ").__contains__(key)

    def __iter__(self):
        return iter(object.__getattribute__(self, "_real_environ"))

    def __len__(self) -> int:
        return len(object.__getattribute__(self, "_real_environ"))

    def __repr__(self) -> str:  # pragma: no cover
        return f"<_EnvironProxy wrapping {object.__getattribute__(self, '_real_environ')!r}>"

    def keys(self):
        return object.__getattribute__(self, "_real_environ").keys()

    def values(self):
        return object.__getattribute__(self, "_real_environ").values()

    def items(self):
        return object.__getattribute__(self, "_real_environ").items()

    def copy(self) -> Dict[str, str]:
        return dict(object.__getattribute__(self, "_real_environ"))

    def setdefault(self, key: str, default: str = "") -> str:
        real = object.__getattribute__(self, "_real_environ")
        if key not in real:
            self[key] = default
        return self[key]


class _EnvironPatch:
    """A special ``_Patch``-like object for replacing ``os.environ``.

    ``os.environ`` is not a simple function; it is a ``os._Environ`` mapping
    that must be replaced atomically on both the ``os`` module and locally in
    any module that has already imported it as ``environ``.
    """

    def __init__(self, proxy: _EnvironProxy) -> None:
        self._proxy = proxy
        self._original_environ = os.environ
        # Keep references to target_module and attr for compatibility
        self.target_module = os
        self.attr = "environ"
        self.original = os.environ

    def apply(self) -> None:
        """Replace ``os.environ`` with the proxy."""
        self._original_environ = os.environ
        os.environ = self._proxy  # type: ignore[assignment]

    def restore(self) -> None:
        """Restore the original ``os.environ``."""
        os.environ = self._original_environ
