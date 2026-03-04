"""Policy dataclass and YAML loading/validation logic for AgentFence.

This module defines the ``Policy`` dataclass (and its nested sub-policies)
that represents a fully-resolved fence policy, as well as the ``load_policy``
helper that reads a YAML file, applies defaults, and validates the result.

Typical usage
-------------
::

    from agent_fence.policy import load_policy

    policy = load_policy("my_policy.yaml")
    print(policy.name)
    print(policy.filesystem.blocked_operations)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_ENFORCEMENT_MODES = frozenset({"block", "log_only"})
VALID_LOG_LEVELS = frozenset({"debug", "info", "warning", "error"})


# ---------------------------------------------------------------------------
# Sub-policy dataclasses
# ---------------------------------------------------------------------------


@dataclass
class AuditLogPolicy:
    """Settings that control the structured audit logger.

    Attributes
    ----------
    enabled:
        Whether audit logging is active at all.
    path:
        Filesystem path for the JSON Lines log file.  Use ``"-"`` for stdout.
    level:
        Minimum severity level to record (``debug``, ``info``, ``warning``,
        ``error``).
    include_stack_frame:
        If ``True``, each log entry includes the caller's stack frame.
    """

    enabled: bool = True
    path: str = "agent_fence_audit.jsonl"
    level: str = "info"
    include_stack_frame: bool = True


@dataclass
class FilesystemPolicy:
    """Settings that govern filesystem operation interception.

    Attributes
    ----------
    enabled:
        Whether filesystem operations are intercepted.
    enforcement_mode:
        Override for the global enforcement mode (``None`` = inherit).
    blocked_operations:
        Fully-qualified operation names that are always denied.
    allowed_operations:
        Fully-qualified operation names that are always permitted without
        further checks.
    read_whitelist:
        Glob patterns for paths the agent may read.
    write_whitelist:
        Glob patterns for paths the agent may write.
    strict_whitelist:
        When ``True``, any path not matching a whitelist entry is denied.
    """

    enabled: bool = True
    enforcement_mode: Optional[str] = None
    blocked_operations: List[str] = field(default_factory=lambda: [
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "shutil.rmtree",
        "shutil.move",
    ])
    allowed_operations: List[str] = field(default_factory=lambda: [
        "os.listdir",
        "os.stat",
        "os.path.exists",
        "os.getcwd",
    ])
    read_whitelist: List[str] = field(default_factory=lambda: [
        "/tmp/**",
        "./data/**",
        "./outputs/**",
    ])
    write_whitelist: List[str] = field(default_factory=lambda: [
        "/tmp/**",
        "./outputs/**",
    ])
    strict_whitelist: bool = False


@dataclass
class RateLimitConfig:
    """A single rate-limit specification.

    Attributes
    ----------
    calls:
        Maximum number of calls allowed within the window.
    window_seconds:
        Duration of the sliding/token-bucket window in seconds.
    """

    calls: int = 60
    window_seconds: float = 60.0


@dataclass
class NetworkPolicy:
    """Settings that govern outbound network interception.

    Attributes
    ----------
    enabled:
        Whether network calls are intercepted.
    enforcement_mode:
        Override for the global enforcement mode (``None`` = inherit).
    domain_whitelist:
        Hostnames / wildcard patterns the agent is allowed to contact.
    block_private_ranges:
        If ``True``, connections to RFC-1918 and loopback addresses are
        blocked unless explicitly whitelisted.
    allowed_methods:
        HTTP methods that are permitted.  Use ``["*"]`` for all.
    rate_limit:
        Token-bucket rate limit for outbound HTTP calls.
    """

    enabled: bool = True
    enforcement_mode: Optional[str] = None
    domain_whitelist: List[str] = field(default_factory=lambda: [
        "api.openai.com",
        "api.anthropic.com",
        "*.huggingface.co",
        "localhost",
        "127.0.0.1",
    ])
    block_private_ranges: bool = False
    allowed_methods: List[str] = field(default_factory=lambda: ["GET", "POST"])
    rate_limit: RateLimitConfig = field(default_factory=lambda: RateLimitConfig(calls=60, window_seconds=60.0))


@dataclass
class SubprocessPolicy:
    """Settings that govern subprocess / shell-execution interception.

    Attributes
    ----------
    enabled:
        Whether subprocess calls are intercepted.
    enforcement_mode:
        Override for the global enforcement mode (``None`` = inherit).
    command_whitelist:
        Executable names the agent is permitted to run.  An empty list means
        **all** subprocess calls are denied.
    block_shell:
        If ``True``, any call with ``shell=True`` is unconditionally blocked.
    rate_limit:
        Token-bucket rate limit for subprocess spawns.
    """

    enabled: bool = True
    enforcement_mode: Optional[str] = None
    command_whitelist: List[str] = field(default_factory=list)
    block_shell: bool = True
    rate_limit: RateLimitConfig = field(default_factory=lambda: RateLimitConfig(calls=5, window_seconds=60.0))


@dataclass
class EnvPolicy:
    """Settings that govern environment-variable access interception.

    Attributes
    ----------
    enabled:
        Whether env-var access is intercepted.
    enforcement_mode:
        Override for the global enforcement mode (``None`` = inherit).
    read_whitelist:
        Variable names the agent is allowed to read.
    read_blocklist:
        Variable names that are always denied, even if they appear in
        ``read_whitelist``.
    allow_write:
        Whether the agent may set or modify environment variables.
    """

    enabled: bool = True
    enforcement_mode: Optional[str] = None
    read_whitelist: List[str] = field(default_factory=lambda: [
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "TZ",
        "TMPDIR",
        "VIRTUAL_ENV",
        "CONDA_DEFAULT_ENV",
    ])
    read_blocklist: List[str] = field(default_factory=lambda: [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "DATABASE_URL",
        "SECRET_KEY",
        "PRIVATE_KEY",
    ])
    allow_write: bool = False


# ---------------------------------------------------------------------------
# Top-level Policy dataclass
# ---------------------------------------------------------------------------


@dataclass
class Policy:
    """A fully-resolved AgentFence policy.

    This dataclass is the single source of truth for all enforcement
    decisions made by the sandbox at runtime.  It is produced by
    ``load_policy`` (YAML file) or constructed directly in tests.

    Attributes
    ----------
    name:
        Human-readable policy name, recorded in audit log entries.
    version:
        Policy schema version string.
    enforcement_mode:
        Global default enforcement mode: ``"block"`` or ``"log_only"``.
    audit_log:
        Audit-log configuration.
    filesystem:
        Filesystem interception configuration.
    network:
        Network interception configuration.
    subprocess:
        Subprocess interception configuration.
    env:
        Environment-variable interception configuration.
    """

    name: str = "default"
    version: str = "1.0"
    enforcement_mode: str = "block"
    audit_log: AuditLogPolicy = field(default_factory=AuditLogPolicy)
    filesystem: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    subprocess: SubprocessPolicy = field(default_factory=SubprocessPolicy)
    env: EnvPolicy = field(default_factory=EnvPolicy)

    def effective_enforcement_mode(self, category: str) -> str:
        """Return the effective enforcement mode for *category*.

        Each category may override the global ``enforcement_mode``.  This
        helper returns the most-specific applicable mode.

        Parameters
        ----------
        category:
            One of ``"filesystem"``, ``"network"``, ``"subprocess"``,
            ``"env"``.

        Returns
        -------
        str
            ``"block"`` or ``"log_only"``.

        Raises
        ------
        ValueError
            If *category* is not recognised.
        """
        category_map: Dict[str, Any] = {
            "filesystem": self.filesystem,
            "network": self.network,
            "subprocess": self.subprocess,
            "env": self.env,
        }
        if category not in category_map:
            raise ValueError(
                f"Unknown policy category: {category!r}. "
                f"Expected one of: {sorted(category_map)}"
            )
        sub_policy = category_map[category]
        override: Optional[str] = getattr(sub_policy, "enforcement_mode", None)
        return override if override is not None else self.enforcement_mode


# ---------------------------------------------------------------------------
# Internal parsing helpers
# ---------------------------------------------------------------------------


def _parse_audit_log(data: Dict[str, Any]) -> AuditLogPolicy:
    """Parse the ``audit_log`` section of a raw YAML dict."""
    defaults = AuditLogPolicy()
    level = data.get("level", defaults.level)
    if level not in VALID_LOG_LEVELS:
        raise ValueError(
            f"audit_log.level must be one of {sorted(VALID_LOG_LEVELS)}, got {level!r}"
        )
    return AuditLogPolicy(
        enabled=bool(data.get("enabled", defaults.enabled)),
        path=str(data.get("path", defaults.path)),
        level=level,
        include_stack_frame=bool(
            data.get("include_stack_frame", defaults.include_stack_frame)
        ),
    )


def _parse_rate_limit(
    data: Optional[Dict[str, Any]], default: RateLimitConfig
) -> RateLimitConfig:
    """Parse a ``rate_limit`` sub-section, falling back to *default*."""
    if data is None:
        return default
    calls = int(data.get("calls", default.calls))
    window = float(data.get("window_seconds", default.window_seconds))
    if calls <= 0:
        raise ValueError(f"rate_limit.calls must be positive, got {calls}")
    if window <= 0:
        raise ValueError(f"rate_limit.window_seconds must be positive, got {window}")
    return RateLimitConfig(calls=calls, window_seconds=window)


def _validate_enforcement_mode(mode: Any, context: str) -> str:
    """Validate that *mode* is a recognised enforcement mode string."""
    if mode not in VALID_ENFORCEMENT_MODES:
        raise ValueError(
            f"{context}: enforcement_mode must be one of "
            f"{sorted(VALID_ENFORCEMENT_MODES)}, got {mode!r}"
        )
    return str(mode)


def _parse_optional_enforcement_mode(
    data: Dict[str, Any], context: str
) -> Optional[str]:
    """Return a validated enforcement_mode override or ``None`` if absent."""
    raw = data.get("enforcement_mode")
    if raw is None:
        return None
    return _validate_enforcement_mode(raw, context)


def _parse_filesystem(data: Dict[str, Any]) -> FilesystemPolicy:
    """Parse the ``filesystem`` section of a raw YAML dict."""
    defaults = FilesystemPolicy()
    return FilesystemPolicy(
        enabled=bool(data.get("enabled", defaults.enabled)),
        enforcement_mode=_parse_optional_enforcement_mode(data, "filesystem"),
        blocked_operations=list(
            data.get("blocked_operations", defaults.blocked_operations)
        ),
        allowed_operations=list(
            data.get("allowed_operations", defaults.allowed_operations)
        ),
        read_whitelist=list(data.get("read_whitelist", defaults.read_whitelist)),
        write_whitelist=list(data.get("write_whitelist", defaults.write_whitelist)),
        strict_whitelist=bool(data.get("strict_whitelist", defaults.strict_whitelist)),
    )


def _parse_network(data: Dict[str, Any]) -> NetworkPolicy:
    """Parse the ``network`` section of a raw YAML dict."""
    defaults = NetworkPolicy()
    allowed_methods_raw = data.get("allowed_methods", defaults.allowed_methods)
    allowed_methods = [m.upper() for m in allowed_methods_raw]
    return NetworkPolicy(
        enabled=bool(data.get("enabled", defaults.enabled)),
        enforcement_mode=_parse_optional_enforcement_mode(data, "network"),
        domain_whitelist=list(
            data.get("domain_whitelist", defaults.domain_whitelist)
        ),
        block_private_ranges=bool(
            data.get("block_private_ranges", defaults.block_private_ranges)
        ),
        allowed_methods=allowed_methods,
        rate_limit=_parse_rate_limit(data.get("rate_limit"), defaults.rate_limit),
    )


def _parse_subprocess(data: Dict[str, Any]) -> SubprocessPolicy:
    """Parse the ``subprocess`` section of a raw YAML dict."""
    defaults = SubprocessPolicy()
    return SubprocessPolicy(
        enabled=bool(data.get("enabled", defaults.enabled)),
        enforcement_mode=_parse_optional_enforcement_mode(data, "subprocess"),
        command_whitelist=list(
            data.get("command_whitelist", defaults.command_whitelist)
        ),
        block_shell=bool(data.get("block_shell", defaults.block_shell)),
        rate_limit=_parse_rate_limit(data.get("rate_limit"), defaults.rate_limit),
    )


def _parse_env(data: Dict[str, Any]) -> EnvPolicy:
    """Parse the ``env`` section of a raw YAML dict."""
    defaults = EnvPolicy()
    return EnvPolicy(
        enabled=bool(data.get("enabled", defaults.enabled)),
        enforcement_mode=_parse_optional_enforcement_mode(data, "env"),
        read_whitelist=list(data.get("read_whitelist", defaults.read_whitelist)),
        read_blocklist=list(data.get("read_blocklist", defaults.read_blocklist)),
        allow_write=bool(data.get("allow_write", defaults.allow_write)),
    )


def _parse_policy_dict(raw: Dict[str, Any]) -> Policy:
    """Build a ``Policy`` from a raw dictionary (e.g. loaded from YAML).

    Parameters
    ----------
    raw:
        Unvalidated mapping, typically the result of ``yaml.safe_load``.

    Returns
    -------
    Policy
        A fully-resolved, validated ``Policy`` instance.

    Raises
    ------
    ValueError
        If any field value is invalid.
    TypeError
        If the top-level structure is not a mapping.
    """
    if not isinstance(raw, dict):
        raise TypeError(
            f"Policy YAML must be a mapping at the top level, got {type(raw).__name__}"
        )

    global_mode = _validate_enforcement_mode(
        raw.get("enforcement_mode", "block"), "enforcement_mode"
    )

    return Policy(
        name=str(raw.get("name", "default")),
        version=str(raw.get("version", "1.0")),
        enforcement_mode=global_mode,
        audit_log=_parse_audit_log(raw.get("audit_log") or {}),
        filesystem=_parse_filesystem(raw.get("filesystem") or {}),
        network=_parse_network(raw.get("network") or {}),
        subprocess=_parse_subprocess(raw.get("subprocess") or {}),
        env=_parse_env(raw.get("env") or {}),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_policy(path: str) -> Policy:
    """Load and validate a policy from a YAML file.

    Reads the YAML document at *path*, applies defaults for any omitted
    fields, validates all values, and returns a ``Policy`` dataclass ready
    for use with the ``Sandbox`` context manager.

    Parameters
    ----------
    path:
        Filesystem path to the YAML policy file.

    Returns
    -------
    Policy
        A fully-resolved policy instance.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    PermissionError
        If *path* cannot be read due to OS permissions.
    yaml.YAMLError
        If the file content is not valid YAML.
    ValueError
        If the policy contains invalid field values.
    TypeError
        If the top-level YAML structure is not a mapping.

    Example
    -------
    ::

        policy = load_policy("my_policy.yaml")
        with Sandbox(policy):
            ...
    """
    resolved = os.path.abspath(path)
    if not os.path.exists(resolved):
        raise FileNotFoundError(f"Policy file not found: {path!r}")

    with open(resolved, "r", encoding="utf-8") as fh:
        try:
            raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise yaml.YAMLError(
                f"Failed to parse policy file {path!r}: {exc}"
            ) from exc

    # An empty YAML document (e.g. blank file) yields None.
    if raw is None:
        raw = {}

    return _parse_policy_dict(raw)


def policy_from_dict(data: Dict[str, Any]) -> Policy:
    """Build a ``Policy`` directly from a Python dictionary.

    Useful in tests and programmatic policy construction without needing
    a YAML file on disk.

    Parameters
    ----------
    data:
        A (possibly partial) dictionary with the same structure as the
        YAML policy format.

    Returns
    -------
    Policy
        A fully-resolved policy instance.

    Raises
    ------
    ValueError
        If any field value is invalid.
    TypeError
        If *data* is not a mapping.
    """
    return _parse_policy_dict(data)
