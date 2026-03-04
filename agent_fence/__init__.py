"""AgentFence: A lightweight sandboxing library for AI agent execution environments.

This package provides a context-manager Sandbox that monkey-patches stdlib functions
(os, shutil, urllib, subprocess, requests) according to a declarative YAML policy,
enforces per-category rate limits, and writes a structured JSON audit log of every
intercepted action.

Public API
----------
- Sandbox         : Context manager that activates policy enforcement.
- PolicyViolation : Exception raised when a blocked action is attempted.
- RateLimitExceeded: Exception raised when a rate limit is exceeded.
- load_policy     : Helper that reads and validates a YAML policy file.

Example
-------
    from agent_fence import Sandbox, load_policy

    policy = load_policy("policy.yaml")
    with Sandbox(policy):
        # Agent code runs here under the policy constraints
        import subprocess
        subprocess.run(["ls"])  # blocked or allowed per policy
"""

from agent_fence.exceptions import PolicyViolation, RateLimitExceeded

# Lazy imports for components defined in later phases to avoid ImportError
# during early installation.  We provide stubs that raise informative errors
# until the full implementation is in place.

try:
    from agent_fence.policy import load_policy  # noqa: F401
except ImportError:  # pragma: no cover
    def load_policy(path: str):  # type: ignore[misc]
        """Load a policy from a YAML file (implementation pending)."""
        raise NotImplementedError(
            "agent_fence.policy module is not yet installed. "
            "Make sure you have the complete package."
        )

try:
    from agent_fence.sandbox import Sandbox  # noqa: F401
except ImportError:  # pragma: no cover
    class Sandbox:  # type: ignore[no-redef]
        """Context manager sandbox (implementation pending)."""

        def __init__(self, *args, **kwargs) -> None:  # type: ignore[misc]
            raise NotImplementedError(
                "agent_fence.sandbox module is not yet installed. "
                "Make sure you have the complete package."
            )

        def __enter__(self):  # type: ignore[misc]
            raise NotImplementedError()

        def __exit__(self, *args):  # type: ignore[misc]
            raise NotImplementedError()


__all__ = [
    "Sandbox",
    "PolicyViolation",
    "RateLimitExceeded",
    "load_policy",
]

__version__ = "0.1.0"
__author__ = "AgentFence Contributors"
