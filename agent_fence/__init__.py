"""AgentFence: A lightweight sandboxing library for AI agent execution environments.

This package provides a context-manager Sandbox that monkey-patches stdlib
functions (os, shutil, urllib, subprocess, requests) according to a declarative
YAML policy, enforces per-category rate limits, and writes a structured JSON
audit log of every intercepted action.

Public API
----------
- Sandbox          : Context manager that activates policy enforcement.
- PolicyViolation  : Exception raised when a blocked action is attempted.
- RateLimitExceeded: Exception raised when a rate limit is exceeded.
- load_policy      : Helper that reads and validates a YAML policy file.
- policy_from_dict : Helper that builds a Policy from a Python dictionary.
- Policy           : The Policy dataclass (for programmatic construction).

Example
-------
::

    from agent_fence import Sandbox, load_policy

    policy = load_policy("policy.yaml")
    with Sandbox(policy):
        # Agent code runs here under the policy constraints
        import os
        import subprocess
        subprocess.run(["ls"])  # blocked or allowed per policy
        os.remove("/tmp/file")  # blocked or allowed per policy

Catching violations::

    from agent_fence import Sandbox, PolicyViolation, RateLimitExceeded, load_policy

    policy = load_policy("policy.yaml")
    try:
        with Sandbox(policy):
            import os
            os.remove("/etc/passwd")   # Blocked by default policy
    except PolicyViolation as exc:
        print(f"Agent tried a blocked action: {exc}")
    except RateLimitExceeded as exc:
        print(f"Agent exceeded rate limit: {exc}")

Using the CLI::

    $ agent_fence run --policy policy.yaml my_agent.py
    $ agent_fence run --policy policy.yaml --mode log_only my_agent.py
    $ agent_fence show-policy policy.yaml
"""

from agent_fence.exceptions import AgentFenceError, PolicyViolation, RateLimitExceeded
from agent_fence.policy import Policy, load_policy, policy_from_dict
from agent_fence.sandbox import Sandbox

__all__ = [
    # Core context manager
    "Sandbox",
    # Exceptions
    "AgentFenceError",
    "PolicyViolation",
    "RateLimitExceeded",
    # Policy helpers
    "Policy",
    "load_policy",
    "policy_from_dict",
]

__version__ = "0.1.0"
__author__ = "AgentFence Contributors"
