# AgentFence 🛡️

**Keep your AI agents on a leash — without touching their code.**

AgentFence is a lightweight open-source Python library and CLI tool that wraps AI agent execution environments with configurable permission boundaries, rate limits, and action whitelists. It intercepts — and optionally blocks — dangerous operations such as file deletion, arbitrary HTTP calls, subprocess execution, and environment variable access before they reach the system. Define your safety policy in a YAML file and run any agent script inside the sandbox with a single command.

---

## Quick Start

```bash
# Install
pip install agent_fence

# Run any Python agent script inside the default sandbox
agent_fence run --policy default_policy.yaml my_agent.py

# Override enforcement mode to log-only (never blocks, just audits)
agent_fence run --policy default_policy.yaml --mode log_only my_agent.py

# Write the audit log to a specific file
agent_fence run --policy default_policy.yaml --log audit.jsonl my_agent.py
```

That's it. No changes to `my_agent.py` required.

---

## Features

- **Zero-modification sandboxing** — The `Sandbox` context manager monkey-patches `os`, `shutil`, `subprocess`, `urllib`, and `requests` at runtime. Your agent code runs unchanged.
- **Declarative YAML policies** — Per-category allow/block rules, path glob whitelists, domain whitelists, and `log_only` vs `block` enforcement modes in a single config file.
- **Token-bucket rate limiting** — Prevent runaway loops with per-category call-frequency caps (e.g. max 10 HTTP calls/min).
- **Structured JSON audit log** — Every intercepted action is recorded as a JSON Lines entry with timestamp, caller stack frame, arguments, and enforcement decision.
- **CLI entrypoint** — `agent_fence run` sandboxes any Python script without code changes; `agent_fence show-policy` inspects your resolved policy.

---

## Usage Examples

### CLI

```bash
# Sandbox an agent script with a custom policy
agent_fence run --policy my_policy.yaml agent_script.py

# Pass arguments to the agent script
agent_fence run --policy my_policy.yaml agent_script.py -- --query "summarise this"

# Inspect the resolved policy (shows all defaults filled in)
agent_fence show-policy my_policy.yaml
```

### Python API

```python
from agent_fence import Sandbox, load_policy

# Load and validate a YAML policy
policy = load_policy("my_policy.yaml")

# Wrap agent execution in the sandbox
with Sandbox(policy):
    import my_agent
    my_agent.run()  # Dangerous operations are intercepted per policy
```

### Handling violations

```python
from agent_fence import Sandbox, load_policy
from agent_fence.exceptions import PolicyViolation, RateLimitExceeded

policy = load_policy("strict_policy.yaml")

try:
    with Sandbox(policy):
        my_agent.run()
except PolicyViolation as e:
    print(f"Agent attempted a blocked action: {e.action} — {e.reason}")
except RateLimitExceeded as e:
    print(f"Agent exceeded rate limit for category: {e.category}")
```

### Programmatic policy construction

```python
from agent_fence import Sandbox
from agent_fence.policy import policy_from_dict

policy = policy_from_dict({
    "name": "dev-strict",
    "enforcement_mode": "block",
    "filesystem": {
        "blocked_operations": ["delete", "write"],
        "allowed_read_paths": ["/tmp/*", "/home/user/data/*"]
    },
    "network": {
        "allowed_domains": ["api.openai.com"],
        "rate_limit": {"calls": 20, "window_seconds": 60}
    },
    "subprocess": {"enabled": False},
    "env": {"blocked_vars": ["AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY"]}
})

with Sandbox(policy):
    my_agent.run()
```

---

## Project Structure

```
agent_fence/
├── __init__.py          # Public API: Sandbox, PolicyViolation, load_policy
├── policy.py            # Policy dataclass + YAML loading/validation
├── sandbox.py           # Core Sandbox context manager (monkey-patching)
├── interceptors.py      # Per-category interceptor functions
├── rate_limiter.py      # Token-bucket rate limiter
├── audit_log.py         # Structured JSON audit logger
├── exceptions.py        # PolicyViolation, RateLimitExceeded exceptions
└── cli.py               # Click CLI: `agent_fence run` + `show-policy`
tests/
├── test_policy.py
├── test_sandbox.py
├── test_rate_limiter.py
├── test_audit_log.py
├── test_exceptions.py
└── test_cli.py
default_policy.yaml      # Example policy with safe defaults
pyproject.toml
README.md
```

---

## Configuration

Policies are defined in YAML. Here is an annotated reference:

```yaml
# Human-readable name (appears in audit log headers)
name: "my-policy"

# Global enforcement mode: "block" raises exceptions, "log_only" audits only
enforcement_mode: "block"

filesystem:
  # Operations to block: delete, write, read, mkdir, rename
  blocked_operations: ["delete", "write"]
  # Glob patterns for paths agents are allowed to read
  allowed_read_paths:
    - "/tmp/*"
    - "/home/user/workspace/data/*"
  # Glob patterns for paths agents are allowed to write
  allowed_write_paths:
    - "/tmp/*"
  # Override enforcement for this category only
  enforcement_mode: "block"

network:
  # Allowlist of domains agents may contact (empty = allow all)
  allowed_domains:
    - "api.openai.com"
    - "api.anthropic.com"
  # Block all outbound network calls
  enabled: true
  enforcement_mode: "block"
  rate_limit:
    calls: 60
    window_seconds: 60

subprocess:
  # Set to false to block all subprocess calls
  enabled: false
  # Allowlist of exact commands that may be executed
  allowed_commands: []
  enforcement_mode: "block"

env:
  # Environment variables that must never be read by the agent
  blocked_vars:
    - "AWS_SECRET_ACCESS_KEY"
    - "OPENAI_API_KEY"
    - "DATABASE_URL"
  enforcement_mode: "block"

audit_log:
  enabled: true
  # Path to the JSON Lines output file (null = stderr)
  path: "audit.jsonl"
  # Minimum decision level to record: "allow" captures everything
  min_level: "allow"
  include_stack_frame: true
```

Copy `default_policy.yaml` from the repo as your starting point and iterate from there.

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*
