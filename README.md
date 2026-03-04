# AgentFence 🛡️

**AgentFence** is a lightweight open-source Python library and CLI tool that wraps AI agent execution environments with configurable permission boundaries, rate limits, and action whitelists.

It intercepts—and optionally blocks—dangerous operations such as file deletion, arbitrary HTTP calls, subprocess execution, and environment-variable access **before they reach the system**, without requiring any changes to agent source code.

---

## Features

| Feature | Description |
|---------|-------------|
| **Context-manager Sandbox** | Monkey-patches `os`, `shutil`, `subprocess`, `urllib`, and `requests` to enforce policy boundaries at runtime |
| **Declarative YAML policies** | Per-category allow/block rules, path glob whitelists, domain whitelists, and `log_only` vs `block` enforcement modes |
| **Token-bucket rate limiting** | Configurable call-frequency caps per action category (e.g. max 60 HTTP calls/minute) |
| **Structured audit log** | JSON Lines file recording every intercepted action with timestamp, caller frame, arguments, and decision |
| **CLI entrypoint** | `agent_fence run --policy policy.yaml agent_script.py` – sandbox any Python script without touching its code |

---

## Installation

```bash
pip install agent_fence
```

Or for development:

```bash
git clone https://github.com/example/agent_fence.git
cd agent_fence
pip install -e .
```

---

## Quick Start

### 1. Copy and customise the default policy

```bash
cp default_policy.yaml my_policy.yaml
# Edit my_policy.yaml to suit your agent's needs
```

### 2. Run your agent script under the sandbox

```bash
agent_fence run --policy my_policy.yaml my_agent.py
```

### 3. Or use the Python API

```python
from agent_fence import Sandbox, load_policy

policy = load_policy("my_policy.yaml")

with Sandbox(policy):
    # Everything inside here runs under policy enforcement
    import os
    import requests

    # This will be allowed (or blocked) according to policy
    requests.get("https://api.openai.com/v1/models")

    # This will raise PolicyViolation if os.remove is blocked
    os.remove("/tmp/safe_file.txt")
```

### 4. Catch policy violations

```python
from agent_fence import Sandbox, PolicyViolation, RateLimitExceeded, load_policy

policy = load_policy("my_policy.yaml")

try:
    with Sandbox(policy):
        import os
        os.remove("/etc/passwd")   # Blocked by default policy
except PolicyViolation as exc:
    print(f"Agent tried a blocked action: {exc}")
except RateLimitExceeded as exc:
    print(f"Agent exceeded rate limit: {exc}")
```

---

## Policy YAML Reference

All settings shown below are optional; AgentFence supplies safe defaults.

```yaml
# Human-readable name logged in audit entries
name: "my-agent-policy"
version: "1.0"

# Global enforcement: "block" (raise exception) or "log_only" (allow + log)
enforcement_mode: block

audit_log:
  enabled: true
  path: "agent_fence_audit.jsonl"  # Use "-" for stdout
  level: info                       # debug | info | warning | error
  include_stack_frame: true

filesystem:
  enabled: true
  blocked_operations:
    - os.remove
    - os.unlink
    - shutil.rmtree
  allowed_operations:
    - os.listdir
    - os.stat
  read_whitelist:
    - "/tmp/**"
    - "./data/**"
  write_whitelist:
    - "/tmp/**"
    - "./outputs/**"
  strict_whitelist: false

network:
  enabled: true
  domain_whitelist:
    - "api.openai.com"
    - "*.huggingface.co"
  allowed_methods: [GET, POST]
  block_private_ranges: false
  rate_limit:
    calls: 60
    window_seconds: 60

subprocess:
  enabled: true
  command_whitelist: []      # Empty = deny all subprocess calls
  block_shell: true
  rate_limit:
    calls: 5
    window_seconds: 60

env:
  enabled: true
  read_whitelist:
    - PATH
    - HOME
  read_blocklist:
    - AWS_SECRET_ACCESS_KEY
    - OPENAI_API_KEY
  allow_write: false
```

---

## CLI Reference

```
Usage: agent_fence run [OPTIONS] SCRIPT [SCRIPT_ARGS]...

  Run SCRIPT inside an AgentFence sandbox using the specified policy.

Options:
  --policy PATH   Path to a YAML policy file.  [required]
  --log    PATH   Override the audit log output path.
  --mode   TEXT   Override enforcement mode: block | log_only.
  --help          Show this message and exit.
```

**Example:**

```bash
agent_fence run --policy my_policy.yaml --mode log_only agent.py --agent-arg value
```

---

## Audit Log Format

Each line of the audit log is a JSON object:

```json
{
  "timestamp": "2024-01-15T12:34:56.789012Z",
  "policy": "my-agent-policy",
  "action": "network",
  "operation": "requests.get",
  "args": ["https://api.openai.com/v1/models"],
  "kwargs": {},
  "decision": "allow",
  "reason": "domain in whitelist",
  "stack_frame": {
    "filename": "my_agent.py",
    "lineno": 42,
    "function": "fetch_models"
  }
}
```

`decision` is either `"allow"` or `"block"`.

---

## Architecture

```
agent_fence/
├── __init__.py        # Public API exports
├── policy.py          # Policy dataclass + YAML loader/validator
├── sandbox.py         # Sandbox context manager (monkey-patching)
├── interceptors.py    # Per-category interceptor functions
├── rate_limiter.py    # Token-bucket rate limiter
├── audit_log.py       # Structured JSON audit logger
├── exceptions.py      # PolicyViolation, RateLimitExceeded
└── cli.py             # Click CLI entrypoint
```

---

## Development

```bash
# Install with dev dependencies
pip install -e .
pip install pytest

# Run the test suite
pytest
```

---

## License

MIT License – see [LICENSE](LICENSE) for details.

---

## Contributing

Pull requests are welcome! Please open an issue first to discuss major changes.

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write tests for your changes
4. Run `pytest` and ensure all tests pass
5. Submit a pull request
