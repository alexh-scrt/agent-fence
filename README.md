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

### 5. Build a policy programmatically

```python
from agent_fence import Sandbox, policy_from_dict

policy = policy_from_dict({
    "name": "my-inline-policy",
    "enforcement_mode": "block",
    "filesystem": {
        "blocked_operations": ["os.remove", "shutil.rmtree"],
        "strict_whitelist": False,
    },
    "network": {
        "domain_whitelist": ["api.openai.com"],
        "rate_limit": {"calls": 30, "window_seconds": 60},
    },
    "subprocess": {
        "command_whitelist": [],  # deny all
        "block_shell": True,
    },
    "env": {
        "read_blocklist": ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY"],
        "allow_write": False,
    },
})

with Sandbox(policy):
    ...
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
  enforcement_mode: block           # overrides global; optional
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
  strict_whitelist: false           # true = deny all paths not in whitelist

network:
  enabled: true
  enforcement_mode: block           # optional override
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
  command_whitelist: []             # Empty = deny all subprocess calls
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

### `agent_fence run`

```
Usage: agent_fence run [OPTIONS] SCRIPT [SCRIPT_ARGS]...

  Run SCRIPT inside an AgentFence sandbox using the specified policy.

Options:
  -p, --policy PATH     Path to a YAML policy file.  Uses built-in defaults
                        if omitted.
  -l, --log PATH        Override the audit log output path from the policy.
                        Use '-' for stdout.
  -m, --mode [block|log_only]
                        Override global enforcement mode.
  -v, --verbose         Enable verbose output (DEBUG logging).
  --version             Show the version and exit.
  --help                Show this message and exit.
```

**Examples:**

```bash
# Run with a policy file
agent_fence run --policy my_policy.yaml agent.py

# Override enforcement mode to log-only for debugging
agent_fence run --policy my_policy.yaml --mode log_only agent.py

# Write audit log to stdout
agent_fence run --policy my_policy.yaml --log - agent.py

# Pass arguments to the agent script
agent_fence run --policy my_policy.yaml agent.py -- --api-key test --verbose

# Verbose sandbox output
agent_fence run --policy my_policy.yaml --verbose agent.py
```

### `agent_fence show-policy`

```
Usage: agent_fence show-policy [POLICY]

  Display the resolved policy settings.

  POLICY is an optional path to a YAML policy file.
  If omitted, the built-in default policy is shown.
```

**Example:**

```bash
agent_fence show-policy my_policy.yaml
```

---

## Audit Log Format

Each line of the audit log is a JSON object:

```json
{
  "timestamp": "2024-01-15T12:34:56.789012+00:00",
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

### Intercepted Operations

| Category | Operations Intercepted |
|----------|------------------------|
| **filesystem** | `os.remove`, `os.unlink`, `os.rmdir`, `os.makedirs`, `os.mkdir`, `os.rename`, `os.replace`, `os.listdir`, `os.scandir`, `os.stat`, `os.lstat`, `os.access`, `os.getcwd`, `os.walk`, `os.path.exists`, `os.path.isfile`, `os.path.isdir`, `os.path.getsize`, `shutil.rmtree`, `shutil.move`, `shutil.copy`, `shutil.copy2`, `shutil.copyfile`, `shutil.copytree` |
| **network** | `urllib.request.urlopen`, `urllib.request.urlretrieve`, `requests.get/post/put/delete/patch/head/options/request` |
| **subprocess** | `subprocess.run`, `subprocess.call`, `subprocess.check_call`, `subprocess.check_output`, `subprocess.Popen` |
| **env** | `os.getenv`, `os.putenv`, `os.unsetenv`, `os.environ.__getitem__`, `os.environ.get`, `os.environ.__setitem__`, `os.environ.__delitem__`, `os.environ.update`, `os.environ.pop` |

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

### How It Works

1. **Policy loading** – `load_policy("policy.yaml")` reads and validates your YAML config into a `Policy` dataclass with full defaults.
2. **Sandbox activation** – `Sandbox.__enter__()` opens the audit logger, initialises the rate limiter, and monkey-patches all configured stdlib functions.
3. **Interception** – Each patched function checks the policy: is the operation blocked? Is the path/domain/command whitelisted? Has the rate limit been hit?
4. **Decision** – In `block` mode, policy violations raise `PolicyViolation` or `RateLimitExceeded`. In `log_only` mode, the action is logged and allowed through.
5. **Audit** – Every intercepted call (allowed or blocked) is written as a JSON Lines entry to the configured log destination.
6. **Teardown** – `Sandbox.__exit__()` restores all original functions and closes the audit log.

---

## Enforcement Modes

| Mode | Behaviour |
|------|----------|
| `block` | Raise `PolicyViolation` or `RateLimitExceeded` when policy is violated. **Default.** |
| `log_only` | Log the violation as a `block` decision but allow the call through. Useful for policy development. |

Modes can be set globally or overridden per category:

```yaml
enforcement_mode: block       # global default

filesystem:
  enforcement_mode: log_only  # filesystem violations are logged but allowed

network:
  enforcement_mode: block     # network violations raise exceptions
```

---

## Rate Limiting

AgentFence uses a **token-bucket** algorithm. Each category starts with a full
bucket of `calls` tokens. Each intercepted call consumes one token. Tokens
refill continuously at a rate of `calls / window_seconds` per second.

```yaml
network:
  rate_limit:
    calls: 10          # max 10 calls
    window_seconds: 60 # per 60-second window

subprocess:
  rate_limit:
    calls: 3
    window_seconds: 60
```

When the bucket is empty, `RateLimitExceeded` is raised (in `block` mode).

---

## Development

```bash
# Install with dev dependencies
pip install -e .
pip install pytest

# Run the test suite
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_sandbox.py -v
```

### Running the Example

```bash
# Use the bundled default policy
agent_fence run --policy default_policy.yaml --mode log_only examples/my_agent.py

# Show what the default policy resolves to
agent_fence show-policy default_policy.yaml
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
