"""Unit tests for agent_fence.policy module.

Covers policy loading from YAML files, policy construction from dicts,
default value handling, validation errors, and the effective_enforcement_mode
helper.
"""

from __future__ import annotations

import os
import textwrap
from typing import Any, Dict

import pytest
import yaml

from agent_fence.policy import (
    AuditLogPolicy,
    EnvPolicy,
    FilesystemPolicy,
    NetworkPolicy,
    Policy,
    RateLimitConfig,
    SubprocessPolicy,
    load_policy,
    policy_from_dict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_yaml(tmp_path, content: str) -> str:
    """Write *content* to a temporary YAML file and return the path."""
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------


class TestPolicyDefaults:
    """Verify that Policy and sub-policies have correct defaults."""

    def test_policy_default_name(self) -> None:
        policy = Policy()
        assert policy.name == "default"

    def test_policy_default_version(self) -> None:
        policy = Policy()
        assert policy.version == "1.0"

    def test_policy_default_enforcement_mode(self) -> None:
        policy = Policy()
        assert policy.enforcement_mode == "block"

    def test_audit_log_defaults(self) -> None:
        al = AuditLogPolicy()
        assert al.enabled is True
        assert al.path == "agent_fence_audit.jsonl"
        assert al.level == "info"
        assert al.include_stack_frame is True

    def test_filesystem_defaults(self) -> None:
        fs = FilesystemPolicy()
        assert fs.enabled is True
        assert fs.enforcement_mode is None
        assert "os.remove" in fs.blocked_operations
        assert "os.listdir" in fs.allowed_operations
        assert fs.strict_whitelist is False

    def test_network_defaults(self) -> None:
        net = NetworkPolicy()
        assert net.enabled is True
        assert net.enforcement_mode is None
        assert "api.openai.com" in net.domain_whitelist
        assert "GET" in net.allowed_methods
        assert net.block_private_ranges is False

    def test_network_rate_limit_defaults(self) -> None:
        net = NetworkPolicy()
        assert net.rate_limit.calls == 60
        assert net.rate_limit.window_seconds == 60.0

    def test_subprocess_defaults(self) -> None:
        sp = SubprocessPolicy()
        assert sp.enabled is True
        assert sp.enforcement_mode is None
        assert sp.command_whitelist == []
        assert sp.block_shell is True

    def test_subprocess_rate_limit_defaults(self) -> None:
        sp = SubprocessPolicy()
        assert sp.rate_limit.calls == 5
        assert sp.rate_limit.window_seconds == 60.0

    def test_env_defaults(self) -> None:
        env = EnvPolicy()
        assert env.enabled is True
        assert env.enforcement_mode is None
        assert "PATH" in env.read_whitelist
        assert "OPENAI_API_KEY" in env.read_blocklist
        assert env.allow_write is False


# ---------------------------------------------------------------------------
# policy_from_dict
# ---------------------------------------------------------------------------


class TestPolicyFromDict:
    """Tests for the policy_from_dict helper."""

    def test_empty_dict_returns_all_defaults(self) -> None:
        policy = policy_from_dict({})
        assert policy.name == "default"
        assert policy.enforcement_mode == "block"

    def test_name_is_set(self) -> None:
        policy = policy_from_dict({"name": "my-policy"})
        assert policy.name == "my-policy"

    def test_version_is_set(self) -> None:
        policy = policy_from_dict({"version": "2.0"})
        assert policy.version == "2.0"

    def test_enforcement_mode_block(self) -> None:
        policy = policy_from_dict({"enforcement_mode": "block"})
        assert policy.enforcement_mode == "block"

    def test_enforcement_mode_log_only(self) -> None:
        policy = policy_from_dict({"enforcement_mode": "log_only"})
        assert policy.enforcement_mode == "log_only"

    def test_invalid_enforcement_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="enforcement_mode"):
            policy_from_dict({"enforcement_mode": "allow_all"})

    def test_non_dict_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            policy_from_dict(["not", "a", "dict"])  # type: ignore[arg-type]

    def test_audit_log_section_parsed(self) -> None:
        policy = policy_from_dict({
            "audit_log": {
                "enabled": False,
                "path": "/var/log/agent.jsonl",
                "level": "warning",
                "include_stack_frame": False,
            }
        })
        assert policy.audit_log.enabled is False
        assert policy.audit_log.path == "/var/log/agent.jsonl"
        assert policy.audit_log.level == "warning"
        assert policy.audit_log.include_stack_frame is False

    def test_invalid_audit_log_level_raises(self) -> None:
        with pytest.raises(ValueError, match="audit_log.level"):
            policy_from_dict({"audit_log": {"level": "verbose"}})

    def test_filesystem_section_parsed(self) -> None:
        policy = policy_from_dict({
            "filesystem": {
                "enabled": False,
                "blocked_operations": ["os.remove"],
                "allowed_operations": ["os.listdir"],
                "read_whitelist": ["/tmp/**"],
                "write_whitelist": ["/tmp/**"],
                "strict_whitelist": True,
            }
        })
        fs = policy.filesystem
        assert fs.enabled is False
        assert fs.blocked_operations == ["os.remove"]
        assert fs.allowed_operations == ["os.listdir"]
        assert fs.read_whitelist == ["/tmp/**"]
        assert fs.write_whitelist == ["/tmp/**"]
        assert fs.strict_whitelist is True

    def test_filesystem_enforcement_mode_override(self) -> None:
        policy = policy_from_dict({
            "enforcement_mode": "block",
            "filesystem": {"enforcement_mode": "log_only"},
        })
        assert policy.filesystem.enforcement_mode == "log_only"

    def test_invalid_filesystem_enforcement_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="enforcement_mode"):
            policy_from_dict({"filesystem": {"enforcement_mode": "ignore"}})

    def test_network_section_parsed(self) -> None:
        policy = policy_from_dict({
            "network": {
                "enabled": True,
                "domain_whitelist": ["example.com"],
                "block_private_ranges": True,
                "allowed_methods": ["GET"],
                "rate_limit": {"calls": 10, "window_seconds": 30},
            }
        })
        net = policy.network
        assert net.domain_whitelist == ["example.com"]
        assert net.block_private_ranges is True
        assert net.allowed_methods == ["GET"]
        assert net.rate_limit.calls == 10
        assert net.rate_limit.window_seconds == 30.0

    def test_network_methods_uppercased(self) -> None:
        policy = policy_from_dict({"network": {"allowed_methods": ["get", "post"]}})
        assert "GET" in policy.network.allowed_methods
        assert "POST" in policy.network.allowed_methods

    def test_subprocess_section_parsed(self) -> None:
        policy = policy_from_dict({
            "subprocess": {
                "enabled": True,
                "command_whitelist": ["ls", "cat"],
                "block_shell": False,
                "rate_limit": {"calls": 2, "window_seconds": 10},
            }
        })
        sp = policy.subprocess
        assert sp.command_whitelist == ["ls", "cat"]
        assert sp.block_shell is False
        assert sp.rate_limit.calls == 2
        assert sp.rate_limit.window_seconds == 10.0

    def test_env_section_parsed(self) -> None:
        policy = policy_from_dict({
            "env": {
                "enabled": True,
                "read_whitelist": ["PATH", "HOME"],
                "read_blocklist": ["SECRET"],
                "allow_write": True,
            }
        })
        env = policy.env
        assert env.read_whitelist == ["PATH", "HOME"]
        assert env.read_blocklist == ["SECRET"]
        assert env.allow_write is True

    def test_rate_limit_zero_calls_raises(self) -> None:
        with pytest.raises(ValueError, match="rate_limit.calls"):
            policy_from_dict({
                "network": {"rate_limit": {"calls": 0, "window_seconds": 60}}
            })

    def test_rate_limit_negative_window_raises(self) -> None:
        with pytest.raises(ValueError, match="rate_limit.window_seconds"):
            policy_from_dict({
                "network": {"rate_limit": {"calls": 10, "window_seconds": -5}}
            })

    def test_partial_network_rate_limit_uses_defaults(self) -> None:
        """Omitting some rate_limit keys should fall back to category defaults."""
        policy = policy_from_dict({"network": {"rate_limit": {"calls": 100}}})
        assert policy.network.rate_limit.calls == 100
        assert policy.network.rate_limit.window_seconds == 60.0


# ---------------------------------------------------------------------------
# load_policy (file-based)
# ---------------------------------------------------------------------------


class TestLoadPolicy:
    """Tests for the load_policy helper that reads YAML from disk."""

    def test_load_default_policy_yaml(self) -> None:
        """The bundled default_policy.yaml must load without errors."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        yaml_path = os.path.join(repo_root, "default_policy.yaml")
        if not os.path.exists(yaml_path):
            pytest.skip("default_policy.yaml not found – skipping")
        policy = load_policy(yaml_path)
        assert isinstance(policy, Policy)
        assert policy.name == "default"

    def test_load_minimal_yaml(self, tmp_path: Any) -> None:
        """A YAML file with only a name should load and apply defaults."""
        path = write_yaml(tmp_path, "name: minimal\n")
        policy = load_policy(path)
        assert policy.name == "minimal"
        assert policy.enforcement_mode == "block"

    def test_load_empty_yaml(self, tmp_path: Any) -> None:
        """A completely empty YAML file should produce a default Policy."""
        path = write_yaml(tmp_path, "")
        policy = load_policy(path)
        assert isinstance(policy, Policy)
        assert policy.name == "default"

    def test_load_full_yaml(self, tmp_path: Any) -> None:
        """A complete policy YAML file is parsed correctly."""
        content = """
            name: full-policy
            version: "2.0"
            enforcement_mode: log_only

            audit_log:
              enabled: true
              path: /tmp/audit.jsonl
              level: debug
              include_stack_frame: false

            filesystem:
              enabled: true
              blocked_operations:
                - os.remove
              allowed_operations:
                - os.listdir
              read_whitelist:
                - /tmp/**
              write_whitelist:
                - /tmp/**
              strict_whitelist: true

            network:
              enabled: true
              domain_whitelist:
                - api.example.com
              block_private_ranges: true
              allowed_methods:
                - GET
              rate_limit:
                calls: 20
                window_seconds: 30

            subprocess:
              enabled: false
              command_whitelist:
                - ls
              block_shell: false
              rate_limit:
                calls: 3
                window_seconds: 60

            env:
              enabled: true
              read_whitelist:
                - PATH
              read_blocklist:
                - SECRET_KEY
              allow_write: true
        """
        path = write_yaml(tmp_path, content)
        policy = load_policy(path)

        assert policy.name == "full-policy"
        assert policy.version == "2.0"
        assert policy.enforcement_mode == "log_only"

        assert policy.audit_log.path == "/tmp/audit.jsonl"
        assert policy.audit_log.level == "debug"
        assert policy.audit_log.include_stack_frame is False

        assert policy.filesystem.strict_whitelist is True
        assert policy.filesystem.blocked_operations == ["os.remove"]

        assert policy.network.domain_whitelist == ["api.example.com"]
        assert policy.network.rate_limit.calls == 20
        assert policy.network.rate_limit.window_seconds == 30.0
        assert policy.network.block_private_ranges is True

        assert policy.subprocess.enabled is False
        assert policy.subprocess.command_whitelist == ["ls"]
        assert policy.subprocess.block_shell is False

        assert policy.env.read_whitelist == ["PATH"]
        assert policy.env.read_blocklist == ["SECRET_KEY"]
        assert policy.env.allow_write is True

    def test_file_not_found_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_policy("/nonexistent/path/policy.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Any) -> None:
        path = write_yaml(tmp_path, ": invalid: [yaml: content")
        with pytest.raises(yaml.YAMLError):
            load_policy(path)

    def test_yaml_not_a_mapping_raises(self, tmp_path: Any) -> None:
        """A YAML document that is a list (not a mapping) must raise TypeError."""
        path = write_yaml(tmp_path, "- item1\n- item2\n")
        with pytest.raises(TypeError):
            load_policy(path)

    def test_invalid_global_enforcement_mode_raises(self, tmp_path: Any) -> None:
        path = write_yaml(tmp_path, "enforcement_mode: silent\n")
        with pytest.raises(ValueError, match="enforcement_mode"):
            load_policy(path)

    def test_invalid_audit_level_in_yaml_raises(self, tmp_path: Any) -> None:
        content = "audit_log:\n  level: trace\n"
        path = write_yaml(tmp_path, content)
        with pytest.raises(ValueError, match="audit_log.level"):
            load_policy(path)


# ---------------------------------------------------------------------------
# Policy.effective_enforcement_mode
# ---------------------------------------------------------------------------


class TestEffectiveEnforcementMode:
    """Tests for Policy.effective_enforcement_mode."""

    def test_inherits_global_when_no_override(self) -> None:
        policy = policy_from_dict({"enforcement_mode": "block"})
        assert policy.effective_enforcement_mode("filesystem") == "block"
        assert policy.effective_enforcement_mode("network") == "block"
        assert policy.effective_enforcement_mode("subprocess") == "block"
        assert policy.effective_enforcement_mode("env") == "block"

    def test_category_override_takes_precedence(self) -> None:
        policy = policy_from_dict({
            "enforcement_mode": "block",
            "filesystem": {"enforcement_mode": "log_only"},
        })
        assert policy.effective_enforcement_mode("filesystem") == "log_only"
        # Other categories still inherit global.
        assert policy.effective_enforcement_mode("network") == "block"

    def test_all_categories_can_override(self) -> None:
        policy = policy_from_dict({
            "enforcement_mode": "block",
            "filesystem": {"enforcement_mode": "log_only"},
            "network": {"enforcement_mode": "log_only"},
            "subprocess": {"enforcement_mode": "log_only"},
            "env": {"enforcement_mode": "log_only"},
        })
        for cat in ("filesystem", "network", "subprocess", "env"):
            assert policy.effective_enforcement_mode(cat) == "log_only", cat

    def test_log_only_global_block_override(self) -> None:
        policy = policy_from_dict({
            "enforcement_mode": "log_only",
            "network": {"enforcement_mode": "block"},
        })
        assert policy.effective_enforcement_mode("network") == "block"
        assert policy.effective_enforcement_mode("filesystem") == "log_only"

    def test_unknown_category_raises(self) -> None:
        policy = Policy()
        with pytest.raises(ValueError, match="Unknown policy category"):
            policy.effective_enforcement_mode("database")


# ---------------------------------------------------------------------------
# RateLimitConfig
# ---------------------------------------------------------------------------


class TestRateLimitConfig:
    """Tests for the RateLimitConfig dataclass."""

    def test_defaults(self) -> None:
        rlc = RateLimitConfig()
        assert rlc.calls == 60
        assert rlc.window_seconds == 60.0

    def test_custom_values(self) -> None:
        rlc = RateLimitConfig(calls=10, window_seconds=30.0)
        assert rlc.calls == 10
        assert rlc.window_seconds == 30.0


# ---------------------------------------------------------------------------
# Edge cases and type coercion
# ---------------------------------------------------------------------------


class TestPolicyEdgeCases:
    """Edge cases and type-coercion behaviour."""

    def test_string_bool_values_coerced(self) -> None:
        """YAML parses true/false as Python bools; ensure we handle them."""
        policy = policy_from_dict({
            "filesystem": {"enabled": True, "strict_whitelist": False}
        })
        assert policy.filesystem.enabled is True
        assert policy.filesystem.strict_whitelist is False

    def test_name_coerced_to_str(self) -> None:
        policy = policy_from_dict({"name": 42})
        assert policy.name == "42"
        assert isinstance(policy.name, str)

    def test_version_coerced_to_str(self) -> None:
        policy = policy_from_dict({"version": 1})
        assert policy.version == "1"

    def test_empty_domain_whitelist_accepted(self) -> None:
        policy = policy_from_dict({"network": {"domain_whitelist": []}})
        assert policy.network.domain_whitelist == []

    def test_empty_blocked_operations_accepted(self) -> None:
        policy = policy_from_dict({"filesystem": {"blocked_operations": []}})
        assert policy.filesystem.blocked_operations == []

    def test_null_audit_log_section_uses_defaults(self) -> None:
        """audit_log: null (or absent) must not crash."""
        policy = policy_from_dict({"audit_log": None})
        assert policy.audit_log.enabled is True

    def test_null_filesystem_section_uses_defaults(self) -> None:
        policy = policy_from_dict({"filesystem": None})
        assert policy.filesystem.enabled is True

    def test_null_network_section_uses_defaults(self) -> None:
        policy = policy_from_dict({"network": None})
        assert policy.network.enabled is True

    def test_null_subprocess_section_uses_defaults(self) -> None:
        policy = policy_from_dict({"subprocess": None})
        assert policy.subprocess.enabled is True

    def test_null_env_section_uses_defaults(self) -> None:
        policy = policy_from_dict({"env": None})
        assert policy.env.enabled is True
