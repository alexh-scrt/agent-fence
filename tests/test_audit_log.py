"""Unit tests for agent_fence.audit_log module.

Verifies that AuditLogger writes correctly structured JSON Lines entries for
both allowed and blocked decisions, respects log-level filtering, handles
disabled logging gracefully, supports the context-manager protocol, and
produces entries with all required fields.
"""

from __future__ import annotations

import io
import json
from typing import Any, Dict, List

import pytest

from agent_fence.audit_log import AuditLogger, _safe_serialise, _utc_now_iso
from agent_fence.policy import Policy, policy_from_dict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_logger(
    policy: Policy,
    stream: io.StringIO,
) -> AuditLogger:
    """Return an opened AuditLogger that writes to *stream*."""
    logger = AuditLogger(policy, stream=stream)
    logger.open()
    return logger


def read_entries(stream: io.StringIO) -> List[Dict[str, Any]]:
    """Parse all JSON Lines entries from *stream* and return as a list."""
    stream.seek(0)
    entries = []
    for line in stream:
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def default_policy(**overrides: Any) -> Policy:
    """Build a policy with audit_log enabled; apply any *overrides*."""
    data: Dict[str, Any] = {"audit_log": {"enabled": True, "level": "debug"}}
    data.update(overrides)
    return policy_from_dict(data)


# ---------------------------------------------------------------------------
# Basic entry writing
# ---------------------------------------------------------------------------


class TestAuditLoggerBasicWriting:
    """Tests for core entry writing functionality."""

    def test_single_allow_entry_written(self) -> None:
        """A single 'allow' call produces exactly one JSON line."""
        stream = io.StringIO()
        policy = default_policy()
        logger = make_logger(policy, stream)

        logger.log(
            action="network",
            operation="requests.get",
            args=("https://api.openai.com",),
            kwargs={},
            decision="allow",
            reason="domain in whitelist",
        )
        logger.close()

        entries = read_entries(stream)
        assert len(entries) == 1

    def test_single_block_entry_written(self) -> None:
        """A single 'block' call produces exactly one JSON line."""
        stream = io.StringIO()
        policy = default_policy()
        logger = make_logger(policy, stream)

        logger.log(
            action="filesystem",
            operation="os.remove",
            args=("/etc/passwd",),
            kwargs={},
            decision="block",
            reason="operation in blocked_operations",
        )
        logger.close()

        entries = read_entries(stream)
        assert len(entries) == 1

    def test_multiple_entries_written(self) -> None:
        """Multiple log calls produce the correct number of entries."""
        stream = io.StringIO()
        policy = default_policy()
        logger = make_logger(policy, stream)

        for i in range(5):
            logger.log(
                action="network",
                operation=f"requests.get#{i}",
                args=(f"https://example.com/{i}",),
                kwargs={},
                decision="allow",
                reason="test",
            )
        logger.close()

        entries = read_entries(stream)
        assert len(entries) == 5

    def test_entry_is_valid_json(self) -> None:
        """Each line is parseable as a JSON object."""
        stream = io.StringIO()
        logger = make_logger(default_policy(), stream)
        logger.log(
            action="env",
            operation="os.getenv",
            args=("SECRET",),
            kwargs={},
            decision="block",
            reason="var in blocklist",
        )
        logger.close()

        entries = read_entries(stream)
        assert isinstance(entries[0], dict)


# ---------------------------------------------------------------------------
# Required fields
# ---------------------------------------------------------------------------


class TestAuditLoggerFields:
    """Tests that every required field is present and correct."""

    def _get_entry(self, decision: str = "allow") -> Dict[str, Any]:
        stream = io.StringIO()
        policy = default_policy(name="test-policy")
        logger = make_logger(policy, stream)
        logger.log(
            action="network",
            operation="requests.post",
            args=("https://api.openai.com",),
            kwargs={"json": {"key": "value"}},
            decision=decision,
            reason="test reason",
        )
        logger.close()
        return read_entries(stream)[0]

    def test_timestamp_present(self) -> None:
        entry = self._get_entry()
        assert "timestamp" in entry

    def test_timestamp_is_string(self) -> None:
        entry = self._get_entry()
        assert isinstance(entry["timestamp"], str)

    def test_timestamp_has_timezone_info(self) -> None:
        entry = self._get_entry()
        # ISO-8601 with timezone ends with +HH:MM or Z
        ts = entry["timestamp"]
        assert "+" in ts or ts.endswith("Z")

    def test_policy_name_present(self) -> None:
        entry = self._get_entry()
        assert entry["policy"] == "test-policy"

    def test_action_present(self) -> None:
        entry = self._get_entry()
        assert entry["action"] == "network"

    def test_operation_present(self) -> None:
        entry = self._get_entry()
        assert entry["operation"] == "requests.post"

    def test_args_present(self) -> None:
        entry = self._get_entry()
        assert "args" in entry
        assert isinstance(entry["args"], list)

    def test_args_serialised_correctly(self) -> None:
        entry = self._get_entry()
        assert entry["args"] == ["https://api.openai.com"]

    def test_kwargs_present(self) -> None:
        entry = self._get_entry()
        assert "kwargs" in entry
        assert isinstance(entry["kwargs"], dict)

    def test_decision_allow(self) -> None:
        entry = self._get_entry(decision="allow")
        assert entry["decision"] == "allow"

    def test_decision_block(self) -> None:
        entry = self._get_entry(decision="block")
        assert entry["decision"] == "block"

    def test_reason_present(self) -> None:
        entry = self._get_entry()
        assert entry["reason"] == "test reason"

    def test_stack_frame_present_when_enabled(self) -> None:
        """stack_frame field present when include_stack_frame=True."""
        stream = io.StringIO()
        policy = policy_from_dict({
            "audit_log": {
                "enabled": True,
                "level": "debug",
                "include_stack_frame": True,
            }
        })
        logger = make_logger(policy, stream)
        logger.log(
            action="env",
            operation="os.getenv",
            args=("HOME",),
            kwargs={},
            decision="allow",
            reason="whitelisted",
        )
        logger.close()

        entry = read_entries(stream)[0]
        assert "stack_frame" in entry

    def test_stack_frame_absent_when_disabled(self) -> None:
        """stack_frame field absent when include_stack_frame=False."""
        stream = io.StringIO()
        policy = policy_from_dict({
            "audit_log": {
                "enabled": True,
                "level": "debug",
                "include_stack_frame": False,
            }
        })
        logger = make_logger(policy, stream)
        logger.log(
            action="env",
            operation="os.getenv",
            args=("HOME",),
            kwargs={},
            decision="allow",
            reason="whitelisted",
        )
        logger.close()

        entry = read_entries(stream)[0]
        assert "stack_frame" not in entry

    def test_extra_fields_merged(self) -> None:
        """Extra fields are merged into the log entry."""
        stream = io.StringIO()
        logger = make_logger(default_policy(), stream)
        logger.log(
            action="network",
            operation="requests.get",
            args=(),
            kwargs={},
            decision="block",
            reason="test",
            extra={"rate_limit_remaining": 0},
        )
        logger.close()

        entry = read_entries(stream)[0]
        assert entry["rate_limit_remaining"] == 0


# ---------------------------------------------------------------------------
# Disabled logging
# ---------------------------------------------------------------------------


class TestAuditLoggerDisabled:
    """Tests that disabled logger produces no output."""

    def test_disabled_logger_writes_nothing(self) -> None:
        stream = io.StringIO()
        policy = policy_from_dict({"audit_log": {"enabled": False}})
        logger = AuditLogger(policy, stream=stream)
        logger.open()
        logger.log(
            action="network",
            operation="requests.get",
            args=(),
            kwargs={},
            decision="allow",
            reason="test",
        )
        logger.close()

        assert stream.getvalue() == ""

    def test_disabled_logger_enabled_attribute_is_false(self) -> None:
        policy = policy_from_dict({"audit_log": {"enabled": False}})
        logger = AuditLogger(policy)
        assert logger.enabled is False


# ---------------------------------------------------------------------------
# Log-level filtering
# ---------------------------------------------------------------------------


class TestAuditLoggerLevelFiltering:
    """Tests for minimum log-level filtering."""

    def test_allow_at_info_level_written_when_level_is_info(self) -> None:
        """allow decisions map to 'info'; logged when min level is 'info'."""
        stream = io.StringIO()
        policy = policy_from_dict({"audit_log": {"enabled": True, "level": "info"}})
        logger = make_logger(policy, stream)
        logger.log(
            action="network",
            operation="requests.get",
            args=(),
            kwargs={},
            decision="allow",
            reason="test",
        )
        logger.close()

        entries = read_entries(stream)
        assert len(entries) == 1

    def test_allow_suppressed_when_level_is_warning(self) -> None:
        """allow decisions (info level) are suppressed when min is 'warning'."""
        stream = io.StringIO()
        policy = policy_from_dict({"audit_log": {"enabled": True, "level": "warning"}})
        logger = make_logger(policy, stream)
        logger.log(
            action="network",
            operation="requests.get",
            args=(),
            kwargs={},
            decision="allow",
            reason="test",
        )
        logger.close()

        entries = read_entries(stream)
        assert len(entries) == 0

    def test_block_at_warning_level_written_when_level_is_warning(self) -> None:
        """block decisions map to 'warning'; logged when min level is 'warning'."""
        stream = io.StringIO()
        policy = policy_from_dict({"audit_log": {"enabled": True, "level": "warning"}})
        logger = make_logger(policy, stream)
        logger.log(
            action="filesystem",
            operation="os.remove",
            args=("/tmp/x",),
            kwargs={},
            decision="block",
            reason="blocked op",
        )
        logger.close()

        entries = read_entries(stream)
        assert len(entries) == 1

    def test_block_suppressed_when_level_is_error(self) -> None:
        """block decisions (warning level) suppressed when min is 'error'."""
        stream = io.StringIO()
        policy = policy_from_dict({"audit_log": {"enabled": True, "level": "error"}})
        logger = make_logger(policy, stream)
        logger.log(
            action="filesystem",
            operation="os.remove",
            args=("/tmp/x",),
            kwargs={},
            decision="block",
            reason="blocked op",
        )
        logger.close()

        entries = read_entries(stream)
        assert len(entries) == 0

    def test_debug_level_allows_all_entries(self) -> None:
        """debug level records both allow and block entries."""
        stream = io.StringIO()
        policy = policy_from_dict({"audit_log": {"enabled": True, "level": "debug"}})
        logger = make_logger(policy, stream)

        for decision in ("allow", "block"):
            logger.log(
                action="env",
                operation="os.getenv",
                args=("PATH",),
                kwargs={},
                decision=decision,
                reason="test",
            )
        logger.close()

        entries = read_entries(stream)
        assert len(entries) == 2


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


class TestAuditLoggerContextManager:
    """Tests for the context-manager interface."""

    def test_context_manager_writes_entries(self) -> None:
        stream = io.StringIO()
        policy = default_policy()

        with AuditLogger(policy, stream=stream) as logger:
            logger.log(
                action="subprocess",
                operation="subprocess.run",
                args=(["ls"],),
                kwargs={},
                decision="block",
                reason="command not in whitelist",
            )

        entries = read_entries(stream)
        assert len(entries) == 1
        assert entries[0]["action"] == "subprocess"

    def test_context_manager_close_called_on_exit(self) -> None:
        """After the with-block the logger stream should be flushed."""
        buf = io.StringIO()
        policy = default_policy()

        with AuditLogger(policy, stream=buf) as logger:
            logger.log(
                action="network",
                operation="requests.get",
                args=(),
                kwargs={},
                decision="allow",
                reason="ok",
            )

        # Stream should still be readable after context exit
        buf.seek(0)
        content = buf.read()
        assert len(content) > 0


# ---------------------------------------------------------------------------
# Convenience shorthands
# ---------------------------------------------------------------------------


class TestAuditLoggerShorthands:
    """Tests for log_allow and log_block helpers."""

    def test_log_allow_shorthand(self) -> None:
        stream = io.StringIO()
        with AuditLogger(default_policy(), stream=stream) as logger:
            logger.log_allow(
                action="network",
                operation="requests.get",
                args=("https://example.com",),
                kwargs={},
                reason="whitelisted",
            )
        entries = read_entries(stream)
        assert len(entries) == 1
        assert entries[0]["decision"] == "allow"

    def test_log_block_shorthand(self) -> None:
        stream = io.StringIO()
        with AuditLogger(default_policy(), stream=stream) as logger:
            logger.log_block(
                action="filesystem",
                operation="shutil.rmtree",
                args=("/",),
                kwargs={},
                reason="blocked op",
            )
        entries = read_entries(stream)
        assert len(entries) == 1
        assert entries[0]["decision"] == "block"

    def test_log_allow_extra_fields(self) -> None:
        stream = io.StringIO()
        with AuditLogger(default_policy(), stream=stream) as logger:
            logger.log_allow(
                action="env",
                operation="os.getenv",
                args=("PATH",),
                kwargs={},
                reason="whitelisted",
                extra={"custom_key": "custom_value"},
            )
        entries = read_entries(stream)
        assert entries[0]["custom_key"] == "custom_value"


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


class TestSafeSerialise:
    """Tests for the _safe_serialise helper."""

    def test_string_passthrough(self) -> None:
        assert _safe_serialise("hello") == "hello"

    def test_int_passthrough(self) -> None:
        assert _safe_serialise(42) == 42

    def test_float_passthrough(self) -> None:
        assert _safe_serialise(3.14) == 3.14

    def test_bool_passthrough(self) -> None:
        assert _safe_serialise(True) is True

    def test_none_passthrough(self) -> None:
        assert _safe_serialise(None) is None

    def test_list_items_serialised(self) -> None:
        result = _safe_serialise([1, "two", None])
        assert result == [1, "two", None]

    def test_tuple_becomes_list(self) -> None:
        result = _safe_serialise((1, 2, 3))
        assert result == [1, 2, 3]
        assert isinstance(result, list)

    def test_dict_keys_stringified(self) -> None:
        result = _safe_serialise({1: "a", 2: "b"})
        assert result == {"1": "a", "2": "b"}

    def test_nested_structure(self) -> None:
        result = _safe_serialise({"a": [1, (2, 3)]})
        assert result == {"a": [1, [2, 3]]}

    def test_unserializable_object_becomes_repr(self) -> None:
        class _Custom:
            def __repr__(self) -> str:
                return "<Custom>"

        result = _safe_serialise(_Custom())
        assert result == "<Custom>"


# ---------------------------------------------------------------------------
# _utc_now_iso
# ---------------------------------------------------------------------------


class TestUtcNowIso:
    """Tests for the _utc_now_iso timestamp helper."""

    def test_returns_string(self) -> None:
        assert isinstance(_utc_now_iso(), str)

    def test_contains_timezone_offset(self) -> None:
        ts = _utc_now_iso()
        assert "+" in ts or ts.endswith("Z")

    def test_successive_calls_non_decreasing(self) -> None:
        t1 = _utc_now_iso()
        t2 = _utc_now_iso()
        # Lexicographic comparison works for ISO-8601 with same timezone.
        assert t2 >= t1


# ---------------------------------------------------------------------------
# Writing without open() should warn but not crash
# ---------------------------------------------------------------------------


class TestAuditLoggerWriteWithoutOpen:
    """Writing to an un-opened logger should not raise."""

    def test_write_without_open_does_not_raise(self) -> None:
        policy = default_policy()
        # Supply no stream and do not call open() — _stream is None.
        logger = AuditLogger(policy)
        # Should not raise; just emit an internal warning.
        logger.log(
            action="network",
            operation="requests.get",
            args=(),
            kwargs={},
            decision="allow",
            reason="test",
        )
