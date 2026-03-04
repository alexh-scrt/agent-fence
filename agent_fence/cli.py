"""Click-based CLI entrypoint for AgentFence.

Provides the ``agent_fence run`` command that loads a YAML policy file and
executes a Python script inside the Sandbox context manager without requiring
any modifications to the agent script.

Usage
-----
::

    agent_fence run --policy my_policy.yaml agent_script.py
    agent_fence run --policy my_policy.yaml --mode log_only agent_script.py
    agent_fence run --policy my_policy.yaml --log /tmp/audit.jsonl agent_script.py
    agent_fence run --policy my_policy.yaml agent_script.py -- --agent-arg value

The command adds the directory containing *SCRIPT* to ``sys.path`` so that
relative imports inside the script work correctly.
"""

from __future__ import annotations

import io
import logging
import os
import runpy
import sys
from typing import Optional, Tuple

import click

from agent_fence.exceptions import PolicyViolation, RateLimitExceeded
from agent_fence.policy import Policy, load_policy, policy_from_dict
from agent_fence.sandbox import Sandbox

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(package_name="agent_fence", prog_name="agent_fence")
def main() -> None:
    """AgentFence – sandbox AI agent scripts with configurable safety policies.

    Use 'agent_fence run' to execute a Python script inside a sandboxed
    environment enforced by a YAML policy file.
    """


# ---------------------------------------------------------------------------
# run command
# ---------------------------------------------------------------------------


@main.command("run")
@click.option(
    "--policy",
    "-p",
    "policy_path",
    required=False,
    default=None,
    metavar="PATH",
    help=(
        "Path to a YAML policy file.  If omitted, the built-in default policy "
        "is used (safe defaults with block mode)."
    ),
    type=click.Path(exists=False, file_okay=True, dir_okay=False),
)
@click.option(
    "--log",
    "-l",
    "log_path",
    required=False,
    default=None,
    metavar="PATH",
    help=(
        "Override the audit log output path from the policy. "
        "Use '-' to write to stdout."
    ),
)
@click.option(
    "--mode",
    "-m",
    "enforcement_mode",
    required=False,
    default=None,
    metavar="MODE",
    type=click.Choice(["block", "log_only"], case_sensitive=False),
    help="Override the global enforcement mode: 'block' or 'log_only'.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output (sets logging level to DEBUG).",
)
@click.argument("script", metavar="SCRIPT")
@click.argument("script_args", nargs=-1, metavar="[SCRIPT_ARGS]...")
def run_command(
    policy_path: Optional[str],
    log_path: Optional[str],
    enforcement_mode: Optional[str],
    verbose: bool,
    script: str,
    script_args: Tuple[str, ...],
) -> None:
    """Run SCRIPT inside an AgentFence sandbox.

    SCRIPT is the path to a Python script to execute.  Any additional
    arguments after SCRIPT are forwarded to the script via sys.argv.

    Examples:

    \b
        agent_fence run --policy policy.yaml my_agent.py
        agent_fence run --policy policy.yaml --mode log_only my_agent.py
        agent_fence run --policy policy.yaml my_agent.py -- --flag value
    """
    # -----------------------------------------------------------------------
    # Configure logging
    # -----------------------------------------------------------------------
    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s [%(name)s] %(message)s",
    )

    # -----------------------------------------------------------------------
    # Validate script path
    # -----------------------------------------------------------------------
    script_abs = os.path.abspath(script)
    if not os.path.exists(script_abs):
        raise click.BadParameter(
            f"Script file not found: {script!r}",
            param_hint="SCRIPT",
        )
    if not os.path.isfile(script_abs):
        raise click.BadParameter(
            f"SCRIPT must be a file, not a directory: {script!r}",
            param_hint="SCRIPT",
        )

    # -----------------------------------------------------------------------
    # Load policy
    # -----------------------------------------------------------------------
    policy = _load_policy(policy_path)

    # Apply CLI overrides to the policy
    if enforcement_mode is not None:
        policy.enforcement_mode = enforcement_mode.lower()
        # Also propagate to sub-policies that have their own override set
        # to the same value (we only override if they have no per-category override).
        # The effective_enforcement_mode helper already handles this, so we
        # just update the global field.

    if log_path is not None:
        policy.audit_log.path = log_path

    if verbose:
        click.echo(
            f"[agent_fence] Policy: {policy.name!r} | "
            f"Mode: {policy.enforcement_mode} | "
            f"Audit log: {policy.audit_log.path!r}",
            err=True,
        )

    # -----------------------------------------------------------------------
    # Prepare sys.argv for the script
    # -----------------------------------------------------------------------
    original_argv = sys.argv[:]
    sys.argv = [script_abs] + list(script_args)

    # Add the script's directory to sys.path so relative imports work
    script_dir = os.path.dirname(script_abs)
    path_inserted = False
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
        path_inserted = True

    # -----------------------------------------------------------------------
    # Execute the script inside the sandbox
    # -----------------------------------------------------------------------
    exit_code = 0
    try:
        with Sandbox(policy):
            try:
                runpy.run_path(script_abs, run_name="__main__")
            except SystemExit as exc:
                # Honour sys.exit() calls inside the script
                code = exc.code
                if isinstance(code, int):
                    exit_code = code
                elif code is None:
                    exit_code = 0
                else:
                    click.echo(str(code), err=True)
                    exit_code = 1
            except PolicyViolation as exc:
                click.echo(
                    f"\n[agent_fence] BLOCKED: {exc}",
                    err=True,
                )
                exit_code = 2
            except RateLimitExceeded as exc:
                click.echo(
                    f"\n[agent_fence] RATE LIMIT EXCEEDED: {exc}",
                    err=True,
                )
                exit_code = 2
            except Exception as exc:
                # Re-raise unexpected exceptions from the script
                raise
    except PolicyViolation as exc:
        # Raised outside the inner try (e.g. sandbox setup)
        click.echo(f"\n[agent_fence] BLOCKED: {exc}", err=True)
        exit_code = 2
    except RateLimitExceeded as exc:
        click.echo(f"\n[agent_fence] RATE LIMIT EXCEEDED: {exc}", err=True)
        exit_code = 2
    except Exception as exc:
        # Unexpected error from the script itself
        click.echo(f"Error running {script!r}: {exc}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        exit_code = 1
    finally:
        # Restore sys.argv and sys.path
        sys.argv = original_argv
        if path_inserted and script_dir in sys.path:
            sys.path.remove(script_dir)

    if exit_code != 0:
        sys.exit(exit_code)


# ---------------------------------------------------------------------------
# show-policy command
# ---------------------------------------------------------------------------


@main.command("show-policy")
@click.argument(
    "policy_path",
    metavar="POLICY",
    required=False,
    default=None,
)
def show_policy_command(policy_path: Optional[str]) -> None:
    """Display the resolved policy settings.

    POLICY is an optional path to a YAML policy file.  If omitted, the
    built-in default policy is shown.

    \b
    Example:
        agent_fence show-policy my_policy.yaml
    """
    policy = _load_policy(policy_path)
    _print_policy(policy)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_policy(policy_path: Optional[str]) -> Policy:
    """Load a policy from *policy_path* or return the default policy.

    Parameters
    ----------
    policy_path:
        Path to a YAML file, or ``None`` to use built-in defaults.

    Returns
    -------
    Policy
        A fully-resolved policy instance.

    Raises
    ------
    click.ClickException
        If the file cannot be found or parsed.
    """
    if policy_path is None:
        # Use the bundled default_policy.yaml if it exists alongside the package
        pkg_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(pkg_dir)
        bundled = os.path.join(repo_root, "default_policy.yaml")
        if os.path.exists(bundled):
            try:
                return load_policy(bundled)
            except Exception:  # noqa: BLE001
                pass
        # Fall back to in-memory defaults
        return Policy()

    try:
        return load_policy(policy_path)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(
            f"Failed to load policy from {policy_path!r}: {exc}"
        ) from exc


def _print_policy(policy: Policy) -> None:
    """Pretty-print the resolved policy settings to stdout."""
    import dataclasses
    import json

    def _to_dict(obj):
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return {k: _to_dict(v) for k, v in dataclasses.asdict(obj).items()}
        return obj

    data = _to_dict(policy)
    click.echo(json.dumps(data, indent=2, default=str))
