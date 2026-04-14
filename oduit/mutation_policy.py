# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Explicit runtime database mutation policy helpers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

import typer

from .cli_types import GlobalConfig
from .exceptions import ConfigError

MutationPolicyName = Literal["allow", "require_allow_mutation", "forbidden"]
LegacyConfigMessage = (
    "db_risk_level has been removed. Replace it with write_protect_db / "
    "agent_write_protect_db / needs_mutation_flag / agent_needs_mutation_flag."
)


@dataclass(frozen=True)
class RuntimeDbMutationPolicy:
    """Resolved runtime DB mutation policy flags for one environment."""

    write_protect_db: bool
    agent_write_protect_db: bool
    needs_mutation_flag: bool
    agent_needs_mutation_flag: bool


@dataclass(frozen=True)
class RuntimeDbMutationDecision:
    """Actor-specific runtime DB mutation decision."""

    allowed: bool
    requires_flag: bool
    forbidden: bool
    policy: MutationPolicyName
    reason: str | None = None


def raise_if_legacy_db_risk_level(config: Mapping[str, Any]) -> None:
    """Reject removed `db_risk_level` configuration eagerly."""
    if "db_risk_level" in config:
        raise ConfigError(LegacyConfigMessage)


def _config_flag_enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def resolve_runtime_db_mutation_policy(
    env_config: Mapping[str, Any],
) -> RuntimeDbMutationPolicy:
    """Resolve the explicit runtime DB mutation policy for one environment."""
    raise_if_legacy_db_risk_level(env_config)
    return RuntimeDbMutationPolicy(
        write_protect_db=_config_flag_enabled(
            env_config.get("write_protect_db", False)
        ),
        agent_write_protect_db=_config_flag_enabled(
            env_config.get("agent_write_protect_db", False)
        ),
        needs_mutation_flag=_config_flag_enabled(
            env_config.get("needs_mutation_flag", False)
        ),
        agent_needs_mutation_flag=_config_flag_enabled(
            env_config.get("agent_needs_mutation_flag", False)
        ),
    )


def _allow_decision() -> RuntimeDbMutationDecision:
    return RuntimeDbMutationDecision(
        allowed=True,
        requires_flag=False,
        forbidden=False,
        policy="allow",
    )


def _require_flag_decision(reason: str) -> RuntimeDbMutationDecision:
    return RuntimeDbMutationDecision(
        allowed=True,
        requires_flag=True,
        forbidden=False,
        policy="require_allow_mutation",
        reason=reason,
    )


def _forbidden_decision(reason: str) -> RuntimeDbMutationDecision:
    return RuntimeDbMutationDecision(
        allowed=False,
        requires_flag=False,
        forbidden=True,
        policy="forbidden",
        reason=reason,
    )


def resolve_human_runtime_db_mutation_decision(
    env_config: Mapping[str, Any],
) -> RuntimeDbMutationDecision:
    """Resolve whether a human runtime DB mutation is allowed."""
    policy = resolve_runtime_db_mutation_policy(env_config)
    if policy.write_protect_db:
        return _forbidden_decision("write_protect_db")
    if policy.needs_mutation_flag:
        return _require_flag_decision("needs_mutation_flag")
    return _allow_decision()


def resolve_agent_runtime_db_mutation_decision(
    env_config: Mapping[str, Any],
) -> RuntimeDbMutationDecision:
    """Resolve whether an agent runtime DB mutation is allowed."""
    policy = resolve_runtime_db_mutation_policy(env_config)
    if policy.write_protect_db:
        return _forbidden_decision("write_protect_db")
    if policy.agent_write_protect_db:
        return _forbidden_decision("agent_write_protect_db")
    if policy.needs_mutation_flag:
        return _require_flag_decision("needs_mutation_flag")
    if policy.agent_needs_mutation_flag:
        return _require_flag_decision("agent_needs_mutation_flag")
    return _allow_decision()


def runtime_db_mutation_policy_details(
    env_config: Mapping[str, Any],
) -> dict[str, Any]:
    """Return stable policy metadata for payloads and error details."""
    policy = resolve_runtime_db_mutation_policy(env_config)
    human = resolve_human_runtime_db_mutation_decision(env_config)
    agent = resolve_agent_runtime_db_mutation_decision(env_config)
    return {
        "write_protect_db": policy.write_protect_db,
        "agent_write_protect_db": policy.agent_write_protect_db,
        "needs_mutation_flag": policy.needs_mutation_flag,
        "agent_needs_mutation_flag": policy.agent_needs_mutation_flag,
        "human_runtime_db_mutation_allowed": human.allowed,
        "human_runtime_db_mutation_requires_flag": human.requires_flag,
        "human_runtime_db_mutation_policy": human.policy,
        "agent_runtime_db_mutation_allowed": agent.allowed,
        "agent_runtime_db_mutation_requires_flag": agent.requires_flag,
        "agent_runtime_db_mutation_policy": agent.policy,
    }


def _human_confirmation_message(action: str, reason: str | None) -> str:
    if reason == "needs_mutation_flag":
        return f"{action} requires --allow-mutation because needs_mutation_flag=true."
    return f"{action} requires --allow-mutation."


def _human_forbidden_message(reason: str | None) -> str:
    if reason == "write_protect_db":
        return "Runtime DB mutation is forbidden because write_protect_db=true."
    return "Runtime DB mutation is forbidden."


def _agent_confirmation_message(action: str, reason: str | None) -> str:
    if reason == "agent_needs_mutation_flag":
        return (
            f"{action} requires --allow-mutation because "
            "agent_needs_mutation_flag=true."
        )
    if reason == "needs_mutation_flag":
        return f"{action} requires --allow-mutation because needs_mutation_flag=true."
    return f"{action} requires --allow-mutation."


def _agent_forbidden_message(reason: str | None) -> str:
    if reason == "agent_write_protect_db":
        return (
            "Runtime DB mutation is forbidden for agent commands because "
            "agent_write_protect_db=true."
        )
    if reason == "write_protect_db":
        return "Runtime DB mutation is forbidden because write_protect_db=true."
    return "Runtime DB mutation is forbidden."


def require_agent_runtime_db_mutation(
    *,
    env_config: Mapping[str, Any],
    allow_mutation: bool,
    operation: str,
    result_type: str,
    action: str,
    safety_level: str,
    fail_fn: Any,
) -> None:
    """Enforce explicit runtime DB mutation policy for agent commands."""
    try:
        decision = resolve_agent_runtime_db_mutation_decision(env_config)
        details = runtime_db_mutation_policy_details(env_config)
    except ConfigError as exc:
        fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"db_risk_level": env_config.get("db_risk_level")},
            remediation=[
                "Set explicit runtime DB policy flags in the active environment.",
            ],
            read_only=False,
            safety_level=safety_level,
        )

    if decision.forbidden:
        fail_fn(
            operation,
            result_type,
            _agent_forbidden_message(decision.reason),
            error_type="MutationForbidden",
            details=details,
            remediation=[
                "Use a read-only planning or inspection command to assess the change.",
                "Disable the write-protection flag only if the mutation is intended.",
            ],
            read_only=False,
            safety_level=safety_level,
        )

    if decision.requires_flag and not allow_mutation:
        fail_fn(
            operation,
            result_type,
            _agent_confirmation_message(action, decision.reason),
            error_type="ConfirmationRequired",
            details=details,
            remediation=[
                f"Retry `{action}` with `--allow-mutation` after ",
                "reviewing the plan output.",
                "Use a read-only planning command first if you need impact analysis.",
            ],
            read_only=False,
            safety_level=safety_level,
        )


def require_cli_runtime_db_mutation(
    *,
    global_config: GlobalConfig,
    env_config: Mapping[str, Any],
    allow_mutation: bool,
    operation: str,
    action: str,
    print_command_error_result_fn: Any,
    confirmation_required_error_fn: Any,
) -> None:
    """Enforce explicit runtime DB mutation policy for classic CLI commands."""
    try:
        decision = resolve_human_runtime_db_mutation_decision(env_config)
        details = runtime_db_mutation_policy_details(env_config)
    except ConfigError as exc:
        print_command_error_result_fn(
            global_config,
            operation,
            str(exc),
            error_type="ConfigError",
            details={"db_risk_level": env_config.get("db_risk_level")},
            remediation=[
                "Set explicit runtime DB policy flags in the active environment.",
            ],
        )
        raise typer.Exit(1) from None

    if decision.requires_flag and not allow_mutation:
        confirmation_required_error_fn(
            global_config,
            operation,
            _human_confirmation_message(action, decision.reason),
            remediation=[
                "Retry with `--allow-mutation` after reviewing the target environment.",
            ],
        )

    if decision.forbidden:
        print_command_error_result_fn(
            global_config,
            operation,
            _human_forbidden_message(decision.reason),
            error_type="MutationForbidden",
            details=details,
            remediation=[
                "Use a read-only planning or inspection command instead.",
                "Disable write protection only if the mutation is intended.",
            ],
        )
        raise typer.Exit(1) from None
