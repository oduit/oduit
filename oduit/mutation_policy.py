# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Environment-aware runtime database mutation policy helpers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

import typer

from .cli_types import GlobalConfig
from .exceptions import ConfigError


class DatabaseRiskLevel(str, Enum):
    """Canonical database risk levels."""

    TEST = "test"
    DEV = "dev"
    PROD = "prod"


_RISK_LEVEL_ALIASES = {
    "testing": DatabaseRiskLevel.TEST,
    "development": DatabaseRiskLevel.DEV,
    "production": DatabaseRiskLevel.PROD,
}


@dataclass(frozen=True)
class RuntimeMutationPolicy:
    """Resolved runtime DB mutation behavior for one environment."""

    risk_level: DatabaseRiskLevel
    allow_without_flag: bool
    require_flag: bool
    forbidden: bool

    @property
    def runtime_mutation_policy(self) -> str:
        """Return a stable machine-facing policy label."""
        if self.allow_without_flag:
            return "auto_allow"
        if self.require_flag:
            return "require_allow_mutation"
        return "forbidden"

    @property
    def runtime_mutation_allowed(self) -> bool:
        """Return whether runtime DB mutation is allowed at all."""
        return not self.forbidden


def normalize_db_risk_level(value: Any) -> DatabaseRiskLevel:
    """Normalize a config value into a canonical risk level."""
    if isinstance(value, DatabaseRiskLevel):
        return value
    if value is None:
        return DatabaseRiskLevel.DEV
    if isinstance(value, str):
        normalized = value.strip().lower()
        if not normalized:
            return DatabaseRiskLevel.DEV
        aliased = _RISK_LEVEL_ALIASES.get(normalized)
        if aliased is not None:
            return aliased
        try:
            return DatabaseRiskLevel(normalized)
        except ValueError as exc:
            raise ConfigError(
                "Invalid db_risk_level. Expected one of: test, dev, prod."
            ) from exc
    raise ConfigError("Invalid db_risk_level. Expected one of: test, dev, prod.")


def resolve_db_risk_level(env_config: Mapping[str, Any]) -> DatabaseRiskLevel:
    """Resolve ``db_risk_level`` from environment config with default ``dev``."""
    return normalize_db_risk_level(env_config.get("db_risk_level"))


def resolve_runtime_mutation_policy(
    env_config: Mapping[str, Any],
) -> RuntimeMutationPolicy:
    """Resolve the effective runtime DB mutation policy for one environment."""
    risk_level = resolve_db_risk_level(env_config)
    if risk_level is DatabaseRiskLevel.TEST:
        return RuntimeMutationPolicy(
            risk_level=risk_level,
            allow_without_flag=True,
            require_flag=False,
            forbidden=False,
        )
    if risk_level is DatabaseRiskLevel.DEV:
        return RuntimeMutationPolicy(
            risk_level=risk_level,
            allow_without_flag=False,
            require_flag=True,
            forbidden=False,
        )
    return RuntimeMutationPolicy(
        risk_level=risk_level,
        allow_without_flag=False,
        require_flag=False,
        forbidden=True,
    )


def runtime_mutation_policy_details(
    env_config: Mapping[str, Any],
) -> dict[str, Any]:
    """Return stable policy metadata for payloads and error details."""
    policy = resolve_runtime_mutation_policy(env_config)
    return {
        "db_risk_level": policy.risk_level.value,
        "runtime_mutation_policy": policy.runtime_mutation_policy,
        "runtime_mutation_allowed": policy.runtime_mutation_allowed,
    }


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
    """Enforce environment-aware runtime DB mutation policy for agent commands."""
    try:
        policy = resolve_runtime_mutation_policy(env_config)
        details = runtime_mutation_policy_details(env_config)
    except ConfigError as exc:
        fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"db_risk_level": env_config.get("db_risk_level")},
            remediation=[
                "Set `db_risk_level` to `test`, `dev`, or `prod` in the "
                "active environment.",
            ],
            read_only=False,
            safety_level=safety_level,
        )

    if policy.allow_without_flag:
        return
    if policy.require_flag:
        if allow_mutation:
            return
        fail_fn(
            operation,
            result_type,
            f"{action} requires --allow-mutation when db_risk_level=dev.",
            error_type="ConfirmationRequired",
            details=details,
            remediation=[
                f"Retry `{action}` with `--allow-mutation` after reviewing "
                "the plan output.",
                "Use a read-only planning command first if you need impact analysis.",
            ],
            read_only=False,
            safety_level=safety_level,
        )

    fail_fn(
        operation,
        result_type,
        "Runtime DB mutation is forbidden when db_risk_level=prod.",
        error_type="MutationForbidden",
        details=details,
        remediation=[
            "Use a read-only planning or inspection command to assess the change.",
            "Run the mutation against a non-production environment if it is intended.",
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
    """Enforce environment-aware runtime DB mutation policy for classic CLI."""
    try:
        policy = resolve_runtime_mutation_policy(env_config)
        details = runtime_mutation_policy_details(env_config)
    except ConfigError as exc:
        print_command_error_result_fn(
            global_config,
            operation,
            str(exc),
            error_type="ConfigError",
            details={"db_risk_level": env_config.get("db_risk_level")},
            remediation=[
                "Set `db_risk_level` to `test`, `dev`, or `prod` in the "
                "active environment.",
            ],
        )
        raise typer.Exit(1) from None

    if policy.allow_without_flag:
        return
    if policy.require_flag:
        if allow_mutation:
            return
        confirmation_required_error_fn(
            global_config,
            operation,
            f"{action} requires --allow-mutation when db_risk_level=dev.",
            remediation=[
                "Retry with `--allow-mutation` after reviewing the target environment.",
            ],
        )

    print_command_error_result_fn(
        global_config,
        operation,
        "Runtime DB mutation is forbidden when db_risk_level=prod.",
        error_type="MutationForbidden",
        details=details,
        remediation=[
            "Use a read-only planning or inspection command instead.",
            "Run the mutation against a non-production environment if it is intended.",
        ],
    )
    raise typer.Exit(1) from None
