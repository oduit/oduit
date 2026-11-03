"""Classic CLI support for preparing branch-aware databases."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import typer

from ..branch_database import (
    BranchDatabaseError,
    BranchDatabaseManager,
    parse_branch_database_settings,
)
from ..cli_types import GlobalConfig
from ..exceptions import ConfigError


def build_branch_database_manager(
    global_config: GlobalConfig,
    build_odoo_operations_fn: Any,
) -> BranchDatabaseManager | None:
    """Build the branch database manager for a resolved classic config."""
    resolution = global_config.branch_database
    if resolution is None:
        return None

    base_env_config = global_config.base_env_config or global_config.env_config or {}
    settings = parse_branch_database_settings(base_env_config)

    def operations_factory(env_config: dict[str, Any]) -> Any:
        return build_odoo_operations_fn(replace(global_config, env_config=env_config))

    return BranchDatabaseManager(
        base_env_config,
        resolution,
        settings,
        operations_factory,
        config_path=global_config.config_path,
    )


def ensure_branch_database(
    global_config: GlobalConfig,
    *,
    allow_mutation: bool,
    operation: str,
    action: str,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> dict[str, Any]:
    """Ensure a branch database, authorizing only a needed feature clone."""
    manager = build_branch_database_manager(global_config, build_odoo_operations_fn)
    if manager is None:
        return {
            "success": False,
            "operation": operation,
            "error": "Branch database resolution is unavailable.",
            "error_type": "BranchDatabaseResolutionError",
        }

    def authorize_clone() -> None:
        require_cli_runtime_db_mutation_fn(
            global_config=global_config,
            env_config=(
                global_config.env_config or global_config.base_env_config or {}
            ),
            allow_mutation=allow_mutation,
            operation=operation,
            action=action,
            print_command_error_result_fn=print_command_error_result_fn,
            confirmation_required_error_fn=confirmation_required_error_fn,
        )

    return manager.ensure(before_duplicate=authorize_clone)


def prepare_branch_database(
    global_config: GlobalConfig,
    *,
    allow_mutation: bool,
    operation: str,
    action: str,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> GlobalConfig:
    """Ensure the active branch database exists before a runtime workflow."""
    resolution = global_config.branch_database
    if resolution is None or not resolution.enabled:
        return global_config

    try:
        result = ensure_branch_database(
            global_config,
            allow_mutation=allow_mutation,
            operation=operation,
            action=action,
            build_odoo_operations_fn=build_odoo_operations_fn,
            require_cli_runtime_db_mutation_fn=require_cli_runtime_db_mutation_fn,
            confirmation_required_error_fn=confirmation_required_error_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )
        if not result.get("success", False):
            _report_failure(
                global_config,
                operation,
                result,
                print_command_error_result_fn,
            )
    except (BranchDatabaseError, ConfigError) as error:
        print_command_error_result_fn(
            global_config,
            operation,
            str(error),
            error_type=type(error).__name__,
            details={
                "branch": resolution.branch,
                "database": resolution.database,
                "base_database": resolution.base_database,
            },
        )
        raise typer.Exit(1) from None

    return global_config


def _report_failure(
    global_config: GlobalConfig,
    operation: str,
    result: dict[str, Any],
    print_command_error_result_fn: Any,
) -> None:
    print_command_error_result_fn(
        global_config,
        operation,
        result.get("error", "Branch database preparation failed."),
        error_type=result.get("error_type", "BranchDatabaseError"),
        details={
            "branch": result.get("branch"),
            "database": result.get("database"),
            "base_database": result.get("base_database"),
        },
        remediation=result.get("remediation"),
    )
    raise typer.Exit(1) from None
