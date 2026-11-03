"""Branch-aware database command implementations."""

from __future__ import annotations

import json
from typing import Any, NoReturn

import typer

from ...branch_database import BranchDatabaseError
from ...cli_types import OutputFormat
from ...exceptions import ConfigError
from ...output import print_error, print_info


def branch_database_status_command(
    ctx: typer.Context,
    *,
    resolve_command_env_config_fn: Any,
    build_branch_database_manager_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Report branch database status without creating or deleting databases."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    try:
        manager = build_branch_database_manager_fn(global_config)
        if manager is None:
            raise BranchDatabaseError("Branch database resolution is unavailable.")
        result = manager.status()
    except (BranchDatabaseError, ConfigError) as error:
        _report_exception(
            global_config,
            "branch_db_status",
            error,
            print_command_error_result_fn,
        )

    _emit_result(global_config, result)
    if not result.get("success", False):
        raise typer.Exit(1)


def branch_database_ensure_command(
    ctx: typer.Context,
    *,
    allow_mutation: bool,
    resolve_command_env_config_fn: Any,
    ensure_branch_database_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Ensure the effective branch database exists."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    try:
        result = ensure_branch_database_fn(
            global_config,
            allow_mutation=allow_mutation,
            operation="branch_db_ensure",
            action="branch database creation",
        )
    except (BranchDatabaseError, ConfigError) as error:
        _report_exception(
            global_config,
            "branch_db_ensure",
            error,
            print_command_error_result_fn,
        )

    _emit_result(global_config, result)
    if not result.get("success", False):
        raise typer.Exit(1)


def branch_database_gc_command(
    ctx: typer.Context,
    *,
    apply: bool,
    allow_mutation: bool,
    resolve_command_env_config_fn: Any,
    build_branch_database_manager_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """List stale managed databases or explicitly drop them through Odoo."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    try:
        manager = build_branch_database_manager_fn(global_config)
        if manager is None:
            raise BranchDatabaseError("Branch database resolution is unavailable.")
        candidates = manager.gc_candidates()
        if apply and candidates:
            require_cli_runtime_db_mutation_fn(
                global_config=global_config,
                env_config=env_config,
                allow_mutation=allow_mutation,
                operation="branch_db_gc",
                action="branch database cleanup",
                print_command_error_result_fn=print_command_error_result_fn,
                confirmation_required_error_fn=confirmation_required_error_fn,
            )
        result = manager.gc(apply=apply)
    except (BranchDatabaseError, ConfigError) as error:
        _report_exception(
            global_config,
            "branch_db_gc",
            error,
            print_command_error_result_fn,
        )

    _emit_result(global_config, result)
    if not result.get("success", False):
        raise typer.Exit(1)


def _emit_result(global_config: Any, result: dict[str, Any]) -> None:
    if global_config.format == OutputFormat.JSON:
        print(json.dumps(result))
        return

    operation = result.get("operation")
    if operation == "branch_db_gc":
        _print_gc(result)
        return
    if not result.get("success", False):
        print_error(result.get("error", "Branch database operation failed."))
        for remediation in result.get("remediation", []):
            print_info(f"Remediation: {remediation}")
        return

    if operation == "branch_db_status":
        _print_status(result)
    elif result.get("created"):
        print_info(f"Created branch database '{result.get('database')}'.")
    elif result.get("enabled"):
        print_info(f"Branch database '{result.get('database')}' is ready.")
    else:
        print_info(
            result.get("message", "Branch-aware database management is disabled.")
        )


def _print_status(result: dict[str, Any]) -> None:
    print_info(
        f"Branch-aware database: {'enabled' if result['enabled'] else 'disabled'}"
    )
    print_info(f"Git branch: {result.get('branch') or '(not available)'}")
    print_info(f"Base branch: {result.get('base_branch')}")
    print_info(f"Base database: {result.get('base_database')}")
    print_info(f"Effective database: {result.get('database')}")
    exists = result.get("exists")
    exists_text = "not checked" if exists is None else ("yes" if exists else "no")
    print_info(f"Database exists: {exists_text}")
    print_info(f"Managed by oduit: {'yes' if result.get('managed') else 'no'}")


def _print_gc(result: dict[str, Any]) -> None:
    candidates = result.get("candidates", [])
    if result.get("dry_run"):
        print_info(f"Branch database GC dry run: {len(candidates)} candidate(s).")
        for candidate in candidates:
            print_info(f"  {candidate['branch']}: {candidate['database']}")
    else:
        print_info(
            f"Branch database GC deleted {len(result.get('deleted', []))} database(s)."
        )
        for error in result.get("errors", []):
            print_error(f"Could not drop '{error['database']}': {error['error']}")


def _report_exception(
    global_config: Any,
    operation: str,
    error: Exception,
    print_command_error_result_fn: Any,
) -> NoReturn:
    print_command_error_result_fn(
        global_config,
        operation,
        str(error),
        error_type=type(error).__name__,
    )
    raise typer.Exit(1) from None
