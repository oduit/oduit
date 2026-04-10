# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""New Typer-based CLI implementation for oduit."""

import os
from typing import Any, NoReturn

import typer
from manifestoo_core.odoo_series import OdooSeries

from .addons_path_manager import AddonsPathManager
from .cli.addon_filters import (
    VALID_FILTER_FIELDS,
    apply_core_addon_filters,
    apply_field_filters,
    build_addon_table,
    get_addon_field_value,
    get_addon_type,
)
from .cli.agent import validate as _agent_validate_impl
from .cli.agent.mutate import (
    agent_create_addon_command as _agent_create_addon_command,
)
from .cli.agent.mutate import (
    agent_export_lang_command as _agent_export_lang_command,
)
from .cli.agent.mutate import (
    agent_install_module_command as _agent_install_module_command,
)
from .cli.agent.mutate import (
    agent_test_summary_command as _agent_test_summary_command,
)
from .cli.agent.mutate import (
    agent_update_module_command as _agent_update_module_command,
)
from .cli.agent.payloads import (
    agent_emit_payload as _agent_emit_payload_impl,
)
from .cli.agent.payloads import (
    agent_fail as _agent_fail_impl,
)
from .cli.agent.payloads import (
    agent_payload as _agent_payload_impl,
)
from .cli.agent.payloads import (
    build_error_output_excerpt as _build_error_output_excerpt_impl,
)
from .cli.agent.payloads import (
    parse_csv_items as _parse_csv_items_impl,
)
from .cli.agent.payloads import (
    parse_json_list_option as _parse_json_list_option_impl,
)
from .cli.agent.payloads import (
    parse_view_types as _parse_view_types_impl,
)
from .cli.agent.payloads import (
    redact_config as _redact_config_impl,
)
from .cli.agent.payloads import (
    strip_arch_from_model_views as _strip_arch_from_model_views_impl,
)
from .cli.agent.query import (
    agent_get_model_fields_command as _agent_get_model_fields_command,
)
from .cli.agent.query import (
    agent_query_model_command as _agent_query_model_command,
)
from .cli.agent.query import (
    agent_read_record_command as _agent_read_record_command,
)
from .cli.agent.query import (
    agent_search_count_command as _agent_search_count_command,
)
from .cli.agent.read_only import (
    agent_context_command as _agent_context_command,
)
from .cli.agent.read_only import (
    agent_dependency_graph_command as _agent_dependency_graph_command,
)
from .cli.agent.read_only import (
    agent_doctor_command as _agent_doctor_command,
)
from .cli.agent.read_only import (
    agent_find_model_extensions_command as _agent_find_model_extensions_command,
)
from .cli.agent.read_only import (
    agent_get_model_views_command as _agent_get_model_views_command,
)
from .cli.agent.read_only import (
    agent_inspect_addon_command as _agent_inspect_addon_command,
)
from .cli.agent.read_only import (
    agent_inspect_addons_command as _agent_inspect_addons_command,
)
from .cli.agent.read_only import (
    agent_list_addon_models_command as _agent_list_addon_models_command,
)
from .cli.agent.read_only import (
    agent_list_addon_tests_command as _agent_list_addon_tests_command,
)
from .cli.agent.read_only import (
    agent_list_addons_command as _agent_list_addons_command,
)
from .cli.agent.read_only import (
    agent_list_duplicates_command as _agent_list_duplicates_command,
)
from .cli.agent.read_only import (
    agent_locate_field_command as _agent_locate_field_command,
)
from .cli.agent.read_only import (
    agent_locate_model_command as _agent_locate_model_command,
)
from .cli.agent.read_only import (
    agent_plan_update_command as _agent_plan_update_command,
)
from .cli.agent.read_only import (
    agent_resolve_config_command as _agent_resolve_config_command,
)
from .cli.agent.services import (
    agent_require_mutation as _agent_require_mutation_impl,
)
from .cli.agent.services import (
    agent_sub_result as _agent_sub_result_impl,
)
from .cli.agent.services import (
    build_agent_test_summary_details as _build_agent_test_summary_details_impl,
)
from .cli.agent.services import (
    parse_filter_values as _parse_filter_values_impl,
)
from .cli.agent.services import (
    require_agent_addons_path as _require_agent_addons_path_impl,
)
from .cli.agent.services import (
    resolve_agent_global_config as _resolve_agent_global_config_impl,
)
from .cli.agent.services import (
    resolve_agent_ops as _resolve_agent_ops_impl,
)
from .cli.app import agent_app, app
from .cli.commands.addons import (
    create_addon_command as _create_addon_command_impl,
)
from .cli.commands.addons import (
    list_addons_command as _list_addons_command_impl,
)
from .cli.commands.addons import (
    list_duplicates_command as _list_duplicates_command_impl,
)
from .cli.commands.addons import (
    list_manifest_values_command as _list_manifest_values_command_impl,
)
from .cli.commands.addons import (
    print_manifest_command as _print_manifest_command_impl,
)
from .cli.commands.database import (
    create_db_command as _create_db_command_impl,
)
from .cli.commands.database import list_db_command as _list_db_command_impl
from .cli.commands.database import list_env_command as _list_env_command_impl
from .cli.commands.database import (
    print_config_command as _print_config_command_impl,
)
from .cli.commands.dependencies import (
    impact_of_update_command as _impact_of_update_command_impl,
)
from .cli.commands.dependencies import (
    install_order_command as _install_order_command_impl,
)
from .cli.commands.dependencies import (
    list_codepends_command as _list_codepends_command_impl,
)
from .cli.commands.dependencies import (
    list_depends_command as _list_depends_command_impl,
)
from .cli.commands.dependencies import (
    list_missing_command as _list_missing_command_impl,
)
from .cli.commands.runtime import doctor_command as _doctor_command_impl
from .cli.commands.runtime import export_lang_command as _export_lang_command_impl
from .cli.commands.runtime import (
    get_odoo_version_command as _get_odoo_version_command_impl,
)
from .cli.commands.runtime import install_command as _install_command_impl
from .cli.commands.runtime import run_command as _run_command_impl
from .cli.commands.runtime import shell_command as _shell_command_impl
from .cli.commands.runtime import test_command as _test_command_impl
from .cli.commands.runtime import update_command as _update_command_impl
from .cli.dependency_output import print_dependency_list, print_dependency_tree
from .cli.doctor import (
    build_doctor_report,
    print_doctor_report,
)
from .cli.errors import (
    confirmation_required_error,
    dependency_error_details,
    print_command_error_result,
)
from .cli.init_env import (
    build_initial_config,
    check_environment_exists,
    detect_binaries,
    display_config_summary,
    import_or_convert_config,
    normalize_addons_path,
    save_config_file,
)
from .cli.init_env import (
    init_env_command as _init_env_command_impl,
)
from .cli_types import (
    AddonTemplate,
    DevFeature,
    GlobalConfig,
    LogLevel,
    OutputFormat,
    ShellInterface,
)
from .config_loader import ConfigLoader
from .exceptions import ConfigError
from .exceptions import ModuleNotFoundError as OduitModuleNotFoundError
from .module_manager import ModuleManager
from .odoo_operations import OdooOperations
from .output import configure_output, print_error
from .schemas import (
    CONTROLLED_RUNTIME_MUTATION,
    CONTROLLED_SOURCE_MUTATION,
    SAFE_READ_ONLY,
)
from .utils import output_result_to_json, validate_addon_name

SHELL_INTERFACE_OPTION = typer.Option(
    "python",
    "--shell-interface",
    help="Shell interface to use (overrides config setting)",
)

ADDON_TEMPLATE_OPTION = typer.Option(
    AddonTemplate.BASIC, "--template", help="Addon template to use"
)

LOG_LEVEL_OPTION = typer.Option(
    None,
    "--log-level",
    "-l",
    help="Set Odoo log level",
)

LANGUAGE_OPTION = typer.Option(
    None,
    "--language",
    "--lang",
    help="Set language (e.g., 'de_DE', 'en_US')",
)


DEV_OPTION = typer.Option(
    None,
    "--dev",
    "-d",
    help=(
        "Comma-separated list of dev features (e.g., 'all', 'xml', 'reload,qweb'). "
        "Available: all, xml, reload, qweb, ipdb, pdb, pudb, werkzeug. "
        "For development only - do not use in production."
    ),
)

ODOO_SERIES_OPTION = typer.Option(
    None,
    "--odoo-series",
    envvar=["ODOO_VERSION", "ODOO_SERIES"],
    help="Odoo series to use, in case it is not autodetected from addons version.",
)

SORT_OPTION = typer.Option(
    "alphabetical",
    "--sort",
    help="Choice between 'alphabetical' and 'topological'. "
    "Topological sorting is useful when seeking a migration order.",
    show_default=True,
)

# Pre-computed help string for filter options
_VALID_FILTER_FIELDS_STR = (
    "name, version, summary, author, website, license, "
    "category, module_path, depends, addon_type"
)

INCLUDE_FILTER_OPTION = typer.Option(
    [],
    "--include",
    help=(
        "Include filter as 'FIELD:VALUE'. Can be used multiple times. "
        f"Valid fields: {_VALID_FILTER_FIELDS_STR}"
    ),
)

EXCLUDE_FILTER_OPTION = typer.Option(
    [],
    "--exclude",
    help=(
        "Exclude filter as 'FIELD:VALUE'. Can be used multiple times. "
        f"Valid fields: {_VALID_FILTER_FIELDS_STR}"
    ),
)


def _resolve_config_source(
    config_loader: ConfigLoader,
    env: str | None,
    env_config: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
    """Resolve where the active configuration came from."""
    config_path = None
    source = "local" if env is None else "env"

    if env is None:
        if config_loader.has_local_config():
            try:
                config_path = config_loader.get_local_config_path()
            except Exception:
                config_path = os.path.abspath(".oduit.toml")
    else:
        resolved_path = None
        try:
            resolved = config_loader.resolve_config_path(env.strip())
            if isinstance(resolved, tuple) and len(resolved) == 2:
                resolved_path = resolved[0]
        except Exception:
            resolved_path = None

        if isinstance(resolved_path, str) and os.path.exists(resolved_path):
            config_path = os.path.abspath(resolved_path)

    if env_config and env_config.get("demo_mode", False):
        source = "demo"

    return source, config_path


def _print_command_error_result(
    global_config: GlobalConfig,
    operation: str,
    message: str,
    error_type: str = "CommandError",
    details: dict[str, Any] | None = None,
    remediation: list[str] | None = None,
) -> None:
    """Print a command error in text or JSON mode."""
    print_command_error_result(
        global_config,
        operation,
        message,
        error_type=error_type,
        details=details,
        remediation=remediation,
    )


def _dependency_error_details(
    module_manager: ModuleManager, message: str
) -> dict[str, Any]:
    """Build structured details for dependency-related CLI failures."""
    return dependency_error_details(module_manager, message)


def _confirmation_required_error(
    global_config: GlobalConfig,
    operation: str,
    message: str,
    remediation: list[str],
) -> None:
    """Fail fast when non-interactive mode forbids prompting."""
    confirmation_required_error(global_config, operation, message, remediation)


def _build_doctor_report(global_config: GlobalConfig) -> dict[str, Any]:
    """Build a diagnostics report for the active configuration."""
    return build_doctor_report(
        global_config,
        addons_path_manager_cls=AddonsPathManager,
        module_manager_cls=ModuleManager,
        odoo_operations_cls=OdooOperations,
    )


def _print_doctor_report(report: dict[str, Any]) -> None:
    """Render a doctor report in text mode."""
    print_doctor_report(report)


def create_global_config(
    env: str | None = None,
    json: bool = False,
    non_interactive: bool = False,
    verbose: bool = False,
    no_http: bool = False,
    odoo_series: OdooSeries | None = None,
) -> GlobalConfig:
    """Create and validate global configuration."""

    # Configure output based on arguments
    format = OutputFormat.JSON if json else OutputFormat.TEXT
    configure_output(
        format_type=format.value,
        non_interactive=True,
    )

    # Handle environment and config loading
    env_config = None
    env_name = None
    config_loader = ConfigLoader()

    if env is None:
        if config_loader.has_local_config():
            if verbose:
                typer.echo("Using local .oduit.toml configuration")
            try:
                env_config = config_loader.load_local_config()
                env_name = "local"
            except (FileNotFoundError, ImportError, ValueError) as e:
                print_error(f"[ERROR] {str(e)}")
                raise typer.Exit(1) from e
        else:
            print_error(
                "No environment specified and no .oduit.toml found in current directory"
            )
            raise typer.Exit(1) from None
    else:
        env_name = env.strip()
        try:
            env_config = config_loader.load_config(env_name)
        except (FileNotFoundError, ImportError, ValueError) as e:
            print_error(f"[ERROR] {str(e)}")
            raise typer.Exit(1) from e
        except Exception as e:
            print_error(f"Error loading environment '{env_name}': {str(e)}")
            raise typer.Exit(1) from e

    config_source, config_path = _resolve_config_source(config_loader, env, env_config)

    return GlobalConfig(
        env=env,
        non_interactive=non_interactive,
        format=format,
        verbose=verbose,
        no_http=no_http,
        env_config=env_config,
        env_name=env_name,
        odoo_series=odoo_series,
        config_source=config_source,
        config_path=config_path,
    )


def _resolve_command_global_config(ctx: typer.Context) -> GlobalConfig:
    """Resolve command context into a `GlobalConfig` instance."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            return create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as exc:
            print_error(f"Failed to create global config: {exc}")
            raise typer.Exit(1) from None

    if not isinstance(ctx.obj, GlobalConfig):
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    return ctx.obj


def _resolve_command_env_config(
    ctx: typer.Context,
) -> tuple[GlobalConfig, dict[str, Any]]:
    """Resolve command context and require an environment configuration."""
    global_config = _resolve_command_global_config(ctx)
    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    return global_config, global_config.env_config


def _build_odoo_operations(global_config: GlobalConfig) -> OdooOperations:
    """Build an operations facade from resolved global config."""
    assert global_config.env_config is not None
    return OdooOperations(global_config.env_config, verbose=global_config.verbose)


# App objects are defined in oduit.cli.app and re-exported here.


def _agent_emit_payload(payload: dict[str, Any]) -> None:
    """Print a structured agent payload."""
    _agent_emit_payload_impl(payload)


def _agent_fail(
    operation: str,
    result_type: str,
    message: str,
    error_type: str = "CommandError",
    details: dict[str, Any] | None = None,
    remediation: list[str] | None = None,
    read_only: bool = True,
    safety_level: str = SAFE_READ_ONLY,
) -> NoReturn:
    """Emit a structured agent error payload and exit."""
    _agent_fail_impl(
        operation,
        result_type,
        message,
        error_type=error_type,
        details=details,
        remediation=remediation,
        read_only=read_only,
        safety_level=safety_level,
        emit_payload_fn=_agent_emit_payload,
    )


def _agent_payload(
    operation: str,
    result_type: str,
    data: dict[str, Any],
    *,
    success: bool = True,
    warnings: list[str] | None = None,
    errors: list[dict[str, Any]] | None = None,
    remediation: list[str] | None = None,
    read_only: bool = True,
    safety_level: str = SAFE_READ_ONLY,
    error: str | None = None,
    error_type: str | None = None,
    include_null_values: bool = False,
    exclude_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Build a structured agent payload using the shared JSON envelope."""
    return _agent_payload_impl(
        operation,
        result_type,
        data,
        success=success,
        warnings=warnings,
        errors=errors,
        remediation=remediation,
        read_only=read_only,
        safety_level=safety_level,
        error=error,
        error_type=error_type,
        include_null_values=include_null_values,
        exclude_fields=exclude_fields,
    )


def _build_error_output_excerpt(
    result: dict[str, Any], *, max_lines: int = 80, max_chars: int = 12000
) -> list[str]:
    """Return a bounded tail excerpt from captured process output."""
    return _build_error_output_excerpt_impl(
        result, max_lines=max_lines, max_chars=max_chars
    )


def _resolve_agent_global_config(
    ctx: typer.Context,
    operation: str,
    result_type: str,
) -> GlobalConfig:
    """Resolve configuration for agent commands without emitting text output."""
    return _resolve_agent_global_config_impl(
        ctx,
        operation,
        result_type,
        configure_output_fn=configure_output,
        fail_fn=_agent_fail,
        config_loader_cls=ConfigLoader,
        resolve_config_source_fn=_resolve_config_source,
    )


def _parse_csv_items(raw_value: str | None) -> list[str] | None:
    """Parse a comma-separated CLI option into a list of strings."""
    return _parse_csv_items_impl(raw_value)


def _parse_view_types(
    raw_value: str | None, operation: str, result_type: str
) -> list[str] | None:
    """Parse and validate requested Odoo view types."""
    return _parse_view_types_impl(
        raw_value, operation, result_type, fail_fn=_agent_fail
    )


def _strip_arch_from_model_views(data: dict[str, Any]) -> dict[str, Any]:
    """Remove nested ``arch_db`` fields from model view payloads."""
    return _strip_arch_from_model_views_impl(data)


def _parse_json_list_option(
    raw_value: str | None,
    option_name: str,
    operation: str,
    result_type: str,
) -> list[Any]:
    """Parse a JSON-encoded list option or emit a structured error."""
    return _parse_json_list_option_impl(
        raw_value,
        option_name,
        operation,
        result_type,
        fail_fn=_agent_fail,
    )


def _resolve_agent_ops(
    ctx: typer.Context,
    operation: str,
    result_type: str,
) -> tuple[GlobalConfig, OdooOperations]:
    """Resolve agent config and instantiate operations."""
    return _resolve_agent_ops_impl(
        ctx,
        operation,
        result_type,
        resolve_agent_global_config_fn=_resolve_agent_global_config,
        fail_fn=_agent_fail,
        odoo_operations_cls=OdooOperations,
    )


def _parse_filter_values(
    raw_values: list[str], option_name: str
) -> list[tuple[str, str]]:
    """Parse repeated FIELD:VALUE filter options."""
    return _parse_filter_values_impl(raw_values, option_name)


def _require_agent_addons_path(
    env_config: dict[str, Any],
    operation: str,
    result_type: str,
) -> str:
    """Return ``addons_path`` or emit a structured config error."""
    return _require_agent_addons_path_impl(
        env_config, operation, result_type, fail_fn=_agent_fail
    )


def _redact_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return a recursively redacted configuration dictionary."""
    return _redact_config_impl(config)


def _agent_require_mutation(
    allow_mutation: bool,
    operation: str,
    result_type: str,
    action: str,
    safety_level: str,
) -> None:
    """Enforce an explicit allow-mutation gate for agent mutation commands."""
    _agent_require_mutation_impl(
        allow_mutation,
        operation,
        result_type,
        action,
        safety_level,
        fail_fn=_agent_fail,
    )


def _agent_sub_result(
    *,
    success: bool,
    data: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
    errors: list[dict[str, Any]] | None = None,
    remediation: list[str] | None = None,
    error: str | None = None,
    error_type: str | None = None,
    read_only: bool = True,
    safety_level: str = SAFE_READ_ONLY,
    skipped: bool = False,
) -> dict[str, Any]:
    """Build a normalized sub-result for aggregate agent payloads."""
    return _agent_sub_result_impl(
        success=success,
        data=data,
        warnings=warnings,
        errors=errors,
        remediation=remediation,
        error=error,
        error_type=error_type,
        read_only=read_only,
        safety_level=safety_level,
        skipped=skipped,
    )


def _build_agent_test_summary_details(
    result: dict[str, Any],
    *,
    module: str | None,
    install: str | None,
    update: str | None,
    coverage: str | None,
    test_file: str | None,
    test_tags: str | None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Normalize ``run_tests()`` output for agent-facing summaries."""
    return _build_agent_test_summary_details_impl(
        result,
        module=module,
        install=install,
        update=update,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
        build_error_output_excerpt_fn=_build_error_output_excerpt,
    )


def _build_validate_addon_change_payload(
    module: str,
    *,
    install_if_needed: bool,
    update: bool,
    resolved_test_tags: str | None,
    discover_tests: bool,
    installed_state: dict[str, Any] | None,
    mutation_action: dict[str, Any],
    sub_results: dict[str, dict[str, Any]],
    completed_steps: list[str],
    failed_step: str | None,
) -> tuple[
    dict[str, Any],
    bool,
    list[str],
    list[dict[str, Any]],
    list[str],
    str | None,
    str | None,
]:
    """Assemble the aggregate payload data for addon-change validation."""
    return _agent_validate_impl.build_validate_addon_change_payload(
        module,
        install_if_needed=install_if_needed,
        update=update,
        resolved_test_tags=resolved_test_tags,
        discover_tests=discover_tests,
        installed_state=installed_state,
        mutation_action=mutation_action,
        sub_results=sub_results,
        completed_steps=completed_steps,
        failed_step=failed_step,
    )


def _run_validate_addon_change_preflight(
    ops: OdooOperations,
    global_config: GlobalConfig,
    module: str,
    *,
    agent_sub_result_fn: Any = _agent_sub_result,
    build_doctor_report_fn: Any = _build_doctor_report,
    module_not_found_error_cls: Any = OduitModuleNotFoundError,
    config_error_cls: Any = ConfigError,
) -> tuple[
    dict[str, dict[str, Any]],
    list[str],
    str | None,
    dict[str, Any] | None,
]:
    """Run inspect, doctor, duplicate, and installed-state checks."""
    return _agent_validate_impl.run_validate_addon_change_preflight(
        ops,
        global_config,
        module,
        agent_sub_result_fn=agent_sub_result_fn,
        build_doctor_report_fn=build_doctor_report_fn,
        module_not_found_error_cls=module_not_found_error_cls,
        config_error_cls=config_error_cls,
    )


def _build_validate_addon_change_discovery_result(
    ops: OdooOperations,
    module: str,
    *,
    discover_tests: bool,
    failed_step: str | None,
    agent_sub_result_fn: Any = _agent_sub_result,
    module_not_found_error_cls: Any = OduitModuleNotFoundError,
    config_error_cls: Any = ConfigError,
) -> tuple[dict[str, Any], str | None, bool]:
    """Build the optional discovered-test sub-result."""
    return _agent_validate_impl.build_validate_addon_change_discovery_result(
        ops,
        module,
        discover_tests=discover_tests,
        failed_step=failed_step,
        agent_sub_result_fn=agent_sub_result_fn,
        module_not_found_error_cls=module_not_found_error_cls,
        config_error_cls=config_error_cls,
    )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    env: str | None = typer.Option(
        None,
        "--env",
        "-e",
        help=(
            "Environment to use (e.g. prod, test). "
            "If not provided, looks for .oduit.toml in current directory"
        ),
    ),
    json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output in JSON format",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Fail instead of prompting for confirmation",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show verbose output including configuration and command details",
    ),
    no_http: bool = typer.Option(
        False,
        "--no-http",
        help="Add --no-http flag to all odoo-bin commands",
    ),
    odoo_series: OdooSeries | None = ODOO_SERIES_OPTION,
) -> None:
    """Odoo CLI tool for starting odoo-bin and running tasks."""

    # Store config info in context for subcommands
    ctx.obj = {
        "env": env,
        "json": json,
        "non_interactive": non_interactive,
        "verbose": verbose,
        "no_http": no_http,
        "odoo_series": odoo_series,
    }
    if not ctx.invoked_subcommand:
        config_loader = ConfigLoader()
        has_local = config_loader.has_local_config()

        if has_local:
            print("Available commands:")
            print("  init ENV           Initialize new environment")
            print("  run                Run Odoo server")
            print("  shell              Start Odoo shell")
            print("  install MODULE     Install a module")
            print("  update MODULE      Update a module")
            print("  test               Run tests")
            print("  create-db          Create database")
            print("  list-db            List databases")
            print("  list-env           List available environments")
            print("  doctor             Diagnose environment issues")
            print("  create-addon NAME  Create new addon")
            print("  list-addons        List available addons")
            print("  print-manifest NAME   Print addon manifest information")
            print("  list-depends MODULES   List direct dependencies for installation")
            print("  install-order MODULES Dependency-resolved install order")
            print("  list-codepends MODULE  List reverse dependencies of a module")
            print("  impact-of-update MODULE  Addons affected by an update")
            print("  list-missing MODULES   Find missing dependencies")
            print("  list-duplicates     List duplicate addon names")
            print("  export-lang MODULE Export language translations")
            print("  print-config       Print environment configuration")
            print("  agent ...          Structured agent-first inspection commands")
            print("")
            print("Examples:")
            print("  oduit run                         # Run with local .oduit.toml")
            print("  oduit test --test-tags /sale      # Test sale module")
            print("  oduit update sale                 # Update sale module")
        else:
            print_error(
                "No command specified and no .oduit.toml found in current directory"
            )
            print("")
            print("Usage: oduit [--env ENV] COMMAND [arguments]")
            print("")
            print("Available commands:")
            print(
                "  init, run, shell, install, update, test, create-db, "
                "list-db, list-env, doctor"
            )
            print(
                "  create-addon, list-addons, print-manifest, list-depends, "
                "install-order, list-codepends, impact-of-update, list-missing, "
                "list-duplicates"
            )
            print("  export-lang, print-config, agent")
            print("")
            print("Examples:")
            print("  oduit --env dev run               # Run Odoo server")
            print("  oduit --env dev update sale       # Update module 'sale'")
        raise typer.Exit(1) from None


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Diagnose environment and configuration issues."""
    _doctor_command_impl(
        ctx,
        resolve_command_global_config_fn=_resolve_command_global_config,
        build_doctor_report_fn=_build_doctor_report,
        print_doctor_report_fn=_print_doctor_report,
    )


@app.command()
def run(
    ctx: typer.Context,
    dev: DevFeature | None = DEV_OPTION,
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    stop_after_init: bool = typer.Option(
        False,
        "--stop-after-init",
        "-s",
        help="Stop the server after initialization",
    ),
) -> None:
    """Run Odoo server."""
    _run_command_impl(
        ctx,
        dev=dev,
        log_level=log_level,
        stop_after_init=stop_after_init,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
    )


@app.command()
def shell(
    ctx: typer.Context,
    shell_interface: ShellInterface | None = SHELL_INTERFACE_OPTION,
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Suppress INFO logs at startup for cleaner output",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Start Odoo shell."""
    _shell_command_impl(
        ctx,
        shell_interface=shell_interface,
        compact=compact,
        log_level=log_level,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
    )


@app.command()
def install(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to install"),
    without_demo: str | None = typer.Option(
        None, "--without-demo", help="Install without demo data"
    ),
    with_demo: bool = typer.Option(
        False, "--with-demo", help="Install with demo data (overrides config)"
    ),
    language: str | None = LANGUAGE_OPTION,
    max_cron_threads: int | None = typer.Option(
        None,
        "--max-cron-threads",
        help="Set maximum cron threads for Odoo server",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    compact: bool = typer.Option(
        False, "--compact", help="Suppress INFO logs at startup for cleaner output"
    ),
    include_command: bool = typer.Option(
        False, "--include-command", help="Include executed command in result JSON"
    ),
    include_stdout: bool = typer.Option(
        False, "--include-stdout", help="Include stdout in result JSON"
    ),
) -> None:
    """Install module."""
    _install_command_impl(
        ctx,
        module=module,
        without_demo=without_demo,
        with_demo=with_demo,
        language=language,
        max_cron_threads=max_cron_threads,
        log_level=log_level,
        compact=compact,
        include_command=include_command,
        include_stdout=include_stdout,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
    )


@app.command()
def update(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to update"),
    without_demo: str | None = typer.Option(
        None, "--without-demo", help="Update without demo data"
    ),
    language: str | None = LANGUAGE_OPTION,
    i18n_overwrite: bool = typer.Option(
        False, "--i18n-overwrite", help="Overwrite existing translations during update"
    ),
    max_cron_threads: int | None = typer.Option(
        None,
        "--max-cron-threads",
        help="Set maximum cron threads for Odoo server",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Suppress INFO logs at startup for cleaner output",
    ),
) -> None:
    """Update module."""
    _update_command_impl(
        ctx,
        module=module,
        without_demo=without_demo,
        language=language,
        i18n_overwrite=i18n_overwrite,
        max_cron_threads=max_cron_threads,
        log_level=log_level,
        compact=compact,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
    )


@app.command()
def test(
    ctx: typer.Context,
    stop_on_error: bool = typer.Option(
        False,
        "--stop-on-error",
        help="Abort test run on first detected failure in output",
    ),
    install: str | None = typer.Option(
        None,
        "--install",
        help="Install specified addon before testing",
    ),
    update: str | None = typer.Option(
        None,
        "--update",
        help="Update specified addon before testing",
    ),
    coverage: str | None = typer.Option(
        None,
        "--coverage",
        help="Run coverage report for specified module after tests",
    ),
    test_file: str | None = typer.Option(
        None,
        "--test-file",
        help="Run a specific Python test file",
    ),
    test_tags: str | None = typer.Option(
        None,
        "--test-tags",
        help="Comma-separated list of specs to filter tests",
    ),
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Show only test progress dots, statistics, and result summaries",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    include_command: bool = typer.Option(
        False, "--include-command", help="Include executed command in result JSON"
    ),
    include_stdout: bool = typer.Option(
        False, "--include-stdout", help="Include stdout in result JSON"
    ),
) -> None:
    """Run module tests with various options.

    Examples:
      oduit test --test-tags /sale                     # Test sale
      oduit test --test-tags /sale --coverage sale     # With coverage
      oduit test --install sale --test-tags /sale      # Install & test
    """
    _test_command_impl(
        ctx,
        stop_on_error=stop_on_error,
        install=install,
        update=update,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
        compact=compact,
        log_level=log_level,
        include_command=include_command,
        include_stdout=include_stdout,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
    )


@app.command("create-db")
def create_db(
    ctx: typer.Context,
    create_role: bool = typer.Option(
        False,
        "--create-role",
        help="Create DB Role",
    ),
    alter_role: bool = typer.Option(
        False,
        "--alter-role",
        help="Alter DB Role",
    ),
    with_sudo: bool = typer.Option(
        False,
        "--with-sudo",
        help="Use sudo for database creation (if required by PostgreSQL setup)",
    ),
    drop: bool = typer.Option(
        False,
        "--drop",
        help="Drop database if it exists before creating",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Run without confirmation prompt (use with caution)",
    ),
    db_user: str | None = typer.Option(
        None,
        "--db-user",
        help="Specify the database user (overrides config setting)",
    ),
) -> None:
    """Create database."""
    _create_db_command_impl(
        ctx,
        create_role=create_role,
        alter_role=alter_role,
        with_sudo=with_sudo,
        drop=drop,
        non_interactive=non_interactive,
        db_user=db_user,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
        confirmation_required_error_fn=_confirmation_required_error,
    )


@app.command("list-db")
def list_db(
    ctx: typer.Context,
    with_sudo: bool = typer.Option(
        False,
        "--with-sudo/--no-sudo",
        help="Use sudo for database listing (default: False)",
    ),
    db_user: str | None = typer.Option(
        None,
        "--db-user",
        help="Specify the database user (overrides config setting)",
    ),
    include_command: bool = typer.Option(
        False, "--include-command", help="Include executed command in result JSON"
    ),
    include_stdout: bool = typer.Option(
        False, "--include-stdout", help="Include stdout in result JSON"
    ),
) -> None:
    """List all databases."""
    _list_db_command_impl(
        ctx,
        with_sudo=with_sudo,
        db_user=db_user,
        include_command=include_command,
        include_stdout=include_stdout,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
    )


@app.command("list-env")
def list_env() -> None:
    """List available environments."""
    _list_env_command_impl(config_loader_cls=ConfigLoader)


@app.command("print-config")
def print_config_cmd(ctx: typer.Context) -> None:
    """Print environment config."""
    _print_config_command_impl(
        ctx,
        resolve_command_env_config_fn=_resolve_command_env_config,
    )


@app.command("create-addon")
def create_addon(
    ctx: typer.Context,
    addon_name: str = typer.Argument(help="Name of the addon to create"),
    path: str | None = typer.Option(
        None, "--path", help="Path where to create the addon"
    ),
    template: AddonTemplate = ADDON_TEMPLATE_OPTION,
) -> None:
    """Create new addon."""
    _create_addon_command_impl(
        ctx,
        addon_name=addon_name,
        path=path,
        template=template,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
        validate_addon_name_fn=validate_addon_name,
    )


def _get_addon_type(addon_name: str, odoo_series: OdooSeries | None) -> str:
    """Determine the addon type (CE, EE, or Custom)."""
    return get_addon_type(addon_name, odoo_series)


def _build_addon_table(
    addon_name: str,
    manifest: Any,
    addon_type: str,
) -> Any:
    """Build a Rich table with addon information."""
    return build_addon_table(addon_name, manifest, addon_type)


def _get_addon_field_value(
    addon_name: str,
    field: str,
    module_manager: ModuleManager,
    odoo_series: OdooSeries | None = None,
) -> str:
    """Get the value of a specific field for an addon."""
    return get_addon_field_value(addon_name, field, module_manager, odoo_series)


def _apply_core_addon_filters(
    addons: list[str],
    exclude_core_addons: bool,
    exclude_enterprise_addons: bool,
    odoo_series: OdooSeries | None,
) -> list[str]:
    """Apply CE/EE core addon exclusion filters."""
    return apply_core_addon_filters(
        addons,
        exclude_core_addons,
        exclude_enterprise_addons,
        odoo_series,
    )


def _apply_field_filters(
    addons: list[str],
    module_manager: ModuleManager,
    include_filter: list[tuple[str, str]],
    exclude_filter: list[tuple[str, str]],
    odoo_series: OdooSeries | None,
) -> list[str]:
    """Apply include/exclude field filters to addon list."""
    return apply_field_filters(
        addons,
        module_manager,
        include_filter,
        exclude_filter,
        odoo_series,
    )


@app.command("print-manifest")
def print_manifest(
    ctx: typer.Context,
    addon_name: str = typer.Argument(help="Name of the addon to display"),
) -> None:
    """Print addon manifest information in a table.

    Displays key manifest fields including name, version, author, license,
    dependencies, and whether the addon is a core CE/EE addon.
    """
    _print_manifest_command_impl(
        ctx,
        addon_name=addon_name,
        resolve_command_env_config_fn=_resolve_command_env_config,
        module_manager_cls=ModuleManager,
        get_addon_type_fn=_get_addon_type,
        build_addon_table_fn=_build_addon_table,
    )


@app.command("list-addons")
def list_addons(
    ctx: typer.Context,
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter addons by directory (e.g., 'myaddons')",
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    exclude_core_addons: bool = typer.Option(
        False,
        "--exclude-core-addons",
        help="Exclude Odoo Community Edition (CE) core addons from the list",
    ),
    exclude_enterprise_addons: bool = typer.Option(
        False,
        "--exclude-enterprise-addons",
        help="Exclude Odoo Enterprise Edition (EE) addons from the list",
    ),
    include: list[str] = INCLUDE_FILTER_OPTION,
    exclude: list[str] = EXCLUDE_FILTER_OPTION,
    sorting: str = SORT_OPTION,
) -> None:
    """List available addons.

    Filter addons using --include or --exclude with FIELD:VALUE format.

    Examples:

      oduit list-addons --exclude category:Theme

      oduit list-addons --include author:Odoo --include category:Sales
    """
    _list_addons_command_impl(
        ctx,
        select_dir=select_dir,
        separator=separator,
        exclude_core_addons=exclude_core_addons,
        exclude_enterprise_addons=exclude_enterprise_addons,
        include=include,
        exclude=exclude,
        sorting=sorting,
        resolve_command_env_config_fn=_resolve_command_env_config,
        module_manager_cls=ModuleManager,
        apply_core_addon_filters_fn=_apply_core_addon_filters,
        apply_field_filters_fn=_apply_field_filters,
    )


@app.command("list-manifest-values")
def list_manifest_values(
    ctx: typer.Context,
    field: str = typer.Argument(
        help=(
            "Manifest field to list unique values for. "
            f"Valid fields: {_VALID_FILTER_FIELDS_STR}"
        ),
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter addons by directory (e.g., 'myaddons')",
    ),
    exclude_core_addons: bool = typer.Option(
        False,
        "--exclude-core-addons",
        help="Exclude Odoo Community Edition (CE) core addons from the list",
    ),
    exclude_enterprise_addons: bool = typer.Option(
        False,
        "--exclude-enterprise-addons",
        help="Exclude Odoo Enterprise Edition (EE) addons from the list",
    ),
) -> None:
    """List unique values for a manifest field across all addons.

    Examples:

      oduit list-manifest-values category

      oduit list-manifest-values author --exclude-core-addons

      oduit list-manifest-values license --separator ","
    """
    _list_manifest_values_command_impl(
        ctx,
        field=field,
        separator=separator,
        select_dir=select_dir,
        exclude_core_addons=exclude_core_addons,
        exclude_enterprise_addons=exclude_enterprise_addons,
        resolve_command_env_config_fn=_resolve_command_env_config,
        valid_filter_fields=VALID_FILTER_FIELDS,
        module_manager_cls=ModuleManager,
        get_addon_field_value_fn=_get_addon_field_value,
        apply_core_addon_filters_fn=_apply_core_addon_filters,
    )


@app.command("list-duplicates")
def list_duplicates(ctx: typer.Context) -> None:
    """List duplicate addon names across configured addon paths."""
    _list_duplicates_command_impl(
        ctx,
        resolve_command_env_config_fn=_resolve_command_env_config,
        addons_path_manager_cls=AddonsPathManager,
        print_command_error_result_fn=_print_command_error_result,
    )


def _print_dependency_tree(
    module_list: list[str],
    module_manager: ModuleManager,
    tree_depth: int | None,
    odoo_series: OdooSeries | None = None,
) -> None:
    """Print dependency tree for a list of modules."""
    print_dependency_tree(module_list, module_manager, tree_depth, odoo_series)


def _print_dependency_list(
    module_list: list[str],
    module_manager: ModuleManager,
    tree_depth: int | None,
    depth: int | None,
    separator: str | None,
    source_desc: str,
    sorting: str = "alphabetical",
) -> None:
    """Print flat list of dependencies."""
    print_dependency_list(
        module_list,
        module_manager,
        tree_depth,
        depth,
        separator,
        source_desc,
        sorting,
    )


@app.command("list-depends")
def list_depends(
    ctx: typer.Context,
    modules: str | None = typer.Argument(
        None, help="Comma-separated module names to check dependencies for"
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    tree: bool = typer.Option(
        False,
        "--tree",
        help="Display dependencies as a tree structure",
    ),
    depth: int | None = typer.Option(
        -1,
        "--depth",
        help="Maximum depth of dependencies to show "
        "(-1= no maximum, 0=direct only, 1=direct+their deps, etc.)",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter modules by directory (e.g., 'myaddons')",
    ),
    sorting: str = SORT_OPTION,
) -> None:
    """List direct dependencies needed to install a set of modules.

    Direct dependencies are external modules (not in the provided set) needed
    for installation. For example, if modules a, b, c depend on crm and mail,
    this will show crm and mail.

    Use --tree to show the full dependency tree with versions.
    Use --select-dir to get dependencies for all modules in a specific directory.
    """
    _list_depends_command_impl(
        ctx,
        modules=modules,
        separator=separator,
        tree=tree,
        depth=depth,
        select_dir=select_dir,
        sorting=sorting,
        resolve_command_env_config_fn=_resolve_command_env_config,
        module_manager_cls=ModuleManager,
        print_dependency_tree_fn=_print_dependency_tree,
        print_dependency_list_fn=_print_dependency_list,
    )


@app.command("list-codepends")
def list_codepends(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to inspect reverse dependencies for"),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
) -> None:
    """List reverse dependencies for a module.

    The output includes the selected module itself plus any modules that
    directly or indirectly depend on it.
    """
    _list_codepends_command_impl(
        ctx,
        module=module,
        separator=separator,
        resolve_command_env_config_fn=_resolve_command_env_config,
        module_manager_cls=ModuleManager,
    )


@app.command("install-order")
def install_order(
    ctx: typer.Context,
    modules: str | None = typer.Argument(
        None, help="Comma-separated module names to compute install order for"
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Get install order for all modules in a specific directory",
    ),
) -> None:
    """Return the dependency-resolved install order for one or more addons."""
    _install_order_command_impl(
        ctx,
        modules=modules,
        separator=separator,
        select_dir=select_dir,
        resolve_command_env_config_fn=_resolve_command_env_config,
        module_manager_cls=ModuleManager,
        print_command_error_result_fn=_print_command_error_result,
        dependency_error_details_fn=_dependency_error_details,
    )


@app.command("impact-of-update")
def impact_of_update(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to analyze for update impact"),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
) -> None:
    """Show addons affected by updating a specific module."""
    _impact_of_update_command_impl(
        ctx,
        module=module,
        separator=separator,
        resolve_command_env_config_fn=_resolve_command_env_config,
        module_manager_cls=ModuleManager,
        print_command_error_result_fn=_print_command_error_result,
    )


@app.command("list-missing")
def list_missing(
    ctx: typer.Context,
    modules: str | None = typer.Argument(
        None, help="Comma-separated module names to check for missing dependencies"
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter modules by directory (e.g., 'myaddons')",
    ),
) -> None:
    """Find missing dependencies for modules.

    This command identifies dependencies that are not available in the addons_path.
    Useful for ensuring all required modules are present before installation.

    Use --select-dir to check all modules in a specific directory.
    """
    _list_missing_command_impl(
        ctx,
        modules=modules,
        separator=separator,
        select_dir=select_dir,
        resolve_command_env_config_fn=_resolve_command_env_config,
        module_manager_cls=ModuleManager,
    )


def _check_environment_exists(config_loader: ConfigLoader, env_name: str) -> None:
    """Check if environment already exists and exit if it does."""
    check_environment_exists(config_loader, env_name)


def _detect_binaries(
    python_bin: str | None,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> tuple[str, str | None, str | None]:
    """Auto-detect binary paths if not provided.

    Returns:
        Tuple of (python_bin, odoo_bin, coverage_bin)
    """
    return detect_binaries(python_bin, odoo_bin, coverage_bin)


def _build_initial_config(
    python_bin: str,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> dict[str, Any]:
    """Build initial flat configuration dictionary."""
    return build_initial_config(python_bin, odoo_bin, coverage_bin)


def _import_or_convert_config(
    env_config: dict[str, Any],
    from_conf: str | None,
    config_loader: ConfigLoader,
    python_bin: str,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> dict[str, Any]:
    """Import config from .conf file or convert flat config to sectioned format."""
    return import_or_convert_config(
        env_config,
        from_conf,
        config_loader,
        python_bin,
        odoo_bin,
        coverage_bin,
    )


def _normalize_addons_path(env_config: dict[str, Any]) -> None:
    """Convert addons_path from comma-separated string to list in-place."""
    normalize_addons_path(env_config)


def _save_config_file(
    config_path: str,
    env_config: dict[str, Any],
    config_loader: ConfigLoader,
) -> None:
    """Save configuration to TOML file."""
    save_config_file(config_path, env_config, config_loader)


def _display_config_summary(env_config: dict[str, Any]) -> None:
    """Display configuration summary to user."""
    display_config_summary(env_config)


@app.command("init")
def init_env(
    env_name: str = typer.Argument(help="Environment name to create"),
    from_conf: str | None = typer.Option(
        None,
        "--from-conf",
        help="Import configuration from existing Odoo .conf file",
    ),
    python_bin: str | None = typer.Option(
        None,
        "--python-bin",
        help="Python binary path (auto-detected if not provided)",
    ),
    odoo_bin: str | None = typer.Option(
        None,
        "--odoo-bin",
        help="Odoo binary path (auto-detected if not provided)",
    ),
    coverage_bin: str | None = typer.Option(
        None,
        "--coverage-bin",
        help="Coverage binary path (auto-detected if not provided)",
    ),
) -> None:
    """Initialize a new oduit environment configuration.

    Creates a new environment configuration in ~/.config/oduit/<env_name>.toml.
    Auto-detects python and odoo binaries from PATH unless explicitly provided.
    Can import settings from existing Odoo .conf file.
    """
    _init_env_command_impl(
        env_name=env_name,
        from_conf=from_conf,
        python_bin=python_bin,
        odoo_bin=odoo_bin,
        coverage_bin=coverage_bin,
        config_loader_cls=ConfigLoader,
        check_environment_exists_fn=_check_environment_exists,
        detect_binaries_fn=_detect_binaries,
        build_initial_config_fn=_build_initial_config,
        import_or_convert_config_fn=_import_or_convert_config,
        normalize_addons_path_fn=_normalize_addons_path,
        save_config_file_fn=_save_config_file,
        display_config_summary_fn=_display_config_summary,
    )


@app.command("export-lang")
def export_lang(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to export"),
    language: str | None = LANGUAGE_OPTION,
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Export language module."""
    _export_lang_command_impl(
        ctx,
        module=module,
        language=language,
        log_level=log_level,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
        module_manager_cls=ModuleManager,
    )


@app.command("version")
def get_odoo_version_cmd(
    ctx: typer.Context,
) -> None:
    """Get Odoo version from odoo-bin."""
    _get_odoo_version_command_impl(
        ctx,
        resolve_command_env_config_fn=_resolve_command_env_config,
        build_odoo_operations_fn=_build_odoo_operations,
    )


@agent_app.command("context")
def agent_context(ctx: typer.Context) -> None:
    """Return a structured environment snapshot for automation."""
    _agent_context_command(
        ctx,
        resolve_agent_global_config_fn=_resolve_agent_global_config,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        odoo_operations_cls=OdooOperations,
        safe_read_only=SAFE_READ_ONLY,
    )


@agent_app.command("inspect-addon")
def agent_inspect_addon(
    ctx: typer.Context,
    module: str = typer.Argument(help="Addon to inspect"),
) -> None:
    """Return a one-shot addon inspection payload."""
    _agent_inspect_addon_command(
        ctx,
        module=module,
        resolve_agent_global_config_fn=_resolve_agent_global_config,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        odoo_operations_cls=OdooOperations,
        module_not_found_error_cls=OduitModuleNotFoundError,
        safe_read_only=SAFE_READ_ONLY,
    )


@agent_app.command("plan-update")
def agent_plan_update(
    ctx: typer.Context,
    module: str = typer.Argument(help="Addon to plan an update for"),
) -> None:
    """Return a structured, read-only update plan for a module."""
    _agent_plan_update_command(
        ctx,
        module=module,
        resolve_agent_global_config_fn=_resolve_agent_global_config,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        odoo_operations_cls=OdooOperations,
        module_not_found_error_cls=OduitModuleNotFoundError,
        safe_read_only=SAFE_READ_ONLY,
    )


@agent_app.command("locate-model")
def agent_locate_model(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to locate"),
    module: str = typer.Option(..., "--module", help="Addon to inspect"),
) -> None:
    """Locate likely source files for a model extension inside one addon."""
    _agent_locate_model_command(
        ctx,
        model=model,
        module=module,
        resolve_agent_ops_fn=_resolve_agent_ops,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        module_not_found_error_cls=OduitModuleNotFoundError,
        config_error_cls=ConfigError,
    )


@agent_app.command("locate-field")
def agent_locate_field(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to inspect"),
    field_name: str = typer.Argument(help="Field to locate"),
    module: str = typer.Option(..., "--module", help="Addon to inspect"),
) -> None:
    """Locate an existing field or suggest the best insertion point."""
    _agent_locate_field_command(
        ctx,
        model=model,
        field_name=field_name,
        module=module,
        resolve_agent_ops_fn=_resolve_agent_ops,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        module_not_found_error_cls=OduitModuleNotFoundError,
        config_error_cls=ConfigError,
    )


@agent_app.command("list-addon-tests")
def agent_list_addon_tests(
    ctx: typer.Context,
    module: str = typer.Argument(help="Addon to inspect"),
    model: str | None = typer.Option(None, "--model", help="Optional model hint"),
    field_name: str | None = typer.Option(
        None,
        "--field",
        help="Optional field hint",
    ),
) -> None:
    """List likely tests for an addon, optionally ranked by model/field references."""
    _agent_list_addon_tests_command(
        ctx,
        module=module,
        model=model,
        field_name=field_name,
        resolve_agent_ops_fn=_resolve_agent_ops,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        module_not_found_error_cls=OduitModuleNotFoundError,
        config_error_cls=ConfigError,
    )


@agent_app.command("list-addon-models")
def agent_list_addon_models(
    ctx: typer.Context,
    module: str = typer.Argument(help="Addon to inspect"),
) -> None:
    """List the models declared or extended by one addon."""
    _agent_list_addon_models_command(
        ctx,
        module=module,
        resolve_agent_ops_fn=_resolve_agent_ops,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        module_not_found_error_cls=OduitModuleNotFoundError,
        config_error_cls=ConfigError,
    )


@agent_app.command("find-model-extensions")
def agent_find_model_extensions(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to inspect across addons"),
    summary: bool = typer.Option(
        False,
        "--summary",
        help="Omit bulky scanned file listings from the payload",
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Find where a model is declared, extended, and installed."""
    _agent_find_model_extensions_command(
        ctx,
        model=model,
        summary=summary,
        database=database,
        timeout=timeout,
        resolve_agent_ops_fn=_resolve_agent_ops,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        config_error_cls=ConfigError,
    )


@agent_app.command("get-model-views")
def agent_get_model_views(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model whose DB views should be fetched"),
    types: str | None = typer.Option(
        None,
        "--types",
        help="Comma-separated view types, e.g. form,tree,kanban,search",
    ),
    summary: bool = typer.Option(
        False,
        "--summary",
        help="Omit bulky arch_db values from the payload",
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Fetch database-backed primary and extension views for a model."""
    _agent_get_model_views_command(
        ctx,
        model=model,
        types=types,
        summary=summary,
        database=database,
        timeout=timeout,
        resolve_agent_global_config_fn=_resolve_agent_global_config,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        parse_view_types_fn=_parse_view_types,
        strip_arch_from_model_views_fn=_strip_arch_from_model_views,
        odoo_operations_cls=OdooOperations,
    )


@agent_app.command("doctor")
def agent_doctor(ctx: typer.Context) -> None:
    """Return doctor diagnostics through the standard agent envelope."""
    _agent_doctor_command(
        ctx,
        resolve_agent_global_config_fn=_resolve_agent_global_config,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        build_doctor_report_fn=_build_doctor_report,
    )


@agent_app.command("list-addons")
def agent_list_addons(
    ctx: typer.Context,
    select_dir: str | None = typer.Option(None, "--select-dir"),
    exclude_core_addons: bool = typer.Option(False, "--exclude-core-addons"),
    exclude_enterprise_addons: bool = typer.Option(
        False,
        "--exclude-enterprise-addons",
    ),
    include: list[str] = INCLUDE_FILTER_OPTION,
    exclude: list[str] = EXCLUDE_FILTER_OPTION,
    sorting: str = SORT_OPTION,
) -> None:
    """Return structured addon inventory for the active environment."""
    _agent_list_addons_command(
        ctx,
        select_dir=select_dir,
        include=include,
        exclude=exclude,
        sorting=sorting,
        exclude_core_addons=exclude_core_addons,
        exclude_enterprise_addons=exclude_enterprise_addons,
        resolve_agent_ops_fn=_resolve_agent_ops,
        require_agent_addons_path_fn=_require_agent_addons_path,
        parse_filter_values_fn=_parse_filter_values,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        module_manager_cls=ModuleManager,
        apply_core_addon_filters_fn=_apply_core_addon_filters,
        apply_field_filters_fn=_apply_field_filters,
    )


@agent_app.command("dependency-graph")
def agent_dependency_graph(
    ctx: typer.Context,
    modules: str = typer.Option(..., "--modules", help="Comma-separated addon names"),
) -> None:
    """Return a structured dependency and reverse-dependency graph."""
    _agent_dependency_graph_command(
        ctx,
        modules=modules,
        resolve_agent_ops_fn=_resolve_agent_ops,
        parse_csv_items_fn=_parse_csv_items,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        config_error_cls=ConfigError,
    )


@agent_app.command("inspect-addons")
def agent_inspect_addons(
    ctx: typer.Context,
    modules: str = typer.Option(..., "--modules", help="Comma-separated addon names"),
) -> None:
    """Inspect multiple addons through the stable agent envelope."""
    _agent_inspect_addons_command(
        ctx,
        modules=modules,
        resolve_agent_ops_fn=_resolve_agent_ops,
        parse_csv_items_fn=_parse_csv_items,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        module_not_found_error_cls=OduitModuleNotFoundError,
    )


@agent_app.command("resolve-config")
def agent_resolve_config(ctx: typer.Context) -> None:
    """Return the resolved configuration with sensitive values redacted."""
    _agent_resolve_config_command(
        ctx,
        resolve_agent_ops_fn=_resolve_agent_ops,
        redact_config_fn=_redact_config,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
    )


@agent_app.command("list-duplicates")
def agent_list_duplicates(ctx: typer.Context) -> None:
    """Return duplicate addon names through the standard agent envelope."""
    _agent_list_duplicates_command(
        ctx,
        resolve_agent_ops_fn=_resolve_agent_ops,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        config_error_cls=ConfigError,
    )


@agent_app.command("install-module")
def agent_install_module(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to install"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    without_demo: str | None = typer.Option(None, "--without-demo"),
    with_demo: bool = typer.Option(False, "--with-demo"),
    language: str | None = LANGUAGE_OPTION,
    max_cron_threads: int | None = typer.Option(None, "--max-cron-threads"),
    compact: bool = typer.Option(False, "--compact"),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Install a module with an explicit mutation gate."""
    _agent_install_module_command(
        ctx,
        module=module,
        allow_mutation=allow_mutation,
        dry_run=dry_run,
        without_demo=without_demo,
        with_demo=with_demo,
        language=language,
        max_cron_threads=max_cron_threads,
        compact=compact,
        log_level=log_level,
        resolve_agent_ops_fn=_resolve_agent_ops,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        agent_require_mutation_fn=_agent_require_mutation,
        output_result_to_json_fn=output_result_to_json,
        module_not_found_error_cls=OduitModuleNotFoundError,
        safe_read_only=SAFE_READ_ONLY,
        controlled_runtime_mutation=CONTROLLED_RUNTIME_MUTATION,
    )


@agent_app.command("update-module")
def agent_update_module(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to update"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    without_demo: str | None = typer.Option(None, "--without-demo"),
    language: str | None = LANGUAGE_OPTION,
    i18n_overwrite: bool = typer.Option(False, "--i18n-overwrite"),
    max_cron_threads: int | None = typer.Option(None, "--max-cron-threads"),
    compact: bool = typer.Option(False, "--compact"),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Update a module with an explicit mutation gate."""
    _agent_update_module_command(
        ctx,
        module=module,
        allow_mutation=allow_mutation,
        dry_run=dry_run,
        without_demo=without_demo,
        language=language,
        i18n_overwrite=i18n_overwrite,
        max_cron_threads=max_cron_threads,
        compact=compact,
        log_level=log_level,
        resolve_agent_ops_fn=_resolve_agent_ops,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        agent_require_mutation_fn=_agent_require_mutation,
        output_result_to_json_fn=output_result_to_json,
        module_not_found_error_cls=OduitModuleNotFoundError,
        safe_read_only=SAFE_READ_ONLY,
        controlled_runtime_mutation=CONTROLLED_RUNTIME_MUTATION,
    )


@agent_app.command("create-addon")
def agent_create_addon(
    ctx: typer.Context,
    addon_name: str = typer.Argument(help="Addon to create"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    path: str | None = typer.Option(None, "--path"),
    template: AddonTemplate = ADDON_TEMPLATE_OPTION,
) -> None:
    """Create a new addon with an explicit mutation gate."""
    _agent_create_addon_command(
        ctx,
        addon_name=addon_name,
        allow_mutation=allow_mutation,
        dry_run=dry_run,
        path=path,
        template=template,
        resolve_agent_ops_fn=_resolve_agent_ops,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        agent_require_mutation_fn=_agent_require_mutation,
        output_result_to_json_fn=output_result_to_json,
        safe_read_only=SAFE_READ_ONLY,
        controlled_source_mutation=CONTROLLED_SOURCE_MUTATION,
    )


@agent_app.command("export-lang")
def agent_export_lang(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to export"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    language: str | None = LANGUAGE_OPTION,
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Export language files with an explicit mutation gate."""
    _agent_export_lang_command(
        ctx,
        module=module,
        allow_mutation=allow_mutation,
        dry_run=dry_run,
        language=language,
        log_level=log_level,
        resolve_agent_ops_fn=_resolve_agent_ops,
        require_agent_addons_path_fn=_require_agent_addons_path,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        agent_require_mutation_fn=_agent_require_mutation,
        output_result_to_json_fn=output_result_to_json,
        module_manager_cls=ModuleManager,
        os_module=os,
        safe_read_only=SAFE_READ_ONLY,
        controlled_source_mutation=CONTROLLED_SOURCE_MUTATION,
    )


@agent_app.command("test-summary")
def agent_test_summary(
    ctx: typer.Context,
    module: str | None = typer.Option(None, "--module", help="Module under test"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    install: str | None = typer.Option(
        None,
        "--install",
        help="Install a module before running tests",
    ),
    update: str | None = typer.Option(
        None,
        "--update",
        help="Update a module before running tests",
    ),
    coverage: str | None = typer.Option(
        None,
        "--coverage",
        help="Generate coverage for a module",
    ),
    test_file: str | None = typer.Option(
        None, "--test-file", help="Specific test file"
    ),
    test_tags: str | None = typer.Option(None, "--test-tags", help="Test tags filter"),
    stop_on_error: bool = typer.Option(False, "--stop-on-error"),
    compact: bool = typer.Option(False, "--compact"),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Run tests and emit a normalized summary payload."""
    _agent_test_summary_command(
        ctx,
        module=module,
        allow_mutation=allow_mutation,
        install=install,
        update=update,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
        stop_on_error=stop_on_error,
        compact=compact,
        log_level=log_level,
        resolve_agent_global_config_fn=_resolve_agent_global_config,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        agent_require_mutation_fn=_agent_require_mutation,
        build_agent_test_summary_details_fn=_build_agent_test_summary_details,
        odoo_operations_cls=OdooOperations,
        controlled_runtime_mutation=CONTROLLED_RUNTIME_MUTATION,
    )


@agent_app.command("validate-addon-change")
def agent_validate_addon_change(
    ctx: typer.Context,
    module: str = typer.Argument(help="Addon to validate end-to-end"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    install_if_needed: bool = typer.Option(False, "--install-if-needed"),
    update: bool = typer.Option(False, "--update"),
    test_tags: str | None = typer.Option(
        None,
        "--test-tags",
        help="Test tags filter; defaults to /<module>.",
    ),
    discover_tests: bool = typer.Option(
        False,
        "--discover-tests",
        help="Include discovered addon test inventory after the module suite passes.",
    ),
    stop_on_error: bool = typer.Option(False, "--stop-on-error"),
    compact: bool = typer.Option(False, "--compact"),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Validate an addon change with one aggregate structured payload."""
    _agent_validate_impl.agent_validate_addon_change_command(
        ctx,
        module=module,
        allow_mutation=allow_mutation,
        install_if_needed=install_if_needed,
        update=update,
        test_tags=test_tags,
        discover_tests=discover_tests,
        stop_on_error=stop_on_error,
        compact=compact,
        log_level=log_level,
        resolve_agent_global_config_fn=_resolve_agent_global_config,
        agent_fail_fn=_agent_fail,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        agent_require_mutation_fn=_agent_require_mutation,
        agent_sub_result_fn=_agent_sub_result,
        build_agent_test_summary_details_fn=_build_agent_test_summary_details,
        build_validate_addon_change_payload_fn=_build_validate_addon_change_payload,
        run_validate_addon_change_preflight_fn=_run_validate_addon_change_preflight,
        build_validate_addon_change_discovery_result_fn=(
            _build_validate_addon_change_discovery_result
        ),
        build_doctor_report_fn=_build_doctor_report,
        odoo_operations_cls=OdooOperations,
        module_not_found_error_cls=OduitModuleNotFoundError,
        config_error_cls=ConfigError,
        controlled_runtime_mutation=CONTROLLED_RUNTIME_MUTATION,
    )


@agent_app.command("query-model")
def agent_query_model(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to query"),
    domain_json: str | None = typer.Option(
        None, "--domain-json", help="JSON array domain"
    ),
    fields: str | None = typer.Option(
        None, "--fields", help="Comma-separated field names"
    ),
    limit: int = typer.Option(80, "--limit", help="Record limit"),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Run a structured read-only model query."""
    _agent_query_model_command(
        ctx,
        model=model,
        domain_json=domain_json,
        fields=fields,
        limit=limit,
        database=database,
        timeout=timeout,
        resolve_agent_ops_fn=_resolve_agent_ops,
        parse_json_list_option_fn=_parse_json_list_option,
        parse_csv_items_fn=_parse_csv_items,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        safe_read_only=SAFE_READ_ONLY,
    )


@agent_app.command("read-record")
def agent_read_record(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to inspect"),
    record_id: int = typer.Argument(help="Record id to read"),
    fields: str | None = typer.Option(
        None, "--fields", help="Comma-separated field names"
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Read a single record by id via OdooQuery."""
    _agent_read_record_command(
        ctx,
        model=model,
        record_id=record_id,
        fields=fields,
        database=database,
        timeout=timeout,
        resolve_agent_ops_fn=_resolve_agent_ops,
        parse_csv_items_fn=_parse_csv_items,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        safe_read_only=SAFE_READ_ONLY,
    )


@agent_app.command("search-count")
def agent_search_count(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to count records for"),
    domain_json: str | None = typer.Option(
        None, "--domain-json", help="JSON array domain"
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Count records matching a domain via OdooQuery."""
    _agent_search_count_command(
        ctx,
        model=model,
        domain_json=domain_json,
        database=database,
        timeout=timeout,
        resolve_agent_ops_fn=_resolve_agent_ops,
        parse_json_list_option_fn=_parse_json_list_option,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        safe_read_only=SAFE_READ_ONLY,
    )


@agent_app.command("get-model-fields")
def agent_get_model_fields(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to inspect"),
    attributes: str | None = typer.Option(
        None,
        "--attributes",
        help="Comma-separated field attributes",
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Inspect model field metadata via OdooQuery."""
    _agent_get_model_fields_command(
        ctx,
        model=model,
        attributes=attributes,
        database=database,
        timeout=timeout,
        resolve_agent_ops_fn=_resolve_agent_ops,
        parse_csv_items_fn=_parse_csv_items,
        agent_payload_fn=_agent_payload,
        agent_emit_payload_fn=_agent_emit_payload,
        safe_read_only=SAFE_READ_ONLY,
    )


def cli_main() -> None:
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    cli_main()
