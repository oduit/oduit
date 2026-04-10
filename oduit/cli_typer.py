# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""New Typer-based CLI implementation for oduit."""

import functools
import json
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
    parse_filter_option,
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
    redact_config_value as _redact_config_value_impl,
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
    build_addon_inspection_data as _build_addon_inspection_data_impl,
)
from .cli.agent.services import (
    build_agent_test_summary_details as _build_agent_test_summary_details_impl,
)
from .cli.agent.services import (
    build_environment_context_data as _build_environment_context_data_impl,
)
from .cli.agent.services import (
    build_update_plan_data as _build_update_plan_data_impl,
)
from .cli.agent.services import (
    get_agent_addon_type as _get_agent_addon_type_impl,
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
from .cli.dependency_output import print_dependency_list, print_dependency_tree
from .cli.doctor import (
    build_doctor_check,
    build_doctor_report,
    format_doctor_value,
    print_doctor_report,
    probe_binary,
    resolve_binary_candidate,
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
from .cli_types import (
    AddonListType,
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
from .output import configure_output, print_error, print_info, print_warning
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

ADDON_LIST_TYPE_OPTION = typer.Option(
    AddonListType.ALL, "--type", help="Type of addons to list"
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


def _build_doctor_check(
    name: str,
    status: str,
    message: str,
    details: dict[str, Any] | None = None,
    remediation: str | None = None,
) -> dict[str, Any]:
    """Create a normalized doctor check entry."""
    return build_doctor_check(name, status, message, details, remediation)


def _resolve_binary_candidate(candidate: str) -> dict[str, Any]:
    """Resolve a binary candidate either from PATH or filesystem."""
    return resolve_binary_candidate(candidate)


def _probe_binary(
    configured_value: str | None, auto_candidates: list[str]
) -> dict[str, Any]:
    """Probe a configured binary or try to auto-detect it."""
    return probe_binary(configured_value, auto_candidates)


def _format_doctor_value(value: Any) -> str:
    """Format a doctor value for human-readable output."""
    return format_doctor_value(value)


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


def with_config(func: Any) -> Any:
    """Decorator to inject global configuration into command functions."""

    @functools.wraps(func)
    def wrapper(ctx: typer.Context) -> Any:
        if ctx.obj is None:
            print_error("No global configuration found")
            raise typer.Exit(1) from None

        if isinstance(ctx.obj, dict):
            try:
                global_config = create_global_config(**ctx.obj)
            except typer.Exit:
                raise
            except Exception as e:
                print_error(f"Failed to create global config: {e}")
                raise typer.Exit(1) from e
        else:
            global_config = ctx.obj

        return func(global_config)

    return wrapper


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


def _redact_config_value(key: str, value: Any) -> Any:
    """Redact sensitive configuration values in structured outputs."""
    return _redact_config_value_impl(key, value)


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


def _get_agent_addon_type(addon_name: str, odoo_series: OdooSeries | None) -> str:
    """Return a machine-oriented addon classification."""
    return _get_agent_addon_type_impl(
        addon_name, odoo_series, get_addon_type_fn=_get_addon_type
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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    report = _build_doctor_report(global_config)
    if global_config.format == OutputFormat.JSON:
        print(json.dumps(report))
    else:
        _print_doctor_report(report)

    if not report.get("success", False):
        raise typer.Exit(1)


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )
    odoo_operations.run_odoo(
        no_http=global_config.no_http,
        dev=dev,
        log_level=log_level.value if log_level else None,
        stop_after_init=stop_after_init,
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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    odoo_operations.run_shell(
        shell_interface=shell_interface.value if shell_interface else None,
        compact=compact,
        log_level=log_level.value if log_level else None,
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
    if not module:
        print_error("Module name is required for install")
        raise typer.Exit(1) from None
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    output = odoo_operations.install_module(
        module,
        no_http=global_config.no_http,
        max_cron_threads=max_cron_threads,
        without_demo=without_demo or False,
        with_demo=with_demo,
        language=language,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )

    # Optional JSON output
    if global_config.format == OutputFormat.JSON:
        # By default, exclude command and stdout from result
        exclude_fields = ["command", "stdout"]

        additional_fields = {
            "without_demo": without_demo,
            "verbose": global_config.verbose,
        }

        # Only include command if requested
        if include_command:
            exclude_fields.remove("command")

        # Only include stdout if requested
        if include_stdout:
            exclude_fields.remove("stdout")

        result_json = output_result_to_json(
            output, additional_fields=additional_fields, exclude_fields=exclude_fields
        )
        print(json.dumps(result_json))

    # Exit with code 1 on failure regardless of output format
    if not output.get("success"):
        raise typer.Exit(1)


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
    if not module:
        print_error("Module name is required for update")
        raise typer.Exit(1) from None
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    if i18n_overwrite:
        language = language or global_config.env_config.get("language", "de_DE")
        # Ensure language is a string
        if language is None:
            language = "de_DE"

    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    result = odoo_operations.update_module(
        module,
        no_http=global_config.no_http,
        max_cron_threads=max_cron_threads,
        without_demo=without_demo or False,
        language=language,
        i18n_overwrite=i18n_overwrite,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )
    if compact and result:
        print_info(str(result))

    # Exit with code 1 on failure regardless of output format
    if not result.get("success"):
        raise typer.Exit(1)


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    result = odoo_operations.run_tests(
        None,
        stop_on_error=stop_on_error,
        update=update,
        install=install,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )

    # Optional JSON output
    if global_config.format == OutputFormat.JSON:
        # By default, exclude command and stdout from result
        exclude_fields = ["command", "stdout"]

        additional_fields: dict[str, Any] = {
            "stop_on_error": stop_on_error,
            "install": install,
            "update": update,
            "coverage": coverage,
            "test_file": test_file,
            "test_tags": test_tags,
            "compact": compact,
            "verbose": global_config.verbose,
        }

        # Only include command if requested
        if include_command:
            exclude_fields.remove("command")

        # Only include stdout if requested
        if include_stdout:
            exclude_fields.remove("stdout")

        result_json = output_result_to_json(
            result, additional_fields=additional_fields, exclude_fields=exclude_fields
        )
        print(json.dumps(result_json))

    # Exit with code 1 on failure regardless of output format
    if not result.get("success"):
        raise typer.Exit(1)


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None
    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    db_name = global_config.env_config.get("db_name", "Unknown")
    effective_non_interactive = non_interactive or global_config.non_interactive

    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    # Check if database exists
    exists_result = odoo_operations.db_exists(
        with_sudo=with_sudo,
        suppress_output=True,
        db_user=db_user,
    )

    db_exists = exists_result.get("exists", False)

    # Handle existing database
    if db_exists:
        if drop:
            confirmation = ""
            if effective_non_interactive:
                _confirmation_required_error(
                    global_config,
                    "create_db",
                    f"Database '{db_name}' already exists and dropping it "
                    "requires confirmation.",
                    remediation=[
                        "Re-run without `--non-interactive` to confirm the drop.",
                        "Or remove `--drop` if the existing database should be kept.",
                    ],
                )
            else:
                print_warning(f"Database '{db_name}' already exists.")
                message = "Do you want to drop it before creating?"
                confirmation = input(f"{message} (y/N): ").strip().lower()

            if confirmation == "y":
                print_info(f"Dropping existing database '{db_name}'...")
                drop_result = odoo_operations.drop_db(
                    with_sudo=with_sudo,
                    suppress_output=False,
                )
                if not drop_result.get("success", False):
                    print_error("Failed to drop database")
                    raise typer.Exit(1) from None
            else:
                print_info("Database drop cancelled.")
                raise typer.Exit(0) from None
        else:
            print_error(
                f"Database '{db_name}' already exists. "
                f"Use --drop flag to drop it first."
            )
            raise typer.Exit(1) from None

    # Create database
    confirmation = ""
    if not db_exists:
        if effective_non_interactive:
            _confirmation_required_error(
                global_config,
                "create_db",
                f"Creating database '{db_name}' requires confirmation in "
                "non-interactive mode.",
                remediation=[
                    "Re-run without `--non-interactive` to confirm database creation.",
                ],
            )
        print_warning(f"This will create a new database named '{db_name}'.")
        message = "Are you sure you want to create a new database?"
        confirmation = input(f"{message} (y/N): ").strip().lower()

    if confirmation == "y":
        odoo_operations.create_db(
            create_role=create_role,
            alter_role=alter_role,
            with_sudo=with_sudo,
            db_user=db_user,
        )
    else:
        print_info("Database creation cancelled.")


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None
    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )
    result = odoo_operations.list_db(
        with_sudo=with_sudo,
        db_user=db_user,
    )

    if global_config.format == OutputFormat.JSON:
        # By default, exclude command and stdout from result
        exclude_fields = ["command", "stdout"]

        additional_fields: dict[str, Any] = {}

        # Only include command if requested
        if include_command:
            exclude_fields.remove("command")

        # Only include stdout if requested
        if include_stdout:
            exclude_fields.remove("stdout")

        result_json = output_result_to_json(
            result, additional_fields=additional_fields, exclude_fields=exclude_fields
        )
        print(json.dumps(result_json))
    elif not result.get("success"):
        raise typer.Exit(1)


@app.command("list-env")
def list_env() -> None:
    """List available environments."""
    from rich.console import Console
    from rich.table import Table

    from oduit.config_loader import ConfigLoader

    try:
        environments = ConfigLoader().get_available_environments()
        if not environments:
            print_info("No environments found in .oduit directory")
            return

        table = Table(title="Available Environments", show_header=True)
        table.add_column("Environment", style="cyan", no_wrap=True)

        for env in environments:
            table.add_row(env)

        console = Console()
        console.print(table)
    except FileNotFoundError:
        print_error("No .oduit directory found in current directory")
        raise typer.Exit(1) from None
    except Exception as e:
        print_error(f"Failed to list environments: {e}")
        raise typer.Exit(1) from None


@app.command("print-config")
def print_config_cmd(ctx: typer.Context) -> None:
    """Print environment config."""
    from rich.console import Console
    from rich.table import Table

    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    if global_config.format == OutputFormat.JSON:
        output_data = output_result_to_json(
            {
                "success": True,
                "operation": "print_config",
                "environment": global_config.env_name,
                "config": global_config.env_config,
            }
        )
        print(json.dumps(output_data))
        return

    console = Console()
    table = Table(
        title=f"Environment Configuration: {global_config.env_name}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Setting", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    for key, value in sorted(global_config.env_config.items()):
        if isinstance(value, list):
            formatted_value = "\n".join(f"• {item}" for item in value)
            table.add_row(key, formatted_value)
        elif isinstance(value, str) and key == "addons_path" and "," in value:
            paths = [p.strip() for p in value.split(",")]
            formatted_value = "\n".join(f"• {item}" for item in paths)
            table.add_row(key, formatted_value)
        else:
            table.add_row(key, str(value))

    console.print(table)


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    if not validate_addon_name(addon_name):
        print_error(
            f"Invalid addon name '{addon_name}'. "
            f"Must be lowercase letters, numbers, underscores only."
        )
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    odoo_operations.create_addon(addon_name, destination=path, template=template.value)


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


def _filter_addons_by_field(
    addons: list[str],
    module_manager: ModuleManager,
    field: str,
    filter_value: str,
    is_include: bool,
    odoo_series: OdooSeries | None = None,
) -> list[str]:
    """Filter addons by a specific field value."""
    from .cli.addon_filters import filter_addons_by_field

    return filter_addons_by_field(
        addons,
        module_manager,
        field,
        filter_value,
        is_include,
        odoo_series,
    )


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
    from rich.console import Console

    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    manifest = module_manager.get_manifest(addon_name)
    if not manifest:
        print_error(f"Addon '{addon_name}' not found in addons path")
        raise typer.Exit(1) from None

    # Detect Odoo series for CE/EE detection
    odoo_series = (
        global_config.odoo_series
        if global_config.odoo_series
        else module_manager.detect_odoo_series()
    )

    addon_type = _get_addon_type(addon_name, odoo_series)

    # JSON output
    if global_config.format == OutputFormat.JSON:
        raw_data = manifest.get_raw_data()
        output_data: dict[str, Any] = output_result_to_json(
            {
                "success": True,
                "operation": "print_manifest",
                "technical_name": addon_name,
                "name": manifest.name,
                "version": manifest.version,
                "summary": manifest.summary,
                "author": manifest.author,
                "website": manifest.website,
                "license": manifest.license,
                "installable": manifest.installable,
                "auto_install": manifest.auto_install,
                "depends": manifest.codependencies,
                "addon_type": addon_type,
                "module_path": manifest.module_path,
            },
            result_type="manifest",
        )
        if manifest.python_dependencies:
            output_data["python_dependencies"] = manifest.python_dependencies
        if manifest.binary_dependencies:
            output_data["binary_dependencies"] = manifest.binary_dependencies
        if "category" in raw_data:
            output_data["category"] = raw_data["category"]
        print(json.dumps(output_data))
        return

    # Table output
    console = Console()
    table = _build_addon_table(addon_name, manifest, addon_type)
    console.print(table)


def _parse_filter_option(
    ctx: Any, param: Any, value: tuple[str, ...]
) -> list[tuple[str, str]]:
    """Parse filter option values into list of (field, value) tuples."""
    return parse_filter_option(ctx, param, value)


@app.command("list-addons")
def list_addons(
    ctx: typer.Context,
    type: AddonListType = ADDON_LIST_TYPE_OPTION,
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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    # Parse include/exclude filters from FIELD:VALUE format
    include_filter: list[tuple[str, str]] = []
    exclude_filter: list[tuple[str, str]] = []

    for filter_str in include:
        if ":" not in filter_str:
            print_error(
                f"Invalid include filter '{filter_str}'. "
                f"Use format 'FIELD:VALUE' (e.g., 'category:Sales')"
            )
            raise typer.Exit(1) from None
        field, value = filter_str.split(":", 1)
        include_filter.append((field.strip(), value.strip()))

    for filter_str in exclude:
        if ":" not in filter_str:
            print_error(
                f"Invalid exclude filter '{filter_str}'. "
                f"Use format 'FIELD:VALUE' (e.g., 'category:Theme')"
            )
            raise typer.Exit(1) from None
        field, value = filter_str.split(":", 1)
        exclude_filter.append((field.strip(), value.strip()))

    module_manager = ModuleManager(global_config.env_config["addons_path"])
    addons = module_manager.find_module_dirs(filter_dir=select_dir)

    addons = [addon for addon in addons if not addon.startswith("test_")]

    # Detect Odoo series once for filters that need it
    odoo_series = (
        global_config.odoo_series
        if global_config.odoo_series
        else module_manager.detect_odoo_series()
    )

    if exclude_core_addons or exclude_enterprise_addons:
        try:
            addons = _apply_core_addon_filters(
                addons, exclude_core_addons, exclude_enterprise_addons, odoo_series
            )
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1) from None

    # Apply include/exclude filters
    try:
        addons = _apply_field_filters(
            addons, module_manager, include_filter, exclude_filter, odoo_series
        )
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1) from None

    try:
        sorted_addons = module_manager.sort_modules(addons, sorting)
    except ValueError as e:
        print_error(f"Sorting failed: {e}")
        raise typer.Exit(1) from None

    if separator:
        print(separator.join(sorted_addons))
    else:
        for addon in sorted_addons:
            print(addon)


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    # Validate field
    if field not in VALID_FILTER_FIELDS:
        print_error(
            f"Invalid field '{field}'. Valid fields: {', '.join(VALID_FILTER_FIELDS)}"
        )
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])
    addons = module_manager.find_module_dirs(filter_dir=select_dir)

    # Detect Odoo series for filters that need it
    odoo_series = (
        global_config.odoo_series
        if global_config.odoo_series
        else module_manager.detect_odoo_series()
    )

    if exclude_core_addons or exclude_enterprise_addons:
        try:
            addons = _apply_core_addon_filters(
                addons, exclude_core_addons, exclude_enterprise_addons, odoo_series
            )
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1) from None

    # Collect unique values
    unique_values: set[str] = set()
    for addon in addons:
        value = _get_addon_field_value(addon, field, module_manager, odoo_series)
        if not value:
            continue
        # Handle comma-separated values (e.g., depends field)
        if field == "depends":
            for v in value.split(","):
                v = v.strip()
                if v:
                    unique_values.add(v)
        else:
            unique_values.add(value)

    sorted_values = sorted(unique_values)

    # JSON output
    if global_config.format == OutputFormat.JSON:
        output_data = output_result_to_json(
            {
                "success": True,
                "operation": "list_manifest_values",
                "field": field,
                "values": sorted_values,
            },
            result_type="manifest_values",
        )
        print(json.dumps(output_data))
        return

    # Text output
    if separator:
        print(separator.join(sorted_values))
    else:
        for value in sorted_values:
            print(value)


@app.command("list-duplicates")
def list_duplicates(ctx: typer.Context) -> None:
    """List duplicate addon names across configured addon paths."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    addons_path = global_config.env_config.get("addons_path")
    if not addons_path:
        _print_command_error_result(
            global_config,
            "list_duplicates",
            "addons_path is not configured",
            error_type="ConfigError",
            remediation=[
                "Set `addons_path` before running duplicate-module analysis.",
            ],
        )
        raise typer.Exit(1) from None

    path_manager = AddonsPathManager(str(addons_path))
    duplicate_modules = path_manager.find_duplicate_module_names()

    if global_config.format == OutputFormat.JSON:
        payload = output_result_to_json(
            {
                "success": True,
                "operation": "list_duplicates",
                "duplicate_modules": duplicate_modules,
                "duplicate_count": len(duplicate_modules),
            },
            result_type="duplicate_modules",
        )
        print(json.dumps(payload))
        return

    if not duplicate_modules:
        print_info("No duplicate addon names found")
        return

    for module_name in sorted(duplicate_modules):
        print(f"{module_name}:")
        for location in duplicate_modules[module_name]:
            print(f"  - {location}")


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    if modules is None and select_dir is None:
        print_error("Either provide module names or use --select-dir option")
        raise typer.Exit(1) from None

    if modules is not None and select_dir is not None:
        print_error("Cannot use both module names and --select-dir option")
        raise typer.Exit(1) from None

    try:
        if select_dir:
            addons = module_manager.find_module_dirs(filter_dir=select_dir)
            if not addons:
                print_error(f"No modules found in directory '{select_dir}'")
                raise typer.Exit(1) from None
            module_list = sorted(addons)
            source_desc = f"directory '{select_dir}'"
        else:
            assert modules is not None
            module_list = [m.strip() for m in modules.split(",")]
            if len(module_list) == 1:
                source_desc = f"'{modules}'"
            else:
                source_desc = f"modules [{', '.join(module_list)}]"

        tree_depth = depth + 1 if depth is not None and depth >= 0 else None

        if tree:
            _print_dependency_tree(
                module_list, module_manager, tree_depth, global_config.odoo_series
            )
        else:
            _print_dependency_list(
                module_list,
                module_manager,
                tree_depth,
                depth,
                separator,
                source_desc,
                sorting,
            )
    except ValueError as e:
        print_error(f"Error checking dependencies: {e}")
        raise typer.Exit(1) from None


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    reverse_dependencies = module_manager.get_reverse_dependencies(module)

    # Include the selected module itself in the output
    all_codeps = sorted(reverse_dependencies + [module])

    if separator:
        if all_codeps:
            print(separator.join(all_codeps))
    elif all_codeps:
        for dep in all_codeps:
            print(f"{dep}")
    else:
        print_info(f"Module '{module}' has no reverse dependencies")


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    if modules is None and select_dir is None:
        _print_command_error_result(
            global_config,
            "install_order",
            "Either provide module names or use --select-dir option",
            details={"modules": modules, "select_dir": select_dir},
        )
        raise typer.Exit(1) from None

    if modules is not None and select_dir is not None:
        _print_command_error_result(
            global_config,
            "install_order",
            "Cannot use both module names and --select-dir option",
            details={"modules": modules, "select_dir": select_dir},
        )
        raise typer.Exit(1) from None

    if select_dir:
        module_list = sorted(module_manager.find_module_dirs(filter_dir=select_dir))
        if not module_list:
            _print_command_error_result(
                global_config,
                "install_order",
                f"No modules found in directory '{select_dir}'",
                details={"select_dir": select_dir},
            )
            raise typer.Exit(1) from None
        source = "select_dir"
    else:
        assert modules is not None
        module_list = [
            module.strip() for module in modules.split(",") if module.strip()
        ]
        missing_modules = [
            module
            for module in module_list
            if module_manager.find_module_path(module) is None
        ]
        if missing_modules:
            _print_command_error_result(
                global_config,
                "install_order",
                f"Modules not found in addons_path: {', '.join(missing_modules)}",
                details={"modules": module_list, "missing_modules": missing_modules},
            )
            raise typer.Exit(1) from None
        source = "modules"

    try:
        ordered_modules = module_manager.get_install_order(*module_list)
    except ValueError as e:
        cycle_details = _dependency_error_details(module_manager, str(e))
        _print_command_error_result(
            global_config,
            "install_order",
            f"Failed to compute install order: {e}",
            error_type=("DependencyCycleError" if cycle_details else "DependencyError"),
            details={
                "modules": module_list,
                "select_dir": select_dir,
                **cycle_details,
            },
            remediation=(
                [
                    "Resolve the dependency cycle and retry the install-order "
                    "analysis.",
                ]
                if cycle_details
                else []
            ),
        )
        raise typer.Exit(1) from None

    if global_config.format == OutputFormat.JSON:
        result_json = output_result_to_json(
            {
                "success": True,
                "operation": "install_order",
                "modules": module_list,
                "install_order": ordered_modules,
                "source": source,
                "select_dir": select_dir,
            }
        )
        print(json.dumps(result_json))
        return

    if separator:
        print(separator.join(ordered_modules))
    else:
        for module in ordered_modules:
            print(module)


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])
    if module_manager.find_module_path(module) is None:
        _print_command_error_result(
            global_config,
            "impact_of_update",
            f"Module '{module}' was not found in addons_path",
            details={"module": module},
        )
        raise typer.Exit(1) from None

    impacted_modules = module_manager.get_reverse_dependencies(module)

    if global_config.format == OutputFormat.JSON:
        result_json = output_result_to_json(
            {
                "success": True,
                "operation": "impact_of_update",
                "module": module,
                "impacted_modules": impacted_modules,
                "impact_count": len(impacted_modules),
            }
        )
        print(json.dumps(result_json))
        return

    if not impacted_modules:
        print_info(f"No addons would be impacted by updating '{module}'")
        return

    if separator:
        print(separator.join(impacted_modules))
    else:
        for impacted_module in impacted_modules:
            print(impacted_module)


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
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    if modules is None and select_dir is None:
        print_error("Either provide module names or use --select-dir option")
        raise typer.Exit(1) from None

    if modules is not None and select_dir is not None:
        print_error("Cannot use both module names and --select-dir option")
        raise typer.Exit(1) from None

    try:
        if select_dir:
            module_list = module_manager.find_module_dirs(filter_dir=select_dir)
            if not module_list:
                print_error(f"No modules found in directory '{select_dir}'")
                raise typer.Exit(1) from None
        else:
            assert modules is not None
            module_list = [m.strip() for m in modules.split(",")]

        all_missing = set()
        for module in module_list:
            missing = module_manager.find_missing_dependencies(module)
            all_missing.update(missing)

        if all_missing:
            sorted_missing = sorted(all_missing)
            if separator:
                print(separator.join(sorted_missing))
            else:
                for dep in sorted_missing:
                    print(dep)
        else:
            if not separator:
                print_info("All dependencies are available")
    except ValueError as e:
        print_error(f"Error checking missing dependencies: {e}")
        raise typer.Exit(1) from None


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
    config_loader = ConfigLoader()

    _check_environment_exists(config_loader, env_name)

    python_bin, odoo_bin, coverage_bin = _detect_binaries(
        python_bin, odoo_bin, coverage_bin
    )

    env_config = _build_initial_config(python_bin, odoo_bin, coverage_bin)

    env_config = _import_or_convert_config(
        env_config, from_conf, config_loader, python_bin, odoo_bin, coverage_bin
    )

    _normalize_addons_path(env_config)

    config_path = config_loader.get_config_path(env_name, "toml")

    try:
        _save_config_file(config_path, env_config, config_loader)
        print_info(f"Environment '{env_name}' created successfully")
        print_info(f"Configuration saved to: {config_path}")
        _display_config_summary(env_config)
    except Exception as e:
        print_error(f"Failed to save configuration: {e}")
        raise typer.Exit(1) from None


@app.command("export-lang")
def export_lang(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to export"),
    language: str | None = LANGUAGE_OPTION,
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Export language module."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    language = language or global_config.env_config.get("language", "de_DE")
    if language is None:
        language = "de_DE"

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    module_path = module_manager.find_module_path(module)
    if not module_path:
        print_warning(
            f"Module '{module}' not found in addons path. Using default path."
        )
        module_path = os.path.join(
            global_config.env_config["addons_path"].split(",")[0], module
        )

    i18n_dir = os.path.join(module_path, "i18n")
    if "_" in language:
        filename = os.path.join(i18n_dir, f"{language.split('_')[0]}.po")
    else:
        filename = os.path.join(i18n_dir, f"{language}.po")

    os.makedirs(i18n_dir, exist_ok=True)
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    odoo_operations.export_module_language(
        module,
        filename,
        language,
        no_http=global_config.no_http,
        log_level=log_level.value if log_level else None,
    )


@app.command("version")
def get_odoo_version_cmd(
    ctx: typer.Context,
) -> None:
    """Get Odoo version from odoo-bin."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    ops = OdooOperations(global_config.env_config, verbose=global_config.verbose)
    result = ops.get_odoo_version(suppress_output=True)

    if global_config.format == OutputFormat.JSON:
        result_json = output_result_to_json(result)
        print(json.dumps(result_json))
    else:
        if result.get("success", False) and result.get("version"):
            typer.echo(result["version"])
        else:
            print_error("Failed to detect Odoo version")
            raise typer.Exit(1)


def _build_environment_context_data(global_config: GlobalConfig) -> dict[str, Any]:
    """Build a one-shot environment snapshot for agent workflows."""
    return _build_environment_context_data_impl(
        global_config,
        build_doctor_report_fn=_build_doctor_report,
        addons_path_manager_cls=AddonsPathManager,
        module_manager_cls=ModuleManager,
        probe_binary_fn=_probe_binary,
        odoo_operations_cls=OdooOperations,
    )


def _build_addon_inspection_data(
    module_manager: ModuleManager,
    module_name: str,
    odoo_series: OdooSeries | None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Aggregate addon inspection data for a single module."""
    return _build_addon_inspection_data_impl(
        module_manager,
        module_name,
        odoo_series,
        get_agent_addon_type_fn=_get_agent_addon_type,
    )


def _build_update_plan_data(
    global_config: GlobalConfig,
    module_name: str,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Build a read-only update plan for a module."""
    return _build_update_plan_data_impl(
        global_config,
        module_name,
        module_manager_cls=ModuleManager,
        addons_path_manager_cls=AddonsPathManager,
        build_addon_inspection_data_fn=_build_addon_inspection_data,
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
