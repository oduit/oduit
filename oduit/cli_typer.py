# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""New Typer-based CLI implementation for oduit."""

from typing import Any

import typer
from manifestoo_core.odoo_series import OdooSeries

from .addons_path_manager import AddonsPathManager
from .cli import agent_support as _agent_support
from .cli import bootstrap_support as _bootstrap_support
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
from .cli.main_support import handle_no_subcommand
from .cli.register_agent_commands import register_agent_commands
from .cli.register_app_commands import register_app_commands
from .cli_types import (
    AddonTemplate,
    GlobalConfig,
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


def create_global_config(
    env: str | None = None,
    json: bool = False,
    non_interactive: bool = False,
    verbose: bool = False,
    no_http: bool = False,
    odoo_series: OdooSeries | None = None,
) -> GlobalConfig:
    """Create and validate global configuration."""
    return _bootstrap_support.create_global_config(
        env=env,
        json=json,
        non_interactive=non_interactive,
        verbose=verbose,
        no_http=no_http,
        odoo_series=odoo_series,
        configure_output_fn=configure_output,
        config_loader_cls=ConfigLoader,
        print_error_fn=print_error,
        echo_fn=typer.echo,
        resolve_config_source_fn=_bootstrap_support.resolve_config_source,
    )


# App objects are defined in oduit.cli.app and re-exported here.


_bootstrap_registration_helpers = _bootstrap_support.build_registration_helpers(
    create_global_config_fn=create_global_config,
    print_error_fn=print_error,
    build_doctor_report_impl_fn=build_doctor_report,
    get_addons_path_manager_cls=lambda: AddonsPathManager,
    get_module_manager_cls=lambda: ModuleManager,
    get_odoo_operations_cls=lambda: OdooOperations,
)


_agent_registration_helpers = _agent_support.build_registration_helpers(
    safe_read_only=SAFE_READ_ONLY,
    fail_impl_fn=_agent_fail_impl,
    emit_payload_fn=_agent_emit_payload_impl,
    resolve_agent_global_config_impl_fn=_resolve_agent_global_config_impl,
    configure_output_fn=configure_output,
    get_config_loader_cls=lambda: ConfigLoader,
    resolve_config_source_fn=_bootstrap_support.resolve_config_source,
    parse_view_types_impl_fn=_parse_view_types_impl,
    parse_json_list_option_impl_fn=_parse_json_list_option_impl,
    resolve_agent_ops_impl_fn=_resolve_agent_ops_impl,
    get_odoo_operations_cls=lambda: OdooOperations,
    require_agent_addons_path_impl_fn=_require_agent_addons_path_impl,
    agent_require_mutation_impl_fn=_agent_require_mutation_impl,
    build_error_output_excerpt_impl_fn=_build_error_output_excerpt_impl,
    build_agent_test_summary_details_impl_fn=_build_agent_test_summary_details_impl,
    build_validate_addon_change_payload_impl_fn=(
        _agent_validate_impl.build_validate_addon_change_payload
    ),
    run_validate_addon_change_preflight_impl_fn=(
        _agent_validate_impl.run_validate_addon_change_preflight
    ),
    build_validate_addon_change_discovery_result_impl_fn=(
        _agent_validate_impl.build_validate_addon_change_discovery_result
    ),
    agent_sub_result_impl_fn=_agent_sub_result_impl,
    build_doctor_report_fn=_bootstrap_registration_helpers["build_doctor_report_fn"],
    module_not_found_error_cls=OduitModuleNotFoundError,
    config_error_cls=ConfigError,
)


def _check_environment_exists(config_loader: ConfigLoader, env_name: str) -> None:
    """Check if environment already exists and exit if it does."""
    check_environment_exists(config_loader, env_name)


def _detect_binaries(
    python_bin: str | None,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> tuple[str, str | None, str | None]:
    """Auto-detect binary paths if not provided."""
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
    """Import config from .conf or convert flat config to sectioned format."""
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

    ctx.obj = {
        "env": env,
        "json": json,
        "non_interactive": non_interactive,
        "verbose": verbose,
        "no_http": no_http,
        "odoo_series": odoo_series,
    }
    handle_no_subcommand(
        ctx=ctx,
        config_loader_cls=ConfigLoader,
        print_error_fn=print_error,
    )


register_app_commands(
    app=app,
    dev_option=DEV_OPTION,
    shell_interface_option=SHELL_INTERFACE_OPTION,
    addon_template_option=ADDON_TEMPLATE_OPTION,
    log_level_option=LOG_LEVEL_OPTION,
    language_option=LANGUAGE_OPTION,
    sort_option=SORT_OPTION,
    include_filter_option=INCLUDE_FILTER_OPTION,
    exclude_filter_option=EXCLUDE_FILTER_OPTION,
    valid_filter_fields_str=_VALID_FILTER_FIELDS_STR,
    resolve_command_global_config_fn=_bootstrap_registration_helpers[
        "resolve_command_global_config_fn"
    ],
    resolve_command_env_config_fn=_bootstrap_registration_helpers[
        "resolve_command_env_config_fn"
    ],
    build_odoo_operations_fn=_bootstrap_registration_helpers[
        "build_odoo_operations_fn"
    ],
    build_doctor_report_fn=_bootstrap_registration_helpers["build_doctor_report_fn"],
    print_doctor_report_fn=print_doctor_report,
    confirmation_required_error_fn=confirmation_required_error,
    print_command_error_result_fn=print_command_error_result,
    dependency_error_details_fn=dependency_error_details,
    get_config_loader_cls=lambda: ConfigLoader,
    get_module_manager_cls=lambda: ModuleManager,
    get_addons_path_manager_cls=lambda: AddonsPathManager,
    validate_addon_name_fn=lambda addon_name: validate_addon_name(addon_name),
    get_addon_type_fn=get_addon_type,
    build_addon_table_fn=build_addon_table,
    get_addon_field_value_fn=get_addon_field_value,
    apply_core_addon_filters_fn=apply_core_addon_filters,
    apply_field_filters_fn=apply_field_filters,
    print_dependency_tree_fn=print_dependency_tree,
    print_dependency_list_fn=print_dependency_list,
    check_environment_exists_fn=check_environment_exists,
    detect_binaries_fn=detect_binaries,
    build_initial_config_fn=build_initial_config,
    import_or_convert_config_fn=import_or_convert_config,
    normalize_addons_path_fn=normalize_addons_path,
    save_config_file_fn=save_config_file,
    display_config_summary_fn=display_config_summary,
    doctor_command_impl=_doctor_command_impl,
    run_command_impl=_run_command_impl,
    shell_command_impl=_shell_command_impl,
    install_command_impl=_install_command_impl,
    update_command_impl=_update_command_impl,
    test_command_impl=_test_command_impl,
    create_db_command_impl=_create_db_command_impl,
    list_db_command_impl=_list_db_command_impl,
    list_env_command_impl=_list_env_command_impl,
    print_config_command_impl=_print_config_command_impl,
    create_addon_command_impl=_create_addon_command_impl,
    print_manifest_command_impl=_print_manifest_command_impl,
    list_addons_command_impl=_list_addons_command_impl,
    list_manifest_values_command_impl=_list_manifest_values_command_impl,
    list_duplicates_command_impl=_list_duplicates_command_impl,
    list_depends_command_impl=_list_depends_command_impl,
    list_codepends_command_impl=_list_codepends_command_impl,
    install_order_command_impl=_install_order_command_impl,
    impact_of_update_command_impl=_impact_of_update_command_impl,
    list_missing_command_impl=_list_missing_command_impl,
    init_env_command_impl=_init_env_command_impl,
    export_lang_command_impl=_export_lang_command_impl,
    get_odoo_version_command_impl=_get_odoo_version_command_impl,
    valid_filter_fields=VALID_FILTER_FIELDS,
)


register_agent_commands(
    agent_app=agent_app,
    addon_template_option=ADDON_TEMPLATE_OPTION,
    language_option=LANGUAGE_OPTION,
    log_level_option=LOG_LEVEL_OPTION,
    include_filter_option=INCLUDE_FILTER_OPTION,
    exclude_filter_option=EXCLUDE_FILTER_OPTION,
    sort_option=SORT_OPTION,
    resolve_agent_global_config_fn=_agent_registration_helpers[
        "resolve_agent_global_config_fn"
    ],
    resolve_agent_ops_fn=_agent_registration_helpers["resolve_agent_ops_fn"],
    parse_view_types_fn=_agent_registration_helpers["parse_view_types_fn"],
    strip_arch_from_model_views_fn=_strip_arch_from_model_views_impl,
    require_agent_addons_path_fn=_agent_registration_helpers[
        "require_agent_addons_path_fn"
    ],
    parse_filter_values_fn=_parse_filter_values_impl,
    parse_csv_items_fn=_parse_csv_items_impl,
    parse_json_list_option_fn=_agent_registration_helpers["parse_json_list_option_fn"],
    redact_config_fn=_redact_config_impl,
    build_doctor_report_fn=_bootstrap_registration_helpers["build_doctor_report_fn"],
    agent_fail_fn=_agent_registration_helpers["agent_fail_fn"],
    agent_payload_fn=_agent_payload_impl,
    agent_emit_payload_fn=_agent_emit_payload_impl,
    agent_require_mutation_fn=_agent_registration_helpers["agent_require_mutation_fn"],
    agent_sub_result_fn=_agent_sub_result_impl,
    build_agent_test_summary_details_fn=_agent_registration_helpers[
        "build_agent_test_summary_details_fn"
    ],
    build_validate_addon_change_payload_fn=_agent_registration_helpers[
        "build_validate_addon_change_payload_fn"
    ],
    run_validate_addon_change_preflight_fn=_agent_registration_helpers[
        "run_validate_addon_change_preflight_fn"
    ],
    build_validate_addon_change_discovery_result_fn=(
        _agent_registration_helpers["build_validate_addon_change_discovery_result_fn"]
    ),
    apply_core_addon_filters_fn=apply_core_addon_filters,
    apply_field_filters_fn=apply_field_filters,
    get_odoo_operations_cls=lambda: OdooOperations,
    get_module_manager_cls=lambda: ModuleManager,
    output_result_to_json_fn=lambda *args, **kwargs: output_result_to_json(
        *args, **kwargs
    ),
    safe_read_only=SAFE_READ_ONLY,
    controlled_runtime_mutation=CONTROLLED_RUNTIME_MUTATION,
    controlled_source_mutation=CONTROLLED_SOURCE_MUTATION,
    config_error_cls=ConfigError,
    module_not_found_error_cls=OduitModuleNotFoundError,
    context_command_impl=_agent_context_command,
    inspect_addon_command_impl=_agent_inspect_addon_command,
    plan_update_command_impl=_agent_plan_update_command,
    locate_model_command_impl=_agent_locate_model_command,
    locate_field_command_impl=_agent_locate_field_command,
    list_addon_tests_command_impl=_agent_list_addon_tests_command,
    list_addon_models_command_impl=_agent_list_addon_models_command,
    find_model_extensions_command_impl=_agent_find_model_extensions_command,
    get_model_views_command_impl=_agent_get_model_views_command,
    doctor_command_impl=_agent_doctor_command,
    list_addons_command_impl=_agent_list_addons_command,
    dependency_graph_command_impl=_agent_dependency_graph_command,
    inspect_addons_command_impl=_agent_inspect_addons_command,
    resolve_config_command_impl=_agent_resolve_config_command,
    list_duplicates_command_impl=_agent_list_duplicates_command,
    install_module_command_impl=_agent_install_module_command,
    update_module_command_impl=_agent_update_module_command,
    create_addon_command_impl=_agent_create_addon_command,
    export_lang_command_impl=_agent_export_lang_command,
    test_summary_command_impl=_agent_test_summary_command,
    validate_impl=_agent_validate_impl,
    query_model_command_impl=_agent_query_model_command,
    read_record_command_impl=_agent_read_record_command,
    search_count_command_impl=_agent_search_count_command,
    get_model_fields_command_impl=_agent_get_model_fields_command,
)


def cli_main() -> None:
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    cli_main()
