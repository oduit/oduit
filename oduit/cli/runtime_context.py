"""Typed runtime and registration contexts for CLI composition."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import typer

from ..cli_types import GlobalConfig

ResolveCommandGlobalConfigFn = Callable[[typer.Context], GlobalConfig]
ResolveCommandEnvConfigFn = Callable[
    [typer.Context], tuple[GlobalConfig, dict[str, Any]]
]
BuildOdooOperationsFn = Callable[[GlobalConfig], Any]
BuildDoctorReportFn = Callable[[GlobalConfig], dict[str, Any]]
ResolveAgentGlobalConfigFn = Callable[[typer.Context, str, str], GlobalConfig]
ResolveAgentOpsFn = Callable[[typer.Context, str, str], tuple[GlobalConfig, Any]]


@dataclass(frozen=True)
class AppRuntimeContext:
    """Bound helpers for classic CLI command registration."""

    resolve_command_global_config_fn: ResolveCommandGlobalConfigFn
    resolve_command_env_config_fn: ResolveCommandEnvConfigFn
    build_odoo_operations_fn: BuildOdooOperationsFn
    build_doctor_report_fn: BuildDoctorReportFn


@dataclass(frozen=True)
class AppRegistrationOptions:
    """Reusable classic CLI options and filter metadata."""

    dev_option: Any
    shell_interface_option: Any
    addon_template_option: Any
    log_level_option: Any
    language_option: Any
    sort_option: Any
    include_filter_option: Any
    exclude_filter_option: Any
    valid_filter_fields_str: str
    valid_filter_fields: list[str]


@dataclass(frozen=True)
class AppRegistrationDependencies:
    """Classic CLI registration dependencies beyond bound runtime helpers."""

    print_doctor_report_fn: Any
    confirmation_required_error_fn: Any
    print_command_error_result_fn: Any
    require_cli_runtime_db_mutation_fn: Any
    dependency_error_details_fn: Any
    get_config_loader_cls: Callable[[], Any]
    get_module_manager_cls: Callable[[], Any]
    get_addons_path_manager_cls: Callable[[], Any]
    module_not_found_error_cls: Any
    validate_addon_name_fn: Any
    get_addon_type_fn: Any
    build_addon_table_fn: Any
    get_addon_field_value_fn: Any
    apply_core_addon_filters_fn: Any
    apply_field_filters_fn: Any
    print_dependency_tree_fn: Any
    print_dependency_list_fn: Any
    check_environment_exists_fn: Any
    detect_binaries_fn: Any
    build_initial_config_fn: Any
    import_or_convert_config_fn: Any
    normalize_addons_path_fn: Any
    save_config_file_fn: Any
    display_config_summary_fn: Any


@dataclass(frozen=True)
class AppCommandImplementations:
    """Classic CLI command implementations."""

    doctor_command_impl: Any
    run_command_impl: Any
    shell_command_impl: Any
    install_command_impl: Any
    update_command_impl: Any
    uninstall_command_impl: Any
    test_command_impl: Any
    create_db_command_impl: Any
    list_db_command_impl: Any
    list_env_command_impl: Any
    print_config_command_impl: Any
    edit_config_command_impl: Any
    create_addon_command_impl: Any
    addon_info_command_impl: Any
    print_manifest_command_impl: Any
    list_addons_command_impl: Any
    list_installed_addons_command_impl: Any
    list_manifest_values_command_impl: Any
    list_duplicates_command_impl: Any
    list_depends_command_impl: Any
    list_codepends_command_impl: Any
    install_order_command_impl: Any
    impact_of_update_command_impl: Any
    list_missing_command_impl: Any
    init_env_command_impl: Any
    export_lang_command_impl: Any
    get_odoo_version_command_impl: Any


@dataclass(frozen=True)
class AppRegistrationContext:
    """Everything needed to register classic CLI commands."""

    app: typer.Typer
    options: AppRegistrationOptions
    runtime: AppRuntimeContext
    dependencies: AppRegistrationDependencies
    implementations: AppCommandImplementations


@dataclass(frozen=True)
class AgentRuntimeContext:
    """Bound helpers and payload services for agent command registration."""

    resolve_agent_global_config_fn: ResolveAgentGlobalConfigFn
    resolve_agent_ops_fn: ResolveAgentOpsFn
    parse_view_types_fn: Any
    strip_arch_from_model_views_fn: Any
    require_agent_addons_path_fn: Any
    parse_filter_values_fn: Any
    apply_core_addon_filters_fn: Any
    apply_field_filters_fn: Any
    parse_csv_items_fn: Any
    parse_json_list_option_fn: Any
    redact_config_fn: Any
    build_doctor_report_fn: Any
    agent_fail_fn: Any
    agent_payload_fn: Any
    agent_emit_payload_fn: Any
    agent_require_mutation_fn: Any
    agent_require_runtime_db_mutation_fn: Any
    agent_sub_result_fn: Any
    build_agent_test_summary_details_fn: Any
    build_validate_addon_change_payload_fn: Any
    run_validate_addon_change_preflight_fn: Any
    build_validate_addon_change_discovery_result_fn: Any
    output_result_to_json_fn: Any


@dataclass(frozen=True)
class AgentHelperContext:
    """Bound helpers built by the agent composition support module."""

    agent_fail_fn: Any
    resolve_agent_global_config_fn: ResolveAgentGlobalConfigFn
    parse_view_types_fn: Any
    parse_json_list_option_fn: Any
    resolve_agent_ops_fn: ResolveAgentOpsFn
    require_agent_addons_path_fn: Any
    agent_require_mutation_fn: Any
    agent_require_runtime_db_mutation_fn: Any
    build_agent_test_summary_details_fn: Any
    build_validate_addon_change_payload_fn: Any
    run_validate_addon_change_preflight_fn: Any
    build_validate_addon_change_discovery_result_fn: Any


@dataclass(frozen=True)
class AgentRegistrationOptions:
    """Reusable agent CLI options."""

    addon_template_option: Any
    language_option: Any
    log_level_option: Any
    include_filter_option: Any
    exclude_filter_option: Any
    sort_option: Any


@dataclass(frozen=True)
class AgentRegistrationDependencies:
    """Agent registration dependencies beyond bound helper callables."""

    safe_read_only: str
    controlled_runtime_mutation: str
    controlled_source_mutation: str
    get_config_loader_cls: Callable[[], Any]
    get_odoo_operations_cls: Callable[[], Any]
    get_module_manager_cls: Callable[[], Any]
    config_error_cls: Any
    module_not_found_error_cls: Any
    os_module: Any


@dataclass(frozen=True)
class AgentCommandImplementations:
    """Agent command implementations."""

    context_command_impl: Any
    addon_info_command_impl: Any
    inspect_addon_command_impl: Any
    plan_update_command_impl: Any
    prepare_addon_change_command_impl: Any
    locate_model_command_impl: Any
    locate_field_command_impl: Any
    list_addon_tests_command_impl: Any
    recommend_tests_command_impl: Any
    list_addon_models_command_impl: Any
    find_model_extensions_command_impl: Any
    get_model_views_command_impl: Any
    doctor_command_impl: Any
    list_addons_command_impl: Any
    list_installed_addons_command_impl: Any
    dependency_graph_command_impl: Any
    inspect_addons_command_impl: Any
    resolve_config_command_impl: Any
    resolve_addon_root_command_impl: Any
    get_addon_files_command_impl: Any
    check_addons_installed_command_impl: Any
    check_model_exists_command_impl: Any
    check_field_exists_command_impl: Any
    list_duplicates_command_impl: Any
    inspect_ref_command_impl: Any
    inspect_cron_command_impl: Any
    inspect_modules_command_impl: Any
    inspect_subtypes_command_impl: Any
    inspect_model_command_impl: Any
    inspect_field_command_impl: Any
    db_table_command_impl: Any
    db_column_command_impl: Any
    db_constraints_command_impl: Any
    db_tables_command_impl: Any
    db_m2m_command_impl: Any
    performance_slow_queries_command_impl: Any
    performance_table_scans_command_impl: Any
    performance_indexes_command_impl: Any
    manifest_check_command_impl: Any
    manifest_show_command_impl: Any
    install_module_command_impl: Any
    uninstall_module_command_impl: Any
    update_module_command_impl: Any
    create_addon_command_impl: Any
    export_lang_command_impl: Any
    test_summary_command_impl: Any
    validate_impl: Any
    query_model_command_impl: Any
    read_record_command_impl: Any
    search_count_command_impl: Any
    get_model_fields_command_impl: Any


@dataclass(frozen=True)
class AgentRegistrationContext:
    """Everything needed to register agent CLI commands."""

    agent_app: typer.Typer
    options: AgentRegistrationOptions
    runtime: AgentRuntimeContext
    dependencies: AgentRegistrationDependencies
    implementations: AgentCommandImplementations
