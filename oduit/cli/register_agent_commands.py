"""Registration helpers for `oduit agent` subcommands."""

from __future__ import annotations

import typer

from ..cli_types import AddonTemplate, LogLevel
from .runtime_context import AgentRegistrationContext

INSTALLED_ADDON_STATE_OPTION = typer.Option(
    [],
    "--state",
    help="Repeatable runtime state filter (defaults to installed)",
)


def register_agent_commands(context: AgentRegistrationContext) -> None:  # noqa: C901
    """Register agent-first commands on the shared Typer app."""

    agent_app = context.agent_app
    addon_template_option = context.options.addon_template_option
    language_option = context.options.language_option
    log_level_option = context.options.log_level_option
    include_filter_option = context.options.include_filter_option
    exclude_filter_option = context.options.exclude_filter_option
    sort_option = context.options.sort_option
    resolve_agent_global_config_fn = context.runtime.resolve_agent_global_config_fn
    resolve_agent_ops_fn = context.runtime.resolve_agent_ops_fn
    parse_view_types_fn = context.runtime.parse_view_types_fn
    strip_arch_from_model_views_fn = context.runtime.strip_arch_from_model_views_fn
    require_agent_addons_path_fn = context.runtime.require_agent_addons_path_fn
    parse_filter_values_fn = context.runtime.parse_filter_values_fn
    apply_core_addon_filters_fn = context.runtime.apply_core_addon_filters_fn
    apply_field_filters_fn = context.runtime.apply_field_filters_fn
    parse_csv_items_fn = context.runtime.parse_csv_items_fn
    parse_json_list_option_fn = context.runtime.parse_json_list_option_fn
    redact_config_fn = context.runtime.redact_config_fn
    build_doctor_report_fn = context.runtime.build_doctor_report_fn
    agent_fail_fn = context.runtime.agent_fail_fn
    agent_payload_fn = context.runtime.agent_payload_fn
    agent_emit_payload_fn = context.runtime.agent_emit_payload_fn
    agent_require_mutation_fn = context.runtime.agent_require_mutation_fn
    agent_require_runtime_db_mutation_fn = (
        context.runtime.agent_require_runtime_db_mutation_fn
    )
    agent_sub_result_fn = context.runtime.agent_sub_result_fn
    build_agent_test_summary_details_fn = (
        context.runtime.build_agent_test_summary_details_fn
    )
    build_validate_addon_change_payload_fn = (
        context.runtime.build_validate_addon_change_payload_fn
    )
    run_validate_addon_change_preflight_fn = (
        context.runtime.run_validate_addon_change_preflight_fn
    )
    build_validate_addon_change_discovery_result_fn = (
        context.runtime.build_validate_addon_change_discovery_result_fn
    )
    output_result_to_json_fn = context.runtime.output_result_to_json_fn
    safe_read_only = context.dependencies.safe_read_only
    controlled_runtime_mutation = context.dependencies.controlled_runtime_mutation
    controlled_source_mutation = context.dependencies.controlled_source_mutation
    get_config_loader_cls = context.dependencies.get_config_loader_cls
    get_odoo_operations_cls = context.dependencies.get_odoo_operations_cls
    get_module_manager_cls = context.dependencies.get_module_manager_cls
    config_error_cls = context.dependencies.config_error_cls
    module_not_found_error_cls = context.dependencies.module_not_found_error_cls
    os_module = context.dependencies.os_module
    context_command_impl = context.implementations.context_command_impl
    addon_info_command_impl = context.implementations.addon_info_command_impl
    inspect_addon_command_impl = context.implementations.inspect_addon_command_impl
    plan_update_command_impl = context.implementations.plan_update_command_impl
    prepare_addon_change_command_impl = (
        context.implementations.prepare_addon_change_command_impl
    )
    locate_model_command_impl = context.implementations.locate_model_command_impl
    locate_field_command_impl = context.implementations.locate_field_command_impl
    list_addon_tests_command_impl = (
        context.implementations.list_addon_tests_command_impl
    )
    recommend_tests_command_impl = context.implementations.recommend_tests_command_impl
    list_addon_models_command_impl = (
        context.implementations.list_addon_models_command_impl
    )
    find_model_extensions_command_impl = (
        context.implementations.find_model_extensions_command_impl
    )
    get_model_views_command_impl = context.implementations.get_model_views_command_impl
    doctor_command_impl = context.implementations.doctor_command_impl
    list_addons_command_impl = context.implementations.list_addons_command_impl
    list_installed_addons_command_impl = (
        context.implementations.list_installed_addons_command_impl
    )
    dependency_graph_command_impl = (
        context.implementations.dependency_graph_command_impl
    )
    inspect_addons_command_impl = context.implementations.inspect_addons_command_impl
    resolve_config_command_impl = context.implementations.resolve_config_command_impl
    resolve_addon_root_command_impl = (
        context.implementations.resolve_addon_root_command_impl
    )
    get_addon_files_command_impl = context.implementations.get_addon_files_command_impl
    check_addons_installed_command_impl = (
        context.implementations.check_addons_installed_command_impl
    )
    check_model_exists_command_impl = (
        context.implementations.check_model_exists_command_impl
    )
    check_field_exists_command_impl = (
        context.implementations.check_field_exists_command_impl
    )
    list_duplicates_command_impl = context.implementations.list_duplicates_command_impl
    inspect_ref_command_impl = context.implementations.inspect_ref_command_impl
    inspect_cron_command_impl = context.implementations.inspect_cron_command_impl
    inspect_modules_command_impl = context.implementations.inspect_modules_command_impl
    inspect_subtypes_command_impl = (
        context.implementations.inspect_subtypes_command_impl
    )
    inspect_model_command_impl = context.implementations.inspect_model_command_impl
    inspect_field_command_impl = context.implementations.inspect_field_command_impl
    db_table_command_impl = context.implementations.db_table_command_impl
    db_column_command_impl = context.implementations.db_column_command_impl
    db_constraints_command_impl = context.implementations.db_constraints_command_impl
    db_tables_command_impl = context.implementations.db_tables_command_impl
    db_m2m_command_impl = context.implementations.db_m2m_command_impl
    performance_slow_queries_command_impl = (
        context.implementations.performance_slow_queries_command_impl
    )
    performance_table_scans_command_impl = (
        context.implementations.performance_table_scans_command_impl
    )
    performance_indexes_command_impl = (
        context.implementations.performance_indexes_command_impl
    )
    manifest_check_command_impl = context.implementations.manifest_check_command_impl
    manifest_show_command_impl = context.implementations.manifest_show_command_impl
    install_module_command_impl = context.implementations.install_module_command_impl
    uninstall_module_command_impl = (
        context.implementations.uninstall_module_command_impl
    )
    update_module_command_impl = context.implementations.update_module_command_impl
    create_addon_command_impl = context.implementations.create_addon_command_impl
    export_lang_command_impl = context.implementations.export_lang_command_impl
    test_summary_command_impl = context.implementations.test_summary_command_impl
    validate_impl = context.implementations.validate_impl
    query_model_command_impl = context.implementations.query_model_command_impl
    read_record_command_impl = context.implementations.read_record_command_impl
    search_count_command_impl = context.implementations.search_count_command_impl
    get_model_fields_command_impl = (
        context.implementations.get_model_fields_command_impl
    )

    @agent_app.command("context")
    def agent_context(ctx: typer.Context) -> None:
        """Return a structured environment snapshot for automation."""
        context_command_impl(
            ctx,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
            safe_read_only=safe_read_only,
        )

    @agent_app.command("inspect-addon")
    def agent_inspect_addon(
        ctx: typer.Context,
        module: str = typer.Argument(help="Addon to inspect"),
    ) -> None:
        """Return a one-shot addon inspection payload."""
        inspect_addon_command_impl(
            ctx,
            module=module,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
            module_not_found_error_cls=module_not_found_error_cls,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("addon-info")
    def agent_addon_info(
        ctx: typer.Context,
        module: str = typer.Argument(help="Addon to summarize"),
        database: str | None = typer.Option(None, "--database"),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Runtime query timeout in seconds"
        ),
    ) -> None:
        """Return a combined manifest, source, and runtime addon summary."""
        addon_info_command_impl(
            ctx,
            module=module,
            database=database,
            timeout=timeout,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
            module_not_found_error_cls=module_not_found_error_cls,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("plan-update")
    def agent_plan_update(
        ctx: typer.Context,
        module: str = typer.Argument(help="Addon to plan an update for"),
    ) -> None:
        """Return a structured, read-only update plan for a module."""
        plan_update_command_impl(
            ctx,
            module=module,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
            module_not_found_error_cls=module_not_found_error_cls,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("prepare-addon-change")
    def agent_prepare_addon_change(
        ctx: typer.Context,
        module: str = typer.Argument(help="Addon to prepare a change for"),
        model: str | None = typer.Option(None, "--model", help="Optional model hint"),
        field_name: str | None = typer.Option(
            None,
            "--field",
            help="Optional field hint",
        ),
        attributes: str | None = typer.Option(
            "string,type,required",
            "--attributes",
            help="Comma-separated field metadata attributes for runtime inspection",
        ),
        types: str | None = typer.Option(
            None,
            "--types",
            help="Comma-separated view types, e.g. form,tree,kanban,search",
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Query timeout in seconds"
        ),
    ) -> None:
        """Bundle the common read-only planning steps for one addon change."""
        prepare_addon_change_command_impl(
            ctx,
            module=module,
            model=model,
            field_name=field_name,
            attributes=attributes,
            types=types,
            database=database,
            timeout=timeout,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            parse_view_types_fn=parse_view_types_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_sub_result_fn=agent_sub_result_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("locate-model")
    def agent_locate_model(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to locate"),
        module: str = typer.Option(..., "--module", help="Addon to inspect"),
    ) -> None:
        """Locate likely source files for a model extension inside one addon."""
        locate_model_command_impl(
            ctx,
            model=model,
            module=module,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
        )

    @agent_app.command("locate-field")
    def agent_locate_field(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        field_name: str = typer.Argument(help="Field to locate"),
        module: str = typer.Option(..., "--module", help="Addon to inspect"),
    ) -> None:
        """Locate an existing field or suggest the best insertion point."""
        locate_field_command_impl(
            ctx,
            model=model,
            field_name=field_name,
            module=module,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
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
        """List likely tests for an addon, optionally ranked by hints."""
        list_addon_tests_command_impl(
            ctx,
            module=module,
            model=model,
            field_name=field_name,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
        )

    @agent_app.command("recommend-tests")
    def agent_recommend_tests(
        ctx: typer.Context,
        module: str = typer.Option(..., "--module", help="Addon to inspect"),
        paths: str = typer.Option(
            ...,
            "--paths",
            help="Comma-separated changed paths relative to the addon root",
        ),
    ) -> None:
        """Map changed addon files to recommended tests and test tags."""
        recommend_tests_command_impl(
            ctx,
            module=module,
            paths=paths,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
        )

    @agent_app.command("list-addon-models")
    def agent_list_addon_models(
        ctx: typer.Context,
        module: str = typer.Argument(help="Addon to inspect"),
    ) -> None:
        """List the models declared or extended by one addon."""
        list_addon_models_command_impl(
            ctx,
            module=module,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
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
        timeout: float = typer.Option(
            30.0, "--timeout", help="Query timeout in seconds"
        ),
    ) -> None:
        """Find where a model is declared, extended, and installed."""
        find_model_extensions_command_impl(
            ctx,
            model=model,
            summary=summary,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            config_error_cls=config_error_cls,
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
        timeout: float = typer.Option(
            30.0, "--timeout", help="Query timeout in seconds"
        ),
    ) -> None:
        """Fetch database-backed primary and extension views for a model."""
        get_model_views_command_impl(
            ctx,
            model=model,
            types=types,
            summary=summary,
            database=database,
            timeout=timeout,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            parse_view_types_fn=parse_view_types_fn,
            strip_arch_from_model_views_fn=strip_arch_from_model_views_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
        )

    @agent_app.command("doctor")
    def agent_doctor(ctx: typer.Context) -> None:
        """Return doctor diagnostics through the standard agent envelope."""
        doctor_command_impl(
            ctx,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            build_doctor_report_fn=build_doctor_report_fn,
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
        include: list[str] = include_filter_option,
        exclude: list[str] = exclude_filter_option,
        sorting: str = sort_option,
    ) -> None:
        """Return structured addon inventory for the active environment."""
        list_addons_command_impl(
            ctx,
            select_dir=select_dir,
            include=include,
            exclude=exclude,
            sorting=sorting,
            exclude_core_addons=exclude_core_addons,
            exclude_enterprise_addons=exclude_enterprise_addons,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            require_agent_addons_path_fn=require_agent_addons_path_fn,
            parse_filter_values_fn=parse_filter_values_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            module_manager_cls=get_module_manager_cls(),
            apply_core_addon_filters_fn=apply_core_addon_filters_fn,
            apply_field_filters_fn=apply_field_filters_fn,
        )

    @agent_app.command("list-installed-addons")
    def agent_list_installed_addons(
        ctx: typer.Context,
        modules: str | None = typer.Option(
            None,
            "--module",
            "--modules",
            help="Comma-separated addon names to inspect at runtime",
        ),
        state: list[str] = INSTALLED_ADDON_STATE_OPTION,
    ) -> None:
        """Return structured runtime installed-addon inventory."""
        list_installed_addons_command_impl(
            ctx,
            modules=modules,
            state=state,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("dependency-graph")
    def agent_dependency_graph(
        ctx: typer.Context,
        modules: str = typer.Option(
            ..., "--modules", help="Comma-separated addon names"
        ),
    ) -> None:
        """Return a structured dependency and reverse-dependency graph."""
        dependency_graph_command_impl(
            ctx,
            modules=modules,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            config_error_cls=config_error_cls,
        )

    @agent_app.command("inspect-addons")
    def agent_inspect_addons(
        ctx: typer.Context,
        modules: str = typer.Option(
            ..., "--modules", help="Comma-separated addon names"
        ),
    ) -> None:
        """Inspect multiple addons through the stable agent envelope."""
        inspect_addons_command_impl(
            ctx,
            modules=modules,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            module_not_found_error_cls=module_not_found_error_cls,
        )

    @agent_app.command("resolve-config")
    def agent_resolve_config(ctx: typer.Context) -> None:
        """Return the resolved configuration with sensitive values redacted."""
        resolve_config_command_impl(
            ctx,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            config_loader_cls=get_config_loader_cls(),
            redact_config_fn=redact_config_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
        )

    @agent_app.command("resolve-addon-root")
    def agent_resolve_addon_root(
        ctx: typer.Context,
        module: str = typer.Argument(help="Addon to resolve"),
    ) -> None:
        """Resolve addon root paths for one module name."""
        resolve_addon_root_command_impl(
            ctx,
            module=module,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            require_agent_addons_path_fn=require_agent_addons_path_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("get-addon-files")
    def agent_get_addon_files(
        ctx: typer.Context,
        module: str = typer.Argument(help="Addon to inspect"),
        globs: str | None = typer.Option(
            None,
            "--globs",
            help="Optional comma-separated glob patterns relative to the addon root",
        ),
    ) -> None:
        """Return a deterministic file inventory for one addon."""
        get_addon_files_command_impl(
            ctx,
            module=module,
            globs=globs,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            require_agent_addons_path_fn=require_agent_addons_path_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("check-addons-installed")
    def agent_check_addons_installed(
        ctx: typer.Context,
        modules: str = typer.Option(
            ...,
            "--modules",
            help="Comma-separated addon names to inspect at runtime",
        ),
    ) -> None:
        """Return runtime installed-state checks for one or more addons."""
        check_addons_installed_command_impl(
            ctx,
            modules=modules,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("check-model-exists")
    def agent_check_model_exists(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        module: str | None = typer.Option(
            None,
            "--module",
            help="Optional addon hint for source filtering",
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Query timeout in seconds"
        ),
    ) -> None:
        """Check whether a model exists in source discovery and runtime metadata."""
        check_model_exists_command_impl(
            ctx,
            model=model,
            module=module,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            require_agent_addons_path_fn=require_agent_addons_path_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("check-field-exists")
    def agent_check_field_exists(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        field_name: str = typer.Argument(help="Field name to inspect"),
        module: str | None = typer.Option(
            None,
            "--module",
            help="Optional addon hint for static source lookup",
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Query timeout in seconds"
        ),
    ) -> None:
        """Check whether a field exists in runtime metadata and source."""
        check_field_exists_command_impl(
            ctx,
            model=model,
            field_name=field_name,
            module=module,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("list-duplicates")
    def agent_list_duplicates(ctx: typer.Context) -> None:
        """Return duplicate addon names through the standard agent envelope."""
        list_duplicates_command_impl(
            ctx,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            config_error_cls=config_error_cls,
        )

    @agent_app.command("inspect-ref")
    def agent_inspect_ref(
        ctx: typer.Context,
        xmlid: str = typer.Argument(help="XMLID to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Resolve one XMLID through the embedded Odoo runtime."""
        inspect_ref_command_impl(
            ctx,
            xmlid=xmlid,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("inspect-cron")
    def agent_inspect_cron(
        ctx: typer.Context,
        xmlid: str = typer.Argument(help="Cron XMLID to inspect"),
        trigger: bool = typer.Option(
            False, "--trigger", help="Trigger the cron after resolving it"
        ),
        allow_mutation: bool = typer.Option(False, "--allow-mutation"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect one cron job and optionally trigger it."""
        inspect_cron_command_impl(
            ctx,
            xmlid=xmlid,
            trigger=trigger,
            allow_mutation=allow_mutation,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_require_mutation_fn=agent_require_mutation_fn,
            agent_require_runtime_db_mutation_fn=(agent_require_runtime_db_mutation_fn),
            safe_read_only=safe_read_only,
            controlled_runtime_mutation=controlled_runtime_mutation,
        )

    @agent_app.command("inspect-modules")
    def agent_inspect_modules(
        ctx: typer.Context,
        state: str | None = typer.Option(
            None, "--state", help="Filter by module state"
        ),
        names_only: bool = typer.Option(
            False, "--names-only", help="Return only module names in the payload"
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect module records from ir.module.module."""
        inspect_modules_command_impl(
            ctx,
            state=state,
            names_only=names_only,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("inspect-subtypes")
    def agent_inspect_subtypes(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """List message subtypes registered for one model."""
        inspect_subtypes_command_impl(
            ctx,
            model=model,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("inspect-model")
    def agent_inspect_model(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect runtime model registration metadata."""
        inspect_model_command_impl(
            ctx,
            model=model,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("inspect-field")
    def agent_inspect_field(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        field: str = typer.Argument(help="Field to inspect"),
        with_db: bool = typer.Option(
            False, "--with-db", help="Include DB-level metadata when available"
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect runtime field metadata."""
        inspect_field_command_impl(
            ctx,
            model=model,
            field=field,
            with_db=with_db,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("db-table")
    def agent_db_table(
        ctx: typer.Context,
        table_name: str = typer.Argument(help="Table to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Describe one PostgreSQL table through the live Odoo connection."""
        db_table_command_impl(
            ctx,
            table_name=table_name,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("db-column")
    def agent_db_column(
        ctx: typer.Context,
        table_name: str = typer.Argument(help="Table to inspect"),
        column_name: str = typer.Argument(help="Column to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Describe one PostgreSQL column through the live Odoo connection."""
        db_column_command_impl(
            ctx,
            table_name=table_name,
            column_name=column_name,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("db-constraints")
    def agent_db_constraints(
        ctx: typer.Context,
        table_name: str = typer.Argument(help="Table to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """List PostgreSQL constraints for one table."""
        db_constraints_command_impl(
            ctx,
            table_name=table_name,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("db-tables")
    def agent_db_tables(
        ctx: typer.Context,
        like: str | None = typer.Option(
            None, "--like", help="Filter table names with a case-insensitive pattern"
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """List PostgreSQL tables through the live Odoo connection."""
        db_tables_command_impl(
            ctx,
            like=like,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("db-m2m")
    def agent_db_m2m(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        field: str = typer.Argument(help="Many2many field to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect the relation table behind a Many2many field."""
        db_m2m_command_impl(
            ctx,
            model=model,
            field=field,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("performance-slow-queries")
    def agent_performance_slow_queries(
        ctx: typer.Context,
        limit: int = typer.Option(10, "--limit", help="Number of queries to show"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Read pg_stat_statements when the extension is available."""
        performance_slow_queries_command_impl(
            ctx,
            limit=limit,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("performance-table-scans")
    def agent_performance_table_scans(
        ctx: typer.Context,
        limit: int = typer.Option(20, "--limit", help="Number of tables to show"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Show tables with high sequential scan counts."""
        performance_table_scans_command_impl(
            ctx,
            limit=limit,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("performance-indexes")
    def agent_performance_indexes(
        ctx: typer.Context,
        limit: int = typer.Option(20, "--limit", help="Number of tables to show"),
        database: str | None = typer.Option(
            None, "--database", help="Override database name"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Show basic table index-usage metrics."""
        performance_indexes_command_impl(
            ctx,
            limit=limit,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("manifest-check")
    def agent_manifest_check(
        ctx: typer.Context,
        target: str = typer.Argument(help="Addon name or filesystem path"),
    ) -> None:
        """Validate a manifest file and report structural warnings."""
        manifest_check_command_impl(
            ctx,
            target=target,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("manifest-show")
    def agent_manifest_show(
        ctx: typer.Context,
        target: str = typer.Argument(help="Addon name or filesystem path"),
    ) -> None:
        """Show manifest metadata for an addon or addon path."""
        manifest_show_command_impl(
            ctx,
            target=target,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("install-module")
    def agent_install_module(
        ctx: typer.Context,
        module: str = typer.Argument(help="Module to install"),
        allow_mutation: bool = typer.Option(False, "--allow-mutation"),
        dry_run: bool = typer.Option(False, "--dry-run"),
        without_demo: str | None = typer.Option(None, "--without-demo"),
        with_demo: bool = typer.Option(False, "--with-demo"),
        language: str | None = language_option,
        max_cron_threads: int | None = typer.Option(None, "--max-cron-threads"),
        compact: bool = typer.Option(False, "--compact"),
        log_level: LogLevel | None = log_level_option,
    ) -> None:
        """Install a module with an explicit mutation gate."""
        install_module_command_impl(
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
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_require_mutation_fn=agent_require_mutation_fn,
            agent_require_runtime_db_mutation_fn=(agent_require_runtime_db_mutation_fn),
            output_result_to_json_fn=output_result_to_json_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            safe_read_only=safe_read_only,
            controlled_runtime_mutation=controlled_runtime_mutation,
        )

    @agent_app.command("update-module")
    def agent_update_module(
        ctx: typer.Context,
        module: str = typer.Argument(help="Module to update"),
        allow_mutation: bool = typer.Option(False, "--allow-mutation"),
        dry_run: bool = typer.Option(False, "--dry-run"),
        without_demo: str | None = typer.Option(None, "--without-demo"),
        language: str | None = language_option,
        i18n_overwrite: bool = typer.Option(False, "--i18n-overwrite"),
        max_cron_threads: int | None = typer.Option(None, "--max-cron-threads"),
        compact: bool = typer.Option(False, "--compact"),
        log_level: LogLevel | None = log_level_option,
    ) -> None:
        """Update a module with an explicit mutation gate."""
        update_module_command_impl(
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
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_require_mutation_fn=agent_require_mutation_fn,
            agent_require_runtime_db_mutation_fn=(agent_require_runtime_db_mutation_fn),
            output_result_to_json_fn=output_result_to_json_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            safe_read_only=safe_read_only,
            controlled_runtime_mutation=controlled_runtime_mutation,
        )

    @agent_app.command("uninstall-module")
    def agent_uninstall_module(
        ctx: typer.Context,
        module: str = typer.Argument(help="Module to uninstall"),
        allow_mutation: bool = typer.Option(False, "--allow-mutation"),
        allow_uninstall: bool = typer.Option(False, "--allow-uninstall"),
        dry_run: bool = typer.Option(False, "--dry-run"),
        compact: bool = typer.Option(False, "--compact"),
        log_level: LogLevel | None = log_level_option,
    ) -> None:
        """Uninstall a module with explicit runtime and destructive gates."""
        uninstall_module_command_impl(
            ctx,
            module=module,
            allow_mutation=allow_mutation,
            allow_uninstall=allow_uninstall,
            dry_run=dry_run,
            compact=compact,
            log_level=log_level,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_require_mutation_fn=agent_require_mutation_fn,
            agent_require_runtime_db_mutation_fn=(agent_require_runtime_db_mutation_fn),
            output_result_to_json_fn=output_result_to_json_fn,
            controlled_runtime_mutation=controlled_runtime_mutation,
            safe_read_only=safe_read_only,
        )

    @agent_app.command("create-addon")
    def agent_create_addon(
        ctx: typer.Context,
        addon_name: str = typer.Argument(help="Addon to create"),
        allow_mutation: bool = typer.Option(False, "--allow-mutation"),
        dry_run: bool = typer.Option(False, "--dry-run"),
        path: str | None = typer.Option(None, "--path"),
        template: AddonTemplate = addon_template_option,
    ) -> None:
        """Create a new addon with an explicit mutation gate."""
        create_addon_command_impl(
            ctx,
            addon_name=addon_name,
            allow_mutation=allow_mutation,
            dry_run=dry_run,
            path=path,
            template=template,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_require_mutation_fn=agent_require_mutation_fn,
            output_result_to_json_fn=output_result_to_json_fn,
            safe_read_only=safe_read_only,
            controlled_source_mutation=controlled_source_mutation,
        )

    @agent_app.command("export-lang")
    def agent_export_lang(
        ctx: typer.Context,
        module: str = typer.Argument(help="Module to export"),
        allow_mutation: bool = typer.Option(False, "--allow-mutation"),
        dry_run: bool = typer.Option(False, "--dry-run"),
        language: str | None = language_option,
        log_level: LogLevel | None = log_level_option,
    ) -> None:
        """Export language files with an explicit mutation gate."""
        export_lang_command_impl(
            ctx,
            module=module,
            allow_mutation=allow_mutation,
            dry_run=dry_run,
            language=language,
            log_level=log_level,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            require_agent_addons_path_fn=require_agent_addons_path_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_require_mutation_fn=agent_require_mutation_fn,
            output_result_to_json_fn=output_result_to_json_fn,
            module_manager_cls=get_module_manager_cls(),
            os_module=os_module,
            safe_read_only=safe_read_only,
            controlled_source_mutation=controlled_source_mutation,
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
        test_tags: str | None = typer.Option(
            None, "--test-tags", help="Test tags filter"
        ),
        stop_on_error: bool = typer.Option(False, "--stop-on-error"),
        compact: bool = typer.Option(False, "--compact"),
        log_level: LogLevel | None = log_level_option,
    ) -> None:
        """Run tests and emit a normalized summary payload."""
        test_summary_command_impl(
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
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_require_mutation_fn=agent_require_mutation_fn,
            agent_require_runtime_db_mutation_fn=(agent_require_runtime_db_mutation_fn),
            build_agent_test_summary_details_fn=build_agent_test_summary_details_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
            controlled_runtime_mutation=controlled_runtime_mutation,
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
            help=(
                "Include discovered addon test inventory after the module suite passes."
            ),
        ),
        stop_on_error: bool = typer.Option(False, "--stop-on-error"),
        compact: bool = typer.Option(False, "--compact"),
        log_level: LogLevel | None = log_level_option,
    ) -> None:
        """Validate an addon change with one aggregate structured payload."""
        validate_impl.agent_validate_addon_change_command(
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
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_require_mutation_fn=agent_require_mutation_fn,
            agent_require_runtime_db_mutation_fn=(agent_require_runtime_db_mutation_fn),
            agent_sub_result_fn=agent_sub_result_fn,
            build_agent_test_summary_details_fn=build_agent_test_summary_details_fn,
            build_validate_addon_change_payload_fn=build_validate_addon_change_payload_fn,
            run_validate_addon_change_preflight_fn=run_validate_addon_change_preflight_fn,
            build_validate_addon_change_discovery_result_fn=(
                build_validate_addon_change_discovery_result_fn
            ),
            build_doctor_report_fn=build_doctor_report_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
            controlled_runtime_mutation=controlled_runtime_mutation,
        )

    @agent_app.command("preflight-addon-change")
    def agent_preflight_addon_change(
        ctx: typer.Context,
        module: str = typer.Argument(help="Addon to inspect before editing"),
        model: str | None = typer.Option(None, "--model", help="Optional model hint"),
        field_name: str | None = typer.Option(
            None,
            "--field",
            help="Optional field hint; requires --model",
        ),
    ) -> None:
        """Run a cheap read-only addon-change preflight."""
        validate_impl.agent_preflight_addon_change_command(
            ctx,
            module=module,
            model=model,
            field_name=field_name,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            agent_fail_fn=agent_fail_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            agent_sub_result_fn=agent_sub_result_fn,
            build_preflight_addon_change_payload_fn=(
                validate_impl.build_preflight_addon_change_payload
            ),
            run_validate_addon_change_preflight_fn=run_validate_addon_change_preflight_fn,
            build_doctor_report_fn=build_doctor_report_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
            safe_read_only=safe_read_only,
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
        timeout: float = typer.Option(
            30.0, "--timeout", help="Query timeout in seconds"
        ),
    ) -> None:
        """Run a structured read-only model query."""
        query_model_command_impl(
            ctx,
            model=model,
            domain_json=domain_json,
            fields=fields,
            limit=limit,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            parse_json_list_option_fn=parse_json_list_option_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
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
        timeout: float = typer.Option(
            30.0, "--timeout", help="Query timeout in seconds"
        ),
    ) -> None:
        """Read a single record by id via OdooQuery."""
        read_record_command_impl(
            ctx,
            model=model,
            record_id=record_id,
            fields=fields,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
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
        timeout: float = typer.Option(
            30.0, "--timeout", help="Query timeout in seconds"
        ),
    ) -> None:
        """Count records matching a domain via OdooQuery."""
        search_count_command_impl(
            ctx,
            model=model,
            domain_json=domain_json,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            parse_json_list_option_fn=parse_json_list_option_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
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
        timeout: float = typer.Option(
            30.0, "--timeout", help="Query timeout in seconds"
        ),
    ) -> None:
        """Inspect model field metadata via OdooQuery."""
        get_model_fields_command_impl(
            ctx,
            model=model,
            attributes=attributes,
            database=database,
            timeout=timeout,
            resolve_agent_ops_fn=resolve_agent_ops_fn,
            parse_csv_items_fn=parse_csv_items_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
            safe_read_only=safe_read_only,
        )
