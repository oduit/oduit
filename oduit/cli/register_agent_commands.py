"""Registration helpers for `oduit agent` subcommands."""

import os
from typing import Any

import typer

from ..cli_types import AddonTemplate, LogLevel

INSTALLED_ADDON_STATE_OPTION = typer.Option(
    [],
    "--state",
    help="Repeatable runtime state filter (defaults to installed)",
)


def register_agent_commands(  # noqa: C901
    *,
    agent_app: typer.Typer,
    addon_template_option: Any,
    language_option: Any,
    log_level_option: Any,
    include_filter_option: Any,
    exclude_filter_option: Any,
    sort_option: Any,
    resolve_agent_global_config_fn: Any,
    resolve_agent_ops_fn: Any,
    parse_view_types_fn: Any,
    strip_arch_from_model_views_fn: Any,
    require_agent_addons_path_fn: Any,
    parse_filter_values_fn: Any,
    parse_csv_items_fn: Any,
    parse_json_list_option_fn: Any,
    redact_config_fn: Any,
    build_doctor_report_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    agent_sub_result_fn: Any,
    build_agent_test_summary_details_fn: Any,
    build_validate_addon_change_payload_fn: Any,
    run_validate_addon_change_preflight_fn: Any,
    build_validate_addon_change_discovery_result_fn: Any,
    apply_core_addon_filters_fn: Any,
    apply_field_filters_fn: Any,
    get_odoo_operations_cls: Any,
    get_module_manager_cls: Any,
    output_result_to_json_fn: Any,
    safe_read_only: str,
    controlled_runtime_mutation: str,
    controlled_source_mutation: str,
    config_error_cls: Any,
    module_not_found_error_cls: Any,
    context_command_impl: Any,
    addon_info_command_impl: Any,
    inspect_addon_command_impl: Any,
    plan_update_command_impl: Any,
    prepare_addon_change_command_impl: Any,
    locate_model_command_impl: Any,
    locate_field_command_impl: Any,
    list_addon_tests_command_impl: Any,
    recommend_tests_command_impl: Any,
    list_addon_models_command_impl: Any,
    find_model_extensions_command_impl: Any,
    get_model_views_command_impl: Any,
    doctor_command_impl: Any,
    list_addons_command_impl: Any,
    list_installed_addons_command_impl: Any,
    dependency_graph_command_impl: Any,
    inspect_addons_command_impl: Any,
    resolve_config_command_impl: Any,
    list_duplicates_command_impl: Any,
    install_module_command_impl: Any,
    uninstall_module_command_impl: Any,
    update_module_command_impl: Any,
    create_addon_command_impl: Any,
    export_lang_command_impl: Any,
    test_summary_command_impl: Any,
    validate_impl: Any,
    query_model_command_impl: Any,
    read_record_command_impl: Any,
    search_count_command_impl: Any,
    get_model_fields_command_impl: Any,
) -> None:
    """Register agent-first commands on the shared Typer app."""

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
            redact_config_fn=redact_config_fn,
            agent_payload_fn=agent_payload_fn,
            agent_emit_payload_fn=agent_emit_payload_fn,
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
            os_module=os,
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
