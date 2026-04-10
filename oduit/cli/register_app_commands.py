"""Registration helpers for classic `oduit` CLI commands."""

from typing import Any

import typer

from ..cli_types import AddonTemplate, DevFeature, LogLevel, ShellInterface

INSTALLED_ADDON_STATE_OPTION = typer.Option(
    [],
    "--state",
    help="Repeatable runtime state filter (defaults to installed)",
)


def register_app_commands(  # noqa: C901
    *,
    app: typer.Typer,
    dev_option: Any,
    shell_interface_option: Any,
    addon_template_option: Any,
    log_level_option: Any,
    language_option: Any,
    sort_option: Any,
    include_filter_option: Any,
    exclude_filter_option: Any,
    valid_filter_fields_str: str,
    resolve_command_global_config_fn: Any,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    build_doctor_report_fn: Any,
    print_doctor_report_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
    dependency_error_details_fn: Any,
    get_config_loader_cls: Any,
    get_module_manager_cls: Any,
    get_addons_path_manager_cls: Any,
    validate_addon_name_fn: Any,
    get_addon_type_fn: Any,
    build_addon_table_fn: Any,
    get_addon_field_value_fn: Any,
    apply_core_addon_filters_fn: Any,
    apply_field_filters_fn: Any,
    print_dependency_tree_fn: Any,
    print_dependency_list_fn: Any,
    check_environment_exists_fn: Any,
    detect_binaries_fn: Any,
    build_initial_config_fn: Any,
    import_or_convert_config_fn: Any,
    normalize_addons_path_fn: Any,
    save_config_file_fn: Any,
    display_config_summary_fn: Any,
    doctor_command_impl: Any,
    run_command_impl: Any,
    shell_command_impl: Any,
    install_command_impl: Any,
    update_command_impl: Any,
    uninstall_command_impl: Any,
    test_command_impl: Any,
    create_db_command_impl: Any,
    list_db_command_impl: Any,
    list_env_command_impl: Any,
    print_config_command_impl: Any,
    create_addon_command_impl: Any,
    print_manifest_command_impl: Any,
    list_addons_command_impl: Any,
    list_installed_addons_command_impl: Any,
    list_manifest_values_command_impl: Any,
    list_duplicates_command_impl: Any,
    list_depends_command_impl: Any,
    list_codepends_command_impl: Any,
    install_order_command_impl: Any,
    impact_of_update_command_impl: Any,
    list_missing_command_impl: Any,
    init_env_command_impl: Any,
    export_lang_command_impl: Any,
    get_odoo_version_command_impl: Any,
    valid_filter_fields: list[str],
) -> None:
    """Register classic CLI commands on the shared Typer app."""

    @app.command()
    def doctor(ctx: typer.Context) -> None:
        """Diagnose environment and configuration issues."""
        doctor_command_impl(
            ctx,
            resolve_command_global_config_fn=resolve_command_global_config_fn,
            build_doctor_report_fn=build_doctor_report_fn,
            print_doctor_report_fn=print_doctor_report_fn,
        )

    @app.command()
    def run(
        ctx: typer.Context,
        dev: DevFeature | None = dev_option,
        log_level: LogLevel | None = log_level_option,
        stop_after_init: bool = typer.Option(
            False,
            "--stop-after-init",
            "-s",
            help="Stop the server after initialization",
        ),
    ) -> None:
        """Run Odoo server."""
        run_command_impl(
            ctx,
            dev=dev,
            log_level=log_level,
            stop_after_init=stop_after_init,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )

    @app.command()
    def shell(
        ctx: typer.Context,
        shell_interface: ShellInterface | None = shell_interface_option,
        compact: bool = typer.Option(
            False,
            "--compact",
            help="Suppress INFO logs at startup for cleaner output",
        ),
        log_level: LogLevel | None = log_level_option,
    ) -> None:
        """Start Odoo shell."""
        shell_command_impl(
            ctx,
            shell_interface=shell_interface,
            compact=compact,
            log_level=log_level,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
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
        language: str | None = language_option,
        max_cron_threads: int | None = typer.Option(
            None,
            "--max-cron-threads",
            help="Set maximum cron threads for Odoo server",
        ),
        log_level: LogLevel | None = log_level_option,
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
        install_command_impl(
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
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )

    @app.command()
    def update(
        ctx: typer.Context,
        module: str = typer.Argument(help="Module to update"),
        without_demo: str | None = typer.Option(
            None, "--without-demo", help="Update without demo data"
        ),
        language: str | None = language_option,
        i18n_overwrite: bool = typer.Option(
            False,
            "--i18n-overwrite",
            help="Overwrite existing translations during update",
        ),
        max_cron_threads: int | None = typer.Option(
            None,
            "--max-cron-threads",
            help="Set maximum cron threads for Odoo server",
        ),
        log_level: LogLevel | None = log_level_option,
        compact: bool = typer.Option(
            False,
            "--compact",
            help="Suppress INFO logs at startup for cleaner output",
        ),
    ) -> None:
        """Update module."""
        update_command_impl(
            ctx,
            module=module,
            without_demo=without_demo,
            language=language,
            i18n_overwrite=i18n_overwrite,
            max_cron_threads=max_cron_threads,
            log_level=log_level,
            compact=compact,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )

    @app.command()
    def uninstall(
        ctx: typer.Context,
        module: str = typer.Argument(help="Module to uninstall"),
        allow_uninstall: bool = typer.Option(
            False,
            "--allow-uninstall",
            help="Confirm that this destructive uninstall is intended",
        ),
        log_level: LogLevel | None = log_level_option,
        compact: bool = typer.Option(
            False,
            "--compact",
            help="Suppress INFO logs at startup for cleaner output",
        ),
        include_command: bool = typer.Option(
            False, "--include-command", help="Include executed command in result JSON"
        ),
        include_stdout: bool = typer.Option(
            False, "--include-stdout", help="Include stdout in result JSON"
        ),
    ) -> None:
        """Uninstall module."""
        uninstall_command_impl(
            ctx,
            module=module,
            allow_uninstall=allow_uninstall,
            compact=compact,
            log_level=log_level,
            include_command=include_command,
            include_stdout=include_stdout,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            confirmation_required_error_fn=confirmation_required_error_fn,
            print_command_error_result_fn=print_command_error_result_fn,
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
        log_level: LogLevel | None = log_level_option,
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
        test_command_impl(
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
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
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
        create_db_command_impl(
            ctx,
            create_role=create_role,
            alter_role=alter_role,
            with_sudo=with_sudo,
            drop=drop,
            non_interactive=non_interactive,
            db_user=db_user,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            confirmation_required_error_fn=confirmation_required_error_fn,
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
        list_db_command_impl(
            ctx,
            with_sudo=with_sudo,
            db_user=db_user,
            include_command=include_command,
            include_stdout=include_stdout,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )

    @app.command("list-env")
    def list_env() -> None:
        """List available environments."""
        list_env_command_impl(config_loader_cls=get_config_loader_cls())

    @app.command("print-config")
    def print_config_cmd(ctx: typer.Context) -> None:
        """Print environment config."""
        print_config_command_impl(
            ctx,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
        )

    @app.command("create-addon")
    def create_addon(
        ctx: typer.Context,
        addon_name: str = typer.Argument(help="Name of the addon to create"),
        path: str | None = typer.Option(
            None, "--path", help="Path where to create the addon"
        ),
        template: AddonTemplate = addon_template_option,
    ) -> None:
        """Create new addon."""
        create_addon_command_impl(
            ctx,
            addon_name=addon_name,
            path=path,
            template=template,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            validate_addon_name_fn=validate_addon_name_fn,
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
        print_manifest_command_impl(
            ctx,
            addon_name=addon_name,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            module_manager_cls=get_module_manager_cls(),
            get_addon_type_fn=get_addon_type_fn,
            build_addon_table_fn=build_addon_table_fn,
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
        include: list[str] = include_filter_option,
        exclude: list[str] = exclude_filter_option,
        sorting: str = sort_option,
    ) -> None:
        """List available addons.

        Filter addons using --include or --exclude with FIELD:VALUE format.

        Examples:

          oduit list-addons --exclude category:Theme

          oduit list-addons --include author:Odoo --include category:Sales
        """
        list_addons_command_impl(
            ctx,
            select_dir=select_dir,
            separator=separator,
            exclude_core_addons=exclude_core_addons,
            exclude_enterprise_addons=exclude_enterprise_addons,
            include=include,
            exclude=exclude,
            sorting=sorting,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            module_manager_cls=get_module_manager_cls(),
            apply_core_addon_filters_fn=apply_core_addon_filters_fn,
            apply_field_filters_fn=apply_field_filters_fn,
        )

    @app.command("list-installed-addons")
    def list_installed_addons(
        ctx: typer.Context,
        modules: str | None = typer.Option(
            None,
            "--module",
            "--modules",
            help="Comma-separated addon names to inspect at runtime",
        ),
        state: list[str] = INSTALLED_ADDON_STATE_OPTION,
        separator: str | None = typer.Option(
            None,
            "--separator",
            help="Separator for text output (e.g., ',' for 'a,b,c')",
        ),
        include_state: bool = typer.Option(
            False,
            "--include-state",
            help="Include module state in text output as 'module:state'",
        ),
    ) -> None:
        """List installed addons from the active database."""
        list_installed_addons_command_impl(
            ctx,
            modules=modules,
            state=state,
            separator=separator,
            include_state=include_state,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )

    @app.command("list-manifest-values")
    def list_manifest_values(
        ctx: typer.Context,
        field: str = typer.Argument(
            help=(
                "Manifest field to list unique values for. "
                f"Valid fields: {valid_filter_fields_str}"
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
        list_manifest_values_command_impl(
            ctx,
            field=field,
            separator=separator,
            select_dir=select_dir,
            exclude_core_addons=exclude_core_addons,
            exclude_enterprise_addons=exclude_enterprise_addons,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            valid_filter_fields=valid_filter_fields,
            module_manager_cls=get_module_manager_cls(),
            get_addon_field_value_fn=get_addon_field_value_fn,
            apply_core_addon_filters_fn=apply_core_addon_filters_fn,
        )

    @app.command("list-duplicates")
    def list_duplicates(ctx: typer.Context) -> None:
        """List duplicate addon names across configured addon paths."""
        list_duplicates_command_impl(
            ctx,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            addons_path_manager_cls=get_addons_path_manager_cls(),
            print_command_error_result_fn=print_command_error_result_fn,
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
        sorting: str = sort_option,
    ) -> None:
        """List direct dependencies needed to install a set of modules.

        Direct dependencies are external modules (not in the provided set) needed
        for installation. For example, if modules a, b, c depend on crm and mail,
        this will show crm and mail.

        Use --tree to show the full dependency tree with versions.
        Use --select-dir to get dependencies for all modules in a specific directory.
        """
        list_depends_command_impl(
            ctx,
            modules=modules,
            separator=separator,
            tree=tree,
            depth=depth,
            select_dir=select_dir,
            sorting=sorting,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            module_manager_cls=get_module_manager_cls(),
            print_dependency_tree_fn=print_dependency_tree_fn,
            print_dependency_list_fn=print_dependency_list_fn,
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
        list_codepends_command_impl(
            ctx,
            module=module,
            separator=separator,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            module_manager_cls=get_module_manager_cls(),
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
        install_order_command_impl(
            ctx,
            modules=modules,
            separator=separator,
            select_dir=select_dir,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            module_manager_cls=get_module_manager_cls(),
            print_command_error_result_fn=print_command_error_result_fn,
            dependency_error_details_fn=dependency_error_details_fn,
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
        impact_of_update_command_impl(
            ctx,
            module=module,
            separator=separator,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            module_manager_cls=get_module_manager_cls(),
            print_command_error_result_fn=print_command_error_result_fn,
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
        list_missing_command_impl(
            ctx,
            modules=modules,
            separator=separator,
            select_dir=select_dir,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            module_manager_cls=get_module_manager_cls(),
        )

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
        init_env_command_impl(
            env_name=env_name,
            from_conf=from_conf,
            python_bin=python_bin,
            odoo_bin=odoo_bin,
            coverage_bin=coverage_bin,
            config_loader_cls=get_config_loader_cls(),
            check_environment_exists_fn=check_environment_exists_fn,
            detect_binaries_fn=detect_binaries_fn,
            build_initial_config_fn=build_initial_config_fn,
            import_or_convert_config_fn=import_or_convert_config_fn,
            normalize_addons_path_fn=normalize_addons_path_fn,
            save_config_file_fn=save_config_file_fn,
            display_config_summary_fn=display_config_summary_fn,
        )

    @app.command("export-lang")
    def export_lang(
        ctx: typer.Context,
        module: str = typer.Argument(help="Module to export"),
        language: str | None = language_option,
        log_level: LogLevel | None = log_level_option,
    ) -> None:
        """Export language module."""
        export_lang_command_impl(
            ctx,
            module=module,
            language=language,
            log_level=log_level,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            module_manager_cls=get_module_manager_cls(),
        )

    @app.command("version")
    def get_odoo_version_cmd(
        ctx: typer.Context,
    ) -> None:
        """Get Odoo version from odoo-bin."""
        get_odoo_version_command_impl(
            ctx,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )
