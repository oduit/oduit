"""Registration helpers for documentation-oriented CLI commands."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from .commands.documentation import (
    addon_documentation_command,
    addons_documentation_command,
    dependency_graph_documentation_command,
    model_documentation_command,
    technical_diff_command,
    technical_documentation_accept_command,
    technical_documentation_check_command,
    technical_documentation_command,
    technical_documentation_next_command,
    technical_documentation_refresh_command,
    technical_documentation_status_command,
    technical_evidence_command,
    technical_report_command,
)
from .runtime_context import AppRegistrationContext


def register_documentation_commands(context: AppRegistrationContext) -> None:
    """Register documentation commands on the shared Typer app."""
    app = context.app
    resolve_command_env_config_fn = context.runtime.resolve_command_env_config_fn
    build_odoo_operations_fn = context.runtime.build_odoo_operations_fn
    print_command_error_result_fn = context.dependencies.print_command_error_result_fn
    module_not_found_error_cls = context.dependencies.module_not_found_error_cls
    module_manager_cls = context.dependencies.get_module_manager_cls()

    docs_app = typer.Typer(help="Generate addon and model documentation bundles")
    app.add_typer(docs_app, name="docs")

    @docs_app.command("addon")
    def docs_addon_command(
        ctx: typer.Context,
        module: str = typer.Argument(help="Addon to document"),
        database: str | None = typer.Option(None, "--database"),
        timeout: float = typer.Option(
            30.0,
            "--timeout",
            help="Runtime query timeout in seconds",
        ),
        source_only: bool = typer.Option(
            False,
            "--source-only",
            help="Skip all runtime/database enrichment",
        ),
        include_arch: bool = typer.Option(
            False,
            "--include-arch",
            help="Include raw view XML in runtime view payloads",
        ),
        attributes: str | None = typer.Option(
            "string,type,required,readonly,store,relation",
            "--field-attributes",
            help="Comma-separated field metadata attributes",
        ),
        types: str | None = typer.Option(
            None,
            "--view-types",
            help="Comma-separated view types such as form,tree,kanban,search",
        ),
        max_models: int | None = typer.Option(
            None,
            "--max-models",
            help="Limit the number of per-model sections",
        ),
        max_fields_per_model: int | None = typer.Option(
            None,
            "--max-fields-per-model",
            help="Limit the number of runtime fields shown per model",
        ),
        path_prefix: str | None = typer.Option(
            None,
            "--path",
            help="Trim this absolute prefix from documented file paths",
        ),
        output_path: Annotated[
            Path | None,
            typer.Option(
                "--output",
                help="Write rendered output to a file instead of stdout",
            ),
        ] = None,
        format_name: str | None = typer.Option(
            None,
            "--format",
            help="Output format: markdown or json",
        ),
    ) -> None:
        """Generate one addon documentation bundle."""
        addon_documentation_command(
            ctx,
            module=module,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            attributes=attributes,
            types=types,
            output_path=output_path,
            format_name=format_name,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_prefix,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            print_command_error_result_fn=print_command_error_result_fn,
            module_not_found_error_cls=module_not_found_error_cls,
        )

    @docs_app.command("model")
    def docs_model_command(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to document"),
        database: str | None = typer.Option(None, "--database"),
        timeout: float = typer.Option(
            30.0,
            "--timeout",
            help="Runtime query timeout in seconds",
        ),
        source_only: bool = typer.Option(
            False,
            "--source-only",
            help="Skip all runtime/database enrichment",
        ),
        include_arch: bool = typer.Option(
            False,
            "--include-arch",
            help="Include raw view XML in runtime view payloads",
        ),
        attributes: str | None = typer.Option(
            "string,type,required,readonly,store,relation",
            "--field-attributes",
            help="Comma-separated field metadata attributes",
        ),
        types: str | None = typer.Option(
            None,
            "--view-types",
            help="Comma-separated view types such as form,tree,kanban,search",
        ),
        max_fields: int | None = typer.Option(
            None,
            "--max-fields",
            help="Limit the number of runtime fields shown",
        ),
        path_prefix: str | None = typer.Option(
            None,
            "--path",
            help="Trim this absolute prefix from documented file paths",
        ),
        output_path: Annotated[
            Path | None,
            typer.Option(
                "--output",
                help="Write rendered output to a file instead of stdout",
            ),
        ] = None,
        format_name: str | None = typer.Option(
            None,
            "--format",
            help="Output format: markdown or json",
        ),
    ) -> None:
        """Generate one model documentation bundle."""
        model_documentation_command(
            ctx,
            model=model,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            attributes=attributes,
            types=types,
            output_path=output_path,
            format_name=format_name,
            max_fields=max_fields,
            path_prefix=path_prefix,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )

    @docs_app.command("dependency-graph")
    def docs_dependency_graph_command(
        ctx: typer.Context,
        modules: str = typer.Option(
            ...,
            "--modules",
            help="Comma-separated addon names",
        ),
        database: str | None = typer.Option(None, "--database"),
        timeout: float = typer.Option(
            30.0,
            "--timeout",
            help="Runtime query timeout in seconds",
        ),
        source_only: bool = typer.Option(
            False,
            "--source-only",
            help="Skip runtime installed-addon filtering",
        ),
        installed_only: bool = typer.Option(
            False,
            "--installed-only",
            help="Keep only installed addons in the rendered graph",
        ),
        transitive: bool = typer.Option(
            True,
            "--transitive/--direct-only",
            help="Include the transitive dependency closure",
        ),
        path_prefix: str | None = typer.Option(
            None,
            "--path",
            help="Trim this absolute prefix from documented file paths",
        ),
        output_path: Annotated[
            Path | None,
            typer.Option(
                "--output",
                help="Write rendered output to a file instead of stdout",
            ),
        ] = None,
        format_name: str | None = typer.Option(
            None,
            "--format",
            help="Output format: markdown, json, or mermaid",
        ),
    ) -> None:
        """Generate dependency-graph documentation."""
        dependency_graph_documentation_command(
            ctx,
            modules=modules,
            database=database,
            timeout=timeout,
            source_only=source_only,
            installed_only=installed_only,
            transitive=transitive,
            output_path=output_path,
            format_name=format_name,
            path_prefix=path_prefix,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            module_manager_cls=module_manager_cls,
            print_command_error_result_fn=print_command_error_result_fn,
        )

    @docs_app.command("addons")
    def docs_addons_command(
        ctx: typer.Context,
        modules: str | None = typer.Option(
            None,
            "--modules",
            help="Comma-separated addon names",
        ),
        select_dir: str | None = typer.Option(
            None,
            "--select-dir",
            help="Select all addons under a named addon directory",
        ),
        database: str | None = typer.Option(None, "--database"),
        timeout: float = typer.Option(
            30.0,
            "--timeout",
            help="Runtime query timeout in seconds",
        ),
        source_only: bool = typer.Option(
            False,
            "--source-only",
            help="Skip all runtime/database enrichment",
        ),
        include_arch: bool = typer.Option(
            False,
            "--include-arch",
            help="Include raw view XML in runtime view payloads",
        ),
        attributes: str | None = typer.Option(
            "string,type,required,readonly,store,relation",
            "--field-attributes",
            help="Comma-separated field metadata attributes",
        ),
        types: str | None = typer.Option(
            None,
            "--view-types",
            help="Comma-separated view types such as form,tree,kanban,search",
        ),
        max_models: int | None = typer.Option(
            None,
            "--max-models",
            help="Limit the number of per-addon model sections",
        ),
        max_fields_per_model: int | None = typer.Option(
            None,
            "--max-fields-per-model",
            help="Limit the number of runtime fields shown per model",
        ),
        path_prefix: str | None = typer.Option(
            None,
            "--path",
            help="Trim this absolute prefix from documented file paths",
        ),
        output_dir: Annotated[
            Path | None,
            typer.Option(
                "--output-dir",
                help="Write the multi-file bundle to this directory",
            ),
        ] = None,
        format_name: str | None = typer.Option(
            None,
            "--format",
            help="Output format: markdown or json",
        ),
    ) -> None:
        """Generate one documentation bundle spanning multiple addons."""
        addons_documentation_command(
            ctx,
            modules=modules,
            select_dir=select_dir,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            attributes=attributes,
            types=types,
            output_dir=output_dir,
            format_name=format_name,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_prefix,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            module_manager_cls=module_manager_cls,
            print_command_error_result_fn=print_command_error_result_fn,
            module_not_found_error_cls=module_not_found_error_cls,
        )

    @docs_app.command("technical")
    def docs_technical_command(
        ctx: typer.Context,
        target: str = typer.Argument(
            help="Addon name or addon path, e.g. has_base or @addons/has_base"
        ),
        template: str = typer.Option(
            "arc42", "--template", help="Documentation template"
        ),
        database: str | None = typer.Option(None, "--database"),
        timeout: float = typer.Option(
            30.0,
            "--timeout",
            help="Runtime query timeout in seconds",
        ),
        source_only: bool = typer.Option(
            False,
            "--source-only",
            help="Skip all runtime/database enrichment",
        ),
        include_arch: bool = typer.Option(
            False,
            "--include-arch",
            help="Include raw view XML in runtime view payloads",
        ),
        attributes: str | None = typer.Option(
            "string,type,required,readonly,store,relation",
            "--field-attributes",
            help="Comma-separated field metadata attributes",
        ),
        types: str | None = typer.Option(
            None,
            "--view-types",
            help="Comma-separated view types such as form,tree,kanban,search",
        ),
        max_models: int | None = typer.Option(
            None,
            "--max-models",
            help="Limit the number of per-model sections",
        ),
        max_fields_per_model: int | None = typer.Option(
            None,
            "--max-fields-per-model",
            help="Limit the number of runtime fields shown per model",
        ),
        path_prefix: str | None = typer.Option(
            None,
            "--path",
            help="Trim this absolute prefix from documented file paths",
        ),
        output_path: Annotated[
            Path | None,
            typer.Option(
                "--output",
                help="Write rendered output to a file instead of stdout",
            ),
        ] = None,
        output_in_addon: bool = typer.Option(
            False,
            "--output-in-addon",
            help="Write to <addon>/docs/architecture.md",
        ),
        force: bool = typer.Option(
            False,
            "--force",
            help="Overwrite an existing documentation file",
        ),
        progress: bool | None = typer.Option(
            None,
            "--progress/--no-progress",
            help="Print progress updates to stderr while generating documentation",
        ),
        progress_level: str = typer.Option(
            "compact",
            "--progress-level",
            help="Progress verbosity: compact, model, or debug",
        ),
        format_name: str | None = typer.Option(
            None,
            "--format",
            help="Output format: markdown or json",
        ),
    ) -> None:
        """Generate arc42 technical documentation for one addon."""
        technical_documentation_command(
            ctx,
            target=target,
            template=template,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            attributes=attributes,
            types=types,
            output_path=output_path,
            output_in_addon=output_in_addon,
            force=force,
            format_name=format_name,
            progress=progress,
            progress_level=progress_level,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_prefix,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            print_command_error_result_fn=print_command_error_result_fn,
            module_not_found_error_cls=module_not_found_error_cls,
        )

    @docs_app.command("technical-evidence")
    def docs_technical_evidence_command(
        ctx: typer.Context,
        target: str = typer.Argument(help="Addon name or addon path"),
        database: str | None = typer.Option(None, "--database"),
        timeout: float = typer.Option(30.0, "--timeout"),
        source_only: bool = typer.Option(False, "--source-only"),
        include_arch: bool = typer.Option(False, "--include-arch"),
        attributes: str | None = typer.Option(
            "string,type,required,readonly,store,relation",
            "--field-attributes",
        ),
        types: str | None = typer.Option(None, "--view-types"),
        max_models: int | None = typer.Option(None, "--max-models"),
        max_fields_per_model: int | None = typer.Option(None, "--max-fields-per-model"),
        path_prefix: str | None = typer.Option(None, "--path"),
        output_in_addon: bool = typer.Option(
            False, "--output-in-addon", help="Write addon-local evidence files"
        ),
        force: bool = typer.Option(False, "--force"),
        format_name: str | None = typer.Option(None, "--format"),
    ) -> None:
        """Generate deterministic evidence markdown and sidecar."""
        technical_evidence_command(
            ctx,
            target=target,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            attributes=attributes,
            types=types,
            output_in_addon=output_in_addon,
            force=force,
            format_name=format_name,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_prefix,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )

    @docs_app.command("technical-report")
    def docs_technical_report_command(
        ctx: typer.Context,
        target: str = typer.Argument(help="Addon name or addon path"),
        database: str | None = typer.Option(None, "--database"),
        timeout: float = typer.Option(30.0, "--timeout"),
        source_only: bool = typer.Option(False, "--source-only"),
        include_arch: bool = typer.Option(False, "--include-arch"),
        attributes: str | None = typer.Option(
            "string,type,required,readonly,store,relation",
            "--field-attributes",
        ),
        types: str | None = typer.Option(None, "--view-types"),
        max_models: int | None = typer.Option(None, "--max-models"),
        max_fields_per_model: int | None = typer.Option(None, "--max-fields-per-model"),
        path_prefix: str | None = typer.Option(None, "--path"),
        output_in_addon: bool = typer.Option(
            False, "--output-in-addon", help="Write addon-local report seed"
        ),
        force: bool = typer.Option(False, "--force"),
        generate_evidence: bool = typer.Option(False, "--generate-evidence"),
        format_name: str | None = typer.Option(None, "--format"),
    ) -> None:
        """Generate LLM/human report seed from evidence snapshots."""
        technical_report_command(
            ctx,
            target=target,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            attributes=attributes,
            types=types,
            output_in_addon=output_in_addon,
            force=force,
            generate_evidence=generate_evidence,
            format_name=format_name,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_prefix,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )

    @docs_app.command("technical-diff")
    def docs_technical_diff_command(
        ctx: typer.Context,
        target: str = typer.Argument(help="Addon name or addon path"),
        include_diff: bool = typer.Option(False, "--include-diff"),
        significant_only: bool = typer.Option(False, "--significant-only"),
        format_name: str | None = typer.Option(None, "--format"),
        path_prefix: str | None = typer.Option(None, "--path"),
    ) -> None:
        """Diff report snapshots against current generated evidence."""
        technical_diff_command(
            ctx,
            target=target,
            include_diff=include_diff,
            format_name=format_name,
            significant_only=significant_only,
            path_prefix=path_prefix,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )

    @docs_app.command("technical-status")
    def docs_technical_status_command(
        ctx: typer.Context,
        target: str | None = typer.Argument(
            None,
            help="Optional addon name or addon path, e.g. has_base or @addons/has_base",
        ),
        format_name: str | None = typer.Option(
            None,
            "--format",
            help="Output format: text or json",
        ),
        select_dir: str | None = typer.Option(
            None,
            "--select-dir",
            help="Select all addons under a named addon directory",
        ),
        only_stale: bool = typer.Option(
            False,
            "--only-stale",
            help="Hide up-to-date rows from the status report",
        ),
        include_files: bool = typer.Option(
            False,
            "--include-files",
            help="Include changed, added, and removed file lists in text output",
        ),
    ) -> None:
        """Report tracking and freshness status for addon technical docs."""
        technical_documentation_status_command(
            ctx,
            target=target,
            format_name=format_name,
            select_dir=select_dir,
            only_stale=only_stale,
            include_files=include_files,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )

    @docs_app.command("technical-check")
    def docs_technical_check_command(
        ctx: typer.Context,
        target: str = typer.Argument(help="Addon name or addon path"),
        format_name: str | None = typer.Option(
            None,
            "--format",
            help="Output format: text or json",
        ),
        include_files: bool = typer.Option(
            False,
            "--include-files",
            help="Include changed, added, and removed file lists",
        ),
        fail_on_stale: bool = typer.Option(
            True,
            "--fail-on-stale/--no-fail-on-stale",
            help="Exit non-zero when the tracked documentation is stale",
        ),
    ) -> None:
        """Check one addon's technical-documentation freshness."""
        technical_documentation_check_command(
            ctx,
            target=target,
            format_name=format_name,
            include_files=include_files,
            fail_on_stale=fail_on_stale,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )

    @docs_app.command("technical-accept")
    def docs_technical_accept_command(
        ctx: typer.Context,
        target: str = typer.Argument(help="Addon name or addon path"),
        force: bool = typer.Option(
            False,
            "--force",
            help="Allow acceptance even when source changed since generation",
        ),
    ) -> None:
        """Accept a manually reviewed architecture document snapshot."""
        technical_documentation_accept_command(
            ctx,
            target=target,
            force=force,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )

    @docs_app.command("technical-next")
    def docs_technical_next_command(
        ctx: typer.Context,
        path: str | None = typer.Argument(
            None,
            help="Optional addon root or addons collection path",
        ),
        format_name: str | None = typer.Option(
            None,
            "--format",
            help="Output format: text or json",
        ),
        include_files: bool = typer.Option(
            False,
            "--include-files",
            help="Include the selected status details in structured output",
        ),
    ) -> None:
        """Return the next addon that needs technical-documentation work."""
        technical_documentation_next_command(
            ctx,
            path=path,
            format_name=format_name,
            include_files=include_files,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )

    @docs_app.command("technical-refresh")
    def docs_technical_refresh_command(
        ctx: typer.Context,
        target: str = typer.Argument(
            help="Addon name or addon path, e.g. has_base or @addons/has_base"
        ),
        dry_run: bool = typer.Option(
            True,
            "--dry-run/--write",
            help="Preview changes by default; use --write to update files",
        ),
        force_edited_blocks: bool = typer.Option(
            False,
            "--force-edited-blocks",
            help="Overwrite managed blocks even when block bodies were edited",
        ),
        add_missing_blocks: bool = typer.Option(
            False,
            "--add-missing-blocks",
            help="Attempt to add known managed blocks missing from the document",
        ),
        source_only: bool | None = typer.Option(
            None,
            "--source-only/--runtime",
            help="Override refresh generation mode from metadata options",
        ),
        database: str | None = typer.Option(None, "--database"),
        timeout: float = typer.Option(
            30.0,
            "--timeout",
            help="Runtime query timeout in seconds",
        ),
        attributes: str | None = typer.Option(
            None,
            "--field-attributes",
            help="Comma-separated field metadata attributes override",
        ),
        types: str | None = typer.Option(
            None,
            "--view-types",
            help="Comma-separated view types such as form,tree,kanban,search",
        ),
        max_models: int | None = typer.Option(
            None,
            "--max-models",
            help="Limit the number of per-model sections",
        ),
        max_fields_per_model: int | None = typer.Option(
            None,
            "--max-fields-per-model",
            help="Limit the number of runtime fields shown per model",
        ),
        path_prefix: str | None = typer.Option(
            None,
            "--path",
            help="Trim this absolute prefix from documented file paths",
        ),
        format_name: str | None = typer.Option(
            None,
            "--format",
            help="Output format: text or json",
        ),
    ) -> None:
        """Refresh managed generated blocks in addon-local technical docs."""
        technical_documentation_refresh_command(
            ctx,
            target=target,
            dry_run=dry_run,
            force_edited_blocks=force_edited_blocks,
            add_missing_blocks=add_missing_blocks,
            source_only=source_only,
            database=database,
            timeout=timeout,
            attributes=attributes,
            types=types,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_prefix,
            format_name=format_name,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )
