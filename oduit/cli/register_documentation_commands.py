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
