"""Documentation command implementations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from ...documentation_renderer import render_dependency_graph_mermaid
from ...utils import output_result_to_json


def _parse_csv_items(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def _resolve_docs_format(global_config: Any, requested_format: str | None) -> str:
    if requested_format:
        return requested_format
    return (
        "json" if getattr(global_config, "format", None).value == "json" else "markdown"
    )


def _write_output(content: str, output_path: Path | None) -> None:
    if output_path is None:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content)


def _emit_document_output(
    *,
    global_config: Any,
    operation: str,
    result_type: str,
    format_name: str,
    data: dict[str, Any],
    rendered_content: str,
    output_path: Path | None,
) -> None:
    if output_path is not None:
        _write_output(rendered_content, output_path)

    if format_name == "json":
        payload = output_result_to_json(
            {
                "success": True,
                "operation": operation,
                "format": format_name,
                "output_path": str(output_path) if output_path is not None else None,
                **data,
            },
            result_type=result_type,
        )
        print(json.dumps(payload))
        return

    if output_path is not None:
        print(f"Wrote {format_name} documentation to {output_path}")
        return
    print(rendered_content)


def addon_documentation_command(
    ctx: typer.Context,
    *,
    module: str,
    database: str | None,
    timeout: float,
    source_only: bool,
    include_arch: bool,
    attributes: str | None,
    types: str | None,
    output_path: Path | None,
    format_name: str | None,
    max_models: int | None,
    max_fields_per_model: int | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    print_command_error_result_fn: Any,
    module_not_found_error_cls: Any,
) -> None:
    """Generate documentation for one addon."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    resolved_format = _resolve_docs_format(global_config, format_name)
    ops = build_odoo_operations_fn(global_config)
    try:
        bundle = ops.build_addon_documentation(
            module,
            odoo_series=global_config.odoo_series,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            field_attributes=_parse_csv_items(attributes),
            view_types=_parse_csv_items(types),
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
        )
    except module_not_found_error_cls as exc:
        print_command_error_result_fn(
            global_config,
            "docs_addon",
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
        raise typer.Exit(1) from None

    if resolved_format == "markdown":
        rendered_content = bundle.markdown
    elif resolved_format == "json":
        rendered_content = json.dumps(bundle.to_dict(), indent=2, sort_keys=True)
    else:
        raise typer.BadParameter("format must be either 'markdown' or 'json'")

    _emit_document_output(
        global_config=global_config,
        operation="docs_addon",
        result_type="addon_documentation",
        format_name=resolved_format,
        data=bundle.to_dict(),
        rendered_content=rendered_content,
        output_path=output_path,
    )


def model_documentation_command(
    ctx: typer.Context,
    *,
    model: str,
    database: str | None,
    timeout: float,
    source_only: bool,
    include_arch: bool,
    attributes: str | None,
    types: str | None,
    output_path: Path | None,
    format_name: str | None,
    max_fields: int | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
) -> None:
    """Generate documentation for one model."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    resolved_format = _resolve_docs_format(global_config, format_name)
    ops = build_odoo_operations_fn(global_config)
    bundle = ops.build_model_documentation(
        model,
        database=database,
        timeout=timeout,
        source_only=source_only,
        include_arch=include_arch,
        field_attributes=_parse_csv_items(attributes),
        view_types=_parse_csv_items(types),
        max_fields=max_fields,
    )

    if resolved_format == "markdown":
        rendered_content = bundle.markdown
    elif resolved_format == "json":
        rendered_content = json.dumps(bundle.to_dict(), indent=2, sort_keys=True)
    else:
        raise typer.BadParameter("format must be either 'markdown' or 'json'")

    _emit_document_output(
        global_config=global_config,
        operation="docs_model",
        result_type="model_documentation",
        format_name=resolved_format,
        data=bundle.to_dict(),
        rendered_content=rendered_content,
        output_path=output_path,
    )


def dependency_graph_documentation_command(
    ctx: typer.Context,
    *,
    modules: str,
    database: str | None,
    timeout: float,
    source_only: bool,
    installed_only: bool,
    transitive: bool,
    output_path: Path | None,
    format_name: str | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    module_manager_cls: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Generate dependency-graph documentation for one or more addons."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    module_list = _parse_csv_items(modules)
    if not module_list:
        print_command_error_result_fn(
            global_config,
            "docs_dependency_graph",
            "At least one module is required",
            error_type="ValidationError",
            details={"modules": modules},
        )
        raise typer.Exit(1) from None

    module_manager = module_manager_cls(env_config["addons_path"])
    missing_modules = [
        module_name
        for module_name in module_list
        if module_manager.find_module_path(module_name) is None
    ]
    if missing_modules:
        print_command_error_result_fn(
            global_config,
            "docs_dependency_graph",
            f"Modules not found in addons_path: {', '.join(missing_modules)}",
            error_type="ModuleNotFoundError",
            details={"modules": module_list, "missing_modules": missing_modules},
            remediation=[
                "Verify the requested modules before generating documentation.",
            ],
        )
        raise typer.Exit(1) from None

    resolved_format = _resolve_docs_format(global_config, format_name)
    ops = build_odoo_operations_fn(global_config)
    bundle = ops.build_dependency_graph_documentation(
        module_list,
        database=database,
        timeout=timeout,
        source_only=source_only,
        installed_only=installed_only,
        transitive=transitive,
    )
    if resolved_format == "markdown":
        rendered_content = bundle.markdown
    elif resolved_format == "json":
        rendered_content = json.dumps(bundle.to_dict(), indent=2, sort_keys=True)
    elif resolved_format == "mermaid":
        rendered_content = render_dependency_graph_mermaid(
            bundle.dependency_graph
        ).content
    else:
        raise typer.BadParameter("format must be markdown, json, or mermaid")

    _emit_document_output(
        global_config=global_config,
        operation="docs_dependency_graph",
        result_type="dependency_graph_documentation",
        format_name=resolved_format,
        data=bundle.to_dict(),
        rendered_content=rendered_content,
        output_path=output_path,
    )
