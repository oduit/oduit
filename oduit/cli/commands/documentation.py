"""Documentation command implementations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from ...documentation_renderer import (
    render_dependency_graph_mermaid,
    render_shared_model_markdown,
)
from ...utils import output_result_to_json


def _parse_csv_items(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def _resolve_docs_format(global_config: Any, requested_format: str | None) -> str:
    if requested_format:
        return requested_format
    format_value = getattr(getattr(global_config, "format", None), "value", None)
    return "json" if format_value == "json" else "markdown"


def _write_output(content: str, output_path: Path | None) -> None:
    if output_path is None:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content)


def _write_multi_addon_output(
    bundle: Any,
    output_dir: Path,
    *,
    write_markdown: bool,
    bundle_json: str,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    if write_markdown:
        _write_output(bundle.index_markdown, output_dir / "index.md")
        for addon_doc in bundle.addon_docs:
            if addon_doc.output_path:
                _write_output(addon_doc.markdown, output_dir / addon_doc.output_path)
        for shared_doc in bundle.shared_models:
            if shared_doc.output_path:
                shared_markdown = shared_doc.markdown or render_shared_model_markdown(
                    shared_doc
                )
                _write_output(shared_markdown, output_dir / shared_doc.output_path)
    bundle_json_path = output_dir / "bundle.json"
    _write_output(bundle_json, bundle_json_path)
    return bundle_json_path


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
    path_prefix: str | None,
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
            path_prefix=path_prefix,
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
    path_prefix: str | None,
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
        path_prefix=path_prefix,
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
    path_prefix: str | None,
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
        path_prefix=path_prefix,
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


def addons_documentation_command(
    ctx: typer.Context,
    *,
    modules: str | None,
    select_dir: str | None,
    database: str | None,
    timeout: float,
    source_only: bool,
    include_arch: bool,
    attributes: str | None,
    types: str | None,
    output_dir: Path | None,
    format_name: str | None,
    max_models: int | None,
    max_fields_per_model: int | None,
    path_prefix: str | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    module_manager_cls: Any,
    print_command_error_result_fn: Any,
    module_not_found_error_cls: Any,
) -> None:
    """Generate documentation for multiple addons in one bundle."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    module_manager = module_manager_cls(env_config["addons_path"])

    if modules is None and select_dir is None:
        print_command_error_result_fn(
            global_config,
            "docs_addons",
            "Either provide module names or use --select-dir option",
            details={"modules": modules, "select_dir": select_dir},
        )
        raise typer.Exit(1) from None

    if modules is not None and select_dir is not None:
        print_command_error_result_fn(
            global_config,
            "docs_addons",
            "Cannot use both module names and --select-dir option",
            details={"modules": modules, "select_dir": select_dir},
        )
        raise typer.Exit(1) from None

    if select_dir:
        module_list = sorted(module_manager.find_module_dirs(filter_dir=select_dir))
        if not module_list:
            print_command_error_result_fn(
                global_config,
                "docs_addons",
                f"No modules found in directory '{select_dir}'",
                details={"select_dir": select_dir},
            )
            raise typer.Exit(1) from None
    else:
        module_list = _parse_csv_items(modules)
        if not module_list:
            print_command_error_result_fn(
                global_config,
                "docs_addons",
                "At least one module is required",
                error_type="ValidationError",
                details={"modules": modules},
            )
            raise typer.Exit(1) from None
        missing_modules = [
            module_name
            for module_name in module_list
            if module_manager.find_module_path(module_name) is None
        ]
        if missing_modules:
            print_command_error_result_fn(
                global_config,
                "docs_addons",
                f"Modules not found in addons_path: {', '.join(missing_modules)}",
                error_type="ModuleNotFoundError",
                details={"modules": module_list, "missing_modules": missing_modules},
                remediation=[
                    "Verify the requested modules before generating documentation.",
                ],
            )
            raise typer.Exit(1) from None

    resolved_format = _resolve_docs_format(global_config, format_name)
    if resolved_format not in {"markdown", "json"}:
        raise typer.BadParameter("format must be either 'markdown' or 'json'")
    if resolved_format == "markdown" and output_dir is None:
        print_command_error_result_fn(
            global_config,
            "docs_addons",
            "--output-dir is required for markdown output",
            error_type="ValidationError",
            details={"format": resolved_format},
        )
        raise typer.Exit(1) from None

    ops = build_odoo_operations_fn(global_config)
    try:
        bundle = ops.build_addons_documentation(
            module_list,
            odoo_series=global_config.odoo_series,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            field_attributes=_parse_csv_items(attributes),
            view_types=_parse_csv_items(types),
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_prefix,
        )
    except module_not_found_error_cls as exc:
        print_command_error_result_fn(
            global_config,
            "docs_addons",
            str(exc),
            error_type="ModuleNotFoundError",
            details={"modules": module_list},
            remediation=[
                "Verify that the requested addons exist in the configured addons "
                "paths.",
            ],
        )
        raise typer.Exit(1) from None

    bundle_json = json.dumps(bundle.to_dict(), indent=2, sort_keys=True)
    if output_dir is not None:
        bundle_json_path = _write_multi_addon_output(
            bundle,
            output_dir,
            write_markdown=resolved_format == "markdown",
            bundle_json=bundle_json,
        )
    else:
        bundle_json_path = None

    if resolved_format == "json":
        print(bundle_json)
        return

    assert output_dir is not None
    print(
        "Wrote multi-addon documentation for "
        f"{len(bundle.addon_docs)} addon(s) with "
        f"{len(bundle.shared_models)} shared model page(s) to {output_dir}"
    )
    if bundle_json_path is not None:
        print(f"Bundle metadata: {bundle_json_path}")
