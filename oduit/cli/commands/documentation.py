"""Documentation command implementations."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer

from ...arc42_renderer import (
    inspect_generated_markdown_quality,
    render_arc42_addon_markdown,
)
from ...documentation_policy import (
    DocumentationDirectoryPolicy,
    DocumentationTargetNotAllowedError,
    load_documentation_directory_policy,
)
from ...documentation_renderer import (
    render_dependency_graph_mermaid,
    render_shared_model_markdown,
)
from ...documentation_tracking import (
    TECHNICAL_DOC_FILENAME,
    TECHNICAL_DOC_METADATA_FILENAME,
    accept_reviewed_technical_documentation,
    build_technical_documentation_metadata,
    inspect_all_technical_documentation_statuses,
    inspect_technical_documentation_status,
    load_technical_documentation_metadata,
    select_next_technical_doc_status,
    technical_doc_needs_action,
    technical_doc_paths,
    technical_evidence_paths,
    utc_now_iso,
    write_technical_documentation_metadata,
)
from ...project_paths import resolve_project_path_context
from ...technical_documentation import (
    resolve_addon_documentation_target,
    resolve_technical_doc_output_path,
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


def _resolve_status_format(global_config: Any, requested_format: str | None) -> str:
    if requested_format:
        return requested_format
    format_value = getattr(getattr(global_config, "format", None), "value", None)
    return "json" if format_value == "json" else "text"


def _selected_path_is_outside_policy(
    select_dir: str | None,
    *,
    path_context: Any,
    documentation_policy: DocumentationDirectoryPolicy,
) -> bool:
    if select_dir is None or not documentation_policy.configured:
        return False
    selected = path_context.resolve_user_path(select_dir)
    return not documentation_policy.intersects(selected)


def _write_output(content: str, output_path: Path | None) -> None:
    if output_path is None:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")


def _check_output_overwrite(
    output_path: Path,
    *,
    force: bool,
) -> None:
    if output_path.exists() and not force:
        raise FileExistsError(str(output_path))


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
    output_path_value: str | None = None,
) -> None:
    if output_path is not None:
        _write_output(rendered_content, output_path)

    if format_name == "json":
        payload = output_result_to_json(
            {
                "success": True,
                "operation": operation,
                "format": format_name,
                "output_path": output_path_value
                if output_path_value is not None
                else (str(output_path) if output_path is not None else None),
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


def _progress_source_label(source: str) -> str:
    return {
        "explicit": "explicit",
        "local_config": ".oduit.toml",
        "git": "git",
        "cwd": "cwd",
    }.get(source, source)


def _normalize_progress_level(progress_level: str) -> str:
    value = (progress_level or "compact").strip().lower()
    if value not in {"compact", "model", "debug"}:
        raise typer.BadParameter(
            "--progress-level must be one of: compact, model, debug"
        )
    return value


def _format_progress_message(
    stage: str, data: dict[str, Any], *, progress_level: str
) -> str | None:
    if progress_level == "compact" and stage not in {
        "path_base",
        "resolve_target",
        "technical_inventory",
        "model_inventory",
        "runtime_metadata_batch",
        "render",
        "writing",
        "writing_metadata",
    }:
        return None
    if progress_level == "model" and stage in {
        "inspect_addon",
        "dependency_graph",
        "model_source",
        "model_runtime_fields",
        "model_runtime_views",
        "model_runtime_fields_cached",
        "model_runtime_views_cached",
        "recommended_tests",
    }:
        return None

    module = data.get("module")
    model = data.get("model")
    index = data.get("index")
    total = data.get("total")
    if stage == "path_base":
        return (
            "resolving project path base: "
            f"{data.get('display_base', '.')} "
            f"({_progress_source_label(str(data.get('source', 'cwd')))})"
        )
    if stage == "resolve_target":
        return f"resolving addon target: {data.get('target', '')}".rstrip()
    if stage == "technical_inventory" and module:
        return f"collecting source inventory: {module}"
    if stage == "inspect_addon" and module:
        return f"inspecting addon: {module}"
    if stage == "model_inventory" and module:
        return f"collecting model inventory: {module}"
    if stage == "runtime_metadata_batch":
        model_count = data.get("model_count")
        model_count_text = str(model_count) if model_count is not None else "unknown"
        return f"querying runtime metadata: {model_count_text} models"
    if stage == "dependency_graph" and module:
        return f"collecting dependency graph: {module}"
    if stage == "model_documentation" and module and model:
        suffix = f" ({index}/{total})" if index and total else ""
        return f"documenting model: {module}:{model}{suffix}"
    if stage == "model_source" and model:
        return f"collecting source evidence: {model}"
    if stage == "model_runtime_fields" and model:
        return f"querying runtime fields: {model}"
    if stage == "model_runtime_views" and model:
        return f"querying runtime views: {model}"
    if stage == "model_runtime_fields_cached" and model and progress_level == "debug":
        return f"using cached runtime fields: {model}"
    if stage == "model_runtime_views_cached" and model and progress_level == "debug":
        return f"using cached runtime views: {model}"
    if stage == "recommended_tests" and module:
        return f"collecting test recommendations: {module}"
    if stage == "render" and module:
        return f"rendering arc42 markdown: {module}"
    if stage == "writing":
        return f"writing: {data.get('path', '')}".rstrip()
    if stage == "writing_metadata":
        return f"writing metadata: {data.get('path', '')}".rstrip()
    return None


def _make_docs_progress(
    global_config: Any, *, enabled: bool | None, progress_level: str
) -> Any:
    if enabled is False:
        return None
    if enabled is None:
        if getattr(getattr(global_config, "format", None), "value", None) == "json":
            return None
        if not sys.stderr.isatty():
            return None

    def progress(stage: str, data: dict[str, Any]) -> None:
        message = _format_progress_message(stage, data, progress_level=progress_level)
        if message:
            typer.echo(f"[oduit docs] {message}", err=True)

    return progress


def _generation_options(
    *,
    source_only: bool,
    include_arch: bool,
    path_prefix: str | None,
    path_base_source: str | None,
    max_models: int | None,
    max_fields_per_model: int | None,
    field_attributes: list[str],
    view_types: list[str],
) -> dict[str, Any]:
    options = {
        "source_only": source_only,
        "include_arch": include_arch,
        "path_prefix": path_prefix,
        "max_models": max_models,
        "max_fields_per_model": max_fields_per_model,
        "field_attributes": list(field_attributes),
        "view_types": list(view_types),
    }
    if path_base_source is not None:
        options["path_base"] = {"path": ".", "source": path_base_source}
    return options


def _addon_local_metadata_output_path(
    bundle: Any, output_path: Path | None
) -> Path | None:
    if output_path is None or getattr(bundle, "target", None) is None:
        return None
    addon_output_path = resolve_technical_doc_output_path(
        bundle.target,
        addon_root=getattr(bundle, "source_addon_root", None),
        output=None,
        output_in_addon=True,
    )
    if addon_output_path is None:
        return None
    if output_path.resolve(strict=False) != addon_output_path.resolve(strict=False):
        return None
    return output_path.with_name(TECHNICAL_DOC_METADATA_FILENAME)


def _status_cell(value: str | None) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    return text or "-"


def _status_flag(value: bool) -> str:
    return "yes" if value else "no"


def _render_pipe_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        rows = [["-" for _ in headers]]
    separator = "|" + "|".join("---" for _ in headers) + "|"
    lines = [
        "| " + " | ".join(headers) + " |",
        separator,
        *("| " + " | ".join(row) + " |" for row in rows),
    ]
    return "\n".join(lines)


def _summarize_paths(paths: list[str], *, limit: int = 10) -> str:
    if not paths:
        return "-"
    visible = paths[:limit]
    if len(paths) <= limit:
        return ", ".join(visible)
    return f"{', '.join(visible)} (+{len(paths) - limit} more)"


def _render_status_text(statuses: list[Any], *, include_files: bool) -> str:
    lines = [
        "Technical documentation status",
        "",
        _render_pipe_table(
            [
                "Addon",
                "Status",
                "Created",
                "Last generated",
                "Doc edited",
                "Source changed",
                "Document",
            ],
            [
                [
                    status.module,
                    status.status,
                    _status_cell(status.created_at),
                    _status_cell(status.last_generated_at),
                    _status_flag(status.document_edited_since_last_generation),
                    _status_flag(status.source_changed_since_last_generation),
                    status.doc_path if status.has_document else "-",
                ]
                for status in statuses
            ],
        ),
    ]
    if include_files:
        for status in statuses:
            if not any(
                [status.changed_files, status.added_files, status.removed_files]
            ):
                continue
            lines.extend(
                [
                    "",
                    f"{status.module} file changes",
                    f"changed: {_summarize_paths(status.changed_files)}",
                    f"added: {_summarize_paths(status.added_files)}",
                    f"removed: {_summarize_paths(status.removed_files)}",
                ]
            )
    return "\n".join(lines)


def _render_single_status_text(status: Any, *, include_files: bool) -> str:
    lines = [f"{status.module}: {status.status}"]
    if include_files:
        lines.extend(
            [
                f"changed: {_summarize_paths(status.changed_files)}",
                f"added: {_summarize_paths(status.added_files)}",
                f"removed: {_summarize_paths(status.removed_files)}",
            ]
        )
    return "\n".join(lines)


def _metadata_summary(status: Any) -> dict[str, Any]:
    options = getattr(status, "generation_options", None) or {}
    return {
        "template": getattr(status, "template", None),
        "generation_count": getattr(status, "generation_count", None),
        "source_only": options.get("source_only"),
        "include_arch": options.get("include_arch"),
        "max_models": options.get("max_models"),
        "max_fields_per_model": options.get("max_fields_per_model"),
        "evidence_counts": getattr(status, "evidence_counts", {}) or {},
    }


def _status_to_payload_dict(status: Any, *, include_files: bool) -> dict[str, Any]:
    data = status.to_dict()
    if not include_files:
        data.pop("changed_files", None)
        data.pop("added_files", None)
        data.pop("removed_files", None)
    data["metadata_summary"] = _metadata_summary(status)
    return data


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
    global_config, env_config = resolve_command_env_config_fn(ctx)
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
    global_config, env_config = resolve_command_env_config_fn(ctx)
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


def technical_documentation_command(
    ctx: typer.Context,
    *,
    target: str,
    template: str,
    database: str | None,
    timeout: float,
    source_only: bool,
    include_arch: bool,
    attributes: str | None,
    types: str | None,
    output_path: Path | None,
    output_in_addon: bool,
    force: bool,
    format_name: str | None,
    progress: bool | None,
    progress_level: str,
    max_models: int | None,
    max_fields_per_model: int | None,
    path_prefix: str | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    print_command_error_result_fn: Any,
    module_not_found_error_cls: Any,
) -> None:
    """Generate arc42 technical documentation for one addon target."""

    global_config, env_config = resolve_command_env_config_fn(ctx)
    resolved_format = _resolve_docs_format(global_config, format_name)
    if resolved_format not in {"markdown", "json"}:
        raise typer.BadParameter("format must be either 'markdown' or 'json'")
    if output_in_addon and resolved_format != "markdown":
        raise typer.BadParameter("--output-in-addon requires markdown output")

    field_attributes = _parse_csv_items(attributes)
    view_types = _parse_csv_items(types)
    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
        explicit_base=path_prefix,
    )
    documentation_policy = load_documentation_directory_policy(
        env_config,
        path_base_dir=path_context.base_dir,
    )
    effective_path_prefix = path_context.base_dir.as_posix()
    normalized_progress_level = _normalize_progress_level(progress_level)
    progress_cb = _make_docs_progress(
        global_config, enabled=progress, progress_level=normalized_progress_level
    )
    render_markdown = not (
        resolved_format == "markdown" and (output_path is not None or output_in_addon)
    )
    if progress_cb is not None:
        progress_cb(
            "path_base",
            {
                "display_base": path_context.relative(path_context.base_dir),
                "source": path_context.source,
            },
        )
    ops = build_odoo_operations_fn(global_config)
    try:
        bundle = ops.build_technical_documentation(
            target,
            template=template,
            odoo_series=global_config.odoo_series,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            field_attributes=field_attributes,
            view_types=view_types,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=effective_path_prefix,
            path_base_dir=effective_path_prefix,
            documentation_policy=documentation_policy,
            progress=progress_cb,
            progress_level=normalized_progress_level,
            render_markdown=render_markdown,
        )
    except module_not_found_error_cls as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical",
            str(exc),
            error_type="ModuleNotFoundError",
            details={"target": target},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
        raise typer.Exit(1) from None
    except FileNotFoundError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical",
            str(exc),
            error_type="NotFoundError",
            details={"target": target},
            remediation=[
                (
                    "Use either a valid addon name or a path that"
                    " resolves to an addon root."
                ),
            ],
        )
        raise typer.Exit(1) from None
    except DocumentationTargetNotAllowedError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical",
            str(exc),
            error_type="DocumentationTargetNotAllowedError",
            details={
                "target": target,
                "addon_root": exc.addon_root,
                "allowed_addon_dirs": exc.allowed_dirs,
            },
            remediation=[
                (
                    "Use an addon under [documentation].allowed_addon_dirs, or "
                    "update that allowlist only for project-controlled addon "
                    "directories."
                ),
            ],
        )
        raise typer.Exit(1) from None
    except ValueError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical",
            str(exc),
            error_type="ValidationError",
            details={"target": target, "template": template},
        )
        raise typer.Exit(1) from None

    resolved_output_path = (
        resolve_technical_doc_output_path(
            bundle.target,
            addon_root=getattr(bundle, "source_addon_root", None),
            output=output_path,
            output_in_addon=output_in_addon,
        )
        if bundle.target is not None
        else output_path
    )
    display_output_path = (
        path_context.relative(resolved_output_path)
        if resolved_output_path is not None
        else None
    )

    if resolved_output_path is not None and bundle.target is not None:
        if bundle.target.target_kind == "module" and bundle.target.ambiguous:
            print_command_error_result_fn(
                global_config,
                "docs_technical",
                "Refusing to write from an ambiguous module-name resolution.",
                error_type="AmbiguousTargetError",
                details={
                    "target": target,
                    "candidate_addon_roots": bundle.target.candidate_addon_roots,
                },
                remediation=[
                    (
                        "Use an explicit addon path such as `@addons/has_base`"
                        " when writing documentation."
                    ),
                ],
            )
            raise typer.Exit(1) from None
        try:
            _check_output_overwrite(resolved_output_path, force=force)
        except FileExistsError:
            print_command_error_result_fn(
                global_config,
                "docs_technical",
                f"Output file already exists: {resolved_output_path}",
                error_type="FileExistsError",
                details={"output_path": str(resolved_output_path)},
                remediation=[
                    "Retry with `--force` to overwrite the existing file.",
                ],
            )
            raise typer.Exit(1) from None

    if resolved_format == "json":
        rendered_content = json.dumps(bundle.to_dict(), indent=2, sort_keys=True)
        _emit_document_output(
            global_config=global_config,
            operation="docs_technical",
            result_type="technical_documentation",
            format_name=resolved_format,
            data=bundle.to_dict(),
            rendered_content=rendered_content,
            output_path=resolved_output_path,
            output_path_value=display_output_path,
        )
        return

    if resolved_output_path is not None:
        metadata_output_path = _addon_local_metadata_output_path(
            bundle, resolved_output_path
        )
        if metadata_output_path is not None:
            previous_metadata, _ = load_technical_documentation_metadata(
                metadata_output_path
            )
            bundle.generated_at = utc_now_iso()
            bundle.output_path = f"docs/{TECHNICAL_DOC_FILENAME}"
            bundle.metadata_path = f"docs/{TECHNICAL_DOC_METADATA_FILENAME}"
            bundle.markdown = render_arc42_addon_markdown(bundle)
            if progress_cb is not None:
                progress_cb("writing", {"path": display_output_path})
            _write_output(bundle.markdown, resolved_output_path)
            metadata = build_technical_documentation_metadata(
                bundle=bundle,
                doc_path=resolved_output_path,
                metadata_path=metadata_output_path,
                generation_options=_generation_options(
                    source_only=source_only,
                    include_arch=include_arch,
                    path_prefix=".",
                    path_base_source=path_context.source,
                    max_models=max_models,
                    max_fields_per_model=max_fields_per_model,
                    field_attributes=field_attributes,
                    view_types=view_types,
                ),
                previous_metadata=previous_metadata,
                path_base_dir=path_context.base_dir,
                source_addon_root=Path(
                    bundle.source_addon_root or bundle.addon_root
                ).resolve(strict=False),
            )
            quality = inspect_generated_markdown_quality(bundle.markdown)
            metadata.warnings = sorted(
                dict.fromkeys(
                    list(metadata.warnings) + list(quality.get("warnings", []))
                )
            )
            if progress_cb is not None:
                progress_cb(
                    "writing_metadata",
                    {"path": path_context.relative(metadata_output_path)},
                )
            write_technical_documentation_metadata(metadata, metadata_output_path)
            print(f"Wrote markdown documentation to {display_output_path}")
            print(
                "Wrote documentation metadata to "
                f"{path_context.relative(metadata_output_path)}"
            )
            return
        if progress_cb is not None:
            progress_cb("writing", {"path": display_output_path})
        _write_output(bundle.markdown, resolved_output_path)
        print(f"Wrote markdown documentation to {display_output_path}")
        return
    print(bundle.markdown)


def technical_evidence_command(
    ctx: typer.Context,
    *,
    target: str,
    database: str | None,
    timeout: float,
    source_only: bool,
    include_arch: bool,
    attributes: str | None,
    types: str | None,
    output_in_addon: bool,
    force: bool,
    format_name: str | None,
    max_models: int | None,
    max_fields_per_model: int | None,
    path_prefix: str | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Generate deterministic technical evidence files."""

    global_config, env_config = resolve_command_env_config_fn(ctx)
    resolved_format = _resolve_status_format(global_config, format_name)
    if resolved_format not in {"text", "json"}:
        raise typer.BadParameter("format must be either 'text' or 'json'")
    if not output_in_addon:
        raise typer.BadParameter("--output-in-addon is required for technical-evidence")

    field_attributes = _parse_csv_items(attributes)
    view_types = _parse_csv_items(types)
    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
        explicit_base=path_prefix,
    )
    documentation_policy = load_documentation_directory_policy(
        env_config,
        path_base_dir=path_context.base_dir,
    )
    ops = build_odoo_operations_fn(global_config)
    try:
        payload = ops.write_technical_evidence(
            target,
            force=force,
            odoo_series=global_config.odoo_series,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            field_attributes=field_attributes,
            view_types=view_types,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_base_dir=path_context.base_dir.as_posix(),
            documentation_policy=documentation_policy,
        )
    except FileExistsError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_evidence",
            str(exc),
            error_type="FileExistsError",
            details={"target": target},
            remediation=["Retry with --force to overwrite evidence files."],
        )
        raise typer.Exit(2) from None
    except (FileNotFoundError, ValueError, DocumentationTargetNotAllowedError) as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_evidence",
            str(exc),
            error_type=type(exc).__name__,
            details={"target": target},
        )
        raise typer.Exit(2) from None

    if resolved_format == "json":
        print(
            json.dumps(
                output_result_to_json(
                    {
                        "success": True,
                        "operation": "docs_technical_evidence",
                        "type": "technical_evidence",
                        "data": payload,
                    }
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return
    print(
        "Wrote technical evidence to"
        f" {path_context.relative(Path(payload['evidence_path']))}"
    )
    print(
        "Wrote technical evidence metadata to "
        f"{path_context.relative(Path(payload['metadata_path']))}"
    )


def technical_report_command(
    ctx: typer.Context,
    *,
    target: str,
    database: str | None,
    timeout: float,
    source_only: bool,
    include_arch: bool,
    attributes: str | None,
    types: str | None,
    output_in_addon: bool,
    force: bool,
    generate_evidence: bool,
    format_name: str | None,
    max_models: int | None,
    max_fields_per_model: int | None,
    path_prefix: str | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Generate LLM/human report seed markdown."""

    global_config, env_config = resolve_command_env_config_fn(ctx)
    resolved_format = _resolve_docs_format(global_config, format_name)
    if resolved_format not in {"markdown", "json"}:
        raise typer.BadParameter("format must be either 'markdown' or 'json'")
    if not output_in_addon:
        raise typer.BadParameter("--output-in-addon is required for technical-report")

    field_attributes = _parse_csv_items(attributes)
    view_types = _parse_csv_items(types)
    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
        explicit_base=path_prefix,
    )
    documentation_policy = load_documentation_directory_policy(
        env_config,
        path_base_dir=path_context.base_dir,
    )
    ops = build_odoo_operations_fn(global_config)
    try:
        resolved_target = resolve_addon_documentation_target(
            env_config,
            target,
            path_base_dir=path_context.base_dir,
            documentation_policy=documentation_policy,
        )
    except (FileNotFoundError, ValueError, DocumentationTargetNotAllowedError) as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_report",
            str(exc),
            error_type=type(exc).__name__,
            details={"target": target},
        )
        raise typer.Exit(2) from None

    addon_root = Path(resolved_target.addon_root).resolve(strict=False)
    report_path, report_metadata_path = technical_doc_paths(addon_root)
    evidence_path, evidence_metadata_path = technical_evidence_paths(addon_root)
    if (not evidence_path.exists() or not evidence_metadata_path.exists()) and (
        not generate_evidence
    ):
        print_command_error_result_fn(
            global_config,
            "docs_technical_report",
            "Technical evidence is missing.",
            error_type="MissingEvidenceError",
            details={"target": target},
            remediation=[
                (
                    "Run oduit docs technical-evidence"
                    f" @addons/{resolved_target.module}"
                    " --output-in-addon first."
                )
            ],
        )
        raise typer.Exit(2) from None
    try:
        if generate_evidence and (
            not evidence_path.exists() or not evidence_metadata_path.exists()
        ):
            ops.write_technical_evidence(
                target,
                force=False,
                odoo_series=global_config.odoo_series,
                database=database,
                timeout=timeout,
                source_only=source_only,
                include_arch=include_arch,
                field_attributes=field_attributes,
                view_types=view_types,
                max_models=max_models,
                max_fields_per_model=max_fields_per_model,
                path_base_dir=path_context.base_dir.as_posix(),
                documentation_policy=documentation_policy,
            )
        _check_output_overwrite(report_path, force=force)
        bundle = ops.build_technical_report_seed(
            target,
            odoo_series=global_config.odoo_series,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            field_attributes=field_attributes,
            view_types=view_types,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_base_dir=path_context.base_dir.as_posix(),
            documentation_policy=documentation_policy,
            generate_evidence_if_missing=generate_evidence,
        )
    except FileExistsError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_report",
            str(exc),
            error_type="FileExistsError",
            details={"target": target},
            remediation=["Retry with --force to overwrite the report."],
        )
        raise typer.Exit(2) from None
    except (FileNotFoundError, ValueError, DocumentationTargetNotAllowedError) as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_report",
            str(exc),
            error_type=type(exc).__name__,
            details={"target": target},
        )
        raise typer.Exit(2) from None

    bundle.generated_at = utc_now_iso()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(bundle.markdown, encoding="utf-8")
    previous_metadata, _ = load_technical_documentation_metadata(report_metadata_path)
    metadata = build_technical_documentation_metadata(
        bundle=bundle,
        doc_path=report_path,
        metadata_path=report_metadata_path,
        generation_options=_generation_options(
            source_only=source_only,
            include_arch=include_arch,
            path_prefix=".",
            path_base_source=path_context.source,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            field_attributes=field_attributes,
            view_types=view_types,
        ),
        previous_metadata=previous_metadata,
        path_base_dir=path_context.base_dir,
        source_addon_root=Path(bundle.source_addon_root or bundle.addon_root).resolve(
            strict=False
        ),
    )
    write_technical_documentation_metadata(metadata, report_metadata_path)
    if resolved_format == "json":
        print(
            json.dumps(
                output_result_to_json(
                    {
                        "success": True,
                        "operation": "docs_technical_report",
                        "type": "technical_documentation",
                        "data": {
                            "module": bundle.module,
                            "report_path": path_context.relative(report_path),
                            "metadata_path": path_context.relative(
                                report_metadata_path
                            ),
                            "evidence_path": path_context.relative(evidence_path),
                        },
                    }
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return
    print(f"Wrote markdown documentation to {path_context.relative(report_path)}")
    print(
        "Wrote documentation metadata to "
        f"{path_context.relative(report_metadata_path)}"
    )


def technical_diff_command(
    ctx: typer.Context,
    *,
    target: str,
    include_diff: bool,
    format_name: str | None,
    significant_only: bool,
    path_prefix: str | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Compare report evidence snapshots against current evidence blocks."""

    global_config, env_config = resolve_command_env_config_fn(ctx)
    resolved_format = _resolve_status_format(global_config, format_name)
    if resolved_format not in {"text", "json"}:
        raise typer.BadParameter("format must be either 'text' or 'json'")
    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
        explicit_base=path_prefix,
    )
    documentation_policy = load_documentation_directory_policy(
        env_config,
        path_base_dir=path_context.base_dir,
    )
    ops = build_odoo_operations_fn(global_config)
    try:
        result = ops.diff_technical_report_evidence(
            target,
            include_diff=include_diff,
            significant_only=significant_only,
            path_base_dir=path_context.base_dir.as_posix(),
            documentation_policy=documentation_policy,
        )
    except (FileNotFoundError, ValueError, DocumentationTargetNotAllowedError) as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_diff",
            str(exc),
            error_type=type(exc).__name__,
            details={"target": target},
        )
        raise typer.Exit(2) from None

    if resolved_format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Technical documentation evidence diff: {result['module']}")
        print(f"Report:   {result['report_path']}")
        print(f"Evidence: {result['evidence_path']}")
        print(f"Current evidence version: {result.get('current_evidence_version')}")
        print(f"Status: {result['status']}")
        changed = [
            entry
            for entry in result.get("entries", [])
            if entry["status"] != "unchanged"
        ]
        if changed:
            print("\nChanged snapshots:")
            for entry in changed:
                change_label = (
                    "stale significant"
                    if entry["status"] == "snapshot_stale" and entry.get("significant")
                    else entry["status"]
                )
                print(f"- {entry['block_id']}: {change_label}")
    if result["status"] in {"stale", "edited_snapshots"}:
        raise typer.Exit(1)
    if result["status"] in {"invalid", "missing_report", "missing_evidence"}:
        raise typer.Exit(2)


def technical_documentation_refresh_command(
    ctx: typer.Context,
    *,
    target: str,
    dry_run: bool,
    force_edited_blocks: bool,
    add_missing_blocks: bool,
    source_only: bool | None,
    database: str | None,
    timeout: float,
    attributes: str | None,
    types: str | None,
    max_models: int | None,
    max_fields_per_model: int | None,
    path_prefix: str | None,
    format_name: str | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Refresh managed generated blocks in addon-local technical docs."""

    global_config, env_config = resolve_command_env_config_fn(ctx)
    resolved_format = _resolve_status_format(global_config, format_name)
    if resolved_format not in {"text", "json"}:
        raise typer.BadParameter("format must be either 'text' or 'json'")
    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
        explicit_base=path_prefix,
    )
    documentation_policy = load_documentation_directory_policy(
        env_config,
        path_base_dir=path_context.base_dir,
    )
    ops = build_odoo_operations_fn(global_config)
    try:
        refresh_result = ops.refresh_technical_documentation(
            target,
            odoo_series=global_config.odoo_series,
            database=database,
            timeout=timeout,
            source_only=source_only,
            field_attributes=_parse_csv_items(attributes),
            view_types=_parse_csv_items(types),
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_context.base_dir.as_posix(),
            path_base_dir=path_context.base_dir.as_posix(),
            documentation_policy=documentation_policy,
            overwrite_edited=force_edited_blocks,
            add_missing=add_missing_blocks,
            write=not dry_run,
        )
    except FileNotFoundError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_refresh",
            str(exc),
            error_type="NotFoundError",
            details={"target": target},
        )
        raise typer.Exit(1) from None
    except DocumentationTargetNotAllowedError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_refresh",
            str(exc),
            error_type="DocumentationTargetNotAllowedError",
            details={
                "target": target,
                "addon_root": exc.addon_root,
                "allowed_addon_dirs": exc.allowed_dirs,
            },
            remediation=[
                (
                    "Use an addon under "
                    "[documentation].allowed_addon_dirs, or "
                    "update that allowlist only for project-controlled "
                    "addon directories."
                ),
            ],
        )
        raise typer.Exit(1) from None
    except ValueError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_refresh",
            str(exc),
            error_type="ValidationError",
            details={"target": target},
        )
        raise typer.Exit(1) from None

    if resolved_format == "json":
        payload = output_result_to_json(
            {
                "success": True,
                "operation": "docs_technical_refresh_preview"
                if dry_run
                else "docs_technical_refresh",
                "type": "technical_documentation_refresh",
                **refresh_result,
            },
            result_type="technical_documentation_refresh",
        )
        print(json.dumps(payload))
        return

    doc_path = refresh_result.get("doc_path")
    updated_blocks = refresh_result.get("updated_blocks", [])
    if dry_run:
        if updated_blocks:
            print(
                f"Would update {len(updated_blocks)} generated block(s) in {doc_path}:"
            )
            for block_id in updated_blocks:
                print(f"- {block_id}")
        else:
            print(f"No generated block updates needed in {doc_path}")
        if refresh_result.get("warnings"):
            print("Warnings:")
            for warning in refresh_result["warnings"]:
                print(f"- {warning}")
        return

    print(f"Updated {len(updated_blocks)} generated block(s) in {doc_path}")
    print(f"Updated metadata {refresh_result.get('metadata_path')}")


def technical_documentation_status_command(
    ctx: typer.Context,
    *,
    target: str | None,
    format_name: str | None,
    select_dir: str | None,
    only_stale: bool,
    include_files: bool,
    resolve_command_env_config_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Report durable technical-documentation status for one addon or many."""

    global_config, env_config = resolve_command_env_config_fn(ctx)
    if target is not None and select_dir is not None:
        raise typer.BadParameter("--select-dir cannot be used with TARGET")

    resolved_format = _resolve_status_format(global_config, format_name)
    if resolved_format not in {"text", "json"}:
        raise typer.BadParameter("format must be either 'text' or 'json'")

    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
    )
    documentation_policy = load_documentation_directory_policy(
        env_config,
        path_base_dir=path_context.base_dir,
    )
    if _selected_path_is_outside_policy(
        select_dir,
        path_context=path_context,
        documentation_policy=documentation_policy,
    ):
        print_command_error_result_fn(
            global_config,
            "docs_technical_status",
            (
                f"Technical documentation is not allowed for directory '{select_dir}'; "
                "it is outside [documentation].allowed_addon_dirs."
            ),
            error_type="DocumentationTargetNotAllowedError",
            details={
                "target": select_dir,
                "addon_root": path_context.resolve_user_path(select_dir).as_posix(),
                "allowed_addon_dirs": documentation_policy.display_allowed_dirs(
                    base_dir=path_context.base_dir
                ),
            },
            remediation=[
                (
                    "Use an addon under [documentation].allowed_addon_dirs, or "
                    "update that allowlist only for project-controlled addon "
                    "directories."
                ),
            ],
        )
        raise typer.Exit(1) from None
    if target is not None:
        try:
            resolved_target = resolve_addon_documentation_target(
                env_config,
                target,
                path_base_dir=path_context.base_dir,
                documentation_policy=documentation_policy,
            )
        except FileNotFoundError as exc:
            print_command_error_result_fn(
                global_config,
                "docs_technical_status",
                str(exc),
                error_type="NotFoundError",
                details={"target": target},
                remediation=[
                    "Use a valid addon name or a path that resolves to an addon root."
                ],
            )
            raise typer.Exit(1) from None
        except DocumentationTargetNotAllowedError as exc:
            print_command_error_result_fn(
                global_config,
                "docs_technical_status",
                str(exc),
                error_type="DocumentationTargetNotAllowedError",
                details={
                    "target": target,
                    "addon_root": exc.addon_root,
                    "allowed_addon_dirs": exc.allowed_dirs,
                },
                remediation=[
                    (
                        "Use an addon under [documentation].allowed_addon_dirs, or "
                        "update that allowlist only for project-controlled addon "
                        "directories."
                    ),
                ],
            )
            raise typer.Exit(1) from None
        if resolved_target.target_kind == "module" and resolved_target.ambiguous:
            print_command_error_result_fn(
                global_config,
                "docs_technical_status",
                "Refusing to inspect an ambiguous module-name resolution.",
                error_type="AmbiguousTargetError",
                details={
                    "target": target,
                    "candidate_addon_roots": resolved_target.candidate_addon_roots,
                },
                remediation=[
                    "Use an explicit addon path such as `@addons/has_base`.",
                ],
            )
            raise typer.Exit(1) from None
        statuses = [
            inspect_technical_documentation_status(
                addon_root=resolved_target.addon_root,
                module=resolved_target.module,
                path_base_dir=path_context.base_dir,
            )
        ]
    else:
        statuses = inspect_all_technical_documentation_statuses(
            addons_path=str(env_config["addons_path"]),
            select_dir=select_dir,
            path_base_dir=path_context.base_dir,
            documentation_policy=documentation_policy,
        )
        if select_dir is not None and not statuses:
            print_command_error_result_fn(
                global_config,
                "docs_technical_status",
                f"No addons found in directory '{select_dir}'",
                error_type="NotFoundError",
                details={"select_dir": select_dir},
            )
            raise typer.Exit(1) from None

    if only_stale:
        statuses = [status for status in statuses if status.status != "up_to_date"]

    if resolved_format == "json":
        payload = output_result_to_json(
            {
                "success": True,
                "operation": "docs_technical_status",
                "type": "technical_documentation_status",
                "statuses": [
                    _status_to_payload_dict(status, include_files=include_files)
                    for status in statuses
                ],
            },
            result_type="technical_documentation_status",
        )
        print(json.dumps(payload))
        return

    if not statuses:
        print("Technical documentation status\n\nNo matching addons.")
        return
    print(_render_status_text(statuses, include_files=include_files))


def technical_documentation_check_command(
    ctx: typer.Context,
    *,
    target: str,
    format_name: str | None,
    include_files: bool,
    fail_on_stale: bool,
    resolve_command_env_config_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Check one addon's technical-documentation freshness state."""

    global_config, env_config = resolve_command_env_config_fn(ctx)
    path_context = resolve_project_path_context(config_path=global_config.config_path)
    documentation_policy = load_documentation_directory_policy(
        env_config,
        path_base_dir=path_context.base_dir,
    )
    resolved_format = _resolve_status_format(global_config, format_name)
    if resolved_format not in {"text", "json"}:
        raise typer.BadParameter("format must be either 'text' or 'json'")

    try:
        resolved_target = resolve_addon_documentation_target(
            env_config,
            target,
            path_base_dir=path_context.base_dir,
            documentation_policy=documentation_policy,
        )
    except FileNotFoundError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_check",
            str(exc),
            error_type="NotFoundError",
            details={"target": target},
            remediation=[
                "Use a valid addon name or a path that resolves to an addon root."
            ],
        )
        raise typer.Exit(1) from None
    except DocumentationTargetNotAllowedError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_check",
            str(exc),
            error_type="DocumentationTargetNotAllowedError",
            details={
                "target": target,
                "addon_root": exc.addon_root,
                "allowed_addon_dirs": exc.allowed_dirs,
            },
            remediation=[
                (
                    "Use an addon under [documentation].allowed_addon_dirs, or "
                    "update that allowlist only for project-controlled addon "
                    "directories."
                ),
            ],
        )
        raise typer.Exit(1) from None

    status = inspect_technical_documentation_status(
        addon_root=resolved_target.addon_root,
        module=resolved_target.module,
        path_base_dir=path_context.base_dir,
    )
    if resolved_target.target_kind == "module" and resolved_target.ambiguous:
        print_command_error_result_fn(
            global_config,
            "docs_technical_check",
            "Refusing to inspect an ambiguous module-name resolution.",
            error_type="AmbiguousTargetError",
            details={
                "target": target,
                "candidate_addon_roots": resolved_target.candidate_addon_roots,
            },
            remediation=["Use an explicit addon path such as `@addons/has_base`."],
        )
        raise typer.Exit(1) from None
    success = status.up_to_date or not fail_on_stale

    if resolved_format == "json":
        payload = output_result_to_json(
            {
                "success": success,
                "operation": "docs_technical_check",
                "type": "technical_documentation_status",
                "status": _status_to_payload_dict(status, include_files=include_files),
                "include_files": include_files,
            },
            result_type="technical_documentation_status",
        )
        print(json.dumps(payload))
    else:
        print(_render_single_status_text(status, include_files=include_files))

    if not success:
        raise typer.Exit(1)


def technical_documentation_next_command(
    ctx: typer.Context,
    *,
    path: str | None,
    format_name: str | None,
    include_files: bool,
    resolve_command_env_config_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Return the next addon that needs technical-documentation work."""

    global_config, env_config = resolve_command_env_config_fn(ctx)
    path_context = resolve_project_path_context(config_path=global_config.config_path)
    documentation_policy = load_documentation_directory_policy(
        env_config,
        path_base_dir=path_context.base_dir,
    )
    resolved_format = _resolve_status_format(global_config, format_name)
    if resolved_format not in {"text", "json"}:
        raise typer.BadParameter("format must be either 'text' or 'json'")

    if _selected_path_is_outside_policy(
        path,
        path_context=path_context,
        documentation_policy=documentation_policy,
    ):
        print_command_error_result_fn(
            global_config,
            "docs_technical_next",
            (
                f"Technical documentation is not allowed for directory '{path}'; "
                "it is outside [documentation].allowed_addon_dirs."
            ),
            error_type="DocumentationTargetNotAllowedError",
            details={
                "target": path,
                "addon_root": path_context.resolve_user_path(path).as_posix(),
                "allowed_addon_dirs": documentation_policy.display_allowed_dirs(
                    base_dir=path_context.base_dir
                ),
            },
            remediation=[
                (
                    "Use an addon under [documentation].allowed_addon_dirs, or "
                    "update that allowlist only for project-controlled addon "
                    "directories."
                ),
            ],
        )
        raise typer.Exit(1) from None

    statuses = inspect_all_technical_documentation_statuses(
        addons_path=str(env_config["addons_path"]),
        select_dir=path,
        path_base_dir=path_context.base_dir,
        documentation_policy=documentation_policy,
    )
    if path is not None and not statuses:
        print_command_error_result_fn(
            global_config,
            "docs_technical_next",
            f"No addons found in directory '{path}'",
            error_type="NotFoundError",
            details={"path": path},
        )
        raise typer.Exit(1) from None

    next_status = select_next_technical_doc_status(statuses)
    stale_count = sum(1 for status in statuses if technical_doc_needs_action(status))

    if resolved_format == "json":
        payload = output_result_to_json(
            {
                "success": True,
                "operation": "docs_technical_next",
                "type": "technical_documentation_next",
                "next_module": next_status.module if next_status is not None else None,
                "status": (
                    _status_to_payload_dict(next_status, include_files=include_files)
                    if next_status is not None
                    else None
                ),
                "scanned_count": len(statuses),
                "stale_count": stale_count,
                "include_files": include_files,
            },
            result_type="technical_documentation_next",
        )
        print(json.dumps(payload))
        return

    if next_status is None:
        typer.echo("No addon needs technical documentation.", err=True)
        return
    print(next_status.module)


def technical_documentation_accept_command(
    ctx: typer.Context,
    *,
    target: str,
    force: bool,
    resolve_command_env_config_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Accept a manually polished technical document without regenerating."""

    global_config, env_config = resolve_command_env_config_fn(ctx)
    path_context = resolve_project_path_context(config_path=global_config.config_path)
    documentation_policy = load_documentation_directory_policy(
        env_config,
        path_base_dir=path_context.base_dir,
    )
    try:
        resolved_target = resolve_addon_documentation_target(
            env_config,
            target,
            path_base_dir=path_context.base_dir,
            documentation_policy=documentation_policy,
        )
    except FileNotFoundError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_accept",
            str(exc),
            error_type="NotFoundError",
            details={"target": target},
        )
        raise typer.Exit(1) from None
    except DocumentationTargetNotAllowedError as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_accept",
            str(exc),
            error_type="DocumentationTargetNotAllowedError",
            details={
                "target": target,
                "addon_root": exc.addon_root,
                "allowed_addon_dirs": exc.allowed_dirs,
            },
            remediation=[
                (
                    "Use an addon under [documentation].allowed_addon_dirs, or "
                    "update that allowlist only for project-controlled addon "
                    "directories."
                ),
            ],
        )
        raise typer.Exit(1) from None
    doc_path = Path(resolved_target.addon_root) / "docs" / TECHNICAL_DOC_FILENAME
    metadata_path = doc_path.with_name(TECHNICAL_DOC_METADATA_FILENAME)
    try:
        metadata = accept_reviewed_technical_documentation(
            addon_root=resolved_target.addon_root,
            module=resolved_target.module,
            metadata_path=metadata_path,
            reviewed_by="manual",
            review_note="Accepted manually polished generated architecture document",
            force=force,
            path_base_dir=path_context.base_dir,
        )
    except (FileNotFoundError, ValueError) as exc:
        print_command_error_result_fn(
            global_config,
            "docs_technical_accept",
            str(exc),
            error_type="ValidationError",
            details={"target": target, "force": force},
        )
        raise typer.Exit(1) from None

    write_technical_documentation_metadata(metadata, metadata_path)
    status = inspect_technical_documentation_status(
        addon_root=resolved_target.addon_root,
        module=resolved_target.module,
        path_base_dir=path_context.base_dir,
    )
    payload = output_result_to_json(
        {
            "success": True,
            "operation": "docs_technical_accept",
            "type": "technical_documentation",
            "module": resolved_target.module,
            "doc_path": path_context.relative(doc_path),
            "metadata_path": path_context.relative(metadata_path),
            "reviewed_at": metadata.reviewed_at,
            "reviewed_by": metadata.reviewed_by,
            "review_note": metadata.review_note,
            "generation_count": metadata.generation_count,
            "status": _status_to_payload_dict(status, include_files=False),
        },
        result_type="technical_documentation",
    )
    print(json.dumps(payload))
