"""Agent command implementations for technical documentation workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from click.core import ParameterSource

from ...arc42_renderer import render_arc42_addon_markdown
from ...documentation_tracking import (
    TECHNICAL_DOC_FILENAME,
    TECHNICAL_DOC_METADATA_FILENAME,
    build_technical_documentation_metadata,
    inspect_all_technical_documentation_statuses,
    inspect_technical_documentation_status,
    load_technical_documentation_metadata,
    select_next_technical_doc_status,
    technical_doc_needs_action,
    utc_now_iso,
    write_technical_documentation_metadata,
)
from ...project_paths import resolve_project_path_context
from ...technical_documentation import (
    resolve_addon_documentation_target,
    resolve_technical_doc_output_path,
)


def _section_titles(bundle: Any) -> list[str]:
    titles: list[str] = []
    for section in getattr(bundle, "sections", []):
        title = getattr(section, "title", "")
        if not title or title.startswith("Appendix"):
            continue
        if ". " in title:
            _, title = title.split(". ", 1)
        titles.append(title)
    return titles


def _evidence_counts(bundle: Any) -> dict[str, int]:
    addon_doc = getattr(bundle, "addon_documentation", None)
    inventory = getattr(bundle, "technical_inventory", None)
    model_count = 0
    if (
        addon_doc is not None
        and getattr(addon_doc, "model_inventory", None) is not None
    ):
        model_count = len(addon_doc.model_inventory.models)
    test_count = 0
    recommended_tests = getattr(addon_doc, "recommended_tests", None)
    if isinstance(recommended_tests, dict):
        tests = recommended_tests.get("tests")
        if isinstance(tests, list):
            test_count = len(tests)
    return {
        "models": model_count,
        "xml_records": len(getattr(inventory, "xml_records", []) or []),
        "routes": len(getattr(inventory, "http_routes", []) or []),
        "tests": test_count,
        "todo_markers": len(getattr(inventory, "todo_markers", []) or []),
    }


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


def _agent_technical_doc_progress(enabled: bool) -> Any:
    if not enabled:
        return None

    def progress(stage: str, data: dict[str, Any]) -> None:
        module = data.get("module")
        model = data.get("model")
        index = data.get("index")
        total = data.get("total")

        message: str | None = None
        if stage == "resolve_target":
            message = f"resolving addon target: {data.get('target', '')}".rstrip()
        elif stage == "technical_inventory" and module:
            message = f"collecting source inventory: {module}"
        elif stage == "inspect_addon" and module:
            message = f"inspecting addon: {module}"
        elif stage == "model_inventory" and module:
            message = f"collecting model inventory: {module}"
        elif stage == "dependency_graph" and module:
            message = f"collecting dependency graph: {module}"
        elif stage == "model_documentation" and module and model:
            suffix = f" ({index}/{total})" if index and total else ""
            message = f"documenting model: {module}:{model}{suffix}"
        elif stage == "model_source" and model:
            message = f"collecting source evidence: {model}"
        elif stage == "model_runtime_fields" and model:
            message = f"querying runtime fields: {model}"
        elif stage == "model_runtime_views" and model:
            message = f"querying runtime views: {model}"
        elif stage == "recommended_tests" and module:
            message = f"collecting test recommendations: {module}"
        elif stage == "render" and module:
            message = f"rendering arc42 markdown: {module}"
        elif stage == "writing":
            message = f"writing: {data.get('path', '')}".rstrip()
        elif stage == "writing_metadata":
            message = f"writing metadata: {data.get('path', '')}".rstrip()

        if message:
            typer.echo(f"[oduit agent technical-doc] {message}", err=True)

    return progress


def agent_technical_doc_command(
    ctx: typer.Context,
    *,
    target: str,
    template: str,
    allow_mutation: bool,
    dry_run: bool,
    force: bool,
    include_markdown: bool,
    database: str | None,
    timeout: float,
    source_only: bool,
    progress: bool,
    include_arch: bool,
    attributes: str | None,
    types: str | None,
    max_models: int | None,
    max_fields_per_model: int | None,
    path_prefix: str | None,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    odoo_operations_cls: Any,
    module_not_found_error_cls: Any,
    safe_read_only: str,
    controlled_source_mutation: str,
) -> None:
    """Create or preview addon-local arc42 technical documentation."""

    result_type = "technical_documentation"
    preview_operation = "technical_doc_preview"
    write_operation = "write_technical_doc"
    global_config = resolve_agent_global_config_fn(ctx, preview_operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(
            preview_operation, result_type, "No environment configuration available"
        )
    assert global_config.env_config is not None

    try:
        dry_run_source = ctx.get_parameter_source("dry_run")
    except Exception:
        dry_run_source = ParameterSource.DEFAULT

    effective_dry_run = dry_run
    if not allow_mutation:
        effective_dry_run = True
    elif dry_run_source is ParameterSource.DEFAULT:
        effective_dry_run = False

    field_attributes = (
        sorted({item.strip() for item in attributes.split(",") if item.strip()})
        if attributes
        else []
    )
    view_types = (
        sorted({item.strip() for item in types.split(",") if item.strip()})
        if types
        else []
    )
    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
        explicit_base=path_prefix,
    )
    effective_path_prefix = path_context.base_dir.as_posix()
    progress_cb = _agent_technical_doc_progress(progress)

    ops = odoo_operations_cls(global_config.env_config, verbose=False)
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
            progress=progress_cb,
        )
    except module_not_found_error_cls as exc:
        agent_fail_fn(
            preview_operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"target": target},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
    except FileNotFoundError as exc:
        agent_fail_fn(
            preview_operation,
            result_type,
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
    except ValueError as exc:
        agent_fail_fn(
            preview_operation,
            result_type,
            str(exc),
            error_type="ValidationError",
            details={"target": target, "template": template},
        )

    assert bundle.target is not None
    output_path = resolve_technical_doc_output_path(
        bundle.target,
        addon_root=getattr(bundle, "source_addon_root", None),
        output=None,
        output_in_addon=True,
    )
    assert output_path is not None
    metadata_path = output_path.with_name(TECHNICAL_DOC_METADATA_FILENAME)

    payload_data = {
        "module": bundle.module,
        "addon_root": bundle.addon_root,
        "template": bundle.template,
        "would_write": path_context.relative(output_path),
        "would_write_metadata": path_context.relative(metadata_path),
        "section_count": len(_section_titles(bundle)),
        "sections": _section_titles(bundle),
        "preview": bundle.markdown[:500],
        "evidence_counts": _evidence_counts(bundle),
    }
    if include_markdown:
        payload_data["markdown"] = bundle.markdown

    if effective_dry_run:
        payload = agent_payload_fn(
            preview_operation,
            result_type,
            payload_data,
            warnings=list(bundle.warnings),
            remediation=sorted(
                dict.fromkeys(
                    list(bundle.remediation)
                    + [
                        (
                            "Retry with `--allow-mutation` to write"
                            " the generated documentation."
                        )
                    ]
                )
            ),
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    if bundle.target.target_kind == "module" and bundle.target.ambiguous:
        agent_fail_fn(
            write_operation,
            result_type,
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
            read_only=False,
            safety_level=controlled_source_mutation,
        )

    agent_require_mutation_fn(
        allow_mutation,
        write_operation,
        result_type,
        "technical documentation write",
        controlled_source_mutation,
    )

    existed_before = output_path.exists()
    if existed_before and not force:
        agent_fail_fn(
            write_operation,
            result_type,
            f"Output file already exists: {output_path}",
            error_type="FileExistsError",
            details={"output_path": output_path.as_posix()},
            remediation=[
                "Retry with `--force` to overwrite the existing file.",
            ],
            read_only=False,
            safety_level=controlled_source_mutation,
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    previous_metadata, metadata_warnings = load_technical_documentation_metadata(
        metadata_path
    )
    bundle.generated_at = utc_now_iso()
    bundle.output_path = f"docs/{TECHNICAL_DOC_FILENAME}"
    bundle.metadata_path = f"docs/{TECHNICAL_DOC_METADATA_FILENAME}"
    bundle.markdown = render_arc42_addon_markdown(bundle)
    if progress_cb is not None:
        progress_cb("writing", {"path": path_context.relative(output_path)})
    output_path.write_text(bundle.markdown, encoding="utf-8")
    metadata = build_technical_documentation_metadata(
        bundle=bundle,
        doc_path=output_path,
        metadata_path=metadata_path,
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
    if progress_cb is not None:
        progress_cb("writing_metadata", {"path": path_context.relative(metadata_path)})
    write_technical_documentation_metadata(metadata, metadata_path)
    status = inspect_technical_documentation_status(
        addon_root=bundle.source_addon_root or bundle.addon_root,
        module=bundle.module,
        path_base_dir=path_context.base_dir,
    )
    write_payload = {
        "module": bundle.module,
        "addon_root": bundle.addon_root,
        "output_path": path_context.relative(output_path),
        "metadata_path": path_context.relative(metadata_path),
        "template": bundle.template,
        "created": not existed_before,
        "overwritten": existed_before,
        "created_at": metadata.created_at,
        "last_generated_at": metadata.last_generated_at,
        "generation_count": metadata.generation_count,
        "status": status.status,
        "document_edited_since_last_generation": (
            status.document_edited_since_last_generation
        ),
        "source_changed_since_last_generation": (
            status.source_changed_since_last_generation
        ),
        "section_count": len(_section_titles(bundle)),
        "evidence_counts": _evidence_counts(bundle),
    }
    if include_markdown:
        write_payload["markdown"] = bundle.markdown
    payload = agent_payload_fn(
        write_operation,
        result_type,
        write_payload,
        warnings=list(bundle.warnings) + metadata_warnings + list(status.warnings),
        remediation=list(bundle.remediation) + list(status.remediation),
        read_only=False,
        safety_level=controlled_source_mutation,
    )
    agent_emit_payload_fn(payload)


def agent_technical_doc_status_command(
    ctx: typer.Context,
    *,
    target: str | None,
    only_stale: bool,
    select_dir: str | None,
    include_files: bool,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Return durable technical-documentation status for one addon or many."""

    operation = "technical_doc_status"
    result_type = "technical_documentation_status"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    if target is not None and select_dir is not None:
        agent_fail_fn(
            operation,
            result_type,
            "--select-dir cannot be used with TARGET",
            error_type="ValidationError",
            details={"target": target, "select_dir": select_dir},
        )

    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
    )
    if target is not None:
        try:
            resolved_target = resolve_addon_documentation_target(
                global_config.env_config,
                target,
                path_base_dir=path_context.base_dir,
            )
        except FileNotFoundError as exc:
            agent_fail_fn(
                operation,
                result_type,
                str(exc),
                error_type="NotFoundError",
                details={"target": target},
                remediation=[
                    "Use a valid addon name or a path that resolves to an addon root."
                ],
            )
        if resolved_target.target_kind == "module" and resolved_target.ambiguous:
            agent_fail_fn(
                operation,
                result_type,
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
        statuses = [
            inspect_technical_documentation_status(
                addon_root=resolved_target.addon_root,
                module=resolved_target.module,
                path_base_dir=path_context.base_dir,
            )
        ]
    else:
        statuses = inspect_all_technical_documentation_statuses(
            addons_path=str(global_config.env_config["addons_path"]),
            select_dir=select_dir,
            path_base_dir=path_context.base_dir,
        )
        if select_dir is not None and not statuses:
            agent_fail_fn(
                operation,
                result_type,
                f"No addons found in directory '{select_dir}'",
                error_type="NotFoundError",
                details={"select_dir": select_dir},
            )

    if only_stale:
        statuses = [status for status in statuses if status.status != "up_to_date"]

    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "statuses": [status.to_dict() for status in statuses],
            "include_files": include_files,
        },
        warnings=[],
        remediation=[],
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)


def agent_technical_doc_check_command(
    ctx: typer.Context,
    *,
    target: str,
    include_files: bool,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Return freshness information for one technical-documentation target."""

    operation = "technical_doc_check"
    result_type = "technical_documentation_status"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    path_context = resolve_project_path_context(config_path=global_config.config_path)
    try:
        resolved_target = resolve_addon_documentation_target(
            global_config.env_config,
            target,
            path_base_dir=path_context.base_dir,
        )
    except FileNotFoundError as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="NotFoundError",
            details={"target": target},
            remediation=[
                "Use a valid addon name or a path that resolves to an addon root."
            ],
        )

    status = inspect_technical_documentation_status(
        addon_root=resolved_target.addon_root,
        module=resolved_target.module,
        path_base_dir=path_context.base_dir,
    )
    if resolved_target.target_kind == "module" and resolved_target.ambiguous:
        agent_fail_fn(
            operation,
            result_type,
            "Refusing to inspect an ambiguous module-name resolution.",
            error_type="AmbiguousTargetError",
            details={
                "target": target,
                "candidate_addon_roots": resolved_target.candidate_addon_roots,
            },
            remediation=["Use an explicit addon path such as `@addons/has_base`."],
        )
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "status": status.to_dict(),
            "include_files": include_files,
        },
        warnings=list(status.warnings),
        remediation=list(status.remediation),
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)


def agent_technical_doc_next_command(
    ctx: typer.Context,
    *,
    path: str | None,
    include_files: bool,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Return the next addon that needs technical-documentation work."""

    operation = "technical_doc_next"
    result_type = "technical_documentation_next"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    path_context = resolve_project_path_context(config_path=global_config.config_path)
    statuses = inspect_all_technical_documentation_statuses(
        addons_path=str(global_config.env_config["addons_path"]),
        select_dir=path,
        path_base_dir=path_context.base_dir,
    )
    if path is not None and not statuses:
        agent_fail_fn(
            operation,
            result_type,
            f"No addons found in directory '{path}'",
            error_type="NotFoundError",
            details={"path": path},
        )

    next_status = select_next_technical_doc_status(statuses)
    stale_count = sum(1 for status in statuses if technical_doc_needs_action(status))
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "next_module": next_status.module if next_status is not None else None,
            "status": next_status.to_dict() if next_status is not None else None,
            "scanned_count": len(statuses),
            "stale_count": stale_count,
            "include_files": include_files,
        },
        warnings=[],
        remediation=[],
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)
