"""Agent command implementations for technical documentation workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from click.core import ParameterSource

from ...arc42_renderer import (
    inspect_generated_markdown_quality,
    render_arc42_addon_markdown,
)
from ...documentation_policy import (
    DocumentationDirectoryPolicy,
    DocumentationTargetNotAllowedError,
    load_documentation_directory_policy,
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


def _normalize_progress_level(progress_level: str) -> str:
    value = (progress_level or "compact").strip().lower()
    if value not in {"compact", "model", "debug"}:
        raise typer.BadParameter(
            "--progress-level must be one of: compact, model, debug"
        )
    return value


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


def _progress_stage_visible(stage: str, *, progress_level: str) -> bool:
    if progress_level == "compact":
        return stage in {
            "resolve_target",
            "technical_inventory",
            "model_inventory",
            "runtime_metadata_batch",
            "render",
            "writing",
            "writing_metadata",
        }
    if progress_level == "model":
        return stage not in {
            "inspect_addon",
            "dependency_graph",
            "model_source",
            "model_runtime_fields",
            "model_runtime_views",
            "model_runtime_fields_cached",
            "model_runtime_views_cached",
            "recommended_tests",
        }
    return True


def _agent_progress_message(
    stage: str, data: dict[str, Any], *, progress_level: str
) -> str | None:
    module = data.get("module")
    model = data.get("model")
    index = data.get("index")
    total = data.get("total")

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


def _agent_technical_doc_progress(enabled: bool, *, progress_level: str) -> Any:
    if not enabled:
        return None

    def progress(stage: str, data: dict[str, Any]) -> None:
        if not _progress_stage_visible(stage, progress_level=progress_level):
            return
        message = _agent_progress_message(
            stage,
            data,
            progress_level=progress_level,
        )

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
    progress_level: str,
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
    documentation_policy = load_documentation_directory_policy(
        global_config.env_config,
        path_base_dir=path_context.base_dir,
    )
    effective_path_prefix = path_context.base_dir.as_posix()
    normalized_progress_level = _normalize_progress_level(progress_level)
    progress_cb = _agent_technical_doc_progress(
        progress, progress_level=normalized_progress_level
    )

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
            documentation_policy=documentation_policy,
            progress=progress_cb,
            progress_level=normalized_progress_level,
            render_markdown=effective_dry_run,
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
    except DocumentationTargetNotAllowedError as exc:
        agent_fail_fn(
            preview_operation,
            result_type,
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
        "quality": inspect_generated_markdown_quality(bundle.markdown),
    }
    preview_quality = payload_data["quality"]
    if include_markdown:
        payload_data["markdown"] = bundle.markdown

    if effective_dry_run:
        payload = agent_payload_fn(
            preview_operation,
            result_type,
            payload_data,
            warnings=list(bundle.warnings) + list(preview_quality.get("warnings", [])),
            remediation=sorted(
                dict.fromkeys(
                    list(bundle.remediation)
                    + [
                        (
                            "Address reported markdown quality warnings before "
                            "considering the document final."
                        ),
                        (
                            "Retry with `--allow-mutation` to write"
                            " the generated documentation."
                        ),
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
    quality = inspect_generated_markdown_quality(bundle.markdown)
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
    metadata.warnings = sorted(
        dict.fromkeys(list(metadata.warnings) + list(quality.get("warnings", [])))
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
        "quality": quality,
        "metadata_summary": _metadata_summary(status),
    }
    if include_markdown:
        write_payload["markdown"] = bundle.markdown
    payload = agent_payload_fn(
        write_operation,
        result_type,
        write_payload,
        warnings=list(bundle.warnings)
        + metadata_warnings
        + list(status.warnings)
        + list(quality.get("warnings", [])),
        remediation=list(bundle.remediation) + list(status.remediation),
        read_only=False,
        safety_level=controlled_source_mutation,
    )
    agent_emit_payload_fn(payload)


def agent_technical_evidence_command(
    ctx: typer.Context,
    *,
    target: str,
    allow_mutation: bool,
    dry_run: bool,
    force: bool,
    include_markdown: bool,
    database: str | None,
    timeout: float,
    source_only: bool,
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
    safe_read_only: str,
    controlled_source_mutation: str,
) -> None:
    """Create or write split deterministic technical evidence."""

    result_type = "technical_evidence"
    preview_operation = "technical_evidence_preview"
    write_operation = "write_technical_evidence"
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
    documentation_policy = load_documentation_directory_policy(
        global_config.env_config,
        path_base_dir=path_context.base_dir,
    )
    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    if effective_dry_run:
        try:
            bundle = ops.build_technical_evidence(
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
            )
        except Exception as exc:
            agent_fail_fn(
                preview_operation, result_type, str(exc), error_type=type(exc).__name__
            )
        addon_root = Path(bundle.source_addon_root or bundle.addon_root).resolve(
            strict=False
        )
        evidence_path, metadata_path = technical_evidence_paths(addon_root)
        data = {
            "module": bundle.module,
            "addon_root": bundle.addon_root,
            "would_write": path_context.relative(evidence_path),
            "would_write_metadata": path_context.relative(metadata_path),
            "preview": bundle.markdown[:500],
        }
        if include_markdown:
            data["markdown"] = bundle.markdown
        payload = agent_payload_fn(
            preview_operation,
            result_type,
            data,
            warnings=list(bundle.warnings),
            remediation=list(bundle.remediation)
            + ["Retry with --allow-mutation to write evidence files."],
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    agent_require_mutation_fn(
        allow_mutation,
        write_operation,
        result_type,
        "technical evidence write",
        controlled_source_mutation,
    )
    try:
        data = ops.write_technical_evidence(
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
    except Exception as exc:
        agent_fail_fn(
            write_operation,
            result_type,
            str(exc),
            error_type=type(exc).__name__,
            read_only=False,
            safety_level=controlled_source_mutation,
        )
    payload = agent_payload_fn(
        write_operation,
        result_type,
        {
            **data,
            "evidence_path": path_context.relative(Path(data["evidence_path"])),
            "metadata_path": path_context.relative(Path(data["metadata_path"])),
        },
        warnings=list(data.get("warnings", [])),
        remediation=list(data.get("remediation", [])),
        read_only=False,
        safety_level=controlled_source_mutation,
    )
    agent_emit_payload_fn(payload)


def agent_technical_report_command(
    ctx: typer.Context,
    *,
    target: str,
    allow_mutation: bool,
    dry_run: bool,
    force: bool,
    include_markdown: bool,
    generate_evidence: bool,
    database: str | None,
    timeout: float,
    source_only: bool,
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
    safe_read_only: str,
    controlled_source_mutation: str,
) -> None:
    """Create or write split LLM/human report seed."""

    result_type = "technical_documentation"
    preview_operation = "technical_report_preview"
    write_operation = "write_technical_report"
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
    documentation_policy = load_documentation_directory_policy(
        global_config.env_config,
        path_base_dir=path_context.base_dir,
    )
    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    if not effective_dry_run:
        agent_require_mutation_fn(
            allow_mutation,
            write_operation,
            result_type,
            "technical report write",
            controlled_source_mutation,
        )
    try:
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
            generate_evidence_if_missing=generate_evidence or effective_dry_run,
        )
    except FileNotFoundError:
        agent_fail_fn(
            preview_operation,
            result_type,
            "Technical evidence is missing.",
            error_type="MissingEvidenceError",
            remediation=[
                f"Run oduit docs technical-evidence @addons/{target}"
                " --output-in-addon first."
            ],
            read_only=effective_dry_run,
            safety_level=safe_read_only
            if effective_dry_run
            else controlled_source_mutation,
        )
    except Exception as exc:
        agent_fail_fn(
            preview_operation,
            result_type,
            str(exc),
            error_type=type(exc).__name__,
            read_only=effective_dry_run,
            safety_level=safe_read_only
            if effective_dry_run
            else controlled_source_mutation,
        )

    addon_root = Path(bundle.source_addon_root or bundle.addon_root).resolve(
        strict=False
    )
    report_path, metadata_path = technical_doc_paths(addon_root)
    data = {
        "module": bundle.module,
        "addon_root": bundle.addon_root,
        "would_write": path_context.relative(report_path),
        "would_write_metadata": path_context.relative(metadata_path),
        "preview": bundle.markdown[:500],
    }
    if include_markdown:
        data["markdown"] = bundle.markdown
    if effective_dry_run:
        payload = agent_payload_fn(
            preview_operation,
            result_type,
            data,
            warnings=list(bundle.warnings),
            remediation=list(bundle.remediation)
            + ["Retry with --allow-mutation to write report seed."],
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    if report_path.exists() and not force:
        agent_fail_fn(
            write_operation,
            result_type,
            f"Output file already exists: {report_path}",
            error_type="FileExistsError",
            remediation=["Retry with --force to overwrite the report."],
            read_only=False,
            safety_level=controlled_source_mutation,
        )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    bundle.generated_at = utc_now_iso()
    report_path.write_text(bundle.markdown, encoding="utf-8")
    previous_metadata, warnings = load_technical_documentation_metadata(metadata_path)
    metadata = build_technical_documentation_metadata(
        bundle=bundle,
        doc_path=report_path,
        metadata_path=metadata_path,
        generation_options={},
        previous_metadata=previous_metadata,
        path_base_dir=path_context.base_dir,
        source_addon_root=addon_root,
    )
    write_technical_documentation_metadata(metadata, metadata_path)
    payload = agent_payload_fn(
        write_operation,
        result_type,
        {
            "module": bundle.module,
            "addon_root": bundle.addon_root,
            "report_path": path_context.relative(report_path),
            "metadata_path": path_context.relative(metadata_path),
        },
        warnings=warnings + list(bundle.warnings),
        remediation=list(bundle.remediation),
        read_only=False,
        safety_level=controlled_source_mutation,
    )
    agent_emit_payload_fn(payload)


def agent_technical_doc_diff_command(
    ctx: typer.Context,
    *,
    target: str,
    include_diff: bool,
    significant_only: bool,
    path_prefix: str | None,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    odoo_operations_cls: Any,
    safe_read_only: str,
) -> None:
    """Read-only technical evidence/report diff command."""

    operation = "technical_doc_diff"
    result_type = "technical_evidence_diff"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None
    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
        explicit_base=path_prefix,
    )
    documentation_policy = load_documentation_directory_policy(
        global_config.env_config,
        path_base_dir=path_context.base_dir,
    )
    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    try:
        data = ops.diff_technical_report_evidence(
            target,
            include_diff=include_diff,
            significant_only=significant_only,
            path_base_dir=path_context.base_dir.as_posix(),
            documentation_policy=documentation_policy,
        )
    except Exception as exc:
        agent_fail_fn(operation, result_type, str(exc), error_type=type(exc).__name__)
    for key in ("report_path", "evidence_path", "evidence_metadata_path"):
        if key in data:
            data[key] = path_context.relative(Path(data[key]))
    payload = agent_payload_fn(
        operation,
        result_type,
        data,
        warnings=list(data.get("warnings", [])),
        remediation=list(data.get("remediation", [])),
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)


def agent_technical_doc_refresh_command(
    ctx: typer.Context,
    *,
    target: str,
    allow_mutation: bool,
    dry_run: bool,
    force_edited_blocks: bool,
    add_missing_blocks: bool,
    include_diff: bool,
    source_only: bool | None,
    database: str | None,
    timeout: float,
    progress: bool,
    progress_level: str,
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
    controlled_source_mutation: str,
    safe_read_only: str,
) -> None:
    """Refresh managed generated blocks in addon-local arc42 documentation."""

    result_type = "technical_documentation_refresh"
    preview_operation = "technical_doc_refresh_preview"
    write_operation = "refresh_technical_doc"
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

    normalized_progress_level = _normalize_progress_level(progress_level)
    progress_cb = _agent_technical_doc_progress(
        progress, progress_level=normalized_progress_level
    )
    path_context = resolve_project_path_context(
        config_path=global_config.config_path,
        explicit_base=path_prefix,
    )
    documentation_policy = load_documentation_directory_policy(
        global_config.env_config,
        path_base_dir=path_context.base_dir,
    )
    ops = odoo_operations_cls(global_config.env_config, verbose=False)

    if not effective_dry_run:
        agent_require_mutation_fn(
            allow_mutation,
            write_operation,
            result_type,
            "technical documentation refresh",
            controlled_source_mutation,
        )

    try:
        refresh_result = ops.refresh_technical_documentation(
            target,
            odoo_series=global_config.odoo_series,
            database=database,
            timeout=timeout,
            source_only=source_only,
            field_attributes=(
                sorted({item.strip() for item in attributes.split(",") if item.strip()})
                if attributes
                else None
            ),
            view_types=(
                sorted({item.strip() for item in types.split(",") if item.strip()})
                if types
                else None
            ),
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_context.base_dir.as_posix(),
            path_base_dir=path_context.base_dir.as_posix(),
            documentation_policy=documentation_policy,
            overwrite_edited=force_edited_blocks,
            add_missing=add_missing_blocks,
            write=not effective_dry_run,
        )
    except FileNotFoundError as exc:
        agent_fail_fn(
            preview_operation,
            result_type,
            str(exc),
            error_type="NotFoundError",
            details={"target": target},
        )
    except DocumentationTargetNotAllowedError as exc:
        agent_fail_fn(
            preview_operation,
            result_type,
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
    except ValueError as exc:
        agent_fail_fn(
            preview_operation,
            result_type,
            str(exc),
            error_type="ValidationError",
            details={"target": target},
            read_only=effective_dry_run,
            safety_level=safe_read_only
            if effective_dry_run
            else controlled_source_mutation,
        )

    payload_data = dict(refresh_result)
    payload_data["doc_path"] = path_context.relative(Path(payload_data["doc_path"]))
    payload_data["metadata_path"] = path_context.relative(
        Path(payload_data["metadata_path"])
    )
    if include_diff:
        payload_data["diff"] = None
    payload = agent_payload_fn(
        preview_operation if effective_dry_run else write_operation,
        result_type,
        payload_data,
        warnings=list(refresh_result.get("warnings", [])),
        remediation=list(refresh_result.get("errors", [])),
        read_only=effective_dry_run,
        safety_level=safe_read_only
        if effective_dry_run
        else controlled_source_mutation,
    )
    if progress_cb is not None:
        progress_cb(
            "render",
            {"module": payload_data.get("module"), "template": "arc42-refresh"},
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
    documentation_policy = load_documentation_directory_policy(
        global_config.env_config,
        path_base_dir=path_context.base_dir,
    )
    if _selected_path_is_outside_policy(
        select_dir,
        path_context=path_context,
        documentation_policy=documentation_policy,
    ):
        agent_fail_fn(
            operation,
            result_type,
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
    if target is not None:
        try:
            resolved_target = resolve_addon_documentation_target(
                global_config.env_config,
                target,
                path_base_dir=path_context.base_dir,
                documentation_policy=documentation_policy,
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
        except DocumentationTargetNotAllowedError as exc:
            agent_fail_fn(
                operation,
                result_type,
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
            documentation_policy=documentation_policy,
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
            "statuses": [
                _status_to_payload_dict(status, include_files=include_files)
                for status in statuses
            ],
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
    documentation_policy = load_documentation_directory_policy(
        global_config.env_config,
        path_base_dir=path_context.base_dir,
    )
    try:
        resolved_target = resolve_addon_documentation_target(
            global_config.env_config,
            target,
            path_base_dir=path_context.base_dir,
            documentation_policy=documentation_policy,
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
    except DocumentationTargetNotAllowedError as exc:
        agent_fail_fn(
            operation,
            result_type,
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
            "status": _status_to_payload_dict(status, include_files=include_files),
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
    documentation_policy = load_documentation_directory_policy(
        global_config.env_config,
        path_base_dir=path_context.base_dir,
    )
    if _selected_path_is_outside_policy(
        path,
        path_context=path_context,
        documentation_policy=documentation_policy,
    ):
        agent_fail_fn(
            operation,
            result_type,
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
    statuses = inspect_all_technical_documentation_statuses(
        addons_path=str(global_config.env_config["addons_path"]),
        select_dir=path,
        path_base_dir=path_context.base_dir,
        documentation_policy=documentation_policy,
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
            "status": (
                _status_to_payload_dict(next_status, include_files=include_files)
                if next_status is not None
                else None
            ),
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


def agent_technical_doc_accept_command(
    ctx: typer.Context,
    *,
    target: str,
    allow_mutation: bool,
    force: bool,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    controlled_source_mutation: str,
) -> None:
    """Accept a manually reviewed technical document snapshot."""

    operation = "technical_doc_accept"
    result_type = "technical_documentation"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    agent_require_mutation_fn(
        allow_mutation,
        operation,
        result_type,
        "technical documentation acceptance",
        controlled_source_mutation,
    )
    path_context = resolve_project_path_context(config_path=global_config.config_path)
    documentation_policy = load_documentation_directory_policy(
        global_config.env_config,
        path_base_dir=path_context.base_dir,
    )
    try:
        resolved_target = resolve_addon_documentation_target(
            global_config.env_config,
            target,
            path_base_dir=path_context.base_dir,
            documentation_policy=documentation_policy,
        )
    except FileNotFoundError as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="NotFoundError",
            details={"target": target},
        )
    except DocumentationTargetNotAllowedError as exc:
        agent_fail_fn(
            operation,
            result_type,
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
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ValidationError",
            details={"target": target, "force": force},
            read_only=False,
            safety_level=controlled_source_mutation,
        )
    write_technical_documentation_metadata(metadata, metadata_path)
    status = inspect_technical_documentation_status(
        addon_root=resolved_target.addon_root,
        module=resolved_target.module,
        path_base_dir=path_context.base_dir,
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "module": resolved_target.module,
            "doc_path": path_context.relative(doc_path),
            "metadata_path": path_context.relative(metadata_path),
            "reviewed_at": metadata.reviewed_at,
            "reviewed_by": metadata.reviewed_by,
            "review_note": metadata.review_note,
            "generation_count": metadata.generation_count,
            "status": _status_to_payload_dict(status, include_files=False),
        },
        warnings=list(status.warnings),
        remediation=list(status.remediation),
        read_only=False,
        safety_level=controlled_source_mutation,
    )
    agent_emit_payload_fn(payload)
