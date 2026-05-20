"""Agent command implementations for technical documentation workflows."""

from __future__ import annotations

from typing import Any

import typer
from click.core import ParameterSource

from ...technical_documentation import resolve_technical_doc_output_path


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
            path_prefix=path_prefix,
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
        output=None,
        output_in_addon=True,
    )
    assert output_path is not None

    payload_data = {
        "module": bundle.module,
        "addon_root": bundle.addon_root,
        "template": bundle.template,
        "would_write": output_path.as_posix(),
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
    output_path.write_text(bundle.markdown, encoding="utf-8")
    write_payload = {
        "module": bundle.module,
        "addon_root": bundle.addon_root,
        "output_path": output_path.as_posix(),
        "template": bundle.template,
        "created": not existed_before,
        "overwritten": existed_before,
        "section_count": len(_section_titles(bundle)),
        "evidence_counts": _evidence_counts(bundle),
    }
    if include_markdown:
        write_payload["markdown"] = bundle.markdown
    payload = agent_payload_fn(
        write_operation,
        result_type,
        write_payload,
        warnings=list(bundle.warnings),
        remediation=list(bundle.remediation),
        read_only=False,
        safety_level=controlled_source_mutation,
    )
    agent_emit_payload_fn(payload)
