"""Mutation-oriented agent commands."""

from pathlib import Path
from typing import Any

import typer

from ...builders import odoo_series_major
from ...exceptions import ConfigError
from ..commands.i18n import (
    _compat_export_output_path,
    _normalize_series_label,
    _resolve_i18n_series,
    _split_csv_values,
    _validate_export_request,
    _validate_import_request,
    _validate_load_request,
)


def _config_flag_enabled(value: Any) -> bool:
    """Normalize boolean-like config values from agent config dictionaries."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _require_uninstall_confirmation(
    *,
    allow_uninstall: bool,
    operation: str,
    result_type: str,
    agent_fail_fn: Any,
    controlled_runtime_mutation: str,
) -> None:
    """Enforce the extra uninstall confirmation gate."""
    if allow_uninstall:
        return
    agent_fail_fn(
        operation,
        result_type,
        "module uninstall requires --allow-uninstall",
        error_type="ConfirmationRequired",
        remediation=[
            "Retry with both `--allow-mutation` and `--allow-uninstall` after "
            "reviewing the dry-run payload.",
        ],
        read_only=False,
        safety_level=controlled_runtime_mutation,
    )


def _export_requires_source_mutation(
    *,
    output: str | None,
    resolved_series: Any,
) -> bool:
    series_major = odoo_series_major(resolved_series)
    assert series_major is not None
    if output == "-":
        return False
    return output is not None or series_major >= 19


def _emit_agent_i18n_failure(
    *,
    operation: str,
    result_type: str,
    message: str,
    agent_fail_fn: Any,
    details: dict[str, Any] | None = None,
    remediation: list[str] | None = None,
    read_only: bool = True,
    safety_level: str,
    error_type: str = "ConfigError",
) -> None:
    agent_fail_fn(
        operation,
        result_type,
        message,
        error_type=error_type,
        details=details,
        remediation=remediation or [],
        read_only=read_only,
        safety_level=safety_level,
    )


def agent_install_module_command(
    ctx: typer.Context,
    *,
    module: str,
    allow_mutation: bool,
    dry_run: bool,
    without_demo: str | None,
    with_demo: bool,
    language: str | None,
    max_cron_threads: int | None,
    compact: bool,
    log_level: Any,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    agent_require_runtime_db_mutation_fn: Any,
    output_result_to_json_fn: Any,
    module_not_found_error_cls: Any,
    safe_read_only: str,
    controlled_runtime_mutation: str,
) -> None:
    """Install a module with an explicit mutation gate."""
    operation = "install_module"
    result_type = "module_installation"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    assert global_config.env_config is not None

    if dry_run:
        try:
            inspection = ops.inspect_addon(
                module, odoo_series=global_config.odoo_series
            )
        except module_not_found_error_cls as exc:
            agent_fail_fn(
                operation,
                result_type,
                str(exc),
                error_type="ModuleNotFoundError",
                details={"module": module},
            )
        payload = agent_payload_fn(
            operation,
            "addon_inspection",
            {
                **inspection.to_dict(),
                "dry_run": True,
                "planned_action": "install",
            },
            warnings=list(inspection.warnings),
            remediation=list(inspection.remediation),
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    agent_require_runtime_db_mutation_fn(
        global_config.env_config,
        allow_mutation=allow_mutation,
        operation=operation,
        result_type=result_type,
        action="module install",
        safety_level=controlled_runtime_mutation,
    )
    result = ops.install_module(
        module,
        no_http=global_config.no_http,
        suppress_output=True,
        compact=compact,
        max_cron_threads=max_cron_threads,
        without_demo=without_demo or False,
        language=language,
        with_demo=with_demo,
        log_level=log_level.value if log_level else None,
    )
    result["operation"] = operation
    payload = output_result_to_json_fn(
        result,
        additional_fields={
            "module": module,
            "without_demo": without_demo,
            "with_demo": with_demo,
            "language": language,
            "compact": compact,
            "read_only": False,
            "safety_level": controlled_runtime_mutation,
            "remediation": (
                ["Inspect unmet dependencies and retry after fixing them."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


def agent_uninstall_module_command(
    ctx: typer.Context,
    *,
    module: str,
    allow_mutation: bool,
    allow_uninstall: bool,
    dry_run: bool,
    compact: bool,
    log_level: Any,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    agent_require_runtime_db_mutation_fn: Any,
    output_result_to_json_fn: Any,
    controlled_runtime_mutation: str,
    safe_read_only: str,
) -> None:
    """Uninstall a module with explicit mutation and destructive-action gates."""
    operation = "uninstall_module"
    result_type = "module_uninstallation"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    assert global_config.env_config is not None
    config_allows_uninstall = _config_flag_enabled(
        global_config.env_config.get("allow_uninstall", False)
    )

    if dry_run:
        state_result = ops.get_addon_install_state(module)
        if not state_result.success:
            agent_fail_fn(
                operation,
                result_type,
                state_result.error or "Failed to query module install state",
                error_type=state_result.error_type or "QueryError",
                details={"module": module},
                remediation=[
                    "Verify database access and retry the uninstall dry run.",
                ],
            )

        dependents_result = ops.list_installed_dependents(
            module,
            database=state_result.database,
        )
        if not dependents_result.success:
            agent_fail_fn(
                operation,
                result_type,
                dependents_result.error or "Failed to query installed dependents",
                error_type=dependents_result.error_type or "QueryError",
                details={"module": module},
                remediation=[
                    "Verify database access and retry the uninstall dry run.",
                ],
            )

        dependent_modules = [addon.module for addon in dependents_result.addons]
        blocked_reasons: list[str] = []
        if not config_allows_uninstall:
            blocked_reasons.append("environment config does not allow uninstall")
        if not allow_uninstall:
            blocked_reasons.append("--allow-uninstall was not provided")
        if not state_result.record_found:
            blocked_reasons.append("module was not found in ir.module.module")
        elif not state_result.installed:
            blocked_reasons.append(
                f"module is not installed (state: {state_result.state})"
            )
        if dependent_modules:
            blocked_reasons.append(
                "installed dependents exist: " + ", ".join(dependent_modules)
            )

        payload = agent_payload_fn(
            operation,
            result_type,
            {
                "module": module,
                "planned_action": "uninstall",
                "config_allows_uninstall": config_allows_uninstall,
                "allow_uninstall_flag": allow_uninstall,
                "installed_state": {
                    "module": module,
                    "record_found": state_result.record_found,
                    "state": state_result.state,
                    "installed": state_result.installed,
                },
                "dependent_modules": dependent_modules,
                "blocked": bool(blocked_reasons),
                "blocked_reasons": blocked_reasons,
                "dry_run": True,
            },
            remediation=[
                "Retry with `--allow-mutation --allow-uninstall` once the blocked "
                "conditions are resolved."
            ],
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    agent_require_runtime_db_mutation_fn(
        global_config.env_config,
        allow_mutation=allow_mutation,
        operation=operation,
        result_type=result_type,
        action="module uninstall",
        safety_level=controlled_runtime_mutation,
    )
    _require_uninstall_confirmation(
        allow_uninstall=allow_uninstall,
        operation=operation,
        result_type=result_type,
        agent_fail_fn=agent_fail_fn,
        controlled_runtime_mutation=controlled_runtime_mutation,
    )
    if not config_allows_uninstall:
        agent_fail_fn(
            operation,
            result_type,
            "Uninstall is disabled in this environment. "
            "Set allow_uninstall=true in config.",
            error_type="ConfigError",
            details={"module": module},
            remediation=[
                "Enable `allow_uninstall = true` in the selected environment before "
                "retrying.",
            ],
            read_only=False,
            safety_level=controlled_runtime_mutation,
        )

    result = ops.uninstall_module(
        module,
        suppress_output=True,
        compact=compact,
        log_level=log_level.value if log_level else None,
        allow_uninstall=allow_uninstall,
    )
    payload = output_result_to_json_fn(
        result,
        additional_fields={
            "module": module,
            "read_only": False,
            "safety_level": controlled_runtime_mutation,
            "remediation": (
                [
                    "Review dependent modules and environment gates, then retry the "
                    "uninstall."
                ]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


def agent_update_module_command(
    ctx: typer.Context,
    *,
    module: str,
    allow_mutation: bool,
    dry_run: bool,
    without_demo: str | None,
    language: str | None,
    i18n_overwrite: bool,
    max_cron_threads: int | None,
    compact: bool,
    log_level: Any,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    agent_require_runtime_db_mutation_fn: Any,
    output_result_to_json_fn: Any,
    module_not_found_error_cls: Any,
    safe_read_only: str,
    controlled_runtime_mutation: str,
) -> None:
    """Update a module with an explicit mutation gate."""
    operation = "update_module"
    result_type = "module_update"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    assert global_config.env_config is not None

    if dry_run:
        try:
            plan = ops.plan_update(module, odoo_series=global_config.odoo_series)
        except module_not_found_error_cls as exc:
            agent_fail_fn(
                operation,
                result_type,
                str(exc),
                error_type="ModuleNotFoundError",
                details={"module": module},
            )
        payload = agent_payload_fn(
            operation,
            "update_plan",
            {
                **plan.to_dict(),
                "dry_run": True,
                "planned_action": "update",
            },
            warnings=list(plan.warnings),
            remediation=list(plan.remediation),
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    agent_require_runtime_db_mutation_fn(
        global_config.env_config,
        allow_mutation=allow_mutation,
        operation=operation,
        result_type=result_type,
        action="module update",
        safety_level=controlled_runtime_mutation,
    )
    result = ops.update_module(
        module,
        no_http=global_config.no_http,
        suppress_output=True,
        compact=compact,
        log_level=log_level.value if log_level else None,
        max_cron_threads=max_cron_threads,
        without_demo=without_demo or False,
        language=language,
        i18n_overwrite=i18n_overwrite,
    )
    result["operation"] = operation
    payload = output_result_to_json_fn(
        result,
        additional_fields={
            "module": module,
            "without_demo": without_demo,
            "language": language,
            "i18n_overwrite": i18n_overwrite,
            "compact": compact,
            "read_only": False,
            "safety_level": controlled_runtime_mutation,
            "remediation": (
                ["Inspect the update error and rerun targeted tests after fixing it."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


def agent_inspect_cron_command(
    ctx: typer.Context,
    *,
    xmlid: str,
    trigger: bool,
    allow_mutation: bool,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    agent_require_runtime_db_mutation_fn: Any,
    safe_read_only: str,
    controlled_runtime_mutation: str,
) -> None:
    """Inspect one cron job and optionally trigger it."""
    operation = "inspect_cron"
    result_type = "cron_inspection"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    assert global_config.env_config is not None

    if trigger:
        agent_require_runtime_db_mutation_fn(
            global_config.env_config,
            allow_mutation=allow_mutation,
            operation=operation,
            result_type=result_type,
            action="cron trigger",
            safety_level=controlled_runtime_mutation,
        )

    result = ops.inspect_cron(
        xmlid,
        trigger=trigger,
        database=database,
        timeout=timeout,
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        result,
        success=bool(result.get("success", False)),
        warnings=[item for item in result.get("warnings", []) if isinstance(item, str)],
        errors=[item for item in result.get("errors", []) if isinstance(item, dict)],
        remediation=[
            item for item in result.get("remediation", []) if isinstance(item, str)
        ],
        read_only=(
            result["read_only"]
            if isinstance(result.get("read_only"), bool)
            else not trigger
        ),
        safety_level=(
            result["safety_level"]
            if isinstance(result.get("safety_level"), str)
            and result.get("safety_level")
            else (controlled_runtime_mutation if trigger else safe_read_only)
        ),
        error=result.get("error"),
        error_type=result.get("error_type"),
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


def agent_create_addon_command(
    ctx: typer.Context,
    *,
    addon_name: str,
    allow_mutation: bool,
    dry_run: bool,
    path: str | None,
    template: Any,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    output_result_to_json_fn: Any,
    safe_read_only: str,
    controlled_source_mutation: str,
) -> None:
    """Create a new addon with an explicit mutation gate."""
    operation = "create_agent_addon"
    result_type = "addon_creation"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)

    if dry_run:
        payload = agent_payload_fn(
            operation,
            result_type,
            {
                "addon_name": addon_name,
                "path": path,
                "template": template.value,
                "dry_run": True,
            },
            remediation=[
                "Retry with `--allow-mutation` to run the scaffold command.",
            ],
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    agent_require_mutation_fn(
        allow_mutation,
        operation,
        result_type,
        "addon creation",
        controlled_source_mutation,
    )
    result = ops.create_addon(
        addon_name,
        destination=path,
        template=template.value,
        suppress_output=True,
    )
    result["operation"] = operation
    payload = output_result_to_json_fn(
        result,
        additional_fields={
            "path": path,
            "template": template.value,
            "read_only": False,
            "safety_level": controlled_source_mutation,
            "remediation": (
                ["Verify the target path and addon name, then retry the scaffold."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


def agent_export_lang_command(
    ctx: typer.Context,
    *,
    module: str,
    allow_mutation: bool,
    dry_run: bool,
    language: str | None,
    log_level: Any,
    resolve_agent_ops_fn: Any,
    require_agent_addons_path_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    output_result_to_json_fn: Any,
    module_manager_cls: Any,
    os_module: Any,
    safe_read_only: str,
    controlled_source_mutation: str,
) -> None:
    """Compatibility wrapper for exporting one module language file."""
    operation = "export_lang_module"
    result_type = "language_export"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None
    addons_path = require_agent_addons_path_fn(env_config, operation, result_type)
    language_value = language or env_config.get("language", "de_DE")
    if language_value is None:
        language_value = "de_DE"

    module_manager = module_manager_cls(addons_path)
    module_path = module_manager.find_module_path(module)
    if not module_path:
        _emit_agent_i18n_failure(
            operation=operation,
            result_type=result_type,
            message=f"Module '{module}' was not found in the configured addons paths.",
            agent_fail_fn=agent_fail_fn,
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
            error_type="ModuleNotFoundError",
            safety_level=safe_read_only if dry_run else controlled_source_mutation,
        )

    try:
        resolved_series = _resolve_i18n_series(
            global_config=global_config,
            env_config=env_config,
            module_manager_cls=module_manager_cls,
            build_odoo_operations_fn=lambda _: ops,
            allow_version_probe=not dry_run,
        )
        filename = str(_compat_export_output_path(module_path, language_value))
        validation = _validate_export_request(
            env_config=env_config,
            modules=[module],
            languages=[language_value],
            output=filename,
            resolved_series=resolved_series,
            log_level=log_level,
        )
    except ConfigError as exc:
        _emit_agent_i18n_failure(
            operation=operation,
            result_type=result_type,
            message=str(exc),
            agent_fail_fn=agent_fail_fn,
            remediation=[
                "Pass --odoo-series explicitly when series auto-detection "
                "is unavailable.",
            ],
            safety_level=safe_read_only if dry_run else controlled_source_mutation,
        )

    if dry_run:
        payload = agent_payload_fn(
            operation,
            result_type,
            {
                "module": module,
                "language": language_value,
                "filename": filename,
                "odoo_series": _normalize_series_label(resolved_series),
                "strategy": validation.strategy,
                "mutation_required": True,
                "dry_run": True,
            },
            remediation=[
                "Retry with `--allow-mutation` to export the translation file.",
            ],
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    agent_require_mutation_fn(
        allow_mutation,
        operation,
        result_type,
        "language export",
        controlled_source_mutation,
    )
    os_module.makedirs(os_module.path.dirname(filename), exist_ok=True)
    result = ops.export_module_language(
        module,
        filename,
        language_value,
        no_http=global_config.no_http,
        log_level=log_level.value if log_level else None,
        suppress_output=True,
        odoo_series=resolved_series,
    )
    result["operation"] = operation
    payload = output_result_to_json_fn(
        result,
        additional_fields={
            "module": module,
            "language": language_value,
            "filename": filename,
            "odoo_series": _normalize_series_label(resolved_series),
            "strategy": validation.strategy,
            "read_only": False,
            "safety_level": controlled_source_mutation,
            "remediation": (
                ["Inspect the export error and verify the module path and language."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


def agent_i18n_export_command(
    ctx: typer.Context,
    *,
    modules: list[str],
    languages: list[str] | None,
    output: str | None,
    allow_mutation: bool,
    dry_run: bool,
    log_level: Any,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    output_result_to_json_fn: Any,
    module_manager_cls: Any,
    safe_read_only: str,
    controlled_source_mutation: str,
) -> None:
    """Export translations through the agent-first i18n surface."""
    operation = "i18n_export"
    result_type = "i18n_export"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None

    normalized_modules = _split_csv_values(modules)
    normalized_languages = _split_csv_values(languages)

    try:
        resolved_series = _resolve_i18n_series(
            global_config=global_config,
            env_config=env_config,
            module_manager_cls=module_manager_cls,
            build_odoo_operations_fn=lambda _: ops,
            allow_version_probe=not dry_run,
        )
        validation = _validate_export_request(
            env_config=env_config,
            modules=normalized_modules,
            languages=normalized_languages,
            output=output,
            resolved_series=resolved_series,
            log_level=log_level,
        )
    except ConfigError as exc:
        _emit_agent_i18n_failure(
            operation=operation,
            result_type=result_type,
            message=str(exc),
            agent_fail_fn=agent_fail_fn,
            remediation=[
                "Pass --odoo-series explicitly when series auto-detection "
                "is unavailable.",
            ],
            safety_level=safe_read_only,
        )

    writes_source_files = _export_requires_source_mutation(
        output=output,
        resolved_series=resolved_series,
    )
    if dry_run:
        payload = agent_payload_fn(
            operation,
            result_type,
            {
                "modules": normalized_modules,
                "languages": normalized_languages or ["pot"],
                "output": output,
                "odoo_series": _normalize_series_label(resolved_series),
                "strategy": validation.strategy,
                "mutation_required": writes_source_files,
                "dry_run": True,
            },
            remediation=(
                ["Retry with `--allow-mutation` to export translation files."]
                if writes_source_files
                else []
            ),
            read_only=not writes_source_files,
            safety_level=(
                controlled_source_mutation if writes_source_files else safe_read_only
            ),
        )
        agent_emit_payload_fn(payload)
        return

    if writes_source_files:
        agent_require_mutation_fn(
            allow_mutation,
            operation,
            result_type,
            "translation export",
            controlled_source_mutation,
        )
        if output and output != "-":
            Path(output).expanduser().resolve().parent.mkdir(
                parents=True, exist_ok=True
            )

    result = ops.export_translations(
        modules=normalized_modules,
        languages=normalized_languages or None,
        output=output,
        odoo_series=resolved_series,
        log_level=log_level.value if log_level else None,
        suppress_output=True,
    )
    result["operation"] = operation
    payload = output_result_to_json_fn(
        result,
        additional_fields={
            "modules": normalized_modules,
            "languages": normalized_languages or ["pot"],
            "output": output,
            "odoo_series": _normalize_series_label(resolved_series),
            "strategy": validation.strategy,
            "read_only": not writes_source_files,
            "safety_level": (
                controlled_source_mutation if writes_source_files else safe_read_only
            ),
            "remediation": (
                [
                    "Inspect the export error and retry with an explicit "
                    "series or output path."
                ]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


def agent_i18n_import_command(
    ctx: typer.Context,
    *,
    files: list[str],
    language: str,
    overwrite: bool,
    allow_mutation: bool,
    dry_run: bool,
    log_level: Any,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_runtime_db_mutation_fn: Any,
    output_result_to_json_fn: Any,
    module_manager_cls: Any,
    safe_read_only: str,
    controlled_runtime_mutation: str,
) -> None:
    """Import translations through the agent-first i18n surface."""
    operation = "i18n_import"
    result_type = "i18n_import"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None

    try:
        resolved_series = _resolve_i18n_series(
            global_config=global_config,
            env_config=env_config,
            module_manager_cls=module_manager_cls,
            build_odoo_operations_fn=lambda _: ops,
            allow_version_probe=not dry_run,
        )
        _validate_import_request(
            env_config=env_config,
            files=files,
            language=language,
            overwrite=overwrite,
            resolved_series=resolved_series,
            log_level=log_level,
        )
    except ConfigError as exc:
        _emit_agent_i18n_failure(
            operation=operation,
            result_type=result_type,
            message=str(exc),
            agent_fail_fn=agent_fail_fn,
            remediation=[
                "Verify file paths, extensions, and Odoo series, then retry.",
            ],
            safety_level=safe_read_only if dry_run else controlled_runtime_mutation,
        )

    if dry_run:
        payload = agent_payload_fn(
            operation,
            result_type,
            {
                "files": files,
                "language": language,
                "overwrite": overwrite,
                "odoo_series": _normalize_series_label(resolved_series),
                "strategy": (
                    "native_i18n"
                    if (odoo_series_major(resolved_series) or 0) >= 19
                    else "legacy_flags"
                ),
                "mutation_required": True,
                "dry_run": True,
            },
            remediation=[
                "Retry with `--allow-mutation` to import the translation files.",
            ],
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    agent_require_runtime_db_mutation_fn(
        env_config,
        allow_mutation=allow_mutation,
        operation=operation,
        result_type=result_type,
        action="translation import",
        safety_level=controlled_runtime_mutation,
    )
    result = ops.import_translations(
        files=files,
        language=language,
        overwrite=overwrite,
        odoo_series=resolved_series,
        log_level=log_level.value if log_level else None,
        suppress_output=True,
    )
    result["operation"] = operation
    payload = output_result_to_json_fn(
        result,
        additional_fields={
            "files": files,
            "language": language,
            "overwrite": overwrite,
            "odoo_series": _normalize_series_label(resolved_series),
            "read_only": False,
            "safety_level": controlled_runtime_mutation,
            "remediation": (
                ["Inspect the failed import sub-results and retry after fixing them."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


def agent_i18n_loadlang_command(
    ctx: typer.Context,
    *,
    languages: list[str],
    allow_mutation: bool,
    dry_run: bool,
    log_level: Any,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_runtime_db_mutation_fn: Any,
    output_result_to_json_fn: Any,
    module_manager_cls: Any,
    safe_read_only: str,
    controlled_runtime_mutation: str,
) -> None:
    """Load languages through the agent-first i18n surface."""
    operation = "i18n_loadlang"
    result_type = "i18n_loadlang"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None
    normalized_languages = _split_csv_values(languages)

    try:
        resolved_series = _resolve_i18n_series(
            global_config=global_config,
            env_config=env_config,
            module_manager_cls=module_manager_cls,
            build_odoo_operations_fn=lambda _: ops,
            allow_version_probe=not dry_run,
        )
        _validate_load_request(
            env_config=env_config,
            languages=normalized_languages,
            resolved_series=resolved_series,
            log_level=log_level,
        )
    except ConfigError as exc:
        _emit_agent_i18n_failure(
            operation=operation,
            result_type=result_type,
            message=str(exc),
            agent_fail_fn=agent_fail_fn,
            remediation=[
                "Verify the locale values and Odoo series, then retry.",
            ],
            safety_level=safe_read_only if dry_run else controlled_runtime_mutation,
        )

    if dry_run:
        payload = agent_payload_fn(
            operation,
            result_type,
            {
                "languages": normalized_languages,
                "odoo_series": _normalize_series_label(resolved_series),
                "strategy": (
                    "native_i18n"
                    if (odoo_series_major(resolved_series) or 0) >= 19
                    else "legacy_flags"
                ),
                "mutation_required": True,
                "dry_run": True,
            },
            remediation=[
                "Retry with `--allow-mutation` to load the requested languages.",
            ],
            read_only=True,
            safety_level=safe_read_only,
        )
        agent_emit_payload_fn(payload)
        return

    agent_require_runtime_db_mutation_fn(
        env_config,
        allow_mutation=allow_mutation,
        operation=operation,
        result_type=result_type,
        action="language loading",
        safety_level=controlled_runtime_mutation,
    )
    result = ops.load_languages(
        languages=normalized_languages,
        odoo_series=resolved_series,
        log_level=log_level.value if log_level else None,
        suppress_output=True,
    )
    result["operation"] = operation
    payload = output_result_to_json_fn(
        result,
        additional_fields={
            "languages": normalized_languages,
            "odoo_series": _normalize_series_label(resolved_series),
            "read_only": False,
            "safety_level": controlled_runtime_mutation,
            "remediation": (
                ["Inspect the language loading error and retry after fixing it."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


def agent_test_summary_command(
    ctx: typer.Context,
    *,
    module: str | None,
    allow_mutation: bool,
    install: str | None,
    update: str | None,
    coverage: str | None,
    test_file: str | None,
    test_tags: str | None,
    stop_on_error: bool,
    compact: bool,
    log_level: Any,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    agent_require_runtime_db_mutation_fn: Any,
    build_agent_test_summary_details_fn: Any,
    odoo_operations_cls: Any,
    safe_read_only: str,
    controlled_runtime_mutation: str,
) -> None:
    """Run tests and emit a normalized summary payload."""
    operation = "test_summary"
    result_type = "test_summary"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    is_runtime_db_mutation = bool(install or update)
    if is_runtime_db_mutation:
        agent_require_runtime_db_mutation_fn(
            global_config.env_config,
            allow_mutation=allow_mutation,
            operation=operation,
            result_type=result_type,
            action="test execution",
            safety_level=controlled_runtime_mutation,
        )

    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    result = ops.run_tests(
        module=module,
        stop_on_error=stop_on_error,
        install=install,
        update=update,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
        compact=compact,
        suppress_output=True,
        log_level=log_level.value if log_level else None,
    )
    payload_data, warnings, suggested_next_steps = build_agent_test_summary_details_fn(
        result,
        module=module,
        install=install,
        update=update,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
    )

    payload = agent_payload_fn(
        operation,
        result_type,
        payload_data,
        success=result.get("success", False),
        warnings=warnings,
        remediation=suggested_next_steps,
        read_only=not is_runtime_db_mutation,
        safety_level=(
            controlled_runtime_mutation if is_runtime_db_mutation else safe_read_only
        ),
        error=result.get("error"),
        error_type=result.get("error_type"),
    )
    agent_emit_payload_fn(payload)
    if not result.get("success", False):
        raise typer.Exit(1)
