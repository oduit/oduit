"""Read-only agent commands for structured inspection workflows."""

from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import typer

from ...addons_path_manager import AddonsPathManager
from ...source_locator import list_model_extensions
from ..manifest_support import build_manifest_result


def _resolve_addon_root_candidates(addons_path: str, module: str) -> list[str]:
    """Return all candidate addon roots for one module name."""
    path_manager = AddonsPathManager(addons_path)
    duplicates = path_manager.find_duplicate_module_names()
    if module in duplicates:
        return sorted(duplicates[module])
    resolved = path_manager.find_module_path(module)
    return [resolved] if resolved is not None else []


def _parse_runtime_modules(modules_value: Any) -> list[str]:
    """Normalize a comma-separated runtime modules string."""
    if not isinstance(modules_value, str) or not modules_value.strip():
        return []
    return sorted({item.strip() for item in modules_value.split(",") if item.strip()})


def _as_string_list(value: Any) -> list[str]:
    """Normalize optional list values from mixed command results."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _as_error_list(value: Any) -> list[dict[str, Any]]:
    """Normalize structured error lists from mixed command results."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _emit_operation_result_payload(
    *,
    operation: str,
    result_type: str,
    result: dict[str, Any],
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    default_read_only: bool = True,
    default_safety_level: str,
    failure_remediation: list[str] | None = None,
) -> None:
    """Emit a raw operation result through the standard agent envelope."""
    success = bool(result.get("success", False))
    remediation = _as_string_list(result.get("remediation"))
    if not remediation and not success and failure_remediation:
        remediation = failure_remediation

    payload = agent_payload_fn(
        operation,
        result_type,
        result,
        success=success,
        warnings=_as_string_list(result.get("warnings")),
        errors=_as_error_list(result.get("errors")),
        remediation=remediation,
        read_only=(
            result["read_only"]
            if isinstance(result.get("read_only"), bool)
            else default_read_only
        ),
        safety_level=(
            result["safety_level"]
            if isinstance(result.get("safety_level"), str)
            and result.get("safety_level")
            else default_safety_level
        ),
        error=result.get("error"),
        error_type=result.get("error_type"),
    )
    agent_emit_payload_fn(payload)
    if not success:
        raise typer.Exit(1)


def agent_inspect_ref_command(
    ctx: typer.Context,
    *,
    xmlid: str,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Resolve one XMLID through the embedded Odoo runtime."""
    operation = "inspect_ref"
    result_type = "xmlid_inspection"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.inspect_ref(xmlid, database=database, timeout=timeout)
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the XMLID and retry the inspection.",
        ],
    )


def agent_inspect_modules_command(
    ctx: typer.Context,
    *,
    state: str | None,
    names_only: bool,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Inspect module records from ir.module.module."""
    operation = "inspect_modules"
    result_type = "module_inspection"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.inspect_modules(
        state=state,
        names_only=names_only,
        database=database,
        timeout=timeout,
    )
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the runtime module-state filter and database access, then retry.",
        ],
    )


def agent_inspect_subtypes_command(
    ctx: typer.Context,
    *,
    model: str,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """List message subtypes registered for one model."""
    operation = "inspect_subtypes"
    result_type = "subtype_inventory"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.inspect_subtypes(model, database=database, timeout=timeout)
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the model name and retry the subtype inspection.",
        ],
    )


def agent_inspect_model_command(
    ctx: typer.Context,
    *,
    model: str,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Inspect runtime model registration metadata."""
    operation = "inspect_model"
    result_type = "model_inspection"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.inspect_model(model, database=database, timeout=timeout)
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the model name and retry the runtime inspection.",
        ],
    )


def agent_inspect_field_command(
    ctx: typer.Context,
    *,
    model: str,
    field: str,
    with_db: bool,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Inspect runtime field metadata."""
    operation = "inspect_field"
    result_type = "field_inspection"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.inspect_field(
        model,
        field,
        with_db=with_db,
        database=database,
        timeout=timeout,
    )
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the model and field names, then retry the inspection.",
        ],
    )


def agent_db_table_command(
    ctx: typer.Context,
    *,
    table_name: str,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Describe one PostgreSQL table through the live Odoo connection."""
    operation = "describe_table"
    result_type = "table_description"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.describe_table(table_name, database=database, timeout=timeout)
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the table name and retry the database inspection.",
        ],
    )


def agent_db_column_command(
    ctx: typer.Context,
    *,
    table_name: str,
    column_name: str,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Describe one PostgreSQL column through the live Odoo connection."""
    operation = "describe_column"
    result_type = "column_description"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.describe_column(
        table_name,
        column_name,
        database=database,
        timeout=timeout,
    )
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the table and column names, then retry the inspection.",
        ],
    )


def agent_db_constraints_command(
    ctx: typer.Context,
    *,
    table_name: str,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """List PostgreSQL constraints for one table."""
    operation = "list_constraints"
    result_type = "constraint_inventory"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.list_constraints(table_name, database=database, timeout=timeout)
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the table name and retry the constraint inspection.",
        ],
    )


def agent_db_tables_command(
    ctx: typer.Context,
    *,
    like: str | None,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """List PostgreSQL tables through the live Odoo connection."""
    operation = "list_tables"
    result_type = "table_inventory"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.list_tables(like, database=database, timeout=timeout)
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the table filter and retry the table inventory query.",
        ],
    )


def agent_db_m2m_command(
    ctx: typer.Context,
    *,
    model: str,
    field: str,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Inspect Many2many relation-table metadata."""
    operation = "inspect_m2m"
    result_type = "m2m_inspection"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.inspect_m2m(model, field, database=database, timeout=timeout)
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the model and Many2many field, then retry the inspection.",
        ],
    )


def agent_performance_slow_queries_command(
    ctx: typer.Context,
    *,
    limit: int,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Read pg_stat_statements when the extension is available."""
    operation = "performance_slow_queries"
    result_type = "slow_query_metrics"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.performance_slow_queries(
        limit=limit,
        database=database,
        timeout=timeout,
    )
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify database access and retry the slow-query inspection.",
        ],
    )


def agent_performance_table_scans_command(
    ctx: typer.Context,
    *,
    limit: int,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Show tables with high sequential scan counts."""
    operation = "performance_table_scans"
    result_type = "table_scan_metrics"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.performance_table_scans(
        limit=limit,
        database=database,
        timeout=timeout,
    )
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify database access and retry the table-scan inspection.",
        ],
    )


def agent_performance_indexes_command(
    ctx: typer.Context,
    *,
    limit: int,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Show basic table index-usage metrics."""
    operation = "performance_indexes"
    result_type = "index_usage_metrics"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.performance_indexes(limit=limit, database=database, timeout=timeout)
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify database access and retry the index-usage inspection.",
        ],
    )


def agent_manifest_check_command(
    ctx: typer.Context,
    *,
    target: str,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Validate a manifest file and report structural warnings."""
    operation = "manifest_check"
    result_type = "manifest_validation"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    if env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert env_config is not None

    result, _ = build_manifest_result(target, env_config)
    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the addon target or manifest path, then retry the validation.",
        ],
    )


def agent_manifest_show_command(
    ctx: typer.Context,
    *,
    target: str,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Show manifest metadata for an addon or addon path."""
    operation = "manifest_show"
    result_type = "manifest"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    if env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert env_config is not None

    result, manifest = build_manifest_result(target, env_config)
    if manifest is not None:
        result = {
            **result,
            "operation": operation,
            "name": manifest.name,
            "version": manifest.version,
            "summary": manifest.summary,
            "author": manifest.author,
            "website": manifest.website,
            "license": manifest.license,
            "installable": manifest.installable,
            "auto_install": manifest.auto_install,
            "depends": manifest.codependencies,
            "python_dependencies": manifest.python_dependencies,
            "binary_dependencies": manifest.binary_dependencies,
            "manifest_data": manifest.get_raw_data(),
        }
    else:
        result["operation"] = operation

    _emit_operation_result_payload(
        operation=operation,
        result_type=result_type,
        result=result,
        agent_payload_fn=agent_payload_fn,
        agent_emit_payload_fn=agent_emit_payload_fn,
        default_safety_level=safe_read_only,
        failure_remediation=[
            "Verify the addon target or manifest path, then retry the inspection.",
        ],
    )


def agent_context_command(
    ctx: typer.Context,
    *,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    odoo_operations_cls: Any,
    safe_read_only: str,
) -> None:
    """Return a structured environment snapshot for automation."""
    operation = "agent_context"
    result_type = "environment_context"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(
            operation,
            result_type,
            "No environment configuration available",
            error_type="ConfigError",
        )
    assert global_config.env_config is not None

    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    context = ops.get_environment_context(
        env_name=global_config.env_name,
        config_source=global_config.config_source,
        config_path=global_config.config_path,
        odoo_series=global_config.odoo_series,
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        context.to_dict(),
        warnings=list(context.warnings),
        remediation=list(context.remediation),
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)


def agent_inspect_addon_command(
    ctx: typer.Context,
    *,
    module: str,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    odoo_operations_cls: Any,
    module_not_found_error_cls: Any,
    safe_read_only: str,
) -> None:
    """Return a one-shot addon inspection payload."""
    operation = "inspect_addon"
    result_type = "addon_inspection"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    try:
        inspection = ops.inspect_addon(module, odoo_series=global_config.odoo_series)
    except module_not_found_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the module exists in the configured addons paths.",
                "Run `oduit agent context` to inspect the resolved addons paths.",
            ],
        )

    payload = agent_payload_fn(
        operation,
        result_type,
        inspection.to_dict(),
        warnings=list(inspection.warnings),
        remediation=list(inspection.remediation),
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)


def agent_addon_info_command(
    ctx: typer.Context,
    *,
    module: str,
    database: str | None,
    timeout: float,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    odoo_operations_cls: Any,
    module_not_found_error_cls: Any,
    safe_read_only: str,
) -> None:
    """Return a combined addon summary for onboarding and planning."""
    operation = "addon_info"
    result_type = "addon_info"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    try:
        info = ops.addon_info(
            module,
            odoo_series=global_config.odoo_series,
            database=database,
            timeout=timeout,
        )
    except module_not_found_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
                "Run `oduit agent context` to inspect the resolved addons paths.",
            ],
        )

    payload = agent_payload_fn(
        operation,
        result_type,
        info.to_dict(),
        warnings=list(info.warnings),
        remediation=list(info.remediation),
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)


def agent_plan_update_command(
    ctx: typer.Context,
    *,
    module: str,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    odoo_operations_cls: Any,
    module_not_found_error_cls: Any,
    safe_read_only: str,
) -> None:
    """Return a structured, read-only update plan for a module."""
    operation = "plan_update"
    result_type = "update_plan"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    try:
        plan = ops.plan_update(module, odoo_series=global_config.odoo_series)
    except module_not_found_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the module exists before planning the update.",
                "Run `oduit agent inspect-addon <module>` to inspect discovery state.",
            ],
        )

    payload = agent_payload_fn(
        operation,
        result_type,
        plan.to_dict(),
        warnings=list(plan.warnings),
        remediation=list(plan.remediation),
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)


def agent_locate_model_command(
    ctx: typer.Context,
    *,
    model: str,
    module: str,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> None:
    """Locate likely source files for a model extension inside one addon."""
    operation = "locate_model"
    result_type = "model_source_location"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    try:
        location = ops.locate_model(module, model)
    except module_not_found_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module, "model": model},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
                "Run `oduit agent inspect-addon <module>` to confirm addon discovery.",
            ],
        )
    except config_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"module": module, "model": model},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    payload = agent_payload_fn(
        operation,
        result_type,
        location.to_dict(),
        warnings=list(location.warnings),
        remediation=list(location.remediation),
    )
    agent_emit_payload_fn(payload)


def agent_locate_field_command(
    ctx: typer.Context,
    *,
    model: str,
    field_name: str,
    module: str,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> None:
    """Locate an existing field or suggest the best insertion point."""
    operation = "locate_field"
    result_type = "field_source_location"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    try:
        location = ops.locate_field(module, model, field_name)
    except module_not_found_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module, "model": model, "field": field_name},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
                "Run `oduit agent inspect-addon <module>` to confirm addon discovery.",
            ],
        )
    except config_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"module": module, "model": model, "field": field_name},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    warnings = list(location.warnings)
    remediation = list(location.remediation)
    runtime_exists: bool | None = None
    runtime_source_modules: list[str] = []
    runtime_result = ops.get_model_fields(
        model,
        attributes=["modules"],
        database=None,
        timeout=30.0,
    )
    if runtime_result.success:
        runtime_exists = field_name in runtime_result.field_names
        runtime_modules = runtime_result.field_definitions.get(field_name, {}).get(
            "modules"
        )
        if isinstance(runtime_modules, str) and runtime_modules.strip():
            runtime_source_modules = sorted(
                {item.strip() for item in runtime_modules.split(",") if item.strip()}
            )
    else:
        warnings.append(
            "Runtime field metadata was unavailable; static source guidance is "
            "still provided."
        )
        remediation.append(
            "Verify database access if you need to know whether the field already "
            "exists at runtime."
        )

    payload_data = {
        **location.to_dict(),
        "source_exists": location.exists,
        "runtime_exists": runtime_exists,
        "runtime_only": bool(runtime_exists and not location.exists),
        "runtime_source_modules": runtime_source_modules,
        "insertion_file": (
            location.insertion_candidate.path if location.insertion_candidate else None
        ),
        "insertion_class": (
            location.insertion_candidate.class_name
            if location.insertion_candidate
            else None
        ),
    }
    payload = agent_payload_fn(
        operation,
        result_type,
        payload_data,
        warnings=list(dict.fromkeys(warnings)),
        remediation=list(dict.fromkeys(remediation)),
    )
    agent_emit_payload_fn(payload)


def agent_list_addon_tests_command(
    ctx: typer.Context,
    *,
    module: str,
    model: str | None,
    field_name: str | None,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> None:
    """List likely tests for an addon, optionally ranked by model/field references."""
    operation = "list_addon_tests"
    result_type = "addon_test_inventory"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    try:
        inventory = ops.list_addon_tests(module, model=model, field_name=field_name)
    except module_not_found_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
    except config_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"module": module},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    payload = agent_payload_fn(
        operation,
        result_type,
        inventory.to_dict(),
        warnings=list(inventory.warnings),
        remediation=list(inventory.remediation),
    )
    agent_emit_payload_fn(payload)


def agent_recommend_tests_command(
    ctx: typer.Context,
    *,
    module: str,
    paths: str,
    resolve_agent_ops_fn: Any,
    parse_csv_items_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> None:
    """Map changed addon files to recommended tests and test tags."""
    operation = "recommend_tests"
    result_type = "recommended_test_plan"
    changed_paths = parse_csv_items_fn(paths) or []
    if not changed_paths:
        agent_fail_fn(
            operation,
            result_type,
            "At least one changed path is required",
            error_type="ValidationError",
            remediation=[
                "Pass `--paths` as a comma-separated list such as "
                "`models/res_partner.py,views/res_partner_views.xml`.",
            ],
        )

    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    try:
        plan = ops.recommend_tests(module, changed_paths)
    except module_not_found_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
    except config_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"module": module},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    payload = agent_payload_fn(
        operation,
        result_type,
        plan,
        warnings=list(plan.get("warnings", [])),
        remediation=list(plan.get("remediation", [])),
    )
    agent_emit_payload_fn(payload)


def agent_list_addon_models_command(
    ctx: typer.Context,
    *,
    module: str,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> None:
    """List the models declared or extended by one addon."""
    operation = "list_addon_models"
    result_type = "addon_model_inventory"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    try:
        inventory = ops.list_addon_models(module)
    except module_not_found_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
    except config_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"module": module},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    payload = agent_payload_fn(
        operation,
        result_type,
        inventory.to_dict(),
        warnings=list(inventory.warnings),
        remediation=list(inventory.remediation),
    )
    agent_emit_payload_fn(payload)


def agent_find_model_extensions_command(
    ctx: typer.Context,
    *,
    model: str,
    summary: bool,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    config_error_cls: Any,
) -> None:
    """Find where a model is declared, extended, and installed."""
    operation = "find_model_extensions"
    result_type = "model_extension_inventory"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    try:
        inventory = ops.find_model_extensions(model, database=database, timeout=timeout)
    except config_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"model": model},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    remediation = list(inventory.remediation)
    if not inventory.installed_fields:
        remediation.append(
            "Runtime field metadata was unavailable; verify database access if "
            "installed state matters."
        )
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            **inventory.to_dict(),
            "summary": summary,
            "base_declaration_count": len(inventory.base_declarations),
            "source_extension_count": len(inventory.source_extensions),
            "source_view_extension_count": len(inventory.source_view_extensions),
            "installed_field_count": len(inventory.installed_fields),
            "installed_extension_field_count": len(
                inventory.installed_extension_fields
            ),
            "installed_view_extension_count": len(inventory.installed_view_extensions),
        },
        warnings=list(inventory.warnings),
        remediation=list(dict.fromkeys(remediation)),
        exclude_fields=["scanned_python_files"] if summary else None,
    )
    agent_emit_payload_fn(payload)


def agent_get_model_views_command(
    ctx: typer.Context,
    *,
    model: str,
    types: str | None,
    summary: bool,
    database: str | None,
    timeout: float,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    parse_view_types_fn: Any,
    strip_arch_from_model_views_fn: Any,
    odoo_operations_cls: Any,
) -> None:
    """Fetch database-backed primary and extension views for a model."""
    operation = "get_model_views"
    result_type = "model_view_inventory"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    requested_types = parse_view_types_fn(types, operation, result_type)
    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    inventory = ops.get_model_views(
        model,
        view_types=requested_types,
        database=database,
        timeout=timeout,
        include_arch=not summary,
    )
    inventory_data = inventory.to_dict()
    if summary:
        inventory_data = strip_arch_from_model_views_fn(inventory_data)

    payload = agent_payload_fn(
        operation,
        result_type,
        {
            **inventory_data,
            "summary": summary,
        },
        success=(
            inventory.error is None
            and bool(inventory.primary_views or inventory.extension_views)
        ),
        warnings=list(inventory.warnings),
        remediation=list(inventory.remediation),
        error=(
            inventory.error
            or (
                f"No database views were found for model '{model}'"
                if not inventory.primary_views and not inventory.extension_views
                else None
            )
        ),
        error_type=(
            inventory.error_type
            or (
                "ModelViewNotFound"
                if not inventory.primary_views and not inventory.extension_views
                else None
            )
        ),
    )
    agent_emit_payload_fn(payload)
    if inventory.error or (
        not inventory.primary_views and not inventory.extension_views
    ):
        raise typer.Exit(1)


def agent_doctor_command(
    ctx: typer.Context,
    *,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    build_doctor_report_fn: Any,
) -> None:
    """Return doctor diagnostics through the standard agent envelope."""
    operation = "agent_doctor"
    result_type = "doctor_report"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(
            operation,
            result_type,
            "No environment configuration available",
            error_type="ConfigError",
        )

    report = build_doctor_report_fn(global_config)
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "source": report.get("source", {}),
            "checks": report.get("checks", []),
            "summary": report.get("summary", {}),
            "next_steps": report.get("next_steps", []),
        },
        success=report.get("success", False),
        warnings=list(report.get("warnings", [])),
        errors=list(report.get("errors", [])),
        remediation=list(report.get("remediation", [])),
        error=report.get("error"),
        error_type=report.get("error_type"),
    )
    agent_emit_payload_fn(payload)
    if not report.get("success", False):
        raise typer.Exit(1)


def agent_list_addons_command(
    ctx: typer.Context,
    *,
    select_dir: str | None,
    include: list[str],
    exclude: list[str],
    sorting: str,
    exclude_core_addons: bool,
    exclude_enterprise_addons: bool,
    resolve_agent_ops_fn: Any,
    require_agent_addons_path_fn: Any,
    parse_filter_values_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    module_manager_cls: Any,
    apply_core_addon_filters_fn: Any,
    apply_field_filters_fn: Any,
) -> None:
    """Return structured addon inventory for the active environment."""
    operation = "agent_list_addons"
    result_type = "addon_inventory"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None
    addons_path = require_agent_addons_path_fn(env_config, operation, result_type)

    try:
        include_filter = parse_filter_values_fn(include, "include")
        exclude_filter = parse_filter_values_fn(exclude, "exclude")
    except ValueError as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            details={"include": include, "exclude": exclude},
        )

    module_manager = module_manager_cls(addons_path)
    addons = module_manager.find_module_dirs(filter_dir=select_dir)
    addons = [addon for addon in addons if not addon.startswith("test_")]
    odoo_series = global_config.odoo_series or module_manager.detect_odoo_series()

    if exclude_core_addons or exclude_enterprise_addons:
        try:
            addons = apply_core_addon_filters_fn(
                addons,
                exclude_core_addons,
                exclude_enterprise_addons,
                odoo_series,
            )
        except ValueError:
            agent_fail_fn(
                operation,
                result_type,
                (
                    "Could not apply addon type filters because Odoo series "
                    "detection failed"
                ),
                error_type="ConfigError",
                remediation=[
                    "Pass `--odoo-series` or ensure addon versions allow "
                    "Odoo series detection.",
                ],
            )

    try:
        addons = apply_field_filters_fn(
            addons,
            module_manager,
            include_filter,
            exclude_filter,
            odoo_series,
        )
        sorted_addons = module_manager.sort_modules(addons, sorting)
    except ValueError as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ValidationError",
        )

    inventory = ops.list_addons_inventory(sorted_addons, odoo_series=odoo_series)
    duplicates = ops.list_duplicates()
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "addons": inventory,
            "total": len(inventory),
            "filters": {
                "select_dir": select_dir,
                "include": include_filter,
                "exclude": exclude_filter,
                "exclude_core_addons": exclude_core_addons,
                "exclude_enterprise_addons": exclude_enterprise_addons,
            },
            "sorting": sorting,
            "duplicate_modules": duplicates,
        },
    )
    agent_emit_payload_fn(payload)


def agent_list_installed_addons_command(
    ctx: typer.Context,
    *,
    modules: str | None,
    state: list[str],
    resolve_agent_ops_fn: Any,
    parse_csv_items_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Return structured runtime installed-addon inventory."""
    operation = "list_installed_addons"
    result_type = "installed_addon_inventory"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    result = ops.list_installed_addons(
        modules=parse_csv_items_fn(modules),
        states=state or None,
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        result.to_dict(),
        success=result.success,
        warnings=list(result.warnings),
        remediation=(
            list(result.remediation)
            if result.remediation
            else (
                ["Verify database access and retry the runtime addon inventory query."]
                if not result.success
                else []
            )
        ),
        read_only=True,
        safety_level=safe_read_only,
        error=result.error,
        error_type=result.error_type,
    )
    agent_emit_payload_fn(payload)
    if not result.success:
        raise typer.Exit(1)


def agent_dependency_graph_command(
    ctx: typer.Context,
    *,
    modules: str,
    resolve_agent_ops_fn: Any,
    parse_csv_items_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    config_error_cls: Any,
) -> None:
    """Return a structured dependency and reverse-dependency graph."""
    operation = "agent_dependency_graph"
    result_type = "dependency_graph"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    module_names = parse_csv_items_fn(modules)
    if not module_names:
        agent_fail_fn(
            operation,
            result_type,
            "At least one module must be provided via --modules",
            error_type="ValidationError",
        )

    try:
        graph = ops.dependency_graph(module_names)
    except config_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"modules": module_names},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )
    payload = agent_payload_fn(
        operation,
        result_type,
        graph,
        warnings=list(graph.get("warnings", [])),
        remediation=(
            ["Resolve dependency cycles before relying on the computed install order."]
            if graph.get("cycles")
            else []
        ),
    )
    agent_emit_payload_fn(payload)


def agent_inspect_addons_command(
    ctx: typer.Context,
    *,
    modules: str,
    resolve_agent_ops_fn: Any,
    parse_csv_items_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    module_not_found_error_cls: Any,
) -> None:
    """Inspect multiple addons through the stable agent envelope."""
    operation = "inspect_addons"
    result_type = "batch_addon_inspection"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    module_names = parse_csv_items_fn(modules)
    if not module_names:
        agent_fail_fn(
            operation,
            result_type,
            "At least one module must be provided via --modules",
            error_type="ValidationError",
        )

    inspections = []
    missing_modules: list[str] = []
    for module_name in module_names:
        try:
            inspections.append(
                ops.inspect_addon(module_name, odoo_series=global_config.odoo_series)
            )
        except module_not_found_error_cls:
            missing_modules.append(module_name)

    success = not missing_modules
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "modules": module_names,
            "inspections": [inspection.to_dict() for inspection in inspections],
            "found_count": len(inspections),
            "missing_modules": missing_modules,
        },
        success=success,
        warnings=(
            [f"Some requested modules were not found: {', '.join(missing_modules)}"]
            if missing_modules
            else []
        ),
        remediation=(
            ["Verify the requested module names and configured addons paths."]
            if missing_modules
            else []
        ),
        error=(
            f"{len(missing_modules)} module(s) were not found"
            if missing_modules
            else None
        ),
        error_type="ModuleNotFoundError" if missing_modules else None,
    )
    agent_emit_payload_fn(payload)
    if not success:
        raise typer.Exit(1)


def agent_resolve_config_command(
    ctx: typer.Context,
    *,
    resolve_agent_ops_fn: Any,
    config_loader_cls: Any,
    redact_config_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
) -> None:
    """Return the resolved configuration with sensitive values redacted."""
    operation = "resolve_config"
    result_type = "config_resolution"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None
    config_loader = config_loader_cls()
    if global_config.config_source == "local":
        config_details = config_loader.load_local_config_details()
    else:
        assert global_config.env_name is not None
        config_details = config_loader.load_config_details(global_config.env_name)
    context = ops.get_environment_context(
        env_name=global_config.env_name,
        config_source=global_config.config_source,
        config_path=global_config.config_path,
        odoo_series=global_config.odoo_series,
    )
    context_data = context.to_dict()
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "environment": {
                "name": global_config.env_name,
                "source": global_config.config_source,
                "config_path": global_config.config_path,
                "format": config_details.format_type,
            },
            "effective_config": redact_config_fn(env_config),
            "normalized_config": redact_config_fn(config_details.canonical_config),
            "config_shape": {
                "raw_shape": config_details.raw_shape,
                "normalized_shape": config_details.normalized_shape,
                "shape_version": config_details.shape_version,
                "source_format": config_details.format_type,
            },
            "deprecation_warnings": list(config_details.deprecation_warnings),
            "missing_required_keys": list(context.missing_critical_config),
            "resolved_binaries": context_data["resolved_binaries"],
            "addons_paths": context_data["addons_paths"],
            "odoo": context_data["odoo"],
            "database": context_data["database"],
        },
        warnings=[
            *list(context.warnings),
            *list(config_details.deprecation_warnings),
        ],
        remediation=list(context.remediation),
    )
    agent_emit_payload_fn(payload)


def agent_list_duplicates_command(
    ctx: typer.Context,
    *,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    config_error_cls: Any,
) -> None:
    """Return duplicate addon names through the standard agent envelope."""
    operation = "list_duplicates"
    result_type = "duplicate_modules"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    try:
        duplicates = ops.list_duplicates()
    except config_error_cls as exc:
        agent_fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "duplicate_modules": duplicates,
            "duplicate_count": len(duplicates),
        },
        warnings=(
            ["Duplicate addon names can make module resolution ambiguous."]
            if duplicates
            else []
        ),
        remediation=(
            ["Remove or reorder duplicate addon paths before mutating modules."]
            if duplicates
            else []
        ),
    )
    agent_emit_payload_fn(payload)


def agent_resolve_addon_root_command(
    ctx: typer.Context,
    *,
    module: str,
    resolve_agent_global_config_fn: Any,
    require_agent_addons_path_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Resolve addon root paths for one module name."""
    operation = "resolve_addon_root"
    result_type = "addon_root_resolution"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    if env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert env_config is not None
    addons_path = require_agent_addons_path_fn(env_config, operation, result_type)
    candidates = _resolve_addon_root_candidates(addons_path, module)
    if not candidates:
        agent_fail_fn(
            operation,
            result_type,
            f"Module '{module}' was not found in addons_path",
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )

    unique = len(candidates) == 1
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "module": module,
            "exists": True,
            "unique": unique,
            "addon_root": candidates[0],
            "duplicate_candidates": candidates,
            "candidate_count": len(candidates),
        },
        warnings=(
            ["Duplicate addon names make root resolution ambiguous."]
            if not unique
            else []
        ),
        remediation=(
            ["Remove or reorder duplicate addon paths before mutating this addon."]
            if not unique
            else []
        ),
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)


def agent_get_addon_files_command(
    ctx: typer.Context,
    *,
    module: str,
    globs: str | None,
    resolve_agent_global_config_fn: Any,
    require_agent_addons_path_fn: Any,
    parse_csv_items_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Return a deterministic file inventory for one addon."""
    operation = "get_addon_files"
    result_type = "addon_file_inventory"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    if env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert env_config is not None
    addons_path = require_agent_addons_path_fn(env_config, operation, result_type)
    candidates = _resolve_addon_root_candidates(addons_path, module)
    if not candidates:
        agent_fail_fn(
            operation,
            result_type,
            f"Module '{module}' was not found in addons_path",
            error_type="ModuleNotFoundError",
            details={"module": module},
        )
    if len(candidates) > 1:
        agent_fail_fn(
            operation,
            result_type,
            f"Module '{module}' is duplicated across addons paths",
            error_type="DuplicateModuleError",
            details={"module": module, "duplicate_candidates": candidates},
            remediation=[
                "Resolve duplicate addon names before requesting a deterministic "
                "file inventory.",
            ],
        )

    addon_root = Path(candidates[0])
    patterns = parse_csv_items_fn(globs) or []
    files = []
    for path in sorted(addon_root.rglob("*")):
        if not path.is_file():
            continue
        relative_path = path.relative_to(addon_root).as_posix()
        if patterns and not any(
            fnmatch(relative_path, pattern) for pattern in patterns
        ):
            continue
        files.append(relative_path)

    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "module": module,
            "addon_root": str(addon_root),
            "globs": patterns,
            "files": files,
            "file_count": len(files),
        },
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)


def agent_check_addons_installed_command(
    ctx: typer.Context,
    *,
    modules: str,
    resolve_agent_ops_fn: Any,
    parse_csv_items_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Return runtime installed-state checks for one or more addons."""
    operation = "check_addons_installed"
    result_type = "addon_install_checks"
    requested_modules = parse_csv_items_fn(modules) or []
    if not requested_modules:
        agent_fail_fn(
            operation,
            result_type,
            "At least one addon name is required.",
            error_type="ValidationError",
            remediation=[
                "Pass `--modules` as a comma-separated list such as `sale,stock`.",
            ],
        )

    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    checks: list[dict[str, Any]] = []
    unknown_modules: list[str] = []
    for module_name in requested_modules:
        state = ops.get_addon_install_state(module_name)
        status = "unknown"
        if state.success:
            status = "installed" if state.installed else "not_installed"
        else:
            unknown_modules.append(module_name)
        checks.append(
            {
                **state.to_dict(),
                "status": status,
            }
        )

    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "requested_modules": requested_modules,
            "checks": checks,
            "installed_modules": [
                check["module"] for check in checks if check["status"] == "installed"
            ],
            "not_installed_modules": [
                check["module"]
                for check in checks
                if check["status"] == "not_installed"
            ],
            "unknown_modules": unknown_modules,
        },
        success=not unknown_modules,
        warnings=(
            ["Some addon install-state checks could not be completed."]
            if unknown_modules
            else []
        ),
        remediation=(
            ["Verify database access before relying on unknown addon states."]
            if unknown_modules
            else []
        ),
        error=(
            f"{len(unknown_modules)} addon install-state check(s) failed"
            if unknown_modules
            else None
        ),
        error_type="QueryError" if unknown_modules else None,
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)
    if unknown_modules:
        raise typer.Exit(1)


def agent_check_model_exists_command(
    ctx: typer.Context,
    *,
    model: str,
    module: str | None,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    require_agent_addons_path_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Check whether a model exists in source discovery and runtime metadata."""
    operation = "check_model_exists"
    result_type = "model_existence"
    global_config, ops = resolve_agent_ops_fn(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None
    addons_path = require_agent_addons_path_fn(env_config, operation, result_type)

    inventory = list_model_extensions(addons_path, model)
    source_candidates = sorted(
        {
            item.module
            for item in (
                inventory.base_declarations
                + inventory.source_extensions
                + inventory.source_view_extensions
            )
        }
    )
    if module is not None:
        source_candidates = [
            candidate for candidate in source_candidates if candidate == module
        ]
    source_exists = bool(source_candidates)

    warnings = list(inventory.warnings)
    remediation = list(inventory.remediation)
    runtime_result = ops.get_model_fields(
        model,
        attributes=["modules"],
        database=database,
        timeout=timeout,
    )
    runtime_exists: bool | None = None
    runtime_source_modules: list[str] = []
    if runtime_result.success:
        runtime_exists = True
        for field_def in runtime_result.field_definitions.values():
            runtime_source_modules.extend(
                _parse_runtime_modules(field_def.get("modules"))
            )
        runtime_source_modules = sorted(set(runtime_source_modules))
    else:
        warnings.append(
            "Runtime model metadata was unavailable; static source guidance is still "
            "provided."
        )
        remediation.append(
            "Verify database access if you need runtime confirmation for the model."
        )

    exists = source_exists or bool(runtime_exists)
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "model": model,
            "module": module,
            "exists": exists,
            "source_exists": source_exists,
            "runtime_exists": runtime_exists,
            "source_addon_candidates": source_candidates,
            "runtime_source_modules": runtime_source_modules,
            "base_declaration_count": len(inventory.base_declarations),
            "source_extension_count": len(inventory.source_extensions),
            "source_view_extension_count": len(inventory.source_view_extensions),
        },
        success=exists,
        warnings=list(dict.fromkeys(warnings)),
        remediation=list(dict.fromkeys(remediation)),
        error=(
            None
            if exists
            else (
                f"Model '{model}' was not found in source discovery or runtime "
                "metadata."
            )
        ),
        error_type=None if exists else "ModelNotFound",
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)
    if not exists:
        raise typer.Exit(1)


def agent_check_field_exists_command(
    ctx: typer.Context,
    *,
    model: str,
    field_name: str,
    module: str | None,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
    safe_read_only: str,
) -> None:
    """Check whether a field exists in runtime metadata and optionally in source."""
    operation = "check_field_exists"
    result_type = "field_existence"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)

    warnings: list[str] = []
    remediation: list[str] = []
    runtime_result = ops.get_model_fields(
        model,
        attributes=["modules", "string", "type"],
        database=database,
        timeout=timeout,
    )
    runtime_exists: bool | None = None
    runtime_source_modules: list[str] = []
    if runtime_result.success:
        runtime_exists = field_name in runtime_result.field_names
        runtime_source_modules = _parse_runtime_modules(
            runtime_result.field_definitions.get(field_name, {}).get("modules")
        )
    else:
        warnings.append(
            "Runtime field metadata was unavailable; static source guidance is still "
            "provided when `--module` is supplied."
        )
        remediation.append(
            "Verify database access if you need runtime confirmation for the field."
        )

    source_exists: bool | None = None
    source_candidates: list[dict[str, Any]] = []
    insertion_candidate: dict[str, Any] | None = None
    insertion_file: str | None = None
    insertion_class: str | None = None
    insertion_confidence: float | None = None
    if module is not None:
        try:
            location = ops.locate_field(module, model, field_name)
        except module_not_found_error_cls as exc:
            agent_fail_fn(
                operation,
                result_type,
                str(exc),
                error_type="ModuleNotFoundError",
                details={"module": module, "model": model, "field": field_name},
            )
        except config_error_cls as exc:
            agent_fail_fn(
                operation,
                result_type,
                str(exc),
                error_type="ConfigError",
                details={"module": module, "model": model, "field": field_name},
            )

        source_exists = location.exists
        source_candidates = [candidate.to_dict() for candidate in location.candidates]
        insertion_candidate = (
            location.insertion_candidate.to_dict()
            if location.insertion_candidate is not None
            else None
        )
        insertion_file = (
            location.insertion_candidate.path
            if location.insertion_candidate is not None
            else None
        )
        insertion_class = (
            location.insertion_candidate.class_name
            if location.insertion_candidate is not None
            else None
        )
        insertion_confidence = location.insertion_confidence
        warnings.extend(location.warnings)
        remediation.extend(location.remediation)
    else:
        warnings.append(
            "Pass `--module <addon>` if you need source candidates or insertion "
            "guidance."
        )

    exists = bool(runtime_exists) or bool(source_exists)
    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "model": model,
            "field": field_name,
            "module": module,
            "exists": exists,
            "runtime_exists": runtime_exists,
            "source_exists": source_exists,
            "runtime_source_modules": runtime_source_modules,
            "source_candidates": source_candidates,
            "insertion_candidate": insertion_candidate,
            "insertion_file": insertion_file,
            "insertion_class": insertion_class,
            "insertion_confidence": insertion_confidence,
        },
        success=exists,
        warnings=list(dict.fromkeys(warnings)),
        remediation=list(dict.fromkeys(remediation)),
        error=(
            None
            if exists
            else f"Field '{field_name}' was not found in runtime metadata or source."
        ),
        error_type=None if exists else "FieldNotFound",
        read_only=True,
        safety_level=safe_read_only,
    )
    agent_emit_payload_fn(payload)
    if not exists:
        raise typer.Exit(1)
