"""Read-only agent commands for structured inspection workflows."""

from typing import Any

import typer


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
            },
            "effective_config": redact_config_fn(env_config),
            "missing_required_keys": list(context.missing_critical_config),
            "resolved_binaries": context_data["resolved_binaries"],
            "addons_paths": context_data["addons_paths"],
            "odoo": context_data["odoo"],
            "database": context_data["database"],
        },
        warnings=list(context.warnings),
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
