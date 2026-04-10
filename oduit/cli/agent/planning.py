"""Aggregate planning commands for coding-agent workflows."""

from typing import Any

import typer

_ADDONS_PATH_REMEDIATION = [
    "Set `addons_path` in the selected environment before retrying.",
]
_ADDON_NOT_FOUND_REMEDIATION = [
    "Verify that the addon exists in the configured addons paths.",
]


def _dedupe_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _skipped_step(
    agent_sub_result_fn: Any, *, reason: str, **data: Any
) -> dict[str, Any]:
    return agent_sub_result_fn(
        success=True,
        skipped=True,
        data={"reason": reason, **data},
    )


def _build_recommended_next_steps(
    *,
    env_name: str | None,
    module: str,
    model: str | None,
    field_name: str | None,
    steps: dict[str, dict[str, Any]],
    failed_step: str | None,
) -> list[str]:
    prefix = "oduit"
    if env_name and env_name != "local":
        prefix = f"oduit --env {env_name}"

    if failed_step is not None:
        remediation = steps.get(failed_step, {}).get("remediation", [])
        if remediation:
            return list(remediation)
        return [f"Review the `{failed_step}` step details and retry the planning flow."]

    recommendations: list[str] = []
    locate_field_step = steps.get("locate_field", {})
    locate_model_step = steps.get("locate_model", {})
    test_step = steps.get("list_addon_tests", {})

    if field_name and locate_field_step.get("success"):
        field_data = locate_field_step.get("data", {})
        candidates = field_data.get("candidates", [])
        insertion_candidate = field_data.get("insertion_candidate")
        if field_data.get("exists") and candidates:
            primary = candidates[0]
            recommendations.append(
                f"Review the existing `{field_name}` definition in "
                f"`{primary['path']}`."
            )
        elif insertion_candidate:
            line_hint = insertion_candidate.get("line_hint")
            line_suffix = f" near line {line_hint}" if line_hint else ""
            recommendations.append(
                f"Add `{field_name}` in `{insertion_candidate['path']}`{line_suffix}."
            )
    elif model and locate_model_step.get("success"):
        candidates = locate_model_step.get("data", {}).get("candidates", [])
        if candidates:
            recommendations.append(
                f"Edit `{candidates[0]['path']}` for the `{model}` change."
            )

    tests = test_step.get("data", {}).get("tests", [])
    if tests:
        recommendations.append(
            f"Start with `{tests[0]['path']}` before broadening the test scope."
        )
    else:
        recommendations.append(
            f"Plan to run the full `{module}` addon suite because no explicit tests "
            "were discovered."
        )

    recommendations.append(
        f"Run `{prefix} agent validate-addon-change {module} --allow-mutation "
        "--install-if-needed --update --discover-tests` after editing."
    )
    recommendations.append(
        f"Run `{prefix} agent test-summary --allow-mutation --module {module} "
        f"--test-tags /{module}` for focused verification."
    )
    return recommendations


def agent_prepare_addon_change_command(  # noqa: C901
    ctx: Any,
    *,
    module: str,
    model: str | None,
    field_name: str | None,
    attributes: str | None,
    types: str | None,
    database: str | None,
    timeout: float,
    resolve_agent_global_config_fn: Any,
    parse_csv_items_fn: Any,
    parse_view_types_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_sub_result_fn: Any,
    odoo_operations_cls: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
    safe_read_only: str,
) -> None:
    """Bundle the common read-only planning steps for one addon change."""
    operation = "prepare_addon_change"
    result_type = "addon_change_context"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(
            operation,
            result_type,
            "No environment configuration available",
            error_type="ConfigError",
        )
    assert global_config.env_config is not None

    requested_attributes = parse_csv_items_fn(attributes)
    requested_view_types = parse_view_types_fn(types, operation, result_type)
    ops = odoo_operations_cls(global_config.env_config, verbose=False)

    steps: dict[str, dict[str, Any]] = {}
    completed_steps: list[str] = []
    soft_failed_steps: list[str] = []
    warnings: list[str] = []
    remediation: list[str] = []
    errors: list[dict[str, Any]] = []
    failed_step: str | None = None
    error: str | None = None
    error_type: str | None = None

    def record_step(
        step_name: str,
        step_result: dict[str, Any],
        *,
        blocking: bool = False,
        soft_failure_warning: str | None = None,
    ) -> None:
        nonlocal failed_step, error, error_type
        steps[step_name] = step_result
        if step_result.get("success", False):
            completed_steps.append(step_name)
        elif blocking and failed_step is None:
            failed_step = step_name
            error = step_result.get("error") or f"{step_name} failed"
            error_type = step_result.get("error_type") or "CommandError"
            errors.append(
                {
                    "step": step_name,
                    "message": error,
                    "error_type": error_type,
                }
            )
        elif not blocking:
            soft_failed_steps.append(step_name)
            warning_text = soft_failure_warning or step_result.get("error")
            if warning_text:
                warnings.append(str(warning_text))

        warnings.extend(step_result.get("warnings", []))
        remediation.extend(step_result.get("remediation", []))

    context = ops.get_environment_context(
        env_name=global_config.env_name,
        config_source=global_config.config_source,
        config_path=global_config.config_path,
        odoo_series=global_config.odoo_series,
    )
    record_step(
        "context",
        agent_sub_result_fn(
            success=True,
            data=context.to_dict(),
            warnings=list(context.warnings),
            remediation=list(context.remediation),
            read_only=True,
            safety_level=safe_read_only,
        ),
    )

    try:
        inspection = ops.inspect_addon(module, odoo_series=global_config.odoo_series)
        record_step(
            "inspect_addon",
            agent_sub_result_fn(
                success=True,
                data=inspection.to_dict(),
                warnings=list(inspection.warnings),
                remediation=list(inspection.remediation),
                read_only=True,
                safety_level=safe_read_only,
            ),
        )
    except module_not_found_error_cls as exc:
        record_step(
            "inspect_addon",
            agent_sub_result_fn(
                success=False,
                data={"module": module},
                error=str(exc),
                error_type="ModuleNotFoundError",
                remediation=[
                    "Verify that the addon exists in the configured addons paths.",
                    "Run `oduit agent context` to inspect the resolved addons paths.",
                ],
                read_only=True,
                safety_level=safe_read_only,
            ),
            blocking=True,
        )

    if failed_step is None:
        try:
            plan = ops.plan_update(module, odoo_series=global_config.odoo_series)
            record_step(
                "plan_update",
                agent_sub_result_fn(
                    success=True,
                    data=plan.to_dict(),
                    warnings=list(plan.warnings),
                    remediation=list(plan.remediation),
                    read_only=True,
                    safety_level=safe_read_only,
                ),
            )
        except module_not_found_error_cls as exc:
            record_step(
                "plan_update",
                agent_sub_result_fn(
                    success=False,
                    data={"module": module},
                    error=str(exc),
                    error_type="ModuleNotFoundError",
                    remediation=[
                        "Verify that the addon exists before planning the update.",
                    ],
                    read_only=True,
                    safety_level=safe_read_only,
                ),
                blocking=True,
            )

    if failed_step is None:
        try:
            addon_models = ops.list_addon_models(module)
            record_step(
                "list_addon_models",
                agent_sub_result_fn(
                    success=True,
                    data=addon_models.to_dict(),
                    warnings=list(addon_models.warnings),
                    remediation=list(addon_models.remediation),
                    read_only=True,
                    safety_level=safe_read_only,
                ),
            )
        except module_not_found_error_cls as exc:
            record_step(
                "list_addon_models",
                agent_sub_result_fn(
                    success=False,
                    data={"module": module},
                    error=str(exc),
                    error_type="ModuleNotFoundError",
                    remediation=_ADDON_NOT_FOUND_REMEDIATION,
                    read_only=True,
                    safety_level=safe_read_only,
                ),
                blocking=True,
            )
        except config_error_cls as exc:
            record_step(
                "list_addon_models",
                agent_sub_result_fn(
                    success=False,
                    data={"module": module},
                    error=str(exc),
                    error_type="ConfigError",
                    remediation=_ADDONS_PATH_REMEDIATION,
                    read_only=True,
                    safety_level=safe_read_only,
                ),
                blocking=True,
            )

    if failed_step is None:
        try:
            addon_tests = ops.list_addon_tests(
                module,
                model=model,
                field_name=field_name,
            )
            record_step(
                "list_addon_tests",
                agent_sub_result_fn(
                    success=True,
                    data=addon_tests.to_dict(),
                    warnings=list(addon_tests.warnings),
                    remediation=list(addon_tests.remediation),
                    read_only=True,
                    safety_level=safe_read_only,
                ),
            )
        except module_not_found_error_cls as exc:
            record_step(
                "list_addon_tests",
                agent_sub_result_fn(
                    success=False,
                    data={"module": module},
                    error=str(exc),
                    error_type="ModuleNotFoundError",
                    remediation=_ADDON_NOT_FOUND_REMEDIATION,
                    read_only=True,
                    safety_level=safe_read_only,
                ),
                blocking=True,
            )
        except config_error_cls as exc:
            record_step(
                "list_addon_tests",
                agent_sub_result_fn(
                    success=False,
                    data={"module": module},
                    error=str(exc),
                    error_type="ConfigError",
                    remediation=_ADDONS_PATH_REMEDIATION,
                    read_only=True,
                    safety_level=safe_read_only,
                ),
                blocking=True,
            )

    if model is None:
        steps["locate_model"] = _skipped_step(
            agent_sub_result_fn,
            reason="model_not_requested",
            module=module,
        )
        steps["locate_field"] = _skipped_step(
            agent_sub_result_fn,
            reason="model_not_requested",
            module=module,
        )
        steps["get_model_fields"] = _skipped_step(
            agent_sub_result_fn,
            reason="model_not_requested",
            module=module,
        )
        steps["get_model_views"] = _skipped_step(
            agent_sub_result_fn,
            reason="model_not_requested",
            module=module,
        )
    else:
        if failed_step is None:
            try:
                model_location = ops.locate_model(module, model)
                model_location_success = bool(model_location.candidates)
                record_step(
                    "locate_model",
                    agent_sub_result_fn(
                        success=model_location_success,
                        data=model_location.to_dict(),
                        warnings=list(model_location.warnings),
                        remediation=list(model_location.remediation),
                        error=(
                            None
                            if model_location_success
                            else (
                                f"No source candidates were found for model `{model}` "
                                f"in addon `{module}`."
                            )
                        ),
                        error_type=(
                            None if model_location_success else "ModelSourceNotFound"
                        ),
                        read_only=True,
                        safety_level=safe_read_only,
                    ),
                    blocking=not model_location_success,
                )
            except module_not_found_error_cls as exc:
                record_step(
                    "locate_model",
                    agent_sub_result_fn(
                        success=False,
                        data={"module": module, "model": model},
                        error=str(exc),
                        error_type="ModuleNotFoundError",
                        remediation=_ADDON_NOT_FOUND_REMEDIATION,
                        read_only=True,
                        safety_level=safe_read_only,
                    ),
                    blocking=True,
                )
            except config_error_cls as exc:
                record_step(
                    "locate_model",
                    agent_sub_result_fn(
                        success=False,
                        data={"module": module, "model": model},
                        error=str(exc),
                        error_type="ConfigError",
                        remediation=_ADDONS_PATH_REMEDIATION,
                        read_only=True,
                        safety_level=safe_read_only,
                    ),
                    blocking=True,
                )

        if field_name is None:
            steps["locate_field"] = _skipped_step(
                agent_sub_result_fn,
                reason="field_not_requested",
                module=module,
                model=model,
            )
        elif failed_step is None:
            try:
                field_location = ops.locate_field(module, model, field_name)
                field_location_success = field_location.exists or (
                    field_location.insertion_candidate is not None
                )
                record_step(
                    "locate_field",
                    agent_sub_result_fn(
                        success=field_location_success,
                        data=field_location.to_dict(),
                        warnings=list(field_location.warnings),
                        remediation=list(field_location.remediation),
                        error=(
                            None
                            if field_location_success
                            else (
                                "No field definition or insertion target was found for "
                                f"`{field_name}` on `{model}` in addon `{module}`."
                            )
                        ),
                        error_type=(
                            None if field_location_success else "FieldSourceNotFound"
                        ),
                        read_only=True,
                        safety_level=safe_read_only,
                    ),
                    blocking=not field_location_success,
                )
            except module_not_found_error_cls as exc:
                record_step(
                    "locate_field",
                    agent_sub_result_fn(
                        success=False,
                        data={"module": module, "model": model, "field": field_name},
                        error=str(exc),
                        error_type="ModuleNotFoundError",
                        remediation=_ADDON_NOT_FOUND_REMEDIATION,
                        read_only=True,
                        safety_level=safe_read_only,
                    ),
                    blocking=True,
                )
            except config_error_cls as exc:
                record_step(
                    "locate_field",
                    agent_sub_result_fn(
                        success=False,
                        data={"module": module, "model": model, "field": field_name},
                        error=str(exc),
                        error_type="ConfigError",
                        remediation=_ADDONS_PATH_REMEDIATION,
                        read_only=True,
                        safety_level=safe_read_only,
                    ),
                    blocking=True,
                )

        fields_result = ops.get_model_fields(
            model,
            attributes=requested_attributes,
            database=database,
            timeout=timeout,
        )
        record_step(
            "get_model_fields",
            agent_sub_result_fn(
                success=fields_result.success,
                data=fields_result.to_dict(),
                remediation=(
                    []
                    if fields_result.success
                    else [
                        "Verify database access and the model name, then retry the "
                        "field metadata query."
                    ]
                ),
                error=fields_result.error,
                error_type=fields_result.error_type,
                read_only=True,
                safety_level=safe_read_only,
            ),
            soft_failure_warning=(
                f"Model field metadata was unavailable for `{model}`."
                if not fields_result.success
                else None
            ),
        )

        views_result = ops.get_model_views(
            model,
            view_types=requested_view_types,
            database=database,
            timeout=timeout,
            include_arch=False,
        )
        views_success = views_result.error is None
        record_step(
            "get_model_views",
            agent_sub_result_fn(
                success=views_success,
                data={**views_result.to_dict(), "summary": True},
                warnings=list(views_result.warnings),
                remediation=list(views_result.remediation),
                error=views_result.error,
                error_type=views_result.error_type,
                read_only=True,
                safety_level=safe_read_only,
            ),
            soft_failure_warning=(
                f"Model view metadata was unavailable for `{model}`."
                if not views_success
                else None
            ),
        )

        if (
            failed_step is not None
            and field_name is not None
            and "locate_field" not in steps
        ):
            steps["locate_field"] = _skipped_step(
                agent_sub_result_fn,
                reason="skipped_after_failed_required_step",
                module=module,
                model=model,
                field=field_name,
            )

    payload = agent_payload_fn(
        operation,
        result_type,
        {
            "module": module,
            "model": model,
            "field": field_name,
            "requested_attributes": requested_attributes or [],
            "requested_view_types": requested_view_types or [],
            "database": database or global_config.env_config.get("db_name"),
            "timeout": timeout,
            "steps": steps,
            "completed_steps": completed_steps,
            "failed_step": failed_step,
            "soft_failed_steps": soft_failed_steps,
            "recommended_next_steps": _build_recommended_next_steps(
                env_name=global_config.env_name,
                module=module,
                model=model,
                field_name=field_name,
                steps=steps,
                failed_step=failed_step,
            ),
        },
        success=failed_step is None,
        warnings=_dedupe_strings(warnings),
        errors=errors,
        remediation=_dedupe_strings(remediation),
        read_only=True,
        safety_level=safe_read_only,
        error=error,
        error_type=error_type,
    )
    agent_emit_payload_fn(payload)
    if failed_step is not None:
        raise typer.Exit(1)
