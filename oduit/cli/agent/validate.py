"""Validation workflow commands for agent refactoring."""

import time
from typing import Any

import typer


def _duration_ms(started_at: float) -> int:
    """Return integer wall-clock duration in milliseconds."""
    return max(int((time.perf_counter() - started_at) * 1000), 0)


def _with_duration(sub_result: dict[str, Any], started_at: float) -> dict[str, Any]:
    """Attach duration metadata to one aggregate sub-result."""
    timed_result = dict(sub_result)
    timed_result["duration_ms"] = _duration_ms(started_at)
    return timed_result


def _summarize_sub_results(
    sub_results: dict[str, dict[str, Any]],
) -> tuple[
    list[str],
    list[dict[str, Any]],
    list[str],
    str | None,
    str | None,
]:
    """Collect warnings, blocking issues, and primary error details."""
    warnings: list[str] = []
    errors: list[dict[str, Any]] = []
    remediation: list[str] = []
    error = None
    error_type = None

    for step_name, step in sub_results.items():
        for warning in step.get("warnings", []):
            if warning not in warnings:
                warnings.append(warning)

        for item in step.get("remediation", []):
            if item not in remediation:
                remediation.append(item)

        if not step.get("success", False):
            step_error = step.get("error") or f"{step_name} failed"
            step_error_type = step.get("error_type") or "CommandError"
            errors.append(
                {
                    "step": step_name,
                    "message": step_error,
                    "error_type": step_error_type,
                }
            )
            if error is None:
                error = step_error
                error_type = step_error_type

    return warnings, errors, remediation, error, error_type


def build_preflight_addon_change_payload(
    module: str,
    *,
    model: str | None,
    field_name: str | None,
    installed_state: dict[str, Any] | None,
    sub_results: dict[str, dict[str, Any]],
    completed_steps: list[str],
    failed_step: str | None,
) -> tuple[
    dict[str, Any],
    bool,
    list[str],
    list[dict[str, Any]],
    list[str],
    str | None,
    str | None,
]:
    """Assemble the aggregate payload for read-only addon-change preflight."""
    warnings, errors, remediation, error, error_type = _summarize_sub_results(
        sub_results
    )
    success = failed_step is None and not errors
    payload_data = {
        "module": module,
        "model": model,
        "field": field_name,
        "installed_state": installed_state,
        "sub_results": sub_results,
        "ready_for_mutation": success,
        "preflight_summary": {
            "completed_steps": completed_steps,
            "failed_step": failed_step,
            "blocking_issues": errors,
            "warnings": warnings,
        },
    }
    return payload_data, success, warnings, errors, remediation, error, error_type


def build_validate_addon_change_payload(
    module: str,
    *,
    install_if_needed: bool,
    update: bool,
    resolved_test_tags: str | None,
    discover_tests: bool,
    installed_state: dict[str, Any] | None,
    mutation_action: dict[str, Any],
    sub_results: dict[str, dict[str, Any]],
    completed_steps: list[str],
    failed_step: str | None,
) -> tuple[
    dict[str, Any],
    bool,
    list[str],
    list[dict[str, Any]],
    list[str],
    str | None,
    str | None,
]:
    """Assemble the aggregate payload data for addon-change validation."""
    warnings, errors, remediation, error, error_type = _summarize_sub_results(
        sub_results
    )
    success = failed_step is None and not errors
    payload_data = {
        "module": module,
        "requested_actions": {
            "install_if_needed": install_if_needed,
            "update": update,
            "test_tags": resolved_test_tags,
            "discover_tests": discover_tests,
        },
        "installed_state": installed_state,
        "mutation_action": mutation_action,
        "sub_results": sub_results,
        "verification_summary": {
            "completed_steps": completed_steps,
            "failed_step": failed_step,
            "blocking_issues": errors,
            "warnings": warnings,
        },
    }
    return payload_data, success, warnings, errors, remediation, error, error_type


def run_validate_addon_change_preflight(
    ops: Any,
    global_config: Any,
    module: str,
    *,
    agent_sub_result_fn: Any,
    build_doctor_report_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> tuple[
    dict[str, dict[str, Any]],
    list[str],
    str | None,
    dict[str, Any] | None,
]:
    """Run inspect, doctor, duplicate, and installed-state checks."""
    sub_results: dict[str, dict[str, Any]] = {}
    completed_steps: list[str] = []
    failed_step: str | None = None
    installed_state: dict[str, Any] | None = None

    try:
        inspection_started = time.perf_counter()
        inspection = ops.inspect_addon(module, odoo_series=global_config.odoo_series)
        sub_results["inspection"] = _with_duration(
            agent_sub_result_fn(
                success=True,
                data=inspection.to_dict(),
                warnings=list(inspection.warnings),
                remediation=list(inspection.remediation),
            ),
            inspection_started,
        )
        completed_steps.append("inspection")
    except module_not_found_error_cls as exc:
        failed_step = "inspection"
        sub_results["inspection"] = _with_duration(
            agent_sub_result_fn(
                success=False,
                data={"module": module},
                error=str(exc),
                error_type="ModuleNotFoundError",
                remediation=[
                    "Verify that the addon exists in the configured addons paths.",
                    "Run `oduit agent context` to inspect the resolved addons paths.",
                ],
            ),
            inspection_started,
        )
        return sub_results, completed_steps, failed_step, installed_state

    doctor_started = time.perf_counter()
    doctor_report = build_doctor_report_fn(global_config)
    sub_results["doctor"] = _with_duration(
        agent_sub_result_fn(
            success=doctor_report.get("success", False),
            data={
                "source": doctor_report.get("source", {}),
                "checks": doctor_report.get("checks", []),
                "summary": doctor_report.get("summary", {}),
                "next_steps": doctor_report.get("next_steps", []),
            },
            warnings=list(doctor_report.get("warnings", [])),
            errors=list(doctor_report.get("errors", [])),
            remediation=list(doctor_report.get("remediation", [])),
            error=doctor_report.get("error"),
            error_type=doctor_report.get("error_type"),
        ),
        doctor_started,
    )
    completed_steps.append("doctor")
    if not doctor_report.get("success", False):
        return sub_results, completed_steps, "doctor", installed_state

    try:
        duplicates_started = time.perf_counter()
        duplicates = ops.list_duplicates()
    except config_error_cls as exc:
        sub_results["duplicates"] = _with_duration(
            agent_sub_result_fn(
                success=False,
                error=str(exc),
                error_type="ConfigError",
                remediation=[
                    "Set `addons_path` in the selected environment before retrying.",
                ],
            ),
            duplicates_started,
        )
        return sub_results, completed_steps, "duplicates", installed_state

    duplicate_warning = (
        ["Duplicate addon names can make module resolution ambiguous."]
        if duplicates
        else []
    )
    duplicate_remediation = (
        ["Remove or reorder duplicate addon paths before mutating modules."]
        if duplicates
        else []
    )
    target_module_duplicated = module in duplicates
    sub_results["duplicates"] = _with_duration(
        agent_sub_result_fn(
            success=not target_module_duplicated,
            data={
                "duplicate_modules": duplicates,
                "duplicate_count": len(duplicates),
                "target_module_duplicated": target_module_duplicated,
            },
            warnings=duplicate_warning,
            remediation=duplicate_remediation,
            error=(
                f"Module '{module}' is duplicated across addons paths"
                if target_module_duplicated
                else None
            ),
            error_type="DuplicateModuleError" if target_module_duplicated else None,
        ),
        duplicates_started,
    )
    completed_steps.append("duplicates")
    if target_module_duplicated:
        return sub_results, completed_steps, "duplicates", installed_state

    installed_state_started = time.perf_counter()
    state_result = ops.get_addon_install_state(module)
    if not state_result.success:
        sub_results["installed_state"] = _with_duration(
            agent_sub_result_fn(
                success=False,
                data={"module": module},
                error=state_result.error,
                error_type=state_result.error_type,
                remediation=[
                    "Verify database access and retry the module-state lookup.",
                ],
            ),
            installed_state_started,
        )
        return sub_results, completed_steps, "installed_state", installed_state

    installed_state = {
        "module": module,
        "record_found": state_result.record_found,
        "state": state_result.state,
        "installed": state_result.installed,
    }
    sub_results["installed_state"] = _with_duration(
        agent_sub_result_fn(
            success=True,
            data=installed_state,
        ),
        installed_state_started,
    )
    completed_steps.append("installed_state")
    return sub_results, completed_steps, None, installed_state


def build_validate_addon_change_discovery_result(
    ops: Any,
    module: str,
    *,
    discover_tests: bool,
    failed_step: str | None,
    agent_sub_result_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> tuple[dict[str, Any], str | None, bool]:
    """Build the optional discovered-test sub-result."""
    if not discover_tests:
        discovery_started = time.perf_counter()
        return (
            _with_duration(
                agent_sub_result_fn(
                    success=True,
                    data={
                        "module": module,
                        "requested": False,
                        "executed": False,
                    },
                    skipped=True,
                ),
                discovery_started,
            ),
            failed_step,
            False,
        )

    if failed_step is not None:
        discovery_started = time.perf_counter()
        return (
            _with_duration(
                agent_sub_result_fn(
                    success=True,
                    data={
                        "module": module,
                        "executed": False,
                        "reason": "skipped_after_failed_required_step",
                    },
                    skipped=True,
                ),
                discovery_started,
            ),
            failed_step,
            False,
        )

    try:
        discovery_started = time.perf_counter()
        inventory = ops.list_addon_tests(module)
    except (module_not_found_error_cls, config_error_cls) as exc:
        return (
            _with_duration(
                agent_sub_result_fn(
                    success=False,
                    data={"module": module},
                    error=str(exc),
                    error_type=(
                        "ModuleNotFoundError"
                        if isinstance(exc, module_not_found_error_cls)
                        else "ConfigError"
                    ),
                    remediation=[
                        "Verify the addon path and test discovery inputs before "
                        "retrying.",
                    ],
                ),
                discovery_started,
            ),
            "discovered_tests",
            False,
        )

    discovery_remediation = list(inventory.remediation)
    discovery_remediation.append(
        "Run a specific discovered test file only when you need narrower "
        "reproduction than the full module suite."
    )
    return (
        _with_duration(
            agent_sub_result_fn(
                success=True,
                data={
                    **inventory.to_dict(),
                    "executed": False,
                    "execution_strategy": "inventory_only",
                    "reason": "full_module_suite_already_ran",
                },
                warnings=list(inventory.warnings),
                remediation=list(dict.fromkeys(discovery_remediation)),
            ),
            discovery_started,
        ),
        None,
        True,
    )


def agent_preflight_addon_change_command(
    ctx: typer.Context,
    *,
    module: str,
    model: str | None,
    field_name: str | None,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_sub_result_fn: Any,
    build_preflight_addon_change_payload_fn: Any,
    run_validate_addon_change_preflight_fn: Any,
    build_doctor_report_fn: Any,
    odoo_operations_cls: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
    safe_read_only: str,
) -> None:
    """Run a cheap read-only addon-change preflight payload."""
    operation = "preflight_addon_change"
    result_type = "addon_change_preflight"
    if field_name is not None and model is None:
        agent_fail_fn(
            operation,
            result_type,
            "`--field` requires `--model`.",
            error_type="ValidationError",
            remediation=[
                "Pass `--model <model_name>` together with `--field <field_name>`.",
            ],
        )

    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    sub_results, completed_steps, failed_step, installed_state = (
        run_validate_addon_change_preflight_fn(
            ops,
            global_config,
            module,
            agent_sub_result_fn=agent_sub_result_fn,
            build_doctor_report_fn=build_doctor_report_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
        )
    )

    if failed_step is None:
        discovery_started = time.perf_counter()
        try:
            if model is not None and field_name is not None:
                source_step = "field_source"
                source_result = ops.locate_field(module, model, field_name)
            elif model is not None:
                source_step = "model_source"
                source_result = ops.locate_model(module, model)
            else:
                source_step = "addon_models"
                source_result = ops.list_addon_models(module)
            sub_results[source_step] = _with_duration(
                agent_sub_result_fn(
                    success=True,
                    data=source_result.to_dict(),
                    warnings=list(source_result.warnings),
                    remediation=list(source_result.remediation),
                ),
                discovery_started,
            )
            completed_steps.append(source_step)
        except (module_not_found_error_cls, config_error_cls) as exc:
            failed_step = source_step
            sub_results[source_step] = _with_duration(
                agent_sub_result_fn(
                    success=False,
                    data={"module": module, "model": model, "field": field_name},
                    error=str(exc),
                    error_type=(
                        "ModuleNotFoundError"
                        if isinstance(exc, module_not_found_error_cls)
                        else "ConfigError"
                    ),
                    remediation=[
                        "Verify the addon path and discovery hints before retrying.",
                    ],
                ),
                discovery_started,
            )

    if failed_step is None:
        tests_started = time.perf_counter()
        try:
            test_inventory = ops.list_addon_tests(
                module,
                model=model,
                field_name=field_name,
            )
            sub_results["addon_tests"] = _with_duration(
                agent_sub_result_fn(
                    success=True,
                    data=test_inventory.to_dict(),
                    warnings=list(test_inventory.warnings),
                    remediation=list(test_inventory.remediation),
                ),
                tests_started,
            )
            completed_steps.append("addon_tests")
        except (module_not_found_error_cls, config_error_cls) as exc:
            failed_step = "addon_tests"
            sub_results["addon_tests"] = _with_duration(
                agent_sub_result_fn(
                    success=False,
                    data={"module": module, "model": model, "field": field_name},
                    error=str(exc),
                    error_type=(
                        "ModuleNotFoundError"
                        if isinstance(exc, module_not_found_error_cls)
                        else "ConfigError"
                    ),
                    remediation=[
                        "Verify the addon path and test discovery hints before "
                        "retrying.",
                    ],
                ),
                tests_started,
            )

    payload_data, success, warnings, errors, remediation, error, error_type = (
        build_preflight_addon_change_payload_fn(
            module,
            model=model,
            field_name=field_name,
            installed_state=installed_state,
            sub_results=sub_results,
            completed_steps=completed_steps,
            failed_step=failed_step,
        )
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        payload_data,
        success=success,
        warnings=warnings,
        errors=errors,
        remediation=remediation,
        read_only=True,
        safety_level=safe_read_only,
        error=error,
        error_type=error_type,
    )
    agent_emit_payload_fn(payload)
    if not success:
        raise typer.Exit(1)


def agent_validate_addon_change_command(
    ctx: typer.Context,
    *,
    module: str,
    allow_mutation: bool,
    install_if_needed: bool,
    update: bool,
    test_tags: str | None,
    discover_tests: bool,
    stop_on_error: bool,
    compact: bool,
    log_level: Any,
    resolve_agent_global_config_fn: Any,
    agent_fail_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    agent_require_mutation_fn: Any,
    agent_require_runtime_db_mutation_fn: Any,
    agent_sub_result_fn: Any,
    build_agent_test_summary_details_fn: Any,
    build_validate_addon_change_payload_fn: Any,
    run_validate_addon_change_preflight_fn: Any,
    build_validate_addon_change_discovery_result_fn: Any,
    build_doctor_report_fn: Any,
    odoo_operations_cls: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
    controlled_runtime_mutation: str,
) -> None:
    """Validate an addon change with one aggregate structured payload."""
    operation = "validate_addon_change"
    result_type = "addon_change_validation"
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        agent_fail_fn(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    agent_require_runtime_db_mutation_fn(
        global_config.env_config,
        allow_mutation=allow_mutation,
        operation=operation,
        result_type=result_type,
        action="addon change validation",
        safety_level=controlled_runtime_mutation,
    )

    ops = odoo_operations_cls(global_config.env_config, verbose=False)
    resolved_test_tags = test_tags or f"/{module}"
    mutation_action = {"action": "none", "performed": False}
    sub_results, completed_steps, failed_step, installed_state = (
        run_validate_addon_change_preflight_fn(
            ops,
            global_config,
            module,
            agent_sub_result_fn=agent_sub_result_fn,
            build_doctor_report_fn=build_doctor_report_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
        )
    )

    if failed_step is None:
        assert installed_state is not None
        should_install = install_if_needed and not installed_state["installed"]
        should_update = update and not should_install
        if should_install:
            module_action_started = time.perf_counter()
            result = ops.install_module(
                module,
                no_http=global_config.no_http,
                suppress_output=True,
                compact=compact,
                max_cron_threads=None,
                without_demo=False,
                language=None,
                with_demo=False,
                log_level=log_level.value if log_level else None,
            )
            mutation_action = {
                "action": "install",
                "performed": True,
                "reason": "module_not_installed",
            }
        elif should_update:
            module_action_started = time.perf_counter()
            result = ops.update_module(
                module,
                no_http=global_config.no_http,
                suppress_output=True,
                compact=compact,
                log_level=log_level.value if log_level else None,
                max_cron_threads=None,
                without_demo=False,
                language=None,
                i18n_overwrite=False,
            )
            mutation_action = {
                "action": "update",
                "performed": True,
                "reason": "update_requested",
            }
        else:
            module_action_started = time.perf_counter()
            result = None
            mutation_action = {
                "action": "none",
                "performed": False,
                "reason": (
                    "module_already_installed"
                    if install_if_needed and installed_state["installed"]
                    else "no_runtime_mutation_requested"
                ),
            }

        if result is None:
            sub_results["module_action"] = _with_duration(
                agent_sub_result_fn(
                    success=True,
                    data=mutation_action,
                    skipped=True,
                ),
                module_action_started,
            )
        else:
            action_success = bool(result.get("success", False))
            remediation = (
                ["Inspect the module-action error before retrying verification."]
                if not action_success
                else []
            )
            sub_results["module_action"] = _with_duration(
                agent_sub_result_fn(
                    success=action_success,
                    data={
                        **result,
                        **mutation_action,
                    },
                    remediation=remediation,
                    error=result.get("error"),
                    error_type=result.get("error_type"),
                    read_only=False,
                    safety_level=controlled_runtime_mutation,
                ),
                module_action_started,
            )
            if not action_success:
                failed_step = "module_action"
        completed_steps.append("module_action")

    if failed_step is None:
        module_tests_started = time.perf_counter()
        test_result = ops.run_tests(
            module=module,
            stop_on_error=stop_on_error,
            install=None,
            update=None,
            coverage=None,
            test_file=None,
            test_tags=resolved_test_tags,
            compact=compact,
            suppress_output=True,
            log_level=log_level.value if log_level else None,
        )
        test_data, test_warnings, test_remediation = (
            build_agent_test_summary_details_fn(
                test_result,
                module=module,
                install=None,
                update=None,
                coverage=None,
                test_file=None,
                test_tags=resolved_test_tags,
            )
        )
        sub_results["module_tests"] = _with_duration(
            agent_sub_result_fn(
                success=bool(test_result.get("success", False)),
                data=test_data,
                warnings=test_warnings,
                remediation=test_remediation,
                error=test_result.get("error"),
                error_type=test_result.get("error_type"),
                read_only=False,
                safety_level=controlled_runtime_mutation,
            ),
            module_tests_started,
        )
        completed_steps.append("module_tests")
        if not test_result.get("success", False):
            failed_step = "module_tests"

    discovery_result, discovery_failed_step, discovery_completed = (
        build_validate_addon_change_discovery_result_fn(
            ops,
            module,
            discover_tests=discover_tests,
            failed_step=failed_step,
            agent_sub_result_fn=agent_sub_result_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
        )
    )
    sub_results["discovered_tests"] = discovery_result
    if discovery_completed:
        completed_steps.append("discovered_tests")
    if discovery_failed_step is not None:
        failed_step = discovery_failed_step

    payload_data, success, warnings, errors, remediation, error, error_type = (
        build_validate_addon_change_payload_fn(
            module,
            install_if_needed=install_if_needed,
            update=update,
            resolved_test_tags=resolved_test_tags,
            discover_tests=discover_tests,
            installed_state=installed_state,
            mutation_action=mutation_action,
            sub_results=sub_results,
            completed_steps=completed_steps,
            failed_step=failed_step,
        )
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        payload_data,
        success=success,
        warnings=warnings,
        errors=errors,
        remediation=remediation,
        read_only=False,
        safety_level=controlled_runtime_mutation,
        error=error,
        error_type=error_type,
    )
    agent_emit_payload_fn(payload)
    if not success:
        raise typer.Exit(1)
