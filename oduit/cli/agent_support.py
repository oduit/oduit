"""Agent helper wrappers for the Typer composition root."""

from typing import Any, NoReturn

from ..cli_types import GlobalConfig


def agent_fail(
    operation: str,
    result_type: str,
    message: str,
    *,
    fail_impl_fn: Any,
    emit_payload_fn: Any,
    error_type: str = "CommandError",
    details: dict[str, Any] | None = None,
    remediation: list[str] | None = None,
    read_only: bool = True,
    safety_level: str,
) -> NoReturn:
    """Emit a structured agent error payload and exit."""
    fail_impl_fn(
        operation,
        result_type,
        message,
        error_type=error_type,
        details=details,
        remediation=remediation,
        read_only=read_only,
        safety_level=safety_level,
        emit_payload_fn=emit_payload_fn,
    )
    raise AssertionError("unreachable")


def build_error_output_excerpt(
    result: dict[str, Any],
    *,
    build_error_output_excerpt_fn: Any,
    max_lines: int = 80,
    max_chars: int = 12000,
) -> list[str]:
    """Return a bounded tail excerpt from captured process output."""
    return build_error_output_excerpt_fn(
        result, max_lines=max_lines, max_chars=max_chars
    )


def resolve_agent_global_config(
    ctx: Any,
    operation: str,
    result_type: str,
    *,
    resolve_agent_global_config_fn: Any,
    configure_output_fn: Any,
    fail_fn: Any,
    config_loader_cls: Any,
    resolve_config_source_fn: Any,
) -> GlobalConfig:
    """Resolve configuration for agent commands without text output."""
    return resolve_agent_global_config_fn(
        ctx,
        operation,
        result_type,
        configure_output_fn=configure_output_fn,
        fail_fn=fail_fn,
        config_loader_cls=config_loader_cls,
        resolve_config_source_fn=resolve_config_source_fn,
    )


def parse_view_types(
    raw_value: str | None,
    operation: str,
    result_type: str,
    *,
    parse_view_types_fn: Any,
    fail_fn: Any,
) -> list[str] | None:
    """Parse and validate requested Odoo view types."""
    return parse_view_types_fn(
        raw_value,
        operation,
        result_type,
        fail_fn=fail_fn,
    )


def parse_json_list_option(
    raw_value: str | None,
    option_name: str,
    operation: str,
    result_type: str,
    *,
    parse_json_list_option_fn: Any,
    fail_fn: Any,
) -> list[Any]:
    """Parse a JSON-encoded list option or emit a structured error."""
    return parse_json_list_option_fn(
        raw_value,
        option_name,
        operation,
        result_type,
        fail_fn=fail_fn,
    )


def resolve_agent_ops(
    ctx: Any,
    operation: str,
    result_type: str,
    *,
    resolve_agent_ops_fn: Any,
    resolve_agent_global_config_fn: Any,
    fail_fn: Any,
    odoo_operations_cls: Any,
) -> tuple[GlobalConfig, Any]:
    """Resolve agent config and instantiate operations."""
    return resolve_agent_ops_fn(
        ctx,
        operation,
        result_type,
        resolve_agent_global_config_fn=resolve_agent_global_config_fn,
        fail_fn=fail_fn,
        odoo_operations_cls=odoo_operations_cls,
    )


def require_agent_addons_path(
    env_config: dict[str, Any],
    operation: str,
    result_type: str,
    *,
    require_agent_addons_path_fn: Any,
    fail_fn: Any,
) -> str:
    """Return ``addons_path`` or emit a structured config error."""
    return require_agent_addons_path_fn(
        env_config,
        operation,
        result_type,
        fail_fn=fail_fn,
    )


def agent_require_mutation(
    allow_mutation: bool,
    operation: str,
    result_type: str,
    action: str,
    safety_level: str,
    *,
    agent_require_mutation_fn: Any,
    fail_fn: Any,
) -> None:
    """Enforce an explicit allow-mutation gate for agent commands."""
    agent_require_mutation_fn(
        allow_mutation,
        operation,
        result_type,
        action,
        safety_level,
        fail_fn=fail_fn,
    )


def build_agent_test_summary_details(
    result: dict[str, Any],
    *,
    module: str | None,
    install: str | None,
    update: str | None,
    coverage: str | None,
    test_file: str | None,
    test_tags: str | None,
    build_agent_test_summary_details_fn: Any,
    build_error_output_excerpt_fn: Any,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Normalize ``run_tests()`` output for agent-facing summaries."""
    return build_agent_test_summary_details_fn(
        result,
        module=module,
        install=install,
        update=update,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
        build_error_output_excerpt_fn=build_error_output_excerpt_fn,
    )


def build_validate_addon_change_payload(
    module: str,
    *,
    build_validate_addon_change_payload_fn: Any,
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
    """Assemble aggregate payload data for addon-change validation."""
    return build_validate_addon_change_payload_fn(
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


def run_validate_addon_change_preflight(
    ops: Any,
    global_config: GlobalConfig,
    module: str,
    *,
    run_validate_addon_change_preflight_fn: Any,
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
    return run_validate_addon_change_preflight_fn(
        ops,
        global_config,
        module,
        agent_sub_result_fn=agent_sub_result_fn,
        build_doctor_report_fn=build_doctor_report_fn,
        module_not_found_error_cls=module_not_found_error_cls,
        config_error_cls=config_error_cls,
    )


def build_validate_addon_change_discovery_result(
    ops: Any,
    module: str,
    *,
    build_validate_addon_change_discovery_result_fn: Any,
    discover_tests: bool,
    failed_step: str | None,
    agent_sub_result_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> tuple[dict[str, Any], str | None, bool]:
    """Build the optional discovered-test sub-result."""
    return build_validate_addon_change_discovery_result_fn(
        ops,
        module,
        discover_tests=discover_tests,
        failed_step=failed_step,
        agent_sub_result_fn=agent_sub_result_fn,
        module_not_found_error_cls=module_not_found_error_cls,
        config_error_cls=config_error_cls,
    )


def build_registration_helpers(
    *,
    safe_read_only: str,
    fail_impl_fn: Any,
    emit_payload_fn: Any,
    resolve_agent_global_config_impl_fn: Any,
    configure_output_fn: Any,
    get_config_loader_cls: Any,
    resolve_config_source_fn: Any,
    parse_view_types_impl_fn: Any,
    parse_json_list_option_impl_fn: Any,
    resolve_agent_ops_impl_fn: Any,
    get_odoo_operations_cls: Any,
    require_agent_addons_path_impl_fn: Any,
    agent_require_mutation_impl_fn: Any,
    build_error_output_excerpt_impl_fn: Any,
    build_agent_test_summary_details_impl_fn: Any,
    build_validate_addon_change_payload_impl_fn: Any,
    run_validate_addon_change_preflight_impl_fn: Any,
    build_validate_addon_change_discovery_result_impl_fn: Any,
    agent_sub_result_impl_fn: Any,
    build_doctor_report_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> dict[str, Any]:
    """Build agent helper callables for CLI registration wiring."""

    def agent_fail_fn(
        operation: str,
        result_type: str,
        message: str,
        error_type: str = "CommandError",
        details: dict[str, Any] | None = None,
        remediation: list[str] | None = None,
        read_only: bool = True,
        safety_level: str = safe_read_only,
    ) -> NoReturn:
        return agent_fail(
            operation,
            result_type,
            message,
            fail_impl_fn=fail_impl_fn,
            emit_payload_fn=emit_payload_fn,
            error_type=error_type,
            details=details,
            remediation=remediation,
            read_only=read_only,
            safety_level=safety_level,
        )

    def build_error_output_excerpt_fn(
        result: dict[str, Any],
        *,
        max_lines: int = 80,
        max_chars: int = 12000,
    ) -> list[str]:
        return build_error_output_excerpt(
            result,
            build_error_output_excerpt_fn=build_error_output_excerpt_impl_fn,
            max_lines=max_lines,
            max_chars=max_chars,
        )

    def resolve_agent_global_config_fn(
        ctx: Any,
        operation: str,
        result_type: str,
    ) -> GlobalConfig:
        return resolve_agent_global_config(
            ctx,
            operation,
            result_type,
            resolve_agent_global_config_fn=resolve_agent_global_config_impl_fn,
            configure_output_fn=configure_output_fn,
            fail_fn=agent_fail_fn,
            config_loader_cls=get_config_loader_cls(),
            resolve_config_source_fn=resolve_config_source_fn,
        )

    def parse_view_types_fn(
        raw_value: str | None,
        operation: str,
        result_type: str,
    ) -> list[str] | None:
        return parse_view_types(
            raw_value,
            operation,
            result_type,
            parse_view_types_fn=parse_view_types_impl_fn,
            fail_fn=agent_fail_fn,
        )

    def parse_json_list_option_fn(
        raw_value: str | None,
        option_name: str,
        operation: str,
        result_type: str,
    ) -> list[Any]:
        return parse_json_list_option(
            raw_value,
            option_name,
            operation,
            result_type,
            parse_json_list_option_fn=parse_json_list_option_impl_fn,
            fail_fn=agent_fail_fn,
        )

    def resolve_agent_ops_fn(
        ctx: Any,
        operation: str,
        result_type: str,
    ) -> tuple[GlobalConfig, Any]:
        return resolve_agent_ops(
            ctx,
            operation,
            result_type,
            resolve_agent_ops_fn=resolve_agent_ops_impl_fn,
            resolve_agent_global_config_fn=resolve_agent_global_config_fn,
            fail_fn=agent_fail_fn,
            odoo_operations_cls=get_odoo_operations_cls(),
        )

    def require_agent_addons_path_fn(
        env_config: dict[str, Any],
        operation: str,
        result_type: str,
    ) -> str:
        return require_agent_addons_path(
            env_config,
            operation,
            result_type,
            require_agent_addons_path_fn=require_agent_addons_path_impl_fn,
            fail_fn=agent_fail_fn,
        )

    def agent_require_mutation_fn(
        allow_mutation: bool,
        operation: str,
        result_type: str,
        action: str,
        safety_level: str,
    ) -> None:
        agent_require_mutation(
            allow_mutation,
            operation,
            result_type,
            action,
            safety_level,
            agent_require_mutation_fn=agent_require_mutation_impl_fn,
            fail_fn=agent_fail_fn,
        )

    def build_agent_test_summary_details_fn(
        result: dict[str, Any],
        *,
        module: str | None,
        install: str | None,
        update: str | None,
        coverage: str | None,
        test_file: str | None,
        test_tags: str | None,
    ) -> tuple[dict[str, Any], list[str], list[str]]:
        return build_agent_test_summary_details(
            result,
            module=module,
            install=install,
            update=update,
            coverage=coverage,
            test_file=test_file,
            test_tags=test_tags,
            build_agent_test_summary_details_fn=(
                build_agent_test_summary_details_impl_fn
            ),
            build_error_output_excerpt_fn=build_error_output_excerpt_fn,
        )

    def build_validate_addon_change_payload_fn(
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
        return build_validate_addon_change_payload(
            module,
            build_validate_addon_change_payload_fn=(
                build_validate_addon_change_payload_impl_fn
            ),
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

    def run_validate_addon_change_preflight_fn(
        ops: Any,
        global_config: GlobalConfig,
        module: str,
        *,
        agent_sub_result_fn: Any = agent_sub_result_impl_fn,
        build_doctor_report_fn: Any = build_doctor_report_fn,
        module_not_found_error_cls: Any = module_not_found_error_cls,
        config_error_cls: Any = config_error_cls,
    ) -> tuple[
        dict[str, dict[str, Any]],
        list[str],
        str | None,
        dict[str, Any] | None,
    ]:
        return run_validate_addon_change_preflight(
            ops,
            global_config,
            module,
            run_validate_addon_change_preflight_fn=(
                run_validate_addon_change_preflight_impl_fn
            ),
            agent_sub_result_fn=agent_sub_result_fn,
            build_doctor_report_fn=build_doctor_report_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
        )

    def build_validate_addon_change_discovery_result_fn(
        ops: Any,
        module: str,
        *,
        discover_tests: bool,
        failed_step: str | None,
        agent_sub_result_fn: Any = agent_sub_result_impl_fn,
        module_not_found_error_cls: Any = module_not_found_error_cls,
        config_error_cls: Any = config_error_cls,
    ) -> tuple[dict[str, Any], str | None, bool]:
        return build_validate_addon_change_discovery_result(
            ops,
            module,
            build_validate_addon_change_discovery_result_fn=(
                build_validate_addon_change_discovery_result_impl_fn
            ),
            discover_tests=discover_tests,
            failed_step=failed_step,
            agent_sub_result_fn=agent_sub_result_fn,
            module_not_found_error_cls=module_not_found_error_cls,
            config_error_cls=config_error_cls,
        )

    return {
        "agent_fail_fn": agent_fail_fn,
        "resolve_agent_global_config_fn": resolve_agent_global_config_fn,
        "parse_view_types_fn": parse_view_types_fn,
        "parse_json_list_option_fn": parse_json_list_option_fn,
        "resolve_agent_ops_fn": resolve_agent_ops_fn,
        "require_agent_addons_path_fn": require_agent_addons_path_fn,
        "agent_require_mutation_fn": agent_require_mutation_fn,
        "build_agent_test_summary_details_fn": build_agent_test_summary_details_fn,
        "build_validate_addon_change_payload_fn": (
            build_validate_addon_change_payload_fn
        ),
        "run_validate_addon_change_preflight_fn": (
            run_validate_addon_change_preflight_fn
        ),
        "build_validate_addon_change_discovery_result_fn": (
            build_validate_addon_change_discovery_result_fn
        ),
    }
