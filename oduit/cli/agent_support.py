"""Compatibility exports and binding helpers for agent CLI composition."""

from typing import Any, NoReturn, cast

from ..cli_types import GlobalConfig
from ..mutation_policy import require_agent_runtime_db_mutation
from .agent.payloads import (
    agent_fail,
    build_error_output_excerpt,
    parse_json_list_option,
    parse_view_types,
)
from .agent.services import (
    agent_require_mutation,
    build_agent_test_summary_details,
    require_agent_addons_path,
    resolve_agent_global_config,
    resolve_agent_ops,
)
from .agent.validate import (
    build_validate_addon_change_discovery_result,
    build_validate_addon_change_payload,
    run_validate_addon_change_preflight,
)
from .runtime_context import AgentHelperContext

__all__ = [
    "agent_fail",
    "build_error_output_excerpt",
    "parse_json_list_option",
    "parse_view_types",
    "agent_require_mutation",
    "require_agent_runtime_db_mutation",
    "build_agent_test_summary_details",
    "require_agent_addons_path",
    "resolve_agent_global_config",
    "resolve_agent_ops",
    "build_validate_addon_change_discovery_result",
    "build_validate_addon_change_payload",
    "run_validate_addon_change_preflight",
    "build_registration_helpers",
]


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
    agent_require_runtime_db_mutation_impl_fn: Any,
    build_error_output_excerpt_impl_fn: Any,
    build_agent_test_summary_details_impl_fn: Any,
    build_validate_addon_change_payload_impl_fn: Any,
    run_validate_addon_change_preflight_impl_fn: Any,
    build_validate_addon_change_discovery_result_impl_fn: Any,
    agent_sub_result_impl_fn: Any,
    build_doctor_report_fn: Any,
    module_not_found_error_cls: Any,
    config_error_cls: Any,
) -> AgentHelperContext:
    """Bind implementation dependencies for agent command registration."""

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

    def resolve_agent_global_config_fn(
        ctx: Any,
        operation: str,
        result_type: str,
    ) -> GlobalConfig:
        return cast(
            GlobalConfig,
            resolve_agent_global_config_impl_fn(
                ctx,
                operation,
                result_type,
                configure_output_fn=configure_output_fn,
                fail_fn=agent_fail_fn,
                config_loader_cls=get_config_loader_cls(),
                resolve_config_source_fn=resolve_config_source_fn,
            ),
        )

    def parse_view_types_fn(
        raw_value: str | None,
        operation: str,
        result_type: str,
    ) -> list[str] | None:
        return cast(
            list[str] | None,
            parse_view_types_impl_fn(
                raw_value,
                operation,
                result_type,
                fail_fn=agent_fail_fn,
            ),
        )

    def parse_json_list_option_fn(
        raw_value: str | None,
        option_name: str,
        operation: str,
        result_type: str,
    ) -> list[Any]:
        return cast(
            list[Any],
            parse_json_list_option_impl_fn(
                raw_value,
                option_name,
                operation,
                result_type,
                fail_fn=agent_fail_fn,
            ),
        )

    def resolve_agent_ops_fn(
        ctx: Any,
        operation: str,
        result_type: str,
    ) -> tuple[GlobalConfig, Any]:
        return cast(
            tuple[GlobalConfig, Any],
            resolve_agent_ops_impl_fn(
                ctx,
                operation,
                result_type,
                resolve_agent_global_config_fn=resolve_agent_global_config_fn,
                fail_fn=agent_fail_fn,
                odoo_operations_cls=get_odoo_operations_cls(),
            ),
        )

    def require_agent_addons_path_fn(
        env_config: dict[str, Any],
        operation: str,
        result_type: str,
    ) -> str:
        return cast(
            str,
            require_agent_addons_path_impl_fn(
                env_config,
                operation,
                result_type,
                fail_fn=agent_fail_fn,
            ),
        )

    def agent_require_mutation_fn(
        allow_mutation: bool,
        operation: str,
        result_type: str,
        action: str,
        safety_level: str,
    ) -> None:
        agent_require_mutation_impl_fn(
            allow_mutation,
            operation,
            result_type,
            action,
            safety_level,
            fail_fn=agent_fail_fn,
        )

    def agent_require_runtime_db_mutation_fn(
        env_config: dict[str, Any],
        *,
        allow_mutation: bool,
        operation: str,
        result_type: str,
        action: str,
        safety_level: str,
    ) -> None:
        agent_require_runtime_db_mutation_impl_fn(
            env_config=env_config,
            allow_mutation=allow_mutation,
            operation=operation,
            result_type=result_type,
            action=action,
            safety_level=safety_level,
            fail_fn=agent_fail_fn,
        )

    def build_error_output_excerpt_fn(
        result: dict[str, Any],
        *,
        max_lines: int = 80,
        max_chars: int = 12000,
    ) -> list[str]:
        return cast(
            list[str],
            build_error_output_excerpt_impl_fn(
                result,
                max_lines=max_lines,
                max_chars=max_chars,
            ),
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
        return cast(
            tuple[dict[str, Any], list[str], list[str]],
            build_agent_test_summary_details_impl_fn(
                result,
                module=module,
                install=install,
                update=update,
                coverage=coverage,
                test_file=test_file,
                test_tags=test_tags,
                build_error_output_excerpt_fn=build_error_output_excerpt_fn,
            ),
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
        return cast(
            tuple[
                dict[str, Any],
                bool,
                list[str],
                list[dict[str, Any]],
                list[str],
                str | None,
                str | None,
            ],
            build_validate_addon_change_payload_impl_fn(
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
            ),
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
        return cast(
            tuple[
                dict[str, dict[str, Any]],
                list[str],
                str | None,
                dict[str, Any] | None,
            ],
            run_validate_addon_change_preflight_impl_fn(
                ops,
                global_config,
                module,
                agent_sub_result_fn=agent_sub_result_fn,
                build_doctor_report_fn=build_doctor_report_fn,
                module_not_found_error_cls=module_not_found_error_cls,
                config_error_cls=config_error_cls,
            ),
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
        return cast(
            tuple[dict[str, Any], str | None, bool],
            build_validate_addon_change_discovery_result_impl_fn(
                ops,
                module,
                discover_tests=discover_tests,
                failed_step=failed_step,
                agent_sub_result_fn=agent_sub_result_fn,
                module_not_found_error_cls=module_not_found_error_cls,
                config_error_cls=config_error_cls,
            ),
        )

    return AgentHelperContext(
        agent_fail_fn=agent_fail_fn,
        resolve_agent_global_config_fn=resolve_agent_global_config_fn,
        parse_view_types_fn=parse_view_types_fn,
        parse_json_list_option_fn=parse_json_list_option_fn,
        resolve_agent_ops_fn=resolve_agent_ops_fn,
        require_agent_addons_path_fn=require_agent_addons_path_fn,
        agent_require_mutation_fn=agent_require_mutation_fn,
        agent_require_runtime_db_mutation_fn=agent_require_runtime_db_mutation_fn,
        build_agent_test_summary_details_fn=build_agent_test_summary_details_fn,
        build_validate_addon_change_payload_fn=build_validate_addon_change_payload_fn,
        run_validate_addon_change_preflight_fn=run_validate_addon_change_preflight_fn,
        build_validate_addon_change_discovery_result_fn=(
            build_validate_addon_change_discovery_result_fn
        ),
    )
