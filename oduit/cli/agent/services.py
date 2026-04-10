"""Shared orchestration helpers for agent command modules."""

from dataclasses import replace
from typing import Any

import typer

from ...cli_types import GlobalConfig, OutputFormat
from ...schemas import SAFE_READ_ONLY


def resolve_agent_global_config(
    ctx: typer.Context,
    operation: str,
    result_type: str,
    *,
    configure_output_fn: Any,
    fail_fn: Any,
    config_loader_cls: Any,
    resolve_config_source_fn: Any,
) -> GlobalConfig:
    """Resolve configuration for agent commands without text output."""
    configure_output_fn(format_type=OutputFormat.JSON.value, non_interactive=True)
    if ctx.obj is None:
        fail_fn(
            operation,
            result_type,
            "No global configuration found",
            remediation=[
                "Pass `--env <name>` or run the command from a directory "
                "with `.oduit.toml`.",
            ],
        )

    if isinstance(ctx.obj, GlobalConfig):
        return replace(
            ctx.obj,
            format=OutputFormat.JSON,
            verbose=False,
            non_interactive=True,
        )

    options = dict(ctx.obj)
    env = options.get("env")
    no_http = bool(options.get("no_http", False))
    odoo_series = options.get("odoo_series")
    config_loader = config_loader_cls()

    env_config = None
    env_name = None
    try:
        if env is None:
            if not config_loader.has_local_config():
                fail_fn(
                    operation,
                    result_type,
                    "No environment specified and no .oduit.toml found in "
                    "current directory",
                    error_type="ConfigError",
                    remediation=[
                        "Pass `--env <name>` to select a named environment.",
                        "Or create a local `.oduit.toml` file in the current "
                        "directory.",
                    ],
                )
            env_config = config_loader.load_local_config()
            env_name = "local"
        else:
            env_name = str(env).strip()
            env_config = config_loader.load_config(env_name)
    except (FileNotFoundError, ImportError, ValueError) as exc:
        fail_fn(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            remediation=[
                "Verify the requested environment exists and the config file is valid.",
            ],
        )
    except Exception as exc:
        fail_fn(
            operation,
            result_type,
            f"Error loading environment '{env_name or 'local'}': {exc}",
            error_type="ConfigError",
            remediation=[
                "Check the environment configuration and try again.",
            ],
        )

    config_source, config_path = resolve_config_source_fn(
        config_loader, env, env_config
    )
    return GlobalConfig(
        env=env,
        non_interactive=True,
        format=OutputFormat.JSON,
        verbose=False,
        no_http=no_http,
        env_config=env_config,
        env_name=env_name,
        odoo_series=odoo_series,
        config_source=config_source,
        config_path=config_path,
    )


def resolve_agent_ops(
    ctx: typer.Context,
    operation: str,
    result_type: str,
    *,
    resolve_agent_global_config_fn: Any,
    fail_fn: Any,
    odoo_operations_cls: Any,
) -> tuple[GlobalConfig, Any]:
    """Resolve agent config and instantiate operations."""
    global_config = resolve_agent_global_config_fn(ctx, operation, result_type)
    if global_config.env_config is None:
        fail_fn(
            operation,
            result_type,
            "No environment configuration available",
            error_type="ConfigError",
        )
    assert global_config.env_config is not None
    return global_config, odoo_operations_cls(global_config.env_config, verbose=False)


def parse_filter_values(
    raw_values: list[str], option_name: str
) -> list[tuple[str, str]]:
    """Parse repeated FIELD:VALUE filter options."""
    filters: list[tuple[str, str]] = []
    for raw_value in raw_values:
        if ":" not in raw_value:
            raise ValueError(
                f"Invalid {option_name} filter '{raw_value}'. Use FIELD:VALUE format."
            )
        field, value = raw_value.split(":", 1)
        filters.append((field.strip(), value.strip()))
    return filters


def require_agent_addons_path(
    env_config: dict[str, Any],
    operation: str,
    result_type: str,
    *,
    fail_fn: Any,
) -> str:
    """Return ``addons_path`` or emit a structured config error."""
    addons_path = env_config.get("addons_path")
    if isinstance(addons_path, str) and addons_path.strip():
        return addons_path

    fail_fn(
        operation,
        result_type,
        "addons_path is required for this agent command",
        error_type="ConfigError",
        remediation=[
            "Set `addons_path` in the selected environment before retrying.",
        ],
    )
    raise AssertionError("unreachable")


def agent_require_mutation(
    allow_mutation: bool,
    operation: str,
    result_type: str,
    action: str,
    safety_level: str,
    *,
    fail_fn: Any,
) -> None:
    """Enforce explicit allow-mutation gate for mutation commands."""
    if allow_mutation:
        return
    fail_fn(
        operation,
        result_type,
        f"{action} requires --allow-mutation",
        error_type="ConfirmationRequired",
        remediation=[
            (
                f"Retry `{action}` with `--allow-mutation` after reviewing "
                "the plan output."
            ),
            "Use a read-only planning command first if you need impact analysis.",
        ],
        read_only=False,
        safety_level=safety_level,
    )


def agent_sub_result(
    *,
    success: bool,
    data: dict[str, Any] | None = None,
    warnings: list[str] | None = None,
    errors: list[dict[str, Any]] | None = None,
    remediation: list[str] | None = None,
    error: str | None = None,
    error_type: str | None = None,
    read_only: bool = True,
    safety_level: str = SAFE_READ_ONLY,
    skipped: bool = False,
) -> dict[str, Any]:
    """Build a normalized sub-result for aggregate payloads."""
    return {
        "success": success,
        "read_only": read_only,
        "safety_level": safety_level,
        "warnings": warnings or [],
        "errors": errors or [],
        "remediation": remediation or [],
        "error": error,
        "error_type": error_type,
        "skipped": skipped,
        "data": data or {},
    }


def build_agent_test_summary_details(
    result: dict[str, Any],
    *,
    module: str | None,
    install: str | None,
    update: str | None,
    coverage: str | None,
    test_file: str | None,
    test_tags: str | None,
    build_error_output_excerpt_fn: Any,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Normalize ``run_tests()`` output for agent-facing summaries."""
    selected_modules = list(
        dict.fromkeys(value for value in [module, install, update, coverage] if value)
    )
    failures = list(result.get("failures", []))
    error_output_excerpt = (
        build_error_output_excerpt_fn(result)
        if not result.get("success", False)
        else []
    )
    traceback_summary = [
        {
            "test_name": failure.get("test_name"),
            "file": failure.get("file"),
            "line": failure.get("line"),
            "function_name": failure.get("function_name"),
            "source_line": failure.get("source_line"),
            "broken_line_count": failure.get("broken_line_count", 0),
            "failure_excerpt": failure.get("failure_excerpt"),
            "error_message": failure.get("error_message"),
        }
        for failure in failures
    ]
    suggested_next_steps: list[str] = []
    if failures:
        suggested_next_steps.append(
            "Inspect the first failure traceback and reproduce it locally."
        )
    if selected_modules:
        suggested_next_steps.append(
            f"Retest the selected module set: {', '.join(selected_modules)}."
        )
    if coverage:
        suggested_next_steps.append(
            "Review the generated coverage report to identify untested files."
        )

    data = {
        "selected_modules": selected_modules,
        "selection": {
            "module": module,
            "install": install,
            "update": update,
            "coverage": coverage,
            "test_file": test_file,
            "test_tags": test_tags,
        },
        "total_tests": result.get("total_tests", 0),
        "passed_tests": result.get("passed_tests", 0),
        "failed_tests": result.get("failed_tests", 0),
        "error_tests": result.get("error_tests", 0),
        "failure_details": failures,
        "error_output_excerpt": error_output_excerpt,
        "traceback_summary": traceback_summary,
        "coverage_summary": {
            "requested": bool(coverage),
            "module": coverage,
            "available": bool(coverage),
        },
        "per_file_coverage": result.get("per_file_coverage", []),
        "suggested_next_steps": suggested_next_steps,
        "return_code": result.get("return_code"),
        "command": result.get("command"),
    }
    warnings = (
        ["Per-file coverage entries are not currently normalized by run_tests()."]
        if coverage
        else []
    )
    return data, warnings, suggested_next_steps


def get_agent_addon_type(
    addon_name: str, odoo_series: Any, *, get_addon_type_fn: Any
) -> str:
    """Return a machine-oriented addon classification."""
    addon_type = get_addon_type_fn(addon_name, odoo_series)
    if addon_type == "Odoo CE (Community)":
        return "core_ce"
    if addon_type == "Odoo EE (Enterprise)":
        return "core_ee"
    return "custom"


def build_environment_context_data(
    global_config: GlobalConfig,
    *,
    build_doctor_report_fn: Any,
    addons_path_manager_cls: Any,
    module_manager_cls: Any,
    probe_binary_fn: Any,
    odoo_operations_cls: Any,
) -> dict[str, Any]:
    """Build a one-shot environment snapshot for agent workflows."""
    import os

    env_config = global_config.env_config or {}
    doctor_report = build_doctor_report_fn(global_config)
    addons_path = str(env_config.get("addons_path", ""))
    path_manager = addons_path_manager_cls(addons_path) if addons_path else None
    configured_paths = path_manager.get_configured_paths() if path_manager else []
    base_paths = path_manager.get_base_addons_paths() if path_manager else []
    all_paths = path_manager.get_all_paths() if path_manager else []
    valid_paths: list[str] = []
    invalid_paths: list[str] = []
    for path in configured_paths:
        absolute_path = os.path.abspath(path)
        if os.path.isdir(absolute_path):
            valid_paths.append(absolute_path)
        else:
            invalid_paths.append(path)

    duplicate_modules = (
        path_manager.find_duplicate_module_names() if path_manager else {}
    )
    module_manager = (
        module_manager_cls(addons_path) if addons_path and not invalid_paths else None
    )
    available_module_count = 0
    detected_series = None
    if module_manager is not None:
        available_module_count = len(module_manager.find_modules(skip_invalid=True))
        detected_series = (
            global_config.odoo_series or module_manager.detect_odoo_series()
        )

    python_info = probe_binary_fn(env_config.get("python_bin"), ["python3", "python"])
    odoo_info = probe_binary_fn(env_config.get("odoo_bin"), ["odoo", "odoo-bin"])
    coverage_info = probe_binary_fn(env_config.get("coverage_bin"), ["coverage"])

    version_result = odoo_operations_cls(env_config, verbose=False).get_odoo_version(
        suppress_output=True
    )

    missing_critical_config = [
        key
        for key in ("python_bin", "odoo_bin", "addons_path")
        if not env_config.get(key)
    ]

    return {
        "environment": {
            "name": global_config.env_name,
            "source": global_config.config_source,
            "config_path": global_config.config_path,
        },
        "resolved_binaries": {
            "python_bin": python_info,
            "odoo_bin": odoo_info,
            "coverage_bin": coverage_info,
        },
        "addons_paths": {
            "configured": configured_paths,
            "base": base_paths,
            "all": all_paths,
            "valid": valid_paths,
            "invalid": invalid_paths,
        },
        "odoo": {
            "version": version_result.get("version"),
            "series": detected_series.value if detected_series else None,
        },
        "database": {
            "db_name": env_config.get("db_name"),
            "db_host": env_config.get("db_host") or "localhost",
            "db_user": env_config.get("db_user"),
        },
        "duplicate_modules": duplicate_modules,
        "available_module_count": available_module_count,
        "invalid_addon_paths": invalid_paths,
        "missing_critical_config": missing_critical_config,
        "doctor_summary": doctor_report.get("summary", {}),
        "doctor_checks": doctor_report.get("checks", []),
    }


def build_addon_inspection_data(
    module_manager: Any,
    module_name: str,
    odoo_series: Any,
    *,
    get_agent_addon_type_fn: Any,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Aggregate addon inspection data for a single module."""
    manifest = module_manager.get_manifest(module_name)
    if manifest is None:
        raise ValueError(f"Module '{module_name}' was not found in addons_path")

    warnings: list[str] = []
    remediation: list[str] = []
    module_path = module_manager.find_module_path(module_name)
    reverse_dependencies = module_manager.get_reverse_dependencies(module_name)

    try:
        missing_dependencies = module_manager.find_missing_dependencies(module_name)
    except ValueError as exc:
        missing_dependencies = []
        warnings.append(str(exc))

    dependency_cycle: list[str] = []
    try:
        install_order = module_manager.get_install_order(module_name)
    except ValueError as exc:
        install_order = []
        warnings.append(str(exc))
        dependency_cycle = module_manager.parse_cycle_error(str(exc))
        if dependency_cycle:
            remediation.append(
                "Break the dependency cycle before attempting installation or update."
            )

    if missing_dependencies:
        remediation.append(
            "Resolve missing dependencies before attempting installation or update."
        )

    raw_data = manifest.get_raw_data()
    inspection = {
        "module": module_name,
        "exists": True,
        "module_path": module_path,
        "addon_type": get_agent_addon_type_fn(module_name, odoo_series),
        "version_display": module_manager.get_module_version_display(
            module_name, odoo_series
        ),
        "manifest": raw_data,
        "manifest_fields": sorted(raw_data.keys()),
        "direct_dependencies": manifest.codependencies,
        "reverse_dependencies": reverse_dependencies,
        "reverse_dependency_count": len(reverse_dependencies),
        "install_order_slice": install_order,
        "install_order_available": bool(install_order),
        "dependency_cycle": dependency_cycle,
        "missing_dependencies": missing_dependencies,
        "impacted_modules": reverse_dependencies,
        "series": odoo_series.value if odoo_series else None,
        "python_dependencies": manifest.python_dependencies,
        "binary_dependencies": manifest.binary_dependencies,
    }
    return inspection, warnings, remediation


def build_update_plan_data(
    global_config: GlobalConfig,
    module_name: str,
    *,
    module_manager_cls: Any,
    addons_path_manager_cls: Any,
    build_addon_inspection_data_fn: Any,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Build a read-only update plan for a module."""
    env_config = global_config.env_config or {}
    module_manager = module_manager_cls(str(env_config.get("addons_path", "")))
    detected_series = global_config.odoo_series or module_manager.detect_odoo_series()
    inspection, warnings, remediation = build_addon_inspection_data_fn(
        module_manager,
        module_name,
        detected_series,
    )

    duplicate_modules = addons_path_manager_cls(
        env_config["addons_path"]
    ).find_duplicate_module_names()
    duplicate_name_risk = module_name in duplicate_modules
    reverse_dependency_count = int(inspection["reverse_dependency_count"])
    missing_dependencies = list(inspection["missing_dependencies"])
    dependency_cycle = list(inspection.get("dependency_cycle", []))

    risk_factors: list[str] = []
    risk_score = 0
    if reverse_dependency_count:
        risk_score += min(reverse_dependency_count * 10, 40)
        risk_factors.append(
            f"{reverse_dependency_count} reverse dependencies would be affected"
        )
    if missing_dependencies:
        risk_score += min(len(missing_dependencies) * 20, 30)
        risk_factors.append("module has missing dependencies")
    if duplicate_name_risk:
        risk_score += 20
        risk_factors.append("module name is duplicated across addons paths")
    if dependency_cycle:
        risk_score += 30
        risk_factors.append("dependency graph contains a cycle")
    if inspection["addon_type"] == "custom":
        risk_score += 10
        risk_factors.append("custom addon changes should be validated in the target DB")

    risk_level = "low"
    if risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"

    backup_advised = reverse_dependency_count > 0 or duplicate_name_risk
    verification_steps = [
        f"Run `oduit agent test-summary --module {module_name} "
        f"--test-tags /{module_name}`.",
        f"Inspect reverse dependencies for `{module_name}` before "
        "updating dependent addons.",
    ]
    if inspection["reverse_dependencies"]:
        verification_steps.append(
            "Retest at least one impacted reverse dependency after the update."
        )
    if backup_advised:
        remediation.append(
            "Take a database backup before updating this module in a shared "
            "environment."
        )

    plan_data = {
        "module": module_name,
        "exists": True,
        "impact_set": inspection["reverse_dependencies"],
        "impact_count": reverse_dependency_count,
        "missing_dependencies": missing_dependencies,
        "duplicate_name_risk": duplicate_name_risk,
        "duplicate_module_locations": duplicate_modules.get(module_name, []),
        "dependency_cycle": dependency_cycle,
        "cycle_risk": bool(dependency_cycle),
        "ordering_constraints": inspection["install_order_slice"],
        "recommended_sequence": [
            "Review dependency and duplicate-module warnings.",
            *(
                ["Take a database backup."]
                if backup_advised
                else ["A dedicated backup is optional for this change."]
            ),
            f"Update `{module_name}`.",
            "Run targeted validation and tests.",
        ],
        "backup_advised": backup_advised,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "verification_steps": verification_steps,
        "inspection": inspection,
    }
    return plan_data, warnings, remediation
