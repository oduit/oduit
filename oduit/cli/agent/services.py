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
