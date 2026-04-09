# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""New Typer-based CLI implementation for oduit."""

import functools
import json
import os
import re
import shutil
from dataclasses import replace
from typing import Any, NoReturn

import click
import typer
from manifestoo_core.odoo_series import OdooSeries

from .addons_path_manager import AddonsPathManager
from .cli_types import (
    AddonListType,
    AddonTemplate,
    DevFeature,
    GlobalConfig,
    LogLevel,
    OutputFormat,
    ShellInterface,
)
from .config_loader import ConfigLoader
from .exceptions import ConfigError
from .exceptions import ModuleNotFoundError as OduitModuleNotFoundError
from .module_manager import ModuleManager
from .odoo_operations import OdooOperations
from .output import configure_output, print_error, print_info, print_warning
from .schemas import CONTROLLED_MUTATION, SAFE_READ_ONLY
from .utils import (
    build_json_payload,
    format_dependency_tree,
    output_result_to_json,
    validate_addon_name,
)

SHELL_INTERFACE_OPTION = typer.Option(
    "python",
    "--shell-interface",
    help="Shell interface to use (overrides config setting)",
)

ADDON_TEMPLATE_OPTION = typer.Option(
    AddonTemplate.BASIC, "--template", help="Addon template to use"
)

ADDON_LIST_TYPE_OPTION = typer.Option(
    AddonListType.ALL, "--type", help="Type of addons to list"
)

LOG_LEVEL_OPTION = typer.Option(
    None,
    "--log-level",
    "-l",
    help="Set Odoo log level",
)

LANGUAGE_OPTION = typer.Option(
    None,
    "--language",
    "--lang",
    help="Set language (e.g., 'de_DE', 'en_US')",
)


DEV_OPTION = typer.Option(
    None,
    "--dev",
    "-d",
    help=(
        "Comma-separated list of dev features (e.g., 'all', 'xml', 'reload,qweb'). "
        "Available: all, xml, reload, qweb, ipdb, pdb, pudb, werkzeug. "
        "For development only - do not use in production."
    ),
)

ODOO_SERIES_OPTION = typer.Option(
    None,
    "--odoo-series",
    envvar=["ODOO_VERSION", "ODOO_SERIES"],
    help="Odoo series to use, in case it is not autodetected from addons version.",
)

SORT_OPTION = typer.Option(
    "alphabetical",
    "--sort",
    help="Choice between 'alphabetical' and 'topological'. "
    "Topological sorting is useful when seeking a migration order.",
    show_default=True,
)

# Pre-computed help string for filter options
_VALID_FILTER_FIELDS_STR = (
    "name, version, summary, author, website, license, "
    "category, module_path, depends, addon_type"
)

INCLUDE_FILTER_OPTION = typer.Option(
    [],
    "--include",
    help=(
        "Include filter as 'FIELD:VALUE'. Can be used multiple times. "
        f"Valid fields: {_VALID_FILTER_FIELDS_STR}"
    ),
)

EXCLUDE_FILTER_OPTION = typer.Option(
    [],
    "--exclude",
    help=(
        "Exclude filter as 'FIELD:VALUE'. Can be used multiple times. "
        f"Valid fields: {_VALID_FILTER_FIELDS_STR}"
    ),
)


def _resolve_config_source(
    config_loader: ConfigLoader,
    env: str | None,
    env_config: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
    """Resolve where the active configuration came from."""
    config_path = None
    source = "local" if env is None else "env"

    if env is None:
        if config_loader.has_local_config():
            try:
                config_path = config_loader.get_local_config_path()
            except Exception:
                config_path = os.path.abspath(".oduit.toml")
    else:
        resolved_path = None
        try:
            resolved = config_loader.resolve_config_path(env.strip())
            if isinstance(resolved, tuple) and len(resolved) == 2:
                resolved_path = resolved[0]
        except Exception:
            resolved_path = None

        if isinstance(resolved_path, str) and os.path.exists(resolved_path):
            config_path = os.path.abspath(resolved_path)

    if env_config and env_config.get("demo_mode", False):
        source = "demo"

    return source, config_path


def _build_doctor_check(
    name: str,
    status: str,
    message: str,
    details: dict[str, Any] | None = None,
    remediation: str | None = None,
) -> dict[str, Any]:
    """Create a normalized doctor check entry."""
    check: dict[str, Any] = {
        "name": name,
        "status": status,
        "message": message,
    }
    if details:
        check["details"] = details
    if remediation:
        check["remediation"] = remediation
    return check


def _resolve_binary_candidate(candidate: str) -> dict[str, Any]:
    """Resolve a binary candidate either from PATH or filesystem."""
    is_path_like = os.path.isabs(candidate) or os.sep in candidate
    resolved_path: str | None

    if is_path_like:
        resolved_path = os.path.abspath(candidate)
        exists = os.path.exists(resolved_path)
        executable = exists and os.access(resolved_path, os.X_OK)
        return {
            "value": candidate,
            "resolved_path": resolved_path,
            "exists": exists,
            "executable": executable,
        }

    resolved_path = shutil.which(candidate)
    return {
        "value": candidate,
        "resolved_path": resolved_path,
        "exists": resolved_path is not None,
        "executable": resolved_path is not None,
    }


def _probe_binary(
    configured_value: str | None, auto_candidates: list[str]
) -> dict[str, Any]:
    """Probe a configured binary or try to auto-detect it."""
    if configured_value:
        result = _resolve_binary_candidate(configured_value)
        result["configured"] = True
        result["auto_detected"] = False
        return result

    for candidate in auto_candidates:
        result = _resolve_binary_candidate(candidate)
        if result["exists"]:
            result["configured"] = False
            result["auto_detected"] = True
            return result

    return {
        "value": configured_value,
        "resolved_path": None,
        "exists": False,
        "executable": False,
        "configured": False,
        "auto_detected": False,
    }


def _format_doctor_value(value: Any) -> str:
    """Format a doctor value for human-readable output."""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return ", ".join(f"{key}={val}" for key, val in value.items())
    return str(value)


def _print_command_error_result(
    global_config: GlobalConfig,
    operation: str,
    message: str,
    error_type: str = "CommandError",
    details: dict[str, Any] | None = None,
    remediation: list[str] | None = None,
) -> None:
    """Print a command error in text or JSON mode."""
    if global_config.format == OutputFormat.JSON:
        payload = output_result_to_json(
            {
                "success": False,
                "operation": operation,
                "error": message,
                "error_type": error_type,
            },
            additional_fields={
                **(details or {}),
                "remediation": remediation or [],
            },
        )
        print(json.dumps(payload))
    else:
        print_error(message)


def _dependency_error_details(
    module_manager: ModuleManager, message: str
) -> dict[str, Any]:
    """Build structured details for dependency-related CLI failures."""
    cycle_path = module_manager.parse_cycle_error(message)
    if not cycle_path:
        return {}
    return {
        "cycle_path": cycle_path,
        "cycle_length": len(cycle_path) - 1,
    }


def _confirmation_required_error(
    global_config: GlobalConfig,
    operation: str,
    message: str,
    remediation: list[str],
) -> None:
    """Fail fast when non-interactive mode forbids prompting."""
    _print_command_error_result(
        global_config,
        operation,
        message,
        error_type="ConfirmationRequired",
        remediation=remediation,
    )
    raise typer.Exit(1) from None


def _build_doctor_report(global_config: GlobalConfig) -> dict[str, Any]:
    """Build a diagnostics report for the active configuration."""
    env_config = global_config.env_config or {}
    checks: list[dict[str, Any]] = []
    next_steps: list[str] = []

    checks.append(
        _build_doctor_check(
            "config_source",
            "ok",
            f"Using {global_config.config_source or 'unknown'} configuration",
            details={
                "env_name": global_config.env_name,
                "config_path": global_config.config_path,
            },
        )
    )

    python_info = _probe_binary(env_config.get("python_bin"), ["python3", "python"])
    if python_info["exists"] and python_info["executable"]:
        checks.append(
            _build_doctor_check(
                "python_bin",
                "ok",
                (
                    f"python_bin is available at {python_info['resolved_path']}"
                    if python_info["configured"]
                    else f"python_bin auto-detected at {python_info['resolved_path']}"
                ),
                details=python_info,
            )
        )
    else:
        checks.append(
            _build_doctor_check(
                "python_bin",
                "error",
                "Configured python_bin is missing or not executable"
                if python_info["configured"]
                else "python_bin was not configured and could not be auto-detected",
                details=python_info,
                remediation=(
                    "Set `python_bin` in `.oduit.toml` or install Python on PATH."
                ),
            )
        )

    odoo_info = _probe_binary(env_config.get("odoo_bin"), ["odoo", "odoo-bin"])
    if odoo_info["exists"] and odoo_info["executable"]:
        checks.append(
            _build_doctor_check(
                "odoo_bin",
                "ok",
                (
                    f"odoo_bin is available at {odoo_info['resolved_path']}"
                    if odoo_info["configured"]
                    else f"odoo_bin auto-detected at {odoo_info['resolved_path']}"
                ),
                details=odoo_info,
            )
        )
    else:
        checks.append(
            _build_doctor_check(
                "odoo_bin",
                "error",
                "Configured odoo_bin does not exist or is not executable"
                if odoo_info["configured"]
                else "odoo_bin was not configured and could not be auto-detected",
                details=odoo_info,
                remediation=(
                    "Set `odoo_bin` in `.oduit.toml` or add `odoo-bin` to PATH."
                ),
            )
        )

    coverage_info = _probe_binary(env_config.get("coverage_bin"), ["coverage"])
    if coverage_info["exists"] and coverage_info["executable"]:
        checks.append(
            _build_doctor_check(
                "coverage_bin",
                "ok",
                (
                    f"coverage_bin is available at {coverage_info['resolved_path']}"
                    if coverage_info["configured"]
                    else (
                        "coverage_bin auto-detected at "
                        f"{coverage_info['resolved_path']}"
                    )
                ),
                details=coverage_info,
            )
        )
    else:
        checks.append(
            _build_doctor_check(
                "coverage_bin",
                "warning",
                "coverage_bin is not configured and could not be auto-detected",
                details=coverage_info,
                remediation=(
                    "Install `coverage` or set `coverage_bin` if you use "
                    "coverage-enabled test runs."
                ),
            )
        )

    pairing_status = "ok" if python_info["exists"] and odoo_info["exists"] else "error"
    checks.append(
        _build_doctor_check(
            "binary_pairing",
            pairing_status,
            "python_bin and odoo_bin are both available"
            if pairing_status == "ok"
            else "python_bin and odoo_bin are not both available",
            details={
                "python_bin": python_info.get("resolved_path")
                or python_info.get("value"),
                "odoo_bin": odoo_info.get("resolved_path") or odoo_info.get("value"),
            },
            remediation=(
                "Ensure both `python_bin` and `odoo_bin` resolve correctly "
                "before running Odoo commands."
            )
            if pairing_status == "error"
            else None,
        )
    )

    addons_path = env_config.get("addons_path")
    module_manager: ModuleManager | None = None
    if not addons_path:
        checks.append(
            _build_doctor_check(
                "addons_path",
                "error",
                "addons_path is not configured",
                remediation=(
                    "Set `addons_path` in `.oduit.toml` or import an existing "
                    "Odoo config with `oduit init`."
                ),
            )
        )
    else:
        path_manager = AddonsPathManager(addons_path)
        configured_paths = path_manager.get_configured_paths()
        invalid_paths: list[str] = []
        valid_paths: list[str] = []

        for path in configured_paths:
            absolute_path = os.path.abspath(path)
            if not os.path.exists(absolute_path):
                invalid_paths.append(path)
            elif not os.path.isdir(absolute_path):
                invalid_paths.append(path)
            else:
                valid_paths.append(absolute_path)

        if invalid_paths:
            checks.append(
                _build_doctor_check(
                    "addons_path",
                    "error",
                    f"Configured addons paths are invalid: {', '.join(invalid_paths)}",
                    details={
                        "configured_paths": configured_paths,
                        "invalid_paths": invalid_paths,
                    },
                    remediation=(
                        "Fix `addons_path` so every configured path exists and "
                        "is a directory. Invalid paths: "
                        f"{', '.join(invalid_paths)}"
                    ),
                )
            )
        else:
            checks.append(
                _build_doctor_check(
                    "addons_path",
                    "ok",
                    f"Configured addons paths are valid ({len(valid_paths)} path(s))",
                    details={"configured_paths": valid_paths},
                )
            )
            module_manager = ModuleManager(addons_path)
            modules = module_manager.find_modules(skip_invalid=True)
            checks.append(
                _build_doctor_check(
                    "addons_scan",
                    "ok",
                    f"Discovered {len(modules)} addon(s)",
                    details={"module_count": len(modules)},
                )
            )

            base_paths = path_manager.get_base_addons_paths()
            base_status = "ok" if base_paths else "warning"
            checks.append(
                _build_doctor_check(
                    "base_addons",
                    base_status,
                    "Base Odoo addons were auto-discovered"
                    if base_paths
                    else "Base Odoo addons were not auto-discovered",
                    details={"base_addons_paths": base_paths},
                    remediation=(
                        "Check whether `odoo_bin` and your addons layout match "
                        "a standard Odoo checkout if base addons should be "
                        "discoverable."
                    )
                    if not base_paths
                    else None,
                )
            )

            duplicate_modules = path_manager.find_duplicate_module_names()
            if duplicate_modules:
                checks.append(
                    _build_doctor_check(
                        "duplicate_addons",
                        "warning",
                        "Duplicate addon names found: "
                        f"{', '.join(sorted(duplicate_modules))}",
                        details={"duplicates": duplicate_modules},
                        remediation=(
                            "Remove or reorder duplicate addon paths to avoid "
                            "ambiguous module resolution."
                        ),
                    )
                )

    ops = OdooOperations(env_config, verbose=False)
    version_result = ops.get_odoo_version(suppress_output=True)
    if version_result.get("success") and version_result.get("version"):
        checks.append(
            _build_doctor_check(
                "odoo_version",
                "ok",
                f"Detected Odoo version {version_result['version']}",
                details={"version": version_result.get("version")},
            )
        )
        if module_manager is not None:
            detected_series = (
                global_config.odoo_series or module_manager.detect_odoo_series()
            )
            if detected_series and detected_series.value != version_result["version"]:
                checks.append(
                    _build_doctor_check(
                        "odoo_series_mismatch",
                        "warning",
                        "Detected Odoo version does not match addon manifest series",
                        details={
                            "odoo_version": version_result["version"],
                            "addons_series": detected_series.value,
                        },
                        remediation=(
                            "Verify that `odoo_bin` and `addons_path` point to "
                            "the same Odoo series."
                        ),
                    )
                )
    else:
        checks.append(
            _build_doctor_check(
                "odoo_version",
                "error",
                "Failed to detect Odoo version",
                details={
                    "error": version_result.get("error"),
                    "return_code": version_result.get("return_code"),
                },
                remediation=(
                    "Check `odoo_bin` and run `oduit version` to inspect the "
                    "failure directly."
                ),
            )
        )

    db_name = env_config.get("db_name")
    if not db_name:
        checks.append(
            _build_doctor_check(
                "db_config",
                "warning",
                "db_name is not configured",
                remediation=(
                    "Set `db_name` if this environment should target a database."
                ),
            )
        )
    else:
        db_host = env_config.get("db_host") or "localhost"
        db_user = env_config.get("db_user")
        db_config_status = "ok" if db_user else "warning"
        checks.append(
            _build_doctor_check(
                "db_config",
                db_config_status,
                f"Database configuration is present for '{db_name}'",
                details={
                    "db_name": db_name,
                    "db_host": db_host,
                    "db_user": db_user,
                },
                remediation=(
                    "Set `db_user` if the default PostgreSQL user is not "
                    "correct for this environment."
                )
                if not db_user
                else None,
            )
        )

        db_result = ops.db_exists(with_sudo=False, suppress_output=True)
        if db_result.get("success") and db_result.get("exists"):
            checks.append(
                _build_doctor_check(
                    "db_exists",
                    "ok",
                    f"Database '{db_name}' exists",
                    details={"database": db_name},
                )
            )
        elif db_result.get("success"):
            checks.append(
                _build_doctor_check(
                    "db_exists",
                    "warning",
                    f"Database '{db_name}' does not exist",
                    details={
                        "database": db_name,
                        "return_code": db_result.get("return_code"),
                    },
                    remediation=(
                        "Create the database with `oduit --env "
                        f"{global_config.env_name or 'dev'} create-db` if it "
                        "should exist."
                    ),
                )
            )
        else:
            checks.append(
                _build_doctor_check(
                    "db_exists",
                    "error",
                    "Database existence check failed",
                    details={
                        "database": db_name,
                        "error": db_result.get("error"),
                        "return_code": db_result.get("return_code"),
                    },
                    remediation=(
                        "Verify PostgreSQL access and database credentials, "
                        "then retry `oduit doctor`."
                    ),
                )
            )

    for check in checks:
        remediation = check.get("remediation")
        if remediation and remediation not in next_steps:
            next_steps.append(remediation)

    summary = {
        "ok": sum(1 for check in checks if check["status"] == "ok"),
        "warning": sum(1 for check in checks if check["status"] == "warning"),
        "error": sum(1 for check in checks if check["status"] == "error"),
    }

    warning_messages = [
        check["message"] for check in checks if check.get("status") == "warning"
    ]
    error_checks = [check for check in checks if check.get("status") == "error"]
    error_message = None
    error_type = None
    if error_checks:
        error_message = (
            f"Doctor found {len(error_checks)} failing check(s): "
            + ", ".join(check["name"] for check in error_checks)
        )
        error_type = "DoctorCheckError"

    return build_json_payload(
        "doctor_report",
        {
            "operation": "doctor",
            "success": summary["error"] == 0,
            "source": {
                "kind": global_config.config_source,
                "env_name": global_config.env_name,
                "config_path": global_config.config_path,
            },
            "checks": checks,
            "summary": summary,
            "next_steps": next_steps,
            "warnings": warning_messages,
            "errors": [
                {
                    "check": check["name"],
                    "message": check["message"],
                }
                for check in error_checks
            ],
            "remediation": next_steps,
            "error": error_message,
            "error_type": error_type,
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        success=summary["error"] == 0,
    )


def _print_doctor_report(report: dict[str, Any]) -> None:
    """Render a doctor report in text mode."""
    labels = {
        "ok": "OK",
        "warning": "WARNING",
        "error": "ERROR",
    }

    source = report.get("source", {})
    source_kind = source.get("kind") or "unknown"
    config_path = source.get("config_path")
    source_line = f"Config source: {source_kind}"
    if config_path:
        source_line += f" ({config_path})"
    typer.echo(source_line)
    typer.echo("")

    for check in report.get("checks", []):
        status = labels.get(check.get("status", "ok"), "OK")
        typer.echo(f"[{status}] {check['message']}")
        details = check.get("details")
        if details:
            for key, value in details.items():
                if value in (None, "", [], {}):
                    continue
                typer.echo(f"  {key}: {_format_doctor_value(value)}")

    summary = report.get("summary", {})
    typer.echo("")
    typer.echo(
        "Summary: "
        f"{summary.get('ok', 0)} OK, "
        f"{summary.get('warning', 0)} WARNING, "
        f"{summary.get('error', 0)} ERROR"
    )

    if report.get("next_steps"):
        typer.echo("Next steps:")
        for step in report["next_steps"]:
            typer.echo(f"- {step}")


def create_global_config(
    env: str | None = None,
    json: bool = False,
    non_interactive: bool = False,
    verbose: bool = False,
    no_http: bool = False,
    odoo_series: OdooSeries | None = None,
) -> GlobalConfig:
    """Create and validate global configuration."""

    # Configure output based on arguments
    format = OutputFormat.JSON if json else OutputFormat.TEXT
    configure_output(
        format_type=format.value,
        non_interactive=True,
    )

    # Handle environment and config loading
    env_config = None
    env_name = None
    config_loader = ConfigLoader()

    if env is None:
        if config_loader.has_local_config():
            if verbose:
                typer.echo("Using local .oduit.toml configuration")
            try:
                env_config = config_loader.load_local_config()
                env_name = "local"
            except (FileNotFoundError, ImportError, ValueError) as e:
                print_error(f"[ERROR] {str(e)}")
                raise typer.Exit(1) from e
        else:
            print_error(
                "No environment specified and no .oduit.toml found in current directory"
            )
            raise typer.Exit(1) from None
    else:
        env_name = env.strip()
        try:
            env_config = config_loader.load_config(env_name)
        except (FileNotFoundError, ImportError, ValueError) as e:
            print_error(f"[ERROR] {str(e)}")
            raise typer.Exit(1) from e
        except Exception as e:
            print_error(f"Error loading environment '{env_name}': {str(e)}")
            raise typer.Exit(1) from e

    config_source, config_path = _resolve_config_source(config_loader, env, env_config)

    return GlobalConfig(
        env=env,
        non_interactive=non_interactive,
        format=format,
        verbose=verbose,
        no_http=no_http,
        env_config=env_config,
        env_name=env_name,
        odoo_series=odoo_series,
        config_source=config_source,
        config_path=config_path,
    )


def with_config(func: Any) -> Any:
    """Decorator to inject global configuration into command functions."""

    @functools.wraps(func)
    def wrapper(ctx: typer.Context) -> Any:
        if ctx.obj is None:
            print_error("No global configuration found")
            raise typer.Exit(1) from None

        if isinstance(ctx.obj, dict):
            try:
                global_config = create_global_config(**ctx.obj)
            except typer.Exit:
                raise
            except Exception as e:
                print_error(f"Failed to create global config: {e}")
                raise typer.Exit(1) from e
        else:
            global_config = ctx.obj

        return func(global_config)

    return wrapper


# Create the main Typer app
app = typer.Typer(
    name="oduit",
    help="Odoo CLI tool for starting odoo-bin and running tasks",
    epilog="""
Examples:
  oduit --env dev run                        # Run Odoo server
  oduit --env dev shell                      # Start Odoo shell
  oduit --env dev test --test-tags /sale     # Test with module filter
  oduit run                                  # Run with local .oduit.toml
    """,
    no_args_is_help=False,  # Allow no args for interactive mode
)
agent_app = typer.Typer(help="Agent-first structured inspection and planning commands")
app.add_typer(agent_app, name="agent")


def _agent_emit_payload(payload: dict[str, Any]) -> None:
    """Print a structured agent payload."""
    print(json.dumps(payload))


def _agent_fail(
    operation: str,
    result_type: str,
    message: str,
    error_type: str = "CommandError",
    details: dict[str, Any] | None = None,
    remediation: list[str] | None = None,
    read_only: bool = True,
    safety_level: str = SAFE_READ_ONLY,
) -> NoReturn:
    """Emit a structured agent error payload and exit."""
    payload = output_result_to_json(
        {
            "success": False,
            "operation": operation,
            "error": message,
            "error_type": error_type,
        },
        additional_fields={
            **(details or {}),
            "remediation": remediation or [],
            "read_only": read_only,
            "safety_level": safety_level,
        },
        result_type=result_type,
    )
    _agent_emit_payload(payload)
    raise typer.Exit(1) from None


def _agent_payload(
    operation: str,
    result_type: str,
    data: dict[str, Any],
    *,
    success: bool = True,
    warnings: list[str] | None = None,
    errors: list[dict[str, Any]] | None = None,
    remediation: list[str] | None = None,
    read_only: bool = True,
    safety_level: str = SAFE_READ_ONLY,
    error: str | None = None,
    error_type: str | None = None,
    include_null_values: bool = False,
    exclude_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Build a structured agent payload using the shared JSON envelope."""
    return output_result_to_json(
        {
            "success": success,
            "operation": operation,
            "error": error,
            "error_type": error_type,
            **data,
        },
        additional_fields={
            "warnings": warnings or [],
            "errors": errors or [],
            "remediation": remediation or [],
            "read_only": read_only,
            "safety_level": safety_level,
        },
        exclude_fields=exclude_fields,
        include_null_values=include_null_values,
        result_type=result_type,
    )


_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def _build_error_output_excerpt(
    result: dict[str, Any], *, max_lines: int = 80, max_chars: int = 12000
) -> list[str]:
    """Return a bounded tail excerpt from captured process output."""
    for stream_name in ("stderr", "stdout"):
        stream_value = result.get(stream_name)
        if not isinstance(stream_value, str) or not stream_value.strip():
            continue

        cleaned_lines = [
            _ANSI_ESCAPE_PATTERN.sub("", line.rstrip())
            for line in stream_value.splitlines()
            if line.strip()
        ]
        if not cleaned_lines:
            continue

        excerpt_lines = cleaned_lines[-max_lines:]
        excerpt_text = "\n".join(excerpt_lines)
        if len(excerpt_text) > max_chars:
            excerpt_text = excerpt_text[-max_chars:]
            excerpt_lines = excerpt_text.splitlines()

        return excerpt_lines

    return []


def _resolve_agent_global_config(
    ctx: typer.Context,
    operation: str,
    result_type: str,
) -> GlobalConfig:
    """Resolve configuration for agent commands without emitting text output."""
    configure_output(format_type=OutputFormat.JSON.value, non_interactive=True)
    if ctx.obj is None:
        _agent_fail(
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
    config_loader = ConfigLoader()

    env_config = None
    env_name = None
    try:
        if env is None:
            if not config_loader.has_local_config():
                _agent_fail(
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
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            remediation=[
                "Verify the requested environment exists and the config file is valid.",
            ],
        )
    except Exception as exc:
        _agent_fail(
            operation,
            result_type,
            f"Error loading environment '{env_name or 'local'}': {exc}",
            error_type="ConfigError",
            remediation=[
                "Check the environment configuration and try again.",
            ],
        )

    config_source, config_path = _resolve_config_source(config_loader, env, env_config)
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


def _parse_csv_items(raw_value: str | None) -> list[str] | None:
    """Parse a comma-separated CLI option into a list of strings."""
    if raw_value is None:
        return None
    items = [item.strip() for item in raw_value.split(",") if item.strip()]
    return items or None


def _parse_view_types(
    raw_value: str | None, operation: str, result_type: str
) -> list[str] | None:
    """Parse and validate requested Odoo view types."""
    values = _parse_csv_items(raw_value)
    if values is None:
        return None

    valid_view_types = {"form", "tree", "kanban", "search", "calendar", "graph"}
    invalid = [value for value in values if value not in valid_view_types]
    if invalid:
        _agent_fail(
            operation,
            result_type,
            f"Unsupported view type(s): {', '.join(invalid)}",
            error_type="ValidationError",
            remediation=[
                "Use supported view types only: form, tree, kanban, search, "
                "calendar, graph.",
            ],
        )
    return values


def _strip_arch_from_model_views(data: dict[str, Any]) -> dict[str, Any]:
    """Remove nested ``arch_db`` fields from model view payloads."""
    result = dict(data)
    for field_name in ("primary_views", "extension_views"):
        views = result.get(field_name)
        if not isinstance(views, list):
            continue
        result[field_name] = [
            {key: value for key, value in view.items() if key != "arch_db"}
            for view in views
            if isinstance(view, dict)
        ]
    return result


def _parse_json_list_option(
    raw_value: str | None,
    option_name: str,
    operation: str,
    result_type: str,
) -> list[Any]:
    """Parse a JSON-encoded list option or emit a structured error."""
    if raw_value is None:
        return []

    parsed: Any = None
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        _agent_fail(
            operation,
            result_type,
            f"{option_name} must be valid JSON: {exc.msg}",
            details={option_name: raw_value},
            remediation=[
                f"Pass `{option_name}` as a JSON array, for example "
                f'\'["name", "=", "Acme"]\'.',
            ],
        )

    if not isinstance(parsed, list):
        _agent_fail(
            operation,
            result_type,
            f"{option_name} must decode to a JSON array",
            details={option_name: raw_value},
            remediation=[
                f"Pass `{option_name}` as a JSON array value.",
            ],
        )

    return parsed


def _resolve_agent_ops(
    ctx: typer.Context,
    operation: str,
    result_type: str,
) -> tuple[GlobalConfig, OdooOperations]:
    """Resolve agent config and instantiate operations."""
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(
            operation,
            result_type,
            "No environment configuration available",
            error_type="ConfigError",
        )
    assert global_config.env_config is not None
    return global_config, OdooOperations(global_config.env_config, verbose=False)


def _parse_filter_values(
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


def _require_agent_addons_path(
    env_config: dict[str, Any],
    operation: str,
    result_type: str,
) -> str:
    """Return ``addons_path`` or emit a structured config error."""
    addons_path = env_config.get("addons_path")
    if isinstance(addons_path, str) and addons_path.strip():
        return addons_path

    _agent_fail(
        operation,
        result_type,
        "addons_path is required for this agent command",
        error_type="ConfigError",
        remediation=[
            "Set `addons_path` in the selected environment before retrying.",
        ],
    )


def _redact_config_value(key: str, value: Any) -> Any:
    """Redact sensitive configuration values in structured outputs."""
    sensitive_markers = ("password", "secret", "token", "api_key", "key")
    normalized_key = key.lower()
    if any(marker in normalized_key for marker in sensitive_markers):
        return "***redacted***"
    if isinstance(value, dict):
        return {
            inner_key: _redact_config_value(inner_key, inner_value)
            for inner_key, inner_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_config_value(key, item) for item in value]
    return value


def _redact_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return a recursively redacted configuration dictionary."""
    return {key: _redact_config_value(key, value) for key, value in config.items()}


def _agent_require_mutation(
    allow_mutation: bool,
    operation: str,
    result_type: str,
    action: str,
) -> None:
    """Enforce an explicit allow-mutation gate for agent mutation commands."""
    if allow_mutation:
        return
    _agent_fail(
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
        safety_level=CONTROLLED_MUTATION,
    )


def _get_agent_addon_type(addon_name: str, odoo_series: OdooSeries | None) -> str:
    """Return a machine-oriented addon classification."""
    addon_type = _get_addon_type(addon_name, odoo_series)
    if addon_type == "Odoo CE (Community)":
        return "core_ce"
    if addon_type == "Odoo EE (Enterprise)":
        return "core_ee"
    return "custom"


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    env: str | None = typer.Option(
        None,
        "--env",
        "-e",
        help=(
            "Environment to use (e.g. prod, test). "
            "If not provided, looks for .oduit.toml in current directory"
        ),
    ),
    json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output in JSON format",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Fail instead of prompting for confirmation",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show verbose output including configuration and command details",
    ),
    no_http: bool = typer.Option(
        False,
        "--no-http",
        help="Add --no-http flag to all odoo-bin commands",
    ),
    odoo_series: OdooSeries | None = ODOO_SERIES_OPTION,
) -> None:
    """Odoo CLI tool for starting odoo-bin and running tasks."""

    # Store config info in context for subcommands
    ctx.obj = {
        "env": env,
        "json": json,
        "non_interactive": non_interactive,
        "verbose": verbose,
        "no_http": no_http,
        "odoo_series": odoo_series,
    }
    if not ctx.invoked_subcommand:
        config_loader = ConfigLoader()
        has_local = config_loader.has_local_config()

        if has_local:
            print("Available commands:")
            print("  init ENV           Initialize new environment")
            print("  run                Run Odoo server")
            print("  shell              Start Odoo shell")
            print("  install MODULE     Install a module")
            print("  update MODULE      Update a module")
            print("  test               Run tests")
            print("  create-db          Create database")
            print("  list-db            List databases")
            print("  list-env           List available environments")
            print("  doctor             Diagnose environment issues")
            print("  create-addon NAME  Create new addon")
            print("  list-addons        List available addons")
            print("  print-manifest NAME   Print addon manifest information")
            print("  list-depends MODULES   List direct dependencies for installation")
            print("  install-order MODULES Dependency-resolved install order")
            print("  list-codepends MODULE  List reverse dependencies of a module")
            print("  impact-of-update MODULE  Addons affected by an update")
            print("  list-missing MODULES   Find missing dependencies")
            print("  list-duplicates     List duplicate addon names")
            print("  export-lang MODULE Export language translations")
            print("  print-config       Print environment configuration")
            print("  agent ...          Structured agent-first inspection commands")
            print("")
            print("Examples:")
            print("  oduit run                         # Run with local .oduit.toml")
            print("  oduit test --test-tags /sale      # Test sale module")
            print("  oduit update sale                 # Update sale module")
        else:
            print_error(
                "No command specified and no .oduit.toml found in current directory"
            )
            print("")
            print("Usage: oduit [--env ENV] COMMAND [arguments]")
            print("")
            print("Available commands:")
            print(
                "  init, run, shell, install, update, test, create-db, "
                "list-db, list-env, doctor"
            )
            print(
                "  create-addon, list-addons, print-manifest, list-depends, "
                "install-order, list-codepends, impact-of-update, list-missing, "
                "list-duplicates"
            )
            print("  export-lang, print-config, agent")
            print("")
            print("Examples:")
            print("  oduit --env dev run               # Run Odoo server")
            print("  oduit --env dev update sale       # Update module 'sale'")
        raise typer.Exit(1) from None


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Diagnose environment and configuration issues."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    report = _build_doctor_report(global_config)
    if global_config.format == OutputFormat.JSON:
        print(json.dumps(report))
    else:
        _print_doctor_report(report)

    if not report.get("success", False):
        raise typer.Exit(1)


@app.command()
def run(
    ctx: typer.Context,
    dev: DevFeature | None = DEV_OPTION,
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    stop_after_init: bool = typer.Option(
        False,
        "--stop-after-init",
        "-s",
        help="Stop the server after initialization",
    ),
) -> None:
    """Run Odoo server."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )
    odoo_operations.run_odoo(
        no_http=global_config.no_http,
        dev=dev,
        log_level=log_level.value if log_level else None,
        stop_after_init=stop_after_init,
    )


@app.command()
def shell(
    ctx: typer.Context,
    shell_interface: ShellInterface | None = SHELL_INTERFACE_OPTION,
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Suppress INFO logs at startup for cleaner output",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Start Odoo shell."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    odoo_operations.run_shell(
        shell_interface=shell_interface.value if shell_interface else None,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )


@app.command()
def install(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to install"),
    without_demo: str | None = typer.Option(
        None, "--without-demo", help="Install without demo data"
    ),
    with_demo: bool = typer.Option(
        False, "--with-demo", help="Install with demo data (overrides config)"
    ),
    language: str | None = LANGUAGE_OPTION,
    max_cron_threads: int | None = typer.Option(
        None,
        "--max-cron-threads",
        help="Set maximum cron threads for Odoo server",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    compact: bool = typer.Option(
        False, "--compact", help="Suppress INFO logs at startup for cleaner output"
    ),
    include_command: bool = typer.Option(
        False, "--include-command", help="Include executed command in result JSON"
    ),
    include_stdout: bool = typer.Option(
        False, "--include-stdout", help="Include stdout in result JSON"
    ),
) -> None:
    """Install module."""
    if not module:
        print_error("Module name is required for install")
        raise typer.Exit(1) from None
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    output = odoo_operations.install_module(
        module,
        no_http=global_config.no_http,
        max_cron_threads=max_cron_threads,
        without_demo=without_demo or False,
        with_demo=with_demo,
        language=language,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )

    # Optional JSON output
    if global_config.format == OutputFormat.JSON:
        # By default, exclude command and stdout from result
        exclude_fields = ["command", "stdout"]

        additional_fields = {
            "without_demo": without_demo,
            "verbose": global_config.verbose,
        }

        # Only include command if requested
        if include_command:
            exclude_fields.remove("command")

        # Only include stdout if requested
        if include_stdout:
            exclude_fields.remove("stdout")

        result_json = output_result_to_json(
            output, additional_fields=additional_fields, exclude_fields=exclude_fields
        )
        print(json.dumps(result_json))

    # Exit with code 1 on failure regardless of output format
    if not output.get("success"):
        raise typer.Exit(1)


@app.command()
def update(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to update"),
    without_demo: str | None = typer.Option(
        None, "--without-demo", help="Update without demo data"
    ),
    language: str | None = LANGUAGE_OPTION,
    i18n_overwrite: bool = typer.Option(
        False, "--i18n-overwrite", help="Overwrite existing translations during update"
    ),
    max_cron_threads: int | None = typer.Option(
        None,
        "--max-cron-threads",
        help="Set maximum cron threads for Odoo server",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Suppress INFO logs at startup for cleaner output",
    ),
) -> None:
    """Update module."""
    if not module:
        print_error("Module name is required for update")
        raise typer.Exit(1) from None
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    if i18n_overwrite:
        language = language or global_config.env_config.get("language", "de_DE")
        # Ensure language is a string
        if language is None:
            language = "de_DE"

    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    result = odoo_operations.update_module(
        module,
        no_http=global_config.no_http,
        max_cron_threads=max_cron_threads,
        without_demo=without_demo or False,
        language=language,
        i18n_overwrite=i18n_overwrite,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )
    if compact and result:
        print_info(str(result))

    # Exit with code 1 on failure regardless of output format
    if not result.get("success"):
        raise typer.Exit(1)


@app.command()
def test(
    ctx: typer.Context,
    stop_on_error: bool = typer.Option(
        False,
        "--stop-on-error",
        help="Abort test run on first detected failure in output",
    ),
    install: str | None = typer.Option(
        None,
        "--install",
        help="Install specified addon before testing",
    ),
    update: str | None = typer.Option(
        None,
        "--update",
        help="Update specified addon before testing",
    ),
    coverage: str | None = typer.Option(
        None,
        "--coverage",
        help="Run coverage report for specified module after tests",
    ),
    test_file: str | None = typer.Option(
        None,
        "--test-file",
        help="Run a specific Python test file",
    ),
    test_tags: str | None = typer.Option(
        None,
        "--test-tags",
        help="Comma-separated list of specs to filter tests",
    ),
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Show only test progress dots, statistics, and result summaries",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    include_command: bool = typer.Option(
        False, "--include-command", help="Include executed command in result JSON"
    ),
    include_stdout: bool = typer.Option(
        False, "--include-stdout", help="Include stdout in result JSON"
    ),
) -> None:
    """Run module tests with various options.

    Examples:
      oduit test --test-tags /sale                     # Test sale
      oduit test --test-tags /sale --coverage sale     # With coverage
      oduit test --install sale --test-tags /sale      # Install & test
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    result = odoo_operations.run_tests(
        None,
        stop_on_error=stop_on_error,
        update=update,
        install=install,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )

    # Optional JSON output
    if global_config.format == OutputFormat.JSON:
        # By default, exclude command and stdout from result
        exclude_fields = ["command", "stdout"]

        additional_fields: dict[str, Any] = {
            "stop_on_error": stop_on_error,
            "install": install,
            "update": update,
            "coverage": coverage,
            "test_file": test_file,
            "test_tags": test_tags,
            "compact": compact,
            "verbose": global_config.verbose,
        }

        # Only include command if requested
        if include_command:
            exclude_fields.remove("command")

        # Only include stdout if requested
        if include_stdout:
            exclude_fields.remove("stdout")

        result_json = output_result_to_json(
            result, additional_fields=additional_fields, exclude_fields=exclude_fields
        )
        print(json.dumps(result_json))

    # Exit with code 1 on failure regardless of output format
    if not result.get("success"):
        raise typer.Exit(1)


@app.command("create-db")
def create_db(
    ctx: typer.Context,
    create_role: bool = typer.Option(
        False,
        "--create-role",
        help="Create DB Role",
    ),
    alter_role: bool = typer.Option(
        False,
        "--alter-role",
        help="Alter DB Role",
    ),
    with_sudo: bool = typer.Option(
        False,
        "--with-sudo",
        help="Use sudo for database creation (if required by PostgreSQL setup)",
    ),
    drop: bool = typer.Option(
        False,
        "--drop",
        help="Drop database if it exists before creating",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Run without confirmation prompt (use with caution)",
    ),
    db_user: str | None = typer.Option(
        None,
        "--db-user",
        help="Specify the database user (overrides config setting)",
    ),
) -> None:
    """Create database."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None
    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    db_name = global_config.env_config.get("db_name", "Unknown")
    effective_non_interactive = non_interactive or global_config.non_interactive

    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    # Check if database exists
    exists_result = odoo_operations.db_exists(
        with_sudo=with_sudo,
        suppress_output=True,
        db_user=db_user,
    )

    db_exists = exists_result.get("exists", False)

    # Handle existing database
    if db_exists:
        if drop:
            confirmation = ""
            if effective_non_interactive:
                _confirmation_required_error(
                    global_config,
                    "create_db",
                    f"Database '{db_name}' already exists and dropping it "
                    "requires confirmation.",
                    remediation=[
                        "Re-run without `--non-interactive` to confirm the drop.",
                        "Or remove `--drop` if the existing database should be kept.",
                    ],
                )
            else:
                print_warning(f"Database '{db_name}' already exists.")
                message = "Do you want to drop it before creating?"
                confirmation = input(f"{message} (y/N): ").strip().lower()

            if confirmation == "y":
                print_info(f"Dropping existing database '{db_name}'...")
                drop_result = odoo_operations.drop_db(
                    with_sudo=with_sudo,
                    suppress_output=False,
                )
                if not drop_result.get("success", False):
                    print_error("Failed to drop database")
                    raise typer.Exit(1) from None
            else:
                print_info("Database drop cancelled.")
                raise typer.Exit(0) from None
        else:
            print_error(
                f"Database '{db_name}' already exists. "
                f"Use --drop flag to drop it first."
            )
            raise typer.Exit(1) from None

    # Create database
    confirmation = ""
    if not db_exists:
        if effective_non_interactive:
            _confirmation_required_error(
                global_config,
                "create_db",
                f"Creating database '{db_name}' requires confirmation in "
                "non-interactive mode.",
                remediation=[
                    "Re-run without `--non-interactive` to confirm database creation.",
                ],
            )
        print_warning(f"This will create a new database named '{db_name}'.")
        message = "Are you sure you want to create a new database?"
        confirmation = input(f"{message} (y/N): ").strip().lower()

    if confirmation == "y":
        odoo_operations.create_db(
            create_role=create_role,
            alter_role=alter_role,
            with_sudo=with_sudo,
            db_user=db_user,
        )
    else:
        print_info("Database creation cancelled.")


@app.command("list-db")
def list_db(
    ctx: typer.Context,
    with_sudo: bool = typer.Option(
        False,
        "--with-sudo/--no-sudo",
        help="Use sudo for database listing (default: False)",
    ),
    db_user: str | None = typer.Option(
        None,
        "--db-user",
        help="Specify the database user (overrides config setting)",
    ),
    include_command: bool = typer.Option(
        False, "--include-command", help="Include executed command in result JSON"
    ),
    include_stdout: bool = typer.Option(
        False, "--include-stdout", help="Include stdout in result JSON"
    ),
) -> None:
    """List all databases."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None
    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )
    result = odoo_operations.list_db(
        with_sudo=with_sudo,
        db_user=db_user,
    )

    if global_config.format == OutputFormat.JSON:
        # By default, exclude command and stdout from result
        exclude_fields = ["command", "stdout"]

        additional_fields: dict[str, Any] = {}

        # Only include command if requested
        if include_command:
            exclude_fields.remove("command")

        # Only include stdout if requested
        if include_stdout:
            exclude_fields.remove("stdout")

        result_json = output_result_to_json(
            result, additional_fields=additional_fields, exclude_fields=exclude_fields
        )
        print(json.dumps(result_json))
    elif not result.get("success"):
        raise typer.Exit(1)


@app.command("list-env")
def list_env() -> None:
    """List available environments."""
    from rich.console import Console
    from rich.table import Table

    from oduit.config_loader import ConfigLoader

    try:
        environments = ConfigLoader().get_available_environments()
        if not environments:
            print_info("No environments found in .oduit directory")
            return

        table = Table(title="Available Environments", show_header=True)
        table.add_column("Environment", style="cyan", no_wrap=True)

        for env in environments:
            table.add_row(env)

        console = Console()
        console.print(table)
    except FileNotFoundError:
        print_error("No .oduit directory found in current directory")
        raise typer.Exit(1) from None
    except Exception as e:
        print_error(f"Failed to list environments: {e}")
        raise typer.Exit(1) from None


@app.command("print-config")
def print_config_cmd(ctx: typer.Context) -> None:
    """Print environment config."""
    from rich.console import Console
    from rich.table import Table

    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    if global_config.format == OutputFormat.JSON:
        output_data = output_result_to_json(
            {
                "success": True,
                "operation": "print_config",
                "environment": global_config.env_name,
                "config": global_config.env_config,
            }
        )
        print(json.dumps(output_data))
        return

    console = Console()
    table = Table(
        title=f"Environment Configuration: {global_config.env_name}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Setting", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    for key, value in sorted(global_config.env_config.items()):
        if isinstance(value, list):
            formatted_value = "\n".join(f"• {item}" for item in value)
            table.add_row(key, formatted_value)
        elif isinstance(value, str) and key == "addons_path" and "," in value:
            paths = [p.strip() for p in value.split(",")]
            formatted_value = "\n".join(f"• {item}" for item in paths)
            table.add_row(key, formatted_value)
        else:
            table.add_row(key, str(value))

    console.print(table)


@app.command("create-addon")
def create_addon(
    ctx: typer.Context,
    addon_name: str = typer.Argument(help="Name of the addon to create"),
    path: str | None = typer.Option(
        None, "--path", help="Path where to create the addon"
    ),
    template: AddonTemplate = ADDON_TEMPLATE_OPTION,
) -> None:
    """Create new addon."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    if not validate_addon_name(addon_name):
        print_error(
            f"Invalid addon name '{addon_name}'. "
            f"Must be lowercase letters, numbers, underscores only."
        )
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    odoo_operations.create_addon(addon_name, destination=path, template=template.value)


def _get_addon_type(addon_name: str, odoo_series: OdooSeries | None) -> str:
    """Determine the addon type (CE, EE, or Custom)."""
    from manifestoo_core.core_addons import is_core_ce_addon, is_core_ee_addon

    if odoo_series:
        if is_core_ce_addon(addon_name, odoo_series):
            return "Odoo CE (Community)"
        elif is_core_ee_addon(addon_name, odoo_series):
            return "Odoo EE (Enterprise)"
    return "Custom"


def _build_addon_table(
    addon_name: str,
    manifest: Any,
    addon_type: str,
) -> Any:
    """Build a Rich table with addon information."""
    from rich.table import Table

    table = Table(
        title=f"Addon: {addon_name}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    # Add rows for each important field
    table.add_row("Technical Name", addon_name)
    table.add_row("Display Name", manifest.name)
    table.add_row("Version", manifest.version)
    table.add_row("Addon Type", addon_type)

    if manifest.summary:
        table.add_row("Summary", manifest.summary)
    if manifest.author:
        table.add_row("Author", manifest.author)
    if manifest.website:
        table.add_row("Website", manifest.website)
    if manifest.license:
        table.add_row("License", manifest.license)

    # Get category from raw data
    raw_data = manifest.get_raw_data()
    if "category" in raw_data:
        table.add_row("Category", str(raw_data["category"]))

    table.add_row("Installable", "Yes" if manifest.installable else "No")
    table.add_row("Auto Install", "Yes" if manifest.auto_install else "No")

    deps_str = (
        ", ".join(manifest.codependencies) if manifest.codependencies else "(none)"
    )
    table.add_row("Dependencies", deps_str)

    if manifest.python_dependencies:
        table.add_row("Python Dependencies", ", ".join(manifest.python_dependencies))
    if manifest.binary_dependencies:
        table.add_row("Binary Dependencies", ", ".join(manifest.binary_dependencies))

    table.add_row("Module Path", manifest.module_path)

    return table


# Valid filter fields for --include and --exclude options
VALID_FILTER_FIELDS = [
    "name",
    "version",
    "summary",
    "author",
    "website",
    "license",
    "category",
    "module_path",
    "depends",
    "addon_type",
]


def _get_addon_field_value(
    addon_name: str,
    field: str,
    module_manager: ModuleManager,
    odoo_series: OdooSeries | None = None,
) -> str:
    """Get the value of a specific field for an addon.

    Args:
        addon_name: Name of the addon
        field: Field name to retrieve
        module_manager: ModuleManager instance
        odoo_series: Optional Odoo series for addon_type detection

    Returns:
        String value of the field, or empty string if not found
    """
    # Handle module_path separately as it's not in manifest
    if field == "module_path":
        path = module_manager.find_module_path(addon_name)
        return path if path else ""

    # Handle addon_type separately
    if field == "addon_type":
        if odoo_series is None:
            odoo_series = module_manager.detect_odoo_series()
        return _get_addon_type(addon_name, odoo_series)

    manifest = module_manager.get_manifest(addon_name)
    if not manifest:
        return ""

    # Map field names to manifest properties
    if field == "name":
        return manifest.name
    elif field == "version":
        return manifest.version
    elif field == "summary":
        return manifest.summary
    elif field == "author":
        return manifest.author
    elif field == "website":
        return manifest.website
    elif field == "license":
        return manifest.license
    elif field == "depends":
        return ",".join(manifest.codependencies)
    elif field == "category":
        raw_data = manifest.get_raw_data()
        return str(raw_data.get("category", ""))

    return ""


def _filter_addons_by_field(
    addons: list[str],
    module_manager: ModuleManager,
    field: str,
    filter_value: str,
    is_include: bool,
    odoo_series: OdooSeries | None = None,
) -> list[str]:
    """Filter addons by a specific field value.

    Args:
        addons: List of addon names to filter
        module_manager: ModuleManager instance
        field: Field name to filter on
        filter_value: Value to match (case-insensitive substring match)
        is_include: If True, include matching addons; if False, exclude them
        odoo_series: Optional Odoo series for addon_type detection

    Returns:
        Filtered list of addon names
    """
    filtered_addons = []
    filter_lower = filter_value.lower()

    for addon in addons:
        field_value = _get_addon_field_value(addon, field, module_manager, odoo_series)
        field_value_lower = field_value.lower() if field_value else ""

        matches = filter_lower in field_value_lower

        if is_include:
            # Include only if it matches
            if matches:
                filtered_addons.append(addon)
        else:
            # Exclude if it matches (include if it doesn't match)
            if not matches:
                filtered_addons.append(addon)

    return filtered_addons


def _apply_core_addon_filters(
    addons: list[str],
    exclude_core_addons: bool,
    exclude_enterprise_addons: bool,
    odoo_series: OdooSeries | None,
) -> list[str]:
    """Apply CE/EE core addon exclusion filters.

    Args:
        addons: List of addon names to filter
        exclude_core_addons: Whether to exclude CE core addons
        exclude_enterprise_addons: Whether to exclude EE addons
        odoo_series: Odoo series for detection

    Returns:
        Filtered list of addon names

    Raises:
        ValueError: If Odoo series cannot be detected
    """
    from manifestoo_core.core_addons import is_core_ce_addon, is_core_ee_addon

    if not odoo_series:
        raise ValueError(
            "Could not detect Odoo series. "
            "Please specify --odoo-series to use exclusion filters"
        )

    filtered_addons = []
    for addon in addons:
        if exclude_core_addons and is_core_ce_addon(addon, odoo_series):
            continue
        if exclude_enterprise_addons and is_core_ee_addon(addon, odoo_series):
            continue
        filtered_addons.append(addon)
    return filtered_addons


def _apply_field_filters(
    addons: list[str],
    module_manager: ModuleManager,
    include_filter: list[tuple[str, str]],
    exclude_filter: list[tuple[str, str]],
    odoo_series: OdooSeries | None,
) -> list[str]:
    """Apply include/exclude field filters to addon list.

    Args:
        addons: List of addon names to filter
        module_manager: ModuleManager instance
        include_filter: List of (field, value) tuples for include filters
        exclude_filter: List of (field, value) tuples for exclude filters
        odoo_series: Odoo series for addon_type detection

    Returns:
        Filtered list of addon names

    Raises:
        ValueError: If field is invalid
    """
    # Apply include filters (skip if empty list)
    if include_filter:
        for field, value in include_filter:
            if field not in VALID_FILTER_FIELDS:
                raise ValueError(
                    f"Invalid field '{field}'. "
                    f"Valid fields: {', '.join(VALID_FILTER_FIELDS)}"
                )
            addons = _filter_addons_by_field(
                addons,
                module_manager,
                field,
                value,
                is_include=True,
                odoo_series=odoo_series,
            )

    # Apply exclude filters (skip if empty list)
    if exclude_filter:
        for field, value in exclude_filter:
            if field not in VALID_FILTER_FIELDS:
                raise ValueError(
                    f"Invalid field '{field}'. "
                    f"Valid fields: {', '.join(VALID_FILTER_FIELDS)}"
                )
            addons = _filter_addons_by_field(
                addons,
                module_manager,
                field,
                value,
                is_include=False,
                odoo_series=odoo_series,
            )

    return addons


@app.command("print-manifest")
def print_manifest(
    ctx: typer.Context,
    addon_name: str = typer.Argument(help="Name of the addon to display"),
) -> None:
    """Print addon manifest information in a table.

    Displays key manifest fields including name, version, author, license,
    dependencies, and whether the addon is a core CE/EE addon.
    """
    from rich.console import Console

    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    manifest = module_manager.get_manifest(addon_name)
    if not manifest:
        print_error(f"Addon '{addon_name}' not found in addons path")
        raise typer.Exit(1) from None

    # Detect Odoo series for CE/EE detection
    odoo_series = (
        global_config.odoo_series
        if global_config.odoo_series
        else module_manager.detect_odoo_series()
    )

    addon_type = _get_addon_type(addon_name, odoo_series)

    # JSON output
    if global_config.format == OutputFormat.JSON:
        raw_data = manifest.get_raw_data()
        output_data: dict[str, Any] = output_result_to_json(
            {
                "success": True,
                "operation": "print_manifest",
                "technical_name": addon_name,
                "name": manifest.name,
                "version": manifest.version,
                "summary": manifest.summary,
                "author": manifest.author,
                "website": manifest.website,
                "license": manifest.license,
                "installable": manifest.installable,
                "auto_install": manifest.auto_install,
                "depends": manifest.codependencies,
                "addon_type": addon_type,
                "module_path": manifest.module_path,
            },
            result_type="manifest",
        )
        if manifest.python_dependencies:
            output_data["python_dependencies"] = manifest.python_dependencies
        if manifest.binary_dependencies:
            output_data["binary_dependencies"] = manifest.binary_dependencies
        if "category" in raw_data:
            output_data["category"] = raw_data["category"]
        print(json.dumps(output_data))
        return

    # Table output
    console = Console()
    table = _build_addon_table(addon_name, manifest, addon_type)
    console.print(table)


def _parse_filter_option(
    ctx: click.Context, param: click.Parameter, value: tuple[str, ...]
) -> list[tuple[str, str]]:
    """Parse filter option values into list of (field, value) tuples.

    Args:
        ctx: Click context
        param: Click parameter
        value: Tuple of strings from multiple --include/--exclude options

    Returns:
        List of (field, value) tuples
    """
    if not value:
        return []

    # value comes as flat tuple: ('field1', 'value1', 'field2', 'value2', ...)
    # We need to pair them up
    result: list[tuple[str, str]] = []
    for i in range(0, len(value), 2):
        if i + 1 < len(value):
            result.append((value[i], value[i + 1]))
    return result


@app.command("list-addons")
def list_addons(
    ctx: typer.Context,
    type: AddonListType = ADDON_LIST_TYPE_OPTION,
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter addons by directory (e.g., 'myaddons')",
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    exclude_core_addons: bool = typer.Option(
        False,
        "--exclude-core-addons",
        help="Exclude Odoo Community Edition (CE) core addons from the list",
    ),
    exclude_enterprise_addons: bool = typer.Option(
        False,
        "--exclude-enterprise-addons",
        help="Exclude Odoo Enterprise Edition (EE) addons from the list",
    ),
    include: list[str] = INCLUDE_FILTER_OPTION,
    exclude: list[str] = EXCLUDE_FILTER_OPTION,
    sorting: str = SORT_OPTION,
) -> None:
    """List available addons.

    Filter addons using --include or --exclude with FIELD:VALUE format.

    Examples:

      oduit list-addons --exclude category:Theme

      oduit list-addons --include author:Odoo --include category:Sales
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    # Parse include/exclude filters from FIELD:VALUE format
    include_filter: list[tuple[str, str]] = []
    exclude_filter: list[tuple[str, str]] = []

    for filter_str in include:
        if ":" not in filter_str:
            print_error(
                f"Invalid include filter '{filter_str}'. "
                f"Use format 'FIELD:VALUE' (e.g., 'category:Sales')"
            )
            raise typer.Exit(1) from None
        field, value = filter_str.split(":", 1)
        include_filter.append((field.strip(), value.strip()))

    for filter_str in exclude:
        if ":" not in filter_str:
            print_error(
                f"Invalid exclude filter '{filter_str}'. "
                f"Use format 'FIELD:VALUE' (e.g., 'category:Theme')"
            )
            raise typer.Exit(1) from None
        field, value = filter_str.split(":", 1)
        exclude_filter.append((field.strip(), value.strip()))

    module_manager = ModuleManager(global_config.env_config["addons_path"])
    addons = module_manager.find_module_dirs(filter_dir=select_dir)

    addons = [addon for addon in addons if not addon.startswith("test_")]

    # Detect Odoo series once for filters that need it
    odoo_series = (
        global_config.odoo_series
        if global_config.odoo_series
        else module_manager.detect_odoo_series()
    )

    if exclude_core_addons or exclude_enterprise_addons:
        try:
            addons = _apply_core_addon_filters(
                addons, exclude_core_addons, exclude_enterprise_addons, odoo_series
            )
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1) from None

    # Apply include/exclude filters
    try:
        addons = _apply_field_filters(
            addons, module_manager, include_filter, exclude_filter, odoo_series
        )
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1) from None

    try:
        sorted_addons = module_manager.sort_modules(addons, sorting)
    except ValueError as e:
        print_error(f"Sorting failed: {e}")
        raise typer.Exit(1) from None

    if separator:
        print(separator.join(sorted_addons))
    else:
        for addon in sorted_addons:
            print(addon)


@app.command("list-manifest-values")
def list_manifest_values(
    ctx: typer.Context,
    field: str = typer.Argument(
        help=(
            "Manifest field to list unique values for. "
            f"Valid fields: {_VALID_FILTER_FIELDS_STR}"
        ),
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter addons by directory (e.g., 'myaddons')",
    ),
    exclude_core_addons: bool = typer.Option(
        False,
        "--exclude-core-addons",
        help="Exclude Odoo Community Edition (CE) core addons from the list",
    ),
    exclude_enterprise_addons: bool = typer.Option(
        False,
        "--exclude-enterprise-addons",
        help="Exclude Odoo Enterprise Edition (EE) addons from the list",
    ),
) -> None:
    """List unique values for a manifest field across all addons.

    Examples:

      oduit list-manifest-values category

      oduit list-manifest-values author --exclude-core-addons

      oduit list-manifest-values license --separator ","
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    # Validate field
    if field not in VALID_FILTER_FIELDS:
        print_error(
            f"Invalid field '{field}'. Valid fields: {', '.join(VALID_FILTER_FIELDS)}"
        )
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])
    addons = module_manager.find_module_dirs(filter_dir=select_dir)

    # Detect Odoo series for filters that need it
    odoo_series = (
        global_config.odoo_series
        if global_config.odoo_series
        else module_manager.detect_odoo_series()
    )

    if exclude_core_addons or exclude_enterprise_addons:
        try:
            addons = _apply_core_addon_filters(
                addons, exclude_core_addons, exclude_enterprise_addons, odoo_series
            )
        except ValueError as e:
            print_error(str(e))
            raise typer.Exit(1) from None

    # Collect unique values
    unique_values: set[str] = set()
    for addon in addons:
        value = _get_addon_field_value(addon, field, module_manager, odoo_series)
        if not value:
            continue
        # Handle comma-separated values (e.g., depends field)
        if field == "depends":
            for v in value.split(","):
                v = v.strip()
                if v:
                    unique_values.add(v)
        else:
            unique_values.add(value)

    sorted_values = sorted(unique_values)

    # JSON output
    if global_config.format == OutputFormat.JSON:
        output_data = output_result_to_json(
            {
                "success": True,
                "operation": "list_manifest_values",
                "field": field,
                "values": sorted_values,
            },
            result_type="manifest_values",
        )
        print(json.dumps(output_data))
        return

    # Text output
    if separator:
        print(separator.join(sorted_values))
    else:
        for value in sorted_values:
            print(value)


@app.command("list-duplicates")
def list_duplicates(ctx: typer.Context) -> None:
    """List duplicate addon names across configured addon paths."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    addons_path = global_config.env_config.get("addons_path")
    if not addons_path:
        _print_command_error_result(
            global_config,
            "list_duplicates",
            "addons_path is not configured",
            error_type="ConfigError",
            remediation=[
                "Set `addons_path` before running duplicate-module analysis.",
            ],
        )
        raise typer.Exit(1) from None

    path_manager = AddonsPathManager(str(addons_path))
    duplicate_modules = path_manager.find_duplicate_module_names()

    if global_config.format == OutputFormat.JSON:
        payload = output_result_to_json(
            {
                "success": True,
                "operation": "list_duplicates",
                "duplicate_modules": duplicate_modules,
                "duplicate_count": len(duplicate_modules),
            },
            result_type="duplicate_modules",
        )
        print(json.dumps(payload))
        return

    if not duplicate_modules:
        print_info("No duplicate addon names found")
        return

    for module_name in sorted(duplicate_modules):
        print(f"{module_name}:")
        for location in duplicate_modules[module_name]:
            print(f"  - {location}")


def _print_dependency_tree(
    module_list: list[str],
    module_manager: ModuleManager,
    tree_depth: int | None,
    odoo_series: OdooSeries | None = None,
) -> None:
    """Print dependency tree for a list of modules."""
    if odoo_series is None:
        odoo_series = module_manager.detect_odoo_series()

    for i, module_name in enumerate(module_list):
        dep_tree = module_manager.get_dependency_tree(module_name, max_depth=tree_depth)
        lines = format_dependency_tree(
            module_name,
            dep_tree,
            module_manager,
            "",
            True,
            set(),
            odoo_series,
            is_root=True,
        )
        for module_part, version_part in lines:
            typer.echo(module_part, nl=False)
            if version_part == " ⬆":
                typer.secho(version_part, fg="bright_black")
            elif version_part:
                typer.secho(version_part, fg="bright_black")
            else:
                typer.echo("")
        if i < len(module_list) - 1:
            typer.echo()


def _print_dependency_list(
    module_list: list[str],
    module_manager: ModuleManager,
    tree_depth: int | None,
    depth: int | None,
    separator: str | None,
    source_desc: str,
    sorting: str = "alphabetical",
) -> None:
    """Print flat list of dependencies."""
    if depth is not None and depth >= 0:
        dependencies = module_manager.get_dependencies_at_depth(
            module_list, max_depth=tree_depth
        )
    else:
        dependencies = module_manager.get_direct_dependencies(*module_list)

    try:
        sorted_dependencies = module_manager.sort_modules(dependencies, sorting)
    except ValueError as e:
        print_error(f"Sorting failed: {e}")
        sorted_dependencies = dependencies

    if separator:
        if sorted_dependencies:
            print(separator.join(sorted_dependencies))
    elif sorted_dependencies:
        for dep in sorted_dependencies:
            print(f"{dep}")
    else:
        print(f"No external dependencies for {source_desc}")


@app.command("list-depends")
def list_depends(
    ctx: typer.Context,
    modules: str | None = typer.Argument(
        None, help="Comma-separated module names to check dependencies for"
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    tree: bool = typer.Option(
        False,
        "--tree",
        help="Display dependencies as a tree structure",
    ),
    depth: int | None = typer.Option(
        -1,
        "--depth",
        help="Maximum depth of dependencies to show "
        "(-1= no maximum, 0=direct only, 1=direct+their deps, etc.)",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter modules by directory (e.g., 'myaddons')",
    ),
    sorting: str = SORT_OPTION,
) -> None:
    """List direct dependencies needed to install a set of modules.

    Direct dependencies are external modules (not in the provided set) needed
    for installation. For example, if modules a, b, c depend on crm and mail,
    this will show crm and mail.

    Use --tree to show the full dependency tree with versions.
    Use --select-dir to get dependencies for all modules in a specific directory.
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    if modules is None and select_dir is None:
        print_error("Either provide module names or use --select-dir option")
        raise typer.Exit(1) from None

    if modules is not None and select_dir is not None:
        print_error("Cannot use both module names and --select-dir option")
        raise typer.Exit(1) from None

    try:
        if select_dir:
            addons = module_manager.find_module_dirs(filter_dir=select_dir)
            if not addons:
                print_error(f"No modules found in directory '{select_dir}'")
                raise typer.Exit(1) from None
            module_list = sorted(addons)
            source_desc = f"directory '{select_dir}'"
        else:
            assert modules is not None
            module_list = [m.strip() for m in modules.split(",")]
            if len(module_list) == 1:
                source_desc = f"'{modules}'"
            else:
                source_desc = f"modules [{', '.join(module_list)}]"

        tree_depth = depth + 1 if depth is not None and depth >= 0 else None

        if tree:
            _print_dependency_tree(
                module_list, module_manager, tree_depth, global_config.odoo_series
            )
        else:
            _print_dependency_list(
                module_list,
                module_manager,
                tree_depth,
                depth,
                separator,
                source_desc,
                sorting,
            )
    except ValueError as e:
        print_error(f"Error checking dependencies: {e}")
        raise typer.Exit(1) from None


@app.command("list-codepends")
def list_codepends(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to inspect reverse dependencies for"),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
) -> None:
    """List reverse dependencies for a module.

    The output includes the selected module itself plus any modules that
    directly or indirectly depend on it.
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    reverse_dependencies = module_manager.get_reverse_dependencies(module)

    # Include the selected module itself in the output
    all_codeps = sorted(reverse_dependencies + [module])

    if separator:
        if all_codeps:
            print(separator.join(all_codeps))
    elif all_codeps:
        for dep in all_codeps:
            print(f"{dep}")
    else:
        print_info(f"Module '{module}' has no reverse dependencies")


@app.command("install-order")
def install_order(
    ctx: typer.Context,
    modules: str | None = typer.Argument(
        None, help="Comma-separated module names to compute install order for"
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Get install order for all modules in a specific directory",
    ),
) -> None:
    """Return the dependency-resolved install order for one or more addons."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    if modules is None and select_dir is None:
        _print_command_error_result(
            global_config,
            "install_order",
            "Either provide module names or use --select-dir option",
            details={"modules": modules, "select_dir": select_dir},
        )
        raise typer.Exit(1) from None

    if modules is not None and select_dir is not None:
        _print_command_error_result(
            global_config,
            "install_order",
            "Cannot use both module names and --select-dir option",
            details={"modules": modules, "select_dir": select_dir},
        )
        raise typer.Exit(1) from None

    if select_dir:
        module_list = sorted(module_manager.find_module_dirs(filter_dir=select_dir))
        if not module_list:
            _print_command_error_result(
                global_config,
                "install_order",
                f"No modules found in directory '{select_dir}'",
                details={"select_dir": select_dir},
            )
            raise typer.Exit(1) from None
        source = "select_dir"
    else:
        assert modules is not None
        module_list = [
            module.strip() for module in modules.split(",") if module.strip()
        ]
        missing_modules = [
            module
            for module in module_list
            if module_manager.find_module_path(module) is None
        ]
        if missing_modules:
            _print_command_error_result(
                global_config,
                "install_order",
                f"Modules not found in addons_path: {', '.join(missing_modules)}",
                details={"modules": module_list, "missing_modules": missing_modules},
            )
            raise typer.Exit(1) from None
        source = "modules"

    try:
        ordered_modules = module_manager.get_install_order(*module_list)
    except ValueError as e:
        cycle_details = _dependency_error_details(module_manager, str(e))
        _print_command_error_result(
            global_config,
            "install_order",
            f"Failed to compute install order: {e}",
            error_type=("DependencyCycleError" if cycle_details else "DependencyError"),
            details={
                "modules": module_list,
                "select_dir": select_dir,
                **cycle_details,
            },
            remediation=(
                [
                    "Resolve the dependency cycle and retry the install-order "
                    "analysis.",
                ]
                if cycle_details
                else []
            ),
        )
        raise typer.Exit(1) from None

    if global_config.format == OutputFormat.JSON:
        result_json = output_result_to_json(
            {
                "success": True,
                "operation": "install_order",
                "modules": module_list,
                "install_order": ordered_modules,
                "source": source,
                "select_dir": select_dir,
            }
        )
        print(json.dumps(result_json))
        return

    if separator:
        print(separator.join(ordered_modules))
    else:
        for module in ordered_modules:
            print(module)


@app.command("impact-of-update")
def impact_of_update(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to analyze for update impact"),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
) -> None:
    """Show addons affected by updating a specific module."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])
    if module_manager.find_module_path(module) is None:
        _print_command_error_result(
            global_config,
            "impact_of_update",
            f"Module '{module}' was not found in addons_path",
            details={"module": module},
        )
        raise typer.Exit(1) from None

    impacted_modules = module_manager.get_reverse_dependencies(module)

    if global_config.format == OutputFormat.JSON:
        result_json = output_result_to_json(
            {
                "success": True,
                "operation": "impact_of_update",
                "module": module,
                "impacted_modules": impacted_modules,
                "impact_count": len(impacted_modules),
            }
        )
        print(json.dumps(result_json))
        return

    if not impacted_modules:
        print_info(f"No addons would be impacted by updating '{module}'")
        return

    if separator:
        print(separator.join(impacted_modules))
    else:
        for impacted_module in impacted_modules:
            print(impacted_module)


@app.command("list-missing")
def list_missing(
    ctx: typer.Context,
    modules: str | None = typer.Argument(
        None, help="Comma-separated module names to check for missing dependencies"
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter modules by directory (e.g., 'myaddons')",
    ),
) -> None:
    """Find missing dependencies for modules.

    This command identifies dependencies that are not available in the addons_path.
    Useful for ensuring all required modules are present before installation.

    Use --select-dir to check all modules in a specific directory.
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    if modules is None and select_dir is None:
        print_error("Either provide module names or use --select-dir option")
        raise typer.Exit(1) from None

    if modules is not None and select_dir is not None:
        print_error("Cannot use both module names and --select-dir option")
        raise typer.Exit(1) from None

    try:
        if select_dir:
            module_list = module_manager.find_module_dirs(filter_dir=select_dir)
            if not module_list:
                print_error(f"No modules found in directory '{select_dir}'")
                raise typer.Exit(1) from None
        else:
            assert modules is not None
            module_list = [m.strip() for m in modules.split(",")]

        all_missing = set()
        for module in module_list:
            missing = module_manager.find_missing_dependencies(module)
            all_missing.update(missing)

        if all_missing:
            sorted_missing = sorted(all_missing)
            if separator:
                print(separator.join(sorted_missing))
            else:
                for dep in sorted_missing:
                    print(dep)
        else:
            if not separator:
                print_info("All dependencies are available")
    except ValueError as e:
        print_error(f"Error checking missing dependencies: {e}")
        raise typer.Exit(1) from None


def _check_environment_exists(config_loader: ConfigLoader, env_name: str) -> None:
    """Check if environment already exists and exit if it does."""
    try:
        existing_envs = config_loader.get_available_environments()
        if env_name in existing_envs:
            print_error(f"Environment '{env_name}' already exists")
            raise typer.Exit(1) from None
    except FileNotFoundError:
        pass


def _detect_binaries(
    python_bin: str | None,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> tuple[str, str | None, str | None]:
    """Auto-detect binary paths if not provided.

    Returns:
        Tuple of (python_bin, odoo_bin, coverage_bin)
    """
    if python_bin is None:
        python_bin = shutil.which("python3") or shutil.which("python")
        if python_bin is None:
            print_error("Python binary not found in PATH")
            raise typer.Exit(1) from None

    if odoo_bin is None:
        odoo_bin = shutil.which("odoo") or shutil.which("odoo-bin")
        if odoo_bin is None:
            print_warning(
                "Odoo binary not found in PATH, you may need to specify --odoo-bin"
            )

    if coverage_bin is None:
        coverage_bin = shutil.which("coverage")
        if coverage_bin is None:
            print_warning(
                "Coverage binary not found in PATH, "
                "you may need to specify --coverage-bin"
            )

    return python_bin, odoo_bin, coverage_bin


def _build_initial_config(
    python_bin: str,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> dict[str, Any]:
    """Build initial flat configuration dictionary."""
    env_config: dict[str, Any] = {
        "python_bin": python_bin,
        "coverage_bin": coverage_bin,
    }

    if odoo_bin:
        env_config["odoo_bin"] = odoo_bin

    return env_config


def _import_or_convert_config(
    env_config: dict[str, Any],
    from_conf: str | None,
    config_loader: ConfigLoader,
    python_bin: str,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> dict[str, Any]:
    """Import config from .conf file or convert flat config to sectioned format."""
    if from_conf:
        if not os.path.exists(from_conf):
            print_error(f"Odoo configuration file not found: {from_conf}")
            raise typer.Exit(1) from None

        try:
            env_config = config_loader.import_odoo_conf(from_conf, sectioned=True)

            if "binaries" not in env_config:
                env_config["binaries"] = {}

            binaries_section = env_config.get("binaries")
            if isinstance(binaries_section, dict):
                if python_bin:
                    binaries_section["python_bin"] = python_bin
                if odoo_bin:
                    binaries_section["odoo_bin"] = odoo_bin
                if coverage_bin:
                    binaries_section["coverage_bin"] = coverage_bin

            print_info(f"Imported configuration from: {from_conf}")
        except Exception as e:
            print_error(f"Failed to import Odoo configuration: {e}")
            raise typer.Exit(1) from None
    else:
        from .config_provider import ConfigProvider

        provider = ConfigProvider(env_config)
        env_config = provider.to_sectioned_dict()

    return env_config


def _normalize_addons_path(env_config: dict[str, Any]) -> None:
    """Convert addons_path from comma-separated string to list in-place."""
    odoo_params_section = env_config.get("odoo_params")
    if isinstance(odoo_params_section, dict) and "addons_path" in odoo_params_section:
        addons_path_value = odoo_params_section["addons_path"]
        if isinstance(addons_path_value, str):
            odoo_params_section["addons_path"] = [
                p.strip() for p in addons_path_value.split(",")
            ]


def _save_config_file(
    config_path: str,
    env_config: dict[str, Any],
    config_loader: ConfigLoader,
) -> None:
    """Save configuration to TOML file."""
    tomllib, tomli_w = config_loader._import_toml_libs()
    if tomli_w is None:
        print_error(
            "TOML writing support not available. Install with: pip install tomli-w"
        )
        raise typer.Exit(1) from None

    os.makedirs(config_loader.config_dir, exist_ok=True)

    with open(config_path, "wb") as f:
        tomli_w.dump(env_config, f)


def _display_config_summary(env_config: dict[str, Any]) -> None:
    """Display configuration summary to user."""
    print_info("\nConfiguration summary:")

    binaries = env_config.get("binaries")
    if isinstance(binaries, dict):
        if binaries.get("python_bin"):
            print_info(f"  python_bin: {binaries['python_bin']}")
        if binaries.get("odoo_bin"):
            print_info(f"  odoo_bin: {binaries['odoo_bin']}")
        if binaries.get("coverage_bin"):
            print_info(f"  coverage_bin: {binaries['coverage_bin']}")

    params = env_config.get("odoo_params")
    if isinstance(params, dict):
        if params.get("db_name"):
            print_info(f"  db_name: {params['db_name']}")
        if params.get("addons_path"):
            addons = params["addons_path"]
            if isinstance(addons, list):
                print_info(f"  addons_path: {', '.join(addons)}")
            else:
                print_info(f"  addons_path: {addons}")


@app.command("init")
def init_env(
    env_name: str = typer.Argument(help="Environment name to create"),
    from_conf: str | None = typer.Option(
        None,
        "--from-conf",
        help="Import configuration from existing Odoo .conf file",
    ),
    python_bin: str | None = typer.Option(
        None,
        "--python-bin",
        help="Python binary path (auto-detected if not provided)",
    ),
    odoo_bin: str | None = typer.Option(
        None,
        "--odoo-bin",
        help="Odoo binary path (auto-detected if not provided)",
    ),
    coverage_bin: str | None = typer.Option(
        None,
        "--coverage-bin",
        help="Coverage binary path (auto-detected if not provided)",
    ),
) -> None:
    """Initialize a new oduit environment configuration.

    Creates a new environment configuration in ~/.config/oduit/<env_name>.toml.
    Auto-detects python and odoo binaries from PATH unless explicitly provided.
    Can import settings from existing Odoo .conf file.
    """
    config_loader = ConfigLoader()

    _check_environment_exists(config_loader, env_name)

    python_bin, odoo_bin, coverage_bin = _detect_binaries(
        python_bin, odoo_bin, coverage_bin
    )

    env_config = _build_initial_config(python_bin, odoo_bin, coverage_bin)

    env_config = _import_or_convert_config(
        env_config, from_conf, config_loader, python_bin, odoo_bin, coverage_bin
    )

    _normalize_addons_path(env_config)

    config_path = config_loader.get_config_path(env_name, "toml")

    try:
        _save_config_file(config_path, env_config, config_loader)
        print_info(f"Environment '{env_name}' created successfully")
        print_info(f"Configuration saved to: {config_path}")
        _display_config_summary(env_config)
    except Exception as e:
        print_error(f"Failed to save configuration: {e}")
        raise typer.Exit(1) from None


@app.command("export-lang")
def export_lang(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to export"),
    language: str | None = LANGUAGE_OPTION,
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Export language module."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    language = language or global_config.env_config.get("language", "de_DE")
    if language is None:
        language = "de_DE"

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    module_path = module_manager.find_module_path(module)
    if not module_path:
        print_warning(
            f"Module '{module}' not found in addons path. Using default path."
        )
        module_path = os.path.join(
            global_config.env_config["addons_path"].split(",")[0], module
        )

    i18n_dir = os.path.join(module_path, "i18n")
    if "_" in language:
        filename = os.path.join(i18n_dir, f"{language.split('_')[0]}.po")
    else:
        filename = os.path.join(i18n_dir, f"{language}.po")

    os.makedirs(i18n_dir, exist_ok=True)
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    odoo_operations.export_module_language(
        module,
        filename,
        language,
        no_http=global_config.no_http,
        log_level=log_level.value if log_level else None,
    )


@app.command("version")
def get_odoo_version_cmd(
    ctx: typer.Context,
) -> None:
    """Get Odoo version from odoo-bin."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    ops = OdooOperations(global_config.env_config, verbose=global_config.verbose)
    result = ops.get_odoo_version(suppress_output=True)

    if global_config.format == OutputFormat.JSON:
        result_json = output_result_to_json(result)
        print(json.dumps(result_json))
    else:
        if result.get("success", False) and result.get("version"):
            typer.echo(result["version"])
        else:
            print_error("Failed to detect Odoo version")
            raise typer.Exit(1)


def _build_environment_context_data(global_config: GlobalConfig) -> dict[str, Any]:
    """Build a one-shot environment snapshot for agent workflows."""
    env_config = global_config.env_config or {}
    doctor_report = _build_doctor_report(global_config)
    addons_path = str(env_config.get("addons_path", ""))
    path_manager = AddonsPathManager(addons_path) if addons_path else None
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
        ModuleManager(addons_path) if addons_path and not invalid_paths else None
    )
    available_module_count = 0
    detected_series = None
    if module_manager is not None:
        available_module_count = len(module_manager.find_modules(skip_invalid=True))
        detected_series = (
            global_config.odoo_series or module_manager.detect_odoo_series()
        )

    python_info = _probe_binary(env_config.get("python_bin"), ["python3", "python"])
    odoo_info = _probe_binary(env_config.get("odoo_bin"), ["odoo", "odoo-bin"])
    coverage_info = _probe_binary(env_config.get("coverage_bin"), ["coverage"])

    version_result = OdooOperations(env_config, verbose=False).get_odoo_version(
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


def _build_addon_inspection_data(
    module_manager: ModuleManager,
    module_name: str,
    odoo_series: OdooSeries | None,
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
        "addon_type": _get_agent_addon_type(module_name, odoo_series),
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


def _build_update_plan_data(
    global_config: GlobalConfig,
    module_name: str,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Build a read-only update plan for a module."""
    env_config = global_config.env_config or {}
    module_manager = ModuleManager(str(env_config.get("addons_path", "")))
    detected_series = global_config.odoo_series or module_manager.detect_odoo_series()
    inspection, warnings, remediation = _build_addon_inspection_data(
        module_manager,
        module_name,
        detected_series,
    )

    duplicate_modules = AddonsPathManager(
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


@agent_app.command("context")
def agent_context(ctx: typer.Context) -> None:
    """Return a structured environment snapshot for automation."""
    operation = "agent_context"
    result_type = "environment_context"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(
            operation,
            result_type,
            "No environment configuration available",
            error_type="ConfigError",
        )
    assert global_config.env_config is not None

    ops = OdooOperations(global_config.env_config, verbose=False)
    context = ops.get_environment_context(
        env_name=global_config.env_name,
        config_source=global_config.config_source,
        config_path=global_config.config_path,
        odoo_series=global_config.odoo_series,
    )
    payload = _agent_payload(
        operation,
        result_type,
        context.to_dict(),
        warnings=list(context.warnings),
        remediation=list(context.remediation),
        read_only=True,
        safety_level=SAFE_READ_ONLY,
    )
    _agent_emit_payload(payload)


@agent_app.command("inspect-addon")
def agent_inspect_addon(
    ctx: typer.Context,
    module: str = typer.Argument(help="Addon to inspect"),
) -> None:
    """Return a one-shot addon inspection payload."""
    operation = "inspect_addon"
    result_type = "addon_inspection"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = OdooOperations(global_config.env_config, verbose=False)
    try:
        inspection = ops.inspect_addon(
            module,
            odoo_series=global_config.odoo_series,
        )
    except OduitModuleNotFoundError as exc:
        _agent_fail(
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

    payload = _agent_payload(
        operation,
        result_type,
        inspection.to_dict(),
        warnings=list(inspection.warnings),
        remediation=list(inspection.remediation),
        read_only=True,
        safety_level=SAFE_READ_ONLY,
    )
    _agent_emit_payload(payload)


@agent_app.command("plan-update")
def agent_plan_update(
    ctx: typer.Context,
    module: str = typer.Argument(help="Addon to plan an update for"),
) -> None:
    """Return a structured, read-only update plan for a module."""
    operation = "plan_update"
    result_type = "update_plan"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = OdooOperations(global_config.env_config, verbose=False)
    try:
        plan = ops.plan_update(
            module,
            odoo_series=global_config.odoo_series,
        )
    except OduitModuleNotFoundError as exc:
        _agent_fail(
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

    payload = _agent_payload(
        operation,
        result_type,
        plan.to_dict(),
        warnings=list(plan.warnings),
        remediation=list(plan.remediation),
        read_only=True,
        safety_level=SAFE_READ_ONLY,
    )
    _agent_emit_payload(payload)


@agent_app.command("locate-model")
def agent_locate_model(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to locate"),
    module: str = typer.Option(..., "--module", help="Addon to inspect"),
) -> None:
    """Locate likely source files for a model extension inside one addon."""
    operation = "locate_model"
    result_type = "model_source_location"
    _, ops = _resolve_agent_ops(ctx, operation, result_type)
    try:
        location = ops.locate_model(module, model)
    except OduitModuleNotFoundError as exc:
        _agent_fail(
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
    except ConfigError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"module": module, "model": model},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    payload = _agent_payload(
        operation,
        result_type,
        location.to_dict(),
        warnings=list(location.warnings),
        remediation=list(location.remediation),
    )
    _agent_emit_payload(payload)


@agent_app.command("locate-field")
def agent_locate_field(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to inspect"),
    field_name: str = typer.Argument(help="Field to locate"),
    module: str = typer.Option(..., "--module", help="Addon to inspect"),
) -> None:
    """Locate an existing field or suggest the best insertion point."""
    operation = "locate_field"
    result_type = "field_source_location"
    _, ops = _resolve_agent_ops(ctx, operation, result_type)
    try:
        location = ops.locate_field(module, model, field_name)
    except OduitModuleNotFoundError as exc:
        _agent_fail(
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
    except ConfigError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"module": module, "model": model, "field": field_name},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    payload = _agent_payload(
        operation,
        result_type,
        location.to_dict(),
        warnings=list(location.warnings),
        remediation=list(location.remediation),
    )
    _agent_emit_payload(payload)


@agent_app.command("list-addon-tests")
def agent_list_addon_tests(
    ctx: typer.Context,
    module: str = typer.Argument(help="Addon to inspect"),
    model: str | None = typer.Option(None, "--model", help="Optional model hint"),
    field_name: str | None = typer.Option(
        None,
        "--field",
        help="Optional field hint",
    ),
) -> None:
    """List likely tests for an addon, optionally ranked by model/field references."""
    operation = "list_addon_tests"
    result_type = "addon_test_inventory"
    _, ops = _resolve_agent_ops(ctx, operation, result_type)
    try:
        inventory = ops.list_addon_tests(module, model=model, field_name=field_name)
    except OduitModuleNotFoundError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
    except ConfigError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"module": module},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    payload = _agent_payload(
        operation,
        result_type,
        inventory.to_dict(),
        warnings=list(inventory.warnings),
        remediation=list(inventory.remediation),
    )
    _agent_emit_payload(payload)


@agent_app.command("list-addon-models")
def agent_list_addon_models(
    ctx: typer.Context,
    module: str = typer.Argument(help="Addon to inspect"),
) -> None:
    """List the models declared or extended by one addon."""
    operation = "list_addon_models"
    result_type = "addon_model_inventory"
    _, ops = _resolve_agent_ops(ctx, operation, result_type)
    try:
        inventory = ops.list_addon_models(module)
    except OduitModuleNotFoundError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
    except ConfigError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"module": module},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )

    payload = _agent_payload(
        operation,
        result_type,
        inventory.to_dict(),
        warnings=list(inventory.warnings),
        remediation=list(inventory.remediation),
    )
    _agent_emit_payload(payload)


@agent_app.command("find-model-extensions")
def agent_find_model_extensions(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to inspect across addons"),
    summary: bool = typer.Option(
        False,
        "--summary",
        help="Omit bulky scanned file listings from the payload",
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Find where a model is declared, extended, and installed."""
    operation = "find_model_extensions"
    result_type = "model_extension_inventory"
    _, ops = _resolve_agent_ops(ctx, operation, result_type)
    try:
        inventory = ops.find_model_extensions(model, database=database, timeout=timeout)
    except ConfigError as exc:
        _agent_fail(
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
            "Runtime field metadata was unavailable; verify database access "
            "if installed state matters."
        )
    payload = _agent_payload(
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
    _agent_emit_payload(payload)


@agent_app.command("get-model-views")
def agent_get_model_views(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model whose DB views should be fetched"),
    types: str | None = typer.Option(
        None,
        "--types",
        help="Comma-separated view types, e.g. form,tree,kanban,search",
    ),
    summary: bool = typer.Option(
        False,
        "--summary",
        help="Omit bulky arch_db values from the payload",
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Fetch database-backed primary and extension views for a model."""
    operation = "get_model_views"
    result_type = "model_view_inventory"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    requested_types = _parse_view_types(types, operation, result_type)
    ops = OdooOperations(global_config.env_config, verbose=False)
    inventory = ops.get_model_views(
        model,
        view_types=requested_types,
        database=database,
        timeout=timeout,
        include_arch=not summary,
    )
    inventory_data = inventory.to_dict()
    if summary:
        inventory_data = _strip_arch_from_model_views(inventory_data)
    remediation = list(inventory.remediation)
    payload = _agent_payload(
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
        remediation=remediation,
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
    _agent_emit_payload(payload)
    if inventory.error or not inventory.primary_views and not inventory.extension_views:
        raise typer.Exit(1)


@agent_app.command("doctor")
def agent_doctor(ctx: typer.Context) -> None:
    """Return doctor diagnostics through the standard agent envelope."""
    operation = "agent_doctor"
    result_type = "doctor_report"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(
            operation,
            result_type,
            "No environment configuration available",
            error_type="ConfigError",
        )

    report = _build_doctor_report(global_config)
    payload = _agent_payload(
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
    _agent_emit_payload(payload)
    if not report.get("success", False):
        raise typer.Exit(1)


@agent_app.command("list-addons")
def agent_list_addons(
    ctx: typer.Context,
    select_dir: str | None = typer.Option(None, "--select-dir"),
    exclude_core_addons: bool = typer.Option(False, "--exclude-core-addons"),
    exclude_enterprise_addons: bool = typer.Option(
        False,
        "--exclude-enterprise-addons",
    ),
    include: list[str] = INCLUDE_FILTER_OPTION,
    exclude: list[str] = EXCLUDE_FILTER_OPTION,
    sorting: str = SORT_OPTION,
) -> None:
    """Return structured addon inventory for the active environment."""
    operation = "agent_list_addons"
    result_type = "addon_inventory"
    global_config, ops = _resolve_agent_ops(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None
    addons_path = _require_agent_addons_path(env_config, operation, result_type)

    try:
        include_filter = _parse_filter_values(include, "include")
        exclude_filter = _parse_filter_values(exclude, "exclude")
    except ValueError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            details={"include": include, "exclude": exclude},
        )

    module_manager = ModuleManager(addons_path)
    addons = module_manager.find_module_dirs(filter_dir=select_dir)
    addons = [addon for addon in addons if not addon.startswith("test_")]
    odoo_series = global_config.odoo_series or module_manager.detect_odoo_series()

    if exclude_core_addons or exclude_enterprise_addons:
        try:
            addons = _apply_core_addon_filters(
                addons,
                exclude_core_addons,
                exclude_enterprise_addons,
                odoo_series,
            )
        except ValueError:
            _agent_fail(
                operation,
                result_type,
                (
                    "Could not apply addon type filters because Odoo series "
                    "detection failed"
                ),
                error_type="ConfigError",
                remediation=[
                    (
                        "Pass `--odoo-series` or ensure addon versions allow "
                        "Odoo series detection."
                    ),
                ],
            )

    try:
        addons = _apply_field_filters(
            addons,
            module_manager,
            include_filter,
            exclude_filter,
            odoo_series,
        )
        sorted_addons = module_manager.sort_modules(addons, sorting)
    except ValueError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ValidationError",
        )

    inventory = ops.list_addons_inventory(sorted_addons, odoo_series=odoo_series)
    duplicates = ops.list_duplicates()
    payload = _agent_payload(
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
    _agent_emit_payload(payload)


@agent_app.command("dependency-graph")
def agent_dependency_graph(
    ctx: typer.Context,
    modules: str = typer.Option(..., "--modules", help="Comma-separated addon names"),
) -> None:
    """Return a structured dependency and reverse-dependency graph."""
    operation = "agent_dependency_graph"
    result_type = "dependency_graph"
    _, ops = _resolve_agent_ops(ctx, operation, result_type)
    module_names = _parse_csv_items(modules)
    if not module_names:
        _agent_fail(
            operation,
            result_type,
            "At least one module must be provided via --modules",
            error_type="ValidationError",
        )

    try:
        graph = ops.dependency_graph(module_names)
    except ConfigError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            details={"modules": module_names},
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )
    payload = _agent_payload(
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
    _agent_emit_payload(payload)


@agent_app.command("inspect-addons")
def agent_inspect_addons(
    ctx: typer.Context,
    modules: str = typer.Option(..., "--modules", help="Comma-separated addon names"),
) -> None:
    """Inspect multiple addons through the stable agent envelope."""
    operation = "inspect_addons"
    result_type = "batch_addon_inspection"
    global_config, ops = _resolve_agent_ops(ctx, operation, result_type)
    module_names = _parse_csv_items(modules)
    if not module_names:
        _agent_fail(
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
        except OduitModuleNotFoundError:
            missing_modules.append(module_name)

    success = not missing_modules
    payload = _agent_payload(
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
    _agent_emit_payload(payload)
    if not success:
        raise typer.Exit(1)


@agent_app.command("resolve-config")
def agent_resolve_config(ctx: typer.Context) -> None:
    """Return the resolved configuration with sensitive values redacted."""
    operation = "resolve_config"
    result_type = "config_resolution"
    global_config, ops = _resolve_agent_ops(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None
    context = ops.get_environment_context(
        env_name=global_config.env_name,
        config_source=global_config.config_source,
        config_path=global_config.config_path,
        odoo_series=global_config.odoo_series,
    )
    context_data = context.to_dict()
    payload = _agent_payload(
        operation,
        result_type,
        {
            "environment": {
                "name": global_config.env_name,
                "source": global_config.config_source,
                "config_path": global_config.config_path,
            },
            "effective_config": _redact_config(env_config),
            "missing_required_keys": list(context.missing_critical_config),
            "resolved_binaries": context_data["resolved_binaries"],
            "addons_paths": context_data["addons_paths"],
            "odoo": context_data["odoo"],
            "database": context_data["database"],
        },
        warnings=list(context.warnings),
        remediation=list(context.remediation),
    )
    _agent_emit_payload(payload)


@agent_app.command("list-duplicates")
def agent_list_duplicates(ctx: typer.Context) -> None:
    """Return duplicate addon names through the standard agent envelope."""
    operation = "list_duplicates"
    result_type = "duplicate_modules"
    _, ops = _resolve_agent_ops(ctx, operation, result_type)
    try:
        duplicates = ops.list_duplicates()
    except ConfigError as exc:
        _agent_fail(
            operation,
            result_type,
            str(exc),
            error_type="ConfigError",
            remediation=[
                "Set `addons_path` in the selected environment before retrying.",
            ],
        )
    payload = _agent_payload(
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
    _agent_emit_payload(payload)


@agent_app.command("install-module")
def agent_install_module(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to install"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    without_demo: str | None = typer.Option(None, "--without-demo"),
    with_demo: bool = typer.Option(False, "--with-demo"),
    language: str | None = LANGUAGE_OPTION,
    max_cron_threads: int | None = typer.Option(None, "--max-cron-threads"),
    compact: bool = typer.Option(False, "--compact"),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Install a module with an explicit mutation gate."""
    operation = "install_module"
    result_type = "module_installation"
    global_config, ops = _resolve_agent_ops(ctx, operation, result_type)

    if dry_run:
        try:
            inspection = ops.inspect_addon(
                module, odoo_series=global_config.odoo_series
            )
        except OduitModuleNotFoundError as exc:
            _agent_fail(
                operation,
                result_type,
                str(exc),
                error_type="ModuleNotFoundError",
                details={"module": module},
            )
        payload = _agent_payload(
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
            safety_level=SAFE_READ_ONLY,
        )
        _agent_emit_payload(payload)
        return

    _agent_require_mutation(allow_mutation, operation, result_type, "module install")
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
    payload = output_result_to_json(
        result,
        additional_fields={
            "module": module,
            "without_demo": without_demo,
            "with_demo": with_demo,
            "language": language,
            "compact": compact,
            "read_only": False,
            "safety_level": CONTROLLED_MUTATION,
            "remediation": (
                ["Inspect unmet dependencies and retry after fixing them."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    _agent_emit_payload(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


@agent_app.command("update-module")
def agent_update_module(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to update"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    without_demo: str | None = typer.Option(None, "--without-demo"),
    language: str | None = LANGUAGE_OPTION,
    i18n_overwrite: bool = typer.Option(False, "--i18n-overwrite"),
    max_cron_threads: int | None = typer.Option(None, "--max-cron-threads"),
    compact: bool = typer.Option(False, "--compact"),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Update a module with an explicit mutation gate."""
    operation = "update_module"
    result_type = "module_update"
    global_config, ops = _resolve_agent_ops(ctx, operation, result_type)

    if dry_run:
        try:
            plan = ops.plan_update(module, odoo_series=global_config.odoo_series)
        except OduitModuleNotFoundError as exc:
            _agent_fail(
                operation,
                result_type,
                str(exc),
                error_type="ModuleNotFoundError",
                details={"module": module},
            )
        payload = _agent_payload(
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
            safety_level=SAFE_READ_ONLY,
        )
        _agent_emit_payload(payload)
        return

    _agent_require_mutation(allow_mutation, operation, result_type, "module update")
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
    payload = output_result_to_json(
        result,
        additional_fields={
            "module": module,
            "without_demo": without_demo,
            "language": language,
            "i18n_overwrite": i18n_overwrite,
            "compact": compact,
            "read_only": False,
            "safety_level": CONTROLLED_MUTATION,
            "remediation": (
                ["Inspect the update error and rerun targeted tests after fixing it."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    _agent_emit_payload(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


@agent_app.command("create-addon")
def agent_create_addon(
    ctx: typer.Context,
    addon_name: str = typer.Argument(help="Addon to create"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    path: str | None = typer.Option(None, "--path"),
    template: AddonTemplate = ADDON_TEMPLATE_OPTION,
) -> None:
    """Create a new addon with an explicit mutation gate."""
    operation = "create_agent_addon"
    result_type = "addon_creation"
    _, ops = _resolve_agent_ops(ctx, operation, result_type)

    if dry_run:
        payload = _agent_payload(
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
            safety_level=SAFE_READ_ONLY,
        )
        _agent_emit_payload(payload)
        return

    _agent_require_mutation(allow_mutation, operation, result_type, "addon creation")
    result = ops.create_addon(
        addon_name,
        destination=path,
        template=template.value,
        suppress_output=True,
    )
    result["operation"] = operation
    payload = output_result_to_json(
        result,
        additional_fields={
            "path": path,
            "template": template.value,
            "read_only": False,
            "safety_level": CONTROLLED_MUTATION,
            "remediation": (
                ["Verify the target path and addon name, then retry the scaffold."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    _agent_emit_payload(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


@agent_app.command("export-lang")
def agent_export_lang(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to export"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    language: str | None = LANGUAGE_OPTION,
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Export language files with an explicit mutation gate."""
    operation = "export_lang_module"
    result_type = "language_export"
    global_config, ops = _resolve_agent_ops(ctx, operation, result_type)
    env_config = global_config.env_config
    assert env_config is not None
    addons_path = _require_agent_addons_path(env_config, operation, result_type)

    language_value = language or env_config.get("language", "de_DE")
    if language_value is None:
        language_value = "de_DE"

    module_manager = ModuleManager(addons_path)
    module_path = module_manager.find_module_path(module)
    if not module_path:
        _agent_fail(
            operation,
            result_type,
            f"Module '{module}' was not found in addons_path",
            error_type="ModuleNotFoundError",
            details={"module": module},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
    i18n_dir = os.path.join(module_path, "i18n")
    language_slug = (
        language_value.split("_")[0] if "_" in language_value else language_value
    )
    filename = os.path.join(i18n_dir, f"{language_slug}.po")

    if dry_run:
        payload = _agent_payload(
            operation,
            result_type,
            {
                "module": module,
                "language": language_value,
                "filename": filename,
                "dry_run": True,
            },
            remediation=[
                "Retry with `--allow-mutation` to export the translation file.",
            ],
            read_only=True,
            safety_level=SAFE_READ_ONLY,
        )
        _agent_emit_payload(payload)
        return

    _agent_require_mutation(allow_mutation, operation, result_type, "language export")
    os.makedirs(i18n_dir, exist_ok=True)
    result = ops.export_module_language(
        module,
        filename,
        language_value,
        no_http=global_config.no_http,
        log_level=log_level.value if log_level else None,
        suppress_output=True,
    )
    result["operation"] = operation
    payload = output_result_to_json(
        result,
        additional_fields={
            "module": module,
            "language": language_value,
            "filename": filename,
            "read_only": False,
            "safety_level": CONTROLLED_MUTATION,
            "remediation": (
                ["Inspect the export error and verify the module path and language."]
                if not result.get("success", False)
                else []
            ),
        },
        result_type=result_type,
    )
    _agent_emit_payload(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


@agent_app.command("test-summary")
def agent_test_summary(
    ctx: typer.Context,
    module: str | None = typer.Option(None, "--module", help="Module under test"),
    allow_mutation: bool = typer.Option(False, "--allow-mutation"),
    install: str | None = typer.Option(
        None,
        "--install",
        help="Install a module before running tests",
    ),
    update: str | None = typer.Option(
        None,
        "--update",
        help="Update a module before running tests",
    ),
    coverage: str | None = typer.Option(
        None,
        "--coverage",
        help="Generate coverage for a module",
    ),
    test_file: str | None = typer.Option(
        None, "--test-file", help="Specific test file"
    ),
    test_tags: str | None = typer.Option(None, "--test-tags", help="Test tags filter"),
    stop_on_error: bool = typer.Option(False, "--stop-on-error"),
    compact: bool = typer.Option(False, "--compact"),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Run tests and emit a normalized summary payload."""
    operation = "test_summary"
    result_type = "test_summary"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    _agent_require_mutation(allow_mutation, operation, result_type, "test execution")

    ops = OdooOperations(global_config.env_config, verbose=False)
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

    selected_modules = list(
        dict.fromkeys(value for value in [module, install, update, coverage] if value)
    )
    failures = list(result.get("failures", []))
    error_output_excerpt = (
        _build_error_output_excerpt(result) if not result.get("success", False) else []
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

    payload = _agent_payload(
        operation,
        result_type,
        {
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
        },
        success=result.get("success", False),
        warnings=(
            ["Per-file coverage entries are not currently normalized by run_tests()."]
            if coverage
            else []
        ),
        remediation=suggested_next_steps,
        read_only=False,
        safety_level=CONTROLLED_MUTATION,
        error=result.get("error"),
        error_type=result.get("error_type"),
    )
    _agent_emit_payload(payload)
    if not result.get("success", False):
        raise typer.Exit(1)


@agent_app.command("query-model")
def agent_query_model(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to query"),
    domain_json: str | None = typer.Option(
        None, "--domain-json", help="JSON array domain"
    ),
    fields: str | None = typer.Option(
        None, "--fields", help="Comma-separated field names"
    ),
    limit: int = typer.Option(80, "--limit", help="Record limit"),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Run a structured read-only model query."""
    operation = "query_model"
    result_type = "query_result"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = OdooOperations(global_config.env_config, verbose=False)
    result = ops.query_model(
        model,
        domain=_parse_json_list_option(
            domain_json, "domain_json", operation, result_type
        ),
        fields=_parse_csv_items(fields),
        limit=limit,
        database=database,
        timeout=timeout,
    )
    payload = _agent_payload(
        operation,
        result_type,
        result.to_dict(),
        success=result.success,
        remediation=(
            [
                "Review the validation error and retry the query with "
                "literal-safe inputs."
            ]
            if not result.success
            else []
        ),
        read_only=True,
        safety_level=SAFE_READ_ONLY,
        error=result.error,
        error_type=result.error_type,
    )
    _agent_emit_payload(payload)
    if not result.success:
        raise typer.Exit(1)


@agent_app.command("read-record")
def agent_read_record(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to inspect"),
    record_id: int = typer.Argument(help="Record id to read"),
    fields: str | None = typer.Option(
        None, "--fields", help="Comma-separated field names"
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Read a single record by id via OdooQuery."""
    operation = "read_record"
    result_type = "record_result"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = OdooOperations(global_config.env_config, verbose=False)
    result = ops.read_record(
        model,
        record_id,
        fields=_parse_csv_items(fields),
        database=database,
        timeout=timeout,
    )
    payload = _agent_payload(
        operation,
        result_type,
        result.to_dict(),
        success=result.success,
        remediation=(
            ["Verify the record id and field names, then retry the read operation."]
            if not result.success
            else []
        ),
        read_only=True,
        safety_level=SAFE_READ_ONLY,
        error=result.error,
        error_type=result.error_type,
    )
    _agent_emit_payload(payload)
    if not result.success:
        raise typer.Exit(1)


@agent_app.command("search-count")
def agent_search_count(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to count records for"),
    domain_json: str | None = typer.Option(
        None, "--domain-json", help="JSON array domain"
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Count records matching a domain via OdooQuery."""
    operation = "search_count"
    result_type = "count_result"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = OdooOperations(global_config.env_config, verbose=False)
    result = ops.search_count(
        model,
        domain=_parse_json_list_option(
            domain_json, "domain_json", operation, result_type
        ),
        database=database,
        timeout=timeout,
    )
    payload = _agent_payload(
        operation,
        result_type,
        result.to_dict(),
        success=result.success,
        remediation=(
            ["Verify the model name and domain syntax, then retry the search count."]
            if not result.success
            else []
        ),
        read_only=True,
        safety_level=SAFE_READ_ONLY,
        error=result.error,
        error_type=result.error_type,
    )
    _agent_emit_payload(payload)
    if not result.success:
        raise typer.Exit(1)


@agent_app.command("get-model-fields")
def agent_get_model_fields(
    ctx: typer.Context,
    model: str = typer.Argument(help="Model to inspect"),
    attributes: str | None = typer.Option(
        None,
        "--attributes",
        help="Comma-separated field attributes",
    ),
    database: str | None = typer.Option(
        None, "--database", help="Override database name"
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
) -> None:
    """Inspect model field metadata via OdooQuery."""
    operation = "get_model_fields"
    result_type = "model_fields"
    global_config = _resolve_agent_global_config(ctx, operation, result_type)
    if global_config.env_config is None:
        _agent_fail(operation, result_type, "No environment configuration available")
    assert global_config.env_config is not None

    ops = OdooOperations(global_config.env_config, verbose=False)
    result = ops.get_model_fields(
        model,
        attributes=_parse_csv_items(attributes),
        database=database,
        timeout=timeout,
    )
    payload = _agent_payload(
        operation,
        result_type,
        result.to_dict(),
        success=result.success,
        remediation=(
            [
                "Verify the model name and requested attributes, then retry "
                "the inspection."
            ]
            if not result.success
            else []
        ),
        read_only=True,
        safety_level=SAFE_READ_ONLY,
        error=result.error,
        error_type=result.error_type,
    )
    _agent_emit_payload(payload)
    if not result.success:
        raise typer.Exit(1)


def cli_main() -> None:
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    cli_main()
