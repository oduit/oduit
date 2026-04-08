# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""New Typer-based CLI implementation for oduit."""

import functools
import json
import os
import shutil
from typing import Any

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
from .module_manager import ModuleManager
from .odoo_operations import OdooOperations
from .output import configure_output, print_error, print_info, print_warning
from .utils import (
    JSON_SCHEMA_VERSION,
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
            additional_fields=details,
        )
        print(json.dumps(payload))
    else:
        print_error(message)


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

    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "type": "doctor_report",
        "success": summary["error"] == 0,
        "source": {
            "kind": global_config.config_source,
            "env_name": global_config.env_name,
            "config_path": global_config.config_path,
        },
        "checks": checks,
        "summary": summary,
        "next_steps": next_steps,
    }


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
            print("  list-codepends MODULE  List codependencies of a module")
            print("  impact-of-update MODULE  Addons affected by an update")
            print("  list-missing MODULES   Find missing dependencies")
            print("  export-lang MODULE Export language translations")
            print("  print-config       Print environment configuration")
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
                "install-order, list-codepends, impact-of-update, list-missing"
            )
            print("  export-lang, print-config")
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
            confirmation = "y"
            if not non_interactive:
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
    confirmation = "y"
    if not non_interactive and not db_exists:
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
        typer.Exit: If Odoo series cannot be detected
    """
    from manifestoo_core.core_addons import is_core_ce_addon, is_core_ee_addon

    if not odoo_series:
        print_error(
            "Could not detect Odoo series. "
            "Please specify --odoo-series to use exclusion filters"
        )
        raise typer.Exit(1) from None

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
        typer.Exit: If field is invalid
    """
    # Apply include filters (skip if empty list)
    if include_filter:
        for field, value in include_filter:
            if field not in VALID_FILTER_FIELDS:
                print_error(
                    f"Invalid field '{field}'. "
                    f"Valid fields: {', '.join(VALID_FILTER_FIELDS)}"
                )
                raise typer.Exit(1) from None
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
                print_error(
                    f"Invalid field '{field}'. "
                    f"Valid fields: {', '.join(VALID_FILTER_FIELDS)}"
                )
                raise typer.Exit(1) from None
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
        addons = _apply_core_addon_filters(
            addons, exclude_core_addons, exclude_enterprise_addons, odoo_series
        )

    # Apply include/exclude filters
    addons = _apply_field_filters(
        addons, module_manager, include_filter, exclude_filter, odoo_series
    )

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
        addons = _apply_core_addon_filters(
            addons, exclude_core_addons, exclude_enterprise_addons, odoo_series
        )

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
    module: str = typer.Argument(help="Module to check codependencies for"),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
) -> None:
    """List codependencies for a module.

    Codependencies are modules that depend on the specified module, meaning
    changes to the specified module may impact those modules.
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

    codependencies = module_manager.get_reverse_dependencies(module)

    # Include the selected module itself in the output
    all_codeps = sorted(codependencies + [module])

    if separator:
        if all_codeps:
            print(separator.join(all_codeps))
    elif all_codeps:
        for dep in all_codeps:
            print(f"{dep}")
    else:
        print_info(f"Module '{module}' has no codependencies")


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
        _print_command_error_result(
            global_config,
            "install_order",
            f"Failed to compute install order: {e}",
            error_type="DependencyError",
            details={"modules": module_list, "select_dir": select_dir},
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


def cli_main() -> None:
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    cli_main()
