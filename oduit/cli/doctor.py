"""Doctor diagnostics helpers for CLI and agent commands."""

import os
import shutil
from typing import Any

import typer

from ..addons_path_manager import AddonsPathManager
from ..cli_types import GlobalConfig
from ..module_manager import ModuleManager
from ..odoo_operations import OdooOperations
from ..utils import build_json_payload


def build_doctor_check(
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


def resolve_binary_candidate(candidate: str) -> dict[str, Any]:
    """Resolve a binary candidate either from PATH or filesystem."""
    is_path_like = os.path.isabs(candidate) or os.sep in candidate

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


def probe_binary(
    configured_value: str | None, auto_candidates: list[str]
) -> dict[str, Any]:
    """Probe a configured binary or try to auto-detect it."""
    if configured_value:
        result = resolve_binary_candidate(configured_value)
        result["configured"] = True
        result["auto_detected"] = False
        return result

    for candidate in auto_candidates:
        result = resolve_binary_candidate(candidate)
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


def format_doctor_value(value: Any) -> str:
    """Format a doctor value for human-readable output."""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return ", ".join(f"{key}={val}" for key, val in value.items())
    return str(value)


def build_doctor_report(
    global_config: GlobalConfig,
    *,
    addons_path_manager_cls: type[AddonsPathManager] = AddonsPathManager,
    module_manager_cls: type[ModuleManager] = ModuleManager,
    odoo_operations_cls: type[OdooOperations] = OdooOperations,
) -> dict[str, Any]:
    """Build a diagnostics report for the active configuration."""
    env_config = global_config.env_config or {}
    checks: list[dict[str, Any]] = []
    next_steps: list[str] = []

    checks.append(
        build_doctor_check(
            "config_source",
            "ok",
            f"Using {global_config.config_source or 'unknown'} configuration",
            details={
                "env_name": global_config.env_name,
                "config_path": global_config.config_path,
            },
        )
    )

    python_info = probe_binary(env_config.get("python_bin"), ["python3", "python"])
    if python_info["exists"] and python_info["executable"]:
        checks.append(
            build_doctor_check(
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
            build_doctor_check(
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

    odoo_info = probe_binary(env_config.get("odoo_bin"), ["odoo", "odoo-bin"])
    if odoo_info["exists"] and odoo_info["executable"]:
        checks.append(
            build_doctor_check(
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
            build_doctor_check(
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

    coverage_info = probe_binary(env_config.get("coverage_bin"), ["coverage"])
    if coverage_info["exists"] and coverage_info["executable"]:
        checks.append(
            build_doctor_check(
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
            build_doctor_check(
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
        build_doctor_check(
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
            build_doctor_check(
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
        path_manager = addons_path_manager_cls(addons_path)
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
                build_doctor_check(
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
                build_doctor_check(
                    "addons_path",
                    "ok",
                    f"Configured addons paths are valid ({len(valid_paths)} path(s))",
                    details={"configured_paths": valid_paths},
                )
            )
            module_manager = module_manager_cls(addons_path)
            modules = module_manager.find_modules(skip_invalid=True)
            checks.append(
                build_doctor_check(
                    "addons_scan",
                    "ok",
                    f"Discovered {len(modules)} addon(s)",
                    details={"module_count": len(modules)},
                )
            )

            base_paths = path_manager.get_base_addons_paths()
            base_status = "ok" if base_paths else "warning"
            checks.append(
                build_doctor_check(
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
                    build_doctor_check(
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

    ops = odoo_operations_cls(env_config, verbose=False)
    version_result = ops.get_odoo_version(suppress_output=True)
    if version_result.get("success") and version_result.get("version"):
        checks.append(
            build_doctor_check(
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
                    build_doctor_check(
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
            build_doctor_check(
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
            build_doctor_check(
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
            build_doctor_check(
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
                build_doctor_check(
                    "db_exists",
                    "ok",
                    f"Database '{db_name}' exists",
                    details={"database": db_name},
                )
            )
        elif db_result.get("success"):
            checks.append(
                build_doctor_check(
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
                build_doctor_check(
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


def print_doctor_report(report: dict[str, Any]) -> None:
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
                typer.echo(f"  {key}: {format_doctor_value(value)}")

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
