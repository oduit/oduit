# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import re
from datetime import datetime
from typing import Any

from .schemas import (
    COMMON_ENVELOPE_KEYS,
    ResultEnvelope,
    ResultMeta,
    infer_read_only,
    infer_safety_level,
)


def infer_error_code(error_type: str | None, error: str | None) -> str | None:
    """Infer a stable machine-facing error code from the payload error fields."""
    if not error_type and not error:
        return None

    normalized_error = (error or "").lower()
    if error_type == "ConfigError":
        if "addons_path" in normalized_error:
            return "config.addons_path_missing"
        if "environment" in normalized_error or "configuration" in normalized_error:
            return "config.environment_missing"
        return "config.invalid"
    if error_type == "ModuleNotFoundError":
        return "module.not_found"
    if error_type == "DuplicateModuleError":
        return "module.duplicate_name"
    if error_type == "ConfirmationRequired":
        return "mutation.confirmation_required"
    if error_type == "ValidationError":
        if "json" in normalized_error:
            return "input.invalid_json"
        return "input.invalid"
    if error_type in {"QueryError", "ConnectionError"}:
        return "runtime.query_failed"
    if error_type == "TestFailure":
        return "runtime.test_failure"
    if error_type == "ModuleUninstallError":
        if "dependent" in normalized_error:
            return "runtime.uninstall_dependency_blocked"
        if "not installed" in normalized_error:
            return "runtime.uninstall_not_installed"
        return "runtime.module_uninstall_failed"
    if error_type == "ModuleOperationError":
        return "runtime.module_operation_failed"
    if error_type == "CommandError":
        if "json" in normalized_error:
            return "input.invalid_json"
        if "dependency" in normalized_error:
            return "runtime.install_dependency_error"
        if "failed test" in normalized_error or "test failure" in normalized_error:
            return "runtime.test_failure"
    return f"error.{(error_type or 'unknown').lower()}"


def build_json_payload(
    payload_type: str,
    data: dict[str, Any] | None = None,
    success: bool | None = None,
    include_null_values: bool = False,
) -> dict[str, Any]:
    """Build a versioned JSON payload envelope."""
    payload_data = dict(data or {})
    operation = payload_data.get("operation")
    envelope_success = (
        success if success is not None else bool(payload_data.get("success"))
    )
    warnings = list(payload_data.pop("warnings", []))
    remediation = list(payload_data.pop("remediation", []))
    errors = list(payload_data.pop("errors", []))
    error = payload_data.get("error")
    error_type = payload_data.get("error_type")
    error_code = payload_data.get("error_code") or infer_error_code(error_type, error)
    read_only = payload_data.get("read_only")
    safety_level = payload_data.get("safety_level")
    meta = ResultMeta(
        timestamp=(
            payload_data.get("timestamp")
            or payload_data.get("generated_at")
            or datetime.now().isoformat()
        ),
        duration=payload_data.get("duration"),
    )

    command_data = {
        key: value
        for key, value in payload_data.items()
        if key not in COMMON_ENVELOPE_KEYS and key not in {"timestamp", "duration"}
    }

    if error and not errors:
        errors = [
            {
                "message": error,
                "error_type": error_type,
                "error_code": error_code,
            }
        ]

    return ResultEnvelope(
        payload_type=payload_type,
        success=envelope_success,
        operation=operation,
        read_only=(
            read_only
            if isinstance(read_only, bool)
            else infer_read_only(operation, payload_type)
        ),
        safety_level=safety_level or infer_safety_level(operation, payload_type),
        warnings=warnings,
        errors=errors,
        remediation=remediation,
        error=error,
        error_type=error_type,
        error_code=error_code,
        data=command_data,
        meta=meta,
    ).to_dict(include_null_values=include_null_values)


def output_result_to_json(
    output: dict[str, Any],
    additional_fields: dict[str, Any] | None = None,
    exclude_fields: list[str] | None = None,
    include_null_values: bool = False,
    result_type: str = "result",
) -> dict[str, Any]:
    """Generate JSON output for the operation result

    Args:
        additional_fields: Extra fields to include in the output
        exclude_fields: Fields to exclude from the output
        include_null_values: Whether to include fields with None values

    Returns:
        Dictionary suitable for JSON output
    """
    output = output.copy()
    payload_type = str(output.pop("type", result_type))

    # Add additional fields if provided
    if additional_fields:
        output.update(additional_fields)

    # Remove excluded fields
    if exclude_fields:
        for field in exclude_fields:
            output.pop(field, None)

    # Remove null values if requested (default behavior)
    output = build_json_payload(
        payload_type=payload_type,
        data=output,
        success=output.get("success", False),
        include_null_values=include_null_values,
    )

    # Remove empty lists/dicts unless they're meaningful for the operation
    meaningful_empty_fields = {
        "warnings",
        "errors",
        "remediation",
        "failures",
        "impact_set",
        "unmet_dependencies",
        "failed_modules",
        "addons",
        "models",
        "base_declarations",
        "source_extensions",
        "source_extension_modules",
        "source_view_extensions",
        "installed_fields",
        "installed_extension_fields",
        "installed_view_extensions",
        "installed_extension_modules",
        "primary_views",
        "extension_views",
        "requested_types",
        "view_counts",
        "install_order",
        "impacted_modules",
        "candidates",
        "tests",
        "missing_modules",
        "related_files",
        "scanned_python_files",
        "nodes",
        "edges",
        "cycles",
        "missing_required_keys",
        "values",
    }
    output = {
        k: v for k, v in output.items() if v != [] or k in meaningful_empty_fields
    }

    # Remove empty strings for stdout/stderr unless there was actually output
    if output.get("stdout") == "":
        output.pop("stdout", None)
    if output.get("stderr") == "":
        output.pop("stderr", None)

    return output


def validate_addon_name(addon_name: str) -> bool:
    """Validate addon name follows basic Odoo conventions"""

    # Check basic format: lowercase letters, numbers, underscores
    if not re.match(r"^[a-z][a-z0-9_]*$", addon_name):
        return False

    # Check length
    if len(addon_name) < 2 or len(addon_name) > 50:
        return False

    # Check doesn't start with odoo
    if addon_name.startswith("odoo"):
        return False

    return True


def format_dependency_tree(
    module_name: str,
    tree: dict[str, Any],
    module_manager: Any,
    prefix: str = "",
    is_last: bool = True,
    seen: set[str] | None = None,
    odoo_series: Any | None = None,
    is_root: bool = False,
) -> list[tuple[str, str]]:
    """Format a dependency tree for display.

    Args:
        module_name: Name of the module to format
        tree: Dependency tree structure from get_dependency_tree()
        module_manager: ModuleManager instance to get manifest info
        prefix: Current line prefix for indentation
        is_last: Whether this is the last item at this level
        seen: Set of already seen modules to detect cycles
        odoo_series: Optional OdooSeries for enhanced version display
        is_root: Whether this is the root module (no connector)

    Returns:
        List of tuples (module_part, version_part) for each line
    """
    if seen is None:
        seen = set()

    lines = []

    if odoo_series and hasattr(module_manager, "get_module_version_display"):
        version = module_manager.get_module_version_display(module_name, odoo_series)
    else:
        manifest = module_manager.get_manifest(module_name)
        version = manifest.version if manifest else "unknown"

    if is_root:
        connector = ""
    else:
        connector = "└── " if is_last else "├── "

    is_repeated = module_name in seen
    if is_repeated:
        lines.append((f"{prefix}{connector}{module_name}", " ⬆"))
        return lines

    lines.append((f"{prefix}{connector}{module_name} ", f"({version})"))
    seen.add(module_name)

    codependencies = tree.get(module_name, {})
    if codependencies:
        if is_root:
            extension = ""
        else:
            extension = "    " if is_last else "│   "
        dep_names = sorted([dep for dep in codependencies.keys() if dep != "base"])

        for i, dep_name in enumerate(dep_names):
            is_last_dep = i == len(dep_names) - 1
            subtree = {dep_name: codependencies[dep_name]}

            dep_lines = format_dependency_tree(
                dep_name,
                subtree,
                module_manager,
                prefix + extension,
                is_last_dep,
                seen,
                odoo_series,
                is_root=False,
            )
            lines.extend(dep_lines)

    return lines
