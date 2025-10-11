# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import re
from typing import Any


def output_result_to_json(
    output: dict[str, Any],
    additional_fields: dict[str, Any] | None = None,
    exclude_fields: list[str] | None = None,
    include_null_values: bool = False,
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
    # Add additional fields if provided
    if additional_fields:
        output.update(additional_fields)

    # Remove excluded fields
    if exclude_fields:
        for field in exclude_fields:
            output.pop(field, None)

    # Remove null values if requested (default behavior)
    if not include_null_values:
        output = {k: v for k, v in output.items() if v is not None}

    # Remove empty lists/dicts unless they're meaningful for the operation
    meaningful_empty_fields = {
        "failures",
        "unmet_dependencies",
        "failed_modules",
        "addons",
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
