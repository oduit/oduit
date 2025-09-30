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
