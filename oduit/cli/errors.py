"""Common CLI error rendering helpers."""

import json
from typing import Any

import typer

from ..cli_types import GlobalConfig, OutputFormat
from ..module_manager import ModuleManager
from ..output import print_error
from ..utils import output_result_to_json


def print_command_error_result(
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


def dependency_error_details(
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


def confirmation_required_error(
    global_config: GlobalConfig,
    operation: str,
    message: str,
    remediation: list[str],
) -> None:
    """Fail fast when non-interactive mode forbids prompting."""
    print_command_error_result(
        global_config,
        operation,
        message,
        error_type="ConfirmationRequired",
        remediation=remediation,
    )
    raise typer.Exit(1) from None
