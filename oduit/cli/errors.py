"""Common CLI error rendering helpers."""

import json
from typing import Any

import typer

from ..cli_types import GlobalConfig, OutputFormat
from ..module_manager import ModuleManager
from ..output import print_error
from ..utils import output_result_to_json


def _cycle_modules_from_path(cycle_path: list[str]) -> list[str]:
    """Return the unique modules in a cycle, excluding the closing node."""
    if len(cycle_path) > 1 and cycle_path[0] == cycle_path[-1]:
        return cycle_path[:-1]
    return cycle_path


def _cycle_edges_from_path(cycle_path: list[str]) -> list[dict[str, str]]:
    """Return ordered dependency edges for a cycle path."""
    if len(cycle_path) < 2:
        return []
    return [
        {"from": cycle_path[index], "to": cycle_path[index + 1]}
        for index in range(len(cycle_path) - 1)
    ]


def _parse_suspected_modules(message: str) -> list[str]:
    """Extract suspected leftover modules from a topological-sort failure."""
    prefix = "Topological sort failed - circular dependency suspected among: "
    if not message.startswith(prefix):
        return []
    return [item.strip() for item in message[len(prefix) :].split(",") if item.strip()]


def _render_error_sections(
    details: dict[str, Any] | None,
    remediation: list[str] | None,
) -> list[list[str]]:
    """Build structured text sections for enriched dependency errors."""
    sections: list[list[str]] = []
    normalized_details = details or {}

    cycle_path = normalized_details.get("cycle_path")
    if isinstance(cycle_path, list) and cycle_path:
        sections.append(["Cycle path:", f"  {' -> '.join(cycle_path)}"])

        cycle_edges = normalized_details.get("cycle_edges")
        if isinstance(cycle_edges, list) and cycle_edges:
            edge_lines = ["Cycle edges:"]
            for edge in cycle_edges:
                if not isinstance(edge, dict):
                    continue
                source = edge.get("from")
                target = edge.get("to")
                if isinstance(source, str) and isinstance(target, str):
                    edge_lines.append(f"  {source} depends on {target}")
            if len(edge_lines) > 1:
                sections.append(edge_lines)

        cycle_modules_info = normalized_details.get("cycle_modules_info")
        cycle_modules = normalized_details.get("cycle_modules")
        if isinstance(cycle_modules_info, dict) and isinstance(cycle_modules, list):
            module_lines = ["Modules involved:"]
            for module_name in cycle_modules:
                if not isinstance(module_name, str):
                    continue
                module_info = cycle_modules_info.get(module_name, {})
                if not isinstance(module_info, dict):
                    continue
                module_path = module_info.get("module_path") or "-"
                module_lines.append(f"  {module_name}  {module_path}")
                depends = module_info.get("depends")
                if isinstance(depends, list):
                    depends_text = ", ".join(
                        dep for dep in depends if isinstance(dep, str)
                    )
                    module_lines.append(f"    depends: {depends_text or '(none)'}")
            if len(module_lines) > 1:
                sections.append(module_lines)

    suspected_modules = normalized_details.get("suspected_modules")
    if isinstance(suspected_modules, list) and suspected_modules:
        sections.append(
            [
                "Suspected modules:",
                "  "
                + ", ".join(
                    module_name
                    for module_name in suspected_modules
                    if isinstance(module_name, str)
                ),
            ]
        )

    if remediation:
        sections.append(["Remediation:", *[f"  - {item}" for item in remediation]])

    return [section for section in sections if section]


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
        sections = _render_error_sections(details, remediation)
        if sections:
            typer.echo("")
            typer.echo("\n\n".join("\n".join(section) for section in sections))


def dependency_error_details(
    module_manager: ModuleManager,
    message: str,
    cycle_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build structured details for dependency-related CLI failures."""
    if cycle_analysis and cycle_analysis.get("cycle_path"):
        return {
            "cycle_path": list(cycle_analysis["cycle_path"]),
            "cycle_length": int(cycle_analysis.get("cycle_length", 0)),
            "cycle_edges": list(cycle_analysis.get("cycle_edges", [])),
            "cycle_modules": list(cycle_analysis.get("cycle_modules", [])),
            "cycle_modules_info": dict(cycle_analysis.get("modules", {})),
        }

    cycle_path = module_manager.parse_cycle_error(message)
    if not cycle_path:
        suspected_modules = _parse_suspected_modules(message)
        return {"suspected_modules": suspected_modules} if suspected_modules else {}

    cycle_modules = _cycle_modules_from_path(cycle_path)
    return {
        "cycle_path": cycle_path,
        "cycle_length": len(cycle_modules),
        "cycle_edges": _cycle_edges_from_path(cycle_path),
        "cycle_modules": cycle_modules,
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
