"""Generated command inventory helpers for the canonical Typer surfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import click
import typer.main

from .app import agent_app, app

CommandTier = str

STABLE_FOR_AGENTS: CommandTier = "stable_for_agents"
BETA_FOR_AGENTS: CommandTier = "beta_for_agents"
HUMAN_ORIENTED: CommandTier = "human_oriented"
COMPATIBILITY_ONLY: CommandTier = "compatibility_only"

COMMAND_TIER_DESCRIPTIONS: dict[CommandTier, str] = {
    STABLE_FOR_AGENTS: "Recommended machine-facing surface for agents.",
    BETA_FOR_AGENTS: "Useful for agents, but still evolving in shape or behavior.",
    HUMAN_ORIENTED: "Supported CLI surface, but documented primarily for humans.",
    COMPATIBILITY_ONLY: "Retained for migration or import compatibility only.",
}


@dataclass(frozen=True)
class CommandInventoryEntry:
    """One canonical command inventory row."""

    name: str
    summary: str
    tier: CommandTier
    safety_level: str | None = None


TOP_LEVEL_COMMAND_TIERS: dict[str, CommandTier] = {
    "doctor": HUMAN_ORIENTED,
    "exec": HUMAN_ORIENTED,
    "exec-file": HUMAN_ORIENTED,
    "run": HUMAN_ORIENTED,
    "shell": HUMAN_ORIENTED,
    "install": HUMAN_ORIENTED,
    "update": HUMAN_ORIENTED,
    "uninstall": HUMAN_ORIENTED,
    "test": HUMAN_ORIENTED,
    "create-db": HUMAN_ORIENTED,
    "list-db": HUMAN_ORIENTED,
    "list-env": HUMAN_ORIENTED,
    "print-config": HUMAN_ORIENTED,
    "edit-config": HUMAN_ORIENTED,
    "create-addon": HUMAN_ORIENTED,
    "inspect": HUMAN_ORIENTED,
    "db": HUMAN_ORIENTED,
    "performance": HUMAN_ORIENTED,
    "manifest": HUMAN_ORIENTED,
    "print-manifest": HUMAN_ORIENTED,
    "addon-info": HUMAN_ORIENTED,
    "list-addons": HUMAN_ORIENTED,
    "list-installed-addons": HUMAN_ORIENTED,
    "list-manifest-values": HUMAN_ORIENTED,
    "list-duplicates": HUMAN_ORIENTED,
    "list-depends": HUMAN_ORIENTED,
    "list-codepends": HUMAN_ORIENTED,
    "install-order": HUMAN_ORIENTED,
    "impact-of-update": HUMAN_ORIENTED,
    "list-missing": HUMAN_ORIENTED,
    "init": HUMAN_ORIENTED,
    "export-lang": HUMAN_ORIENTED,
    "version": HUMAN_ORIENTED,
}

AGENT_COMMAND_METADATA: dict[str, tuple[CommandTier, str]] = {
    "context": (STABLE_FOR_AGENTS, "safe_read_only"),
    "inspect-addon": (STABLE_FOR_AGENTS, "safe_read_only"),
    "addon-info": (STABLE_FOR_AGENTS, "safe_read_only"),
    "plan-update": (STABLE_FOR_AGENTS, "safe_read_only"),
    "prepare-addon-change": (BETA_FOR_AGENTS, "safe_read_only"),
    "locate-model": (BETA_FOR_AGENTS, "safe_read_only"),
    "locate-field": (BETA_FOR_AGENTS, "safe_read_only"),
    "list-addon-tests": (BETA_FOR_AGENTS, "safe_read_only"),
    "recommend-tests": (BETA_FOR_AGENTS, "safe_read_only"),
    "list-addon-models": (BETA_FOR_AGENTS, "safe_read_only"),
    "find-model-extensions": (BETA_FOR_AGENTS, "safe_read_only"),
    "get-model-views": (BETA_FOR_AGENTS, "safe_read_only"),
    "doctor": (STABLE_FOR_AGENTS, "safe_read_only"),
    "list-addons": (STABLE_FOR_AGENTS, "safe_read_only"),
    "list-installed-addons": (STABLE_FOR_AGENTS, "safe_read_only"),
    "dependency-graph": (STABLE_FOR_AGENTS, "safe_read_only"),
    "inspect-addons": (STABLE_FOR_AGENTS, "safe_read_only"),
    "resolve-config": (STABLE_FOR_AGENTS, "safe_read_only"),
    "resolve-addon-root": (STABLE_FOR_AGENTS, "safe_read_only"),
    "get-addon-files": (STABLE_FOR_AGENTS, "safe_read_only"),
    "check-addons-installed": (STABLE_FOR_AGENTS, "safe_read_only"),
    "check-model-exists": (BETA_FOR_AGENTS, "safe_read_only"),
    "check-field-exists": (BETA_FOR_AGENTS, "safe_read_only"),
    "list-duplicates": (STABLE_FOR_AGENTS, "safe_read_only"),
    "inspect-ref": (STABLE_FOR_AGENTS, "safe_read_only"),
    "inspect-cron": (STABLE_FOR_AGENTS, "controlled_runtime_mutation"),
    "inspect-modules": (STABLE_FOR_AGENTS, "safe_read_only"),
    "inspect-subtypes": (STABLE_FOR_AGENTS, "safe_read_only"),
    "inspect-model": (STABLE_FOR_AGENTS, "safe_read_only"),
    "inspect-field": (STABLE_FOR_AGENTS, "safe_read_only"),
    "db-table": (STABLE_FOR_AGENTS, "safe_read_only"),
    "db-column": (STABLE_FOR_AGENTS, "safe_read_only"),
    "db-constraints": (STABLE_FOR_AGENTS, "safe_read_only"),
    "db-tables": (STABLE_FOR_AGENTS, "safe_read_only"),
    "db-m2m": (STABLE_FOR_AGENTS, "safe_read_only"),
    "performance-slow-queries": (STABLE_FOR_AGENTS, "safe_read_only"),
    "performance-table-scans": (STABLE_FOR_AGENTS, "safe_read_only"),
    "performance-indexes": (STABLE_FOR_AGENTS, "safe_read_only"),
    "manifest-check": (STABLE_FOR_AGENTS, "safe_read_only"),
    "manifest-show": (STABLE_FOR_AGENTS, "safe_read_only"),
    "install-module": (STABLE_FOR_AGENTS, "controlled_runtime_mutation"),
    "update-module": (STABLE_FOR_AGENTS, "controlled_runtime_mutation"),
    "uninstall-module": (STABLE_FOR_AGENTS, "controlled_runtime_mutation"),
    "create-addon": (STABLE_FOR_AGENTS, "controlled_source_mutation"),
    "export-lang": (STABLE_FOR_AGENTS, "controlled_runtime_mutation"),
    "test-summary": (STABLE_FOR_AGENTS, "controlled_runtime_mutation"),
    "validate-addon-change": (
        BETA_FOR_AGENTS,
        "controlled_runtime_mutation",
    ),
    "preflight-addon-change": (BETA_FOR_AGENTS, "safe_read_only"),
    "query-model": (STABLE_FOR_AGENTS, "safe_read_only"),
    "read-record": (STABLE_FOR_AGENTS, "safe_read_only"),
    "search-count": (STABLE_FOR_AGENTS, "safe_read_only"),
    "get-model-fields": (STABLE_FOR_AGENTS, "safe_read_only"),
}


def _clean_summary(summary: str | None) -> str:
    if not summary:
        return ""
    return " ".join(summary.split())


def _command_summary(command: object) -> str:
    short_help = getattr(command, "get_short_help_str", None)
    if callable(short_help):
        return _clean_summary(short_help(limit=4096))
    return _clean_summary(getattr(command, "help", None))


def _render_markdown_cell(text: str) -> str:
    return text.replace("|", r"\|")


def _render_markdown_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]

    def _format_row(row: list[str]) -> str:
        cells = [cell.ljust(widths[index]) for index, cell in enumerate(row)]
        return "| " + " | ".join(cells) + " |"

    separator = "| " + " | ".join("-" * width for width in widths) + " |"
    return [_format_row(headers), separator, *(_format_row(row) for row in rows)]


def _require_exact_keys(
    actual_names: set[str], metadata_names: set[str], *, surface: str
) -> None:
    missing = sorted(actual_names - metadata_names)
    extra = sorted(metadata_names - actual_names)
    if missing or extra:
        problems: list[str] = []
        if missing:
            problems.append(f"missing metadata for {surface}: {', '.join(missing)}")
        if extra:
            problems.append(f"stale metadata for {surface}: {', '.join(extra)}")
        raise ValueError("; ".join(problems))


def get_top_level_command_inventory() -> list[CommandInventoryEntry]:
    """Return the canonical top-level CLI command inventory."""
    root = cast(click.Group, typer.main.get_command(app))
    command_names = [name for name in root.commands if name != "agent"]
    _require_exact_keys(
        set(command_names),
        set(TOP_LEVEL_COMMAND_TIERS),
        surface="top-level CLI commands",
    )
    entries: list[CommandInventoryEntry] = []
    for name in command_names:
        entries.append(
            CommandInventoryEntry(
                name=name,
                summary=_command_summary(root.commands[name]),
                tier=TOP_LEVEL_COMMAND_TIERS[name],
            )
        )
    return entries


def get_agent_command_inventory() -> list[CommandInventoryEntry]:
    """Return the canonical `oduit agent` command inventory."""
    root = cast(click.Group, typer.main.get_command(agent_app))
    command_names = list(root.commands)
    _require_exact_keys(
        set(command_names),
        set(AGENT_COMMAND_METADATA),
        surface="agent commands",
    )
    entries: list[CommandInventoryEntry] = []
    for name in command_names:
        tier, safety_level = AGENT_COMMAND_METADATA[name]
        entries.append(
            CommandInventoryEntry(
                name=name,
                summary=_command_summary(root.commands[name]),
                tier=tier,
                safety_level=safety_level,
            )
        )
    return entries


def render_cli_inventory_rst() -> str:
    """Render the canonical top-level CLI command inventory page."""
    lines = [
        "CLI command inventory",
        "=====================",
        "",
        "This page is generated from the canonical Typer registration surface in",
        "``oduit.cli.app``.",
        "",
        ".. list-table:: Canonical top-level CLI commands",
        "   :header-rows: 1",
        "",
        "   * - Command",
        "     - Stability tier",
        "     - Summary",
    ]
    for entry in get_top_level_command_inventory():
        lines.extend(
            [
                f"   * - ``{entry.name}``",
                f"     - ``{entry.tier}``",
                f"     - {entry.summary}",
            ]
        )
    return "\n".join(lines) + "\n"


def render_agent_inventory_rst() -> str:
    """Render the canonical agent command inventory page."""
    lines = [
        "Agent command inventory",
        "=======================",
        "",
        "This page is generated from the canonical agent command registration",
        "surface in ``oduit.cli.app``.",
        "",
        "Command tiers:",
        "",
    ]
    for tier, description in COMMAND_TIER_DESCRIPTIONS.items():
        lines.append(f"* ``{tier}``: {description}")
    lines.extend(
        [
            "",
            ".. list-table:: Canonical `oduit agent` commands",
            "   :header-rows: 1",
            "",
            "   * - Command",
            "     - Stability tier",
            "     - Safety level",
            "     - Summary",
        ]
    )
    for entry in get_agent_command_inventory():
        lines.extend(
            [
                f"   * - ``{entry.name}``",
                f"     - ``{entry.tier}``",
                f"     - ``{entry.safety_level}``",
                f"     - {entry.summary}",
            ]
        )
    return "\n".join(lines) + "\n"


def render_public_api_cli_section_markdown() -> str:
    """Render the generated CLI section for `docs/maintainer/public_api.md`."""
    rows = [
        [
            f"`{entry.name}`",
            f"`{entry.tier}`",
            _render_markdown_cell(entry.summary),
        ]
        for entry in get_top_level_command_inventory()
    ]
    lines = ["## CLI commands in `oduit.cli.app`", ""]
    lines.extend(_render_markdown_table(["Command", "Stability tier", "Summary"], rows))
    return "\n".join(lines)


def render_public_api_agent_section_markdown() -> str:
    """Render the generated agent section for `docs/maintainer/public_api.md`."""
    rows = [
        [
            f"`{entry.name}`",
            f"`{entry.tier}`",
            f"`{entry.safety_level}`",
            _render_markdown_cell(entry.summary),
        ]
        for entry in get_agent_command_inventory()
    ]
    lines = ["## `oduit agent` subcommands in `oduit.cli.app`", ""]
    lines.extend(
        _render_markdown_table(
            ["Command", "Stability tier", "Safety level", "Summary"],
            rows,
        )
    )
    return "\n".join(lines)
