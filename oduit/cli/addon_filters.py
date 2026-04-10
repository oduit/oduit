"""Addon manifest inspection and filtering helpers."""

from typing import Any

import click
from manifestoo_core.odoo_series import OdooSeries

from ..module_manager import ModuleManager


def get_addon_type(addon_name: str, odoo_series: OdooSeries | None) -> str:
    """Determine the addon type (CE, EE, or Custom)."""
    from manifestoo_core.core_addons import is_core_ce_addon, is_core_ee_addon

    if odoo_series:
        if is_core_ce_addon(addon_name, odoo_series):
            return "Odoo CE (Community)"
        if is_core_ee_addon(addon_name, odoo_series):
            return "Odoo EE (Enterprise)"
    return "Custom"


def build_addon_table(
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


def get_addon_field_value(
    addon_name: str,
    field: str,
    module_manager: ModuleManager,
    odoo_series: OdooSeries | None = None,
) -> str:
    """Get a normalized field value for an addon."""
    if field == "module_path":
        path = module_manager.find_module_path(addon_name)
        return path if path else ""

    if field == "addon_type":
        if odoo_series is None:
            odoo_series = module_manager.detect_odoo_series()
        return get_addon_type(addon_name, odoo_series)

    manifest = module_manager.get_manifest(addon_name)
    if not manifest:
        return ""

    if field == "name":
        return manifest.name
    if field == "version":
        return manifest.version
    if field == "summary":
        return manifest.summary
    if field == "author":
        return manifest.author
    if field == "website":
        return manifest.website
    if field == "license":
        return manifest.license
    if field == "depends":
        return ",".join(manifest.codependencies)
    if field == "category":
        raw_data = manifest.get_raw_data()
        return str(raw_data.get("category", ""))
    return ""


def filter_addons_by_field(
    addons: list[str],
    module_manager: ModuleManager,
    field: str,
    filter_value: str,
    is_include: bool,
    odoo_series: OdooSeries | None = None,
) -> list[str]:
    """Filter addons by a specific field value."""
    filtered_addons: list[str] = []
    filter_lower = filter_value.lower()

    for addon in addons:
        field_value = get_addon_field_value(addon, field, module_manager, odoo_series)
        field_value_lower = field_value.lower() if field_value else ""
        matches = filter_lower in field_value_lower

        if is_include:
            if matches:
                filtered_addons.append(addon)
        else:
            if not matches:
                filtered_addons.append(addon)

    return filtered_addons


def apply_core_addon_filters(
    addons: list[str],
    exclude_core_addons: bool,
    exclude_enterprise_addons: bool,
    odoo_series: OdooSeries | None,
) -> list[str]:
    """Apply CE/EE core addon exclusion filters."""
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


def apply_field_filters(
    addons: list[str],
    module_manager: ModuleManager,
    include_filter: list[tuple[str, str]],
    exclude_filter: list[tuple[str, str]],
    odoo_series: OdooSeries | None,
) -> list[str]:
    """Apply include/exclude field filters to addon list."""
    if include_filter:
        for field, value in include_filter:
            if field not in VALID_FILTER_FIELDS:
                raise ValueError(
                    f"Invalid field '{field}'. "
                    f"Valid fields: {', '.join(VALID_FILTER_FIELDS)}"
                )
            addons = filter_addons_by_field(
                addons,
                module_manager,
                field,
                value,
                is_include=True,
                odoo_series=odoo_series,
            )

    if exclude_filter:
        for field, value in exclude_filter:
            if field not in VALID_FILTER_FIELDS:
                raise ValueError(
                    f"Invalid field '{field}'. "
                    f"Valid fields: {', '.join(VALID_FILTER_FIELDS)}"
                )
            addons = filter_addons_by_field(
                addons,
                module_manager,
                field,
                value,
                is_include=False,
                odoo_series=odoo_series,
            )

    return addons


def parse_filter_option(
    ctx: click.Context, param: click.Parameter, value: tuple[str, ...]
) -> list[tuple[str, str]]:
    """Parse filter option values into list of (field, value) tuples."""
    del ctx
    del param
    if not value:
        return []

    result: list[tuple[str, str]] = []
    for i in range(0, len(value), 2):
        if i + 1 < len(value):
            result.append((value[i], value[i + 1]))
    return result
