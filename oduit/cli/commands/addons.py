"""Addon, manifest, and inventory command implementations."""

import json
from typing import Any

import typer

from ...cli_types import AddonTemplate, OutputFormat
from ...module_manager import ModuleManager
from ...output import print_error, print_info
from ...utils import output_result_to_json


def _parse_filter_pairs(
    raw_values: list[str],
    option_name: str,
) -> list[tuple[str, str]]:
    """Parse repeated FIELD:VALUE filter options."""
    parsed_filters: list[tuple[str, str]] = []
    for filter_str in raw_values:
        if ":" not in filter_str:
            print_error(
                f"Invalid {option_name} filter '{filter_str}'. "
                "Use format 'FIELD:VALUE' "
                "(e.g., 'category:Sales' or 'category:Theme')"
            )
            raise typer.Exit(1) from None
        field, value = filter_str.split(":", 1)
        parsed_filters.append((field.strip(), value.strip()))
    return parsed_filters


def _print_addon_info_text(info: Any) -> None:
    """Render a compact human-readable addon summary."""
    installed_state = info.installed_state.state if info.installed_state else "unknown"
    if info.installed_state and not info.installed_state.success:
        installed_flag = "unknown"
    else:
        installed_flag = (
            "yes" if info.installed_state and info.installed_state.installed else "no"
        )

    print(f"Module: {info.module}")
    print(f"Path: {info.module_path or '-'}")
    print(f"Addon type: {info.addon_type}")
    print(f"Version: {info.version_display}")
    print(f"Installed: {installed_flag} ({installed_state})")
    print(f"Installable: {'yes' if info.installable else 'no'}")
    print(f"Auto install: {'yes' if info.auto_install else 'no'}")
    print(f"Depends: {', '.join(info.depends) if info.depends else '-'}")
    print(
        "Reverse dependencies: "
        f"{', '.join(info.reverse_dependencies) if info.reverse_dependencies else '-'}"
    )
    print(
        "Missing dependencies: "
        f"{', '.join(info.missing_dependencies) if info.missing_dependencies else '-'}"
    )
    print(f"License: {info.license or '-'}")
    print(f"Summary: {info.summary or '-'}")
    print(f"Description: {info.description or '-'}")
    print(f"Models: {', '.join(info.models) if info.models else '-'}")
    print(
        "Inherit models: "
        f"{', '.join(info.inherit_models) if info.inherit_models else '-'}"
    )
    print(f"Languages: {', '.join(info.languages) if info.languages else '-'}")
    print("Test cases:")
    if info.test_cases:
        for test_case in info.test_cases:
            print(f"  - {test_case.path} ({test_case.test_type})")
    else:
        print("  - none found")

    if info.warnings:
        print("Warnings:")
        for warning in info.warnings:
            print(f"  - {warning}")


def create_addon_command(
    ctx: typer.Context,
    *,
    addon_name: str,
    path: str | None,
    template: AddonTemplate,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    validate_addon_name_fn: Any,
) -> None:
    """Create a new addon."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    if not validate_addon_name_fn(addon_name):
        print_error(
            f"Invalid addon name '{addon_name}'. "
            "Must be lowercase letters, numbers, underscores only."
        )
        raise typer.Exit(1) from None

    odoo_operations = build_odoo_operations_fn(global_config)
    odoo_operations.create_addon(addon_name, destination=path, template=template.value)


def print_manifest_command(
    ctx: typer.Context,
    *,
    addon_name: str,
    resolve_command_env_config_fn: Any,
    module_manager_cls: type[ModuleManager] = ModuleManager,
    get_addon_type_fn: Any = None,
    build_addon_table_fn: Any = None,
) -> None:
    """Print manifest details for one addon."""
    from rich.console import Console

    global_config, env_config = resolve_command_env_config_fn(ctx)
    module_manager = module_manager_cls(env_config["addons_path"])
    manifest = module_manager.get_manifest(addon_name)
    if not manifest:
        print_error(f"Addon '{addon_name}' not found in addons path")
        raise typer.Exit(1) from None

    odoo_series = (
        global_config.odoo_series
        if global_config.odoo_series
        else module_manager.detect_odoo_series()
    )
    addon_type = get_addon_type_fn(addon_name, odoo_series)

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

    console = Console()
    table = build_addon_table_fn(addon_name, manifest, addon_type)
    console.print(table)


def addon_info_command(
    ctx: typer.Context,
    *,
    addon_name: str,
    database: str | None,
    timeout: float,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    print_command_error_result_fn: Any,
    module_not_found_error_cls: Any,
) -> None:
    """Print a combined addon summary for one addon."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    odoo_operations = build_odoo_operations_fn(global_config)
    try:
        info = odoo_operations.addon_info(
            addon_name,
            odoo_series=global_config.odoo_series,
            database=database,
            timeout=timeout,
        )
    except module_not_found_error_cls as exc:
        print_command_error_result_fn(
            global_config,
            "addon_info",
            str(exc),
            error_type="ModuleNotFoundError",
            details={"module": addon_name},
            remediation=[
                "Verify that the addon exists in the configured addons paths.",
            ],
        )
        raise typer.Exit(1) from None

    if global_config.format == OutputFormat.JSON:
        payload = output_result_to_json(
            {
                "success": True,
                "operation": "addon_info",
                **info.to_dict(),
            },
            result_type="addon_info",
        )
        print(json.dumps(payload))
        return

    _print_addon_info_text(info)


def list_addons_command(
    ctx: typer.Context,
    *,
    select_dir: str | None,
    separator: str | None,
    exclude_core_addons: bool,
    exclude_enterprise_addons: bool,
    include: list[str],
    exclude: list[str],
    sorting: str,
    resolve_command_env_config_fn: Any,
    module_manager_cls: type[ModuleManager] = ModuleManager,
    apply_core_addon_filters_fn: Any = None,
    apply_field_filters_fn: Any = None,
) -> None:
    """List available addons."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    include_filter = _parse_filter_pairs(include, "include")
    exclude_filter = _parse_filter_pairs(exclude, "exclude")

    module_manager = module_manager_cls(env_config["addons_path"])
    addons = module_manager.find_module_dirs(filter_dir=select_dir)
    addons = [addon for addon in addons if not addon.startswith("test_")]

    odoo_series = (
        global_config.odoo_series
        if global_config.odoo_series
        else module_manager.detect_odoo_series()
    )

    if exclude_core_addons or exclude_enterprise_addons:
        try:
            addons = apply_core_addon_filters_fn(
                addons,
                exclude_core_addons,
                exclude_enterprise_addons,
                odoo_series,
            )
        except ValueError as exc:
            print_error(str(exc))
            raise typer.Exit(1) from None

    try:
        addons = apply_field_filters_fn(
            addons,
            module_manager,
            include_filter,
            exclude_filter,
            odoo_series,
        )
    except ValueError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from None

    try:
        sorted_addons = module_manager.sort_modules(addons, sorting)
    except ValueError as exc:
        print_error(f"Sorting failed: {exc}")
        raise typer.Exit(1) from None

    if separator:
        print(separator.join(sorted_addons))
    else:
        for addon in sorted_addons:
            print(addon)


def list_manifest_values_command(
    ctx: typer.Context,
    *,
    field: str,
    separator: str | None,
    select_dir: str | None,
    exclude_core_addons: bool,
    exclude_enterprise_addons: bool,
    resolve_command_env_config_fn: Any,
    valid_filter_fields: list[str],
    module_manager_cls: type[ModuleManager] = ModuleManager,
    get_addon_field_value_fn: Any = None,
    apply_core_addon_filters_fn: Any = None,
) -> None:
    """List unique manifest values across addons."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    if field not in valid_filter_fields:
        print_error(
            f"Invalid field '{field}'. Valid fields: {', '.join(valid_filter_fields)}"
        )
        raise typer.Exit(1) from None

    module_manager = module_manager_cls(env_config["addons_path"])
    addons = module_manager.find_module_dirs(filter_dir=select_dir)
    odoo_series = (
        global_config.odoo_series
        if global_config.odoo_series
        else module_manager.detect_odoo_series()
    )

    if exclude_core_addons or exclude_enterprise_addons:
        try:
            addons = apply_core_addon_filters_fn(
                addons,
                exclude_core_addons,
                exclude_enterprise_addons,
                odoo_series,
            )
        except ValueError as exc:
            print_error(str(exc))
            raise typer.Exit(1) from None

    unique_values: set[str] = set()
    for addon in addons:
        value = get_addon_field_value_fn(addon, field, module_manager, odoo_series)
        if not value:
            continue
        if field == "depends":
            for dependency in value.split(","):
                dependency = dependency.strip()
                if dependency:
                    unique_values.add(dependency)
        else:
            unique_values.add(value)

    sorted_values = sorted(unique_values)
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

    if separator:
        print(separator.join(sorted_values))
    else:
        for value in sorted_values:
            print(value)


def list_duplicates_command(
    ctx: typer.Context,
    *,
    resolve_command_env_config_fn: Any,
    addons_path_manager_cls: Any,
    print_command_error_result_fn: Any,
) -> None:
    """List duplicate addon names across configured addon paths."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    addons_path = env_config.get("addons_path")
    if not addons_path:
        print_command_error_result_fn(
            global_config,
            "list_duplicates",
            "addons_path is not configured",
            error_type="ConfigError",
            remediation=[
                "Set `addons_path` before running duplicate-module analysis.",
            ],
        )
        raise typer.Exit(1) from None

    path_manager = addons_path_manager_cls(str(addons_path))
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
