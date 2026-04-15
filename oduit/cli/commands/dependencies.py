"""Dependency analysis command implementations."""

import json
from typing import Any

import typer

from ...cli_types import OutputFormat
from ...module_manager import ModuleManager
from ...output import print_error, print_info
from ...utils import output_result_to_json


def _resolve_requested_modules(
    *,
    module_manager: ModuleManager,
    modules: str | None,
    select_dir: str | None,
) -> tuple[list[str], str]:
    """Resolve requested modules from explicit names or a selected directory."""
    if modules is None and select_dir is None:
        raise ValueError("Either provide module names or use --select-dir option")

    if modules is not None and select_dir is not None:
        raise ValueError("Cannot use both module names and --select-dir option")

    if select_dir:
        module_list = sorted(module_manager.find_module_dirs(filter_dir=select_dir))
        if not module_list:
            raise ValueError(f"No modules found in directory '{select_dir}'")
        return module_list, "select_dir"

    assert modules is not None
    module_list = [module.strip() for module in modules.split(",") if module.strip()]
    if not module_list:
        raise ValueError("At least one module name must be provided")

    missing_modules = [
        module
        for module in module_list
        if module_manager.find_module_path(module) is None
    ]
    if missing_modules:
        raise LookupError(
            f"Modules not found in addons_path: {', '.join(missing_modules)}"
        )

    return module_list, "modules"


def _install_order_cycle_remediation(module_list: list[str]) -> list[str]:
    """Return remediation hints for install-order cycle failures."""
    joined_modules = ",".join(module_list)
    return [
        "Resolve the dependency cycle and retry the install-order analysis.",
        (
            f"Run 'oduit explain-install-order {joined_modules}' for "
            "manifest-level details."
        ),
    ]


def _explain_cycle_remediation() -> list[str]:
    """Return remediation hints for the dedicated cycle explanation command."""
    return [
        "Break at least one manifest dependency in the cycle.",
        (
            "Move shared code into a base or bridge addon when two addons depend "
            "on each other."
        ),
        "Retry install-order after removing the cycle.",
    ]


def _print_cycle_explanation_text(
    module_list: list[str],
    cycle_analysis: dict[str, Any],
    remediation: list[str],
) -> None:
    """Print a human-oriented explanation of an install-order dependency cycle."""
    cycle_path = cycle_analysis.get("cycle_path", [])
    cycle_edges = cycle_analysis.get("cycle_edges", [])
    modules = cycle_analysis.get("modules", {})
    cycle_modules = cycle_analysis.get("cycle_modules", [])

    typer.echo("Dependency cycle detected")
    typer.echo("")
    typer.echo("Requested modules:")
    for module_name in module_list:
        typer.echo(f"  {module_name}")

    typer.echo("")
    typer.echo("Cycle:")
    typer.echo(f"  {' -> '.join(cycle_path)}")

    if cycle_edges:
        typer.echo("")
        typer.echo("Edges:")
        for edge in cycle_edges:
            if not isinstance(edge, dict):
                continue
            source = edge.get("from")
            target = edge.get("to")
            if isinstance(source, str) and isinstance(target, str):
                typer.echo(f"  {source} depends on {target}")

    if isinstance(modules, dict) and cycle_modules:
        typer.echo("")
        typer.echo("Modules involved:")
        for module_name in cycle_modules:
            if not isinstance(module_name, str):
                continue
            module_info = modules.get(module_name, {})
            if not isinstance(module_info, dict):
                continue
            module_path = module_info.get("module_path") or "-"
            typer.echo(f"  {module_name}  {module_path}")
            depends = module_info.get("depends")
            if isinstance(depends, list):
                depends_text = ", ".join(
                    dependency for dependency in depends if isinstance(dependency, str)
                )
                typer.echo(f"    depends: {depends_text or '(none)'}")

    typer.echo("")
    typer.echo("How to resolve:")
    for item in remediation:
        typer.echo(f"  - {item}")


def list_depends_command(
    ctx: typer.Context,
    *,
    modules: str | None,
    separator: str | None,
    tree: bool,
    depth: int | None,
    select_dir: str | None,
    sorting: str,
    resolve_command_env_config_fn: Any,
    module_manager_cls: type[ModuleManager] = ModuleManager,
    print_dependency_tree_fn: Any = None,
    print_dependency_list_fn: Any = None,
) -> None:
    """List direct dependencies for one or more modules."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    module_manager = module_manager_cls(env_config["addons_path"])

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
            module_list = [module.strip() for module in modules.split(",")]
            if len(module_list) == 1:
                source_desc = f"'{modules}'"
            else:
                source_desc = f"modules [{', '.join(module_list)}]"

        tree_depth = depth + 1 if depth is not None and depth >= 0 else None
        if tree:
            print_dependency_tree_fn(
                module_list,
                module_manager,
                tree_depth,
                global_config.odoo_series,
            )
        else:
            print_dependency_list_fn(
                module_list,
                module_manager,
                tree_depth,
                depth,
                separator,
                source_desc,
                sorting,
            )
    except ValueError as exc:
        print_error(f"Error checking dependencies: {exc}")
        raise typer.Exit(1) from None


def list_codepends_command(
    ctx: typer.Context,
    *,
    module: str,
    separator: str | None,
    resolve_command_env_config_fn: Any,
    module_manager_cls: type[ModuleManager] = ModuleManager,
) -> None:
    """List reverse dependencies for a module."""
    _, env_config = resolve_command_env_config_fn(ctx)
    module_manager = module_manager_cls(env_config["addons_path"])
    reverse_dependencies = module_manager.get_reverse_dependencies(module)
    all_codeps = sorted(reverse_dependencies + [module])

    if separator:
        if all_codeps:
            print(separator.join(all_codeps))
    elif all_codeps:
        for dependency in all_codeps:
            print(f"{dependency}")
    else:
        print_info(f"Module '{module}' has no reverse dependencies")


def install_order_command(
    ctx: typer.Context,
    *,
    modules: str | None,
    separator: str | None,
    select_dir: str | None,
    resolve_command_env_config_fn: Any,
    module_manager_cls: type[ModuleManager] = ModuleManager,
    print_command_error_result_fn: Any = None,
    dependency_error_details_fn: Any = None,
) -> None:
    """Return dependency-resolved install order."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    module_manager = module_manager_cls(env_config["addons_path"])

    try:
        module_list, source = _resolve_requested_modules(
            module_manager=module_manager,
            modules=modules,
            select_dir=select_dir,
        )
    except LookupError as exc:
        print_command_error_result_fn(
            global_config,
            "install_order",
            str(exc),
            details={
                "modules": [module.strip() for module in modules.split(",")]
                if modules
                else None,
                "select_dir": select_dir,
                "missing_modules": [
                    module.strip()
                    for module in modules.split(",")
                    if module.strip()
                    and module_manager.find_module_path(module.strip()) is None
                ]
                if modules
                else [],
            },
        )
        raise typer.Exit(1) from None
    except ValueError as exc:
        print_command_error_result_fn(
            global_config,
            "install_order",
            str(exc),
            details={"modules": modules, "select_dir": select_dir},
        )
        raise typer.Exit(1) from None

    try:
        ordered_modules = module_manager.get_install_order(*module_list)
    except ValueError as exc:
        cycle_analysis = module_manager.analyze_dependency_cycle(*module_list)
        cycle_details = dependency_error_details_fn(
            module_manager,
            str(exc),
            cycle_analysis=cycle_analysis,
        )
        print_command_error_result_fn(
            global_config,
            "install_order",
            f"Failed to compute install order: {exc}",
            error_type="DependencyCycleError" if cycle_details else "DependencyError",
            details={
                "modules": module_list,
                "requested_modules": module_list,
                "select_dir": select_dir,
                **cycle_details,
            },
            remediation=_install_order_cycle_remediation(module_list)
            if cycle_details
            else [],
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


def explain_install_order_command(
    ctx: typer.Context,
    *,
    modules: str | None,
    select_dir: str | None,
    resolve_command_env_config_fn: Any,
    module_manager_cls: type[ModuleManager] = ModuleManager,
    print_command_error_result_fn: Any = None,
    dependency_error_details_fn: Any = None,
) -> None:
    """Explain dependency cycles that block install-order computation."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    module_manager = module_manager_cls(env_config["addons_path"])

    try:
        module_list, source = _resolve_requested_modules(
            module_manager=module_manager,
            modules=modules,
            select_dir=select_dir,
        )
    except LookupError as exc:
        missing_modules = (
            [
                module.strip()
                for module in modules.split(",")
                if module.strip()
                and module_manager.find_module_path(module.strip()) is None
            ]
            if modules
            else []
        )
        print_command_error_result_fn(
            global_config,
            "explain_install_order",
            str(exc),
            details={
                "requested_modules": [module.strip() for module in modules.split(",")]
                if modules
                else [],
                "select_dir": select_dir,
                "missing_modules": missing_modules,
            },
            error_type="DependencyError",
        )
        raise typer.Exit(1) from None
    except ValueError as exc:
        print_command_error_result_fn(
            global_config,
            "explain_install_order",
            str(exc),
            details={"requested_modules": modules, "select_dir": select_dir},
            error_type="DependencyError",
        )
        raise typer.Exit(1) from None

    cycle_analysis = module_manager.analyze_dependency_cycle(*module_list)
    remediation = _explain_cycle_remediation()

    if cycle_analysis.get("cycle_path"):
        if global_config.format == OutputFormat.JSON:
            result_json = output_result_to_json(
                {
                    "success": False,
                    "operation": "explain_install_order",
                    "error": "Dependency cycle detected",
                    "error_type": "DependencyCycleError",
                    "requested_modules": module_list,
                    "source": source,
                    "select_dir": select_dir,
                },
                additional_fields={
                    "graph": cycle_analysis.get("graph", {}),
                    "cycle_path": cycle_analysis.get("cycle_path", []),
                    "cycle_length": cycle_analysis.get("cycle_length", 0),
                    "cycle_edges": cycle_analysis.get("cycle_edges", []),
                    "cycle_modules": cycle_analysis.get("cycle_modules", []),
                    "modules": cycle_analysis.get("modules", {}),
                    "remediation": remediation,
                },
            )
            print(json.dumps(result_json))
        else:
            _print_cycle_explanation_text(module_list, cycle_analysis, remediation)
        raise typer.Exit(1) from None

    try:
        ordered_modules = module_manager.get_install_order(*module_list)
    except ValueError as exc:
        cycle_details = dependency_error_details_fn(module_manager, str(exc))
        print_command_error_result_fn(
            global_config,
            "explain_install_order",
            str(exc),
            error_type="DependencyCycleError" if cycle_details else "DependencyError",
            details={
                "requested_modules": module_list,
                "select_dir": select_dir,
                **cycle_details,
            },
            remediation=remediation if cycle_details else [],
        )
        raise typer.Exit(1) from None

    if global_config.format == OutputFormat.JSON:
        result_json = output_result_to_json(
            {
                "success": True,
                "operation": "explain_install_order",
                "requested_modules": module_list,
                "source": source,
                "select_dir": select_dir,
                "cycle_path": [],
                "cycle_length": 0,
                "cycle_edges": [],
                "cycle_modules": [],
                "modules": {},
                "install_order": ordered_modules,
                "message": "No dependency cycle detected",
            }
        )
        print(json.dumps(result_json))
        return

    print_info("No dependency cycle detected")
    for module_name in ordered_modules:
        print(module_name)


def impact_of_update_command(
    ctx: typer.Context,
    *,
    module: str,
    separator: str | None,
    resolve_command_env_config_fn: Any,
    module_manager_cls: type[ModuleManager] = ModuleManager,
    print_command_error_result_fn: Any = None,
) -> None:
    """Show addons affected by updating a specific module."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    module_manager = module_manager_cls(env_config["addons_path"])
    if module_manager.find_module_path(module) is None:
        print_command_error_result_fn(
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


def list_missing_command(
    ctx: typer.Context,
    *,
    modules: str | None,
    separator: str | None,
    select_dir: str | None,
    resolve_command_env_config_fn: Any,
    module_manager_cls: type[ModuleManager] = ModuleManager,
) -> None:
    """Find missing dependencies for one or more modules."""
    _, env_config = resolve_command_env_config_fn(ctx)
    module_manager = module_manager_cls(env_config["addons_path"])

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
            module_list = [module.strip() for module in modules.split(",")]

        all_missing: set[str] = set()
        for module in module_list:
            missing = module_manager.find_missing_dependencies(module)
            all_missing.update(missing)

        if all_missing:
            sorted_missing = sorted(all_missing)
            if separator:
                print(separator.join(sorted_missing))
            else:
                for dependency in sorted_missing:
                    print(dependency)
        elif not separator:
            print_info("All dependencies are available")
    except ValueError as exc:
        print_error(f"Error checking missing dependencies: {exc}")
        raise typer.Exit(1) from None
