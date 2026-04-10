"""Dependency rendering helpers for CLI commands."""

import typer
from manifestoo_core.odoo_series import OdooSeries

from ..module_manager import ModuleManager
from ..output import print_error
from ..utils import format_dependency_tree


def print_dependency_tree(
    module_list: list[str],
    module_manager: ModuleManager,
    tree_depth: int | None,
    odoo_series: OdooSeries | None = None,
) -> None:
    """Print dependency tree for a list of modules."""
    if odoo_series is None:
        odoo_series = module_manager.detect_odoo_series()

    for i, module_name in enumerate(module_list):
        dep_tree = module_manager.get_dependency_tree(module_name, max_depth=tree_depth)
        lines = format_dependency_tree(
            module_name,
            dep_tree,
            module_manager,
            "",
            True,
            set(),
            odoo_series,
            is_root=True,
        )
        for module_part, version_part in lines:
            typer.echo(module_part, nl=False)
            if version_part == " ⬆":
                typer.secho(version_part, fg="bright_black")
            elif version_part:
                typer.secho(version_part, fg="bright_black")
            else:
                typer.echo("")
        if i < len(module_list) - 1:
            typer.echo()


def print_dependency_list(
    module_list: list[str],
    module_manager: ModuleManager,
    tree_depth: int | None,
    depth: int | None,
    separator: str | None,
    source_desc: str,
    sorting: str = "alphabetical",
) -> None:
    """Print flat list of dependencies."""
    if depth is not None and depth >= 0:
        dependencies = module_manager.get_dependencies_at_depth(
            module_list, max_depth=tree_depth
        )
    else:
        dependencies = module_manager.get_direct_dependencies(*module_list)

    try:
        sorted_dependencies = module_manager.sort_modules(dependencies, sorting)
    except ValueError as e:
        print_error(f"Sorting failed: {e}")
        sorted_dependencies = dependencies

    if separator:
        if sorted_dependencies:
            print(separator.join(sorted_dependencies))
    elif sorted_dependencies:
        for dep in sorted_dependencies:
            print(dep)
    else:
        print(f"No external dependencies for {source_desc}")
