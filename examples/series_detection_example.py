#!/usr/bin/env python3
"""Example demonstrating Odoo series detection and enhanced version display."""

from pathlib import Path

from oduit.module_manager import ModuleManager


def main():
    """Demonstrate series detection and version display features."""
    addons_path = str(Path(__file__).parent.parent / "tmp" / "myaddons")

    print("=== Odoo Series Detection and Enhanced Version Display ===\n")

    manager = ModuleManager(addons_path)

    print(f"Addons path: {addons_path}\n")

    series = manager.detect_odoo_series()
    if series:
        print(f"Detected Odoo series: {series.value}")
    else:
        print("Could not detect Odoo series from available modules")

    print("\n=== Module Version Display ===\n")

    modules = manager.find_module_dirs()
    for module_name in modules[:5]:
        version = manager.get_module_version_display(module_name)
        print(f"{module_name}: {version}")

    print("\n=== Formatted Dependency Tree ===\n")

    if modules:
        module_to_show = modules[0]
        print(f"Dependency tree for '{module_to_show}':\n")

        lines = manager.get_formatted_dependency_tree(module_to_show, max_depth=2)
        for line in lines:
            print(line)


if __name__ == "__main__":
    main()
