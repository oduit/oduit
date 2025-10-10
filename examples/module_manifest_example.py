#!/usr/bin/env python3
"""
Example script showing how to parse Odoo module manifests and build dependency
graphs using oduit.

This example demonstrates:
1. Parsing module manifest files
2. Getting module dependencies
3. Building complete dependency graphs
4. Creating hierarchical dependency trees
5. Getting proper module installation order
6. Finding missing dependencies
7. Finding reverse dependencies (modules that depend on a given module)
8. Error handling for missing or invalid manifests
"""

from oduit.config_loader import ConfigLoader
from oduit.module_manager import ModuleManager


def print_dependency_graph(
    graph: dict[str, list[str]], title: str = "Dependency Graph"
):
    """Helper function to pretty print dependency graphs."""
    print(f"\n{title}:")
    print("-" * len(title))
    for module, deps in graph.items():
        if deps:
            print(f"  {module} → {', '.join(deps)}")
        else:
            print(f"  {module} (no dependencies)")


def print_dependency_tree(tree: dict, indent: int = 0):
    """Helper function to pretty print dependency trees."""
    for module, subtree in tree.items():
        print("  " * indent + f"├─ {module}")
        if subtree:
            print_dependency_tree(subtree, indent + 1)


def main():  # noqa: C901
    # Load configuration using ConfigLoader
    config_loader = ConfigLoader()
    # Option 1: Load configuration from ~/.config/oduit/common-test.yaml
    # Replace "common-test" with your environment name
    try:
        env_config = config_loader.load_config("common-test")
        addons_path = env_config.get(
            "addons_path", "/opt/odoo/addons,/opt/custom/addons"
        )
        print("Loaded configuration from common-test.yaml")
        print(f"Using addons_path: {addons_path}")
    except Exception as e:
        print(f"Could not load config: {e}")
        print("Using default addons_path")
        addons_path = "/opt/odoo/addons,/opt/custom/addons"

    # Initialize the module manager
    module_manager = ModuleManager(addons_path)

    try:
        # Example 1: Parse a module manifest
        module_name = "base"  # Base module should exist in most Odoo installations

        print(f"Parsing manifest for module: {module_name}")
        manifest = module_manager.parse_manifest(module_name)

        if manifest:
            print(f"✓ Successfully parsed manifest for {module_name}")
            print(f"  Name: {manifest.get('name', 'Unknown')}")
            print(f"  Version: {manifest.get('version', 'Unknown')}")
            print(f"  Installable: {manifest.get('installable', False)}")
            print(f"  Auto-install: {manifest.get('auto_install', False)}")
        else:
            print(f"✗ Module {module_name} not found or has no manifest")

        # Example 2: Get module codependencies
        print(f"\nGetting codependencies for module: {module_name}")
        codependencies = module_manager.get_module_codependencies(module_name)

        if codependencies:
            print(f"✓ Module {module_name} has {len(codependencies)} codependencies:")
            for dep in codependencies:
                print(f"  - {dep}")
        else:
            print(f"✓ Module {module_name} has no codependencies")

        # Example 3: Build complete dependency graph
        print(f"\nBuilding dependency graph for module: {module_name}")
        try:
            graph = module_manager.build_dependency_graph(module_name)
            print(f"✓ Successfully built dependency graph with {len(graph)} modules")
            print_dependency_graph(
                graph, f"Complete dependency graph for {module_name}"
            )

        except ValueError as e:
            print(f"✗ Error building dependency graph: {e}")

        # Example 4: Get hierarchical dependency tree
        print(f"\nBuilding dependency tree for module: {module_name}")
        try:
            tree = module_manager.get_dependency_tree(module_name)
            print("✓ Successfully built dependency tree")
            print(f"\nHierarchical dependency tree for {module_name}:")
            print("-" * 40)
            print_dependency_tree(tree)

        except ValueError as e:
            print(f"✗ Error building dependency tree: {e}")

        # Example 5: Test with a common module that has dependencies
        common_modules = ["web", "sale", "account", "stock"]

        print("\nChecking codependencies for common modules...")
        for mod in common_modules:
            deps = module_manager.get_module_codependencies(mod)
            if deps:  # Only print if module exists and has dependencies
                print(f"  {mod}: {', '.join(deps)}")

        # Example 6: Demonstrate graph building for a module with complex dependencies
        complex_module = "sale"  # Sale module typically has multiple dependencies
        print(f"\nBuilding dependency graph for complex module: {complex_module}")
        try:
            complex_graph = module_manager.build_dependency_graph(complex_module)
            print(f"✓ Built graph with {len(complex_graph)} total modules")

            # Show only modules with dependencies
            modules_with_deps = {k: v for k, v in complex_graph.items() if v}
            if modules_with_deps:
                print_dependency_graph(
                    modules_with_deps,
                    f"Modules with dependencies in {complex_module} graph",
                )

        except ValueError as e:
            print(f"✗ Could not build dependency graph for {complex_module}: {e}")

        # Example 7: Get installation order for modules (NEW in Phase 2.5)
        print("\n" + "=" * 60)
        print("NEW FUNCTIONALITY - Phase 2.5 Features")
        print("=" * 60)

        test_modules = ["base", "web"]
        print(f"\nGetting installation order for modules: {', '.join(test_modules)}")
        try:
            install_order = module_manager.get_install_order(*test_modules)
            print(f"✓ Installation order: {' → '.join(install_order)}")
            print("  (Install modules in this order to satisfy dependencies)")
        except Exception as e:
            print(f"✗ Could not determine install order: {type(e).__name__}: {e}")
            import traceback

            traceback.print_exc()

        # Example 8: Find missing dependencies (NEW in Phase 2.5)
        print(f"\nChecking for missing dependencies in module: {complex_module}")
        try:
            missing_deps = module_manager.find_missing_dependencies(complex_module)
            if missing_deps:
                print(f"✗ Missing dependencies found: {', '.join(missing_deps)}")
                print("  These modules are required but not found in addons_path")
            else:
                print(f"✓ All dependencies for {complex_module} are available")
        except ValueError as e:
            print(f"✗ Error checking dependencies: {e}")

        # Example 9: Find reverse dependencies (NEW in Phase 2.5)
        base_module = "base"
        print(f"\nFinding modules that depend on: {base_module}")
        try:
            reverse_deps = module_manager.get_reverse_dependencies(base_module)
            if reverse_deps:
                print(
                    f"✓ Found {len(reverse_deps)} modules that depend on {base_module}:"
                )
                # Show first 10 to avoid overwhelming output
                for dep in reverse_deps[:10]:
                    print(f"  - {dep}")
                if len(reverse_deps) > 10:
                    print(f"  ... and {len(reverse_deps) - 10} more modules")
            else:
                print(f"✓ No modules depend on {base_module}")
        except Exception as e:
            print(f"✗ Error finding reverse dependencies: {e}")

        # Example 10: Demonstrate installation planning
        planning_modules = ["account", "sale"]
        print(
            f"\nDemonstrating installation planning for: {', '.join(planning_modules)}"
        )
        try:
            # Check for missing dependencies first
            all_missing = set()
            for mod in planning_modules:
                try:
                    missing = module_manager.find_missing_dependencies(mod)
                    all_missing.update(missing)
                except ValueError:
                    pass

            if all_missing:
                missing_list = ", ".join(sorted(all_missing))
                print(f"⚠  Warning: Missing dependencies: {missing_list}")

            # Get installation order
            install_order = module_manager.get_install_order(*planning_modules)
            print("✓ Recommended installation order:")
            for i, module in enumerate(install_order, 1):
                print(f"  {i}. {module}")

        except ValueError as e:
            print(f"✗ Installation planning failed: {e}")

    except ValueError as e:
        print(f"✗ Error parsing manifest: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
