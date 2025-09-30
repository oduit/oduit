# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
from typing import Any

from .manifest import (
    InvalidManifestError,
    Manifest,
    ManifestError,
    ManifestNotFoundError,
)


class ModuleManager:
    """Manages Odoo module discovery and interaction."""

    def __init__(self, addons_path: str):
        """Initialize ModuleManager."""
        self.addons_path = addons_path

    def _find_odoo_base_addons_paths(self) -> list[str]:
        """Find Odoo base addons paths by looking for odoo-bin in parent directories."""
        base_paths = []

        for path in self.addons_path.split(","):
            path = path.strip()
            if not path:
                continue

            # Convert to absolute path for consistency
            path = os.path.abspath(path)

            # Look for odoo-bin in parent directories
            for subdir in [".", "..", "../..", "../../.."]:
                check_dir = os.path.normpath(os.path.join(path, subdir))
                potential_odoo_bin = os.path.join(check_dir, "odoo-bin")

                if os.path.exists(potential_odoo_bin):
                    # Found odoo-bin, check for base addons in odoo/addons/
                    base_addons_path = os.path.join(check_dir, "odoo", "addons")
                    if (
                        os.path.isdir(base_addons_path)
                        and base_addons_path not in base_paths
                    ):
                        base_paths.append(base_addons_path)
                    # Break out of subdirectory loop once we find odoo-bin
                    break

        return base_paths

    def find_module_dirs(self) -> list[str]:
        """Return all module directories with __manifest__.py in configured paths"""
        module_dirs: set[str] = set()

        # Combine configured addons_path and Odoo base addons paths
        all_paths = self.addons_path.split(",") + self._find_odoo_base_addons_paths()

        for path in all_paths:
            path = path.strip()
            if os.path.isdir(path):
                for entry in os.listdir(path):
                    full = os.path.join(path, entry)
                    if os.path.isdir(full) and os.path.exists(
                        os.path.join(full, "__manifest__.py")
                    ):
                        module_dirs.add(entry)

        return sorted(module_dirs)

    def find_module_path(self, module_name: str) -> str | None:
        """Find the absolute path to a module within addons_path and Odoo base addons"""
        # Combine configured addons_path and Odoo base addons paths
        all_paths = self.addons_path.split(",") + self._find_odoo_base_addons_paths()

        for path in all_paths:
            path = path.strip()
            if os.path.isdir(path):
                module_path = os.path.join(path, module_name)
                if os.path.isdir(module_path) and os.path.exists(
                    os.path.join(module_path, "__manifest__.py")
                ):
                    return module_path

        return None

    def get_manifest(self, module_name: str) -> Manifest | None:
        """Get the manifest for a module.

        Args:
            module_name: Name of the module to get manifest for

        Returns:
            Manifest instance or None if module not found
        """
        module_path = self.find_module_path(module_name)
        if not module_path:
            return None

        try:
            return Manifest(module_path)
        except ManifestError:
            # If manifest has errors, treat as if module doesn't exist
            return None

    def parse_manifest(self, module_name: str) -> dict[str, Any] | None:
        """Parse and return module's __manifest__.py content.

        Args:
            module_name: Name of the module to parse manifest for

        Returns:
            Dictionary containing manifest data or None if not found

        Raises:
            ValueError: If manifest exists but contains invalid Python syntax

        Note:
            This method is maintained for backward compatibility.
            Consider using get_manifest() for new code.
        """
        module_path = self.find_module_path(module_name)
        if not module_path:
            return None

        # Try to create manifest directly to preserve exception behavior
        try:
            manifest = Manifest(module_path)
            return manifest.get_raw_data()
        except (ManifestNotFoundError, FileNotFoundError):
            return None
        except (ManifestError, InvalidManifestError) as e:
            # Convert to ValueError for backward compatibility
            raise ValueError(str(e)) from e

    def get_module_dependencies(self, module_name: str) -> list[str]:
        """Get direct dependencies from module's manifest 'depends' field.

        Args:
            module_name: Name of the module to get dependencies for

        Returns:
            List of dependency module names, empty list if no dependencies
            or module not found
        """
        manifest = self.get_manifest(module_name)
        if not manifest:
            return []

        return manifest.dependencies

    def build_dependency_graph(self, module_name: str) -> dict[str, list[str]]:
        """Build complete dependency graph for a module and all its dependencies.

        Args:
            module_name: Name of the root module to build graph for

        Returns:
            Dictionary mapping each module to its direct dependencies.
            Format: {module_name: [list_of_dependencies]}

        Raises:
            ValueError: If circular dependency is detected
        """
        graph: dict[str, list[str]] = {}
        visited: set[str] = set()
        visiting: set[str] = set()  # For circular dependency detection

        def _build_graph_recursive(mod_name: str) -> None:
            if mod_name in visiting:
                # Circular dependency detected
                cycle_path = list(visiting) + [mod_name]
                raise ValueError(
                    f"Circular dependency detected: {' -> '.join(cycle_path)}"
                )

            if mod_name in visited:
                return

            visiting.add(mod_name)

            # Get dependencies for current module
            dependencies = self.get_module_dependencies(mod_name)
            graph[mod_name] = dependencies

            # Recursively process dependencies
            for dep in dependencies:
                _build_graph_recursive(dep)

            visiting.remove(mod_name)
            visited.add(mod_name)

        _build_graph_recursive(module_name)
        return graph

    def get_dependency_tree(self, module_name: str) -> dict[str, Any]:
        """Get hierarchical dependency tree for a module.

        Args:
            module_name: Name of the module to get dependency tree for

        Returns:
            Nested dictionary representing the dependency tree.
            Format: {module_name: {dependency1: {subdeps...}, dependency2: {}}}

        Raises:
            ValueError: If circular dependency is detected
        """
        visited: set[str] = set()
        visiting: set[str] = set()  # For circular dependency detection

        def _build_tree_recursive(mod_name: str) -> dict[str, Any]:
            if mod_name in visiting:
                # Circular dependency detected
                cycle_path = list(visiting) + [mod_name]
                raise ValueError(
                    f"Circular dependency detected: {' -> '.join(cycle_path)}"
                )

            if mod_name in visited:
                # Already processed module, return empty to avoid infinite recursion
                return {}

            visiting.add(mod_name)

            # Get dependencies for current module
            dependencies = self.get_module_dependencies(mod_name)
            tree = {}

            # Build subtree for each dependency
            for dep in dependencies:
                tree[dep] = _build_tree_recursive(dep)

            visiting.remove(mod_name)
            visited.add(mod_name)

            return tree

        return {module_name: _build_tree_recursive(module_name)}

    def get_install_order(self, *module_names: str) -> list[str]:
        """Get the proper installation order for one or more modules and
        their dependencies.

        Uses topological sorting to determine the correct order for installing modules
        such that all dependencies are installed before the modules that depend on them.

        Args:
            *module_names: One or more module names to get install order for

        Returns:
            List of module names in the order they should be installed.
            Dependencies come first, then modules that depend on them.

        Raises:
            ValueError: If circular dependency is detected
        """
        if not module_names:
            raise ValueError("At least one module name must be provided")

        # Build a combined dependency graph for all requested modules
        all_graphs = {}
        for module_name in module_names:
            try:
                graph = self.build_dependency_graph(module_name)
                all_graphs.update(graph)
            except ValueError as e:
                if "Circular dependency" in str(e):
                    raise
                # For missing modules, continue but they won't be in final result
                continue

        if not all_graphs:
            # If no modules were found, return empty list
            return []

        # Implement Kahn's algorithm for topological sorting
        # The in-degree represents how many dependencies a module has
        in_degree = {
            module: len(dependencies) for module, dependencies in all_graphs.items()
        }

        # Initialize queue with nodes that have no dependencies (in-degree = 0)
        queue = [module for module, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            # Remove a node with no dependencies
            current = queue.pop(0)
            result.append(current)

            # For each module that depends on the current one, reduce its in-degree
            for module, dependencies in all_graphs.items():
                if current in dependencies:
                    in_degree[module] -= 1
                    # If this module now has no unmet dependencies, add it to queue
                    if in_degree[module] == 0:
                        queue.append(module)

        # If we haven't processed all nodes, there's a cycle
        if len(result) != len(all_graphs):
            raise ValueError("Topological sort failed - circular dependency detected")

        return result

    def find_missing_dependencies(self, module_name: str) -> list[str]:
        """Find dependencies that are not available in the addons_path.

        Args:
            module_name: Name of the module to check dependencies for

        Returns:
            List of dependency names that could not be found in addons_path.
            Empty list if all dependencies are available.

        Raises:
            ValueError: If circular dependency is detected during graph traversal
        """
        try:
            # Build dependency graph - this will traverse all dependencies
            graph = self.build_dependency_graph(module_name)

            # Check which modules in the graph don't exist in addons_path
            missing = []
            for module in graph:
                if self.find_module_path(module) is None:
                    missing.append(module)

            return sorted(missing)

        except ValueError as e:
            # Re-raise circular dependency errors
            if "Circular dependency" in str(e):
                raise
            # For other errors (module not found), return root as missing
            return [module_name]

    def get_reverse_dependencies(self, target_module: str) -> list[str]:
        """Get all modules that directly or indirectly depend on the target module.

        This method searches through all available modules to find which ones
        have the target module in their dependency chain.

        Args:
            target_module: Name of the module to find reverse dependencies for

        Returns:
            List of module names that depend on the target module.
            Empty list if no modules depend on the target.
        """
        # Get all available modules
        all_modules = self.find_module_dirs()
        reverse_deps = []

        for module in all_modules:
            try:
                # Build dependency graph for this module
                graph = self.build_dependency_graph(module)

                # Check if target_module appears in the graph
                # (excluding the module itself if it's the same as target)
                if target_module in graph and module != target_module:
                    reverse_deps.append(module)

            except ValueError:
                # Skip modules with circular dependencies or other errors
                continue

        return sorted(reverse_deps)
