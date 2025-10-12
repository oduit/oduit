# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

from graphlib import TopologicalSorter
from typing import Any

from manifestoo_core.core_addons import is_core_ce_addon, is_core_ee_addon
from manifestoo_core.odoo_series import OdooSeries, detect_from_addon_version

from .addons_path_manager import AddonsPathManager
from .cli_types import SortingChoice
from .manifest import (
    InvalidManifestError,
    Manifest,
    ManifestError,
    ManifestNotFoundError,
)
from .manifest_collection import ManifestCollection


class ModuleManager:
    """Manages Odoo module operations and dependency resolution."""

    def __init__(self, addons_path: str):
        """Initialize ModuleManager.

        Args:
            addons_path: Comma-separated string of addon directory paths
        """
        self.addons_path = addons_path
        self._path_manager = AddonsPathManager(addons_path)

    def find_module_dirs(self, filter_dir: str | None = None) -> list[str]:
        """Return all module directories with __manifest__.py in configured paths

        Args:
            filter_dir: Optional directory name to filter results.
                       Only modules in directories with exact basename match
                       will be returned.

        Returns:
            Sorted list of module directory names
        """
        return self._path_manager.get_module_names(filter_dir)

    def find_modules(
        self, filter_dir: str | None = None, skip_invalid: bool = False
    ) -> ManifestCollection:
        """Return all modules with manifests in configured paths as a collection

        Args:
            filter_dir: Optional directory name to filter results.
                       Only modules in directories with exact basename match
                       will be returned.
            skip_invalid: If True, skip modules with invalid manifests instead of
                raising an exception

        Returns:
            ManifestCollection containing all found modules

        Raises:
            ManifestError: If a manifest is invalid and skip_invalid is False
        """
        if filter_dir:
            return self._path_manager.get_collection_by_filter(filter_dir, skip_invalid)
        return self._path_manager.get_all_collections(skip_invalid)

    def find_module_path(self, module_name: str) -> str | None:
        """Find the absolute path to a module within addons_path and Odoo base addons

        Args:
            module_name: Name of the module to find

        Returns:
            Absolute path to module directory or None if not found
        """
        return self._path_manager.find_module_path(module_name)

    def get_manifest(self, module_name: str) -> Manifest | None:
        """Get the manifest for a module.

        Args:
            module_name: Name of the module to get manifest for

        Returns:
            Manifest instance or None if module not found
        """
        return self._path_manager.get_manifest(module_name)

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

    def get_module_codependencies(self, module_name: str) -> list[str]:
        """Get codependencies from module's manifest 'depends' field.

        Codependencies are modules that this module depends on, meaning changes
        to those modules may impact this module.

        Args:
            module_name: Name of the module to get codependencies for

        Returns:
            List of codependency module names, empty list if no codependencies
            or module not found
        """
        manifest = self.get_manifest(module_name)
        if not manifest:
            return []

        return manifest.codependencies

    def get_direct_dependencies(self, *module_names: str) -> list[str]:
        """Get direct dependencies needed to install a set of modules.

        Direct dependencies are the minimal set of external modules (not in the
        provided set) needed to install the specified modules.

        Args:
            *module_names: One or more module names to get direct dependencies for

        Returns:
            Sorted list of module names that are direct dependencies (external to
            the provided set) needed for installation

        Example:
            For modules a, b, c where:
            - a depends on ['b', 'c']
            - b depends on ['crm']
            - c depends on ['mail']
            get_direct_dependencies('a', 'b', 'c') returns ['crm', 'mail']
        """
        if not module_names:
            return []

        module_set = set(module_names)
        direct_deps = set()

        for module_name in module_names:
            # Get all dependencies through the dependency graph
            try:
                graph = self.build_dependency_graph(module_name)
                # Collect all modules in the graph that are not in our module set
                for module in graph:
                    if module not in module_set and module != "base":
                        direct_deps.add(module)
            except ValueError:
                # Skip modules with errors
                continue

        return sorted(direct_deps)

    def build_dependency_graph(self, module_name: str) -> dict[str, list[str]]:
        """Build complete dependency graph for a module and all its codependencies.

        Args:
            module_name: Name of the root module to build graph for

        Returns:
            Dictionary mapping each module to its direct codependencies.
            Format: {module_name: [list_of_codependencies]}

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

            # Get codependencies for current module
            codependencies = self.get_module_codependencies(mod_name)
            graph[mod_name] = codependencies

            # Recursively process codependencies
            for dep in codependencies:
                _build_graph_recursive(dep)

            visiting.remove(mod_name)
            visited.add(mod_name)

        _build_graph_recursive(module_name)
        return graph

    def get_dependency_tree(
        self, module_name: str, max_depth: int | None = None
    ) -> dict[str, Any]:
        """Get hierarchical dependency tree for a module.

        Args:
            module_name: Name of the module to get dependency tree for
            max_depth: Maximum depth to traverse (None for unlimited)

        Returns:
            Nested dictionary representing the dependency tree.
            Format: {module_name: {codependency1: {subdeps...}, codependency2: {}}}

        Raises:
            ValueError: If circular dependency is detected
        """
        visited: set[str] = set()
        visiting: set[str] = set()  # For circular dependency detection

        def _build_tree_recursive(
            mod_name: str, current_depth: int = 0
        ) -> dict[str, Any]:
            if mod_name in visiting:
                # Circular dependency detected
                cycle_path = list(visiting) + [mod_name]
                raise ValueError(
                    f"Circular dependency detected: {' -> '.join(cycle_path)}"
                )

            if mod_name in visited:
                # Already processed module, return empty to avoid infinite recursion
                return {}

            # Check if we've reached max depth
            if max_depth is not None and current_depth >= max_depth:
                return {}

            visiting.add(mod_name)

            # Get codependencies for current module
            codependencies = self.get_module_codependencies(mod_name)
            tree = {}

            # Build subtree for each codependency
            for dep in codependencies:
                tree[dep] = _build_tree_recursive(dep, current_depth + 1)

            visiting.remove(mod_name)
            visited.add(mod_name)

            return tree

        return {module_name: _build_tree_recursive(module_name)}

    def get_dependencies_at_depth(
        self, module_names: list[str], max_depth: int | None = None
    ) -> list[str]:
        """Get all dependencies up to a specified depth for a list of modules.

        Args:
            module_names: List of module names to get dependencies for
            max_depth: Maximum depth to traverse (None for unlimited)

        Returns:
            Sorted list of unique dependency names (excluding input modules)
        """
        module_set = set(module_names)
        all_deps = set()

        for module_name in module_names:
            dep_tree = self.get_dependency_tree(module_name, max_depth=max_depth)

            # Flatten the tree to get all dependencies
            def _flatten_tree(tree: dict[str, Any]) -> set[str]:
                deps = set()
                for key, subtree in tree.items():
                    if key not in module_set and key != "base":
                        deps.add(key)
                    if isinstance(subtree, dict) and subtree:
                        deps.update(_flatten_tree(subtree))
                return deps

            all_deps.update(_flatten_tree(dep_tree))

        return sorted(all_deps - module_set)

    def get_install_order(self, *module_names: str) -> list[str]:
        """Get the proper installation order for one or more modules and
        their codependencies.

        Uses topological sorting to determine the correct order for installing
        modules such that all codependencies are installed before the modules
        that depend on them.

        Args:
            *module_names: One or more module names to get install order for

        Returns:
            List of module names in the order they should be installed.
            Codependencies come first, then modules that depend on them.

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
        # The in-degree represents how many codependencies a module has
        in_degree = {
            module: len(codependencies) for module, codependencies in all_graphs.items()
        }

        # Initialize queue with nodes that have no codependencies (in-degree = 0)
        queue = [module for module, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            # Remove a node with no codependencies
            current = queue.pop(0)
            result.append(current)

            # For each module that depends on the current one, reduce its in-degree
            for module, codependencies in all_graphs.items():
                if current in codependencies:
                    in_degree[module] -= 1
                    # If this module now has no unmet codependencies, add it to queue
                    if in_degree[module] == 0:
                        queue.append(module)

        # If we haven't processed all nodes, there's a cycle
        if len(result) != len(all_graphs):
            raise ValueError("Topological sort failed - circular dependency detected")

        return result

    def find_missing_dependencies(self, module_name: str) -> list[str]:
        """Find codependencies that are not available in the addons_path.

        Args:
            module_name: Name of the module to check codependencies for

        Returns:
            List of codependency names that could not be found in addons_path.
            Empty list if all codependencies are available.

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
        have the target module in their codependency chain.

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

    def detect_odoo_series(self) -> OdooSeries | None:
        """Detect the Odoo series from available modules.

        Scans all available modules and attempts to detect the Odoo series
        from their version strings.

        Returns:
            OdooSeries if detected, None if unable to detect
        """
        module_dirs = self.find_module_dirs()

        for module_name in module_dirs:
            manifest = self.get_manifest(module_name)
            if manifest and manifest.version:
                series = detect_from_addon_version(manifest.version)
                if series:
                    return series

        return None

    def get_module_version_display(
        self, module_name: str, odoo_series: OdooSeries | None = None
    ) -> str:
        """Get formatted version string for display in dependency trees.

        Args:
            module_name: Name of the module
            odoo_series: Detected Odoo series (if None, will try to detect)

        Returns:
            Formatted version string:
            - "16.0+ce" for core CE addons
            - "16.0+ee" for core EE addons
            - "1.0.2" for custom addons (actual version)
            - "✘ not installed" for missing addons
        """
        manifest = self.get_manifest(module_name)

        if not manifest:
            return "✘ not installed"

        if odoo_series is None:
            odoo_series = self.detect_odoo_series()

        if odoo_series:
            if is_core_ce_addon(module_name, odoo_series):
                return f"{odoo_series.value}+ce"
            elif is_core_ee_addon(module_name, odoo_series):
                return f"{odoo_series.value}+ee"

        return manifest.version

    def get_formatted_dependency_tree(
        self, module_name: str, max_depth: int | None = None
    ) -> list[str]:
        """Get formatted dependency tree for display.

        Args:
            module_name: Name of the module to get dependency tree for
            max_depth: Maximum depth to traverse (None for unlimited)

        Returns:
            List of formatted lines representing the dependency tree
        """
        from .utils import format_dependency_tree

        odoo_series = self.detect_odoo_series()
        dep_tree = self.get_dependency_tree(module_name, max_depth=max_depth)

        lines_tuples = format_dependency_tree(
            module_name, dep_tree, self, odoo_series=odoo_series
        )
        return [
            f"{module_part}{version_part}" for module_part, version_part in lines_tuples
        ]

    def sort_modules(
        self,
        module_names: list[str],
        sorting: SortingChoice | str = SortingChoice.ALPHABETICAL,
    ) -> list[str]:
        """Sort module names according to the specified sorting method.

        Args:
            module_names: List of module names to sort
            sorting: Sorting method - either 'alphabetical' or 'topological'

        Returns:
            Sorted list of module names

        Raises:
            ValueError: If circular dependency is detected in topological sort
        """
        if isinstance(sorting, str):
            sorting = SortingChoice(sorting)

        if sorting == SortingChoice.ALPHABETICAL:
            return sorted(module_names)
        elif sorting == SortingChoice.TOPOLOGICAL:
            return self._sort_topological(module_names)

    def _sort_topological(self, module_names: list[str]) -> list[str]:
        """Sort modules topologically based on their dependencies.

        Args:
            module_names: List of module names to sort

        Returns:
            Topologically sorted list of module names

        Raises:
            ValueError: If circular dependency is detected
        """
        if not module_names:
            return []

        module_set = set(module_names)
        graph: dict[str, set[str]] = {}

        for module_name in module_names:
            manifest = self.get_manifest(module_name)
            if manifest:
                deps_in_set = {
                    dep for dep in manifest.codependencies if dep in module_set
                }
                graph[module_name] = deps_in_set
            else:
                graph[module_name] = set()

        try:
            ts = TopologicalSorter(graph)
            return list(ts.static_order())
        except ValueError as e:
            raise ValueError(f"Circular dependency detected: {e}") from e
