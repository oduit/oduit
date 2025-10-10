# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from oduit.module_manager import ModuleManager


class TestUtils(unittest.TestCase):
    @patch("os.path.isdir")
    @patch("os.listdir")
    @patch("os.path.exists")
    def test_find_module_dirs(self, mock_exists, mock_listdir, mock_isdir):
        """Test finding module directories."""
        mock_isdir.return_value = True
        mock_listdir.return_value = ["module1", "module2", "not_a_module"]

        # Make only module1 and module2 have __manifest__.py
        def exists_side_effect(path):
            return "module1" in path or "module2" in path

        mock_exists.side_effect = exists_side_effect

        addons_path = "/path/to/addons1,/path/to/addons2"
        module_manager = ModuleManager(addons_path)
        result = module_manager.find_module_dirs()

        self.assertEqual(result, ["module1", "module2"])

    @patch("os.path.isdir")
    @patch("os.listdir")
    @patch("os.path.exists")
    @patch("os.path.basename")
    def test_find_module_dirs_with_filter_dir_exact_match(
        self, mock_basename, mock_exists, mock_listdir, mock_isdir
    ):
        """Test finding module directories with filter_dir exact match."""
        mock_isdir.return_value = True

        def listdir_side_effect(path):
            if "addons1" in path:
                return ["module1", "module2"]
            elif "addons2" in path:
                return ["module3", "module4"]
            return []

        mock_listdir.side_effect = listdir_side_effect

        def exists_side_effect(path):
            return any(
                mod in path for mod in ["module1", "module2", "module3", "module4"]
            )

        mock_exists.side_effect = exists_side_effect

        def basename_side_effect(path):
            if "addons1" in path:
                return "addons1"
            elif "addons2" in path:
                return "addons2"
            return ""

        mock_basename.side_effect = basename_side_effect

        addons_path = "/path/to/addons1,/path/to/addons2"
        module_manager = ModuleManager(addons_path)
        result = module_manager.find_module_dirs(filter_dir="addons1")

        self.assertEqual(result, ["module1", "module2"])

    @patch("os.path.isdir")
    @patch("os.listdir")
    @patch("os.path.exists")
    @patch("os.path.basename")
    def test_find_module_dirs_with_filter_dir_partial_no_match(
        self, mock_basename, mock_exists, mock_listdir, mock_isdir
    ):
        """Test filter_dir doesn't match partial strings in dir name."""
        mock_isdir.return_value = True
        mock_listdir.return_value = ["module1", "module2"]

        def exists_side_effect(path):
            return "module1" in path or "module2" in path

        mock_exists.side_effect = exists_side_effect
        mock_basename.return_value = "myaddons"

        addons_path = "/path/to/myaddons"
        module_manager = ModuleManager(addons_path)
        result = module_manager.find_module_dirs(filter_dir="a")

        self.assertEqual(result, [])

    @patch("os.path.isdir")
    @patch("os.listdir")
    @patch("os.path.exists")
    @patch("os.path.basename")
    def test_find_module_dirs_with_filter_dir_substring_no_match(
        self, mock_basename, mock_exists, mock_listdir, mock_isdir
    ):
        """Test filter_dir doesn't match substring of directory name."""
        mock_isdir.return_value = True
        mock_listdir.return_value = ["module1", "module2"]

        def exists_side_effect(path):
            return "module1" in path or "module2" in path

        mock_exists.side_effect = exists_side_effect
        mock_basename.return_value = "custom_addons"

        addons_path = "/path/to/custom_addons"
        module_manager = ModuleManager(addons_path)
        result = module_manager.find_module_dirs(filter_dir="custom")

        self.assertEqual(result, [])

    @patch("os.path.isdir")
    @patch("os.listdir")
    @patch("os.path.exists")
    @patch("os.path.basename")
    def test_find_module_dirs_with_filter_dir_no_match(
        self, mock_basename, mock_exists, mock_listdir, mock_isdir
    ):
        """Test finding module directories with filter_dir (no match)."""
        mock_isdir.return_value = True
        mock_listdir.return_value = ["module1", "module2"]
        mock_exists.return_value = True
        mock_basename.return_value = "addons1"

        addons_path = "/path/to/addons1"
        module_manager = ModuleManager(addons_path)
        result = module_manager.find_module_dirs(filter_dir="nonexistent")

        self.assertEqual(result, [])


class TestModuleManager(unittest.TestCase):
    def setUp(self):
        self.addons_path = "/path/to/addons1,/path/to/addons2"
        self.module_manager = ModuleManager(self.addons_path)

    @patch("oduit.module_manager.Manifest")
    @patch("oduit.module_manager.ModuleManager.find_module_path")
    def test_parse_manifest_success(self, mock_find_module_path, mock_manifest_class):
        """Test successful manifest parsing."""
        mock_find_module_path.return_value = "/path/to/addons1/test_module"

        # Create mock manifest instance
        mock_manifest = MagicMock()
        expected = {
            "name": "Test Module",
            "version": "17.0.1.0.0",
            "depends": ["base", "web", "sale"],
            "installable": True,
            "auto_install": False,
        }
        mock_manifest.get_raw_data.return_value = expected
        mock_manifest_class.return_value = mock_manifest

        result = self.module_manager.parse_manifest("test_module")
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.find_module_path")
    def test_parse_manifest_module_not_found(self, mock_find_module_path):
        """Test parsing manifest when module is not found."""
        mock_find_module_path.return_value = None

        result = self.module_manager.parse_manifest("nonexistent_module")
        self.assertIsNone(result)

    @patch("oduit.module_manager.ModuleManager.find_module_path")
    def test_parse_manifest_file_not_found(self, mock_find_module_path):
        """Test parsing manifest when file doesn't exist."""
        mock_find_module_path.return_value = "/path/to/addons1/test_module"

        with patch("builtins.open", side_effect=FileNotFoundError):
            result = self.module_manager.parse_manifest("test_module")
            self.assertIsNone(result)

    @patch("oduit.module_manager.Manifest")
    @patch("oduit.module_manager.ModuleManager.find_module_path")
    def test_parse_manifest_invalid_syntax(
        self, mock_find_module_path, mock_manifest_class
    ):
        """Test parsing manifest with invalid Python syntax."""
        mock_find_module_path.return_value = "/path/to/addons1/test_module"

        # Import the actual exception class for testing
        import os
        import sys

        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from oduit.manifest import InvalidManifestError

        # Manifest constructor raises InvalidManifestError - caught and converted
        mock_manifest_class.side_effect = InvalidManifestError(
            "Invalid manifest syntax"
        )

        with self.assertRaises(ValueError) as context:
            self.module_manager.parse_manifest("test_module")
        self.assertIn("Invalid manifest syntax", str(context.exception))

    @patch("oduit.module_manager.Manifest")
    @patch("oduit.module_manager.ModuleManager.find_module_path")
    def test_parse_manifest_not_dict(self, mock_find_module_path, mock_manifest_class):
        """Test parsing manifest that doesn't contain a dictionary."""
        mock_find_module_path.return_value = "/path/to/addons1/test_module"

        # Import the actual exception class for testing
        import os
        import sys

        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from oduit.manifest import InvalidManifestError

        mock_manifest_class.side_effect = InvalidManifestError("is not a dictionary")

        with self.assertRaises(ValueError) as context:
            self.module_manager.parse_manifest("test_module")
        self.assertIn("is not a dictionary", str(context.exception))

    @patch("oduit.module_manager.ModuleManager.get_manifest")
    def test_get_module_codependencies_success(self, mock_get_manifest):
        """Test getting module codependencies successfully."""
        mock_manifest = MagicMock()
        mock_manifest.codependencies = ["base", "web", "sale"]
        mock_get_manifest.return_value = mock_manifest

        result = self.module_manager.get_module_codependencies("test_module")
        self.assertEqual(result, ["base", "web", "sale"])

    @patch("oduit.module_manager.ModuleManager.parse_manifest")
    def test_get_module_codependencies_no_depends_field(self, mock_parse_manifest):
        """Test getting codependencies when manifest has no depends field."""
        mock_parse_manifest.return_value = {
            "name": "Test Module",
            "version": "17.0.1.0.0",
        }

        result = self.module_manager.get_module_codependencies("test_module")
        self.assertEqual(result, [])

    @patch("oduit.module_manager.ModuleManager.parse_manifest")
    def test_get_module_codependencies_empty_depends(self, mock_parse_manifest):
        """Test getting codependencies when depends field is empty."""
        mock_parse_manifest.return_value = {
            "name": "Test Module",
            "depends": [],
        }

        result = self.module_manager.get_module_codependencies("test_module")
        self.assertEqual(result, [])

    @patch("oduit.module_manager.ModuleManager.parse_manifest")
    def test_get_module_codependencies_invalid_depends_type(self, mock_parse_manifest):
        """Test getting codependencies when depends field is not a list."""
        mock_parse_manifest.return_value = {
            "name": "Test Module",
            "depends": "not_a_list",
        }

        result = self.module_manager.get_module_codependencies("test_module")
        self.assertEqual(result, [])

    @patch("oduit.module_manager.ModuleManager.get_manifest")
    def test_get_module_codependencies_mixed_types(self, mock_get_manifest):
        """Test getting codependencies with mixed types in depends list."""
        mock_manifest = MagicMock()
        mock_manifest.codependencies = [
            "base",
            "web",
            "sale",
        ]
        mock_get_manifest.return_value = mock_manifest

        result = self.module_manager.get_module_codependencies("test_module")
        self.assertEqual(result, ["base", "web", "sale"])

    @patch("oduit.module_manager.ModuleManager.parse_manifest")
    def test_get_module_codependencies_module_not_found(self, mock_parse_manifest):
        """Test getting codependencies when module is not found."""
        mock_parse_manifest.return_value = None

        result = self.module_manager.get_module_codependencies("nonexistent_module")
        self.assertEqual(result, [])

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_build_dependency_graph_simple(self, mock_get_codependencies):
        """Test building dependency graph for a simple module."""

        # Module A depends on B and C, B depends on D, C and D have no dependencies
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b", "module_c"],
                "module_b": ["module_d"],
                "module_c": [],
                "module_d": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.build_dependency_graph("module_a")

        expected = {
            "module_a": ["module_b", "module_c"],
            "module_b": ["module_d"],
            "module_c": [],
            "module_d": [],
        }
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_build_dependency_graph_no_dependencies(self, mock_get_codependencies):
        """Test building dependency graph for module with no dependencies."""
        mock_get_codependencies.return_value = []

        result = self.module_manager.build_dependency_graph("standalone_module")

        expected = {"standalone_module": []}
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_build_dependency_graph_circular_dependency(self, mock_get_codependencies):
        """Test building dependency graph with circular dependency."""

        # A -> B -> C -> A (circular)
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b"],
                "module_b": ["module_c"],
                "module_c": ["module_a"],  # Creates circular dependency
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        with self.assertRaises(ValueError) as context:
            self.module_manager.build_dependency_graph("module_a")

        self.assertIn("Circular dependency detected", str(context.exception))
        self.assertIn("module_a", str(context.exception))

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_build_dependency_graph_shared_dependency(self, mock_get_codependencies):
        """Test building dependency graph with shared dependencies."""

        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b", "module_c"],
                "module_b": ["module_d"],
                "module_c": [],
                "module_d": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.build_dependency_graph("module_a")

        expected = {
            "module_a": ["module_b", "module_c"],
            "module_b": ["module_d"],
            "module_c": [],
            "module_d": [],
        }
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_dependency_tree_simple(self, mock_get_codependencies):
        """Test getting dependency tree for a simple module."""

        # A depends on B and C, B depends on D, C and D have no dependencies
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b", "module_c"],
                "module_b": ["module_d"],
                "module_c": [],
                "module_d": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.get_dependency_tree("module_a")

        expected = {"module_a": {"module_b": {"module_d": {}}, "module_c": {}}}
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_dependency_tree_no_dependencies(self, mock_get_codependencies):
        """Test getting dependency tree for module with no dependencies."""
        mock_get_codependencies.return_value = []

        result = self.module_manager.get_dependency_tree("standalone_module")

        expected = {"standalone_module": {}}
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_dependency_tree_circular_dependency(self, mock_get_codependencies):
        """Test getting dependency tree with circular dependency."""

        # A -> B -> C -> A (circular)
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b"],
                "module_b": ["module_c"],
                "module_c": ["module_a"],  # Creates circular dependency
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        with self.assertRaises(ValueError) as context:
            self.module_manager.get_dependency_tree("module_a")

        self.assertIn("Circular dependency detected", str(context.exception))

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_dependency_tree_shared_dependency(self, mock_get_codependencies):
        """Test getting dependency tree with shared dependencies."""

        # A depends on B and C, both B and C depend on D
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b", "module_c"],
                "module_b": ["module_d"],
                "module_c": ["module_d"],
                "module_d": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.get_dependency_tree("module_a")

        expected = {
            "module_a": {
                "module_b": {"module_d": {}},
                "module_c": {
                    "module_d": {}  # Shared dependency appears in both branches
                },
            }
        }
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_install_order_simple(self, mock_get_codependencies):
        """Test getting install order for a simple module."""

        # A depends on B and C, B depends on D, C and D have no dependencies
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b", "module_c"],
                "module_b": ["module_d"],
                "module_c": [],
                "module_d": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.get_install_order("module_a")

        # D should be first, then B and C (order may vary), then A last
        self.assertEqual(result[0], "module_d")  # D has no dependencies, so first
        self.assertEqual(result[-1], "module_a")  # A depends on others, so last
        self.assertIn("module_b", result[1:3])  # B should be before A but after D
        self.assertIn("module_c", result[1:3])  # C should be before A but after D

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_install_order_no_dependencies(self, mock_get_codependencies):
        """Test getting install order for module with no dependencies."""
        mock_get_codependencies.return_value = []

        result = self.module_manager.get_install_order("standalone_module")

        expected = ["standalone_module"]
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_install_order_linear_chain(self, mock_get_codependencies):
        """Test getting install order for a linear dependency chain."""

        # A -> B -> C -> D (linear chain)
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b"],
                "module_b": ["module_c"],
                "module_c": ["module_d"],
                "module_d": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.get_install_order("module_a")

        expected = ["module_d", "module_c", "module_b", "module_a"]
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_install_order_circular_dependency(self, mock_get_codependencies):
        """Test getting install order with circular dependency."""

        # A -> B -> C -> A (circular)
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b"],
                "module_b": ["module_c"],
                "module_c": ["module_a"],  # Creates circular dependency
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        with self.assertRaises(ValueError) as context:
            self.module_manager.get_install_order("module_a")

        self.assertIn("Circular dependency detected", str(context.exception))

    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_install_order_multiple_modules(self, mock_get_codependencies):
        """Test getting install order for multiple modules."""

        # A depends on C, B depends on D, C and D have no dependencies
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_c"],
                "module_b": ["module_d"],
                "module_c": [],
                "module_d": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.get_install_order("module_a", "module_b")

        # Should install dependencies first (C and D), then A and B
        self.assertIn("module_c", result)
        self.assertIn("module_d", result)
        self.assertIn("module_a", result)
        self.assertIn("module_b", result)

        # Dependencies should come before modules that depend on them
        self.assertLess(result.index("module_c"), result.index("module_a"))
        self.assertLess(result.index("module_d"), result.index("module_b"))

    @patch("oduit.module_manager.ModuleManager.find_module_path")
    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_find_missing_dependencies_all_available(
        self, mock_get_codependencies, mock_find_module_path
    ):
        """Test finding missing dependencies when all dependencies are available."""

        # A depends on B and C, all modules exist
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b", "module_c"],
                "module_b": [],
                "module_c": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect
        mock_find_module_path.return_value = "/some/path"  # All modules found

        result = self.module_manager.find_missing_dependencies("module_a")

        expected = []
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.find_module_path")
    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_find_missing_dependencies_some_missing(
        self, mock_get_codependencies, mock_find_module_path
    ):
        """Test finding missing dependencies when some dependencies are missing."""

        # A depends on B and C, B depends on D
        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b", "module_c"],
                "module_b": ["module_d"],
                "module_c": [],
                "module_d": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        # Only module_a and module_c exist, module_b and module_d are missing
        def find_module_path_side_effect(module):
            existing_modules = ["module_a", "module_c"]
            return "/some/path" if module in existing_modules else None

        mock_find_module_path.side_effect = find_module_path_side_effect

        result = self.module_manager.find_missing_dependencies("module_a")

        expected = ["module_b", "module_d"]
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.find_module_path")
    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_find_missing_dependencies_module_not_found(
        self, mock_get_codependencies, mock_find_module_path
    ):
        """Test finding missing dependencies when the root module doesn't exist."""

        # Module doesn't exist, so we can't build a dependency graph
        mock_find_module_path.return_value = None

        def codependencies_side_effect(module):
            if module == "nonexistent_module":
                return []  # Module doesn't exist, so no dependencies
            return []

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.find_missing_dependencies("nonexistent_module")

        expected = ["nonexistent_module"]
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.find_module_dirs")
    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_reverse_dependencies_simple(
        self, mock_get_codependencies, mock_find_module_dirs
    ):
        """Test getting reverse dependencies for a simple case."""

        # Available modules: A, B, C, D
        # A depends on B, B depends on C, C depends on D
        # So reverse deps for D should be [A, B, C]
        mock_find_module_dirs.return_value = [
            "module_a",
            "module_b",
            "module_c",
            "module_d",
        ]

        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b"],
                "module_b": ["module_c"],
                "module_c": ["module_d"],
                "module_d": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.get_reverse_dependencies("module_d")

        expected = ["module_a", "module_b", "module_c"]
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.find_module_dirs")
    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_reverse_dependencies_no_dependents(
        self, mock_get_codependencies, mock_find_module_dirs
    ):
        """Test getting reverse dependencies when no modules depend on the target."""

        mock_find_module_dirs.return_value = ["module_a", "module_b", "module_c"]

        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_b"],
                "module_b": [],
                "module_c": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.get_reverse_dependencies("module_c")

        expected = []
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.find_module_dirs")
    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_reverse_dependencies_multiple_dependents(
        self, mock_get_codependencies, mock_find_module_dirs
    ):
        """Test reverse dependencies with multiple modules depending on target."""

        # A depends on C, B depends on C, C has no dependencies
        # So reverse deps for C should be [A, B]
        mock_find_module_dirs.return_value = ["module_a", "module_b", "module_c"]

        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_c"],
                "module_b": ["module_c"],
                "module_c": [],
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        result = self.module_manager.get_reverse_dependencies("module_c")

        expected = ["module_a", "module_b"]
        self.assertEqual(result, expected)

    @patch("oduit.module_manager.ModuleManager.find_module_dirs")
    @patch("oduit.module_manager.ModuleManager.get_module_codependencies")
    def test_get_reverse_dependencies_with_errors(
        self, mock_get_codependencies, mock_find_module_dirs
    ):
        """Test reverse dependencies when some modules have circular deps."""

        mock_find_module_dirs.return_value = [
            "module_a",
            "module_b",
            "module_c",
            "module_d",
            "module_e",
        ]

        def codependencies_side_effect(module):
            deps_map = {
                "module_a": ["module_c"],  # A depends on C (clean)
                "module_b": ["module_e"],  # B depends on E (circular: B -> E -> B)
                "module_c": [],  # C has no dependencies (clean)
                "module_d": ["module_c"],  # D depends on C (clean)
                "module_e": [
                    "module_b"
                ],  # E depends on B (creates circular dependency)
            }
            return deps_map.get(module, [])

        mock_get_codependencies.side_effect = codependencies_side_effect

        # Should return module_a and module_d (clean dependencies on module_c)
        # module_b should be skipped due to circular dependency with module_e
        result = self.module_manager.get_reverse_dependencies("module_c")

        expected = ["module_a", "module_d"]
        self.assertEqual(result, expected)

    def test_find_odoo_base_modules_with_temp_structure(self):
        """Test finding base modules in Odoo installation structure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create structure: temp_dir/odoo-bin and temp_dir/odoo/addons/base/
            odoo_bin_path = os.path.join(temp_dir, "odoo-bin")
            with open(odoo_bin_path, "w") as f:
                f.write("#!/usr/bin/env python3")
            os.chmod(odoo_bin_path, 0o755)

            # Create base addons structure
            base_addons_dir = os.path.join(temp_dir, "odoo", "addons")
            os.makedirs(base_addons_dir)

            # Create a base module
            base_module_dir = os.path.join(base_addons_dir, "base")
            os.makedirs(base_module_dir)
            manifest_path = os.path.join(base_module_dir, "__manifest__.py")
            with open(manifest_path, "w") as f:
                f.write("{'name': 'Base', 'depends': []}")

            # Create custom addons dir
            custom_addons_dir = os.path.join(temp_dir, "custom_addons")
            os.makedirs(custom_addons_dir)

            # Create a custom module
            custom_module_dir = os.path.join(custom_addons_dir, "custom_module")
            os.makedirs(custom_module_dir)
            custom_manifest_path = os.path.join(custom_module_dir, "__manifest__.py")
            with open(custom_manifest_path, "w") as f:
                f.write("{'name': 'Custom Module', 'depends': ['base']}")

            # Initialize ModuleManager with custom_addons_dir
            module_manager = ModuleManager(custom_addons_dir)

            # Should find both custom module and base module
            found_modules = module_manager.find_module_dirs()
            self.assertIn("base", found_modules)
            self.assertIn("custom_module", found_modules)

            # Should be able to find the base module path
            base_path = module_manager.find_module_path("base")
            self.assertIsNotNone(base_path)
            self.assertEqual(base_path, base_module_dir)

            # Should be able to find the custom module path
            custom_path = module_manager.find_module_path("custom_module")
            self.assertIsNotNone(custom_path)
            self.assertEqual(custom_path, custom_module_dir)
