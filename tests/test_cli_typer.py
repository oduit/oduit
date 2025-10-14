# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import unittest
from unittest.mock import MagicMock, patch

import typer
from typer.testing import CliRunner

from oduit.cli_typer import app, create_global_config
from oduit.cli_types import AddonTemplate, GlobalConfig, OutputFormat, ShellInterface


class TestCreateGlobalConfig(unittest.TestCase):
    @patch("oduit.cli_typer.configure_output")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_create_global_config_with_env(
        self, mock_config_loader_class, mock_configure
    ):
        """Test creating global config with environment."""
        mock_config = {"db_name": "test_db", "addons_path": "/test/addons"}
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        result = create_global_config(env="dev", verbose=True)

        self.assertIsInstance(result, GlobalConfig)
        self.assertEqual(result.env, "dev")
        self.assertEqual(result.verbose, True)
        self.assertEqual(result.env_config, mock_config)
        self.assertEqual(result.env_name, "dev")
        mock_loader_instance.load_config.assert_called_once_with("dev")

    @patch("oduit.cli_typer.configure_output")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_create_global_config_with_local_config(
        self, mock_config_loader_class, mock_configure
    ):
        """Test creating global config with local .oduit.toml."""
        mock_config = {"db_name": "local_db", "addons_path": "/local/addons"}
        mock_loader_instance = MagicMock()
        mock_loader_instance.has_local_config.return_value = True
        mock_loader_instance.load_local_config.return_value = mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        result = create_global_config(verbose=True)

        self.assertIsInstance(result, GlobalConfig)
        self.assertIsNone(result.env)
        self.assertEqual(result.env_name, "local")
        self.assertEqual(result.env_config, mock_config)
        mock_loader_instance.load_local_config.assert_called_once()

    @patch("oduit.cli_typer.configure_output")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_create_global_config_no_config_raises(
        self, mock_config_loader_class, mock_configure
    ):
        """Test that missing config raises typer.Exit."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.has_local_config.return_value = False
        mock_config_loader_class.return_value = mock_loader_instance

        with self.assertRaises(typer.Exit) as context:
            create_global_config()

        self.assertEqual(context.exception.exit_code, 1)

    @patch("oduit.cli_typer.configure_output")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_create_global_config_handles_load_error(
        self, mock_config_loader_class, mock_configure
    ):
        """Test handling of config load errors."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.side_effect = FileNotFoundError(
            "Config not found"
        )
        mock_config_loader_class.return_value = mock_loader_instance

        with self.assertRaises(typer.Exit) as context:
            create_global_config(env="nonexistent")

        self.assertEqual(context.exception.exit_code, 1)


class TestCLICommands(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
        self.mock_config = {
            "db_name": "test_db",
            "addons_path": "/test/addons",
            "odoo_bin": "/usr/bin/odoo-bin",
            "python_bin": "/usr/bin/python3",
        }

    def test_main_no_args_shows_error(self):
        """Test main command with no arguments shows error."""
        # Mock sys.argv to simulate no arguments
        with patch("sys.argv", ["oduit"]):
            result = self.runner.invoke(app, [])

            self.assertEqual(result.exit_code, 1)
            self.assertIn("No command specified", result.output)

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_run_command(self, mock_config_loader_class, mock_odoo_ops):
        """Test run command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "run"])

        self.assertEqual(result.exit_code, 0)
        mock_odoo_ops.assert_called_once()
        mock_ops_instance.run_odoo.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_shell_command(self, mock_config_loader_class, mock_odoo_ops):
        """Test shell command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "shell"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.run_shell.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_shell_command_with_interface(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test shell command with custom interface."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "shell", "--shell-interface", "ipython"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.run_shell.assert_called_once()
        args, kwargs = mock_ops_instance.run_shell.call_args
        self.assertEqual(kwargs.get("shell_interface"), "ipython")

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_install_command(self, mock_config_loader_class, mock_odoo_ops):
        """Test install command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.install_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "install", "sale"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.install_module.assert_called_once()
        args, kwargs = mock_ops_instance.install_module.call_args
        self.assertEqual(args[0], "sale")

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_install_command_with_options(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test install command with various options."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.install_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "install",
                "sale",
                "--without-demo",
                "all",
                "--language",
                "de_DE",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        args, kwargs = mock_ops_instance.install_module.call_args
        self.assertEqual(kwargs.get("without_demo"), "all")
        self.assertEqual(kwargs.get("language"), "de_DE")

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_update_command(self, mock_config_loader_class, mock_odoo_ops):
        """Test update command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.update_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "update", "sale"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.update_module.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_update_command_with_compact(self, mock_config_loader_class, mock_odoo_ops):
        """Test update command with compact flag."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.update_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "update", "sale", "--compact"]
        )

        self.assertEqual(result.exit_code, 0)
        args, kwargs = mock_ops_instance.update_module.call_args
        self.assertTrue(kwargs.get("compact"))

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_test_command(self, mock_config_loader_class, mock_odoo_ops):
        """Test test command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "test", "--test-tags", "/sale"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.run_tests.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_test_command_with_coverage(self, mock_config_loader_class, mock_odoo_ops):
        """Test test command with coverage option."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "test",
                "--test-tags",
                "/sale",
                "--coverage",
                "sale",
                "--compact",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        args, kwargs = mock_ops_instance.run_tests.call_args
        self.assertEqual(kwargs.get("coverage"), "sale")
        self.assertTrue(kwargs.get("compact"))

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    @patch("builtins.input")
    def test_create_db_with_confirmation(
        self, mock_input, mock_config_loader_class, mock_odoo_ops
    ):
        """Test create-db command with user confirmation."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.db_exists.return_value = {"exists": False, "success": True}
        mock_odoo_ops.return_value = mock_ops_instance
        mock_input.return_value = "y"

        result = self.runner.invoke(app, ["--env", "dev", "create-db"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.db_exists.assert_called_once()
        mock_ops_instance.create_db.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    @patch("builtins.input")
    def test_create_db_cancelled(
        self, mock_input, mock_config_loader_class, mock_odoo_ops
    ):
        """Test create-db command cancelled by user."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.db_exists.return_value = {"exists": False, "success": True}
        mock_odoo_ops.return_value = mock_ops_instance
        mock_input.return_value = "n"

        result = self.runner.invoke(app, ["--env", "dev", "create-db"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.db_exists.assert_called_once()
        mock_ops_instance.create_db.assert_not_called()
        self.assertIn("cancelled", result.output)

    @patch("oduit.cli_typer.ConfigLoader")
    def test_print_config_command(self, mock_config_loader_class):
        """Test print-config command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(app, ["--env", "dev", "print-config"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("db_name", result.output)
        self.assertIn("test_db", result.output)

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    @patch("oduit.cli_typer.validate_addon_name")
    def test_create_addon_command(
        self, mock_validate, mock_config_loader_class, mock_odoo_ops
    ):
        """Test create-addon command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_validate.return_value = True
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "create-addon", "my_module"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.create_addon.assert_called_once()
        args, kwargs = mock_ops_instance.create_addon.call_args
        self.assertEqual(args[0], "my_module")

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    @patch("oduit.cli_typer.validate_addon_name")
    def test_create_addon_invalid_name(
        self, mock_validate, mock_config_loader_class, mock_odoo_ops
    ):
        """Test create-addon with invalid name."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_validate.return_value = False

        result = self.runner.invoke(
            app, ["--env", "dev", "create-addon", "Invalid-Name"]
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Invalid addon name", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_addons_command(self, mock_config_loader_class, mock_module_manager):
        """Test list-addons command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = ["sale", "purchase"]
        mock_manager_instance.sort_modules.return_value = ["purchase", "sale"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-addons"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("sale", result.output)
        self.assertIn("purchase", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_addons_with_select_dir(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-addons command with --select-dir filter."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = ["module1", "module2"]
        mock_manager_instance.sort_modules.return_value = ["module1", "module2"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-addons", "--select-dir", "myaddons"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.find_module_dirs.assert_called_once_with(
            filter_dir="myaddons"
        )
        self.assertIn("module1", result.output)
        self.assertIn("module2", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_command(self, mock_config_loader_class, mock_module_manager):
        """Test list-depends command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_direct_dependencies.return_value = [
            "base",
            "web",
            "sale",
        ]
        mock_manager_instance.sort_modules.return_value = ["base", "web", "sale"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-depends", "my_module"])

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_direct_dependencies.assert_called_once_with(
            "my_module"
        )
        self.assertIn("base", result.output)
        self.assertIn("web", result.output)
        self.assertIn("sale", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_no_missing(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends command when module has no dependencies."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_direct_dependencies.return_value = []
        mock_manager_instance.sort_modules.return_value = []
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-depends", "my_module"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("No external dependencies", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_error(self, mock_config_loader_class, mock_module_manager):
        """Test list-depends command with ValueError."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_direct_dependencies.side_effect = ValueError(
            "Module not found"
        )
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-depends", "my_module"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Error checking dependencies", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_codepends_command(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-codepends command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_reverse_dependencies.return_value = [
            "module_a",
            "module_b",
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-codepends", "base_module"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_reverse_dependencies.assert_called_once_with(
            "base_module"
        )
        self.assertIn("base_module", result.output)
        self.assertIn("module_a", result.output)
        self.assertIn("module_b", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_codepends_no_dependents(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-codepends command when no modules depend on target."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_reverse_dependencies.return_value = []
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-codepends", "standalone_module"]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("standalone_module", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_addons_with_separator(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-addons command with --separator parameter."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = [
            "sale",
            "purchase",
            "crm",
        ]
        mock_manager_instance.sort_modules.return_value = ["crm", "purchase", "sale"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-addons", "--separator", ","]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("crm,purchase,sale", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_with_separator(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends command with --separator parameter."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_direct_dependencies.return_value = [
            "base",
            "web",
            "sale",
        ]
        mock_manager_instance.sort_modules.return_value = ["base", "web", "sale"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "my_module", "--separator", ","]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("base,web,sale", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_with_tree(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends command with --tree flag."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manifest_a = MagicMock()
        mock_manifest_a.version = "1.0.0"
        mock_manifest_b = MagicMock()
        mock_manifest_b.version = "1.1.0"
        mock_manager_instance.get_manifest.side_effect = [
            mock_manifest_a,
            mock_manifest_b,
        ]
        mock_manager_instance.get_dependency_tree.return_value = {
            "my_module": {"web": {}}
        }
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "my_module", "--tree"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_dependency_tree.assert_called_once_with(
            "my_module", max_depth=None
        )
        self.assertIn("my_module", result.output)
        # 'base' addon should be filtered out as it's always required
        self.assertNotIn("base", result.output)
        # Child dependency should have tree connector
        self.assertIn("└──", result.output)
        self.assertIn("web", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_tree_multiple_modules(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends --tree with multiple modules."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_dependency_tree.side_effect = [
            {"module_a": {"dependencies": {"base": {}}}},
            {"module_b": {"dependencies": {"base": {}, "web": {}}}},
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "module_a,module_b", "--tree"]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(mock_manager_instance.get_dependency_tree.call_count, 2)
        self.assertIn("module_a", result.output)
        self.assertIn("module_b", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_tree_error_handling(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends --tree with ValueError from get_dependency_tree."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_dependency_tree.side_effect = ValueError(
            "Module not found"
        )
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "my_module", "--tree"]
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Module not found", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_with_depth(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends command with --depth parameter."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_dependencies_at_depth.return_value = ["base", "web"]
        mock_manager_instance.sort_modules.return_value = ["base", "web"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "my_module", "--depth", "1"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_dependencies_at_depth.assert_called_once_with(
            ["my_module"], max_depth=2
        )
        self.assertIn("base", result.output)
        self.assertIn("web", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_with_depth_zero(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends command with --depth 0 (direct dependencies only)."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_dependencies_at_depth.return_value = ["base"]
        mock_manager_instance.sort_modules.return_value = ["base"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "my_module", "--depth", "0"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_dependencies_at_depth.assert_called_once_with(
            ["my_module"], max_depth=1
        )
        self.assertIn("base", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_tree_with_depth(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends --tree with --depth parameter."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_dependency_tree.return_value = {
            "my_module": {"dependencies": {"base": {}}}
        }
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "my_module", "--tree", "--depth", "0"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_dependency_tree.assert_called_once_with(
            "my_module", max_depth=1
        )
        self.assertIn("my_module", result.output)
        self.assertIn("└──", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_multiple_modules_with_depth(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends with multiple modules and --depth."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_dependencies_at_depth.return_value = [
            "base",
            "web",
            "mail",
        ]
        mock_manager_instance.sort_modules.return_value = ["base", "web", "mail"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "list-depends", "module_a,module_b", "--depth", "1"],
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_dependencies_at_depth.assert_called_once_with(
            ["module_a", "module_b"], max_depth=2
        )
        self.assertIn("base", result.output)
        self.assertIn("web", result.output)
        self.assertIn("mail", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_tree_multiple_modules_with_depth(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends --tree with multiple modules and --depth."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_dependency_tree.side_effect = [
            {"module_a": {"dependencies": {"base": {}}}},
            {"module_b": {"dependencies": {"web": {}}}},
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "list-depends",
                "module_a,module_b",
                "--tree",
                "--depth",
                "0",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(mock_manager_instance.get_dependency_tree.call_count, 2)
        mock_manager_instance.get_dependency_tree.assert_any_call(
            "module_a", max_depth=1
        )
        mock_manager_instance.get_dependency_tree.assert_any_call(
            "module_b", max_depth=1
        )
        self.assertIn("module_a", result.output)
        self.assertIn("module_b", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_with_select_dir(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends command with --select-dir option."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = ["module1", "module2"]
        mock_manager_instance.get_direct_dependencies.return_value = [
            "base",
            "web",
        ]
        mock_manager_instance.sort_modules.return_value = ["base", "web"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "--select-dir", "myaddons"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.find_module_dirs.assert_called_once_with(
            filter_dir="myaddons"
        )
        mock_manager_instance.get_direct_dependencies.assert_called_once_with(
            "module1", "module2"
        )
        self.assertIn("base", result.output)
        self.assertIn("web", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_with_select_dir_and_separator(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends with --select-dir and --separator."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = ["module1", "module2"]
        mock_manager_instance.get_direct_dependencies.return_value = [
            "base",
            "web",
            "sale",
        ]
        mock_manager_instance.sort_modules.return_value = ["base", "web", "sale"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "list-depends",
                "--select-dir",
                "myaddons",
                "--separator",
                ",",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("base,web,sale", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_with_select_dir_and_depth(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends with --select-dir and --depth."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = ["module1", "module2"]
        mock_manager_instance.get_dependencies_at_depth.return_value = ["base"]
        mock_manager_instance.sort_modules.return_value = ["base"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "list-depends",
                "--select-dir",
                "myaddons",
                "--depth",
                "0",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_dependencies_at_depth.assert_called_once_with(
            ["module1", "module2"], max_depth=1
        )
        self.assertIn("base", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_with_select_dir_and_tree(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends with --select-dir and --tree."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = ["module1", "module2"]
        mock_manager_instance.get_dependency_tree.side_effect = [
            {"module1": {"dependencies": {"base": {}}}},
            {"module2": {"dependencies": {"web": {}}}},
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "--select-dir", "myaddons", "--tree"]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(mock_manager_instance.get_dependency_tree.call_count, 2)
        mock_manager_instance.get_dependency_tree.assert_any_call(
            "module1", max_depth=None
        )
        mock_manager_instance.get_dependency_tree.assert_any_call(
            "module2", max_depth=None
        )
        self.assertIn("module1", result.output)
        self.assertIn("module2", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_no_modules_no_select_dir(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends without modules or --select-dir raises error."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-depends"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Either provide module names or use --select-dir", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_both_modules_and_select_dir(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends with both modules and --select-dir raises error."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "list-depends", "my_module", "--select-dir", "myaddons"],
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn(
            "Cannot use both module names and --select-dir option", result.output
        )

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_codepends_with_separator(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-codepends command with --separator parameter."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_reverse_dependencies.return_value = [
            "module_a",
            "module_b",
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-codepends", "base_module", "--separator", ","]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("base_module,module_a,module_b", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_codepends_reverse_dependencies(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-codepends returns reverse dependencies.

        Modules that depend on target are returned. If module 'a' depends on 'b',
        then 'list-codepends b' should return 'a' and 'b'.
        This matches the behavior of manifestoo's list-codepends command.
        """
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_reverse_dependencies.return_value = ["a"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-codepends", "b"])

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_reverse_dependencies.assert_called_once_with("b")
        self.assertIn("a", result.output)
        self.assertIn("b", result.output)

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    @patch("os.makedirs")
    def test_export_lang_command(
        self,
        mock_makedirs,
        mock_config_loader_class,
        mock_module_manager,
        mock_odoo_ops,
    ):
        """Test export-lang command."""
        mock_config = {**self.mock_config, "language": "de_DE"}
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.return_value = "/test/addons/sale"
        mock_module_manager.return_value = mock_manager_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "export-lang", "sale"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.export_module_language.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_verbose_flag(self, mock_config_loader_class, mock_odoo_ops):
        """Test verbose flag propagation."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "--verbose", "run"])

        self.assertEqual(result.exit_code, 0)
        args, kwargs = mock_odoo_ops.call_args
        self.assertTrue(kwargs.get("verbose"))

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_no_http_flag(self, mock_config_loader_class, mock_odoo_ops):
        """Test no-http flag propagation."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "--no-http", "run"])

        self.assertEqual(result.exit_code, 0)
        args, kwargs = mock_ops_instance.run_odoo.call_args
        self.assertTrue(kwargs.get("no_http"))

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_json_flag(self, mock_config_loader_class, mock_odoo_ops):
        """Test --json flag sets format to JSON."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.install_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "--json", "install", "sale"])

        self.assertEqual(result.exit_code, 0)


class TestInitCommandHelpers(unittest.TestCase):
    @patch("oduit.cli_typer.ConfigLoader")
    def test_check_environment_exists_raises_exit(self, mock_config_loader_class):
        """Test _check_environment_exists exits if environment exists."""
        from oduit.cli_typer import _check_environment_exists

        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = ["dev", "prod"]

        with self.assertRaises(typer.Exit) as context:
            _check_environment_exists(mock_loader, "dev")

        self.assertEqual(context.exception.exit_code, 1)

    @patch("oduit.cli_typer.ConfigLoader")
    def test_check_environment_exists_passes_new_env(self, mock_config_loader_class):
        """Test _check_environment_exists passes for new environment."""
        from oduit.cli_typer import _check_environment_exists

        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = ["dev", "prod"]

        _check_environment_exists(mock_loader, "staging")

    @patch("oduit.cli_typer.ConfigLoader")
    def test_check_environment_exists_handles_file_not_found(
        self, mock_config_loader_class
    ):
        """Test _check_environment_exists handles FileNotFoundError."""
        from oduit.cli_typer import _check_environment_exists

        mock_loader = MagicMock()
        mock_loader.get_available_environments.side_effect = FileNotFoundError()

        _check_environment_exists(mock_loader, "dev")

    @patch("shutil.which")
    def test_detect_binaries_all_provided(self, mock_which):
        """Test _detect_binaries with all binaries provided."""
        from oduit.cli_typer import _detect_binaries

        python_bin, odoo_bin, coverage_bin = _detect_binaries(
            "/usr/bin/python3", "/usr/bin/odoo-bin", "/usr/bin/coverage"
        )

        self.assertEqual(python_bin, "/usr/bin/python3")
        self.assertEqual(odoo_bin, "/usr/bin/odoo-bin")
        self.assertEqual(coverage_bin, "/usr/bin/coverage")
        mock_which.assert_not_called()

    @patch("shutil.which")
    def test_detect_binaries_auto_detect_python3(self, mock_which):
        """Test _detect_binaries auto-detects python3."""
        from oduit.cli_typer import _detect_binaries

        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
            "odoo": "/usr/bin/odoo",
            "coverage": "/usr/bin/coverage",
        }.get(x)

        python_bin, odoo_bin, coverage_bin = _detect_binaries(None, None, None)

        self.assertEqual(python_bin, "/usr/bin/python3")
        self.assertEqual(odoo_bin, "/usr/bin/odoo")
        self.assertEqual(coverage_bin, "/usr/bin/coverage")

    @patch("shutil.which")
    def test_detect_binaries_auto_detect_python_fallback(self, mock_which):
        """Test _detect_binaries falls back to python if python3 not found."""
        from oduit.cli_typer import _detect_binaries

        mock_which.side_effect = lambda x: {
            "python": "/usr/bin/python",
            "odoo-bin": "/usr/bin/odoo-bin",
            "coverage": "/usr/bin/coverage",
        }.get(x)

        python_bin, odoo_bin, coverage_bin = _detect_binaries(None, None, None)

        self.assertEqual(python_bin, "/usr/bin/python")
        self.assertEqual(odoo_bin, "/usr/bin/odoo-bin")
        self.assertEqual(coverage_bin, "/usr/bin/coverage")

    @patch("shutil.which")
    def test_detect_binaries_python_not_found_exits(self, mock_which):
        """Test _detect_binaries exits if python not found."""
        from oduit.cli_typer import _detect_binaries

        mock_which.return_value = None

        with self.assertRaises(typer.Exit) as context:
            _detect_binaries(None, None, None)

        self.assertEqual(context.exception.exit_code, 1)

    @patch("shutil.which")
    def test_detect_binaries_odoo_not_found_continues(self, mock_which):
        """Test _detect_binaries continues if odoo not found."""
        from oduit.cli_typer import _detect_binaries

        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
            "coverage": "/usr/bin/coverage",
        }.get(x)

        python_bin, odoo_bin, coverage_bin = _detect_binaries(None, None, None)

        self.assertEqual(python_bin, "/usr/bin/python3")
        self.assertIsNone(odoo_bin)
        self.assertEqual(coverage_bin, "/usr/bin/coverage")

    @patch("shutil.which")
    def test_detect_binaries_coverage_not_found_continues(self, mock_which):
        """Test _detect_binaries continues if coverage not found."""
        from oduit.cli_typer import _detect_binaries

        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
            "odoo": "/usr/bin/odoo",
        }.get(x)

        python_bin, odoo_bin, coverage_bin = _detect_binaries(None, None, None)

        self.assertEqual(python_bin, "/usr/bin/python3")
        self.assertEqual(odoo_bin, "/usr/bin/odoo")
        self.assertIsNone(coverage_bin)

    def test_build_initial_config_with_all_binaries(self):
        """Test _build_initial_config with all binaries."""
        from oduit.cli_typer import _build_initial_config

        config = _build_initial_config(
            "/usr/bin/python3", "/usr/bin/odoo", "/usr/bin/coverage"
        )

        self.assertEqual(config["python_bin"], "/usr/bin/python3")
        self.assertEqual(config["odoo_bin"], "/usr/bin/odoo")
        self.assertEqual(config["coverage_bin"], "/usr/bin/coverage")

    def test_build_initial_config_without_odoo(self):
        """Test _build_initial_config without odoo binary."""
        from oduit.cli_typer import _build_initial_config

        config = _build_initial_config("/usr/bin/python3", None, "/usr/bin/coverage")

        self.assertEqual(config["python_bin"], "/usr/bin/python3")
        self.assertNotIn("odoo_bin", config)
        self.assertEqual(config["coverage_bin"], "/usr/bin/coverage")

    def test_build_initial_config_without_coverage(self):
        """Test _build_initial_config without coverage binary."""
        from oduit.cli_typer import _build_initial_config

        config = _build_initial_config("/usr/bin/python3", "/usr/bin/odoo", None)

        self.assertEqual(config["python_bin"], "/usr/bin/python3")
        self.assertEqual(config["odoo_bin"], "/usr/bin/odoo")
        self.assertIsNone(config["coverage_bin"])

    @patch("os.path.exists")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_import_or_convert_config_from_conf(
        self, mock_config_loader_class, mock_exists
    ):
        """Test _import_or_convert_config imports from .conf file."""
        from oduit.cli_typer import _import_or_convert_config

        mock_exists.return_value = True
        mock_loader = MagicMock()
        mock_loader.import_odoo_conf.return_value = {
            "odoo_params": {"db_name": "test_db"},
            "binaries": {},
        }

        env_config = {"python_bin": "/usr/bin/python3"}
        result = _import_or_convert_config(
            env_config,
            "/path/to/odoo.conf",
            mock_loader,
            "/usr/bin/python3",
            "/usr/bin/odoo",
            "/usr/bin/coverage",
        )

        mock_loader.import_odoo_conf.assert_called_once_with(
            "/path/to/odoo.conf", sectioned=True
        )
        self.assertIn("odoo_params", result)
        self.assertIn("binaries", result)
        self.assertEqual(result["binaries"]["python_bin"], "/usr/bin/python3")
        self.assertEqual(result["binaries"]["odoo_bin"], "/usr/bin/odoo")
        self.assertEqual(result["binaries"]["coverage_bin"], "/usr/bin/coverage")
        self.assertNotIn("python_bin", result)

    @patch("os.path.exists")
    def test_import_or_convert_config_conf_not_found(self, mock_exists):
        """Test _import_or_convert_config exits if .conf file not found."""
        from oduit.cli_typer import _import_or_convert_config

        mock_exists.return_value = False
        mock_loader = MagicMock()

        env_config = {"python_bin": "/usr/bin/python3"}
        with self.assertRaises(typer.Exit) as context:
            _import_or_convert_config(
                env_config,
                "/path/to/missing.conf",
                mock_loader,
                "/usr/bin/python3",
                None,
                None,
            )

        self.assertEqual(context.exception.exit_code, 1)

    @patch("os.path.exists")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_import_or_convert_config_import_error(
        self, mock_config_loader_class, mock_exists
    ):
        """Test _import_or_convert_config handles import errors."""
        from oduit.cli_typer import _import_or_convert_config

        mock_exists.return_value = True
        mock_loader = MagicMock()
        mock_loader.import_odoo_conf.side_effect = Exception("Parse error")

        env_config = {"python_bin": "/usr/bin/python3"}
        with self.assertRaises(typer.Exit) as context:
            _import_or_convert_config(
                env_config,
                "/path/to/odoo.conf",
                mock_loader,
                "/usr/bin/python3",
                None,
                None,
            )

        self.assertEqual(context.exception.exit_code, 1)

    @patch("oduit.config_provider.ConfigProvider")
    def test_import_or_convert_config_no_conf(self, mock_provider_class):
        """Test _import_or_convert_config converts to sectioned format."""
        from oduit.cli_typer import _import_or_convert_config

        mock_provider = MagicMock()
        mock_provider.to_sectioned_dict.return_value = {
            "binaries": {"python_bin": "/usr/bin/python3"},
            "odoo_params": {},
        }
        mock_provider_class.return_value = mock_provider

        env_config = {"python_bin": "/usr/bin/python3"}
        result = _import_or_convert_config(
            env_config, None, MagicMock(), "/usr/bin/python3", None, None
        )

        mock_provider_class.assert_called_once_with(env_config)
        mock_provider.to_sectioned_dict.assert_called_once()
        self.assertIn("binaries", result)

    def test_normalize_addons_path_string_to_list(self):
        """Test _normalize_addons_path converts string to list."""
        from oduit.cli_typer import _normalize_addons_path

        env_config = {
            "odoo_params": {"addons_path": "/path/one,/path/two, /path/three"}
        }

        _normalize_addons_path(env_config)

        expected = ["/path/one", "/path/two", "/path/three"]
        self.assertEqual(env_config["odoo_params"]["addons_path"], expected)

    def test_normalize_addons_path_already_list(self):
        """Test _normalize_addons_path leaves list unchanged."""
        from oduit.cli_typer import _normalize_addons_path

        env_config = {"odoo_params": {"addons_path": ["/path/one", "/path/two"]}}

        _normalize_addons_path(env_config)

        self.assertEqual(
            env_config["odoo_params"]["addons_path"], ["/path/one", "/path/two"]
        )

    def test_normalize_addons_path_no_odoo_params(self):
        """Test _normalize_addons_path handles missing odoo_params."""
        from oduit.cli_typer import _normalize_addons_path

        env_config = {"binaries": {"python_bin": "/usr/bin/python3"}}

        _normalize_addons_path(env_config)

        self.assertNotIn("odoo_params", env_config)

    def test_normalize_addons_path_no_addons_path(self):
        """Test _normalize_addons_path handles missing addons_path."""
        from oduit.cli_typer import _normalize_addons_path

        env_config = {"odoo_params": {"db_name": "test"}}

        _normalize_addons_path(env_config)

        self.assertNotIn("addons_path", env_config["odoo_params"])

    @patch("os.makedirs")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_save_config_file_success(self, mock_config_loader_class, mock_makedirs):
        """Test _save_config_file saves config successfully."""
        from unittest.mock import mock_open

        from oduit.cli_typer import _save_config_file

        mock_loader = MagicMock()
        mock_tomli_w = MagicMock()
        mock_loader._import_toml_libs.return_value = (None, mock_tomli_w)
        mock_loader.config_dir = "/home/user/.config/oduit"

        env_config = {"binaries": {"python_bin": "/usr/bin/python3"}}

        with patch("builtins.open", mock_open()):
            _save_config_file("/path/to/config.toml", env_config, mock_loader)

        mock_makedirs.assert_called_once_with("/home/user/.config/oduit", exist_ok=True)
        mock_tomli_w.dump.assert_called_once()

    @patch("oduit.cli_typer.ConfigLoader")
    def test_save_config_file_no_tomli_w(self, mock_config_loader_class):
        """Test _save_config_file exits if tomli_w not available."""
        from oduit.cli_typer import _save_config_file

        mock_loader = MagicMock()
        mock_loader._import_toml_libs.return_value = (None, None)

        env_config = {"binaries": {"python_bin": "/usr/bin/python3"}}

        with self.assertRaises(typer.Exit) as context:
            _save_config_file("/path/to/config.toml", env_config, mock_loader)

        self.assertEqual(context.exception.exit_code, 1)

    def test_display_config_summary_full_config(self):
        """Test _display_config_summary displays full config."""
        from oduit.cli_typer import _display_config_summary

        env_config = {
            "binaries": {
                "python_bin": "/usr/bin/python3",
                "odoo_bin": "/usr/bin/odoo",
                "coverage_bin": "/usr/bin/coverage",
            },
            "odoo_params": {
                "db_name": "test_db",
                "addons_path": ["/path/one", "/path/two"],
            },
        }

        _display_config_summary(env_config)

    def test_display_config_summary_minimal_config(self):
        """Test _display_config_summary handles minimal config."""
        from oduit.cli_typer import _display_config_summary

        env_config = {"binaries": {"python_bin": "/usr/bin/python3"}}

        _display_config_summary(env_config)

    def test_display_config_summary_string_addons_path(self):
        """Test _display_config_summary handles string addons_path."""
        from oduit.cli_typer import _display_config_summary

        env_config = {
            "binaries": {"python_bin": "/usr/bin/python3"},
            "odoo_params": {"addons_path": "/single/path"},
        }

        _display_config_summary(env_config)


class TestInitCommand(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    @patch("shutil.which")
    @patch("oduit.cli_typer.ConfigLoader")
    @patch("oduit.config_provider.ConfigProvider")
    def test_init_command_success(
        self,
        mock_provider_class,
        mock_config_loader_class,
        mock_which,
    ):
        """Test init command creates environment successfully."""
        from unittest.mock import mock_open

        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = []
        mock_loader.get_config_path.return_value = "/home/user/.config/oduit/dev.toml"
        mock_loader.config_dir = "/home/user/.config/oduit"
        mock_tomli_w = MagicMock()
        mock_loader._import_toml_libs.return_value = (None, mock_tomli_w)
        mock_config_loader_class.return_value = mock_loader

        mock_provider = MagicMock()
        mock_provider.to_sectioned_dict.return_value = {
            "binaries": {"python_bin": "/usr/bin/python3"},
            "odoo_params": {},
        }
        mock_provider_class.return_value = mock_provider

        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
            "odoo": "/usr/bin/odoo",
            "coverage": "/usr/bin/coverage",
        }.get(x)

        with patch("builtins.open", mock_open()):
            with patch("os.makedirs"):
                result = self.runner.invoke(app, ["init", "dev"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("created successfully", result.output)

    @patch("shutil.which")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_init_command_environment_exists(
        self, mock_config_loader_class, mock_which
    ):
        """Test init command fails if environment already exists."""
        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = ["dev", "prod"]
        mock_config_loader_class.return_value = mock_loader

        result = self.runner.invoke(app, ["init", "dev"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("already exists", result.output)

    @patch("os.path.exists")
    @patch("shutil.which")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_init_command_from_conf(
        self,
        mock_config_loader_class,
        mock_which,
        mock_exists,
    ):
        """Test init command imports from .conf file."""
        from unittest.mock import MagicMock, mock_open

        mock_exists.return_value = True
        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = []
        mock_loader.get_config_path.return_value = "/home/user/.config/oduit/dev.toml"
        mock_loader.config_dir = "/home/user/.config/oduit"
        mock_loader.import_odoo_conf.return_value = {
            "odoo_params": {"db_name": "test_db"},
            "binaries": {},
        }
        mock_tomli_w = MagicMock()
        mock_tomli_w.dump = MagicMock()
        mock_loader._import_toml_libs.return_value = (None, mock_tomli_w)
        mock_config_loader_class.return_value = mock_loader

        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
        }.get(x)

        original_open = open

        def selective_open(path, mode="r", *args, **kwargs):
            if "/home/user/.config/oduit/dev.toml" in str(path):
                m = mock_open()
                return m.return_value
            return original_open(path, mode, *args, **kwargs)

        with patch("builtins.open", side_effect=selective_open):
            with patch("os.makedirs"):
                result = self.runner.invoke(
                    app, ["init", "dev", "--from-conf", "/etc/odoo.conf"]
                )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Imported configuration", result.output)

    @patch("shutil.which")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_init_command_custom_binaries(self, mock_config_loader_class, mock_which):
        """Test init command with custom binary paths."""
        from unittest.mock import mock_open

        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = []
        mock_loader.get_config_path.return_value = "/home/user/.config/oduit/dev.toml"
        mock_loader.config_dir = "/home/user/.config/oduit"
        mock_tomli_w = MagicMock()
        mock_loader._import_toml_libs.return_value = (None, mock_tomli_w)
        mock_config_loader_class.return_value = mock_loader

        with patch("oduit.config_provider.ConfigProvider") as mock_provider_class:
            mock_provider = MagicMock()
            mock_provider.to_sectioned_dict.return_value = {
                "binaries": {
                    "python_bin": "/custom/python",
                    "odoo_bin": "/custom/odoo",
                },
                "odoo_params": {},
            }
            mock_provider_class.return_value = mock_provider

            with patch("builtins.open", mock_open()):
                with patch("os.makedirs"):
                    result = self.runner.invoke(
                        app,
                        [
                            "init",
                            "dev",
                            "--python-bin",
                            "/custom/python",
                            "--odoo-bin",
                            "/custom/odoo",
                        ],
                    )

        self.assertEqual(result.exit_code, 0)

    @patch("oduit.cli_typer.ConfigLoader")
    def test_init_command_no_tomli_w(self, mock_config_loader_class):
        """Test init command exits if tomli_w not available."""
        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = []
        mock_loader.get_config_path.return_value = "/home/user/.config/oduit/dev.toml"
        mock_loader._import_toml_libs.return_value = (None, None)
        mock_config_loader_class.return_value = mock_loader

        with patch("shutil.which", return_value="/usr/bin/python3"):
            with patch("oduit.config_provider.ConfigProvider") as mock_provider_class:
                mock_provider = MagicMock()
                mock_provider.to_sectioned_dict.return_value = {
                    "binaries": {"python_bin": "/usr/bin/python3"},
                    "odoo_params": {},
                }
                mock_provider_class.return_value = mock_provider

                result = self.runner.invoke(app, ["init", "dev"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("TOML writing support not available", result.output)


class TestCLITypes(unittest.TestCase):
    def test_output_format_enum(self):
        """Test OutputFormat enum values."""
        self.assertEqual(OutputFormat.TEXT.value, "text")
        self.assertEqual(OutputFormat.JSON.value, "json")

    def test_addon_template_enum(self):
        """Test AddonTemplate enum values."""
        self.assertEqual(AddonTemplate.BASIC.value, "basic")
        self.assertEqual(AddonTemplate.WEBSITE.value, "website")

    def test_shell_interface_enum(self):
        """Test ShellInterface enum values."""
        self.assertEqual(ShellInterface.PYTHON.value, "python")
        self.assertEqual(ShellInterface.IPYTHON.value, "ipython")
        self.assertEqual(ShellInterface.PTPYTHON.value, "ptpython")
        self.assertEqual(ShellInterface.BPYTHON.value, "bpython")

    def test_global_config_dataclass(self):
        """Test GlobalConfig dataclass."""
        config = GlobalConfig(
            env="dev",
            format=OutputFormat.JSON,
            verbose=True,
            no_http=True,
            env_config={"db_name": "test"},
            env_name="dev",
        )

        self.assertEqual(config.env, "dev")
        self.assertEqual(config.format, OutputFormat.JSON)
        self.assertTrue(config.verbose)
        self.assertTrue(config.no_http)
        if config.env_config is not None:
            self.assertEqual(config.env_config["db_name"], "test")
        self.assertEqual(config.env_name, "dev")


if __name__ == "__main__":
    unittest.main()
