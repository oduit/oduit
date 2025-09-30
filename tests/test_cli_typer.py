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
    @patch("oduit.cli_typer.load_config")
    def test_create_global_config_with_env(self, mock_load_config, mock_configure):
        """Test creating global config with environment."""
        mock_config = {"db_name": "test_db", "addons_path": "/test/addons"}
        mock_load_config.return_value = mock_config

        result = create_global_config(env="dev", verbose=True)

        self.assertIsInstance(result, GlobalConfig)
        self.assertEqual(result.env, "dev")
        self.assertEqual(result.verbose, True)
        self.assertEqual(result.env_config, mock_config)
        self.assertEqual(result.env_name, "dev")
        mock_load_config.assert_called_once_with("dev")

    @patch("oduit.cli_typer.configure_output")
    @patch("oduit.cli_typer.has_local_config")
    @patch("oduit.cli_typer.load_local_config")
    def test_create_global_config_with_local_config(
        self, mock_load_local, mock_has_local, mock_configure
    ):
        """Test creating global config with local .oduit.toml."""
        mock_has_local.return_value = True
        mock_config = {"db_name": "local_db", "addons_path": "/local/addons"}
        mock_load_local.return_value = mock_config

        result = create_global_config(verbose=True)

        self.assertIsInstance(result, GlobalConfig)
        self.assertIsNone(result.env)
        self.assertEqual(result.env_name, "local")
        self.assertEqual(result.env_config, mock_config)
        mock_load_local.assert_called_once()

    @patch("oduit.cli_typer.configure_output")
    @patch("oduit.cli_typer.has_local_config")
    def test_create_global_config_no_config_raises(
        self, mock_has_local, mock_configure
    ):
        """Test that missing config raises typer.Exit."""
        mock_has_local.return_value = False

        with self.assertRaises(typer.Exit) as context:
            create_global_config()

        self.assertEqual(context.exception.exit_code, 1)

    @patch("oduit.cli_typer.configure_output")
    @patch("oduit.cli_typer.load_config")
    def test_create_global_config_handles_load_error(
        self, mock_load_config, mock_configure
    ):
        """Test handling of config load errors."""
        mock_load_config.side_effect = FileNotFoundError("Config not found")

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
            self.assertIn("No environment specified", result.output)

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    def test_run_command(self, mock_load_config, mock_odoo_ops):
        """Test run command."""
        mock_load_config.return_value = self.mock_config
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "run"])

        self.assertEqual(result.exit_code, 0)
        mock_odoo_ops.assert_called_once()
        mock_ops_instance.run_odoo.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    def test_shell_command(self, mock_load_config, mock_odoo_ops):
        """Test shell command."""
        mock_load_config.return_value = self.mock_config
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "shell"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.run_shell.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    def test_shell_command_with_interface(self, mock_load_config, mock_odoo_ops):
        """Test shell command with custom interface."""
        mock_load_config.return_value = self.mock_config
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
    @patch("oduit.cli_typer.load_config")
    def test_install_command(self, mock_load_config, mock_odoo_ops):
        """Test install command."""
        mock_load_config.return_value = self.mock_config
        mock_ops_instance = MagicMock()
        mock_ops_instance.install_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "install", "sale"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.install_module.assert_called_once()
        args, kwargs = mock_ops_instance.install_module.call_args
        self.assertEqual(args[0], "sale")

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    def test_install_command_with_options(self, mock_load_config, mock_odoo_ops):
        """Test install command with various options."""
        mock_load_config.return_value = self.mock_config
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
                "--i18n-overwrite",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        args, kwargs = mock_ops_instance.install_module.call_args
        self.assertEqual(kwargs.get("without_demo"), "all")
        self.assertEqual(kwargs.get("language"), "de_DE")
        self.assertTrue(kwargs.get("i18n_overwrite"))

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    def test_update_command(self, mock_load_config, mock_odoo_ops):
        """Test update command."""
        mock_load_config.return_value = self.mock_config
        mock_ops_instance = MagicMock()
        mock_ops_instance.update_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "update", "sale"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.update_module.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    def test_update_command_with_compact(self, mock_load_config, mock_odoo_ops):
        """Test update command with compact flag."""
        mock_load_config.return_value = self.mock_config
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
    @patch("oduit.cli_typer.load_config")
    def test_test_command(self, mock_load_config, mock_odoo_ops):
        """Test test command."""
        mock_load_config.return_value = self.mock_config
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "test", "--test-tags", "/sale"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.run_tests.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    def test_test_command_with_coverage(self, mock_load_config, mock_odoo_ops):
        """Test test command with coverage option."""
        mock_load_config.return_value = self.mock_config
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
    @patch("oduit.cli_typer.load_config")
    @patch("builtins.input")
    def test_create_db_with_confirmation(
        self, mock_input, mock_load_config, mock_odoo_ops
    ):
        """Test create-db command with user confirmation."""
        mock_load_config.return_value = self.mock_config
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance
        mock_input.return_value = "y"

        result = self.runner.invoke(app, ["--env", "dev", "create-db"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.create_db.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    @patch("builtins.input")
    def test_create_db_cancelled(self, mock_input, mock_load_config, mock_odoo_ops):
        """Test create-db command cancelled by user."""
        mock_load_config.return_value = self.mock_config
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance
        mock_input.return_value = "n"

        result = self.runner.invoke(app, ["--env", "dev", "create-db"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.create_db.assert_not_called()
        self.assertIn("cancelled", result.output)

    @patch("oduit.cli_typer.load_config")
    def test_print_config_command(self, mock_load_config):
        """Test print-config command."""
        mock_load_config.return_value = self.mock_config

        result = self.runner.invoke(app, ["--env", "dev", "print-config"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("db_name", result.output)
        self.assertIn("test_db", result.output)

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    @patch("oduit.cli_typer.validate_addon_name")
    def test_create_addon_command(self, mock_validate, mock_load_config, mock_odoo_ops):
        """Test create-addon command."""
        mock_load_config.return_value = self.mock_config
        mock_validate.return_value = True
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "create-addon", "my_module"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.create_addon.assert_called_once()
        args, kwargs = mock_ops_instance.create_addon.call_args
        self.assertEqual(args[0], "my_module")

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    @patch("oduit.cli_typer.validate_addon_name")
    def test_create_addon_invalid_name(
        self, mock_validate, mock_load_config, mock_odoo_ops
    ):
        """Test create-addon with invalid name."""
        mock_load_config.return_value = self.mock_config
        mock_validate.return_value = False

        result = self.runner.invoke(
            app, ["--env", "dev", "create-addon", "Invalid-Name"]
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Invalid addon name", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.load_config")
    def test_list_addons_command(self, mock_load_config, mock_module_manager):
        """Test list-addons command."""
        mock_load_config.return_value = self.mock_config
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = ["sale", "purchase"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-addons"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("sale", result.output)
        self.assertIn("purchase", result.output)

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.load_config")
    @patch("os.makedirs")
    def test_export_lang_command(
        self, mock_makedirs, mock_load_config, mock_module_manager, mock_odoo_ops
    ):
        """Test export-lang command."""
        mock_config = {**self.mock_config, "language": "de_DE"}
        mock_load_config.return_value = mock_config
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.return_value = "/test/addons/sale"
        mock_module_manager.return_value = mock_manager_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "export-lang", "sale"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.export_module_language.assert_called_once()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    def test_verbose_flag(self, mock_load_config, mock_odoo_ops):
        """Test verbose flag propagation."""
        mock_load_config.return_value = self.mock_config
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "--verbose", "run"])

        self.assertEqual(result.exit_code, 0)
        args, kwargs = mock_odoo_ops.call_args
        self.assertTrue(kwargs.get("verbose"))

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.load_config")
    def test_no_http_flag(self, mock_load_config, mock_odoo_ops):
        """Test no-http flag propagation."""
        mock_load_config.return_value = self.mock_config
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "--no-http", "run"])

        self.assertEqual(result.exit_code, 0)
        args, kwargs = mock_ops_instance.run_odoo.call_args
        self.assertTrue(kwargs.get("no_http"))


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
