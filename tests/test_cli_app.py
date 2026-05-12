# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import json
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import typer
from typer.testing import CliRunner

from oduit.api_models import (
    AddonInfo,
    AddonInstallState,
    AddonTestFile,
    InstalledAddonInventory,
    InstalledAddonRecord,
)
from oduit.cli.app import app, create_global_config
from oduit.cli_types import AddonTemplate, GlobalConfig, OutputFormat, ShellInterface


class TestCreateGlobalConfig(unittest.TestCase):
    @patch("oduit.cli.app.configure_output")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.configure_output")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.configure_output")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.configure_output")
    @patch("oduit.cli.app.ConfigLoader")
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

    def assert_common_json_envelope(
        self,
        payload: dict,
        *,
        read_only: bool,
        safety_level: str,
    ) -> None:
        self.assertEqual(payload["schema_version"], "2.0")
        self.assertIn("type", payload)
        self.assertIn("success", payload)
        self.assertEqual(payload["read_only"], read_only)
        self.assertEqual(payload["safety_level"], safety_level)
        self.assertIn("warnings", payload)
        self.assertIn("errors", payload)
        self.assertIn("remediation", payload)
        self.assertIn("data", payload)
        self.assertIn("meta", payload)
        self.assertIn("timestamp", payload["meta"])

    def test_main_no_args_shows_error(self):
        """Test main command with no arguments shows error."""
        # Mock sys.argv to simulate no arguments
        with patch("sys.argv", ["oduit"]):
            result = self.runner.invoke(app, [])

            self.assertEqual(result.exit_code, 1)
            self.assertIn("No command specified", result.output)

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_command(self, mock_config_loader_class, mock_odoo_ops):
        """Test install command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.install_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "install", "sale", "--allow-mutation"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.install_module.assert_called_once()
        args, kwargs = mock_ops_instance.install_module.call_args
        self.assertEqual(args[0], "sale")

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_command_reads_modules_from_stdin(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test install command accepts piped module lists."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.install_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "install", "--allow-mutation"],
            input="sale,purchase\n",
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.install_module.assert_called_once()
        args, kwargs = mock_ops_instance.install_module.call_args
        self.assertEqual(args[0], "sale,purchase")

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
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
                "--allow-mutation",
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_update_command(self, mock_config_loader_class, mock_odoo_ops):
        """Test update command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.update_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "update", "sale", "--allow-mutation"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.update_module.assert_called_once()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_update_command_reads_modules_from_stdin(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test update command accepts piped module lists."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.update_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "update", "--allow-mutation"],
            input="sale\npurchase\n",
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.update_module.assert_called_once()
        args, kwargs = mock_ops_instance.update_module.call_args
        self.assertEqual(args[0], "sale,purchase")

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_update_command_with_compact(self, mock_config_loader_class, mock_odoo_ops):
        """Test update command with compact flag."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.update_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "update", "sale", "--allow-mutation", "--compact"]
        )

        self.assertEqual(result.exit_code, 0)
        args, kwargs = mock_ops_instance.update_module.call_args
        self.assertTrue(kwargs.get("compact"))

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_uninstall_command_requires_config_opt_in(
        self, mock_config_loader_class, mock_odoo_ops
    ):
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
                "uninstall",
                "sale",
                "--allow-mutation",
                "--allow-uninstall",
            ],
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("allow_uninstall=true", result.output)
        mock_ops_instance.uninstall_module.assert_not_called()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_uninstall_command_requires_allow_uninstall_flag(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = {
            **self.mock_config,
            "allow_uninstall": True,
        }
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "uninstall", "sale", "--allow-mutation"]
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("--allow-uninstall", result.output)
        mock_ops_instance.uninstall_module.assert_not_called()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_uninstall_command_json_schema(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = {
            **self.mock_config,
            "allow_uninstall": True,
        }
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.uninstall_module.return_value = {
            "success": True,
            "operation": "uninstall_module",
            "module": "sale",
            "previous_state": "installed",
            "final_state": "uninstalled",
            "uninstalled": True,
        }
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "--json",
                "uninstall",
                "sale",
                "--allow-mutation",
                "--allow-uninstall",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=False,
            safety_level="controlled_runtime_mutation",
        )
        self.assertEqual(payload["type"], "module_uninstallation")
        self.assertEqual(payload["operation"], "uninstall_module")
        self.assertEqual(payload["final_state"], "uninstalled")
        _, kwargs = mock_ops_instance.uninstall_module.call_args
        self.assertTrue(kwargs.get("allow_uninstall"))

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_test_command(self, mock_config_loader_class, mock_odoo_ops):
        """Test test command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "test", "--allow-mutation", "--test-tags", "/sale"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.run_tests.assert_called_once()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
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
                "--allow-mutation",
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_plain_test_command_ignores_mutation_flag_policy(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = {
            **self.mock_config,
            "needs_mutation_flag": True,
        }
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "test", "--test-tags", "/sale"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.run_tests.assert_called_once()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_test_install_requires_allow_mutation_when_configured(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = {
            **self.mock_config,
            "needs_mutation_flag": True,
        }
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "test", "--install", "sale", "--test-tags", "/sale"]
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("needs_mutation_flag=true", result.output)
        mock_odoo_ops.assert_not_called()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_test_update_requires_allow_mutation_when_configured(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = {
            **self.mock_config,
            "needs_mutation_flag": True,
        }
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "test", "--update", "sale", "--test-tags", "/sale"]
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("needs_mutation_flag=true", result.output)
        mock_odoo_ops.assert_not_called()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_command_requires_allow_mutation_when_configured(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = {
            **self.mock_config,
            "needs_mutation_flag": True,
        }
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(app, ["--env", "dev", "install", "sale"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("needs_mutation_flag=true", result.output)
        mock_odoo_ops.assert_not_called()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_command_is_allowed_without_flag_by_default(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.install_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "install", "sale"])

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.install_module.assert_called_once()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_command_is_blocked_when_write_protected(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = {
            **self.mock_config,
            "write_protect_db": True,
        }
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "install", "sale", "--allow-mutation"]
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("write_protect_db=true", result.output)
        mock_odoo_ops.assert_not_called()

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    @patch("builtins.input")
    def test_create_db_with_drop_recreates_in_one_run(
        self, mock_input, mock_config_loader_class, mock_odoo_ops
    ):
        """Test create-db --drop drops and recreates in a single run."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        mock_ops_instance = MagicMock()
        mock_ops_instance.db_exists.return_value = {"exists": True, "success": True}
        mock_ops_instance.drop_db.return_value = {"success": True}
        mock_ops_instance.create_db.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance
        mock_input.return_value = "y"

        result = self.runner.invoke(
            app,
            ["--env", "dev", "create-db", "--drop"],
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.db_exists.assert_called_once()
        mock_ops_instance.drop_db.assert_called_once()
        mock_ops_instance.create_db.assert_called_once()
        self.assertNotIn("Database creation cancelled", result.output)

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    @patch("builtins.input")
    def test_create_db_with_drop_cancelled_does_not_create(
        self, mock_input, mock_config_loader_class, mock_odoo_ops
    ):
        """Test create-db --drop cancelled: no drop, no create."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        mock_ops_instance = MagicMock()
        mock_ops_instance.db_exists.return_value = {"exists": True, "success": True}
        mock_odoo_ops.return_value = mock_ops_instance
        mock_input.return_value = "n"

        result = self.runner.invoke(
            app,
            ["--env", "dev", "create-db", "--drop"],
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.db_exists.assert_called_once()
        mock_ops_instance.drop_db.assert_not_called()
        mock_ops_instance.create_db.assert_not_called()
        self.assertIn("Database drop cancelled", result.output)

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_create_db_non_interactive_fails_fast(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test create-db fails fast in non-interactive mode."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.db_exists.return_value = {"exists": False, "success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "--non-interactive", "create-db"]
        )

        self.assertEqual(result.exit_code, 1)
        mock_ops_instance.create_db.assert_not_called()
        self.assertIn("requires confirmation", result.output)

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_create_db_non_interactive_json_fails_fast(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test create-db emits structured error in non-interactive JSON mode."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.db_exists.return_value = {"exists": False, "success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "--json", "--non-interactive", "create-db"]
        )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=False,
            safety_level="controlled_runtime_mutation",
        )
        self.assertEqual(payload["error_type"], "ConfirmationRequired")
        self.assertIn("requires confirmation", payload["error"])
        self.assertTrue(payload["remediation"])

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    @patch("builtins.input")
    def test_create_db_is_blocked_when_write_protected(
        self, mock_input, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = {
            **self.mock_config,
            "write_protect_db": True,
        }
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(app, ["--env", "dev", "create-db"])

        self.assertEqual(result.exit_code, 1)
        mock_input.assert_not_called()
        mock_odoo_ops.assert_not_called()
        self.assertIn("write_protect_db=true", result.output)

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_create_db_requires_allow_mutation_when_configured(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = {
            **self.mock_config,
            "needs_mutation_flag": True,
        }
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(app, ["--env", "dev", "create-db"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("needs_mutation_flag=true", result.output)
        mock_odoo_ops.assert_not_called()

    @patch("oduit.cli.app.ConfigLoader")
    def test_print_config_command(self, mock_config_loader_class):
        """Test print-config command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(app, ["--env", "dev", "print-config"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("db_name", result.output)
        self.assertIn("test_db", result.output)

    @patch("oduit.cli.commands.database.subprocess.run")
    @patch("oduit.cli.app.ConfigLoader")
    def test_edit_config_command_for_env(
        self, mock_config_loader_class, mock_subprocess_run
    ):
        expected_path = os.path.abspath("/tmp/dev.toml")
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_loader_instance.resolve_config_path.return_value = (
            "/tmp/dev.toml",
            "toml",
        )
        mock_config_loader_class.return_value = mock_loader_instance

        with patch.dict("os.environ", {"VISUAL": "vim", "EDITOR": "vim"}, clear=False):
            result = self.runner.invoke(app, ["--env", "dev", "edit-config"])

        self.assertEqual(result.exit_code, 0)
        mock_loader_instance.resolve_config_path.assert_called_once_with("dev")
        mock_subprocess_run.assert_called_once_with(["vim", expected_path], check=True)
        self.assertIn(expected_path, result.output)

    @patch("oduit.cli.commands.database.subprocess.run")
    @patch("oduit.cli.app.ConfigLoader")
    def test_edit_config_command_for_local_config(
        self, mock_config_loader_class, mock_subprocess_run
    ):
        expected_path = os.path.abspath("/tmp/.oduit.toml")
        mock_loader_instance = MagicMock()
        mock_loader_instance.has_local_config.return_value = True
        mock_loader_instance.get_local_config_path.return_value = "/tmp/.oduit.toml"
        mock_loader_instance.load_local_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        with patch.dict("os.environ", {"EDITOR": "nvim"}, clear=False):
            result = self.runner.invoke(app, ["edit-config"])

        self.assertEqual(result.exit_code, 0)
        mock_subprocess_run.assert_called_once_with(["nvim", expected_path], check=True)
        self.assertIn(expected_path, result.output)

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    @patch("oduit.cli.app.validate_addon_name")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    @patch("oduit.cli.app.validate_addon_name")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    def test_list_addons_help_does_not_expose_dead_type_option(self):
        """Test list-addons help omits unsupported --type option."""
        result = self.runner.invoke(app, ["list-addons", "--help"])

        self.assertEqual(result.exit_code, 0)
        self.assertNotIn("--type", result.output)

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_installed_addons_command(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test list-installed-addons command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.list_installed_addons.return_value = InstalledAddonInventory(
            success=True,
            operation="list_installed_addons",
            addons=[
                InstalledAddonRecord(
                    module="base",
                    state="installed",
                    installed=True,
                ),
                InstalledAddonRecord(
                    module="sale",
                    state="installed",
                    installed=True,
                ),
            ],
            total=2,
            states=["installed"],
        )
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-installed-addons"])

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output.strip().splitlines(), ["base", "sale"])
        mock_ops_instance.list_installed_addons.assert_called_once_with(
            modules=None,
            states=None,
        )

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_installed_addons_reads_modules_from_stdin(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test list-installed-addons accepts piped module filters."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.list_installed_addons.return_value = InstalledAddonInventory(
            success=True,
            operation="list_installed_addons",
            addons=[
                InstalledAddonRecord(
                    module="sale",
                    state="installed",
                    installed=True,
                ),
            ],
            total=1,
            states=["installed"],
        )
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "list-installed-addons"],
            input="sale,purchase\n",
        )

        self.assertEqual(result.exit_code, 0)
        mock_ops_instance.list_installed_addons.assert_called_once_with(
            modules=["sale", "purchase"],
            states=None,
        )

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_installed_addons_include_state_and_separator(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test list-installed-addons text formatting helpers."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.list_installed_addons.return_value = InstalledAddonInventory(
            success=True,
            operation="list_installed_addons",
            addons=[
                InstalledAddonRecord(
                    module="sale",
                    state="installed",
                    installed=True,
                ),
                InstalledAddonRecord(
                    module="stock",
                    state="to_upgrade",
                    installed=False,
                ),
            ],
            total=2,
            states=["installed", "to_upgrade"],
        )
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "list-installed-addons",
                "--state",
                "installed",
                "--state",
                "to_upgrade",
                "--include-state",
                "--separator",
                ",",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output.strip(), "sale:installed,stock:to_upgrade")
        mock_ops_instance.list_installed_addons.assert_called_once_with(
            modules=None,
            states=["installed", "to_upgrade"],
        )

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_installed_addons_json_output(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test list-installed-addons JSON output."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.list_installed_addons.return_value = InstalledAddonInventory(
            success=True,
            operation="list_installed_addons",
            addons=[
                InstalledAddonRecord(
                    module="sale",
                    state="installed",
                    installed=True,
                    shortdesc="Sales",
                )
            ],
            total=1,
            states=["installed"],
            modules_filter=["sale"],
        )
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "--json",
                "list-installed-addons",
                "--modules",
                "sale",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=True,
            safety_level="safe_read_only",
        )
        self.assertEqual(payload["type"], "installed_addon_inventory")
        self.assertEqual(payload["operation"], "list_installed_addons")
        self.assertEqual(payload["addons"][0]["module"], "sale")
        self.assertEqual(payload["modules_filter"], ["sale"])

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_addon_info_json_output(self, mock_config_loader_class, mock_odoo_ops):
        """Test addon-info JSON output."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.addon_info.return_value = AddonInfo(
            module="sale",
            module_path="/test/addons/sale",
            addon_type="core",
            version_display="17.0.1.0.0",
            summary="Sales",
            description="Sales management",
            license="LGPL-3",
            depends=["base"],
            models=["sale.order"],
            inherit_models=["mail.thread"],
            model_count=1,
            test_cases=[
                AddonTestFile(
                    path="/test/addons/sale/tests/test_sale.py", test_type="python"
                )
            ],
            test_count=1,
            languages=["de", "fr"],
            installed_state=AddonInstallState(
                success=True,
                operation="get_addon_install_state",
                module="sale",
                record_found=True,
                state="installed",
                installed=True,
                database="test_db",
            ),
        )
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "--json", "addon-info", "sale"],
        )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=True,
            safety_level="safe_read_only",
        )
        self.assertEqual(payload["type"], "addon_info")
        self.assertEqual(payload["operation"], "addon_info")
        self.assertEqual(payload["module"], "sale")
        self.assertEqual(payload["models"], ["sale.order"])
        self.assertEqual(payload["languages"], ["de", "fr"])
        self.assertEqual(payload["installed_state"]["state"], "installed")
        mock_ops_instance.addon_info.assert_called_once_with(
            "sale",
            odoo_series=None,
            database=None,
            timeout=30.0,
        )

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_installed_addons_runtime_failure_exits_non_zero(
        self, mock_config_loader_class, mock_odoo_ops
    ):
        """Test list-installed-addons exits non-zero on runtime failure."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.list_installed_addons.return_value = InstalledAddonInventory(
            success=False,
            operation="list_installed_addons",
            states=["installed"],
            error="database unavailable",
            error_type="QueryError",
        )
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-installed-addons"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("database unavailable", result.output)

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_depends_reads_modules_from_stdin(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends accepts piped module lists."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.get_direct_dependencies.return_value = ["base", "web"]
        mock_manager_instance.sort_modules.return_value = ["base", "web"]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "list-depends"],
            input="sale,purchase\n",
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_direct_dependencies.assert_called_once_with(
            "sale", "purchase"
        )
        self.assertIn("base", result.output)

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_order_command(self, mock_config_loader_class, mock_module_manager):
        """Test install-order command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.side_effect = lambda module: (
            f"/test/addons/{module}"
        )
        mock_manager_instance.get_install_order.return_value = [
            "base",
            "sale",
            "my_module",
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "install-order", "my_module,sale"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_install_order.assert_called_once_with(
            "my_module", "sale"
        )
        self.assertIn("base", result.output)
        self.assertIn("sale", result.output)
        self.assertIn("my_module", result.output)

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_order_command_reads_modules_from_stdin(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test install-order command accepts piped module lists."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.side_effect = lambda module: (
            f"/test/addons/{module}"
        )
        mock_manager_instance.get_install_order.return_value = [
            "base",
            "sale",
            "purchase",
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "install-order"],
            input="sale,purchase\n",
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_install_order.assert_called_once_with(
            "sale", "purchase"
        )
        self.assertIn("base", result.output)

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_order_json_with_select_dir(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test install-order JSON output with --select-dir."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = ["sale", "purchase"]
        mock_manager_instance.get_install_order.return_value = [
            "base",
            "sale",
            "purchase",
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "--json", "install-order", "--select-dir", "myaddons"],
        )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=True,
            safety_level="safe_read_only",
        )
        self.assertEqual(payload["type"], "result")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["operation"], "install_order")
        self.assertEqual(payload["source"], "select_dir")
        self.assertEqual(payload["select_dir"], "myaddons")
        self.assertEqual(payload["install_order"], ["base", "sale", "purchase"])

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_order_json_missing_module(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test install-order emits structured JSON on missing modules."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.side_effect = lambda module: None
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "--json", "install-order", "missing_module"]
        )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=True,
            safety_level="safe_read_only",
        )
        self.assertEqual(payload["type"], "result")
        self.assertFalse(payload["success"])
        self.assertEqual(payload["operation"], "install_order")
        self.assertIn("Modules not found", payload["error"])

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_order_json_cycle_details(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test install-order JSON output includes cycle details."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.return_value = "/test/addons/module_a"
        mock_manager_instance.get_install_order.side_effect = ValueError(
            "Circular dependency detected: module_a -> module_b -> module_a"
        )
        mock_manager_instance.parse_cycle_error.return_value = [
            "module_a",
            "module_b",
            "module_a",
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "--json", "install-order", "module_a"]
        )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["error_type"], "DependencyCycleError")
        self.assertEqual(payload["cycle_path"], ["module_a", "module_b", "module_a"])
        self.assertEqual(payload["cycle_length"], 2)
        self.assertTrue(payload["remediation"])

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_order_text_cycle_details(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test install-order text mode shows cycle details."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.return_value = "/test/addons/module_a"
        mock_manager_instance.get_install_order.side_effect = ValueError(
            "Circular dependency detected: module_a -> module_b -> module_a"
        )
        mock_manager_instance.analyze_dependency_cycle.return_value = {
            "requested_modules": ["module_a"],
            "graph": {"module_a": ["module_b"], "module_b": ["module_a"]},
            "cycle_path": ["module_a", "module_b", "module_a"],
            "cycle_length": 2,
            "cycle_edges": [
                {"from": "module_a", "to": "module_b"},
                {"from": "module_b", "to": "module_a"},
            ],
            "cycle_modules": ["module_a", "module_b"],
            "modules": {
                "module_a": {
                    "module_path": "/test/addons/module_a",
                    "depends": ["module_b"],
                },
                "module_b": {
                    "module_path": "/test/addons/module_b",
                    "depends": ["module_a"],
                },
            },
        }
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(app, ["--env", "dev", "install-order", "module_a"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Cycle path:", result.output)
        self.assertIn("module_a -> module_b -> module_a", result.output)
        self.assertIn("module_a depends on module_b", result.output)
        self.assertIn("Run 'oduit explain-install-order module_a'", result.output)

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_explain_install_order_json_cycle_details(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test explain-install-order returns structured cycle diagnostics."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.return_value = "/test/addons/module_a"
        mock_manager_instance.analyze_dependency_cycle.return_value = {
            "requested_modules": ["module_a"],
            "graph": {"module_a": ["module_b"], "module_b": ["module_a"]},
            "cycle_path": ["module_a", "module_b", "module_a"],
            "cycle_length": 2,
            "cycle_edges": [
                {"from": "module_a", "to": "module_b"},
                {"from": "module_b", "to": "module_a"},
            ],
            "cycle_modules": ["module_a", "module_b"],
            "modules": {
                "module_a": {
                    "module_path": "/test/addons/module_a",
                    "depends": ["module_b"],
                },
                "module_b": {
                    "module_path": "/test/addons/module_b",
                    "depends": ["module_a"],
                },
            },
        }
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "--json", "explain-install-order", "module_a"]
        )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["operation"], "explain_install_order")
        self.assertEqual(payload["error_type"], "DependencyCycleError")
        self.assertEqual(payload["requested_modules"], ["module_a"])
        self.assertEqual(payload["cycle_path"], ["module_a", "module_b", "module_a"])
        self.assertEqual(
            payload["cycle_edges"][0], {"from": "module_a", "to": "module_b"}
        )
        self.assertEqual(payload["modules"]["module_a"]["depends"], ["module_b"])

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_explain_install_order_reads_modules_from_stdin(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test explain-install-order accepts piped module lists."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.side_effect = lambda module: (
            f"/test/addons/{module}"
        )
        mock_manager_instance.analyze_dependency_cycle.return_value = {
            "requested_modules": ["sale", "purchase"],
            "graph": {},
            "cycle_path": [],
            "cycle_length": 0,
            "cycle_edges": [],
            "cycle_modules": [],
            "modules": {},
        }
        mock_manager_instance.get_install_order.return_value = [
            "base",
            "sale",
            "purchase",
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "--json", "explain-install-order"],
            input="sale,purchase\n",
        )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assertEqual(payload["requested_modules"], ["sale", "purchase"])
        self.assertEqual(payload["source"], "stdin")
        mock_manager_instance.get_install_order.assert_called_once_with(
            "sale", "purchase"
        )

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_explain_install_order_json_select_dir(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test explain-install-order supports --select-dir."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_dirs.return_value = ["module_a", "module_b"]
        mock_manager_instance.analyze_dependency_cycle.return_value = {
            "requested_modules": ["module_a", "module_b"],
            "graph": {"module_a": ["module_b"], "module_b": ["module_a"]},
            "cycle_path": ["module_a", "module_b", "module_a"],
            "cycle_length": 2,
            "cycle_edges": [
                {"from": "module_a", "to": "module_b"},
                {"from": "module_b", "to": "module_a"},
            ],
            "cycle_modules": ["module_a", "module_b"],
            "modules": {
                "module_a": {
                    "module_path": "/test/addons/module_a",
                    "depends": ["module_b"],
                },
                "module_b": {
                    "module_path": "/test/addons/module_b",
                    "depends": ["module_a"],
                },
            },
        }
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "--json",
                "explain-install-order",
                "--select-dir",
                "myaddons",
            ],
        )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["source"], "select_dir")
        self.assertEqual(payload["select_dir"], "myaddons")
        self.assertEqual(payload["requested_modules"], ["module_a", "module_b"])
        self.assertIn("module_b", payload["modules"])

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_explain_install_order_json_non_cycle_failure(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test explain-install-order keeps non-cycle failures as DependencyError."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.return_value = "/test/addons/module_a"
        mock_manager_instance.analyze_dependency_cycle.return_value = {
            "requested_modules": ["module_a"],
            "graph": {},
            "cycle_path": [],
            "cycle_length": 0,
            "cycle_edges": [],
            "cycle_modules": [],
            "modules": {},
        }
        mock_manager_instance.get_install_order.side_effect = ValueError(
            "Dependency graph unavailable"
        )
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "--json", "explain-install-order", "module_a"]
        )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["operation"], "explain_install_order")
        self.assertEqual(payload["error_type"], "DependencyError")
        self.assertEqual(payload["requested_modules"], ["module_a"])
        self.assertEqual(payload["error"], "Dependency graph unavailable")

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_impact_of_update_command(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test impact-of-update command."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.return_value = "/test/addons/sale"
        mock_manager_instance.get_reverse_dependencies.return_value = [
            "sale_stock",
            "custom_sale",
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(app, ["--env", "dev", "impact-of-update", "sale"])

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_reverse_dependencies.assert_called_once_with("sale")
        self.assertIn("sale_stock", result.output)
        self.assertIn("custom_sale", result.output)

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_impact_of_update_json_no_dependents(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test impact-of-update JSON output preserves empty impact lists."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_module_path.return_value = "/test/addons/base"
        mock_manager_instance.get_reverse_dependencies.return_value = []
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "--json", "impact-of-update", "base"]
        )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=True,
            safety_level="safe_read_only",
        )
        self.assertEqual(payload["type"], "result")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["operation"], "impact_of_update")
        self.assertEqual(payload["module"], "base")
        self.assertEqual(payload["impacted_modules"], [])
        self.assertEqual(payload["impact_count"], 0)

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.AddonsPathManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_duplicates_command(
        self, mock_config_loader_class, mock_path_manager_class
    ):
        """Test list-duplicates command in text mode."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_path_manager = MagicMock()
        mock_path_manager.find_duplicate_module_names.return_value = {
            "sale": ["/a/sale", "/b/sale"]
        }
        mock_path_manager_class.return_value = mock_path_manager

        result = self.runner.invoke(app, ["--env", "dev", "list-duplicates"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("sale:", result.output)
        self.assertIn("/a/sale", result.output)
        self.assertIn("/b/sale", result.output)

    @patch("oduit.cli.app.AddonsPathManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_duplicates_json_command(
        self, mock_config_loader_class, mock_path_manager_class
    ):
        """Test list-duplicates command in JSON mode."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_path_manager = MagicMock()
        mock_path_manager.find_duplicate_module_names.return_value = {
            "sale": ["/a/sale", "/b/sale"]
        }
        mock_path_manager_class.return_value = mock_path_manager

        result = self.runner.invoke(app, ["--env", "dev", "--json", "list-duplicates"])

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=True,
            safety_level="safe_read_only",
        )
        self.assertEqual(payload["type"], "duplicate_modules")
        self.assertEqual(payload["duplicate_count"], 1)
        self.assertEqual(payload["duplicate_modules"]["sale"], ["/a/sale", "/b/sale"])

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_depends_no_modules_no_select_dir(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends without modules or --select-dir raises error."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(app, ["--env", "dev", "list-depends"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn(
            "Either provide module names, pipe module names, or use --select-dir",
            result.output,
        )

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
    def test_list_missing_reads_modules_from_stdin(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-missing accepts piped module lists."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_manager_instance = MagicMock()
        mock_manager_instance.find_missing_dependencies.side_effect = [
            ["base"],
            ["web"],
        ]
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "list-missing", "--separator", ","],
            input="sale,purchase\n",
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.find_missing_dependencies.assert_any_call("sale")
        mock_manager_instance.find_missing_dependencies.assert_any_call("purchase")
        self.assertEqual(result.output.strip(), "base,web")

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ModuleManager")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_json_flag(self, mock_config_loader_class, mock_odoo_ops):
        """Test --json flag sets format to JSON."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.install_module.return_value = {"success": True}
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "--json", "install", "sale", "--allow-mutation"],
        )

        self.assertEqual(result.exit_code, 0)

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_install_command_json_schema(self, mock_config_loader_class, mock_odoo_ops):
        """Test install JSON output includes stable schema fields."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.install_module.return_value = {
            "success": True,
            "operation": "install",
            "return_code": 0,
            "command": ["python3", "odoo-bin", "-i", "sale"],
            "stdout": "installed",
            "module": "sale",
        }
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(
            app,
            ["--env", "dev", "--json", "install", "sale", "--allow-mutation"],
        )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=False,
            safety_level="controlled_runtime_mutation",
        )
        self.assertEqual(payload["type"], "result")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["operation"], "install")
        self.assertEqual(payload["return_code"], 0)
        self.assertNotIn("command", payload)
        self.assertNotIn("stdout", payload)

    @patch("oduit.cli.app.OdooOperations")
    @patch("oduit.cli.app.ConfigLoader")
    def test_version_command_json_schema(self, mock_config_loader_class, mock_odoo_ops):
        """Test version JSON output includes stable schema fields."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance
        mock_ops_instance = MagicMock()
        mock_ops_instance.get_odoo_version.return_value = {
            "success": True,
            "operation": "get_odoo_version",
            "version": "17.0",
            "return_code": 0,
            "command": ["python3", "odoo-bin", "--version"],
            "stdout": "Odoo 17.0",
            "stderr": "",
        }
        mock_odoo_ops.return_value = mock_ops_instance

        result = self.runner.invoke(app, ["--env", "dev", "--json", "version"])

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=True,
            safety_level="safe_read_only",
        )
        self.assertEqual(payload["type"], "result")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["operation"], "get_odoo_version")
        self.assertEqual(payload["version"], "17.0")

    @patch("oduit.cli.app.ConfigLoader")
    def test_print_config_json_schema(self, mock_config_loader_class):
        """Test print-config JSON output uses the shared schema envelope."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        result = self.runner.invoke(app, ["--env", "dev", "--json", "print-config"])

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assert_common_json_envelope(
            payload,
            read_only=True,
            safety_level="safe_read_only",
        )
        self.assertEqual(payload["type"], "result")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["operation"], "print_config")
        self.assertEqual(payload["environment"], "dev")
        self.assertEqual(payload["config"], self.mock_config)


class TestInitCommandHelpers(unittest.TestCase):
    @patch("oduit.cli.app.ConfigLoader")
    def test_check_environment_exists_raises_exit(self, mock_config_loader_class):
        """Test _check_environment_exists exits if environment exists."""
        from oduit.cli.init_env import check_environment_exists

        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = ["dev", "prod"]

        with self.assertRaises(typer.Exit) as context:
            check_environment_exists(mock_loader, "dev")

        self.assertEqual(context.exception.exit_code, 1)

    @patch("oduit.cli.app.ConfigLoader")
    def test_check_environment_exists_passes_new_env(self, mock_config_loader_class):
        """Test _check_environment_exists passes for new environment."""
        from oduit.cli.init_env import check_environment_exists

        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = ["dev", "prod"]

        check_environment_exists(mock_loader, "staging")

    @patch("oduit.cli.app.ConfigLoader")
    def test_check_environment_exists_handles_file_not_found(
        self, mock_config_loader_class
    ):
        """Test _check_environment_exists handles FileNotFoundError."""
        from oduit.cli.init_env import check_environment_exists

        mock_loader = MagicMock()
        mock_loader.get_available_environments.side_effect = FileNotFoundError()

        check_environment_exists(mock_loader, "dev")

    def test_resolve_init_target_rejects_local_and_output_together(self):
        """Test local/output target selection is mutually exclusive."""
        from oduit.cli.init_env import resolve_init_target

        with self.assertRaises(typer.Exit) as context:
            resolve_init_target(
                env_name="dev",
                config_loader=MagicMock(),
                local=True,
                output_path=Path("custom.toml"),
                force=False,
                dry_run=False,
            )

        self.assertEqual(context.exception.exit_code, 1)

    def test_resolve_init_target_dry_run_skips_environment_checks(self):
        """Test dry-run resolves to stdout without touching the filesystem."""
        from oduit.cli.init_env import resolve_init_target

        mock_loader = MagicMock()

        target = resolve_init_target(
            env_name="dev",
            config_loader=mock_loader,
            local=False,
            output_path=None,
            force=False,
            dry_run=True,
        )

        self.assertIsNone(target)
        mock_loader.get_available_environments.assert_not_called()

    @patch("pathlib.Path.exists", return_value=False)
    def test_resolve_init_target_local_file(self, mock_exists):
        """Test local init target resolves to .oduit.toml."""
        from oduit.cli.init_env import resolve_init_target

        target = resolve_init_target(
            env_name="dev",
            config_loader=MagicMock(),
            local=True,
            output_path=None,
            force=False,
            dry_run=False,
        )

        self.assertIsNotNone(target)
        if target is not None:
            self.assertEqual(target.name, ".oduit.toml")
        mock_exists.assert_called()

    @patch("shutil.which")
    def test_detect_binaries_all_provided(self, mock_which):
        """Test _detect_binaries with all binaries provided."""
        from oduit.cli.init_env import detect_binaries

        python_bin, odoo_bin, coverage_bin = detect_binaries(
            "/usr/bin/python3", "/usr/bin/odoo-bin", "/usr/bin/coverage"
        )

        self.assertEqual(python_bin, "/usr/bin/python3")
        self.assertEqual(odoo_bin, "/usr/bin/odoo-bin")
        self.assertEqual(coverage_bin, "/usr/bin/coverage")
        mock_which.assert_not_called()

    @patch("shutil.which")
    def test_detect_binaries_auto_detect_python3(self, mock_which):
        """Test _detect_binaries auto-detects python3."""
        from oduit.cli.init_env import detect_binaries

        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
            "odoo": "/usr/bin/odoo",
            "coverage": "/usr/bin/coverage",
        }.get(x)

        python_bin, odoo_bin, coverage_bin = detect_binaries(None, None, None)

        self.assertEqual(python_bin, "/usr/bin/python3")
        self.assertEqual(odoo_bin, "/usr/bin/odoo")
        self.assertEqual(coverage_bin, "/usr/bin/coverage")

    @patch("shutil.which")
    def test_detect_binaries_auto_detect_python_fallback(self, mock_which):
        """Test _detect_binaries falls back to python if python3 not found."""
        from oduit.cli.init_env import detect_binaries

        mock_which.side_effect = lambda x: {
            "python": "/usr/bin/python",
            "odoo-bin": "/usr/bin/odoo-bin",
            "coverage": "/usr/bin/coverage",
        }.get(x)

        python_bin, odoo_bin, coverage_bin = detect_binaries(None, None, None)

        self.assertEqual(python_bin, "/usr/bin/python")
        self.assertEqual(odoo_bin, "/usr/bin/odoo-bin")
        self.assertEqual(coverage_bin, "/usr/bin/coverage")

    @patch("shutil.which")
    def test_detect_binaries_python_not_found_exits(self, mock_which):
        """Test _detect_binaries exits if python not found."""
        from oduit.cli.init_env import detect_binaries

        mock_which.return_value = None

        with self.assertRaises(typer.Exit) as context:
            detect_binaries(None, None, None)

        self.assertEqual(context.exception.exit_code, 1)

    @patch("shutil.which")
    def test_detect_binaries_odoo_not_found_continues(self, mock_which):
        """Test _detect_binaries continues if odoo not found."""
        from oduit.cli.init_env import detect_binaries

        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
            "coverage": "/usr/bin/coverage",
        }.get(x)

        python_bin, odoo_bin, coverage_bin = detect_binaries(None, None, None)

        self.assertEqual(python_bin, "/usr/bin/python3")
        self.assertIsNone(odoo_bin)
        self.assertEqual(coverage_bin, "/usr/bin/coverage")

    @patch("shutil.which")
    def test_detect_binaries_coverage_not_found_continues(self, mock_which):
        """Test _detect_binaries continues if coverage not found."""
        from oduit.cli.init_env import detect_binaries

        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
            "odoo": "/usr/bin/odoo",
        }.get(x)

        python_bin, odoo_bin, coverage_bin = detect_binaries(None, None, None)

        self.assertEqual(python_bin, "/usr/bin/python3")
        self.assertEqual(odoo_bin, "/usr/bin/odoo")
        self.assertIsNone(coverage_bin)

    def test_build_initial_config_with_all_binaries(self):
        """Test _build_initial_config with all binaries."""
        from oduit.cli.init_env import build_initial_config

        config = build_initial_config(
            "/usr/bin/python3", "/usr/bin/odoo", "/usr/bin/coverage"
        )

        self.assertEqual(config["python_bin"], "/usr/bin/python3")
        self.assertEqual(config["odoo_bin"], "/usr/bin/odoo")
        self.assertEqual(config["coverage_bin"], "/usr/bin/coverage")
        self.assertFalse(config["write_protect_db"])
        self.assertFalse(config["agent_write_protect_db"])
        self.assertFalse(config["needs_mutation_flag"])
        self.assertFalse(config["agent_needs_mutation_flag"])

    def test_build_initial_config_without_odoo(self):
        """Test _build_initial_config without odoo binary."""
        from oduit.cli.init_env import build_initial_config

        config = build_initial_config("/usr/bin/python3", None, "/usr/bin/coverage")

        self.assertEqual(config["python_bin"], "/usr/bin/python3")
        self.assertNotIn("odoo_bin", config)
        self.assertEqual(config["coverage_bin"], "/usr/bin/coverage")
        self.assertFalse(config["write_protect_db"])
        self.assertFalse(config["agent_write_protect_db"])
        self.assertFalse(config["needs_mutation_flag"])
        self.assertFalse(config["agent_needs_mutation_flag"])

    def test_build_initial_config_without_coverage(self):
        """Test _build_initial_config without coverage binary."""
        from oduit.cli.init_env import build_initial_config

        config = build_initial_config("/usr/bin/python3", "/usr/bin/odoo", None)

        self.assertEqual(config["python_bin"], "/usr/bin/python3")
        self.assertEqual(config["odoo_bin"], "/usr/bin/odoo")
        self.assertIsNone(config["coverage_bin"])
        self.assertFalse(config["write_protect_db"])
        self.assertFalse(config["agent_write_protect_db"])
        self.assertFalse(config["needs_mutation_flag"])
        self.assertFalse(config["agent_needs_mutation_flag"])

    @patch("os.path.exists")
    @patch("oduit.cli.app.ConfigLoader")
    def test_import_or_convert_config_from_conf(
        self, mock_config_loader_class, mock_exists
    ):
        """Test _import_or_convert_config imports from .conf file."""
        from oduit.cli.init_env import import_or_convert_config
        from oduit.config_loader import ImportedOdooConfDetails

        mock_exists.return_value = True
        mock_loader = MagicMock()
        mock_loader.inspect_odoo_conf_import.return_value = ImportedOdooConfDetails(
            config={
                "odoo_params": {"db_name": "test_db"},
                "binaries": {"odoo_bin": "/workspace/odoo-bin"},
            },
            handled_option_keys=("db_name",),
            unknown_option_keys=(),
            odoo_bin_candidates=("/workspace/odoo-bin",),
        )

        env_config = {"python_bin": "/usr/bin/python3"}
        result = import_or_convert_config(
            env_config,
            "/path/to/odoo.conf",
            mock_loader,
            "/usr/bin/python3",
            "/usr/bin/odoo",
            "/usr/bin/coverage",
        )

        mock_loader.inspect_odoo_conf_import.assert_called_once_with(
            "/path/to/odoo.conf", sectioned=True
        )
        self.assertIn("odoo_params", result)
        self.assertIn("binaries", result)
        self.assertEqual(result["binaries"]["python_bin"], "/usr/bin/python3")
        self.assertEqual(result["binaries"]["odoo_bin"], "/workspace/odoo-bin")
        self.assertEqual(result["binaries"]["coverage_bin"], "/usr/bin/coverage")
        self.assertNotIn("python_bin", result)

    @patch("os.path.exists")
    def test_import_or_convert_config_conf_not_found(self, mock_exists):
        """Test _import_or_convert_config exits if .conf file not found."""
        from oduit.cli.init_env import import_or_convert_config

        mock_exists.return_value = False
        mock_loader = MagicMock()

        env_config = {"python_bin": "/usr/bin/python3"}
        with self.assertRaises(typer.Exit) as context:
            import_or_convert_config(
                env_config,
                "/path/to/missing.conf",
                mock_loader,
                "/usr/bin/python3",
                None,
                None,
            )

        self.assertEqual(context.exception.exit_code, 1)

    @patch("os.path.exists")
    @patch("oduit.cli.app.ConfigLoader")
    def test_import_or_convert_config_import_error(
        self, mock_config_loader_class, mock_exists
    ):
        """Test _import_or_convert_config handles import errors."""
        from oduit.cli.init_env import import_or_convert_config

        mock_exists.return_value = True
        mock_loader = MagicMock()
        mock_loader.inspect_odoo_conf_import.side_effect = Exception("Parse error")

        env_config = {"python_bin": "/usr/bin/python3"}
        with self.assertRaises(typer.Exit) as context:
            import_or_convert_config(
                env_config,
                "/path/to/odoo.conf",
                mock_loader,
                "/usr/bin/python3",
                None,
                None,
            )

        self.assertEqual(context.exception.exit_code, 1)

    @patch("os.path.exists")
    def test_import_or_convert_config_requires_explicit_odoo_bin_when_ambiguous(
        self, mock_exists
    ):
        """Test ambiguous odoo-bin discovery asks for an explicit override."""
        from oduit.cli.init_env import import_or_convert_config
        from oduit.config_loader import ImportedOdooConfDetails

        mock_exists.return_value = True
        mock_loader = MagicMock()
        mock_loader.inspect_odoo_conf_import.return_value = ImportedOdooConfDetails(
            config={
                "odoo_params": {"db_name": "test_db"},
                "binaries": {"odoo_bin": "/workspace/odoo-bin"},
            },
            handled_option_keys=("db_name",),
            unknown_option_keys=(),
            odoo_bin_candidates=("/workspace/odoo-bin", "/workspace/odoo/odoo-bin"),
        )

        with self.assertRaises(typer.Exit) as context:
            import_or_convert_config(
                {"python_bin": "/usr/bin/python3"},
                "/path/to/odoo.conf",
                mock_loader,
                "/usr/bin/python3",
                "/usr/bin/odoo",
                "/usr/bin/coverage",
            )

        self.assertEqual(context.exception.exit_code, 1)

    @patch("oduit.config_provider.ConfigProvider")
    def test_import_or_convert_config_no_conf(self, mock_provider_class):
        """Test _import_or_convert_config converts to sectioned format."""
        from oduit.cli.init_env import import_or_convert_config

        mock_provider = MagicMock()
        mock_provider.to_sectioned_dict.return_value = {
            "binaries": {"python_bin": "/usr/bin/python3"},
            "odoo_params": {},
        }
        mock_provider_class.return_value = mock_provider

        env_config = {"python_bin": "/usr/bin/python3"}
        result = import_or_convert_config(
            env_config, None, MagicMock(), "/usr/bin/python3", None, None
        )

        mock_provider_class.assert_called_once_with(env_config)
        mock_provider.to_sectioned_dict.assert_called_once()
        self.assertIn("binaries", result)

    def test_normalize_addons_path_string_to_list(self):
        """Test _normalize_addons_path converts string to list."""
        from oduit.cli.init_env import normalize_addons_path

        env_config = {
            "odoo_params": {"addons_path": "/path/one,/path/two, /path/three"}
        }

        normalize_addons_path(env_config)

        expected = ["/path/one", "/path/two", "/path/three"]
        self.assertEqual(env_config["odoo_params"]["addons_path"], expected)

    def test_normalize_addons_path_already_list(self):
        """Test _normalize_addons_path leaves list unchanged."""
        from oduit.cli.init_env import normalize_addons_path

        env_config = {"odoo_params": {"addons_path": ["/path/one", "/path/two"]}}

        normalize_addons_path(env_config)

        self.assertEqual(
            env_config["odoo_params"]["addons_path"], ["/path/one", "/path/two"]
        )

    def test_normalize_addons_path_no_odoo_params(self):
        """Test _normalize_addons_path handles missing odoo_params."""
        from oduit.cli.init_env import normalize_addons_path

        env_config = {"binaries": {"python_bin": "/usr/bin/python3"}}

        normalize_addons_path(env_config)

        self.assertNotIn("odoo_params", env_config)

    def test_normalize_addons_path_no_addons_path(self):
        """Test _normalize_addons_path handles missing addons_path."""
        from oduit.cli.init_env import normalize_addons_path

        env_config = {"odoo_params": {"db_name": "test"}}

        normalize_addons_path(env_config)

        self.assertNotIn("addons_path", env_config["odoo_params"])

    def test_save_config_file_success(self):
        """Test _save_config_file saves config successfully."""
        from oduit.cli.init_env import save_config_file

        mock_loader = MagicMock()
        mock_tomli_w = MagicMock()
        mock_loader._import_toml_libs.return_value = (None, mock_tomli_w)
        mock_tomli_w.dumps.return_value = (
            '[binaries]\npython_bin = "/usr/bin/python3"\n'
        )

        env_config = {"binaries": {"python_bin": "/usr/bin/python3"}}

        with patch("pathlib.Path.mkdir", autospec=True) as mock_mkdir:
            with patch("pathlib.Path.write_text", autospec=True) as mock_write_text:
                save_config_file("/path/to/config.toml", env_config, mock_loader)

        mock_mkdir.assert_called_once()
        mkdir_args, mkdir_kwargs = mock_mkdir.call_args
        self.assertEqual(Path(mkdir_args[0]).as_posix(), "/path/to")
        self.assertEqual(mkdir_kwargs, {"parents": True, "exist_ok": True})
        mock_tomli_w.dumps.assert_called_once_with(env_config)
        write_args, write_kwargs = mock_write_text.call_args
        self.assertEqual(Path(write_args[0]).as_posix(), "/path/to/config.toml")
        self.assertEqual(
            write_args[1],
            '[binaries]\npython_bin = "/usr/bin/python3"\n',
        )
        self.assertEqual(write_kwargs, {"encoding": "utf-8"})

    def test_save_config_file_no_tomli_w(self):
        """Test _save_config_file exits if tomli_w not available."""
        from oduit.cli.init_env import save_config_file

        mock_loader = MagicMock()
        mock_loader._import_toml_libs.return_value = (None, None)

        env_config = {"binaries": {"python_bin": "/usr/bin/python3"}}

        with patch("pathlib.Path.mkdir", autospec=True) as mock_mkdir:
            with self.assertRaises(typer.Exit) as context:
                save_config_file("/path/to/config.toml", env_config, mock_loader)

        self.assertEqual(context.exception.exit_code, 1)
        mock_mkdir.assert_not_called()

    def test_display_config_summary_full_config(self):
        """Test _display_config_summary displays full config."""
        from oduit.cli.init_env import display_config_summary

        env_config = {
            "binaries": {
                "python_bin": "/usr/bin/python3",
                "odoo_bin": "/usr/bin/odoo",
                "coverage_bin": "/usr/bin/coverage",
            },
            "odoo_params": {
                "db_name": "test_db",
                "write_protect_db": False,
                "agent_write_protect_db": False,
                "needs_mutation_flag": False,
                "agent_needs_mutation_flag": False,
                "addons_path": ["/path/one", "/path/two"],
            },
        }

        display_config_summary(env_config)

    def test_display_config_summary_minimal_config(self):
        """Test _display_config_summary handles minimal config."""
        from oduit.cli.init_env import display_config_summary

        env_config = {"binaries": {"python_bin": "/usr/bin/python3"}}

        display_config_summary(env_config)

    def test_display_config_summary_string_addons_path(self):
        """Test _display_config_summary handles string addons_path."""
        from oduit.cli.init_env import display_config_summary

        env_config = {
            "binaries": {"python_bin": "/usr/bin/python3"},
            "odoo_params": {"addons_path": "/single/path"},
        }

        display_config_summary(env_config)


class TestInitCommand(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()

    @patch("shutil.which")
    @patch("oduit.cli.app.ConfigLoader")
    @patch("oduit.config_provider.ConfigProvider")
    def test_init_command_success(
        self,
        mock_provider_class,
        mock_config_loader_class,
        mock_which,
    ):
        """Test init command creates environment successfully."""
        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = []
        mock_loader.get_config_path.return_value = "/home/user/.config/oduit/dev.toml"
        mock_tomli_w = MagicMock()
        mock_tomli_w.dumps.return_value = (
            '[binaries]\npython_bin = "/usr/bin/python3"\n'
        )
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

        with patch("pathlib.Path.mkdir"):
            with patch("pathlib.Path.write_text"):
                result = self.runner.invoke(app, ["init", "dev"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("created successfully", result.output)

    @patch("shutil.which")
    @patch("oduit.cli.app.ConfigLoader")
    def test_init_command_environment_exists(
        self, mock_config_loader_class, mock_which
    ):
        """Test init command fails if environment already exists."""
        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = ["dev", "prod"]
        mock_loader.get_config_path.return_value = "/home/user/.config/oduit/dev.toml"
        mock_loader.resolve_config_path.return_value = (
            "/home/user/.config/oduit/dev.toml",
            "toml",
        )
        mock_config_loader_class.return_value = mock_loader
        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
            "odoo": "/usr/bin/odoo",
            "coverage": "/usr/bin/coverage",
        }.get(x)

        result = self.runner.invoke(app, ["init", "dev"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("already exists", result.output)

    @patch("os.path.exists")
    @patch("shutil.which")
    @patch("oduit.cli.app.ConfigLoader")
    def test_init_command_from_conf(
        self,
        mock_config_loader_class,
        mock_which,
        mock_exists,
    ):
        """Test init command imports from .conf file."""
        from oduit.config_loader import ImportedOdooConfDetails

        mock_exists.return_value = True
        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = []
        mock_loader.get_config_path.return_value = "/home/user/.config/oduit/dev.toml"
        mock_loader.inspect_odoo_conf_import.return_value = ImportedOdooConfDetails(
            config={
                "odoo_params": {
                    "db_name": "test_db",
                    "config_file": "/etc/odoo.conf",
                    "db_password": "secret",
                },
                "binaries": {"odoo_bin": "/workspace/odoo-bin"},
            },
            handled_option_keys=("db_name", "db_password"),
            unknown_option_keys=("workers_file",),
            odoo_bin_candidates=("/workspace/odoo-bin",),
        )
        mock_tomli_w = MagicMock()
        mock_tomli_w.dumps.return_value = '[odoo_params]\ndb_name = "test_db"\n'
        mock_loader._import_toml_libs.return_value = (None, mock_tomli_w)
        mock_config_loader_class.return_value = mock_loader

        mock_which.side_effect = lambda x: {
            "python3": "/usr/bin/python3",
        }.get(x)

        with patch("pathlib.Path.mkdir"):
            with patch("pathlib.Path.write_text"):
                result = self.runner.invoke(
                    app, ["init", "dev", "--from-conf", "/etc/odoo.conf"]
                )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Imported configuration", result.output)
        self.assertIn("Converted 2 known options.", result.output)
        self.assertIn("workers_file", result.output)
        self.assertIn("may contain database or SMTP credentials", result.output)

    @patch("shutil.which")
    @patch("oduit.cli.app.ConfigLoader")
    def test_init_command_custom_binaries(self, mock_config_loader_class, mock_which):
        """Test init command with custom binary paths."""
        mock_loader = MagicMock()
        mock_loader.get_available_environments.return_value = []
        mock_loader.get_config_path.return_value = "/home/user/.config/oduit/dev.toml"
        mock_tomli_w = MagicMock()
        mock_tomli_w.dumps.return_value = '[binaries]\npython_bin = "/custom/python"\n'
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

            with patch("pathlib.Path.mkdir"):
                with patch("pathlib.Path.write_text"):
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

    @patch("oduit.cli.app.ConfigLoader")
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

    @patch("shutil.which")
    @patch("oduit.cli.app.ConfigLoader")
    @patch("oduit.config_provider.ConfigProvider")
    def test_init_command_dry_run_outputs_toml_without_writing(
        self,
        mock_provider_class,
        mock_config_loader_class,
        mock_which,
    ):
        """Test --dry-run prints TOML and skips writing/availability checks."""
        mock_loader = MagicMock()
        mock_tomli_w = MagicMock()
        mock_tomli_w.dumps.return_value = (
            '[binaries]\npython_bin = "/usr/bin/python3"\n'
        )
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

        with patch("pathlib.Path.write_text") as mock_write_text:
            result = self.runner.invoke(app, ["init", "dev", "--dry-run"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("[binaries]", result.output)
        self.assertNotIn("Configuration saved to", result.output)
        mock_loader.get_available_environments.assert_not_called()
        mock_write_text.assert_not_called()

    @patch("shutil.which")
    @patch("oduit.cli.app.ConfigLoader")
    @patch("oduit.config_provider.ConfigProvider")
    def test_init_command_rejects_local_and_output_together(
        self,
        mock_provider_class,
        mock_config_loader_class,
        mock_which,
    ):
        """Test --local and --output are mutually exclusive at the CLI."""
        mock_loader = MagicMock()
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

        result = self.runner.invoke(
            app,
            [
                "init",
                "dev",
                "--local",
                "--output",
                "./custom.toml",
            ],
        )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Use either --local or --output, not both.", result.output)


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
