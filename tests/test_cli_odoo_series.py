# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import unittest
from unittest.mock import MagicMock, patch

from manifestoo_core.odoo_series import OdooSeries
from typer.testing import CliRunner

from oduit.cli_typer import app, create_global_config
from oduit.cli_types import GlobalConfig


class TestOdooSeriesOption(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
        self.mock_config = {
            "db_name": "test_db",
            "addons_path": "/test/addons",
            "odoo_bin": "/usr/bin/odoo-bin",
        }

    @patch("oduit.cli_typer.configure_output")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_create_global_config_with_odoo_series(
        self, mock_config_loader_class, mock_configure
    ):
        """Test creating global config with explicit odoo_series."""
        mock_config = {"db_name": "test_db", "addons_path": "/test/addons"}
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        result = create_global_config(
            env="dev", verbose=True, odoo_series=OdooSeries.v16_0
        )

        self.assertIsInstance(result, GlobalConfig)
        self.assertEqual(result.env, "dev")
        self.assertEqual(result.odoo_series, OdooSeries.v16_0)
        self.assertEqual(result.env_config, mock_config)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_tree_with_odoo_series_option(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends --tree with --odoo-series option."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        mock_manager_instance = MagicMock()
        mock_manifest = MagicMock()
        mock_manifest.version = "1.0.0"
        mock_manager_instance.get_manifest.return_value = mock_manifest
        mock_manager_instance.get_dependency_tree.return_value = {
            "my_module": {"base": {}}
        }
        mock_manager_instance.detect_odoo_series.return_value = OdooSeries.v16_0
        mock_manager_instance.is_core_ce_addon.return_value = True
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app,
            [
                "--env",
                "dev",
                "--odoo-series",
                "16.0",
                "list-depends",
                "my_module",
                "--tree",
            ],
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.get_dependency_tree.assert_called_once_with(
            "my_module", max_depth=None
        )
        self.assertIn("my_module", result.output)

    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_tree_without_odoo_series_option(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends --tree without --odoo-series (auto-detect)."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        mock_manager_instance = MagicMock()
        mock_manifest = MagicMock()
        mock_manifest.version = "1.0.0"
        mock_manager_instance.get_manifest.return_value = mock_manifest
        mock_manager_instance.get_dependency_tree.return_value = {
            "my_module": {"base": {}}
        }
        mock_manager_instance.detect_odoo_series.return_value = OdooSeries.v17_0
        mock_manager_instance.is_core_ce_addon.return_value = True
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "my_module", "--tree"]
        )

        self.assertEqual(result.exit_code, 0)
        mock_manager_instance.detect_odoo_series.assert_called_once()
        self.assertIn("my_module", result.output)

    @patch.dict("os.environ", {"ODOO_VERSION": "15.0"})
    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_tree_with_odoo_version_envvar(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends --tree with ODOO_VERSION environment variable."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        mock_manager_instance = MagicMock()
        mock_manifest = MagicMock()
        mock_manifest.version = "1.0.0"
        mock_manager_instance.get_manifest.return_value = mock_manifest
        mock_manager_instance.get_dependency_tree.return_value = {
            "my_module": {"base": {}}
        }
        mock_manager_instance.is_core_ce_addon.return_value = True
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "my_module", "--tree"]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("my_module", result.output)

    @patch.dict("os.environ", {"ODOO_SERIES": "14.0"})
    @patch("oduit.cli_typer.ModuleManager")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_list_depends_tree_with_odoo_series_envvar(
        self, mock_config_loader_class, mock_module_manager
    ):
        """Test list-depends --tree with ODOO_SERIES environment variable."""
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_config.return_value = self.mock_config
        mock_config_loader_class.return_value = mock_loader_instance

        mock_manager_instance = MagicMock()
        mock_manifest = MagicMock()
        mock_manifest.version = "1.0.0"
        mock_manager_instance.get_manifest.return_value = mock_manifest
        mock_manager_instance.get_dependency_tree.return_value = {
            "my_module": {"base": {}}
        }
        mock_manager_instance.is_core_ce_addon.return_value = True
        mock_module_manager.return_value = mock_manager_instance

        result = self.runner.invoke(
            app, ["--env", "dev", "list-depends", "my_module", "--tree"]
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("my_module", result.output)


if __name__ == "__main__":
    unittest.main()
