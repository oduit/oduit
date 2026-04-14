# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import tempfile
import unittest
from unittest.mock import MagicMock, mock_open, patch

from oduit.config_loader import ConfigLoader


class TestConfigLoader(unittest.TestCase):
    @patch("os.path.expanduser")
    def test_get_config_path(self, mock_expanduser):
        """Test get_config_path function."""
        mock_expanduser.return_value = "/mocked/home/.config/oduit"
        config_loader = ConfigLoader()

        # Test YAML path (default)
        result = config_loader.get_config_path("test")
        expected = os.path.join("/mocked/home/.config/oduit", "test.yaml")
        self.assertEqual(result, expected)

        # Test TOML path
        result = config_loader.get_config_path("test", "toml")
        expected = os.path.join("/mocked/home/.config/oduit", "test.toml")
        self.assertEqual(result, expected)

        mock_expanduser.assert_called_with("~/.config/oduit")

    @patch("builtins.open", new_callable=mock_open)
    @patch("yaml.safe_load")
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_load_yaml_config(self, mock_expanduser, mock_exists, mock_yaml, mock_file):
        """Test load_config function with YAML file."""
        mock_expanduser.return_value = "/mocked/home/.config/oduit"

        def exists_side_effect(path):
            return path.endswith("test.yaml")

        mock_exists.side_effect = exists_side_effect

        config_dict = {
            "python_bin": "/usr/bin/python3",
            "addons_path": ["/path1", "/path2"],
        }
        mock_yaml.return_value = config_dict

        config_loader = ConfigLoader()
        result = config_loader.load_config("test")

        self.assertEqual(result["python_bin"], "/usr/bin/python3")
        self.assertEqual(result["addons_path"], "/path1,/path2")

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=b'python_bin = "/usr/bin/python3"\n'
        b'addons_path = ["/path1", "/path2"]',
    )
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_load_toml_config(self, mock_expanduser, mock_exists, mock_file):
        """Test load_config function with TOML file."""
        mock_expanduser.return_value = "/mocked/home/.config/oduit"

        def exists_side_effect(path):
            return path.endswith("test.toml")

        mock_exists.side_effect = exists_side_effect

        # Mock the TOML library import
        with patch.object(ConfigLoader, "_import_toml_libs") as mock_import:
            mock_tomllib = MagicMock()
            mock_tomllib.load.return_value = {
                "python_bin": "/usr/bin/python3",
                "addons_path": ["/path1", "/path2"],
            }
            mock_import.return_value = (mock_tomllib, None)

            config_loader = ConfigLoader()
            result = config_loader.load_config("test")

            self.assertEqual(result["python_bin"], "/usr/bin/python3")
            self.assertEqual(result["addons_path"], "/path1,/path2")

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=(
            b'[binaries]\npython_bin = "/usr/bin/python3"\n'
            b'[odoo_params]\naddons_path = ["/path1", "/path2"]\n'
            b"allow_uninstall = true\n"
        ),
    )
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_load_toml_sectioned_config_preserves_runtime_db_policy_keys(
        self, mock_expanduser, mock_exists, mock_file
    ):
        """Test load_config normalizes sectioned TOML and keeps safety keys."""
        mock_expanduser.return_value = "/mocked/home/.config/oduit"

        def exists_side_effect(path):
            return path.endswith("test.toml")

        mock_exists.side_effect = exists_side_effect

        with patch.object(ConfigLoader, "_import_toml_libs") as mock_import:
            mock_tomllib = MagicMock()
            mock_tomllib.load.return_value = {
                "binaries": {"python_bin": "/usr/bin/python3"},
                "odoo_params": {
                    "addons_path": ["/path1", "/path2"],
                    "allow_uninstall": True,
                    "write_protect_db": True,
                    "agent_write_protect_db": True,
                    "needs_mutation_flag": True,
                    "agent_needs_mutation_flag": True,
                },
            }
            mock_import.return_value = (mock_tomllib, None)

            config_loader = ConfigLoader()
            result = config_loader.load_config("test")

        self.assertEqual(result["python_bin"], "/usr/bin/python3")
        self.assertEqual(result["addons_path"], "/path1,/path2")
        self.assertTrue(result["allow_uninstall"])
        self.assertTrue(result["write_protect_db"])
        self.assertTrue(result["agent_write_protect_db"])
        self.assertTrue(result["needs_mutation_flag"])
        self.assertTrue(result["agent_needs_mutation_flag"])

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=(
            b'[binaries]\npython_bin = "/usr/bin/python3"\n'
            b'[odoo_params]\naddons_path = ["/path1", "/path2"]\n'
            b"allow_uninstall = true\n"
        ),
    )
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_load_config_details_reports_sectioned_shape(
        self, mock_expanduser, mock_exists, mock_file
    ):
        """Test load_config_details exposes canonical shape metadata."""
        mock_expanduser.return_value = "/mocked/home/.config/oduit"

        def exists_side_effect(path):
            return path.endswith("test.toml")

        mock_exists.side_effect = exists_side_effect

        with patch.object(ConfigLoader, "_import_toml_libs") as mock_import:
            mock_tomllib = MagicMock()
            mock_tomllib.load.return_value = {
                "binaries": {"python_bin": "/usr/bin/python3"},
                "odoo_params": {
                    "addons_path": ["/path1", "/path2"],
                    "allow_uninstall": True,
                    "write_protect_db": True,
                    "agent_write_protect_db": True,
                },
            }
            mock_import.return_value = (mock_tomllib, None)

            details = ConfigLoader().load_config_details("test")

        self.assertEqual(details.raw_shape, "sectioned")
        self.assertEqual(details.normalized_shape, "sectioned")
        self.assertEqual(details.shape_version, "1.0")
        self.assertEqual(details.config["addons_path"], "/path1,/path2")
        self.assertEqual(
            details.canonical_config["odoo_params"]["addons_path"], "/path1,/path2"
        )
        self.assertTrue(details.canonical_config["odoo_params"]["write_protect_db"])
        self.assertTrue(
            details.canonical_config["odoo_params"]["agent_write_protect_db"]
        )
        self.assertEqual(details.deprecation_warnings, ())

    @patch("builtins.open", new_callable=mock_open)
    @patch("yaml.safe_load")
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_load_config_details_warns_for_legacy_flat_shape(
        self, mock_expanduser, mock_exists, mock_yaml, mock_file
    ):
        """Test load_config_details marks flat configs as deprecated."""
        mock_expanduser.return_value = "/mocked/home/.config/oduit"

        def exists_side_effect(path):
            return path.endswith("test.yaml")

        mock_exists.side_effect = exists_side_effect
        mock_yaml.return_value = {
            "python_bin": "/usr/bin/python3",
            "addons_path": ["/path1", "/path2"],
            "db_name": "test_db",
        }

        details = ConfigLoader().load_config_details("test")

        self.assertEqual(details.raw_shape, "legacy_flat")
        self.assertEqual(details.format_type, "yaml")
        self.assertEqual(len(details.deprecation_warnings), 1)
        self.assertIn(
            "Legacy flat config keys are deprecated", details.deprecation_warnings[0]
        )

    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_load_config_file_not_found(self, mock_expanduser, mock_exists):
        """Test load_config when file doesn't exist."""
        mock_expanduser.return_value = "/mocked/home/.config/oduit"
        mock_exists.return_value = False

        config_loader = ConfigLoader()
        with self.assertRaises(FileNotFoundError) as context:
            config_loader.load_config("test")

        self.assertIn("Configuration file not found", str(context.exception))

    def test_get_available_environments(self):
        """Test get_available_environments with custom config_dir."""
        # Use a temporary directory for testing
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test config files including both YAML and TOML
            test_files = ["env1.yaml", "env2.toml", "env3.yaml", "not_config.txt"]
            for file in test_files:
                with open(os.path.join(temp_dir, file), "w") as f:
                    f.write(
                        "test: config" if file.endswith(".yaml") else 'test = "config"'
                    )

            config_loader = ConfigLoader(config_dir=temp_dir)
            environments = config_loader.get_available_environments()

            self.assertEqual(sorted(environments), ["env1", "env2", "env3"])

    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_detect_config_format(self, mock_expanduser, mock_exists):
        """Test _detect_config_format method."""
        mock_expanduser.return_value = "/mocked/home/.config/oduit"

        def exists_side_effect(path):
            if path.endswith("toml_env.toml"):
                return True
            elif path.endswith("yaml_env.yaml"):
                return True
            return False

        mock_exists.side_effect = exists_side_effect

        config_loader = ConfigLoader()

        # Test TOML file detection
        path, format_type = config_loader._detect_config_format("toml_env")
        self.assertTrue(path.endswith("toml_env.toml"))
        self.assertEqual(format_type, "toml")

        # Test YAML file detection
        path, format_type = config_loader._detect_config_format("yaml_env")
        self.assertTrue(path.endswith("yaml_env.yaml"))
        self.assertEqual(format_type, "yaml")

        # Test fallback to YAML when no file exists
        path, format_type = config_loader._detect_config_format("nonexistent")
        self.assertTrue(path.endswith("nonexistent.yaml"))
        self.assertEqual(format_type, "yaml")

    @patch("os.path.exists")
    def test_has_local_config(self, mock_exists):
        """Test has_local_config function."""
        mock_exists.return_value = True
        config_loader = ConfigLoader()

        result = config_loader.has_local_config()
        self.assertTrue(result)
        mock_exists.assert_called_once_with(".oduit.toml")

        # Test when file doesn't exist
        mock_exists.return_value = False
        result = config_loader.has_local_config()
        self.assertFalse(result)

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=b'python_bin = "/usr/bin/python3"\n'
        b'addons_path = ["/path1", "/path2"]',
    )
    @patch("os.path.exists")
    def test_load_local_config(self, mock_exists, mock_file):
        """Test load_local_config function."""
        mock_exists.return_value = True

        # Mock the TOML library import
        with patch.object(ConfigLoader, "_import_toml_libs") as mock_import:
            mock_tomllib = MagicMock()
            mock_tomllib.load.return_value = {
                "python_bin": "/usr/bin/python3",
                "addons_path": ["/path1", "/path2"],
            }
            mock_import.return_value = (mock_tomllib, None)

            config_loader = ConfigLoader()
            result = config_loader.load_local_config()

            self.assertEqual(result["python_bin"], "/usr/bin/python3")
            self.assertEqual(result["addons_path"], "/path1,/path2")
            mock_exists.assert_called_once_with(".oduit.toml")

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=(
            b'[binaries]\npython_bin = "/usr/bin/python3"\n'
            b'[odoo_params]\naddons_path = ["/path1", "/path2"]\n'
            b"allow_uninstall = true\n"
        ),
    )
    @patch("os.path.exists")
    def test_load_local_sectioned_config_preserves_runtime_db_policy_keys(
        self, mock_exists, mock_file
    ):
        """Test load_local_config keeps safety keys in sectioned TOML."""
        mock_exists.return_value = True

        with patch.object(ConfigLoader, "_import_toml_libs") as mock_import:
            mock_tomllib = MagicMock()
            mock_tomllib.load.return_value = {
                "binaries": {"python_bin": "/usr/bin/python3"},
                "odoo_params": {
                    "addons_path": ["/path1", "/path2"],
                    "allow_uninstall": True,
                    "needs_mutation_flag": True,
                    "agent_needs_mutation_flag": True,
                },
            }
            mock_import.return_value = (mock_tomllib, None)

            config_loader = ConfigLoader()
            result = config_loader.load_local_config()

        self.assertEqual(result["addons_path"], "/path1,/path2")
        self.assertTrue(result["allow_uninstall"])
        self.assertTrue(result["needs_mutation_flag"])
        self.assertTrue(result["agent_needs_mutation_flag"])

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=(
            b'[binaries]\npython_bin = "/usr/bin/python3"\n'
            b'[odoo_params]\naddons_path = ["/path1", "/path2"]\n'
            b'db_risk_level = "prod"\n'
        ),
    )
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_load_config_rejects_legacy_db_risk_level(
        self, mock_expanduser, mock_exists, mock_file
    ):
        """Test legacy db_risk_level fails fast during config load."""
        mock_expanduser.return_value = "/mocked/home/.config/oduit"
        mock_exists.side_effect = lambda path: path.endswith("test.toml")

        with patch.object(ConfigLoader, "_import_toml_libs") as mock_import:
            mock_tomllib = MagicMock()
            mock_tomllib.load.return_value = {
                "binaries": {"python_bin": "/usr/bin/python3"},
                "odoo_params": {
                    "addons_path": ["/path1", "/path2"],
                    "db_risk_level": "prod",
                },
            }
            mock_import.return_value = (mock_tomllib, None)

            with self.assertRaisesRegex(Exception, "db_risk_level"):
                ConfigLoader().load_config("test")

    def test_local_config_integration(self):
        """Test local config functionality with real file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change to temp directory
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)

                # Create a local config file
                with open(".oduit.toml", "w") as f:
                    f.write("""
python_bin = "/usr/bin/python3"
odoo_bin = "/path/to/odoo-bin"
config_file = "/path/to/config.conf"
addons_path = ["/path1", "/path2"]
db_name = "test_db"
""")

                config_loader = ConfigLoader()

                # Test has_local_config
                self.assertTrue(config_loader.has_local_config())

                # Test load_local_config (will only work if tomli is available)
                try:
                    config = config_loader.load_local_config()
                    self.assertEqual(config["python_bin"], "/usr/bin/python3")
                    self.assertEqual(config["addons_path"], "/path1,/path2")
                except SystemExit:
                    # Skip if TOML libraries not available
                    pass

            finally:
                os.chdir(original_cwd)


if __name__ == "__main__":
    unittest.main()
