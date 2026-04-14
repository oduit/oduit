# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import unittest

from oduit.config_provider import ConfigProvider


class TestConfigProvider(unittest.TestCase):
    def test_get_odoo_params_list_basic(self):
        """Test get_odoo_params_list with basic parameters."""
        config = {
            "db_name": "test",
            "addons_path": "/path/to/addons",
            "http_port": "8069",
        }

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        expected = [
            "--database=test",
            "--addons-path=/path/to/addons",
            "--http-port=8069",
        ]

        self.assertEqual(sorted(params_list), sorted(expected))

    def test_get_odoo_params_list_with_underscores(self):
        """Test get_odoo_params_list converts underscores to hyphens."""
        config = {"db_name": "test", "log_level": "info", "workers": "4"}

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        expected = ["--database=test", "--log-level=info", "--workers=4"]

        self.assertEqual(sorted(params_list), sorted(expected))

    def test_get_odoo_params_list_with_boolean_true(self):
        """Test get_odoo_params_list with boolean True values."""
        config = {"db_name": "test", "dev": True, "test_enable": True}

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        expected = ["--database=test", "--dev", "--test-enable"]

        self.assertEqual(sorted(params_list), sorted(expected))

    def test_get_odoo_params_list_with_boolean_false(self):
        """Test get_odoo_params_list ignores boolean False values."""
        config = {"db_name": "test", "dev": False, "test_enable": True}

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        expected = ["--database=test", "--test-enable"]

        self.assertEqual(sorted(params_list), sorted(expected))

    def test_get_odoo_params_list_with_none_and_empty_values(self):
        """Test get_odoo_params_list ignores None and empty string values."""
        config = {
            "db_name": "test",
            "empty_param": "",
            "none_param": None,
            "whitespace_param": "   ",
            "valid_param": "value",
        }

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        expected = ["--database=test", "--valid-param=value"]

        self.assertEqual(sorted(params_list), sorted(expected))

    def test_get_odoo_params_list_sectioned_format(self):
        """Test get_odoo_params_list with sectioned configuration format."""
        config = {
            "binaries": {
                "python_bin": "/usr/bin/python3",
                "odoo_bin": "/path/to/odoo-bin",
            },
            "odoo_params": {
                "db_name": "test",
                "addons_path": "/path/to/addons",
                "dev": True,
            },
        }

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        expected = ["--database=test", "--addons-path=/path/to/addons", "--dev"]

        self.assertEqual(sorted(params_list), sorted(expected))

    def test_get_odoo_params_list_mixed_types(self):
        """Test get_odoo_params_list with mixed value types."""
        config = {
            "db_name": "test",
            "workers": 4,  # integer
            "timeout": 30.5,  # float
            "dev": True,  # boolean
            "log_level": "info",  # string
        }

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        expected = [
            "--database=test",
            "--workers=4",
            "--timeout=30.5",
            "--dev",
            "--log-level=info",
        ]

        self.assertEqual(sorted(params_list), sorted(expected))

    def test_get_odoo_params_list_empty_config(self):
        """Test get_odoo_params_list with empty configuration."""
        config = {}

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        self.assertEqual(params_list, [])

    def test_get_odoo_params_list_only_binaries(self):
        """Test get_odoo_params_list when config only contains binaries."""
        config = {
            "python_bin": "/usr/bin/python3",
            "odoo_bin": "/path/to/odoo-bin",
            "coverage_bin": "/usr/bin/coverage",
        }

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        # Should be empty since these are binaries, not odoo params
        self.assertEqual(params_list, [])

    def test_get_odoo_params_list_odoo_config_compatibility(self):
        """Test get_odoo_params_list generates Odoo-compatible parameter names.

        This test verifies that the output format is compatible with
        odoo.tools.config.parse_config() by checking key mappings that
        differ from simple underscore-to-hyphen conversion.
        """
        config = {
            "db_name": "test_db",
            "db_host": "localhost",
            "db_port": 5432,
            "db_user": "odoo",
            "db_password": "admin",
            "db_sslmode": "prefer",
            "db_maxconn": 64,
            "db_template": "template0",
            "addons_path": "/path/to/addons",
            "upgrade_path": "/path/to/upgrades",
            "server_wide_modules": "base,web",
            "data_dir": "/var/lib/odoo",
            "http_interface": "127.0.0.1",
            "http_port": 8069,
            "gevent_port": 8072,
            "proxy_mode": True,
            "test_enable": True,
            "test_tags": "standard",
            "log_level": "info",
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "smtp_ssl": True,
            "translate_out": "/tmp/i18n.po",
            "load_language": "fr_FR",
            "list_db": False,
        }

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list([])

        expected_mappings = {
            "--database=test_db",
            "--db_host=localhost",
            "--db_port=5432",
            "--db_user=odoo",
            "--db_password=admin",
            "--db_sslmode=prefer",
            "--db_maxconn=64",
            "--db-template=template0",
            "--addons-path=/path/to/addons",
            "--upgrade-path=/path/to/upgrades",
            "--load=base,web",
            "--data-dir=/var/lib/odoo",
            "--http-interface=127.0.0.1",
            "--http-port=8069",
            "--gevent-port=8072",
            "--proxy-mode",
            "--test-enable",
            "--test-tags=standard",
            "--log-level=info",
            "--smtp=smtp.example.com",
            "--smtp-port=587",
            "--smtp-ssl",
            "--i18n-export=/tmp/i18n.po",
            "--load-language=fr_FR",
        }

        self.assertEqual(set(params_list), expected_mappings)

        self.assertIn("--database=test_db", params_list)
        self.assertNotIn("--db-name=test_db", params_list)
        self.assertNotIn("--db_name=test_db", params_list)

        self.assertIn("--load=base,web", params_list)
        self.assertNotIn("--server-wide-modules=base,web", params_list)

        self.assertIn("--smtp=smtp.example.com", params_list)
        self.assertNotIn("--smtp-server=smtp.example.com", params_list)

        self.assertIn("--db_host=localhost", params_list)
        self.assertIn("--db_port=5432", params_list)
        self.assertIn("--db_user=odoo", params_list)
        self.assertIn("--db_password=admin", params_list)
        self.assertIn("--db_sslmode=prefer", params_list)
        self.assertIn("--db_maxconn=64", params_list)
        self.assertNotIn("--db-sslmode=prefer", params_list)
        self.assertNotIn("--db-maxconn=64", params_list)

    def test_get_odoo_params_list_skip_keys(self):
        """Test get_odoo_params_list with skip_keys parameter."""
        config = {
            "db_name": "test_db",
            "addons_path": "/path/to/addons",
            "http_port": 8069,
            "workers": 4,
            "log_level": "info",
            "dev": True,
        }

        provider = ConfigProvider(config)
        params_list = provider.get_odoo_params_list(["workers", "log_level"])

        expected = [
            "--database=test_db",
            "--addons-path=/path/to/addons",
            "--http-port=8069",
            "--dev",
        ]

        self.assertEqual(sorted(params_list), sorted(expected))
        self.assertNotIn("--workers=4", params_list)
        self.assertNotIn("--log-level=info", params_list)

    def test_get_optional_allow_uninstall_defaults_false(self):
        """Test get_optional returns the provided default for missing keys."""
        provider = ConfigProvider({"addons_path": "/path/to/addons"})

        self.assertFalse(provider.get_optional("allow_uninstall", False))

    def test_get_optional_allow_uninstall_from_sectioned_config(self):
        """Test get_optional finds allow_uninstall in sectioned odoo_params."""
        provider = ConfigProvider(
            {
                "binaries": {"python_bin": "/usr/bin/python3"},
                "odoo_params": {
                    "addons_path": "/path/to/addons",
                    "allow_uninstall": True,
                },
            }
        )

        self.assertTrue(provider.get_optional("allow_uninstall", False))

    def test_get_odoo_params_list_skips_internal_policy_keys(self):
        """Test config-only policy keys are not rendered as Odoo CLI args."""
        provider = ConfigProvider(
            {
                "db_name": "test_db",
                "allow_uninstall": True,
                "write_protect_db": True,
                "agent_write_protect_db": True,
                "needs_mutation_flag": True,
                "agent_needs_mutation_flag": True,
            }
        )

        params_list = provider.get_odoo_params_list([])

        self.assertEqual(params_list, ["--database=test_db"])
        self.assertNotIn("--allow-uninstall", params_list)
        self.assertNotIn("--write-protect-db", params_list)
        self.assertNotIn("--agent-write-protect-db", params_list)
        self.assertNotIn("--needs-mutation-flag", params_list)
        self.assertNotIn("--agent-needs-mutation-flag", params_list)

    def test_to_sectioned_dict_preserves_runtime_db_policy_keys(self):
        """Test canonical export keeps explicit DB policy keys in odoo_params."""
        provider = ConfigProvider(
            {
                "python_bin": "/usr/bin/python3",
                "db_name": "test_db",
                "write_protect_db": True,
                "agent_write_protect_db": True,
                "needs_mutation_flag": True,
                "agent_needs_mutation_flag": True,
            }
        )

        result = provider.to_sectioned_dict()

        self.assertEqual(result["binaries"]["python_bin"], "/usr/bin/python3")
        self.assertEqual(result["odoo_params"]["db_name"], "test_db")
        self.assertTrue(result["odoo_params"]["write_protect_db"])
        self.assertTrue(result["odoo_params"]["agent_write_protect_db"])
        self.assertTrue(result["odoo_params"]["needs_mutation_flag"])
        self.assertTrue(result["odoo_params"]["agent_needs_mutation_flag"])

    def test_get_optional_runtime_db_policy_keys(self):
        """Test get_optional exposes explicit runtime DB policy flags."""
        provider = ConfigProvider(
            {
                "odoo_params": {
                    "write_protect_db": True,
                    "agent_write_protect_db": True,
                    "needs_mutation_flag": True,
                    "agent_needs_mutation_flag": True,
                }
            }
        )

        self.assertTrue(provider.get_optional("write_protect_db"))
        self.assertTrue(provider.get_optional("agent_write_protect_db"))
        self.assertTrue(provider.get_optional("needs_mutation_flag"))
        self.assertTrue(provider.get_optional("agent_needs_mutation_flag"))


if __name__ == "__main__":
    unittest.main()
