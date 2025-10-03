# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import unittest

from oduit.builders import ConfigProvider, DatabaseCommandBuilder
from oduit.exceptions import ConfigError


class TestConfigProvider(unittest.TestCase):
    def test_validate_keys(self):
        """Test the validate_keys method."""
        # Test with all required keys present
        env_config = {"key1": "value1", "key2": "value2", "key3": "value3"}
        config_provider = ConfigProvider(env_config)
        required_keys = ["key1", "key2"]
        command_name = "test command"

        # Should not raise an error
        config_provider.validate_keys(required_keys, command_name)

        # Test with missing keys
        env_config = {"key1": "value1"}
        config_provider = ConfigProvider(env_config)
        required_keys = ["key1", "key2", "key3"]
        command_name = "test command"

        with self.assertRaises(ConfigError) as context:
            config_provider.validate_keys(required_keys, command_name)

        error_message = str(context.exception)
        self.assertIn("Missing required configuration for test command", error_message)
        self.assertIn("key2, key3", error_message)

        # Test with empty string values (should be considered missing)
        env_config = {"key1": "value1", "key2": "", "key3": "value3"}
        config_provider = ConfigProvider(env_config)
        required_keys = ["key1", "key2"]
        command_name = "test command"

        with self.assertRaises(ConfigError) as context:
            config_provider.validate_keys(required_keys, command_name)

        error_message = str(context.exception)
        self.assertIn("Missing required configuration for test command", error_message)
        self.assertIn("key2", error_message)


class TestDatabaseCommandBuilder(unittest.TestCase):
    def test_build_drop_command(self):
        """Test the build_drop_command method."""
        env_config = {
            "db_name": "test_db",
        }

        config_provider = ConfigProvider(env_config)
        builder = DatabaseCommandBuilder(config_provider, with_sudo=True)
        result = builder.drop_command().build()

        expected = [
            "sudo",
            "-S",
            "su",
            "-",
            "postgres",
            "-c",
            'dropdb --if-exists "test_db"',
        ]
        self.assertEqual(result, expected)

        # Test with missing configuration
        with self.assertRaises(ConfigError):
            bad_config_provider = ConfigProvider({})
            DatabaseCommandBuilder(bad_config_provider)

        builder = DatabaseCommandBuilder(config_provider, with_sudo=False)
        result = builder.drop_command().build()

        expected = ["dropdb", "--if-exists", "test_db"]
        self.assertEqual(result, expected)

    def test_build_create_command(self):
        """Test the build_create_command method."""
        env_config = {
            "db_name": "test_db",
            "db_user": "test_user",
        }

        config_provider = ConfigProvider(env_config)
        builder = DatabaseCommandBuilder(config_provider)
        result = builder.create_command().build()

        expected = [
            "sudo",
            "-S",
            "su",
            "-",
            "postgres",
            "-c",
            'createdb -O "test_user" "test_db"',
        ]
        self.assertEqual(result, expected)

        # Test with only db_name (should not raise, should not include -O)
        env_config_no_user = {"db_name": "test_db"}
        config_provider_no_user = ConfigProvider(env_config_no_user)
        builder_no_user = DatabaseCommandBuilder(config_provider_no_user)
        result_no_user = builder_no_user.create_command().build()

        expected_no_user = [
            "sudo",
            "-S",
            "su",
            "-",
            "postgres",
            "-c",
            'createdb "test_db"',
        ]
        self.assertEqual(result_no_user, expected_no_user)

    def test_create_build_role_command(self):
        """Test the build_role_command method."""
        env_config = {
            "db_name": "test_db",
            "db_user": "test_user",
        }

        config_provider = ConfigProvider(env_config)
        builder = DatabaseCommandBuilder(config_provider)
        result = builder.create_role_command().build()

        expected = [
            "sudo",
            "-S",
            "su",
            "-",
            "postgres",
            "-c",
            'psql -c "CREATE ROLE \\"test_user\\"";',
        ]
        self.assertEqual(result, expected)

    def test_build_list_db_command(self):
        """Test the list_db_command method."""
        env_config = {
            "db_name": "test_db",
            "db_user": "test_user",
        }

        config_provider = ConfigProvider(env_config)
        builder = DatabaseCommandBuilder(config_provider, with_sudo=True)
        result = builder.list_db_command().build()

        expected = [
            "sudo",
            "-S",
            "su",
            "-",
            "postgres",
            "-c",
            'psql -l -U "test_user"',
        ]
        self.assertEqual(result, expected)

        builder = DatabaseCommandBuilder(config_provider, with_sudo=False)
        result = builder.list_db_command().build()

        expected = ["psql", "-l", "-U", "test_user"]
        self.assertEqual(result, expected)

        builder = DatabaseCommandBuilder(config_provider, with_sudo=True)
        result = builder.list_db_command(db_user="custom_user").build()

        expected = [
            "sudo",
            "-S",
            "su",
            "-",
            "postgres",
            "-c",
            'psql -l -U "custom_user"',
        ]
        self.assertEqual(result, expected)


class TestOdooOperations(unittest.TestCase):
    def test_parse_install_results_unmet_dependencies(self):
        """Test parsing install results with unmet dependencies error."""
        from oduit.operation_result import OperationResult

        # Test the exact error from the user's example
        output = (
            "2025-09-10 08:04:38,822 65826 INFO test_db_17_itcos2 "
            "odoo.modules.graph: module fastapi_reseller: "
            "Unmet dependencies: ti4health_shopify\n"
            "2025-09-10 08:04:38,822 65826 INFO test_db_17_itcos2 "
            "odoo.modules.loading: loading 88 modules...\n"
            "2025-09-10 08:04:39,605 65826 INFO test_db_17_itcos2 "
            "odoo.modules.loading: 88 modules loaded in 0.78s, 0 queries (+0 extra)\n"
            "2025-09-10 08:04:39,773 65826 ERROR test_db_17_itcos2 "
            "odoo.modules.loading: Some modules are not loaded, some dependencies "
            "or manifest may be missing: ['fastapi_reseller']"
        )

        result_builder = OperationResult("install")
        result = result_builder._parse_install_results(output)

        self.assertFalse(result["success"])
        self.assertEqual(result["total_modules"], 88)
        self.assertEqual(result["modules_loaded"], 88)
        self.assertEqual(len(result["unmet_dependencies"]), 1)
        self.assertEqual(result["unmet_dependencies"][0]["module"], "fastapi_reseller")
        self.assertEqual(
            result["unmet_dependencies"][0]["dependencies"], ["ti4health_shopify"]
        )
        self.assertEqual(result["failed_modules"], ["fastapi_reseller"])
        self.assertIn(
            "Module 'fastapi_reseller' has unmet dependencies: ti4health_shopify",
            result["dependency_errors"],
        )
        self.assertIn(
            "odoo.modules.loading: Some modules are not loaded, some dependencies "
            "or manifest may be missing: ['fastapi_reseller']",
            result["error_messages"],
        )

    def test_parse_install_results_multiple_unmet_dependencies(self):
        """Test parsing install results with multiple unmet dependencies."""
        from oduit.operation_result import OperationResult

        output = (
            "INFO test_db odoo.modules.graph: module module_a: "
            "Unmet dependencies: dep1, dep2\n"
            "INFO test_db odoo.modules.graph: module module_b: "
            "Unmet dependencies: dep3\n"
            "INFO test_db odoo.modules.loading: loading 50 modules...\n"
            "INFO test_db odoo.modules.loading: 48 modules loaded in 1.23s\n"
            "ERROR test_db odoo.modules.loading: Some modules are not loaded, some "
            "dependencies or manifest may be missing: ['module_a', 'module_b']"
        )

        result_builder = OperationResult("install")
        result = result_builder._parse_install_results(output)

        self.assertFalse(result["success"])
        self.assertEqual(result["total_modules"], 50)
        self.assertEqual(result["modules_loaded"], 48)
        self.assertEqual(len(result["unmet_dependencies"]), 2)
        self.assertEqual(result["unmet_dependencies"][0]["module"], "module_a")
        self.assertEqual(
            result["unmet_dependencies"][0]["dependencies"], ["dep1", "dep2"]
        )
        self.assertEqual(result["unmet_dependencies"][1]["module"], "module_b")
        self.assertEqual(result["unmet_dependencies"][1]["dependencies"], ["dep3"])
        self.assertEqual(set(result["failed_modules"]), {"module_a", "module_b"})
        self.assertEqual(len(result["dependency_errors"]), 2)

    def test_parse_install_results_success(self):
        """Test parsing install results with successful installation."""
        from oduit.operation_result import OperationResult

        output = """INFO test_db odoo.modules.loading: loading 45 modules...
INFO test_db odoo.modules.loading: 45 modules loaded in 2.34s, 0 queries (+0 extra)
INFO test_db odoo.modules.loading: Modules loaded."""

        result_builder = OperationResult("install")
        result = result_builder._parse_install_results(output)

        self.assertTrue(result["success"])
        self.assertEqual(result["total_modules"], 45)
        self.assertEqual(result["modules_loaded"], 45)
        self.assertEqual(len(result["unmet_dependencies"]), 0)
        self.assertEqual(len(result["failed_modules"]), 0)
        self.assertEqual(len(result["dependency_errors"]), 0)
        self.assertEqual(len(result["error_messages"]), 0)

    def test_parse_install_results_empty_output(self):
        """Test parsing install results with empty output."""
        from oduit.operation_result import OperationResult

        result_builder = OperationResult("install")
        result_builder._parse_install_results("")

        # For empty output, default values should be set
        parsed = result_builder._parse_install_results("")
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["total_modules"], 0)
        self.assertEqual(parsed["modules_loaded"], 0)
        self.assertEqual(len(parsed["unmet_dependencies"]), 0)
        self.assertEqual(len(parsed["failed_modules"]), 0)
        self.assertEqual(len(parsed["dependency_errors"]), 0)
        self.assertEqual(len(parsed["error_messages"]), 0)

    def test_parse_install_results_general_errors(self):
        """Test parsing install results with general error messages."""
        from oduit.operation_result import OperationResult

        output = """INFO test_db odoo.modules.loading: loading 25 modules...
ERROR test_db odoo.modules.loading: Failed to install module test_module
ERROR test_db odoo.addons.test_module: Configuration error in manifest
INFO test_db odoo.modules.loading: 24 modules loaded in 1.45s"""

        result_builder = OperationResult("install")
        result = result_builder._parse_install_results(output)

        self.assertFalse(result["success"])
        self.assertEqual(result["total_modules"], 25)
        self.assertEqual(result["modules_loaded"], 24)
        self.assertEqual(len(result["error_messages"]), 2)
        self.assertIn(
            "ERROR test_db odoo.modules.loading: Failed to install module test_module",
            result["error_messages"],
        )
        self.assertIn(
            "ERROR test_db odoo.addons.test_module: Configuration error in manifest",
            result["error_messages"],
        )


if __name__ == "__main__":
    unittest.main()
