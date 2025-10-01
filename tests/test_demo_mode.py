# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import unittest

from oduit.config_loader import ConfigLoader
from oduit.demo_process_manager import DEMO_MODULES, DemoProcessManager
from oduit.odoo_operations import OdooOperations


class TestDemoMode(unittest.TestCase):
    """Test demo mode functionality"""

    def test_load_demo_config(self):
        """Test that load_demo_config returns valid demo configuration"""
        config_loader = ConfigLoader()
        config = config_loader.load_demo_config()

        # Check required keys
        self.assertIn("demo_mode", config)
        self.assertTrue(config["demo_mode"])
        self.assertIn("available_modules", config)
        self.assertIn("python_bin", config)
        self.assertIn("odoo_bin", config)
        self.assertIn("db_name", config)

        # Check demo modules are present
        modules = config["available_modules"]
        self.assertIn("module_ok", modules)
        self.assertIn("module_error", modules)
        self.assertIn("module_warning", modules)

    def test_demo_process_manager(self):
        """Test DemoProcessManager functionality"""
        manager = DemoProcessManager()

        # Test successful module operation
        cmd = ["python", "odoo-bin", "-u", "module_ok"]
        result = manager.run_command(cmd)
        self.assertTrue(result["success"])
        self.assertEqual(result["return_code"], 0)
        # Check that the output contains log-style content
        self.assertIn("odoo", result["output"])

        # Test failing module operation
        cmd = ["python", "odoo-bin", "-u", "module_error"]
        result = manager.run_command(cmd)
        self.assertFalse(result["success"])
        self.assertEqual(result["return_code"], 1)

        # Test unknown module operation
        cmd = ["python", "odoo-bin", "-u", "unknown_module"]
        result = manager.run_command(cmd)
        self.assertFalse(result["success"])
        self.assertIn("invalid module names, ignored", result["output"])

    def test_demo_operations_integration(self):
        """Test OdooOperations with demo mode"""
        config_loader = ConfigLoader()
        config = config_loader.load_demo_config()
        ops = OdooOperations(config)

        # Test module update in demo mode
        result = ops.update_module("module_ok", suppress_output=True)
        self.assertTrue(result["success"])
        self.assertEqual(result["module"], "module_ok")
        self.assertIsNotNone(result["duration"])

        # Test module installation in demo mode
        result = ops.install_module("sale", suppress_output=True)
        self.assertTrue(result["success"])
        self.assertEqual(result["module"], "sale")

        # Test database creation in demo mode
        result = ops.create_db(suppress_output=True)
        self.assertTrue(result["success"])
        self.assertEqual(result["database"], "demo_db")

    def test_demo_modules_catalog(self):
        """Test the demo modules catalog"""
        # Verify catalog structure
        self.assertIn("module_ok", DEMO_MODULES)
        self.assertIn("module_error", DEMO_MODULES)
        self.assertIn("module_warning", DEMO_MODULES)

        # Check module_ok configuration
        module_ok = DEMO_MODULES["module_ok"]
        self.assertEqual(module_ok["status"], "success")
        self.assertIn("install_time", module_ok)
        self.assertIn("log_stream", module_ok)

        # Check module_error configuration
        module_error = DEMO_MODULES["module_error"]
        self.assertEqual(module_error["status"], "error")
        self.assertIn("stderr", module_error)
        self.assertIn("log_stream", module_error)

    def test_demo_vs_real_mode_detection(self):
        """Test that demo mode is properly detected"""
        config_loader = ConfigLoader()
        demo_config = config_loader.load_demo_config()
        ops = OdooOperations(demo_config)

        # Test that demo process manager is used
        process_manager = ops.process_manager
        self.assertIsInstance(process_manager, DemoProcessManager)

        # Test that regular process manager is used for non-demo config
        regular_config = {"demo_mode": False}
        ops = OdooOperations(regular_config)
        process_manager = ops.process_manager
        self.assertNotIsInstance(process_manager, DemoProcessManager)

    def test_fastapi_reseller_dependency_error(self):
        """Test fastapi_reseller module with unmet dependencies in demo mode"""
        config_loader = ConfigLoader()
        config = config_loader.load_demo_config()
        ops = OdooOperations(config)

        # Test installing fastapi_reseller which has unmet dependencies
        result = ops.install_module("fastapi_reseller", suppress_output=True)

        # Should fail due to unmet dependencies
        self.assertFalse(result["success"])
        self.assertEqual(result["module"], "fastapi_reseller")

        # Check that parsing detected the dependency error
        self.assertIn("unmet_dependencies", result)
        self.assertGreater(len(result["unmet_dependencies"]), 0)

        # Verify the specific dependency is captured
        deps = result["unmet_dependencies"][0]
        self.assertEqual(deps["module"], "fastapi_reseller")
        self.assertIn("ti4health_shopify", deps["dependencies"])

        # Check failed modules list
        self.assertIn("failed_modules", result)
        self.assertIn("fastapi_reseller", result["failed_modules"])

        # Check dependency error messages
        self.assertIn("dependency_errors", result)
        self.assertGreater(len(result["dependency_errors"]), 0)
        dependency_error = result["dependency_errors"][0]
        self.assertIn("fastapi_reseller", dependency_error)
        self.assertIn("ti4health_shopify", dependency_error)


if __name__ == "__main__":
    unittest.main()
