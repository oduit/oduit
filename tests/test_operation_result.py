# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import time
import unittest
from datetime import datetime

from oduit.operation_result import OperationResult
from oduit.utils import output_result_to_json


class TestOperationResult(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.result_builder = OperationResult("test_operation", module="test_module")

    def test_init_basic(self):
        """Test basic initialization of OperationResult"""
        builder = OperationResult("install", module="my_module", database="test_db")

        self.assertEqual(builder.result["operation"], "install")
        self.assertEqual(builder.result["module"], "my_module")
        self.assertEqual(builder.result["database"], "test_db")
        self.assertFalse(builder.result["success"])
        self.assertIsNone(builder.result["return_code"])
        self.assertEqual(builder.result["command"], [])
        self.assertEqual(builder.result["stdout"], "")
        self.assertEqual(builder.result["stderr"], "")

    def test_set_success(self):
        """Test setting success status"""
        builder = OperationResult("test")

        # Test success with default return code
        builder.set_success(True)
        self.assertTrue(builder.result["success"])
        self.assertEqual(builder.result["return_code"], 0)

        # Test failure with custom return code
        builder.set_success(False, 1)
        self.assertFalse(builder.result["success"])
        self.assertEqual(builder.result["return_code"], 1)

    def test_set_command(self):
        """Test setting command"""
        builder = OperationResult("test")
        cmd = ["python", "script.py", "--arg"]

        builder.set_command(cmd)
        self.assertEqual(builder.result["command"], cmd)

    def test_set_output(self):
        """Test setting output"""
        builder = OperationResult("test")

        builder.set_output("stdout content", "stderr content")
        self.assertEqual(builder.result["stdout"], "stdout content")
        self.assertEqual(builder.result["stderr"], "stderr content")

    def test_set_error(self):
        """Test setting error"""
        builder = OperationResult("test")

        builder.set_error("Test error", "TestError")
        self.assertEqual(builder.result["error"], "Test error")
        self.assertEqual(builder.result["error_type"], "TestError")
        self.assertFalse(builder.result["success"])

    def test_set_custom_data(self):
        """Test setting custom data"""
        builder = OperationResult("test")

        builder.set_custom_data(
            test_count=5, custom_flag=True, extra_info="additional data"
        )

        self.assertEqual(builder.result["test_count"], 5)
        self.assertEqual(builder.result["custom_flag"], True)
        self.assertEqual(builder.result["extra_info"], "additional data")

    def test_to_json_output_basic(self):
        """Test basic to_json_output functionality"""
        builder = OperationResult("install", module="my_module")
        builder.set_success(True, 0)
        builder.set_command(["odoo-bin", "-i", "my_module"])
        builder.set_output("Installation complete", "")

        json_output = output_result_to_json(builder.finalize())

        # Check core fields are present
        self.assertEqual(json_output["operation"], "install")
        self.assertEqual(json_output["module"], "my_module")
        self.assertTrue(json_output["success"])
        self.assertEqual(json_output["return_code"], 0)
        self.assertEqual(json_output["command"], ["odoo-bin", "-i", "my_module"])
        self.assertEqual(json_output["stdout"], "Installation complete")

        # Check null values are excluded by default
        self.assertNotIn("stderr", json_output)  # Empty string should be excluded
        self.assertNotIn("database", json_output)  # None should be excluded
        self.assertNotIn("error", json_output)  # None should be excluded

    def test_to_json_output_with_additional_fields(self):
        """Test to_json_output with additional fields"""
        builder = OperationResult("test", module="test_module")
        builder.set_success(True, 0)

        additional_fields = {"verbose": True, "no_http": False, "custom_param": "value"}

        json_output = output_result_to_json(
            builder.finalize(), additional_fields=additional_fields
        )

        self.assertEqual(json_output["verbose"], True)
        self.assertEqual(json_output["no_http"], False)
        self.assertEqual(json_output["custom_param"], "value")

    def test_to_json_output_with_exclude_fields(self):
        """Test to_json_output with excluded fields"""
        builder = OperationResult("test", module="test_module")
        builder.set_success(True, 0)
        builder.set_output("stdout", "stderr")

        exclude_fields = ["stdout", "module"]
        json_output = output_result_to_json(
            builder.finalize(), exclude_fields=exclude_fields
        )
        self.assertNotIn("stdout", json_output)
        self.assertNotIn("module", json_output)
        self.assertIn("stderr", json_output)  # Should still be present

    def test_to_json_output_include_null_values(self):
        """Test to_json_output with null values included"""
        builder = OperationResult("test", module="test_module")
        builder.set_success(True, 0)

        json_output = output_result_to_json(
            builder.finalize(), include_null_values=True
        )
        # Null values should be present
        self.assertIn("database", json_output)
        self.assertIsNone(json_output["database"])
        self.assertIn("error", json_output)
        self.assertIsNone(json_output["error"])

    def test_to_json_output_meaningful_empty_fields(self):
        """Test that meaningful empty fields are preserved"""
        builder = OperationResult("test")
        builder.set_success(True, 0)
        builder.set_custom_data(
            failures=[],
            unmet_dependencies=[],
            failed_modules=[],
            addons=[],
            empty_list=[],  # This should be removed
        )

        json_output = output_result_to_json(builder.finalize())
        # Meaningful empty fields should be preserved
        self.assertIn("failures", json_output)
        self.assertEqual(json_output["failures"], [])
        self.assertIn("unmet_dependencies", json_output)
        self.assertEqual(json_output["unmet_dependencies"], [])

        # Non-meaningful empty fields should be removed
        self.assertNotIn("empty_list", json_output)

    def test_to_json_output_with_test_data(self):
        """Test to_json_output with test-specific data"""
        builder = OperationResult("test", module="test_module")
        builder.set_success(False, 1)
        builder.set_custom_data(
            total_tests=10,
            passed_tests=7,
            failed_tests=2,
            error_tests=1,
            failures=[
                {
                    "test_name": "TestCase.test_method",
                    "error_message": "AssertionError: Test failed",
                    "file": "/path/to/test.py",
                    "line": 42,
                }
            ],
        )

        json_output = output_result_to_json(
            builder.finalize(),
            additional_fields={"verbose": True, "stop_on_error": False},
        )
        # Test statistics should be present
        self.assertEqual(json_output["total_tests"], 10)
        self.assertEqual(json_output["passed_tests"], 7)
        self.assertEqual(json_output["failed_tests"], 2)
        self.assertEqual(json_output["error_tests"], 1)
        self.assertEqual(len(json_output["failures"]), 1)
        self.assertEqual(
            json_output["failures"][0]["test_name"], "TestCase.test_method"
        )

        # Additional fields should be present
        self.assertTrue(json_output["verbose"])
        self.assertFalse(json_output["stop_on_error"])

    def test_to_json_output_with_install_data(self):
        """Test to_json_output with install-specific data"""
        builder = OperationResult("install", module="my_module")
        builder.set_success(False, 1)
        builder.set_error("Installation failed", "InstallationError")
        builder.set_custom_data(
            modules_loaded=3,
            total_modules=5,
            unmet_dependencies=[
                {
                    "module": "my_module",
                    "dependencies": ["missing_dep1", "missing_dep2"],
                }
            ],
            dependency_errors=[
                "Module 'my_module' has unmet dependencies: missing_dep1, missing_dep2"
            ],
        )

        json_output = output_result_to_json(
            builder.finalize(),
            additional_fields={"without_demo": True},
        )

        # Install-specific data should be present
        self.assertEqual(json_output["modules_loaded"], 3)
        self.assertEqual(json_output["total_modules"], 5)
        self.assertEqual(len(json_output["unmet_dependencies"]), 1)
        self.assertEqual(len(json_output["dependency_errors"]), 1)
        self.assertTrue(json_output["without_demo"])

        # Error information should be present
        self.assertEqual(json_output["error"], "Installation failed")
        self.assertEqual(json_output["error_type"], "InstallationError")

    def test_to_json_output_timing(self):
        """Test that timing information is included"""
        builder = OperationResult("test")
        builder.set_success(True, 0)

        # Simulate some operation time
        time.sleep(0.01)

        json_output = output_result_to_json(
            builder.finalize(),
        )

        # Duration should be present and positive
        self.assertIn("duration", json_output)
        self.assertGreater(json_output["duration"], 0)

        # Timestamp should be present and valid ISO format
        self.assertIn("timestamp", json_output)
        # Should be able to parse the timestamp
        datetime.fromisoformat(json_output["timestamp"])

    def test_to_json_output_empty_stdout_stderr_handling(self):
        """Test that empty stdout/stderr are properly handled"""
        builder = OperationResult("test")
        builder.set_success(True, 0)

        # Test with empty strings
        builder.set_output("", "")
        json_output = output_result_to_json(
            builder.finalize(),
        )

        self.assertNotIn("stdout", json_output)
        self.assertNotIn("stderr", json_output)

        # Test with actual content
        builder.set_output("actual output", "actual error")
        json_output = output_result_to_json(
            builder.finalize(),
        )

        self.assertIn("stdout", json_output)
        self.assertIn("stderr", json_output)
        self.assertEqual(json_output["stdout"], "actual output")
        self.assertEqual(json_output["stderr"], "actual error")

    def test_to_json_output_preserves_original_result(self):
        """Test that to_json_output doesn't modify the original result"""
        builder = OperationResult("test", module="test_module")
        builder.set_success(True, 0)
        builder.set_custom_data(test_data="original")

        # Call to_json_output with modifications
        json_output = output_result_to_json(
            builder.finalize(),
            additional_fields={"new_field": "new_value"},
            exclude_fields=["module"],
        )

        # Original result should be unchanged
        self.assertEqual(builder.result["test_data"], "original")
        self.assertNotIn("new_field", builder.result)

        # JSON output should have modifications
        self.assertEqual(json_output["new_field"], "new_value")
        self.assertNotIn("module", json_output)


if __name__ == "__main__":
    unittest.main()
