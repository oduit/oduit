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

    def test_parse_install_results_successful_installation(self):
        """Test parsing successful module installation output"""
        builder = OperationResult("install", module="test_module")
        output = """
2024-01-01 10:00:00,000 1234 INFO ? odoo: loading 5 modules...
2024-01-01 10:00:01,000 1234 INFO ? odoo: 5 modules loaded in 1.2s
"""
        result = builder._parse_install_results(output)

        self.assertTrue(result["success"])
        self.assertEqual(result["total_modules"], 5)
        self.assertEqual(result["modules_loaded"], 5)
        self.assertEqual(result["unmet_dependencies"], [])
        self.assertEqual(result["failed_modules"], [])

    def test_parse_install_results_unmet_dependencies(self):
        """Test parsing installation output with unmet dependencies"""
        builder = OperationResult("install", module="my_module")
        builder.set_custom_data(modules=["my_module"])
        output = """
2024-01-01 10:00:00,000 1234 INFO ? odoo.modules.loading: loading 3 modules...
2024-01-01 10:00:01,000 1234 WARNING ? odoo.modules.loading: module my_module: Unmet dependencies: dep1, dep2
2024-01-01 10:00:02,000 1234 INFO ? odoo: 2 modules loaded in 0.5s
"""
        result = builder._parse_install_results(output)

        self.assertFalse(result["success"])
        self.assertEqual(len(result["unmet_dependencies"]), 1)
        self.assertEqual(result["unmet_dependencies"][0]["module"], "my_module")
        self.assertEqual(
            result["unmet_dependencies"][0]["dependencies"], ["dep1", "dep2"]
        )
        self.assertIn(
            "Module 'my_module' has unmet dependencies", result["dependency_errors"][0]
        )

    def test_parse_install_results_failed_modules(self):
        """Test parsing installation output with failed modules"""
        builder = OperationResult("install", module="test_module")
        builder.set_custom_data(modules=["test_module"])
        output = """
2024-01-01 10:00:00,000 1234 INFO ? odoo.modules.loading: loading 5 modules...
2024-01-01 10:00:01,000 1234 ERROR ? odoo.modules.loading: Some modules are not loaded, some dependencies or manifest may be missing: ['test_module', 'other_module']
2024-01-01 10:00:02,000 1234 INFO ? odoo: 3 modules loaded in 0.8s
"""
        result = builder._parse_install_results(output)

        self.assertFalse(result["success"])
        self.assertIn("test_module", result["failed_modules"])
        self.assertIn("other_module", result["failed_modules"])

    def test_parse_install_results_general_errors(self):
        """Test parsing installation output with general errors"""
        builder = OperationResult("install", module="test_module")
        builder.set_custom_data(modules=[])
        output = """
2024-01-01 10:00:00,000 1234 ERROR ? odoo.modules.loading: Some modules are not loaded, some dependencies or manifest may be missing: ['unrelated_module']
"""
        result = builder._parse_install_results(output)

        self.assertFalse(result["success"])
        self.assertGreater(len(result["error_messages"]), 0)

    def test_parse_install_results_target_module_not_in_failed_list(self):
        """Test that success is True when target module is not in failed list"""
        builder = OperationResult("install", module="my_module")
        builder.set_custom_data(modules=["my_module"])
        output = """
2024-01-01 10:00:00,000 1234 ERROR ? odoo.modules.loading: Some modules are not loaded, some dependencies or manifest may be missing: ['other_module', 'another_module']
2024-01-01 10:00:02,000 1234 INFO ? odoo: 3 modules loaded in 0.8s
"""
        result = builder._parse_install_results(output)

        self.assertTrue(result["success"])
        self.assertIn("other_module", result["failed_modules"])
        self.assertIn("another_module", result["failed_modules"])

    def test_parse_test_results_successful_tests(self):
        """Test parsing successful test output"""
        builder = OperationResult("test", module="test_module")
        output = """
2024-01-01 10:00:00,000 1234 INFO test_module odoo.modules.loading: test_module: 10 tests 2.5s 150 queries
2024-01-01 10:00:02,500 1234 INFO test_module odoo.modules.loading: 0 failed, 0 error(s) of 10 tests
"""
        result = builder._parse_test_results(output)

        self.assertEqual(result["total_tests"], 10)
        self.assertEqual(result["passed_tests"], 10)
        self.assertEqual(result["failed_tests"], 0)
        self.assertEqual(result["error_tests"], 0)
        self.assertEqual(len(result["failures"]), 0)

    def test_parse_test_results_with_failures(self):
        """Test parsing test output with failures"""
        builder = OperationResult("test", module="test_module")
        output = """
2024-01-01 10:00:00,000 1234 INFO test_module odoo.modules.loading: test_module: 10 tests 2.5s 150 queries
2024-01-01 10:00:02,500 1234 ERROR test_module odoo.modules.loading: FAIL: TestCase.test_method
2024-01-01 10:00:02,501 1234 ERROR test_module File "/path/to/test.py", line 42, in test_method
2024-01-01 10:00:02,502 1234 ERROR test_module AssertionError: Expected 5, got 3
2024-01-01 10:00:02,503 1234 INFO test_module odoo.modules.loading: 1 failed, 0 error(s) of 10 tests
"""
        result = builder._parse_test_results(output)

        self.assertEqual(result["total_tests"], 10)
        self.assertEqual(result["passed_tests"], 9)
        self.assertEqual(result["failed_tests"], 1)
        self.assertEqual(result["error_tests"], 0)
        self.assertEqual(len(result["failures"]), 1)
        self.assertEqual(result["failures"][0]["test_name"], "TestCase.test_method")
        self.assertEqual(result["failures"][0]["file"], "/path/to/test.py")
        self.assertEqual(result["failures"][0]["line"], 42)
        self.assertIn("AssertionError", result["failures"][0]["error_message"])

    def test_parse_test_results_with_errors(self):
        """Test parsing test output with errors"""
        builder = OperationResult("test", module="test_module")
        output = """
2024-01-01 10:00:00,000 1234 INFO test_module odoo.modules.loading: test_module: 8 tests 1.8s 120 queries
2024-01-01 10:00:01,800 1234 INFO test_module odoo.modules.loading: 0 failed, 2 error(s) of 8 tests
"""
        result = builder._parse_test_results(output)

        self.assertEqual(result["total_tests"], 8)
        self.assertEqual(result["passed_tests"], 6)
        self.assertEqual(result["failed_tests"], 0)
        self.assertEqual(result["error_tests"], 2)

    def test_check_for_failure_patterns_invalid_module_names(self):
        """Test failure pattern detection for invalid module names"""
        builder = OperationResult("install", module="bad_module")
        builder.set_custom_data(modules=["bad_module"])
        output = (
            "odoo.modules.loading: invalid module names, ignored: bad_module, other_bad"
        )

        has_failure, msg = builder._check_for_failure_patterns(output, "install")

        self.assertTrue(has_failure)
        self.assertIsNotNone(msg)
        if msg:
            self.assertIn("invalid module names", msg)

    def test_check_for_failure_patterns_module_not_found(self):
        """Test failure pattern detection for ModuleNotFoundError"""
        builder = OperationResult("install", module="my_module")
        builder.set_custom_data(modules=["my_module"])
        output = "ModuleNotFoundError: No module named 'some_dependency'"

        has_failure, msg = builder._check_for_failure_patterns(output, "install")

        self.assertTrue(has_failure)
        self.assertIsNotNone(msg)
        if msg:
            self.assertIn("ModuleNotFoundError", msg)

    def test_check_for_failure_patterns_no_failure(self):
        """Test failure pattern detection with successful output"""
        builder = OperationResult("install", module="my_module")
        builder.set_custom_data(modules=["my_module"])
        output = """
2024-01-01 10:00:00,000 1234 INFO ? odoo: loading 5 modules...
2024-01-01 10:00:01,000 1234 INFO ? odoo: 5 modules loaded in 1.2s
"""

        has_failure, msg = builder._check_for_failure_patterns(output, "install")

        self.assertFalse(has_failure)
        self.assertIsNone(msg)

    def test_check_for_module_warnings_invalid_module(self):
        """Test module warning detection"""
        builder = OperationResult("install", module="bad_module")
        output = "invalid module names, ignored: bad_module, other_module"

        warning = builder._check_for_module_warnings(output, "bad_module")

        self.assertIsNotNone(warning)
        if warning:
            self.assertIn("invalid module names", warning)

    def test_check_for_module_warnings_no_warning(self):
        """Test module warning detection with clean output"""
        builder = OperationResult("install", module="good_module")
        output = "2024-01-01 10:00:00,000 1234 INFO ? odoo: 5 modules loaded in 1.2s"

        warning = builder._check_for_module_warnings(output, "good_module")

        self.assertIsNone(warning)

    def test_handle_process_result_success(self):
        """Test handling successful process result"""
        builder = OperationResult("install", module="test_module")
        process_result = {
            "return_code": 0,
            "output": "Installation successful",
            "stdout": "Installation successful",
            "stderr": "",
        }

        builder.handle_process_result(process_result)

        self.assertEqual(builder.result["return_code"], 0)
        self.assertEqual(builder.result["stdout"], "Installation successful")

    def test_handle_process_result_with_failure_pattern(self):
        """Test handling process result with failure patterns"""
        builder = OperationResult("install", module="bad_module")
        builder.set_custom_data(modules=["bad_module"])
        process_result = {
            "return_code": 0,
            "output": "odoo.modules.loading: invalid module names, ignored: bad_module",
            "stdout": "odoo.modules.loading: invalid module names, ignored: bad_module",
            "stderr": "",
        }

        builder.handle_process_result(process_result)

        self.assertFalse(builder.result["success"])
        self.assertIsNotNone(builder.result["error"])

    def test_handle_process_result_with_module_warning(self):
        """Test handling process result with module warnings"""
        builder = OperationResult("install", module="test_module")
        builder.set_success(True)
        process_result = {
            "return_code": 0,
            "output": "invalid module names, ignored: test_module",
            "stdout": "invalid module names, ignored: test_module",
            "stderr": "",
        }

        builder.handle_process_result(
            process_result, check_module_warnings=True, module="test_module"
        )

        self.assertFalse(builder.result["success"])
        self.assertIsNotNone(builder.result["error"])

    def test_handle_process_result_none(self):
        """Test handling None process result"""
        builder = OperationResult("install", module="test_module")

        builder.handle_process_result(None)

        self.assertFalse(builder.result["success"])
        self.assertEqual(builder.result["error"], "Process execution failed")
        self.assertEqual(builder.result["error_type"], "ProcessError")

    def test_parse_and_merge_install_results(self):
        """Test parsing and merging install results"""
        builder = OperationResult("install", module="test_module")
        builder.set_custom_data(modules=["test_module"], custom_field="value")
        output = """
2024-01-01 10:00:00,000 1234 INFO ? odoo.modules.loading: loading 5 modules...
2024-01-01 10:00:01,000 1234 INFO ? odoo: 5 modules loaded in 1.2s
"""

        builder.parse_and_merge_install_results(output, extra_data="additional")

        self.assertEqual(builder.result["modules_loaded"], 5)
        self.assertEqual(builder.result["total_modules"], 5)
        self.assertEqual(builder.result["custom_field"], "value")
        self.assertEqual(builder.result["extra_data"], "additional")

    def test_parse_and_merge_test_results(self):
        """Test parsing and merging test results"""
        builder = OperationResult("test", module="test_module")
        builder.set_custom_data(modules=["test_module"], verbose=True)
        output = """
2024-01-01 10:00:00,000 1234 INFO test_module odoo.modules.loading: test_module: 10 tests 2.5s 150 queries
2024-01-01 10:00:02,500 1234 INFO test_module odoo.modules.loading: 0 failed, 0 error(s) of 10 tests
"""

        builder.parse_and_merge_test_results(output, test_tags=["tag1"])

        self.assertEqual(builder.result["total_tests"], 10)
        self.assertEqual(builder.result["passed_tests"], 10)
        self.assertTrue(builder.result["verbose"])
        self.assertEqual(builder.result["test_tags"], ["tag1"])

    def test_process_with_parsers_install(self):
        """Test process_with_parsers for install operation"""
        builder = OperationResult("install", module="test_module")
        builder.set_custom_data(
            operation_type="install",
            result_parsers=["install"],
            modules=["test_module"],
        )
        output = """
2024-01-01 10:00:00,000 1234 INFO ? odoo.modules.loading: loading 3 modules...
2024-01-01 10:00:01,000 1234 INFO ? odoo: 3 modules loaded in 0.8s
"""

        builder.process_with_parsers(output)

        self.assertTrue(builder.result["success"])
        self.assertEqual(builder.result["modules_loaded"], 3)

    def test_process_with_parsers_test(self):
        """Test process_with_parsers for test operation"""
        builder = OperationResult("test", module="test_module")
        builder.set_custom_data(
            operation_type="test", result_parsers=["test"], modules=["test_module"]
        )
        output = """
2024-01-01 10:00:00,000 1234 INFO test_module odoo.modules.loading: test_module: 5 tests 1.0s 50 queries
2024-01-01 10:00:01,000 1234 INFO test_module odoo.modules.loading: 0 failed, 0 error(s) of 5 tests
"""

        builder.process_with_parsers(output)

        self.assertTrue(builder.result["success"])
        self.assertEqual(builder.result["total_tests"], 5)

    def test_process_with_parsers_with_failure_patterns(self):
        """Test process_with_parsers detects failure patterns"""
        builder = OperationResult("install", module="bad_module")
        builder.set_custom_data(
            operation_type="install", result_parsers=["install"], modules=["bad_module"]
        )
        output = "odoo.modules.loading: invalid module names, ignored: bad_module"

        builder.process_with_parsers(output)

        self.assertFalse(builder.result["success"])
        self.assertIsNotNone(builder.result["error"])

    def test_set_new_operation(self):
        """Test resetting operation"""
        builder = OperationResult("install", module="module1", database="db1")
        builder.set_success(True, 0)
        builder.set_custom_data(custom_field="value")

        builder.set_new_operation("test")

        self.assertEqual(builder.result["operation"], "test")
        self.assertFalse(builder.result["success"])
        self.assertIsNone(builder.result["return_code"])
        self.assertIsNone(builder.result["module"])
        self.assertIsNone(builder.result["database"])
        self.assertNotIn("custom_field", builder.result)

    def test_set_operation(self):
        """Test setting operation"""
        builder = OperationResult("install")
        builder.set_operation("update")

        self.assertEqual(builder.result["operation"], "update")

    def test_set_module(self):
        """Test setting module"""
        builder = OperationResult("install")
        builder.set_module("new_module")

        self.assertEqual(builder.result["module"], "new_module")

    def test_set_database(self):
        """Test setting database"""
        builder = OperationResult("install")
        builder.set_database("test_db")

        self.assertEqual(builder.result["database"], "test_db")

    def test_set_addon_name(self):
        """Test setting addon name"""
        builder = OperationResult("install")
        builder.set_addon_name("my_addon")

        self.assertEqual(builder.result["addon_name"], "my_addon")

    def test_set_addons(self):
        """Test setting addons list"""
        builder = OperationResult("install")
        addons = ["addon1", "addon2", "addon3"]
        builder.set_addons(addons)

        self.assertEqual(builder.result["addons"], addons)

    def test_finalize(self):
        """Test finalize method"""
        builder = OperationResult("install", module="test_module")
        builder.set_success(True, 0)

        time.sleep(0.01)
        result = builder.finalize()

        self.assertIn("duration", result)
        self.assertGreater(result["duration"], 0)
        self.assertIn("timestamp", result)

    def test_merge_parsed_results_preserves_custom_data(self):
        """Test that _merge_parsed_results preserves existing custom data"""
        builder = OperationResult("install", module="test_module")
        builder.set_custom_data(custom_field="original", other_field="keep")

        parsed_results = {
            "modules_loaded": 5,
            "total_modules": 5,
            "success": True,
        }

        builder._merge_parsed_results(parsed_results, new_field="added")

        self.assertEqual(builder.result["custom_field"], "original")
        self.assertEqual(builder.result["other_field"], "keep")
        self.assertEqual(builder.result["modules_loaded"], 5)
        self.assertEqual(builder.result["new_field"], "added")

    def test_merge_parsed_results_install_failure_logic(self):
        """Test _merge_parsed_results handles install failures"""
        builder = OperationResult("install", module="test_module")
        builder.set_custom_data(modules=["test_module"])

        parsed_results = {
            "success": False,
            "dependency_errors": ["Module 'test_module' has unmet dependencies: dep1"],
        }

        builder._merge_parsed_results(parsed_results)

        self.assertFalse(builder.result["success"])
        self.assertIn("Module installation failed", builder.result["error"])

    def test_merge_parsed_results_test_failure_logic(self):
        """Test _merge_parsed_results handles test failures"""
        builder = OperationResult("test", module="test_module")

        parsed_results = {
            "total_tests": 10,
            "failed_tests": 2,
            "error_tests": 1,
            "passed_tests": 7,
        }

        builder._merge_parsed_results(parsed_results)

        self.assertFalse(builder.result["success"])
        self.assertIn("Tests failed", builder.result["error"])
        self.assertEqual(builder.result["error_type"], "TestFailure")

    def test_core_fields_not_overridden_by_custom_data(self):
        """Test that set_custom_data doesn't override core fields"""
        builder = OperationResult("install", module="test_module")
        builder.set_success(True, 0)
        builder.set_output("original stdout", "original stderr")

        builder.set_custom_data(
            success=False,
            stdout="custom stdout",
            operation="custom_op",
            custom_field="value",
        )

        self.assertTrue(builder.result["success"])
        self.assertEqual(builder.result["stdout"], "original stdout")
        self.assertEqual(builder.result["operation"], "install")
        self.assertEqual(builder.result["custom_field"], "value")


if __name__ == "__main__":
    unittest.main()
