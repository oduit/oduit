# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.


import json
import sys
import unittest
from io import StringIO

from oduit.output import OutputFormatter, configure_output
from oduit.process_manager import ProcessManager


class TestOutputFormatterJSONParsing(unittest.TestCase):
    """Test JSON parsing functionality in OutputFormatter."""

    def setUp(self):
        """Set up test fixtures."""
        self.formatter = OutputFormatter("json", True)

    def test_is_odoo_log_line_detection(self):
        """Test Odoo log line detection."""
        # Valid Odoo log lines
        valid_lines = [
            "2025-08-21 09:07:24,574 65551 INFO test_db "
            "odoo.service.server: Starting post tests",
            "2025-08-21 10:15:30,123 12345 ERROR my_db "
            "odoo.modules.loading: Module loading failed",
            "2025-08-21 11:22:45,999 98765 WARNING prod_db "
            "odoo.http.request: Request timeout",
            "2025-08-21 12:30:15,000 11111 DEBUG test_db "
            "odoo.sql_db: SQL query executed",
        ]

        for line in valid_lines:
            with self.subTest(line=line):
                self.assertTrue(self.formatter._is_odoo_log_line(line))

        # Invalid lines
        invalid_lines = [
            "Not an Odoo log line",
            "2025-08-21 invalid format",
            "Some random process output",
            "coverage report line goes here",
        ]

        for line in invalid_lines:
            with self.subTest(line=line):
                self.assertFalse(self.formatter._is_odoo_log_line(line))

    def test_parse_odoo_log_line(self):
        """Test Odoo log line parsing."""
        test_line = (
            "2025-08-21 09:07:24,574 65551 INFO test_db "
            "odoo.service.server: Starting post tests"
        )

        result = self.formatter._parse_odoo_log_line(test_line)

        expected = {
            "source": "odoo",
            "level": "info",
            "timestamp": "2025-08-21T09:07:24.574000",
            "process_id": 65551,
            "database": "test_db",
            "module": "odoo.service.server",
            "message": "Starting post tests",
        }

        self.assertEqual(result, expected)

    def test_parse_odoo_log_line_invalid(self):
        """Test Odoo log line parsing with invalid input."""
        invalid_line = "Not a valid Odoo log line"
        result = self.formatter._parse_odoo_log_line(invalid_line)
        self.assertIsNone(result)

    def test_is_coverage_report_line_detection(self):
        """Test coverage report line detection."""
        # Valid coverage lines
        valid_lines = [
            "mail_mail_helper.py                 58      3    95%   74, 107, 120",
            "attach_mail_helpdesk_ticket.py     29     19    34%   22-67",
            "simple_module/models/base.py                                              "
            "10      0   100%",
            "path/to/file.py                                                           "
            "5      2    60%   1, 3",
        ]

        for line in valid_lines:
            with self.subTest(line=line):
                self.assertTrue(self.formatter._is_coverage_report_line(line))

        # Invalid lines
        invalid_lines = [
            "Not a coverage line",
            "some_file.py but not coverage format",
            "2025-08-21 09:07:24,574 65551 INFO test_db odoo.service.server: Starting",
            "Name                     Stmts   Miss  Cover   Missing",  # Header line
            "TOTAL                      500     50    90%",  # Summary line
        ]

        for line in invalid_lines:
            with self.subTest(line=line):
                self.assertFalse(self.formatter._is_coverage_report_line(line))

    def test_parse_coverage_report_line_with_ranges(self):
        """Test coverage report parsing with line ranges."""
        test_line = "attach_mail_helpdesk_ticket.py     29     19    34%   22-67"

        result = self.formatter._parse_coverage_report_line(test_line)

        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result["source"], "coverage")
            self.assertEqual(result["type"], "file_coverage")
            self.assertEqual(
                result["file_path"],
                "attach_mail_helpdesk_ticket.py",
            )
            self.assertEqual(result["statements"], 29)
            self.assertEqual(result["missing"], 19)
            self.assertEqual(result["covered"], 10)
            self.assertEqual(result["coverage_percentage"], 34)

            # Check that range 22-67 is properly expanded
            expected_missing = list(range(22, 68))  # 22-67 inclusive
            self.assertEqual(result["missing_lines"], expected_missing)
            self.assertIn("timestamp", result)

    def test_parse_coverage_report_line_individual_lines(self):
        """Test coverage report parsing with individual missing lines."""
        test_line = (
            "mail_mail_helper.py                 58      3    95%   74, 107, 120"
        )

        result = self.formatter._parse_coverage_report_line(test_line)

        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result["missing_lines"], [74, 107, 120])
            self.assertEqual(result["coverage_percentage"], 95)

    def test_parse_coverage_report_line_mixed_ranges_and_lines(self):
        """Test coverage report parsing with mixed ranges and individual lines."""
        test_line = (
            "portal.py                   80     25    69%   10, 15-20, 25, 30-35, 40"
        )

        result = self.formatter._parse_coverage_report_line(test_line)

        self.assertIsNotNone(result)
        if result:
            expected_missing = [
                10,
                15,
                16,
                17,
                18,
                19,
                20,
                25,
                30,
                31,
                32,
                33,
                34,
                35,
                40,
            ]
            self.assertEqual(result["missing_lines"], expected_missing)

    def test_parse_coverage_report_line_no_missing(self):
        """Test coverage report parsing with 100% coverage (no missing lines)."""
        test_line = "models/mail_thread.py                  100      0    100%"

        result = self.formatter._parse_coverage_report_line(test_line)

        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result["missing"], 0)
            self.assertEqual(result["covered"], 100)
            self.assertEqual(result["coverage_percentage"], 100)
            self.assertEqual(result["missing_lines"], [])

    def test_parse_coverage_report_line_invalid(self):
        """Test coverage report parsing with invalid input."""
        invalid_line = "Not a valid coverage line"
        result = self.formatter._parse_coverage_report_line(invalid_line)
        self.assertIsNone(result)


class TestProcessManagerJSONOutput(unittest.TestCase):
    """Test ProcessManager JSON output functionality."""

    def setUp(self):
        """Set up test fixtures."""
        configure_output("json", True)
        self.process_manager = ProcessManager()

    def tearDown(self):
        """Clean up after tests."""
        configure_output("text", False)

    def _capture_output(self, func, *args):
        """Helper to capture stdout from a function call."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        try:
            func(*args)
            output = captured_output.getvalue().strip()
            return json.loads(output) if output else None
        finally:
            sys.stdout = old_stdout

    def test_parse_and_output_odoo_log_json(self):
        """Test that Odoo logs are properly parsed and output as JSON."""
        odoo_line = (
            "2025-08-21 09:07:24,574 65551 INFO test_db "
            "odoo.service.server: Starting post tests"
        )

        result = self._capture_output(
            self.process_manager._parse_and_output_odoo_log, odoo_line
        )

        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result["source"], "odoo")
            self.assertEqual(result["level"], "info")
            self.assertEqual(result["process_id"], 65551)
            self.assertEqual(result["database"], "test_db")
            self.assertEqual(result["module"], "odoo.service.server")
            self.assertEqual(result["message"], "Starting post tests")

    def test_parse_and_output_coverage_report_json(self):
        """Test that coverage reports are properly parsed and output as JSON."""
        coverage_line = (
            "mail_mail_helper.py                 58      3    95%   74, 107, 120"
        )

        result = self._capture_output(
            self.process_manager._parse_and_output_odoo_log, coverage_line
        )

        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result["source"], "coverage")
            self.assertEqual(result["type"], "file_coverage")
            self.assertEqual(
                result["file_path"],
                "mail_mail_helper.py",
            )
            self.assertEqual(result["statements"], 58)
            self.assertEqual(result["missing"], 3)
            self.assertEqual(result["covered"], 55)
            self.assertEqual(result["coverage_percentage"], 95)
            self.assertEqual(result["missing_lines"], [74, 107, 120])

    def test_parse_and_output_generic_process_json(self):
        """Test that generic process output is handled properly."""
        generic_line = "Some random process output"

        result = self._capture_output(
            self.process_manager._parse_and_output_odoo_log, generic_line
        )

        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result["source"], "process")
            self.assertEqual(result["level"], "info")
            self.assertEqual(result["message"], "Some random process output")
            self.assertIn("timestamp", result)

    def test_no_output_in_text_mode(self):
        """Test that no JSON output occurs in text mode."""
        configure_output("text", False)

        odoo_line = (
            "2025-08-21 09:07:24,574 65551 INFO test_db odoo.service.server: Starting"
        )

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        try:
            self.process_manager._parse_and_output_odoo_log(odoo_line)
            output = captured_output.getvalue().strip()

            # Should be empty because we're in text mode
            self.assertEqual(output, "")
        finally:
            sys.stdout = old_stdout

    def test_parsing_priority(self):
        """Test that Odoo logs take priority over coverage parsing."""
        # A line that could theoretically match both patterns
        # (though unlikely in practice)
        # This test ensures Odoo logs are checked first

        odoo_line = (
            "2025-08-21 09:07:24,574 65551 INFO test_db "
            "odoo.service.server: Starting post tests"
        )

        result = self._capture_output(
            self.process_manager._parse_and_output_odoo_log, odoo_line
        )

        # Should be parsed as Odoo log, not as coverage or generic process
        self.assertIsNotNone(result)
        if result:
            self.assertEqual(result["source"], "odoo")
            self.assertNotEqual(result["source"], "coverage")
            self.assertNotEqual(result["source"], "process")


class TestIntegrationJSONParsing(unittest.TestCase):
    """Integration tests for JSON parsing across the system."""

    def test_print_result_with_odoo_log_message(self):
        """Test that print_result properly handles Odoo log messages."""
        configure_output("json", True)

        odoo_message = (
            "2025-08-21 09:07:24,574 65551 INFO test_db "
            "odoo.service.server: Starting post tests"
        )
        test_data = {"test": "data"}

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        try:
            from oduit.output import print_result

            print_result(test_data, odoo_message)
            output = captured_output.getvalue().strip()

            if output:
                result = json.loads(output)

                # Should merge the result data with parsed Odoo log
                self.assertEqual(result["status"], "success")
                self.assertEqual(result["result"], test_data)
                self.assertEqual(result["source"], "odoo")
                self.assertEqual(result["level"], "info")
                self.assertEqual(result["message"], "Starting post tests")

        finally:
            sys.stdout = old_stdout
            configure_output("text", False)

    def test_print_error_result_with_odoo_log_message(self):
        """Test that print_error_result properly handles Odoo log messages."""
        configure_output("json", True)

        odoo_error = (
            "2025-08-21 09:07:24,574 65551 ERROR test_db "
            "odoo.modules.loading: Module loading failed"
        )

        # Capture output and expect SystemExit
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        try:
            from oduit.output import print_error_result

            with self.assertRaises(SystemExit):
                print_error_result(odoo_error, 1)

            output = captured_output.getvalue().strip()
            if output:
                result = json.loads(output)

                # Should merge the error info with parsed Odoo log
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["error_code"], 1)
                self.assertEqual(result["source"], "odoo")
                self.assertEqual(result["level"], "error")
                self.assertEqual(result["message"], "Module loading failed")

        finally:
            sys.stdout = old_stdout
            configure_output("text", False)


if __name__ == "__main__":
    unittest.main()
