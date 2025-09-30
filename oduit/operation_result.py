# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import re
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .builders import CommandOperation


class OperationResult:
    """Builder class for creating standardized operation results"""

    def __init__(
        self,
        operation: str | None = None,
        module: str | None = None,
        database: str | None = None,
    ):
        self.result: dict[str, Any] = {
            "success": False,
            "return_code": None,
            "operation": operation,
            "command": [],
            "stdout": "",
            "stderr": "",
            "module": module,
            "database": database,
            "addon_name": None,
            "addons": None,
            "error": None,
            "error_type": None,
            "duration": None,
            "timestamp": datetime.now().isoformat(),
        }
        self.start_time = time.time()
        self._core_fields = {
            "success",
            "return_code",
            "operation",
            "command",
            "stdout",
            "stderr",
            "module",
            "database",
            "addon_name",
            "addons",
            "error",
            "error_type",
            "duration",
            "timestamp",
        }

    @classmethod
    def from_operation(cls, command_operation: "CommandOperation") -> "OperationResult":
        """Factory method to create OperationResult from CommandOperation."""
        # Import here to avoid circular import

        # Determine operation name from operation_type
        operation = command_operation.operation_type

        # Extract database and module info
        database = command_operation.database
        module = command_operation.modules[0] if command_operation.modules else None

        # Create instance with basic metadata
        instance = cls(operation=operation, module=module, database=database)

        # Set the command
        instance.set_command(command_operation.command)

        # Set additional metadata from CommandOperation
        instance.set_custom_data(
            operation_type=command_operation.operation_type,
            modules=command_operation.modules,
            test_tags=command_operation.test_tags,
            extra_args=command_operation.extra_args,
            is_odoo_command=command_operation.is_odoo_command,
            expected_result_fields=command_operation.expected_result_fields,
            result_parsers=command_operation.result_parsers,
        )

        return instance

    def set_success(self, success: bool, return_code: int = 0) -> "OperationResult":
        self.result["success"] = success
        self.result["return_code"] = return_code
        return self

    def set_new_operation(self, operation: str) -> "OperationResult":
        self.result = {
            "success": False,
            "return_code": None,
            "operation": operation,
            "command": [],
            "stdout": "",
            "stderr": "",
            "module": None,
            "database": None,
            "addon_name": None,
            "addons": None,
            "error": None,
            "error_type": None,
            "duration": None,
            "timestamp": datetime.now().isoformat(),
        }
        self.start_time = time.time()

        return self

    def set_operation(self, operation: str) -> "OperationResult":
        self.result["operation"] = operation
        return self

    def set_command(self, command: list[str]) -> "OperationResult":
        self.result["command"] = command
        return self

    def set_output(self, stdout: str = "", stderr: str = "") -> "OperationResult":
        self.result["stdout"] = stdout
        self.result["stderr"] = stderr
        return self

    def set_module(self, module: str) -> "OperationResult":
        self.result["module"] = module
        return self

    def set_database(self, database: str) -> "OperationResult":
        self.result["database"] = database
        return self

    def set_addon_name(self, addon_name: str) -> "OperationResult":
        self.result["addon_name"] = addon_name
        return self

    def set_addons(self, addons: list[str]) -> "OperationResult":
        self.result["addons"] = addons
        return self

    def set_error(self, error: str, error_type: str | None = None) -> "OperationResult":
        self.result["error"] = error
        self.result["error_type"] = error_type
        self.result["success"] = False
        return self

    def set_custom_data(self, **kwargs: Any) -> "OperationResult":
        """Add operation-specific data"""
        for key, value in kwargs.items():
            if key not in self.result:  # Don't override core fields
                self.result[key] = value
        return self

    def parse_and_merge_install_results(
        self, output: str, **additional_data: Any
    ) -> "OperationResult":
        """Parse install output and merge with existing custom data"""
        parsed_results = self._parse_install_results(output)
        return self._merge_parsed_results(parsed_results, **additional_data)

    def parse_and_merge_test_results(
        self, output: str, **additional_data: Any
    ) -> "OperationResult":
        """Parse test output and merge with existing custom data"""
        parsed_results = self._parse_test_results(output)
        return self._merge_parsed_results(parsed_results, **additional_data)

    def process_with_parsers(
        self, output: str, **additional_data: Any
    ) -> "OperationResult":
        """Automatically select and apply appropriate parsers based on operation
        metadata.
        """
        # Get the result parsers from custom data
        result_parsers = self.result.get("result_parsers", [])

        if not result_parsers:
            # Fallback: infer parser from operation type
            operation_type = self.result.get(
                "operation_type", self.result.get("operation", "")
            )

            # Map operation types to parsers
            parser_mapping = {
                "install": ["install"],
                "update": ["install"],  # Update operations use install parser
                "test": ["test"],
                "test_coverage": ["test"],
            }

            result_parsers = parser_mapping.get(operation_type, [])

        # Apply parsers in order
        for parser in result_parsers:
            if parser == "install":
                self.parse_and_merge_install_results(output, **additional_data)
            elif parser == "test":
                self.parse_and_merge_test_results(output, **additional_data)

        # If no parsers were applied, just set the output
        if not result_parsers:
            self.set_output(stdout=output)

        return self

    def _merge_parsed_results(
        self, parsed_results: dict[str, Any], **additional_data: Any
    ) -> "OperationResult":
        """Merge parsed results with existing custom data, handling success logic"""
        # Get existing custom data
        existing_custom_data = {
            k: v
            for k, v in self.result.items()
            if k not in self._core_fields and v is not None
        }

        # Filter out core fields from parsed results before merging
        filtered_parsed_results = {
            k: v for k, v in parsed_results.items() if k not in self._core_fields
        }

        # Merge all custom data
        existing_custom_data.update(filtered_parsed_results)
        existing_custom_data.update(additional_data)

        # Set all custom data at once
        self.set_custom_data(**existing_custom_data)

        # Handle semantic success logic for install operations
        if self.result["operation"] == "install" and not parsed_results.get(
            "success", True
        ):
            self.set_success(False, self.result.get("return_code", 1))
            if parsed_results.get("dependency_errors"):
                error_msg = "; ".join(parsed_results["dependency_errors"])
                self.set_error(
                    f"Module installation failed: {error_msg}", "InstallationError"
                )

        # Handle semantic success logic for test operations
        elif self.result["operation"] == "test" and (
            parsed_results.get("failed_tests", 0) > 0
            or parsed_results.get("error_tests", 0) > 0
        ):
            self.set_success(False, self.result.get("return_code", 1))
            failed = parsed_results.get("failed_tests", 0)
            errors = parsed_results.get("error_tests", 0)
            self.set_error(
                f"Tests failed: {failed} failed, {errors} errors", "TestFailure"
            )

        return self

    def _parse_install_results(self, output: str) -> dict[str, Any]:
        """Parse Odoo install output to extract installation errors and dependencies"""
        install_info = {
            "success": True,
            "modules_loaded": 0,
            "total_modules": 0,
            "unmet_dependencies": [],
            "failed_modules": [],
            "dependency_errors": [],
            "error_messages": [],
        }

        if not output:
            return install_info

        lines = output.split("\n")

        for line in lines:
            # Pattern for unmet dependencies: "module module_name: Unmet dependencies"
            unmet_deps_match = re.search(
                r"module\s+(\w+):\s+Unmet\s+dependencies:\s+(.+)", line
            )
            if unmet_deps_match:
                module_name = unmet_deps_match.group(1)
                dependencies = [
                    dep.strip() for dep in unmet_deps_match.group(2).split(",")
                ]
                install_info["unmet_dependencies"].append(
                    {"module": module_name, "dependencies": dependencies}
                )
                install_info["dependency_errors"].append(
                    f"Module '{module_name}' has unmet dependencies: "
                    f"{', '.join(dependencies)}"
                )
                install_info["success"] = False

            # Pattern for modules loading: "loading X modules..."
            loading_match = re.search(r"loading\s+(\d+)\s+modules", line)
            if loading_match:
                install_info["total_modules"] = int(loading_match.group(1))

            # Pattern for modules loaded: "X modules loaded in Y.Ys"
            loaded_match = re.search(r"(\d+)\s+modules\s+loaded\s+in", line)
            if loaded_match:
                install_info["modules_loaded"] = int(loaded_match.group(1))

            # Pattern for failed modules: "Some modules are not loaded, some
            # dependencies or manifest may be missing: ['module1', 'module2']"
            failed_modules_match = re.search(
                r"Some\s+modules\s+are\s+not\s+loaded.*:\s*\[([^\]]+)\]", line
            )
            if failed_modules_match:
                # Parse the module list - handle both quoted and unquoted module names
                modules_str = failed_modules_match.group(1)
                # Remove quotes and split by comma
                modules = [
                    module.strip().strip("'\"") for module in modules_str.split(",")
                ]
                install_info["failed_modules"].extend(modules)
                install_info["success"] = False

            # Look for general ERROR lines
            if "ERROR" in line and any(
                keyword in line.lower() for keyword in ["module", "install", "loading"]
            ):
                # Clean the error message
                clean_line = re.sub(
                    r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}\s+\d+\s+ERROR\s+\S+\s+",
                    "",
                    line,
                )
                if clean_line and clean_line not in install_info["error_messages"]:
                    install_info["error_messages"].append(clean_line)
                    install_info["success"] = False

        return install_info

    def _parse_test_results(self, output: str) -> dict[str, Any]:
        """Parse Odoo test output to extract test statistics and error details"""
        test_info = {
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "error_tests": 0,
            "failures": [],
        }

        if not output:
            return test_info

        lines = output.split("\n")

        # Extract test statistics from lines like:
        # "fastapi_connections: 11 tests 1.69s 90 queries"
        # "1 failed, 0 error(s) of 7 tests when loading database"
        for line in lines:
            # Pattern for module test stats: "module_name: X tests Y.Ys Z queries"
            module_stats_match = re.search(
                r"(\w+):\s+(\d+)\s+tests\s+[\d.]+s\s+\d+\s+queries", line
            )
            if module_stats_match:
                test_info["total_tests"] = int(module_stats_match.group(2))

            # Pattern for failure summary: "X failed, Y error(s) of Z tests"
            failure_match = re.search(
                r"(\d+)\s+failed,\s+(\d+)\s+error\(s\)\s+of\s+(\d+)\s+tests", line
            )
            if failure_match:
                test_info["failed_tests"] = int(failure_match.group(1))
                test_info["error_tests"] = int(failure_match.group(2))
                # Use the total from result summary, more accurate than module stats
                test_info["total_tests"] = int(failure_match.group(3))
                # Calculate passed tests
                test_info["passed_tests"] = (
                    test_info["total_tests"]
                    - test_info["failed_tests"]
                    - test_info["error_tests"]
                )

        # Extract failure details - look for FAIL patterns
        for i, line in enumerate(lines):
            # Look for failure headers like: "FAIL: FastAPIDemoCase.test_no_key"
            # or "ERROR ... FAIL: AdvancedTestCase.test_workflow"
            fail_match = re.search(r"FAIL:\s+(.+)", line)
            if fail_match:
                test_name = fail_match.group(1)
                failure_info = {
                    "test_name": test_name,
                    "traceback": [],
                    "file": None,
                    "line": None,
                    "error_message": None,
                }

                # Collect traceback lines starting from next line until we hit
                # empty line or next test
                j = i + 1
                while j < len(lines):
                    next_line = lines[j].strip()
                    if (
                        not next_line
                        or "Starting" in lines[j]
                        or ("INFO" in lines[j] and "ERROR" not in lines[j])
                    ):
                        break

                    # Remove timestamp prefix if present
                    # (e.g., "2025-09-04 10:58:52,787 12345 ")
                    clean_line = re.sub(
                        r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}\s+\d+\s+",
                        "",
                        next_line,
                    )
                    failure_info["traceback"].append(clean_line)

                    # Extract file and line number
                    file_match = re.search(
                        r'File\s+"([^"]+)",\s+line\s+(\d+)', clean_line
                    )
                    if file_match and not file_match.group(1).endswith("odoo-bin"):
                        failure_info["file"] = file_match.group(1)
                        failure_info["line"] = int(file_match.group(2))

                    # Extract error message
                    if any(
                        error_type in clean_line
                        for error_type in [
                            "AssertionError",
                            "ValueError",
                            "TypeError",
                            "Error:",
                        ]
                    ):
                        failure_info["error_message"] = clean_line

                    j += 1

                test_info["failures"].append(failure_info)

        return test_info

    def _check_for_module_warnings(self, output: str, module: str) -> str | None:
        """Check if output contains warnings about invalid/ignored modules"""
        if not output or not module:
            return None

        # Check for Odoo's "invalid module names, ignored" warning
        if f"invalid module names, ignored: {module}" in output:
            return f"Module '{module}' not found or invalid"

        # Check for other module-related warnings
        if "WARNING" in output and module in output and "ignored" in output:
            return f"Module '{module}' was ignored (check module name and availability)"

        return None

    def handle_process_result(
        self,
        process_result: dict | None,
        check_module_warnings: bool = False,
        module: str | None = None,
    ) -> "OperationResult":
        """Convert ProcessManager result to our standard format"""
        if process_result:
            success = process_result.get("success", False)
            output = process_result.get("output", "")

            # Check for module warnings if requested
            if check_module_warnings and module and success:
                warning = self._check_for_module_warnings(output, module)
                if warning:
                    success = False
                    self.set_error(warning, "ModuleWarning")

            self.set_success(
                success,
                process_result.get("return_code", 1),
            ).set_output(
                process_result.get("stdout", output), process_result.get("stderr", "")
            )

            if "error" in process_result and not self.result.get("error"):
                self.set_error(process_result["error"])
        else:
            self.set_error("Process execution failed", "ProcessError")

        return self

    def finalize(self) -> dict[str, Any]:
        """Complete the result and return the dictionary"""
        self.result["duration"] = time.time() - self.start_time
        return self.result
