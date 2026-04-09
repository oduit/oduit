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

    ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*m")

    @classmethod
    def _clean_test_log_line(cls, line: str) -> str:
        """Strip ANSI escape sequences from one test log line."""
        return cls.ANSI_ESCAPE_PATTERN.sub("", line)

    # Specific failure patterns for different operations
    FAILURE_PATTERNS = {
        "install": [
            # Critical installation failures
            re.compile(r"odoo\.modules\.loading: invalid module names, ignored:"),
            re.compile(
                r"odoo\.modules\.loading: Some modules are not loaded, "
                r"some dependencies or manifest may be missing:"
            ),
            # Module not found errors
            re.compile(r"ModuleNotFoundError"),
            re.compile(r"No module named"),
            # Import/dependency errors for requested modules
            re.compile(r"ImportError"),
        ],
        "update": [
            # Critical update failures
            re.compile(r"odoo\.modules\.loading: invalid module names, ignored:"),
            re.compile(
                r"odoo\.modules\.loading: Some modules are not loaded, "
                r"some dependencies or manifest may be missing:"
            ),
            # Module not found errors
            re.compile(r"ModuleNotFoundError"),
            re.compile(r"No module named"),
            # Import/dependency errors for requested modules
            re.compile(r"ImportError"),
        ],
        "test": [
            # Critical test failures
            re.compile(r"odoo\.modules\.loading: invalid module names, ignored:"),
            re.compile(
                r"odoo\.modules\.loading: Some modules are not loaded, "
                r"some dependencies or manifest may be missing:"
            ),
            # Module not found errors
            re.compile(r"ModuleNotFoundError"),
            re.compile(r"No module named"),
            # Import/dependency errors for requested modules
            re.compile(r"ImportError"),
        ],
        # Generic patterns that apply to all operations
        "generic": [
            re.compile(r"ERROR.*FATAL"),
            re.compile(r"CRITICAL"),
            re.compile(r"Exception.*Traceback"),
        ],
    }
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

        # Check for failure patterns before applying parsers
        operation_type = self.result.get(
            "operation_type", self.result.get("operation", "")
        )
        has_failure, failure_msg = self._check_for_failure_patterns(
            output, operation_type
        )
        if has_failure and failure_msg:
            # Override success status if failure patterns detected
            self.result["success"] = False
            if not self.result.get("error"):
                self.set_error(failure_msg, "OperationFailure")
        else:
            # No failure patterns detected, set success to True
            # (will be overridden by process result if needed)
            self.result["success"] = True

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
        install_info: dict[str, Any] = {
            "success": True,
            "modules_loaded": 0,
            "total_modules": 0,
            "modules_installed": [],
            "unmet_dependencies": [],
            "failed_modules": [],
            "dependency_errors": [],
            "error_messages": [],
        }

        if not output:
            return install_info

        lines = output.split("\n")

        for line in lines:
            # Pattern for loading modules: "Loading module X (Y/Z)"
            loading_module_match = re.search(
                r"Loading\s+module\s+(\w+)\s+\(\d+/\d+\)", line
            )
            if loading_module_match:
                module_name = loading_module_match.group(1)
                if module_name not in install_info["modules_installed"]:
                    install_info["modules_installed"].append(module_name)

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

            # Pattern for UserError about missing dependencies
            # "UserError: You try to install module 'X' that depends on module 'Y'"
            user_error_match = re.search(
                r"UserError.*try to install module ['\"](\w+)['\"].*"
                r"depends on module ['\"](\w+)['\"]",
                line,
            )
            if user_error_match:
                module_name = user_error_match.group(1)
                missing_dep = user_error_match.group(2)
                install_info["dependency_errors"].append(
                    f"Module '{module_name}' depends on missing module '{missing_dep}'"
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

                # Only set success to False if the target modules are in the failed list
                # or if no target modules are specified
                target_modules = self.result.get("modules", [])
                if not target_modules or any(
                    target_module in modules for target_module in target_modules
                ):
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

                    # Only set success to False if the error mentions target modules
                    # or if no target modules are specified
                    target_modules = self.result.get("modules", [])
                    if not target_modules:
                        install_info["success"] = False
                    elif any(
                        target_module in clean_line for target_module in target_modules
                    ):
                        install_info["success"] = False
                    # For "Some modules are not loaded" errors, check if target
                    # modules are in the failed list
                    elif "Some modules are not loaded" in clean_line:
                        # Extract the failed modules from the error message
                        failed_pattern = re.search(r":\s*\[([^\]]+)\]", clean_line)
                        if failed_pattern:
                            failed_modules = [
                                m.strip().strip("'\"")
                                for m in failed_pattern.group(1).split(",")
                            ]
                            if not target_modules or any(
                                target_module in failed_modules
                                for target_module in target_modules
                            ):
                                install_info["success"] = False

        return install_info

    def _parse_test_failure(self, lines: list[str], start_index: int) -> dict[str, Any]:
        """Parse one traceback block starting at a FAIL header."""
        line = self._clean_test_log_line(lines[start_index])
        fail_match = re.search(r"FAIL:\s+(.+)", line)
        if fail_match is None:
            return {}

        failure_info: dict[str, Any] = {
            "test_name": fail_match.group(1),
            "traceback": [],
            "file": None,
            "line": None,
            "function_name": None,
            "source_line": None,
            "source_lines": [],
            "locations": [],
            "broken_line_count": 0,
            "failure_excerpt": None,
            "error_message": None,
        }
        expect_source_line = False
        j = start_index + 1

        while j < len(lines):
            raw_next_line = lines[j]
            next_line = self._clean_test_log_line(raw_next_line).strip()
            if (
                not next_line
                or "Starting" in lines[j]
                or ("INFO" in next_line and "ERROR" not in next_line)
            ):
                break

            clean_line = re.sub(
                r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}\s+\d+\s+",
                "",
                next_line,
            )
            failure_info["traceback"].append(clean_line)

            file_match = re.search(
                r'File\s+"([^"]+)",\s+line\s+(\d+)(?:,\s+in\s+(.+))?',
                clean_line,
            )
            if file_match and not file_match.group(1).endswith("odoo-bin"):
                location = {
                    "file": file_match.group(1),
                    "line": int(file_match.group(2)),
                    "function": file_match.group(3),
                }
                failure_info["locations"].append(location)
                if failure_info["file"] is None:
                    failure_info["file"] = location["file"]
                    failure_info["line"] = location["line"]
                    failure_info["function_name"] = location["function"]
                expect_source_line = True
                j += 1
                continue

            is_error_line = any(
                error_type in clean_line
                for error_type in [
                    "AssertionError",
                    "ValueError",
                    "TypeError",
                    "Error:",
                ]
            )
            if (
                expect_source_line
                and clean_line not in ("Traceback (most recent call last):",)
                and not is_error_line
            ):
                failure_info["source_lines"].append(clean_line)
                if failure_info["source_line"] is None:
                    failure_info["source_line"] = clean_line
                expect_source_line = False

            if is_error_line:
                failure_info["error_message"] = clean_line
                expect_source_line = False

            j += 1

        failure_info["broken_line_count"] = len(failure_info["locations"]) + len(
            failure_info["source_lines"]
        )
        if failure_info["file"] and failure_info["line"] is not None:
            excerpt = f"{failure_info['file']}:{failure_info['line']}"
            if failure_info["source_line"]:
                excerpt = f"{excerpt}: {failure_info['source_line']}"
            failure_info["failure_excerpt"] = excerpt

        return failure_info

    def _parse_test_results(self, output: str) -> dict[str, Any]:
        """Parse Odoo test output to extract test statistics and error details"""
        test_info: dict[str, Any] = {
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "error_tests": 0,
            "failures": [],
        }

        if not output:
            return test_info

        lines = output.split("\n")

        authoritative_result_seen = False

        def _apply_summary(failed: int, errors: int, total: int) -> None:
            test_info["failed_tests"] = failed
            test_info["error_tests"] = errors
            test_info["total_tests"] = total
            test_info["passed_tests"] = max(total - failed - errors, 0)

        # Extract test statistics from authoritative Odoo test loggers first.
        # Fall back to legacy loading summaries only when no
        # odoo.tests.result line exists.
        for raw_line in lines:
            line = self._clean_test_log_line(raw_line)
            stats_match = re.search(
                r"odoo\.tests\.stats:\s+[\w.]+:\s+(\d+)\s+tests\s+[\d.]+s\s+\d+\s+queries",
                line,
            )
            if stats_match:
                test_info["total_tests"] = int(stats_match.group(1))

            legacy_stats_match = re.search(
                r"odoo\.modules\.loading:\s+[\w.]+:\s+(\d+)\s+tests\s+[\d.]+s\s+\d+\s+queries",
                line,
            )
            if legacy_stats_match and test_info["total_tests"] == 0:
                test_info["total_tests"] = int(legacy_stats_match.group(1))

            result_match = re.search(
                r"odoo\.tests\.result:\s+(\d+)\s+failed,\s+(\d+)\s+error\(s\)\s+of\s+(\d+)\s+tests",
                line,
            )
            if result_match:
                _apply_summary(
                    int(result_match.group(1)),
                    int(result_match.group(2)),
                    int(result_match.group(3)),
                )
                authoritative_result_seen = True
                continue

            if authoritative_result_seen:
                continue

            legacy_result_match = re.search(
                r"odoo\.modules\.loading:\s+(\d+)\s+failed,\s+(\d+)\s+error\(s\)\s+of\s+(\d+)\s+tests",
                line,
            )
            if legacy_result_match:
                _apply_summary(
                    int(legacy_result_match.group(1)),
                    int(legacy_result_match.group(2)),
                    int(legacy_result_match.group(3)),
                )

        # Extract failure details - look for FAIL patterns
        for i, raw_line in enumerate(lines):
            line = self._clean_test_log_line(raw_line)
            # Look for failure headers like: "FAIL: FastAPIDemoCase.test_no_key"
            # or "ERROR ... FAIL: AdvancedTestCase.test_workflow"
            if re.search(r"FAIL:\s+(.+)", line):
                test_info["failures"].append(self._parse_test_failure(lines, i))

        return test_info

    def _check_for_failure_patterns(
        self, output: str, operation_type: str
    ) -> tuple[bool, str | None]:
        """Check if output contains specific failure patterns for the operation

        Returns:
            Tuple of (has_failure, failure_message)
        """
        # Get the modules being installed/updated for context
        modules = self.result.get("modules", [])

        # Get patterns for this specific operation
        operation_patterns = self.FAILURE_PATTERNS.get(operation_type, [])

        # Also check generic patterns
        all_patterns = operation_patterns + self.FAILURE_PATTERNS.get("generic", [])

        for pattern in all_patterns:
            match = pattern.search(output)
            if match:
                # Extract the full line or matched content
                failure_msg = match.group(0).strip()

                # For module-specific errors, check if they mention our target modules
                if any(
                    keyword in failure_msg
                    for keyword in [
                        "invalid module names",
                        "Some modules are not loaded",
                    ]
                ):
                    # Check if any of our target modules are mentioned in this error
                    for module in modules:
                        # Look for the module name in the error context
                        if module in failure_msg:
                            return True, failure_msg

                        # For "invalid module names" errors, check the list
                        if "invalid module names, ignored:" in failure_msg:
                            # Extract the module list from the error message
                            ignored_pattern = re.compile(
                                r"invalid module names, ignored:\s*(.+)"
                            )
                            ignored_match = ignored_pattern.search(output)
                            if ignored_match:
                                ignored_modules = [
                                    m.strip() for m in ignored_match.group(1).split(",")
                                ]
                                if module in ignored_modules:
                                    return True, failure_msg

                        # For "Some modules are not loaded" errors, check failed modules
                        if "Some modules are not loaded" in failure_msg:
                            # Extract the failed modules list from the error message
                            failed_pattern = re.compile(
                                r"Some modules are not loaded.*:\s*\[(.+?)\]"
                            )
                            failed_match = failed_pattern.search(output)
                            if failed_match:
                                failed_modules = [
                                    m.strip().strip("'\"")
                                    for m in failed_match.group(1).split(",")
                                ]
                                if module in failed_modules:
                                    return True, failure_msg

                    # If none of our target modules are mentioned, skip
                    continue

                # For other patterns (non-module-specific), treat as failure immediately
                return True, failure_msg

        return False, None

    def _check_for_module_warnings(self, output: str, module: str) -> str | None:
        """Check if output contains warnings about invalid/ignored modules"""
        # Look for the specific warning pattern
        warning_pattern = re.compile(
            r"invalid module names, ignored:.*" + re.escape(module)
        )
        match = warning_pattern.search(output)
        if match:
            return match.group(0).strip()

        # Check for other module-related warnings
        other_warnings = [
            r"module.*not found",
            r"module.*not installable",
            r"No module named",
        ]

        for pattern in other_warnings:
            if re.search(pattern, output, re.IGNORECASE):
                return f"Module issue detected: {pattern}"

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
            output = process_result.get("output", "")
            operation_type = self.result.get("operation", "")

            # Check for specific failure patterns first
            has_failure, failure_msg = self._check_for_failure_patterns(
                output, operation_type
            )
            if has_failure and failure_msg:
                # Override success status if failure patterns detected
                self.result["success"] = False
                self.set_error(failure_msg, "OperationFailure")

            # Check for module warnings if requested (legacy support)
            elif check_module_warnings and module and self.result.get("success", True):
                warning = self._check_for_module_warnings(output, module)
                if warning:
                    self.result["success"] = False
                    self.set_error(warning, "ModuleWarning")

            # Set the return code and output (preserve existing success status)
            self.result["return_code"] = process_result.get("return_code", 1)
            self.set_output(
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
