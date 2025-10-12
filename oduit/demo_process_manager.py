# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import time
from collections.abc import Generator
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .base_process_manager import BaseProcessManager
from .output import print_info

if TYPE_CHECKING:
    from .builders import CommandOperation

# Demo module catalog with predefined behaviors
DEMO_MODULES = {
    "module_ok": {
        "status": "success",
        "install_time": 2.5,
        "dependencies": [],
        "description": "Always succeeds for testing",
        "log_stream": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: loading 1 modules...",
            "INFO odoo.modules.loading: updating modules list",
            "INFO odoo.modules.loading: Loading module module_ok (1/1)",
            "INFO odoo.modules.registry: module module_ok: creating or updating "
            "database tables",
            "INFO odoo.modules.loading: Module module_ok loaded in 0.45s",
            "INFO odoo.modules.loading: Modules loaded.",
        ],
    },
    "module_error": {
        "status": "error",
        "error_type": "dependency_missing",
        "description": "Simulates dependency errors",
        "log_stream": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: loading 1 modules...",
            "INFO odoo.modules.loading: updating modules list",
            "INFO odoo.modules.loading: Loading module module_error (1/1)",
            "ERROR odoo.modules.loading: Could not load module module_error",
            "ERROR odoo.modules.loading: ModuleNotFoundError: No module named "
            "'missing_dependency'",
            "ERROR odoo.modules.loading: Failed to install module module_error",
        ],
        "stderr": "ModuleNotFoundError: No module named 'missing_dependency'",
    },
    "module_warning": {
        "status": "warning",
        "warnings": ["Deprecated API usage detected"],
        "install_time": 3.0,
        "description": "Succeeds with warnings",
        "log_stream": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: loading 1 modules...",
            "INFO odoo.modules.loading: updating modules list",
            "INFO odoo.modules.loading: Loading module module_warning (1/1)",
            "WARNING odoo.modules.loading: Deprecated API usage detected in "
            "module_warning",
            "INFO odoo.modules.registry: module module_warning: creating or "
            "updating database tables",
            "INFO odoo.modules.loading: Module module_warning loaded in 0.67s",
            "INFO odoo.modules.loading: Modules loaded.",
        ],
    },
    "module_slow": {
        "status": "success",
        "install_time": 15.0,
        "description": "Simulates time-consuming operations",
        "log_stream": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: loading 1 modules...",
            "INFO odoo.modules.loading: updating modules list",
            "INFO odoo.modules.loading: Loading module module_slow (1/1)",
            "INFO odoo.modules.loading: Installing module_slow dependencies...",
            "INFO odoo.modules.loading: Processing large dataset...",
            "INFO odoo.modules.loading: Updating database schema...",
            "INFO odoo.modules.loading: Creating views and data...",
            "INFO odoo.modules.registry: module module_slow: creating or updating "
            "database tables",
            "INFO odoo.modules.loading: Module module_slow loaded in 12.34s",
            "INFO odoo.modules.loading: Modules loaded.",
        ],
    },
    "sale": {
        "status": "success",
        "install_time": 4.2,
        "dependencies": ["base", "product"],
        "description": "Standard Odoo sales module",
        "log_stream": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: loading 66 modules...",
            "INFO odoo.modules.loading: updating modules list",
            "INFO odoo.modules.loading: Loading module sale (63/66)",
            "INFO odoo.modules.registry: module sale: creating or updating "
            "database tables",
            "INFO odoo.modules.loading: loading sale/data/sales_data.xml",
            "INFO odoo.modules.loading: loading sale/security/ir.model.access.csv",
            "INFO odoo.modules.loading: Module sale loaded in 3.21s",
            "INFO odoo.modules.loading: 66 modules loaded in 4.20s",
            "INFO odoo.modules.loading: Modules loaded.",
        ],
    },
    "purchase": {
        "status": "success",
        "install_time": 3.8,
        "dependencies": ["base", "product"],
        "description": "Standard Odoo purchase module",
        "log_stream": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: loading 58 modules...",
            "INFO odoo.modules.loading: updating modules list",
            "INFO odoo.modules.loading: Loading module purchase (45/58)",
            "INFO odoo.modules.registry: module purchase: creating or updating "
            "database tables",
            "INFO odoo.modules.loading: Module purchase loaded in 2.87s",
            "INFO odoo.modules.loading: Modules loaded.",
        ],
    },
    "stock": {
        "status": "success",
        "install_time": 5.1,
        "dependencies": ["base", "product"],
        "description": "Standard Odoo inventory module",
        "log_stream": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: loading 72 modules...",
            "INFO odoo.modules.loading: updating modules list",
            "INFO odoo.modules.loading: Loading module stock (68/72)",
            "INFO odoo.modules.registry: module stock: creating or updating "
            "database tables",
            "INFO odoo.modules.loading: loading stock/data/stock_data.xml",
            "INFO odoo.modules.loading: Module stock loaded in 4.12s",
            "INFO odoo.modules.loading: Modules loaded.",
        ],
    },
    "account": {
        "status": "success",
        "install_time": 6.3,
        "dependencies": ["base"],
        "description": "Standard Odoo accounting module",
        "log_stream": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: loading 84 modules...",
            "INFO odoo.modules.loading: updating modules list",
            "INFO odoo.modules.loading: Loading module account (75/84)",
            "INFO odoo.modules.registry: module account: creating or updating "
            "database tables",
            "INFO odoo.modules.loading: loading account/data/account_data.xml",
            "INFO odoo.modules.loading: loading account/data/"
            "account_chart_template.xml",
            "INFO odoo.modules.loading: Module account loaded in 5.67s",
            "INFO odoo.modules.loading: Modules loaded.",
        ],
    },
    "fastapi_reseller": {
        "status": "error",
        "error_type": "unmet_dependencies",
        "description": "Module with unmet dependencies, simulates dependency errors",
        "log_stream": [
            "INFO odoo: Odoo version 17.0",
            "INFO test_db_17_itcos2 odoo.modules.graph: module fastapi_reseller: "
            "Unmet dependencies: ti4health_shopify",
            "INFO test_db_17_itcos2 odoo.modules.loading: loading 88 modules...",
            "INFO test_db_17_itcos2 odoo.modules.loading: 88 modules loaded in "
            "0.78s, 0 queries (+0 extra)",
            "ERROR test_db_17_itcos2 odoo.modules.loading: Some modules are not "
            "loaded, some dependencies or manifest may be missing: "
            "['fastapi_reseller']",
        ],
        "stderr": "Module dependencies not met",
    },
}

# Test scenarios for different test outcomes
TEST_SCENARIOS = {
    "test_module_pass": {
        "success": True,
        "logs": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: addons paths: ['/opt/odoo/addons', '/custom/addons']",
            "INFO odoo: database: test_db",
            "INFO odoo.service.server: HTTP service running on localhost:8069",
            "INFO test_db odoo.modules.loading: loading 1 modules...",
            "INFO test_db odoo.modules.loading: 1 modules loaded in 0.05s",
            "INFO test_db odoo.modules.loading: loading 45 modules...",
            (
                "INFO test_db odoo.addons.test_module_pass.tests.test_basic: Starting "
                "BasicTestCase.test_create_record ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_pass.tests.test_basic: Starting "
                "BasicTestCase.test_update_record ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_pass.tests.test_basic: Starting "
                "BasicTestCase.test_delete_record ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_pass.tests."
                "test_advanced: Starting "
                "AdvancedTestCase.test_workflow ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_pass.tests."
                "test_advanced: Starting "
                "AdvancedTestCase.test_permissions ..."
            ),
            "INFO test_db odoo.modules.loading: 45 modules loaded in 2.30s",
            "INFO test_db odoo.modules.loading: Modules loaded.",
            "INFO test_db odoo.service.server: Starting post tests",
            "INFO test_db odoo.service.server: 5 post-tests in 0.25s",
            "INFO test_db odoo.tests.stats: test_module_pass: 5 tests 0.89s 32 queries",
            "INFO test_db odoo.tests.result: 0 failed, 0 error(s) of 5 tests",
            "INFO test_db odoo.service.server: Initiating shutdown",
        ],
    },
    "test_module_one_fail": {
        "success": False,
        "logs": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: addons paths: ['/opt/odoo/addons', '/custom/addons']",
            "INFO odoo: database: test_db",
            "INFO odoo.service.server: HTTP service running on localhost:8069",
            "INFO test_db odoo.modules.loading: loading 1 modules...",
            "INFO test_db odoo.modules.loading: 1 modules loaded in 0.05s",
            "INFO test_db odoo.modules.loading: loading 45 modules...",
            (
                "INFO test_db odoo.addons.test_module_one_fail.tests."
                "test_basic: Starting "
                "BasicTestCase.test_create_record ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_one_fail.tests.test_basic: "
                "Starting BasicTestCase.test_update_record ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_one_fail.tests.test_basic: "
                "Starting BasicTestCase.test_delete_record ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_one_fail.tests.test_advanced: "
                "Starting AdvancedTestCase.test_workflow ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_one_fail.tests.test_advanced: "
                "======================================================================"
            ),
            (
                "ERROR test_db odoo.addons.test_module_one_fail.tests.test_advanced: "
                "FAIL: AdvancedTestCase.test_workflow"
            ),
            "Traceback (most recent call last):",
            (
                '  File "/custom/addons/test_module_one_fail/tests/test_advanced.py", '
                "line 45, in test_workflow",
            ),
            "    self.assertEqual(record.state, 'confirmed')",
            "AssertionError: 'draft' != 'confirmed'",
            " ",
            (
                "INFO test_db odoo.addons.test_module_one_fail.tests.test_advanced: "
                "Starting AdvancedTestCase.test_permissions ..."
            ),
            "INFO test_db odoo.modules.loading: 45 modules loaded in 2.45s",
            "INFO test_db odoo.modules.loading: Modules loaded.",
            "INFO test_db odoo.service.server: Starting post tests",
            "INFO test_db odoo.service.server: 5 post-tests in 0.32s",
            (
                "INFO test_db odoo.tests.stats: test_module_one_fail: "
                "5 tests 1.12s 38 queries"
            ),
            (
                "ERROR test_db odoo.tests.result: 1 failed, 0 error(s) of 5 tests "
                "when loading database 'test_db'"
            ),
            "INFO test_db odoo.service.server: Initiating shutdown",
        ],
    },
    "test_module_multi_fail": {
        "success": False,
        "logs": [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: addons paths: ['/opt/odoo/addons', '/custom/addons']",
            "INFO odoo: database: test_db",
            "INFO odoo.service.server: HTTP service running on localhost:8069",
            "INFO test_db odoo.modules.loading: loading 1 modules...",
            "INFO test_db odoo.modules.loading: 1 modules loaded in 0.05s",
            "INFO test_db odoo.modules.loading: loading 45 modules...",
            (
                "INFO test_db odoo.addons.test_module_multi_fail.tests.test_basic: "
                "Starting BasicTestCase.test_create_record ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_multi_fail.tests.test_basic: "
                "Starting BasicTestCase.test_update_record ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_multi_fail.tests.test_basic: "
                "======================================================================"
            ),
            (
                "ERROR test_db odoo.addons.test_module_multi_fail.tests.test_basic: "
                "FAIL: BasicTestCase.test_update_record"
            ),
            "Traceback (most recent call last):",
            (
                '  File "/custom/addons/test_module_multi_fail/tests/test_basic.py", '
                "line 28, in test_update_record",
            ),
            "    self.assertTrue(record.active)",
            "AssertionError: False is not true",
            " ",
            (
                "INFO test_db odoo.addons.test_module_multi_fail.tests.test_basic: "
                "Starting BasicTestCase.test_delete_record ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_multi_fail.tests.test_advanced: "
                "Starting AdvancedTestCase.test_workflow ..."
            ),
            (
                "INFO test_db odoo.addons.test_module_multi_fail.tests.test_advanced: "
                "======================================================================"
            ),
            (
                "ERROR test_db odoo.addons.test_module_multi_fail.tests.test_advanced: "
                "FAIL: AdvancedTestCase.test_workflow"
            ),
            "Traceback (most recent call last):",
            '  File "/custom/addons/test_module_multi_fail/tests/test_advanced.py", line 45, in test_workflow',  # noqa: E501
            "    self.assertEqual(record.state, 'confirmed')",
            "AssertionError: 'draft' != 'confirmed'",
            " ",
            "INFO test_db odoo.addons.test_module_multi_fail.tests.test_advanced: Starting AdvancedTestCase.test_permissions ...",  # noqa: E501
            "INFO test_db odoo.addons.test_module_multi_fail.tests.test_validation: Starting ValidationTestCase.test_email_format ...",  # noqa: E501
            "INFO test_db odoo.addons.test_module_multi_fail.tests.test_validation: ======================================================================",  # noqa: E501
            "ERROR test_db odoo.addons.test_module_multi_fail.tests.test_validation: FAIL: ValidationTestCase.test_email_format",  # noqa: E501
            "Traceback (most recent call last):",
            '  File "/custom/addons/test_module_multi_fail/tests/test_validation.py", line 67, in test_email_format',  # noqa: E501
            (
                "    self.assertRegex(partner.email, "
                "r'^[\\\\w\\\\.-]+@[\\\\w\\\\.-]+\\\\.\\\\w+$')"
            ),
            "AssertionError: Regex didn't match: '^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$' not found in 'invalid-email'",  # noqa: E501
            " ",
            "INFO test_db odoo.modules.loading: 45 modules loaded in 2.67s",
            "INFO test_db odoo.modules.loading: Modules loaded.",
            "INFO test_db odoo.service.server: Starting post tests",
            "INFO test_db odoo.service.server: 6 post-tests in 0.45s",
            "INFO test_db odoo.tests.stats: test_module_multi_fail: 6 tests 1.78s 52 queries",  # noqa: E501
            "ERROR test_db odoo.tests.result: 3 failed, 0 error(s) of 6 tests when loading database 'test_db'",  # noqa: E501
            "INFO test_db odoo.service.server: Initiating shutdown",
        ],
    },
}


class DemoProcessManager(BaseProcessManager):
    """Mock process manager for demo mode that simulates Odoo operations"""

    def __init__(self, available_modules: list[str] | None = None):
        """Initialize with list of available modules"""
        self.available_modules = available_modules or list(DEMO_MODULES.keys())
        self.demo_modules = DEMO_MODULES

    def _stream_logs(self, log_lines: list[str], verbose: bool = False) -> str:
        """Stream log lines progressively with timing like real Odoo"""
        output_lines = []

        if not verbose:
            # In non-verbose mode, just return all logs at once
            return "\n".join(log_lines)

        for _i, line in enumerate(log_lines):
            # Add timestamp prefix like real Odoo
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            pid = "12345"  # Fake PID
            formatted_line = f"{timestamp} {pid} {line}"

            # Print the line in real-time
            print(formatted_line)
            output_lines.append(formatted_line)

            # Add progressive delays to simulate real processing
            if "loading" in line.lower() or "updating" in line.lower():
                time.sleep(0.1)
            elif "error" in line.lower():
                time.sleep(0.2)
            elif "module" in line.lower() and (
                "loaded" in line.lower() or "creating" in line.lower()
            ):
                time.sleep(0.3)
            else:
                time.sleep(0.05)

        return "\n".join(output_lines)

    def _extract_module_name(self, cmd: list[str]) -> str:
        """Extract module name from command line arguments"""
        for i, arg in enumerate(cmd):
            if arg in ["-i", "-u", "--init", "--update"] and i + 1 < len(cmd):
                return cmd[i + 1]
        return "unknown_module"

    def run_command(
        self,
        cmd: list[str],
        stop_on_error: bool = False,
        compact: bool = False,
        verbose: bool = False,
        suppress_output: bool = False,
    ) -> dict[str, Any]:
        """Execute a command in demo mode with simulated behavior"""
        if verbose and not suppress_output:
            print(f"[DEMO] Running command: {' '.join(cmd)}")

        # Simulate module operations (install/update)
        if "-i" in cmd or "-u" in cmd:
            return self._simulate_module_operation(
                cmd, verbose=verbose, suppress_output=suppress_output
            )
        elif "--test-enable" in cmd:
            return self._simulate_test_operation(
                cmd, verbose=verbose, suppress_output=suppress_output
            )
        elif "scaffold" in cmd:
            return self._simulate_scaffold_operation(
                cmd, verbose=verbose, suppress_output=suppress_output
            )
        elif "--i18n-export" in cmd:
            return self._simulate_export_operation(
                cmd, verbose=verbose, suppress_output=suppress_output
            )
        elif "shell" in cmd:
            return self._simulate_shell_operation(
                cmd, verbose=verbose, suppress_output=suppress_output
            )
        else:
            return self._simulate_generic_operation(
                cmd, verbose=verbose, suppress_output=suppress_output
            )

    def run_command_yielding(
        self,
        cmd: list[str],
        stop_on_error: bool = False,
        compact: bool = False,
        verbose: bool = False,
        suppress_output: bool = False,
    ) -> Generator[dict[str, Any], None, None]:
        """Generator version that yields lines as they arrive for demo operations"""
        # For demo purposes, we'll simulate yielding lines by breaking down the
        # operation
        command_str = " ".join(cmd)

        # Start message
        start_msg = f"[DEMO] Starting command: {command_str}"
        yield {"line": start_msg, "process_running": True}

        # Determine operation type and simulate different stages
        if "-i" in cmd or "-u" in cmd:
            # Module install/update operation
            module_name = self._extract_module_name(cmd)
            stages = [
                f"Loading configuration for module: {module_name}",
                "Checking module dependencies...",
                f"Installing/updating module {module_name}...",
                "Running post-installation hooks...",
                f"Module {module_name} installation completed successfully",
            ]
        elif "--test-enable" in cmd:
            # Test operation
            stages = [
                "Setting up test environment...",
                "Loading test database...",
                "Running module tests...",
                "Test results: 5 passed, 0 failed",
                "Test execution completed",
            ]
        elif "scaffold" in cmd:
            # Scaffold operation
            addon_name = cmd[-1] if len(cmd) > 2 else "new_addon"
            stages = [
                f"Creating addon structure for: {addon_name}",
                "Generating manifest file...",
                "Creating Python files...",
                "Creating view files...",
                f"Addon {addon_name} scaffolded successfully",
            ]
        else:
            # Generic operation
            stages = [
                "Initializing operation...",
                "Processing command...",
                "Finalizing...",
                "Operation completed successfully",
            ]

        # Yield each stage
        for stage in stages:
            yield {"line": f"[DEMO] {stage}", "process_running": True}

        # Get final result and yield it
        result = self.run_command(
            cmd, stop_on_error, compact, verbose, suppress_output=True
        )
        yield {"result": result, "process_running": False}

    def _simulate_module_operation(
        self, cmd: list[str], verbose: bool = False, suppress_output: bool = False
    ) -> dict[str, Any]:
        """Simulate module install/update operations with realistic log streaming"""
        # Extract module name and operation type
        module = None
        operation = "unknown"

        for i, arg in enumerate(cmd):
            if arg == "-i" and i + 1 < len(cmd):
                module = cmd[i + 1]
                operation = "install"
                break
            elif arg == "-u" and i + 1 < len(cmd):
                module = cmd[i + 1]
                operation = "update"
                break

        if not module:
            error_log = "ERROR: No module specified for operation"
            if verbose and not suppress_output:
                print(error_log)
            return {
                "success": False,
                "return_code": 1,
                "output": error_log,
                "stderr": "Module name is required",
                "command": " ".join(cmd),
            }

        # Check if module exists in our demo catalog
        if module not in self.demo_modules:
            # Simulate Odoo's "invalid module names, ignored" behavior with streaming
            warning_logs = [
                "INFO odoo: Odoo version 17.0",
                "INFO odoo: loading 1 modules...",
                "INFO odoo.modules.loading: updating modules list",
                f"WARNING odoo.modules.loading: invalid module names, ignored: {module}",  # noqa: E501
                "INFO odoo.modules.loading: Modules loaded.",
            ]

            output = self._stream_logs(warning_logs, verbose and not suppress_output)
            return {
                "success": False,
                "return_code": 0,  # Odoo doesn't exit with error for invalid modules
                "output": output,
                "stderr": "",
                "command": " ".join(cmd),
            }

        module_info = self.demo_modules[module]

        # Simulate processing with log streaming
        if verbose and not suppress_output:
            print(f"[DEMO] Processing {operation} for module: {module}")

        # Get log stream for this module
        log_stream = module_info.get(  # type: ignore[attr-defined]
            "log_stream",
            [
                "INFO odoo: Odoo version 17.0",
                f"INFO odoo.modules.loading: Module {module} processed successfully",
            ],
        )

        # Stream the logs progressively
        output = self._stream_logs(log_stream, verbose and not suppress_output)

        # Generate result based on module status
        status = module_info["status"]  # type: ignore[index]

        if status == "error":
            return {
                "success": False,
                "return_code": 1,
                "output": output,
                "stderr": module_info.get("stderr", f"Module {module} has errors"),  # type: ignore[attr-defined]
                "command": " ".join(cmd),
            }
        elif status == "warning":
            return {
                "success": True,
                "return_code": 0,
                "output": output,
                "stderr": "",
                "command": " ".join(cmd),
            }
        else:  # success
            return {
                "success": True,
                "return_code": 0,
                "output": output,
                "stderr": "",
                "command": " ".join(cmd),
            }

    def _simulate_test_operation(
        self, cmd: list[str], verbose: bool = False, suppress_output: bool = False
    ) -> dict[str, Any]:
        """Simulate test operations with realistic log streaming"""
        # Extract module being tested
        module = None
        for i, arg in enumerate(cmd):
            if arg.startswith("--test-tags") and i + 1 < len(cmd):
                # Extract module from test tags like "/module_name"
                test_tags = cmd[i + 1]
                if test_tags.startswith("/"):
                    module = test_tags[1:]
                break

        if verbose and not suppress_output:
            print(f"[DEMO] Running tests for module: {module or 'all'}")

        # Get predefined test scenarios based on module name
        if module in TEST_SCENARIOS:
            scenario = TEST_SCENARIOS[module]
            test_logs = scenario["logs"].copy()  # type: ignore[attr-defined]

            # Stream the logs progressively (with timestamps for INFO lines)
            output_lines = []
            for line in test_logs:
                if (
                    line.startswith("FAIL:")
                    or line.startswith("Traceback")
                    or line.startswith("  File")
                    or line.startswith("    ")
                    or any(
                        err in line
                        for err in ["AssertionError", "ValueError", "TypeError"]
                    )
                ):
                    # Don't add timestamps to failure details
                    if verbose and not suppress_output:
                        print(line)
                    output_lines.append(line)
                else:
                    # Add timestamp to regular log lines
                    if verbose and not suppress_output:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                        pid = "12345"
                        formatted_line = f"{timestamp} {pid} {line}"
                        print(formatted_line)
                        output_lines.append(formatted_line)
                    else:
                        output_lines.append(line)

                # Add progressive delays for realism
                if "loading" in line.lower() or "Starting" in line:
                    time.sleep(0.05)
                elif "ERROR" in line or "FAIL:" in line:
                    time.sleep(0.2)
                else:
                    time.sleep(0.03)

            output = "\n".join(output_lines)

            return {
                "success": scenario["success"],
                "return_code": 0 if scenario["success"] else 1,
                "output": output,
                "stderr": "",
                "command": " ".join(cmd),
            }
        else:
            # Default test behavior for unknown modules
            test_logs = [
                "INFO odoo: Odoo version 17.0",
                f"INFO odoo.tests.runner: Running tests for {module or 'all modules'}...",  # noqa: E501
                "INFO odoo.tests.runner: test_basic_functionality "
                "(test_module.TestBasic) ... ok",
                "INFO odoo.tests.runner: test_advanced_features "
                "(test_module.TestAdvanced) ... ok",
                "INFO odoo.tests.stats: 2 tests, 2 passed, 0 failed, 0 errors",
                "INFO odoo.tests.result: All tests passed successfully",
            ]

            output = self._stream_logs(test_logs, verbose and not suppress_output)

            return {
                "success": True,
                "return_code": 0,
                "output": output,
                "stderr": "",
                "command": " ".join(cmd),
            }

    def _generate_all_pass_tests(self, module: str | None) -> list[str]:
        """Generate logs for a module with all passing tests"""
        module_name = module or "test_module"
        return [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: addons paths: ['/opt/odoo/addons', '/custom/addons']",
            "INFO odoo: database: test_db",
            "INFO odoo.service.server: HTTP service running on localhost:8069",
            "INFO test_db odoo.modules.loading: loading 1 modules...",
            "INFO test_db odoo.modules.loading: 1 modules loaded in 0.05s",
            "INFO test_db odoo.modules.loading: loading 45 modules...",
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: Starting BasicTestCase.test_create_record ...",  # noqa: E501
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: Starting BasicTestCase.test_update_record ...",  # noqa: E501
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: Starting BasicTestCase.test_delete_record ...",  # noqa: E501
            f"INFO test_db odoo.addons.{module_name}.tests.test_advanced: Starting AdvancedTestCase.test_workflow ...",  # noqa: E501
            f"INFO test_db odoo.addons.{module_name}.tests.test_advanced: Starting AdvancedTestCase.test_permissions ...",  # noqa: E501
            "INFO test_db odoo.modules.loading: 45 modules loaded in 2.30s",
            "INFO test_db odoo.modules.loading: Modules loaded.",
            "INFO test_db odoo.service.server: Starting post tests",
            "INFO test_db odoo.service.server: 5 post-tests in 0.25s",
            f"INFO test_db odoo.tests.stats: {module_name}: 5 tests 0.89s 32 queries",
            "INFO test_db odoo.tests.result: 0 failed, 0 error(s) of 5 tests",
            "INFO test_db odoo.service.server: Initiating shutdown",
        ]

    def _generate_one_fail_tests(self, module: str | None) -> list[str]:
        """Generate logs for a module with one failing test"""
        module_name = module or "test_module"
        return [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: addons paths: ['/opt/odoo/addons', '/custom/addons']",
            "INFO odoo: database: test_db",
            "INFO odoo.service.server: HTTP service running on localhost:8069",
            "INFO test_db odoo.modules.loading: loading 1 modules...",
            "INFO test_db odoo.modules.loading: 1 modules loaded in 0.05s",
            "INFO test_db odoo.modules.loading: loading 45 modules...",
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: Starting BasicTestCase.test_create_record ...",  # noqa: E501
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: Starting BasicTestCase.test_update_record ...",  # noqa: E501
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: Starting BasicTestCase.test_delete_record ...",  # noqa: E501
            f"INFO test_db odoo.addons.{module_name}.tests.test_advanced: Starting AdvancedTestCase.test_workflow ...",  # noqa: E501
            f"INFO test_db odoo.addons.{module_name}.tests.test_advanced: ======================================================================",  # noqa: E501
            f"ERROR test_db odoo.addons.{module_name}.tests.test_advanced: FAIL: AdvancedTestCase.test_workflow",  # noqa: E501
            "Traceback (most recent call last):",
            f'  File "/custom/addons/{module_name}/tests/test_advanced.py", line 45, in test_workflow',  # noqa: E501
            "    self.assertEqual(record.state, 'confirmed')",
            "AssertionError: 'draft' != 'confirmed'",
            " ",
            f"INFO test_db odoo.addons.{module_name}.tests.test_advanced: Starting AdvancedTestCase.test_permissions ...",  # noqa: E501
            "INFO test_db odoo.modules.loading: 45 modules loaded in 2.45s",
            "INFO test_db odoo.modules.loading: Modules loaded.",
            "INFO test_db odoo.service.server: Starting post tests",
            "INFO test_db odoo.service.server: 5 post-tests in 0.32s",
            f"INFO test_db odoo.tests.stats: {module_name}: 5 tests 1.12s 38 queries",
            (
                "ERROR test_db odoo.tests.result: 1 failed, 0 error(s) of 5 tests "
                "when loading database 'test_db'"
            ),
            "INFO test_db odoo.service.server: Initiating shutdown",
        ]

    def _generate_multi_fail_tests(self, module: str | None) -> list[str]:
        """Generate logs for a module with multiple failing tests"""
        module_name = module or "test_module"
        return [
            "INFO odoo: Odoo version 17.0",
            "INFO odoo: addons paths: ['/opt/odoo/addons', '/custom/addons']",
            "INFO odoo: database: test_db",
            "INFO odoo.service.server: HTTP service running on localhost:8069",
            "INFO test_db odoo.modules.loading: loading 1 modules...",
            "INFO test_db odoo.modules.loading: 1 modules loaded in 0.05s",
            "INFO test_db odoo.modules.loading: loading 45 modules...",
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: ",
            "Starting BasicTestCase.test_create_record ...",
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: ",
            "Starting BasicTestCase.test_update_record ...",
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: ",
            "======================================================================",
            f"ERROR test_db odoo.addons.{module_name}.tests.test_basic: ",
            "FAIL: BasicTestCase.test_update_record",
            "Traceback (most recent call last):",
            f'  File "/custom/addons/{module_name}/tests/test_basic.py", line 28, ',
            "in test_update_record",
            "    self.assertTrue(record.active)",
            "AssertionError: False is not true",
            " ",
            f"INFO test_db odoo.addons.{module_name}.tests.test_basic: ",
            "Starting BasicTestCase.test_delete_record ...",
            f"INFO test_db odoo.addons.{module_name}.tests.test_advanced: ",
            "Starting AdvancedTestCase.test_workflow ...",
            f"INFO test_db odoo.addons.{module_name}.tests.test_advanced: ",
            "======================================================================",
            f"ERROR test_db odoo.addons.{module_name}.tests.test_advanced: ",
            "FAIL: AdvancedTestCase.test_workflow",
            "Traceback (most recent call last):",
            f'  File "/custom/addons/{module_name}/tests/test_advanced.py", ',
            "line 45, in test_workflow",
            "    self.assertEqual(record.state, 'confirmed')",
            "AssertionError: 'draft' != 'confirmed'",
            " ",
            f"INFO test_db odoo.addons.{module_name}.tests.test_advanced: ",
            "Starting AdvancedTestCase.test_permissions ...",
            f"INFO test_db odoo.addons.{module_name}.tests.test_validation: ",
            "Starting ValidationTestCase.test_email_format ...",
            f"INFO test_db odoo.addons.{module_name}.tests.test_validation: ",
            "======================================================================",
            f"ERROR test_db odoo.addons.{module_name}.tests.test_validation: ",
            "FAIL: ValidationTestCase.test_email_format",
            "Traceback (most recent call last):",
            f'  File "/custom/addons/{module_name}/tests/test_validation.py", line 67, in test_email_format',  # noqa: E501
            (
                "    self.assertRegex(partner.email, "
                "r'^[\\\\\\\\w\\\\\\\\.-]+@[\\\\\\\\w\\\\\\\\.-]+\\\\\\\\.\\\\\\\\w+$')"
            ),
            "AssertionError: Regex didn't match: '^[\\\\\\\\w\\\\\\\\.-]+@[\\\\\\\\w\\\\\\\\.-]+\\\\\\\\.\\\\\\\\w+$' not found in 'invalid-email'",  # noqa: E501
            " ",
            "INFO test_db odoo.modules.loading: 45 modules loaded in 2.67s",
            "INFO test_db odoo.modules.loading: Modules loaded.",
            "INFO test_db odoo.service.server: Starting post tests",
            "INFO test_db odoo.service.server: 6 post-tests in 0.45s",
            f"INFO test_db odoo.tests.stats: {module_name}: 6 tests 1.78s 52 queries",
            "ERROR test_db odoo.tests.result: 3 failed, 0 error(s) of 6 tests when loading database 'test_db'",  # noqa: E501
            "INFO test_db odoo.service.server: Initiating shutdown",
        ]

    def _simulate_scaffold_operation(
        self, cmd: list[str], verbose: bool = False, suppress_output: bool = False
    ) -> dict[str, Any]:
        """Simulate addon scaffolding"""
        addon_name = None

        # Extract addon name (usually the last argument)
        if len(cmd) > 1:
            addon_name = cmd[-1]

        if verbose and not suppress_output:
            print(f"[DEMO] Creating addon: {addon_name}")

        time.sleep(0.3)

        if addon_name:
            output = (
                f"INFO odoo.tools.scaffold: Creating addon {addon_name}...\n"
                f"INFO odoo.tools.scaffold: Addon {addon_name} created successfully"
            )
            return {
                "success": True,
                "return_code": 0,
                "output": output,
                "stderr": "",
                "command": " ".join(cmd),
            }
        else:
            return {
                "success": False,
                "return_code": 1,
                "output": "ERROR: Addon name is required",
                "stderr": "scaffold command requires addon name",
                "command": " ".join(cmd),
            }

    def _simulate_export_operation(
        self, cmd: list[str], verbose: bool = False, suppress_output: bool = False
    ) -> dict[str, Any]:
        """Simulate language export operations"""
        if verbose and not suppress_output:
            print("[DEMO] Simulating language export...")

        time.sleep(0.2)

        return {
            "success": True,
            "return_code": 0,
            "output": (
                "INFO odoo.tools.translate: Language export completed successfully"
            ),
            "stderr": "",
            "command": " ".join(cmd),
        }

    def _simulate_shell_operation(
        self, cmd: list[str], verbose: bool = False, suppress_output: bool = False
    ) -> dict[str, Any]:
        """Simulate shell operations"""
        if verbose and not suppress_output:
            print("[DEMO] Simulating Odoo shell...")

        return {
            "success": True,
            "return_code": 0,
            "output": (
                "INFO odoo.service.server: Odoo shell ready\n>>> # Demo shell session"
            ),
            "stderr": "",
            "command": " ".join(cmd),
        }

    def _simulate_generic_operation(
        self, cmd: list[str], verbose: bool = False, suppress_output: bool = False
    ) -> dict[str, Any]:
        """Simulate generic Odoo operations"""
        if verbose and not suppress_output:
            print(f"[DEMO] Simulating generic operation: {' '.join(cmd)}")

        time.sleep(0.1)

        return {
            "success": True,
            "return_code": 0,
            "output": "INFO odoo.service: Operation completed successfully",
            "stderr": "",
            "command": " ".join(cmd),
        }

    def run_operation(
        self,
        command_operation: "CommandOperation",
        verbose: bool = False,
        suppress_output: bool = False,
    ) -> dict[str, Any]:
        """Execute a CommandOperation directly in demo mode.

        This provides enhanced result processing with parsing for demo operations.

        Args:
            command_operation: Structured command operation with metadata
            verbose: Enable verbose output
            suppress_output: Suppress output to console

        Returns:
            Dict containing execution results
        """
        from .operation_result import OperationResult

        if verbose and not suppress_output:
            print_info(f"[DEMO] Executing {command_operation.operation_type} operation")

        # Create OperationResult from CommandOperation
        result_builder = OperationResult.from_operation(command_operation)

        try:
            # Execute using regular demo process manager logic
            process_result = self.run_command(
                command_operation.command,
                verbose=verbose,
                suppress_output=suppress_output,
            )

            # Use the enhanced result processing
            if process_result:
                # Get output for parsing
                output = process_result.get("output", "")

                # Set basic result info
                result_builder.set_success(
                    process_result.get("success", False),
                    process_result.get("return_code", 1),
                ).set_output(
                    process_result.get("stdout", output),
                    process_result.get("stderr", ""),
                )

                # Apply automatic parsing based on operation metadata
                result_builder.process_with_parsers(output)

                if "error" in process_result:
                    result_builder.set_error(process_result["error"])
            else:
                result_builder.set_error("Operation execution failed", "ExecutionError")

        except Exception as e:
            result_builder.set_error(
                f"Failed to execute operation: {str(e)}", "OperationError"
            )

        return result_builder.finalize()

    def run_shell_command(
        self,
        cmd: list[str] | str,
        verbose: bool = False,
        capture_output: bool = True,
        suppress_output: bool = False,
    ) -> dict[str, Any]:
        """Simulate shell command execution"""
        if isinstance(cmd, str):
            cmd_list: list[str] = [cmd]
        else:
            cmd_list = cmd
        return self._simulate_shell_operation(
            cmd_list, verbose=verbose, suppress_output=False
        )

    @staticmethod
    def run_interactive_shell(cmd: list[str]) -> int:
        """Simulate interactive shell - just print a message"""
        print("[DEMO] Interactive shell simulation - type 'exit' to quit")
        print(">>> # This is a demo shell. Real Odoo shell would be interactive here.")
        return 0
