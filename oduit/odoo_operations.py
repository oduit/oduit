# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import shutil
import sys
from typing import Any

from manifestoo_core.core_addons import is_core_ce_addon, is_core_ee_addon
from manifestoo_core.odoo_series import OdooSeries

from . import output as _output_module
from .addons_path_manager import AddonsPathManager
from .api_models import (
    AddonInspection,
    AddonInstallState,
    AddonModelInventory,
    AddonsPathStatus,
    AddonTestInventory,
    BinaryProbe,
    DatabaseSummary,
    EnvironmentContext,
    EnvironmentSource,
    FieldSourceLocation,
    InstalledAddonInventory,
    InstalledAddonRecord,
    InstalledModelField,
    InstalledViewExtension,
    ModelExtensionInventory,
    ModelFieldsResult,
    ModelSourceLocation,
    ModelViewInventory,
    ModelViewRecord,
    OdooVersionInfo,
    QueryModelResult,
    RecordReadResult,
    SearchCountResult,
    UpdatePlan,
)
from .builders import (
    ConfigProvider,
    DatabaseCommandBuilder,
    InstallCommandBuilder,
    LanguageCommandBuilder,
    OdooTestCommandBuilder,
    OdooTestCoverageCommandBuilder,
    RunCommandBuilder,
    ShellCommandBuilder,
    UpdateCommandBuilder,
    VersionCommandBuilder,
)
from .demo_process_manager import DemoProcessManager
from .exceptions import (
    ConfigError,
    DatabaseOperationError,
    ModuleInstallError,
    ModuleNotFoundError,
    ModuleUpdateError,
    OdooOperationError,
)
from .module_manager import ModuleManager
from .odoo_query import OdooQuery
from .operation_result import OperationResult
from .output import print_error, print_error_result, print_info
from .process_manager import ProcessManager
from .source_locator import (
    list_addon_models,
    list_addon_tests,
    list_model_extensions,
    locate_field_sources,
    locate_model_sources,
    recommend_tests,
)
from .utils import validate_addon_name


class OdooOperations:
    """High-level operations for managing Odoo instances.

    This class provides a comprehensive interface for performing various Odoo operations
    including server management, module operations, database operations, testing, and
    development tasks. It uses the CommandBuilder pattern and ProcessManager to execute
    operations in both regular and demo modes.

    The class supports both interactive and programmatic usage with flexible output
    formatting (JSON and human-readable) and comprehensive error handling.

    Attributes:
        process_manager: Main ProcessManager instance for executing commands
        _demo_process_manager: Optional DemoProcessManager for demo mode operations

    Example:
        Basic usage for module operations:

        >>> from oduit import OdooOperations, ConfigLoader
        >>> env_config = ConfigLoader.load_config('config.yaml')
        >>> ops = OdooOperations(env_config)
        >>>
        >>> # Install a module
        >>> result = ops.install_module('sale')
        >>> if result['success']:
        >>>     print("Module installed successfully")
        >>>
        >>> # Run tests
        >>> test_result = ops.run_tests(module='sale')
    """

    def __init__(self, env_config: dict, verbose: bool = False):
        from .base_process_manager import BaseProcessManager

        self.result_builder = OperationResult()
        self.verbose = verbose
        self.env_config = env_config
        self._query_helper: OdooQuery | None = None

        self.config = ConfigProvider(env_config)
        if env_config.get("demo_mode", False):
            available_modules = env_config.get("available_modules", [])
            self.process_manager: BaseProcessManager = DemoProcessManager(
                available_modules
            )
        else:
            self.process_manager = ProcessManager()

    def run_odoo(
        self,
        no_http: bool = False,
        dev: str | None = None,
        log_level: str | None = None,
        stop_after_init: bool = False,
    ) -> None:
        """Start the Odoo server with the specified configuration.

        Launches the Odoo server process using the provided environment configuration.
        The server can be started in development mode and with HTTP disabled if needed.
        Supports both regular and demo modes based on the configuration.

        Args:
            no_http (bool, optional): Disable HTTP server during startup.
                Defaults to False.
            dev (str | None, optional): Enable dev mode with specified features
                (e.g., 'all', 'xml'). Defaults to None.

        Returns:
            None: This method handles the server startup process but doesn't
                return a result

        Raises:
            ConfigError: If the environment configuration is invalid or incomplete

        Example:
            >>> env_config = {'python_bin': '/usr/bin/python3',
            ...               'odoo_bin': '/path/to/odoo-bin'}
            >>> ops = OdooOperations(env_config, verbose=True)
            >>> ops.run_odoo()
        """

        if self.verbose:
            print_info("Starting Odoo...")
        dev_mode = dev or self.config.get_optional("dev", False)
        builder = RunCommandBuilder(self.config)

        if no_http:
            builder.disable_http()
        if dev_mode and isinstance(dev_mode, str):
            builder.dev(dev_mode)
        if log_level and isinstance(log_level, str):
            builder.log_level(log_level)

        builder.stop_after_init(stop_after_init)
        try:
            operation = builder.build_operation()
            self.process_manager.run_operation(operation, verbose=self.verbose)

        except ConfigError as e:
            if _output_module._formatter.format_type == "json":
                print_error_result(str(e), 1)
            else:
                print_error(str(e))

    def run_shell(
        self,
        shell_interface: str | None = "python",
        no_http: bool = True,
        compact: bool = False,
        log_level: str | None = None,
    ) -> dict:
        """Start an interactive Odoo shell or execute piped commands.

        Launches an Odoo shell environment for interactive Python code execution
        or command piping. Supports different shell interfaces (python, ipython)
        and handles both TTY (interactive) and piped input modes. In JSON output
        mode, interactive sessions are disabled but piped input is supported.

        Args:
            no_http (bool, optional): Disable HTTP server during shell session.
                Defaults to False.
            shell_interface (str | None, optional): Shell interface to use
                ('python', 'ipython'). Defaults to "python".
            compact (bool, optional): Use compact output format. Defaults to False.
            log_level (str | None, optional): Set Odoo log level. Defaults to None.

        Returns:
            dict: Operation result with success status and command details

        Raises:
            ConfigError: If shell interface is not specified or configuration
                is invalid

        Example:
            >>> ops = OdooOperations(config)
            >>> # Interactive shell
            >>> ops.run_shell(shell_interface='python')
            >>>
            >>> # Piped command
            >>> # echo "print('Hello')" | python script.py
        """
        if _output_module._formatter.format_type == "json" and sys.stdin.isatty():
            print_error_result("Interactive shell not available in JSON mode", 1)
            return {
                "success": False,
                "error": "Interactive shell not available in JSON mode",
            }

        if self.verbose and not compact:
            print_info("Starting Odoo shell...")
        interface = shell_interface or self.config.get_optional(
            "shell_interface", False
        )
        if not interface:
            raise ConfigError(
                "Shell interface must be provided either via --shell-interface "
                "parameter or in the configuration file."
            )

        builder = ShellCommandBuilder(self.config)

        if no_http:
            builder.disable_http()
        if shell_interface:
            builder.shell_interface(shell_interface)
        if compact:
            builder.log_level("warn")
        elif log_level and isinstance(log_level, str):
            builder.log_level(log_level)

        try:
            operation = builder.build_operation()

            # Check if stdin is a TTY (interactive) or piped
            if sys.stdin.isatty():
                # Interactive mode - use PTY handling
                if self.verbose and not compact:
                    print_info(f"Running command: {' '.join(operation.command)}")
                if hasattr(self.process_manager, "run_interactive_shell"):
                    self.process_manager.run_interactive_shell(operation.command)
                    # For interactive shell, create a success result
                    result = {"success": True, "return_code": 0, "output": ""}
                else:
                    # Fallback for demo mode
                    result = self.process_manager.run_operation(
                        operation, verbose=self.verbose
                    )
            else:
                # Piped input - use specialized shell command method
                capture_output = _output_module._formatter.format_type == "json"
                result = self.process_manager.run_shell_command(
                    operation.command,
                    verbose=self.verbose and not compact,
                    capture_output=capture_output,
                )

        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if _output_module._formatter.format_type == "json":
                print_error_result(str(e), 1)
            else:
                print_error(str(e))

        return result

    def update_module(
        self,
        module: str,
        no_http: bool = False,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        compact: bool = False,
        log_level: str | None = None,
        max_cron_threads: int | None = None,
        without_demo: str | bool = False,
        stop_after_init: bool = True,
        i18n_overwrite: bool = False,
        language: str | None = None,
    ) -> dict:
        """Update a module and return operation result

        Args:
            module: Module name to update
            no_http: Disable HTTP server during update
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error
            language: Define language (e.g., 'en_US') for translation updates

        Returns:
            Dictionary with operation result including success status and command.

        Raises:
            ModuleUpdateError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid
        """
        builder = UpdateCommandBuilder(self.config, module)
        if i18n_overwrite:
            builder.i18n_overwrite(True)
        if language and isinstance(language, str):
            builder.load_language(language)

        if no_http:
            builder.disable_http()
        if compact:
            builder.log_level("warn")
        elif log_level and isinstance(log_level, str):
            builder.log_level(log_level)
        if without_demo and isinstance(without_demo, str):
            builder.without_demo(without_demo)
        elif without_demo:
            builder.without_demo(module)
        if max_cron_threads and isinstance(max_cron_threads, int):
            builder.max_cron_threads(max_cron_threads)
        builder.stop_after_init(stop_after_init)

        try:
            # Optional verbose output (if not suppress_output)
            if self.verbose and not suppress_output:
                print_info(f"Updating module: {module}")

            # Execute operation with automatic parsing
            operation = builder.build_operation()
            result = self.process_manager.run_operation(
                operation, verbose=self.verbose, suppress_output=suppress_output
            )

        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        # Raise exception if requested and operation failed
        if raise_on_error and not result.get("success", False):
            raise ModuleUpdateError(
                result.get("error", "Module update failed"),
                operation_result=result,
            )

        return result

    def install_module(
        self,
        module: str,
        verbose: bool = False,
        no_http: bool = False,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        compact: bool = False,
        max_cron_threads: int | None = None,
        log_level: str | None = None,
        without_demo: str | bool = False,
        language: str | None = None,
        with_demo: bool = False,
        stop_after_init: bool = True,
    ) -> dict:
        """Install a module and return operation result

        Args:
            env_config: Environment configuration dictionary
            module: Module name to install
            verbose: Enable verbose output
            no_http: Disable HTTP server during installation
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error
            language: Define language (e.g., 'en_US') for translation installation

        Returns:
            Dictionary with operation result including success status and command.

        Raises:
            ModuleInstallError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid
        """
        # Build command
        builder = InstallCommandBuilder(self.config, module)
        if language and isinstance(language, str):
            builder.load_language(language)
        if no_http:
            builder.disable_http()
        if compact:
            builder.log_level("warn")
        elif log_level and isinstance(log_level, str):
            builder.log_level(log_level)
        if with_demo:
            builder.with_demo(with_demo)
        if without_demo and isinstance(without_demo, str):
            builder.without_demo(without_demo)
        elif without_demo:
            builder.without_demo(module)
        if max_cron_threads and isinstance(max_cron_threads, int):
            builder.max_cron_threads(max_cron_threads)
        builder.stop_after_init(stop_after_init)

        try:
            # Optional verbose output (if not suppress_output)
            if self.verbose and not suppress_output:
                print_info(f"Installing module: {module}")

            # Execute operation with automatic parsing
            operation = builder.build_operation()
            result = self.process_manager.run_operation(
                operation, verbose=verbose, suppress_output=suppress_output
            )

        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        # Raise exception if requested and operation failed
        if raise_on_error and not result.get("success", False):
            raise ModuleInstallError(
                result.get("error", "Module installation failed"),
                operation_result=result,
            )

        return result

    def export_module_language(
        self,
        module: str,
        filename: str,
        language: str,
        no_http: bool = False,
        log_level: str | None = None,
        suppress_output: bool = False,
    ) -> dict:
        """Export language translations for a specific module to a file.

        Exports the language translations for the specified module to a file.
        This is useful for translation management, backup, or distribution of
        language files. The operation uses Odoo's built-in export functionality.

        Args:
            module (str): Name of the module to export translations for
            filename (str): Output filename for the exported language file
            language (str): Language code to export (e.g., 'en_US', 'fr_FR')
            no_http (bool, optional): Disable HTTP server during export.
                Defaults to False.
            log_level (str | None, optional): Set Odoo log level. Defaults to None.

        Returns:
            dict: Operation result with success status and command details

        Raises:
            ConfigError: If the environment configuration is invalid

        Example:
            >>> env_config = {'python_bin': '/usr/bin/python3',
            ...               'odoo_bin': '/path/to/odoo-bin'}
            >>> ops = OdooOperations(env_config)
            >>> ops.export_module_language('sale', 'sale_fr.po', 'fr_FR')
        """
        if self.verbose and not suppress_output:
            print_info(f"Export language {language} to {filename} for module: {module}")
        builder = LanguageCommandBuilder(self.config, module, filename, language)

        if no_http:
            builder.disable_http()
        if log_level and isinstance(log_level, str):
            builder.log_level(log_level)

        try:
            operation = builder.build_operation()
            result = self.process_manager.run_operation(
                operation,
                verbose=self.verbose and not suppress_output,
                suppress_output=suppress_output,
            )

        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if suppress_output:
                return result
            if _output_module._formatter.format_type == "json":
                print_error_result(str(e), 1)
            else:
                print_error(str(e))

        return result

    def run_tests(
        self,
        module: str | None = None,
        stop_on_error: bool = False,
        install: str | None = None,
        update: str | None = None,
        coverage: str | None = None,
        test_file: str | None = None,
        test_tags: str | None = None,
        compact: bool = False,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        log_level: str | None = None,
    ) -> dict:
        """Run tests for a module

        Args:
            module: Module name for testing (optional)
            stop_on_error: Stop execution on first error (optional)
            install: Module to install before testing (optional)
            update: Module to update before testing (optional)
            coverage: Module name to generate coverage report for (optional)
            test_file: Specific test file to run (optional)
            test_tags: Test tags to filter tests (optional)
            compact: Use compact output format (optional)
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error
            log_level: Set Odoo log level (optional)

        Returns:
            Dictionary with operation result including test statistics and failures

        Raises:
            ModuleUpdateError: If raise_on_error=True and operation fails
        """
        if self.verbose and module and not suppress_output:
            print_info(f"Testing module: {module}")

        test_result = None
        coverage_result = None

        builder: OdooTestCoverageCommandBuilder | OdooTestCommandBuilder
        if coverage:
            builder = OdooTestCoverageCommandBuilder(self.config, coverage)
        else:
            builder = OdooTestCommandBuilder(self.config)

        if install:
            builder.test_module(install, install=True)
        elif update:
            builder.test_module(update, install=False)

        if test_file:
            builder.test_file(test_file)
        if test_tags:
            builder.test_tags(test_tags)
        elif coverage and not test_file:
            builder.test_tags(f"/{coverage}")
        elif module and not test_file:
            builder.test_tags(f"/{module}")
        if compact:
            builder.log_level("warn")
        elif log_level and isinstance(log_level, str):
            builder.log_level(log_level)
        builder.workers(0)

        try:
            operation = builder.build_operation()
            test_result = self.process_manager.run_operation(
                operation,
                verbose=self.verbose,
                suppress_output=suppress_output,
            )

            if coverage:
                coverage_bin = self.config.get_required("coverage_bin")

                cmd2 = [coverage_bin, "report", "-m"]
                coverage_result = self.process_manager.run_command(
                    cmd2, verbose=self.verbose, suppress_output=suppress_output
                )

            if not suppress_output and _output_module._formatter.format_type == "json":
                test_success = (
                    test_result.get("success", False) if test_result else False
                )
                test_additional_fields = {
                    "stop_on_error": stop_on_error,
                    "install": install,
                    "update": update,
                    "coverage": coverage,
                    "compact": compact,
                    "verbose": self.verbose,
                    "test_success": test_success,
                }

                if coverage_result is not None:
                    coverage_success = (
                        coverage_result.get("success", False)
                        if coverage_result
                        else False
                    )
                    test_additional_fields["coverage_success"] = coverage_success

                    overall_success = (
                        test_result.get("success", False) if test_result else False
                    ) and (
                        coverage_result.get("success", False)
                        if coverage_result
                        else True
                    )
                    test_additional_fields["success"] = overall_success

                if test_result:
                    test_result.update(test_additional_fields)

        except ConfigError as e:
            test_result = {
                "success": False,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        final_result = test_result or {
            "success": False,
            "error": "Test execution failed",
        }

        if raise_on_error and not final_result.get("success", False):
            raise ModuleUpdateError(
                final_result.get("error", "Module test failed"),
                operation_result=final_result,
            )

        return final_result

    def db_exists(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        db_user: str | None = None,
    ) -> dict:
        """Check if database exists and return operation result

        Args:
            with_sudo: Use sudo for database operations (default True)
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error
            db_user: Database user to connect as (optional)

        Returns:
            Dictionary with operation result including success status, exists flag,
            and command details. The 'exists' key indicates if database exists.

        Raises:
            DatabaseOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid

        Example:
            >>> ops = OdooOperations(config)
            >>> result = ops.db_exists()
            >>> if result['exists']:
            >>>     print("Database exists")
        """
        db_name = self.config.get_optional("db_name", "unknown")

        builder = DatabaseCommandBuilder(self.config, with_sudo=with_sudo)
        exists_operation = builder.exists_db_command(db_user=db_user).build_operation()

        try:
            if self.verbose and not suppress_output:
                print_info(f"Checking if database exists: {db_name}")

            exists_result = self.process_manager.run_operation(
                exists_operation, verbose=self.verbose
            )

            stdout = exists_result.get("stdout", "") if exists_result else ""
            exists = stdout.strip() == "1"
            check_success = (
                exists_result.get("success", False) if exists_result else False
            )

            final_result = {
                "success": check_success,
                "exists": exists,
                "return_code": exists_result.get("return_code", 1)
                if exists_result
                else 1,
                "command": exists_operation.command,
                "operation": "exists_db",
                "database": db_name,
            }

            if exists_result:
                final_result.update(
                    {
                        "stdout": exists_result.get("stdout", ""),
                        "stderr": exists_result.get("stderr", ""),
                    }
                )
                if exists_result.get("error"):
                    final_result["error"] = exists_result["error"]
                elif not check_success:
                    output = (
                        exists_result.get("stderr") or exists_result.get("stdout") or ""
                    ).strip()
                    if output:
                        final_result["error"] = output

        except ConfigError as e:
            final_result = {
                "success": False,
                "exists": False,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not final_result.get("success", False):
            raise DatabaseOperationError(
                final_result.get("error", "Database exists check operation failed"),
                operation_result=final_result,
            )

        return final_result

    def drop_db(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
    ) -> dict:
        """Drop database and return operation result

        Args:
            with_sudo: Use sudo for database operations (default True)
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error

        Returns:
            Dictionary with operation result including success status and command.

        Raises:
            DatabaseOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid
        """
        db_name = self.config.get_optional("db_name", "unknown")

        builder = DatabaseCommandBuilder(self.config, with_sudo=with_sudo)
        drop_operation = builder.drop_command().build_operation()

        try:
            if self.verbose and not suppress_output:
                print_info(f"Dropping database: {db_name}")

            drop_result = self.process_manager.run_operation(
                drop_operation, verbose=self.verbose
            )

            drop_success = drop_result.get("success", False) if drop_result else False

            final_result = {
                "success": drop_success,
                "return_code": drop_result.get("return_code", 1) if drop_result else 1,
                "command": drop_operation.command,
                "operation": "drop_database",
                "database": db_name,
            }

            if drop_result:
                final_result.update(
                    {
                        "stdout": drop_result.get("stdout", ""),
                        "stderr": drop_result.get("stderr", ""),
                    }
                )

        except ConfigError as e:
            final_result = {
                "success": False,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not final_result.get("success", False):
            raise DatabaseOperationError(
                final_result.get("error", "Database drop operation failed"),
                operation_result=final_result,
            )

        return final_result

    def create_db(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        create_role: bool = False,
        alter_role: bool = False,
        extension: str | None = None,
        raise_on_error: bool = False,
        db_user: str | None = None,
    ) -> dict:
        """Create database and return operation result

        Args:
            with_sudo: Use sudo for database operations (default True)
            suppress_output: Suppress all output (for programmatic use)
            create_role: Create database role before creating database
            alter_role: Alter database role before creating database
            extension: Create extension in database (e.g., 'postgis')
            raise_on_error: Raise exception on failure instead of returning error
            db_user: Database user for role operations (optional)

        Returns:
            Dictionary with operation result including success status and command.

        Raises:
            DatabaseOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid
        """
        db_name = self.config.get_optional("db_name", "unknown")

        create_result = None
        cmd_role = None
        cmd_alter = None
        cmd_extension = None

        builder = DatabaseCommandBuilder(self.config, with_sudo=with_sudo)
        if create_role:
            builder = DatabaseCommandBuilder(self.config, with_sudo=with_sudo)
            cmd_role = builder.create_role_command(db_user=db_user).build()
        if alter_role:
            builder = DatabaseCommandBuilder(self.config, with_sudo=with_sudo)
            cmd_alter = builder.alter_role_command(db_user=db_user).build()
        if extension is not None:
            builder = DatabaseCommandBuilder(self.config, with_sudo=with_sudo)
            cmd_extension = builder.create_extension_command(extension).build()

        builder = DatabaseCommandBuilder(self.config, with_sudo=with_sudo)
        create_operation = builder.create_command().build_operation()

        try:
            if self.verbose and not suppress_output:
                print_info(f"Creating database: {db_name}")

            if cmd_role:
                role_result = self.process_manager.run_command(
                    cmd_role, verbose=self.verbose
                )
                if role_result and not role_result.get("success", False):
                    print_error(
                        f"Warning: Role creation command failed: "
                        f"{role_result.get('stderr', '').strip()}"
                    )
            if cmd_alter:
                alter_result = self.process_manager.run_command(
                    cmd_alter, verbose=self.verbose
                )
                if alter_result and not alter_result.get("success", False):
                    print_error(
                        f"Warning: Role alteration command failed: "
                        f"{alter_result.get('stderr', '').strip()}"
                    )
            if cmd_extension:
                extension_result = self.process_manager.run_command(
                    cmd_extension, verbose=self.verbose
                )
                if extension_result and not extension_result.get("success", False):
                    print_error(
                        f"Warning: Extension creation command failed: "
                        f"{extension_result.get('stderr', '').strip()}"
                    )

            create_result = self.process_manager.run_operation(
                create_operation, verbose=self.verbose
            )

            create_success = (
                create_result.get("success", False) if create_result else False
            )

            create_return_code = (
                create_result.get("return_code", 1) if create_result else 1
            )
            final_result = {
                "success": create_success,
                "return_code": create_return_code,
                "command": create_operation.command,
                "operation": "create_database",
                "database": db_name,
            }

            if create_result:
                final_result.update(
                    {
                        "stdout": create_result.get("stdout", ""),
                        "stderr": create_result.get("stderr", ""),
                    }
                )

        except ConfigError as e:
            final_result = {
                "success": False,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not final_result.get("success", False):
            raise DatabaseOperationError(
                final_result.get("error", "Database operation failed"),
                operation_result=final_result,
            )

        return final_result

    def list_db(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        db_user: str | None = None,
    ) -> dict:
        """List all databases and return operation result

        Args:
            with_sudo: Use sudo for database operations (default True)
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error
            db_user: Database user to connect as (optional)

        Returns:
            Dictionary with operation result including success status and command.

        Raises:
            DatabaseOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid
        """
        builder = DatabaseCommandBuilder(self.config, with_sudo=with_sudo)
        list_operation = builder.list_db_command(db_user=db_user).build_operation()

        try:
            if self.verbose and not suppress_output:
                print_info("Listing databases...")

            list_result = self.process_manager.run_operation(
                list_operation, verbose=self.verbose, suppress_output=suppress_output
            )

            list_success = list_result.get("success", False) if list_result else False

            final_result = {
                "success": list_success,
                "return_code": list_result.get("return_code", 1) if list_result else 1,
                "command": list_operation.command,
                "operation": "list_db",
            }

            if list_result:
                final_result.update(
                    {
                        "stdout": list_result.get("stdout", ""),
                        "stderr": list_result.get("stderr", ""),
                    }
                )

        except ConfigError as e:
            final_result = {
                "success": False,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not final_result.get("success", False):
            error_msg = final_result.get("error", "Database list operation failed")
            if not isinstance(error_msg, str):
                error_msg = str(error_msg)
            raise DatabaseOperationError(
                error_msg,
                operation_result=final_result,
            )

        return final_result

    def create_addon(
        self,
        addon_name: str,
        destination: str | None = None,
        template: str | None = None,
        suppress_output: bool = False,
    ) -> dict:
        """Create a new Odoo addon using the scaffold command.

        Creates a new Odoo addon with basic structure using odoo-bin scaffold.
        The addon name is validated to ensure it follows Odoo naming conventions.
        If no destination is specified, the first path in addons_path is used.

        Args:
            addon_name (str): Name for the new addon (must follow naming conventions)
            destination (str | None, optional): Target directory for the new addon.
                If None, uses first path from addons_path. Defaults to None.
            template (str | None, optional): Template name to use for scaffolding.
                Defaults to None (uses default template).

        Returns:
            dict: Operation result with success status and command details

        Raises:
            ConfigError: If the environment configuration is invalid

        Example:
            >>> env_config = {'python_bin': '/usr/bin/python3',
            ...               'odoo_bin': '/path/to/odoo-bin',
            ...               'addons_path': '/path/to/addons'}
            >>> ops = OdooOperations(env_config)
            >>> result = ops.create_addon('my_custom_module')
            >>> if result['success']:
            ...     print("Addon created successfully")
        """
        if not suppress_output:
            print_info(f"Creating addon: {addon_name}")

        if not validate_addon_name(addon_name):
            error_msg = (
                f"Invalid addon name: {addon_name}. "
                f"Must be lowercase letters, numbers, and underscores only."
            )
            result = {
                "success": False,
                "error": error_msg,
                "error_type": "ValidationError",
            }
            if suppress_output:
                return result
            if _output_module._formatter.format_type == "json":
                print_error_result(error_msg, 1)
            else:
                print_error(error_msg)
            return result

        cmd = [
            self.config.get_required("python_bin"),
            self.config.get_required("odoo_bin"),
            "scaffold",
            addon_name,
        ]

        if destination:
            cmd.append(destination)
        elif self.config.get_required("addons_path"):
            first_addon_path = (
                self.config.get_required("addons_path").split(",")[0].strip()
            )
            cmd.append(first_addon_path)

        if template:
            cmd.extend(["-t", template])

        try:
            result = self.process_manager.run_command(
                cmd,
                verbose=self.verbose and not suppress_output,
                suppress_output=suppress_output,
            )

            if result:
                result.update(
                    {
                        "operation": "create_addon",
                        "addon_name": addon_name,
                        "command": cmd,
                    }
                )
            else:
                result = {"success": False, "error": "Failed to create addon"}

        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if suppress_output:
                return result
            if _output_module._formatter.format_type == "json":
                print_error_result(str(e), 1)
            else:
                print_error(str(e))

        return result

    def get_odoo_version(
        self,
        suppress_output: bool = False,
        raise_on_error: bool = False,
    ) -> dict:
        """Get the Odoo version from odoo-bin

        Args:
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error

        Returns:
            Dictionary with operation result including version string and
            success status. The 'version' key contains the version
            (e.g., '17.0', '18.0').

        Raises:
            OdooOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid

        Example:
            >>> ops = OdooOperations(config)
            >>> result = ops.get_odoo_version()
            >>> if result['success']:
            >>>     print(f"Odoo version: {result['version']}")
        """
        builder = VersionCommandBuilder(self.config)

        try:
            if self.verbose and not suppress_output:
                print_info("Getting Odoo version...")

            operation = builder.build_operation()
            version_result = self.process_manager.run_operation(
                operation, verbose=self.verbose, suppress_output=suppress_output
            )

            version = None
            if version_result and version_result.get("success", False):
                output = version_result.get("stdout", "").strip()
                import re

                match = re.search(r"(\d+\.\d+)", output)
                if match:
                    version = match.group(1)

            final_result = {
                "success": version_result.get("success", False)
                if version_result
                else False,
                "version": version,
                "return_code": version_result.get("return_code", 1)
                if version_result
                else 1,
                "command": operation.command,
                "operation": "get_odoo_version",
            }

            if version_result:
                final_result.update(
                    {
                        "stdout": version_result.get("stdout", ""),
                        "stderr": version_result.get("stderr", ""),
                    }
                )

        except ConfigError as e:
            final_result = {
                "success": False,
                "version": None,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not final_result.get("success", False):
            error_msg = final_result.get("error", "Failed to get Odoo version")
            raise OdooOperationError(
                str(error_msg) if error_msg else "Failed to get Odoo version",
                operation_result=final_result,
            )

        return final_result

    def _get_query_helper(self) -> OdooQuery:
        """Return the shared ``OdooQuery`` helper for this environment."""
        if self._query_helper is None:
            self._query_helper = OdooQuery(self.env_config)
        return self._query_helper

    @staticmethod
    def _probe_binary(configured_value: Any, fallbacks: list[str]) -> BinaryProbe:
        """Resolve a configured or auto-detected binary into a typed probe."""
        configured_text = str(configured_value) if configured_value else None
        if configured_text:
            resolved_path = configured_text
            auto_detected = False
        else:
            resolved_path = None
            auto_detected = False
            for candidate in fallbacks:
                detected = shutil.which(candidate)
                if detected:
                    resolved_path = detected
                    auto_detected = True
                    break

        exists = bool(resolved_path and os.path.exists(resolved_path))
        executable = bool(resolved_path and os.access(resolved_path, os.X_OK))
        return BinaryProbe(
            value=configured_text,
            resolved_path=resolved_path,
            exists=exists,
            executable=executable,
            configured=configured_text is not None,
            auto_detected=auto_detected,
        )

    @staticmethod
    def _build_check(
        name: str,
        status: str,
        message: str,
        details: dict[str, Any] | None = None,
        remediation: str | None = None,
    ) -> dict[str, Any]:
        """Build a doctor-style check entry for programmatic context output."""
        check: dict[str, Any] = {
            "name": name,
            "status": status,
            "message": message,
        }
        if details:
            check["details"] = details
        if remediation:
            check["remediation"] = remediation
        return check

    @staticmethod
    def _get_addon_type(addon_name: str, odoo_series: OdooSeries | None) -> str:
        """Classify an addon as core CE, core EE, or custom."""
        if odoo_series:
            if is_core_ce_addon(addon_name, odoo_series):
                return "core_ce"
            if is_core_ee_addon(addon_name, odoo_series):
                return "core_ee"
        return "custom"

    def _get_module_manager(self) -> ModuleManager:
        """Return a configured module manager for addon-aware operations."""
        addons_path = self.config.get_required("addons_path")
        return ModuleManager(addons_path)

    def get_environment_context(
        self,
        env_name: str | None = None,
        config_source: str | None = None,
        config_path: str | None = None,
        odoo_series: OdooSeries | None = None,
    ) -> EnvironmentContext:
        """Return a typed environment snapshot for planning and inspection.

        Args:
            env_name: Optional display name for the active environment.
            config_source: Optional source description such as ``env`` or ``local``.
            config_path: Optional path to the resolved configuration file.
            odoo_series: Optional pre-detected Odoo series override.

        Returns:
            Typed environment context with resolved binaries, addon paths,
            duplicate modules, and doctor-style summary data.
        """
        env_config = self.env_config
        checks: list[dict[str, Any]] = []
        remediation: list[str] = []
        warnings: list[str] = []

        python_info = self._probe_binary(
            env_config.get("python_bin"), ["python3", "python"]
        )
        odoo_info = self._probe_binary(env_config.get("odoo_bin"), ["odoo", "odoo-bin"])
        coverage_info = self._probe_binary(env_config.get("coverage_bin"), ["coverage"])

        for name, probe, label in (
            ("python_bin", python_info, "python_bin"),
            ("odoo_bin", odoo_info, "odoo_bin"),
            ("coverage_bin", coverage_info, "coverage_bin"),
        ):
            if probe.exists and probe.executable:
                checks.append(
                    self._build_check(
                        name,
                        "ok",
                        f"{label} resolves correctly",
                        details={"resolved_path": probe.resolved_path},
                    )
                )
            else:
                remediation_text = (
                    f"Configure `{label}` so it points to an executable binary."
                )
                checks.append(
                    self._build_check(
                        name,
                        "error" if name != "coverage_bin" else "warning",
                        f"{label} could not be resolved",
                        details={"configured_value": probe.value},
                        remediation=remediation_text,
                    )
                )
                if name != "coverage_bin":
                    remediation.append(remediation_text)
                    warnings.append(f"{label} could not be resolved")

        addons_path = str(env_config.get("addons_path", ""))
        path_manager = AddonsPathManager(addons_path) if addons_path else None
        configured_paths = path_manager.get_configured_paths() if path_manager else []
        base_paths = path_manager.get_base_addons_paths() if path_manager else []
        all_paths = path_manager.get_all_paths() if path_manager else []
        valid_paths: list[str] = []
        invalid_paths: list[str] = []
        for path in configured_paths:
            absolute_path = os.path.abspath(path)
            if os.path.isdir(absolute_path):
                valid_paths.append(absolute_path)
            else:
                invalid_paths.append(path)

        if invalid_paths:
            remediation_text = (
                "Fix `addons_path` so every configured path exists and is a directory."
            )
            checks.append(
                self._build_check(
                    "addons_path",
                    "error",
                    f"Configured addons paths are invalid: {', '.join(invalid_paths)}",
                    details={"invalid_paths": invalid_paths},
                    remediation=remediation_text,
                )
            )
            remediation.append(remediation_text)
            warnings.append("Configured addons paths contain invalid entries")
        elif configured_paths:
            checks.append(
                self._build_check(
                    "addons_path",
                    "ok",
                    f"Configured addons paths are valid ({len(valid_paths)} path(s))",
                    details={"configured_paths": valid_paths},
                )
            )
        else:
            remediation_text = (
                "Set `addons_path` before running addon inspection commands."
            )
            checks.append(
                self._build_check(
                    "addons_path",
                    "error",
                    "addons_path is not configured",
                    remediation=remediation_text,
                )
            )
            remediation.append(remediation_text)

        duplicate_modules = (
            path_manager.find_duplicate_module_names() if path_manager else {}
        )
        if duplicate_modules:
            remediation_text = (
                "Remove or reorder duplicate addon paths to avoid ambiguous "
                "module resolution."
            )
            checks.append(
                self._build_check(
                    "duplicate_addons",
                    "warning",
                    "Duplicate addon names found: "
                    f"{', '.join(sorted(duplicate_modules))}",
                    details={"duplicates": duplicate_modules},
                    remediation=remediation_text,
                )
            )
            remediation.append(remediation_text)
            warnings.append("Duplicate addon names found")

        module_manager = (
            ModuleManager(addons_path) if addons_path and not invalid_paths else None
        )
        available_module_count = 0
        detected_series = odoo_series
        if module_manager is not None:
            modules = module_manager.find_modules(skip_invalid=True)
            available_module_count = len(modules)
            checks.append(
                self._build_check(
                    "addons_scan",
                    "ok",
                    f"Discovered {available_module_count} addon(s)",
                    details={"module_count": available_module_count},
                )
            )
            if detected_series is None:
                detected_series = module_manager.detect_odoo_series()

        version_result = self.get_odoo_version(suppress_output=True)
        if version_result.get("success") and version_result.get("version"):
            checks.append(
                self._build_check(
                    "odoo_version",
                    "ok",
                    f"Detected Odoo version {version_result['version']}",
                    details={"version": version_result.get("version")},
                )
            )
        else:
            remediation_text = (
                "Check `odoo_bin` and inspect the version command output."
            )
            checks.append(
                self._build_check(
                    "odoo_version",
                    "error",
                    "Failed to detect Odoo version",
                    details={"error": version_result.get("error")},
                    remediation=remediation_text,
                )
            )
            remediation.append(remediation_text)

        db_name = env_config.get("db_name")
        db_user = env_config.get("db_user")
        if db_name:
            status = "ok" if db_user else "warning"
            remediation_text = (
                "Set `db_user` if the default PostgreSQL user is not correct."
            )
            checks.append(
                self._build_check(
                    "db_config",
                    status,
                    f"Database configuration is present for '{db_name}'",
                    details={
                        "db_name": db_name,
                        "db_host": env_config.get("db_host") or "localhost",
                        "db_user": db_user,
                    },
                    remediation=None if db_user else remediation_text,
                )
            )
            if not db_user:
                remediation.append(remediation_text)
                warnings.append("db_user is not configured")
        else:
            checks.append(
                self._build_check(
                    "db_config",
                    "warning",
                    "db_name is not configured",
                    remediation=(
                        "Set `db_name` if this environment should target a database."
                    ),
                )
            )

        summary = {
            "ok": sum(1 for check in checks if check["status"] == "ok"),
            "warning": sum(1 for check in checks if check["status"] == "warning"),
            "error": sum(1 for check in checks if check["status"] == "error"),
        }

        return EnvironmentContext(
            environment=EnvironmentSource(
                name=env_name,
                source=config_source,
                config_path=config_path,
            ),
            resolved_binaries={
                "python_bin": python_info,
                "odoo_bin": odoo_info,
                "coverage_bin": coverage_info,
            },
            addons_paths=AddonsPathStatus(
                configured=configured_paths,
                base=base_paths,
                all=all_paths,
                valid=valid_paths,
                invalid=invalid_paths,
            ),
            odoo=OdooVersionInfo(
                version=version_result.get("version"),
                series=detected_series.value if detected_series else None,
            ),
            database=DatabaseSummary(
                db_name=db_name,
                db_host=env_config.get("db_host") or "localhost",
                db_user=db_user,
            ),
            duplicate_modules=duplicate_modules,
            available_module_count=available_module_count,
            invalid_addon_paths=invalid_paths,
            missing_critical_config=[
                key
                for key in ("python_bin", "odoo_bin", "addons_path")
                if not env_config.get(key)
            ],
            doctor_summary=summary,
            doctor_checks=checks,
            warnings=list(dict.fromkeys(warnings)),
            remediation=list(dict.fromkeys(remediation)),
        )

    def inspect_addon(
        self,
        module_name: str,
        odoo_series: OdooSeries | None = None,
    ) -> AddonInspection:
        """Return a typed inspection payload for one addon.

        Raises:
            ModuleNotFoundError: If the module cannot be found in ``addons_path``.
        """
        addons_path = self.config.get_optional("addons_path")
        module_manager = ModuleManager(str(addons_path or ""))
        detected_series = odoo_series or module_manager.detect_odoo_series()
        manifest = module_manager.get_manifest(module_name)
        if manifest is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )

        warnings: list[str] = []
        remediation: list[str] = []
        reverse_dependencies = module_manager.get_reverse_dependencies(module_name)
        raw_data = manifest.get_raw_data()

        try:
            missing_dependencies = module_manager.find_missing_dependencies(module_name)
        except ValueError as exc:
            missing_dependencies = []
            warnings.append(str(exc))

        dependency_cycle: list[str] = []
        try:
            install_order = module_manager.get_install_order(module_name)
        except ValueError as exc:
            install_order = []
            warnings.append(str(exc))
            dependency_cycle = module_manager.parse_cycle_error(str(exc))
            if dependency_cycle:
                remediation.append(
                    "Break the dependency cycle before attempting installation "
                    "or update."
                )

        if missing_dependencies:
            remediation.append(
                "Resolve missing dependencies before attempting installation or update."
            )

        return AddonInspection(
            module=module_name,
            exists=True,
            module_path=module_manager.find_module_path(module_name),
            addon_type=self._get_addon_type(module_name, detected_series),
            version_display=module_manager.get_module_version_display(
                module_name, detected_series
            ),
            manifest=raw_data,
            manifest_fields=sorted(raw_data.keys()),
            direct_dependencies=manifest.codependencies,
            reverse_dependencies=reverse_dependencies,
            reverse_dependency_count=len(reverse_dependencies),
            install_order_slice=install_order,
            install_order_available=bool(install_order),
            dependency_cycle=dependency_cycle,
            missing_dependencies=missing_dependencies,
            impacted_modules=reverse_dependencies,
            series=detected_series.value if detected_series else None,
            python_dependencies=manifest.python_dependencies,
            binary_dependencies=manifest.binary_dependencies,
            warnings=warnings,
            remediation=list(dict.fromkeys(remediation)),
        )

    def plan_update(
        self,
        module_name: str,
        odoo_series: OdooSeries | None = None,
    ) -> UpdatePlan:
        """Return a typed, read-only update plan for one addon."""
        inspection = self.inspect_addon(module_name, odoo_series=odoo_series)
        addons_path = self.config.get_required("addons_path")
        duplicate_modules = AddonsPathManager(addons_path).find_duplicate_module_names()
        duplicate_name_risk = module_name in duplicate_modules
        reverse_dependency_count = inspection.reverse_dependency_count
        missing_dependencies = list(inspection.missing_dependencies)
        dependency_cycle = list(inspection.dependency_cycle)

        risk_factors: list[str] = []
        risk_score = 0
        if reverse_dependency_count:
            risk_score += min(reverse_dependency_count * 10, 40)
            risk_factors.append(
                f"{reverse_dependency_count} reverse dependencies would be affected"
            )
        if missing_dependencies:
            risk_score += min(len(missing_dependencies) * 20, 30)
            risk_factors.append("module has missing dependencies")
        if duplicate_name_risk:
            risk_score += 20
            risk_factors.append("module name is duplicated across addons paths")
        if dependency_cycle:
            risk_score += 30
            risk_factors.append("dependency graph contains a cycle")
        if inspection.addon_type == "custom":
            risk_score += 10
            risk_factors.append(
                "custom addon changes should be validated in the target DB"
            )

        risk_level = "low"
        if risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 20:
            risk_level = "medium"

        backup_advised = reverse_dependency_count > 0 or duplicate_name_risk
        verification_steps = [
            f"Run targeted tests for `{module_name}` before and after the update.",
            f"Inspect reverse dependencies for `{module_name}` before "
            "updating dependent addons.",
        ]
        if inspection.reverse_dependencies:
            verification_steps.append(
                "Retest at least one impacted reverse dependency after the update."
            )

        remediation = list(inspection.remediation)
        if backup_advised:
            remediation.append(
                "Take a database backup before updating this module in a "
                "shared environment."
            )

        return UpdatePlan(
            module=module_name,
            exists=True,
            impact_set=list(inspection.reverse_dependencies),
            impact_count=reverse_dependency_count,
            missing_dependencies=missing_dependencies,
            duplicate_name_risk=duplicate_name_risk,
            duplicate_module_locations=duplicate_modules.get(module_name, []),
            dependency_cycle=dependency_cycle,
            cycle_risk=bool(dependency_cycle),
            ordering_constraints=list(inspection.install_order_slice),
            recommended_sequence=[
                "Review dependency and duplicate-module warnings.",
                *(
                    ["Take a database backup."]
                    if backup_advised
                    else ["A dedicated backup is optional for this change."]
                ),
                f"Update `{module_name}`.",
                "Run targeted validation and tests.",
            ],
            backup_advised=backup_advised,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            verification_steps=verification_steps,
            inspection=inspection,
            warnings=list(dict.fromkeys(inspection.warnings)),
            remediation=list(dict.fromkeys(remediation)),
        )

    def inspect_addons(
        self,
        module_names: list[str],
        odoo_series: OdooSeries | None = None,
    ) -> list[AddonInspection]:
        """Return typed inspection payloads for multiple addons."""
        return [
            self.inspect_addon(module_name, odoo_series=odoo_series)
            for module_name in module_names
        ]

    def locate_model(
        self,
        module_name: str,
        model: str,
    ) -> ModelSourceLocation:
        """Return static source candidates for a model extension."""
        module_manager = self._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return locate_model_sources(addon_root, module_name, model)

    def locate_field(
        self,
        module_name: str,
        model: str,
        field_name: str,
    ) -> FieldSourceLocation:
        """Return static field source candidates inside one addon."""
        module_manager = self._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return locate_field_sources(addon_root, module_name, model, field_name)

    def list_addon_tests(
        self,
        module_name: str,
        model: str | None = None,
        field_name: str | None = None,
    ) -> AddonTestInventory:
        """Return likely addon test files for one addon."""
        module_manager = self._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return list_addon_tests(
            addon_root, module_name, model=model, field_name=field_name
        )

    def list_addon_models(self, module_name: str) -> AddonModelInventory:
        """Return a static model inventory for one addon."""
        module_manager = self._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return list_addon_models(addon_root, module_name)

    def recommend_tests(
        self,
        module_name: str,
        paths: list[str],
    ) -> dict[str, Any]:
        """Return changed-file to test recommendations for one addon."""
        module_manager = self._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return recommend_tests(addon_root, module_name, paths).to_dict()

    def find_model_extensions(
        self,
        model: str,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> ModelExtensionInventory:
        """Return combined source and installed metadata for one model."""
        addons_path = self.config.get_required("addons_path")
        inventory = list_model_extensions(addons_path, model)

        field_result = self.query_model(
            "ir.model.fields",
            domain=[["model", "=", model]],
            fields=["name", "ttype", "relation", "modules", "state"],
            limit=500,
            database=database,
            timeout=timeout,
        )
        if field_result.success:
            inventory.installed_fields = [
                InstalledModelField(
                    name=str(record.get("name", "")),
                    ttype=str(record.get("ttype", "")),
                    relation=(
                        str(record["relation"])
                        if isinstance(record.get("relation"), str)
                        else None
                    ),
                    modules=(
                        str(record["modules"])
                        if isinstance(record.get("modules"), str)
                        else None
                    ),
                    state=(
                        str(record["state"])
                        if isinstance(record.get("state"), str)
                        else None
                    ),
                )
                for record in field_result.records
                if record.get("name")
            ]
        elif field_result.error:
            inventory.warnings.append(
                f"Failed to query installed field metadata: {field_result.error}"
            )

        view_result = self.query_model(
            "ir.ui.view",
            domain=[["model", "=", model], ["inherit_id", "!=", False]],
            fields=["name", "key", "priority", "inherit_id"],
            limit=200,
            database=database,
            timeout=timeout,
        )
        if view_result.success:
            inventory.installed_view_extensions = [
                InstalledViewExtension(
                    name=str(record.get("name", "")),
                    key=(
                        str(record["key"])
                        if isinstance(record.get("key"), str)
                        else None
                    ),
                    priority=(
                        int(record["priority"])
                        if isinstance(record.get("priority"), int)
                        and not isinstance(record.get("priority"), bool)
                        else None
                    ),
                    inherit_id=(
                        list(record["inherit_id"])
                        if isinstance(record.get("inherit_id"), list)
                        else None
                    ),
                )
                for record in view_result.records
                if record.get("name")
            ]
        elif view_result.error:
            inventory.warnings.append(
                f"Failed to query installed view metadata: {view_result.error}"
            )

        declared_modules = {item.module for item in inventory.base_declarations}
        inventory.installed_extension_fields = [
            field
            for field in inventory.installed_fields
            if field.modules and field.modules not in declared_modules
        ]
        inventory.installed_extension_modules = sorted(
            {
                field.modules
                for field in inventory.installed_extension_fields
                if field.modules
            }
        )
        inventory.warnings = sorted(dict.fromkeys(inventory.warnings))
        return inventory

    def list_duplicates(self) -> dict[str, list[str]]:
        """Return duplicate module names across configured addon paths."""
        addons_path = self.config.get_required("addons_path")
        return AddonsPathManager(addons_path).find_duplicate_module_names()

    def list_addons_inventory(
        self,
        module_names: list[str],
        odoo_series: OdooSeries | None = None,
    ) -> list[dict[str, Any]]:
        """Return structured addon inventory records."""
        module_manager = self._get_module_manager()
        duplicates = self.list_duplicates()
        detected_series = odoo_series or module_manager.detect_odoo_series()
        inventory: list[dict[str, Any]] = []
        for module_name in module_names:
            manifest = module_manager.get_manifest(module_name)
            if manifest is None:
                continue
            raw_data = manifest.get_raw_data()
            inventory.append(
                {
                    "module": module_name,
                    "module_path": module_manager.find_module_path(module_name),
                    "addon_type": self._get_addon_type(module_name, detected_series),
                    "version": manifest.version,
                    "summary": manifest.summary,
                    "author": manifest.author,
                    "category": raw_data.get("category"),
                    "license": manifest.license,
                    "depends": list(manifest.codependencies),
                    "python_dependencies": list(manifest.python_dependencies),
                    "binary_dependencies": list(manifest.binary_dependencies),
                    "duplicate_name": module_name in duplicates,
                    "duplicate_locations": duplicates.get(module_name, []),
                }
            )
        return inventory

    @staticmethod
    def _normalize_optional_bool(value: Any) -> bool | None:
        """Normalize Odoo truthy values into optional booleans."""
        if value is None:
            return None
        return bool(value)

    @classmethod
    def _normalize_installed_addon_record(
        cls,
        record: dict[str, Any],
    ) -> InstalledAddonRecord:
        """Normalize one ``ir.module.module`` record into the public shape."""
        state = str(record.get("state") or "uninstalled")
        return InstalledAddonRecord(
            module=str(record.get("name") or ""),
            state=state,
            installed=state == "installed",
            shortdesc=(
                str(record["shortdesc"])
                if isinstance(record.get("shortdesc"), str)
                else None
            ),
            application=cls._normalize_optional_bool(record.get("application")),
            auto_install=cls._normalize_optional_bool(record.get("auto_install")),
        )

    def get_addon_install_state(
        self,
        module: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> AddonInstallState:
        """Return the runtime install state for one addon."""
        result = self.query_model(
            "ir.module.module",
            domain=[["name", "=", module]],
            fields=["name", "state"],
            limit=1,
            database=database,
            timeout=timeout,
        )
        if not result.success:
            return AddonInstallState(
                success=False,
                operation="get_addon_install_state",
                module=module,
                database=result.database,
                error=result.error,
                error_type=result.error_type,
            )

        record = result.records[0] if result.records else {}
        state = str(record.get("state") or "uninstalled")
        return AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module=module,
            record_found=bool(result.records),
            state=state,
            installed=state == "installed",
            database=result.database,
        )

    def list_installed_addons(
        self,
        *,
        modules: list[str] | None = None,
        states: list[str] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> InstalledAddonInventory:
        """Return runtime addon inventory from ``ir.module.module``."""
        modules_filter = list(dict.fromkeys(modules or []))
        states_filter = list(dict.fromkeys(states or ["installed"]))
        domain: list[list[Any]] = [["state", "in", states_filter]]
        if modules_filter:
            domain.append(["name", "in", modules_filter])

        result = self.query_model(
            "ir.module.module",
            domain=domain,
            fields=["name", "state", "shortdesc", "application", "auto_install"],
            limit=500,
            database=database,
            timeout=timeout,
        )
        if not result.success:
            return InstalledAddonInventory(
                success=False,
                operation="list_installed_addons",
                states=states_filter,
                modules_filter=modules_filter,
                database=result.database,
                error=result.error,
                error_type=result.error_type,
                remediation=[
                    "Verify database access and retry the runtime addon inventory "
                    "query."
                ],
            )

        addons = sorted(
            (
                self._normalize_installed_addon_record(record)
                for record in result.records
            ),
            key=lambda addon: addon.module,
        )
        return InstalledAddonInventory(
            success=True,
            operation="list_installed_addons",
            addons=addons,
            total=len(addons),
            states=states_filter,
            modules_filter=modules_filter,
            database=result.database,
        )

    def dependency_graph(self, module_names: list[str]) -> dict[str, Any]:
        """Return dependency graph data for one or more addons."""
        module_manager = self._get_module_manager()
        graph: dict[str, set[str]] = {}
        missing_dependencies: dict[str, list[str]] = {}
        cycle: list[str] = []
        warnings: list[str] = []

        for module_name in module_names:
            try:
                subgraph = module_manager.build_dependency_graph(module_name)
                for graph_module, dependencies in subgraph.items():
                    graph.setdefault(graph_module, set()).update(dependencies)
            except ValueError as exc:
                warnings.append(str(exc))
                parsed_cycle = module_manager.parse_cycle_error(str(exc))
                if parsed_cycle:
                    cycle = parsed_cycle
            missing_dependencies[module_name] = (
                module_manager.find_missing_dependencies(module_name)
            )

        nodes = sorted(graph)
        edges = [
            {"source": module_name, "target": dependency}
            for module_name in sorted(graph)
            for dependency in sorted(graph[module_name])
        ]
        install_order: list[str] = []
        if not cycle:
            try:
                install_order = module_manager.sort_modules(nodes, "topological")
            except ValueError as exc:
                warnings.append(str(exc))
                parsed_cycle = module_manager.parse_cycle_error(str(exc))
                if parsed_cycle:
                    cycle = parsed_cycle

        return {
            "modules": module_names,
            "nodes": nodes,
            "edges": edges,
            "missing_dependencies": missing_dependencies,
            "cycles": [cycle] if cycle else [],
            "install_order": install_order,
            "warnings": warnings,
        }

    def query_model(
        self,
        model: str,
        domain: list[Any] | tuple[Any, ...] | None = None,
        fields: list[str] | tuple[str, ...] | None = None,
        limit: int = 80,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> QueryModelResult:
        """Delegate typed read-only model queries to ``OdooQuery``."""
        return QueryModelResult.from_dict(
            self._get_query_helper().query_model(
                model,
                domain=domain,
                fields=fields,
                limit=limit,
                database=database,
                timeout=timeout,
            )
        )

    def read_record(
        self,
        model: str,
        record_id: int,
        fields: list[str] | tuple[str, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> RecordReadResult:
        """Delegate typed single-record reads to ``OdooQuery``."""
        return RecordReadResult.from_dict(
            self._get_query_helper().read_record(
                model,
                record_id,
                fields=fields,
                database=database,
                timeout=timeout,
            )
        )

    def search_count(
        self,
        model: str,
        domain: list[Any] | tuple[Any, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> SearchCountResult:
        """Delegate typed count queries to ``OdooQuery``."""
        return SearchCountResult.from_dict(
            self._get_query_helper().search_count(
                model,
                domain=domain,
                database=database,
                timeout=timeout,
            )
        )

    def get_model_fields(
        self,
        model: str,
        attributes: list[str] | tuple[str, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> ModelFieldsResult:
        """Delegate typed field metadata queries to ``OdooQuery``."""
        return ModelFieldsResult.from_dict(
            self._get_query_helper().get_model_fields(
                model,
                attributes=attributes,
                database=database,
                timeout=timeout,
            )
        )

    def get_model_views(
        self,
        model: str,
        view_types: list[str] | tuple[str, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
        include_arch: bool = True,
    ) -> ModelViewInventory:
        """Return primary and extension DB views for one model."""
        fields = ["name", "type", "mode", "priority", "inherit_id", "key", "active"]
        if include_arch:
            fields.append("arch_db")

        result = self.query_model(
            "ir.ui.view",
            domain=[["model", "=", model]],
            fields=fields,
            limit=500,
            database=database,
            timeout=timeout,
        )
        warnings: list[str] = []
        remediation: list[str] = []
        requested_types = list(view_types or [])

        if not result.success:
            return ModelViewInventory(
                model=model,
                requested_types=requested_types,
                database=database,
                error=result.error,
                error_type=result.error_type,
                warnings=(
                    [f"Failed to query model views: {result.error}"]
                    if result.error
                    else warnings
                ),
                remediation=(
                    [
                        "Verify database access and model name, then retry the "
                        "view query."
                    ]
                    if result.error
                    else remediation
                ),
            )

        normalized_types = {value for value in requested_types}
        records: list[ModelViewRecord] = []
        for record in result.records:
            raw_type = record.get("type")
            if not isinstance(raw_type, str):
                continue
            if normalized_types and raw_type not in normalized_types:
                continue

            raw_inherit_id = record.get("inherit_id")
            inherit_id = (
                list(raw_inherit_id) if isinstance(raw_inherit_id, list) else None
            )
            records.append(
                ModelViewRecord(
                    id=int(record.get("id", 0) or 0),
                    name=str(record.get("name", "")),
                    view_type=raw_type,
                    mode=(
                        str(record["mode"])
                        if isinstance(record.get("mode"), str)
                        else None
                    ),
                    priority=(
                        int(record["priority"])
                        if isinstance(record.get("priority"), int)
                        and not isinstance(record.get("priority"), bool)
                        else None
                    ),
                    inherit_id=inherit_id,
                    key=(
                        str(record["key"])
                        if isinstance(record.get("key"), str)
                        else None
                    ),
                    active=(
                        bool(record["active"])
                        if isinstance(record.get("active"), bool)
                        else None
                    ),
                    arch_db=(
                        str(record["arch_db"])
                        if isinstance(record.get("arch_db"), str)
                        else None
                    ),
                )
            )

        records.sort(
            key=lambda item: (
                item.view_type,
                0 if item.mode == "primary" and not item.inherit_id else 1,
                item.priority if item.priority is not None else 9999,
                item.id,
            )
        )
        primary_views = [
            record
            for record in records
            if record.mode == "primary" and not record.inherit_id
        ]
        extension_views = [record for record in records if record not in primary_views]
        view_counts = {
            "total": len(records),
            "primary": len(primary_views),
            "extension": len(extension_views),
        }
        for view_type in sorted(
            {record.view_type for record in records} | normalized_types
        ):
            view_counts[view_type] = sum(
                1 for record in records if record.view_type == view_type
            )

        if not records:
            remediation.append(
                "No views were found for the model in the selected database."
            )

        return ModelViewInventory(
            model=model,
            requested_types=requested_types,
            primary_views=primary_views,
            extension_views=extension_views,
            view_counts=view_counts,
            database=database,
            warnings=warnings,
            remediation=remediation,
        )

    def execute_python_code(
        self,
        python_code: str,
        no_http: bool = True,
        capture_output: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        shell_interface: str | None = None,
        log_level: str | None = None,
    ) -> dict:
        """Execute Python code in the Odoo shell environment

        Args:
            python_code: Python code to execute in Odoo shell
            no_http: Disable HTTP server (default True for shell operations)
            capture_output: Capture output instead of direct terminal output
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error
            shell_interface: Shell interface to use (e.g., 'python', 'ipython')
            log_level: Set Odoo log level (optional)

        Returns:
            Dictionary with operation result including stdout/stderr and success status

        Raises:
            OdooOperationError: If raise_on_error=True and operation fails
        """
        interface = shell_interface or self.config.get_optional(
            "shell_interface", False
        )
        if not interface:
            raise ConfigError(
                "Shell interface must be provided either via --shell-interface "
                "parameter or in the configuration file."
            )
        builder = ShellCommandBuilder(self.config)

        if shell_interface:
            builder.shell_interface(shell_interface)
        if no_http:
            builder.disable_http()
        if log_level and isinstance(log_level, str):
            builder.log_level(log_level)

        try:
            operation = builder.build_operation()

            if self.verbose and not suppress_output:
                print_info("Executing Python code in Odoo shell")
                if self.verbose:
                    print_info(f"Code: {python_code}")

            process_result = self.process_manager.run_shell_command(
                operation.command,
                verbose=self.verbose and not suppress_output,
                capture_output=capture_output,
                input_data=f"{python_code}\n",
            )

            if process_result:
                result = {
                    "success": process_result.get("success", False),
                    "return_code": process_result.get("return_code", 1),
                    "stdout": process_result.get("stdout", ""),
                    "stderr": process_result.get("stderr", ""),
                    "operation": "execute_python_code",
                    "command": operation.command,
                    "python_code": python_code,
                }

                if "error" in process_result:
                    result["error"] = process_result["error"]
            else:
                result = {
                    "success": False,
                    "error": "Failed to execute Python code in shell",
                    "error_type": "ExecutionError",
                }

        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not result.get("success", False):
            raise OdooOperationError(
                result.get("error", "Python code execution failed"),
                operation_result=result,
            )

        return result
