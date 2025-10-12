# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import sys

from . import output as _output_module
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
)
from .demo_process_manager import DemoProcessManager
from .exceptions import (
    ConfigError,
    DatabaseOperationError,
    ModuleInstallError,
    ModuleUpdateError,
    OdooOperationError,
)
from .operation_result import OperationResult
from .output import print_error, print_error_result, print_info
from .process_manager import ProcessManager
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
        >>> config = ConfigLoader.load_config('config.yaml')
        >>> ops = OdooOperations()
        >>>
        >>> # Install a module
        >>> result = ops.install_module(config, 'sale')
        >>> if result['success']:
        >>>     print("Module installed successfully")
        >>>
        >>> # Run tests
        >>> test_result = ops.run_module_tests(config, 'sale')
    """

    def __init__(self, env_config: dict, verbose: bool = False):
        from .base_process_manager import BaseProcessManager

        self.result_builder = OperationResult()
        self.verbose = verbose

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
            >>> ops = OdooOperations()
            >>> config = {'python_bin': '/usr/bin/python3',
            ...           'odoo_bin': '/path/to/odoo-bin'}
            >>> ops.run_odoo(config, verbose=True)
        """

        if self.verbose:
            print_info("Starting Odoo...")
        dev_mode = dev or self.config.get_optional("dev", False)
        builder = RunCommandBuilder(self.config)

        if no_http:
            builder._remove_http_config()
            builder.no_http(True)
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
            builder._remove_http_config()
            builder.no_http(True)
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
            builder._remove_http_config()
            builder.no_http(True)
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
            builder._remove_http_config()
            builder.no_http(True)
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
            >>> ops = OdooOperations()
            >>> ops.export_module_language(config, 'sale', 'sale_fr.po', 'fr_FR')
        """
        if self.verbose:
            print_info(f"Export language {language} to {filename} for module: {module}")
        builder = LanguageCommandBuilder(self.config, module, filename, language)

        if no_http:
            builder._remove_http_config()
            builder.no_http(True)
        if log_level and isinstance(log_level, str):
            builder.log_level(log_level)

        try:
            operation = builder.build_operation()
            result = self.process_manager.run_operation(operation, verbose=self.verbose)

        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
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

            # grep -qw returns 0 if match found (exists), 1 if not found
            exists = exists_result.get("return_code", 1) == 0
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
    ) -> dict:
        """Create a new Odoo addon using the scaffold command.

        Creates a new Odoo addon with basic structure using odoo-bin scaffold.
        The addon name is validated to ensure it follows Odoo naming conventions.
        If no destination is specified, the first path in addons_path is used.

        Args:
            env_config (dict): Environment configuration dictionary containing
                Odoo settings
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
            >>> ops = OdooOperations()
            >>> result = ops.create_addon(config, 'my_custom_module')
            >>> if result['success']:
            ...     print("Addon created successfully")
        """
        print_info(f"Creating addon: {addon_name}")

        # Validate addon name (basic validation)
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

        # Add destination if provided, otherwise use first addons_path
        if destination:
            cmd.append(destination)
        elif self.config.get_required("addons_path"):
            # Use first path in addons_path
            first_addon_path = (
                self.config.get_required("addons_path").split(",")[0].strip()
            )
            cmd.append(first_addon_path)

        # Add template if provided
        if template:
            cmd.extend(["-t", template])

        try:
            # For scaffold command, we don't have a builder with build_operation() yet
            # So we'll use the legacy approach temporarily
            result = self.process_manager.run_command(cmd)

            # Enhance result with metadata
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
            if _output_module._formatter.format_type == "json":
                print_error_result(str(e), 1)
            else:
                print_error(str(e))

        return result

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
            builder._remove_http_config()
            builder.no_http(True)
        if log_level and isinstance(log_level, str):
            builder.log_level(log_level)

        try:
            operation = builder.build_operation()

            if self.verbose and not suppress_output:
                print_info("Executing Python code in Odoo shell")
                if self.verbose:
                    print_info(f"Code: {python_code}")

            full_command = f'echo "{python_code}" | {" ".join(operation.command)}'

            process_result = self.process_manager.run_shell_command(
                full_command,
                verbose=self.verbose and not suppress_output,
                capture_output=capture_output,
            )

            if process_result:
                result = {
                    "success": process_result.get("success", False),
                    "return_code": process_result.get("return_code", 1),
                    "stdout": process_result.get("stdout", ""),
                    "stderr": process_result.get("stderr", ""),
                    "operation": "execute_python_code",
                    "command": operation.command,
                    "full_command": full_command,
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
