from __future__ import annotations

import sys

from .. import output as _output_module
from ..builders import (
    InstallCommandBuilder,
    LanguageCommandBuilder,
    OdooTestCommandBuilder,
    OdooTestCoverageCommandBuilder,
    RunCommandBuilder,
    ShellCommandBuilder,
    UpdateCommandBuilder,
    VersionCommandBuilder,
)
from ..exceptions import (
    ConfigError,
    ModuleInstallError,
    ModuleUpdateError,
    OdooOperationError,
)
from ..output import print_error, print_error_result, print_info
from .base import OperationsService


class RuntimeOperationsService(OperationsService):
    """Runtime-oriented command execution helpers."""

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

        if self.operations.verbose:
            print_info("Starting Odoo...")
        dev_mode = dev or self.operations.config.get_optional("dev", False)
        builder = RunCommandBuilder(self.operations.config)

        if no_http:
            builder.disable_http()
        if dev_mode and isinstance(dev_mode, str):
            builder.dev(dev_mode)
        if log_level and isinstance(log_level, str):
            builder.log_level(log_level)

        builder.stop_after_init(stop_after_init)
        try:
            operation = builder.build_operation()
            self.operations.process_manager.run_operation(
                operation, verbose=self.operations.verbose
            )

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

        if self.operations.verbose and not compact:
            print_info("Starting Odoo shell...")
        interface = shell_interface or self.operations.config.get_optional(
            "shell_interface", False
        )
        if not interface:
            raise ConfigError(
                "Shell interface must be provided either via --shell-interface "
                "parameter or in the configuration file."
            )

        builder = ShellCommandBuilder(self.operations.config)

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
                if self.operations.verbose and not compact:
                    print_info(f"Running command: {' '.join(operation.command)}")
                if hasattr(self.operations.process_manager, "run_interactive_shell"):
                    self.operations.process_manager.run_interactive_shell(
                        operation.command
                    )
                    # For interactive shell, create a success result
                    result = {"success": True, "return_code": 0, "output": ""}
                else:
                    # Fallback for demo mode
                    result = self.operations.process_manager.run_operation(
                        operation, verbose=self.operations.verbose
                    )
            else:
                # Piped input - use specialized shell command method
                capture_output = _output_module._formatter.format_type == "json"
                result = self.operations.process_manager.run_shell_command(
                    operation.command,
                    verbose=self.operations.verbose and not compact,
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
        builder = UpdateCommandBuilder(self.operations.config, module)
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
            if self.operations.verbose and not suppress_output:
                print_info(f"Updating module: {module}")

            # Execute operation with automatic parsing
            operation = builder.build_operation()
            result = self.operations.process_manager.run_operation(
                operation,
                verbose=self.operations.verbose,
                suppress_output=suppress_output,
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
        builder = InstallCommandBuilder(self.operations.config, module)
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
            if self.operations.verbose and not suppress_output:
                print_info(f"Installing module: {module}")

            # Execute operation with automatic parsing
            operation = builder.build_operation()
            result = self.operations.process_manager.run_operation(
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
        if self.operations.verbose and not suppress_output:
            print_info(f"Export language {language} to {filename} for module: {module}")
        builder = LanguageCommandBuilder(
            self.operations.config, module, filename, language
        )

        if no_http:
            builder.disable_http()
        if log_level and isinstance(log_level, str):
            builder.log_level(log_level)

        try:
            operation = builder.build_operation()
            result = self.operations.process_manager.run_operation(
                operation,
                verbose=self.operations.verbose and not suppress_output,
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
        if self.operations.verbose and module and not suppress_output:
            print_info(f"Testing module: {module}")

        test_result = None
        coverage_result = None

        builder: OdooTestCoverageCommandBuilder | OdooTestCommandBuilder
        if coverage:
            builder = OdooTestCoverageCommandBuilder(self.operations.config, coverage)
        else:
            builder = OdooTestCommandBuilder(self.operations.config)

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
            test_result = self.operations.process_manager.run_operation(
                operation,
                verbose=self.operations.verbose,
                suppress_output=suppress_output,
            )

            if coverage:
                coverage_bin = self.operations.config.get_required("coverage_bin")

                cmd2 = [coverage_bin, "report", "-m"]
                coverage_result = self.operations.process_manager.run_command(
                    cmd2,
                    verbose=self.operations.verbose,
                    suppress_output=suppress_output,
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
                    "verbose": self.operations.verbose,
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
        builder = VersionCommandBuilder(self.operations.config)

        try:
            if self.operations.verbose and not suppress_output:
                print_info("Getting Odoo version...")

            operation = builder.build_operation()
            version_result = self.operations.process_manager.run_operation(
                operation,
                verbose=self.operations.verbose,
                suppress_output=suppress_output,
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
