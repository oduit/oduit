from __future__ import annotations

import re
import socket
import sys
from typing import Any

from .. import output as _output_module
from ..builders import (
    CommandOperation,
    ConfigProvider,
    I18nExportCommandBuilder,
    I18nImportCommandBuilder,
    I18nLoadLanguageCommandBuilder,
    InstallCommandBuilder,
    OdooTestCommandBuilder,
    OdooTestCoverageCommandBuilder,
    RunCommandBuilder,
    ShellCommandBuilder,
    UpdateCommandBuilder,
    VersionCommandBuilder,
    odoo_series_major,
)
from ..exceptions import (
    ConfigError,
    ModuleInstallError,
    ModuleUpdateError,
    OdooOperationError,
)
from ..module_manager import ModuleManager
from ..output import print_error, print_error_result, print_info, print_warning
from .base import OperationsService

_ADDRESS_IN_USE_PATTERN = re.compile(r"address already in use", re.IGNORECASE)
_PORT_IN_USE_PATTERN = re.compile(
    r"port\s+(?P<port>\d+)\s+is in use by another program",
    re.IGNORECASE,
)


class RuntimeOperationsService(OperationsService):
    """Runtime-oriented command execution helpers."""

    _TEST_HTTP_PORT_RETRY_LIMIT = 5

    @staticmethod
    def _coerce_http_port(value: Any) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_http_port_conflict(output: str) -> bool:
        return bool(_ADDRESS_IN_USE_PATTERN.search(output)) or bool(
            _PORT_IN_USE_PATTERN.search(output)
        )

    @staticmethod
    def _extract_conflicting_http_port(output: str) -> int | None:
        match = _PORT_IN_USE_PATTERN.search(output)
        if not match:
            return None
        return int(match.group("port"))

    @staticmethod
    def _normalize_odoo_series_label(value: Any | None) -> str | None:
        major = odoo_series_major(value)
        if major is None:
            return None
        return f"{major}.0"

    def _resolve_i18n_odoo_series(self, explicit_odoo_series: Any | None = None) -> Any:
        for candidate in (
            explicit_odoo_series,
            self.operations.config.get_optional("odoo_series"),
        ):
            if odoo_series_major(candidate) is not None:
                return candidate

        addons_path = self.operations.config.get_optional("addons_path")
        if isinstance(addons_path, str) and addons_path.strip():
            detected_series = ModuleManager(addons_path).detect_odoo_series()
            if odoo_series_major(detected_series) is not None:
                return detected_series

        version_result = self.get_odoo_version(suppress_output=True)
        if version_result.get("success", False):
            detected_version = version_result.get("version")
            if odoo_series_major(detected_version) is not None:
                return detected_version

        raise ConfigError(
            "Unable to determine the Odoo series for the i18n command. "
            "Pass --odoo-series 18.0 or --odoo-series 19.0."
        )

    def _run_i18n_operation(
        self,
        operation: CommandOperation,
        *,
        suppress_output: bool,
    ) -> dict[str, Any]:
        result = self.operations.process_manager.run_operation(
            operation,
            verbose=self.operations.verbose and not suppress_output,
            suppress_output=suppress_output,
        )
        result.update(operation.expected_result_fields)
        return result

    @staticmethod
    def _aggregate_import_stdout(sub_results: list[dict[str, Any]]) -> str:
        if len(sub_results) == 1:
            return str(sub_results[0].get("stdout", ""))

        output_sections: list[str] = []
        for sub_result in sub_results:
            stdout = str(sub_result.get("stdout", "")).strip()
            if not stdout:
                continue
            files = sub_result.get("files")
            heading = files[0] if isinstance(files, list) and files else "import"
            output_sections.append(f"[{heading}]\n{stdout}")
        return "\n\n".join(output_sections)

    @staticmethod
    def _raise_if_operation_failed(
        result: dict[str, Any],
        *,
        raise_on_error: bool,
        fallback_message: str,
    ) -> None:
        if raise_on_error and not result.get("success", False):
            raise OdooOperationError(
                result.get("error", fallback_message),
                operation_result=result,
            )

    def _find_available_http_port(
        self,
        start_port: int,
        host: str | None = None,
    ) -> int:
        probe_host = "127.0.0.1" if not host or host == "0.0.0.0" else host

        for candidate_port in range(start_port, 65536):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate_socket:
                try:
                    candidate_socket.bind((probe_host, candidate_port))
                except OSError:
                    continue
                return candidate_port

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate_socket:
            candidate_socket.bind((probe_host, 0))
            return int(candidate_socket.getsockname()[1])

    def _build_test_operation(
        self,
        *,
        module: str | None = None,
        install: str | None = None,
        update: str | None = None,
        coverage: str | None = None,
        test_file: str | None = None,
        test_tags: str | None = None,
        compact: bool = False,
        log_level: str | None = None,
        http_port_override: int | None = None,
    ) -> CommandOperation:
        config_data = dict(self.operations.config.get_full_config())
        if http_port_override is not None:
            config_data["http_port"] = http_port_override

        config = ConfigProvider(config_data)
        builder: OdooTestCoverageCommandBuilder | OdooTestCommandBuilder
        if coverage:
            builder = OdooTestCoverageCommandBuilder(config, coverage)
        else:
            builder = OdooTestCommandBuilder(config)

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
        return builder.build_operation()

    @staticmethod
    def _add_http_port_retry_metadata(
        result: dict[str, Any],
        attempted_ports: list[int],
        retry_warnings: list[str],
    ) -> dict[str, Any]:
        metadata = {
            "http_port": attempted_ports[-1] if attempted_ports else None,
            "http_port_attempts": attempted_ports,
            "http_port_retry_count": max(len(attempted_ports) - 1, 0),
            "http_port_auto_retried": len(attempted_ports) > 1,
        }
        result.update(metadata)
        if retry_warnings:
            warnings = list(result.get("warnings", []))
            warnings.extend(retry_warnings)
            result["warnings"] = warnings
        return result

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

    def export_translations(
        self,
        modules: list[str] | tuple[str, ...],
        languages: list[str] | tuple[str, ...] | None = None,
        output: str | None = None,
        *,
        odoo_series: Any | None = None,
        log_level: str | None = None,
        suppress_output: bool = False,
        raise_on_error: bool = False,
    ) -> dict[str, Any]:
        """Export translations with the correct Odoo 18/19 command strategy."""
        resolved_series = self._resolve_i18n_odoo_series(odoo_series)
        if self.operations.verbose and not suppress_output:
            module_names = ", ".join(str(module) for module in modules)
            print_info(f"Export translations for {module_names}")

        try:
            builder = I18nExportCommandBuilder(
                self.operations.config,
                modules=modules,
                languages=languages,
                output=output,
                odoo_series=resolved_series,
            )
            if log_level and isinstance(log_level, str):
                builder.log_level(log_level)
            operation = builder.build_operation()
            result = self._run_i18n_operation(
                operation,
                suppress_output=suppress_output,
            )
        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        self._raise_if_operation_failed(
            result,
            raise_on_error=raise_on_error,
            fallback_message="Translation export failed",
        )
        return result

    def import_translations(
        self,
        files: list[str] | tuple[str, ...],
        language: str,
        *,
        overwrite: bool = False,
        odoo_series: Any | None = None,
        log_level: str | None = None,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        stop_on_error: bool = True,
    ) -> dict[str, Any]:
        """Import translations using one native run or per-file legacy runs."""
        resolved_series = self._resolve_i18n_odoo_series(odoo_series)
        series_major = odoo_series_major(resolved_series)
        assert series_major is not None

        sub_results: list[dict[str, Any]] = []
        imported_files: list[str] = []
        failed_files: list[str] = []

        try:
            if series_major >= 19:
                builders = [
                    I18nImportCommandBuilder(
                        self.operations.config,
                        files=files,
                        language=language,
                        overwrite=overwrite,
                        odoo_series=resolved_series,
                    )
                ]
            else:
                builders = [
                    I18nImportCommandBuilder(
                        self.operations.config,
                        files=[filename],
                        language=language,
                        overwrite=overwrite,
                        odoo_series=resolved_series,
                    )
                    for filename in files
                ]

            for builder in builders:
                if log_level and isinstance(log_level, str):
                    builder.log_level(log_level)
                operation = builder.build_operation()
                sub_result = self._run_i18n_operation(
                    operation,
                    suppress_output=suppress_output,
                )
                sub_results.append(sub_result)

                result_files = sub_result.get("files", [])
                if sub_result.get("success", False):
                    imported_files.extend(result_files)
                else:
                    failed_files.extend(result_files)
                    if stop_on_error and series_major < 19:
                        break
        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))
            self._raise_if_operation_failed(
                result,
                raise_on_error=raise_on_error,
                fallback_message="Translation import failed",
            )
            return result

        aggregate_success = bool(sub_results) and all(
            sub_result.get("success", False) for sub_result in sub_results
        )
        first_failure_code = next(
            (
                int(sub_result.get("return_code", 1))
                for sub_result in sub_results
                if not sub_result.get("success", False)
            ),
            0,
        )
        top_level_stdout = self._aggregate_import_stdout(sub_results)
        result = {
            "success": aggregate_success,
            "operation": "i18n_import",
            "operation_type": "i18n_import",
            "database": self.operations.config.get_optional("db_name"),
            "files": list(dict.fromkeys(str(filename) for filename in files)),
            "language": str(language).strip(),
            "overwrite": overwrite,
            "strategy": "native_i18n" if series_major >= 19 else "legacy_flags",
            "odoo_series": self._normalize_odoo_series_label(resolved_series),
            "imported_files": imported_files,
            "failed_files": failed_files,
            "sub_results": sub_results,
            "return_code": 0 if aggregate_success else first_failure_code,
            "stdout": top_level_stdout,
            "stderr": "",
        }
        if not aggregate_success:
            failed_message = ", ".join(failed_files) or "translation import"
            result["error"] = f"Translation import failed for: {failed_message}"

        self._raise_if_operation_failed(
            result,
            raise_on_error=raise_on_error,
            fallback_message="Translation import failed",
        )
        return result

    def load_languages(
        self,
        languages: list[str] | tuple[str, ...],
        *,
        odoo_series: Any | None = None,
        log_level: str | None = None,
        suppress_output: bool = False,
        raise_on_error: bool = False,
    ) -> dict[str, Any]:
        """Load languages into the configured database."""
        resolved_series = self._resolve_i18n_odoo_series(odoo_series)

        try:
            builder = I18nLoadLanguageCommandBuilder(
                self.operations.config,
                languages=languages,
                odoo_series=resolved_series,
            )
            if log_level and isinstance(log_level, str):
                builder.log_level(log_level)
            operation = builder.build_operation()
            result = self._run_i18n_operation(
                operation,
                suppress_output=suppress_output,
            )
        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        self._raise_if_operation_failed(
            result,
            raise_on_error=raise_on_error,
            fallback_message="Language loading failed",
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
        odoo_series: Any | None = None,
    ) -> dict:
        """Compatibility wrapper for exporting one module language file."""
        if self.operations.verbose and not suppress_output:
            print_info(f"Export language {language} to {filename} for module: {module}")

        return self.export_translations(
            modules=[module],
            languages=[language],
            output=filename,
            odoo_series=odoo_series,
            log_level=log_level,
            suppress_output=suppress_output,
        )

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
        operation: CommandOperation | None = None
        configured_http_port = self._coerce_http_port(
            self.operations.config.get_optional("http_port")
        )
        current_http_port = configured_http_port
        attempted_ports: list[int] = []
        retry_warnings: list[str] = []
        http_interface = self.operations.config.get_optional("http_interface")

        try:
            for attempt_index in range(self._TEST_HTTP_PORT_RETRY_LIMIT):
                if current_http_port is not None:
                    attempted_ports.append(current_http_port)

                operation = self._build_test_operation(
                    module=module,
                    install=install,
                    update=update,
                    coverage=coverage,
                    test_file=test_file,
                    test_tags=test_tags,
                    compact=compact,
                    log_level=log_level,
                    http_port_override=current_http_port,
                )
                test_result = self.operations.process_manager.run_operation(
                    operation,
                    verbose=self.operations.verbose,
                    suppress_output=suppress_output,
                )

                output = test_result.get("stdout") or test_result.get("output") or ""
                if test_result.get("success") or not self._is_http_port_conflict(
                    output
                ):
                    break

                if attempt_index == self._TEST_HTTP_PORT_RETRY_LIMIT - 1:
                    break

                conflicting_http_port = self._extract_conflicting_http_port(output)
                attempted_http_port = current_http_port
                if attempted_http_port is None:
                    attempted_http_port = (
                        conflicting_http_port or configured_http_port or 8069
                    )
                    attempted_ports.append(attempted_http_port)

                next_http_port = self._find_available_http_port(
                    (conflicting_http_port or attempted_http_port) + 1,
                    host=http_interface,
                )
                retry_warning = (
                    f"HTTP port {attempted_http_port} is busy during test execution; "
                    f"retrying with {next_http_port}."
                )
                retry_warnings.append(retry_warning)
                if not suppress_output:
                    print_warning(retry_warning)
                current_http_port = next_http_port

            if test_result is not None:
                self._add_http_port_retry_metadata(
                    test_result,
                    attempted_ports,
                    retry_warnings,
                )

            if coverage and test_result and test_result.get("success"):
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
