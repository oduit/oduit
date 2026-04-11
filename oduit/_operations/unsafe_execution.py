from __future__ import annotations

from typing import Any

from .. import output as _output_module
from ..builders import ShellCommandBuilder
from ..exceptions import ConfigError, ModuleUninstallError, OdooOperationError
from ..output import print_error, print_error_result, print_info
from .base import OperationsService


class UnsafeExecutionOperationsService(OperationsService):
    """Explicitly unsafe or trusted execution helpers."""

    def uninstall_module(
        self,
        module: str,
        *,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        compact: bool = False,
        log_level: str | None = None,
        allow_uninstall: bool = False,
        check_dependents: bool = True,
    ) -> dict[str, Any]:
        """Uninstall a module through a trusted runtime action."""
        config_allows_uninstall = self.operations._config_allows_uninstall()
        result: dict[str, Any] = {
            "success": False,
            "operation": "uninstall_module",
            "module": module,
            "config_allows_uninstall": config_allows_uninstall,
            "allow_uninstall": allow_uninstall,
            "check_dependents": check_dependents,
            "dependent_modules": [],
            "compact": compact,
            "log_level": log_level,
        }

        if not config_allows_uninstall:
            result.update(
                {
                    "error": (
                        "Uninstall is disabled in this environment. "
                        "Set allow_uninstall=true in config."
                    ),
                    "error_type": "ConfigError",
                }
            )
        elif not allow_uninstall:
            result.update(
                {
                    "error": "Module uninstall requires allow_uninstall=True.",
                    "error_type": "ConfirmationRequired",
                }
            )
        else:
            state_result = self.operations.get_addon_install_state(module)
            result["database"] = state_result.database
            if not state_result.success:
                result.update(
                    {
                        "error": state_result.error or "Failed to query module state",
                        "error_type": state_result.error_type or "QueryError",
                    }
                )
            elif not state_result.record_found:
                result.update(
                    {
                        "error": (
                            f"Module '{module}' was not found in ir.module.module."
                        ),
                        "error_type": "ModuleNotFoundError",
                    }
                )
            elif not state_result.installed:
                result.update(
                    {
                        "error": (
                            f"Module '{module}' is not installed "
                            f"(state: {state_result.state})."
                        ),
                        "error_type": "ModuleUninstallError",
                        "previous_state": state_result.state,
                        "final_state": state_result.state,
                    }
                )
            else:
                result["previous_state"] = state_result.state
                if check_dependents:
                    dependents_result = self.operations.list_installed_dependents(
                        module,
                        database=state_result.database,
                    )
                    if not dependents_result.success:
                        result.update(
                            {
                                "error": (
                                    dependents_result.error
                                    or "Failed to query installed dependents"
                                ),
                                "error_type": dependents_result.error_type
                                or "QueryError",
                            }
                        )
                    else:
                        dependent_modules = [
                            addon.module for addon in dependents_result.addons
                        ]
                        result["dependent_modules"] = dependent_modules
                        if dependent_modules:
                            result.update(
                                {
                                    "error": (
                                        f"Cannot uninstall '{module}' because "
                                        "installed dependents exist: "
                                        f"{', '.join(dependent_modules)}."
                                    ),
                                    "error_type": "ModuleUninstallError",
                                }
                            )

                if not result.get("error"):
                    executor_result = (
                        self.operations._get_code_executor()._execute_generated_code(
                            type(self.operations)._build_uninstall_module_code(module),
                            database=state_result.database,
                            commit=True,
                        )
                    )
                    if not executor_result.get("success", False):
                        result.update(
                            {
                                "error": (
                                    executor_result.get("error")
                                    or f"Failed to uninstall module '{module}'."
                                ),
                                "error_type": "ModuleUninstallError",
                            }
                        )
                        if executor_result.get("traceback"):
                            result["traceback"] = executor_result["traceback"]
                        if executor_result.get("output"):
                            result["stdout"] = executor_result["output"]
                    else:
                        payload = executor_result.get("value")
                        if not isinstance(payload, dict):
                            result.update(
                                {
                                    "error": (
                                        "Trusted uninstall action returned no data."
                                    ),
                                    "error_type": "ModuleUninstallError",
                                }
                            )
                        else:
                            result.update(payload)
                            result["success"] = bool(payload.get("uninstalled", False))
                            result["final_state"] = str(
                                payload.get("final_state") or "unknown"
                            )
                            if executor_result.get("output"):
                                result["stdout"] = executor_result["output"]
                            if not result["success"]:
                                result.update(
                                    {
                                        "error": (
                                            f"Module '{module}' remained in state "
                                            f"{result['final_state']} after uninstall."
                                        ),
                                        "error_type": "ModuleUninstallError",
                                    }
                                )

        if raise_on_error and not result.get("success", False):
            raise ModuleUninstallError(
                result.get("error", "Module uninstall failed"),
                operation_result=result,
            )

        if (
            result.get("success")
            and self.operations.verbose
            and not suppress_output
            and not compact
        ):
            print_info(f"Uninstalled module: {module}")

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
        interface = shell_interface or self.operations.config.get_optional(
            "shell_interface", False
        )
        if not interface:
            raise ConfigError(
                "Shell interface must be provided either via --shell-interface "
                "parameter or in the configuration file."
            )
        builder = ShellCommandBuilder(self.operations.config)

        if shell_interface:
            builder.shell_interface(shell_interface)
        if no_http:
            builder.disable_http()
        if log_level and isinstance(log_level, str):
            builder.log_level(log_level)

        try:
            operation = builder.build_operation()

            if self.operations.verbose and not suppress_output:
                print_info("Executing Python code in Odoo shell")
                if self.operations.verbose:
                    print_info(f"Code: {python_code}")

            process_result = self.operations.process_manager.run_shell_command(
                operation.command,
                verbose=self.operations.verbose and not suppress_output,
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
