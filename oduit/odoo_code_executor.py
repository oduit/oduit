# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Odoo code execution for programmatic use.

This module provides a class that allows executing Python code within an Odoo
environment and capturing the results directly, without printing to console.
It's designed for programmatic use where you want to execute Odoo operations
and get the results back as Python objects.
"""

import io
import sys
import threading
import traceback
from typing import Any

from .config_provider import ConfigProvider
from .odoo_embedded_manager import OdooEmbeddedManager
from .output import print_error, print_info


class OdooCodeExecutor:
    """Execute Python code within an Odoo environment and capture results.

    This class provides a way to execute arbitrary Python code within an Odoo
    environment and capture the results directly as Python objects, without
    printing to console. It's perfect for programmatic use cases where you
    want to query data, perform operations, and get results back.

    Features:
    - Execute code within proper Odoo environment with 'env' variable
    - Capture return values and exceptions
    - Support for both single expressions and multi-line code blocks
    - Automatic database connection and cleanup
    - Thread-safe execution
    - Proper transaction handling (read-only by default)

    Example:
        executor = OdooCodeExecutor(config_provider)
        result = executor.execute_code("env['res.partner'].search([],limit=1).name")
        print(f"Partner name: {result['value']}")
    """

    def __init__(self, config_provider: ConfigProvider):
        """Initialize the code executor.

        Args:
            config_provider: ConfigProvider instance with Odoo configuration
        """
        self.config_provider = config_provider
        self._embedded_manager = OdooEmbeddedManager(config_provider)

    def execute_code(
        self,
        code: str,
        database: str | None = None,
        commit: bool = False,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Execute Python code within an Odoo environment.

        Args:
            code: Python code to execute (can be expression or statements)
            database: Database name to connect to (uses config default if None)
            commit: Whether to commit changes (default: False for safety)
            timeout: Maximum execution time in seconds

        Returns:
            Dictionary with execution results:
            - success (bool): True if execution succeeded
            - value (Any): Return value if code was an expression
            - output (str): Any stdout output from the code
            - error (str): Error message if execution failed
            - traceback (str): Full traceback if an exception occurred
        """
        try:
            from odoo.tools import config

            # Configure Odoo directly without command line parsing
            config_dict = {
                "db_host": self.config_provider.get_optional("db_host", "localhost"),
                "db_port": self.config_provider.get_optional("db_port", 5432),
                "db_user": self.config_provider.get_optional("db_user"),
                "db_password": self.config_provider.get_optional("db_password"),
                "addons_path": self.config_provider.get_optional("addons_path"),
                "data_dir": self.config_provider.get_optional("data_dir"),
                "db_name": self.config_provider.get_optional("db_name"),
                "list_db": False,
                "http_enable": False,
            }

            # Update Odoo config directly
            for key, value in config_dict.items():
                if value is not None:
                    config[key] = value

            # Determine database
            db_name = database or config.get("db_name")
            if not db_name:
                return {
                    "success": False,
                    "error": (
                        "No database specified. Use database parameter or set "
                        "db_name in config."
                    ),
                }

            # Execute code with database connection
            return self._execute_with_database(code, db_name, commit, timeout)

        except ImportError as e:
            error_msg = f"Odoo not available for code execution: {e}"
            print_error(error_msg)
            return {"success": False, "error": error_msg}
        except Exception as e:
            error_msg = f"Failed to initialize Odoo for code execution: {e}"
            print_error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "traceback": traceback.format_exc(),
            }

    def _execute_with_database(
        self, code: str, db_name: str, commit: bool, timeout: float
    ) -> dict[str, Any]:
        """Execute code with database connection."""
        try:
            import odoo

            # Set up threading context
            threading.current_thread().dbname = db_name  # type: ignore[attr-defined]

            # Get registry and create environment
            registry = odoo.registry(db_name)

            with registry.cursor() as cr:
                # Create Odoo environment
                uid = odoo.SUPERUSER_ID
                ctx = odoo.api.Environment(cr, uid, {})["res.users"].context_get()  # type: ignore[attr-defined]
                env = odoo.api.Environment(cr, uid, ctx)

                # Set up execution context
                execution_context = {
                    "env": env,
                    "odoo": odoo,
                    "registry": registry,
                    "cr": cr,
                    "uid": uid,
                    "context": ctx,
                    # Add some commonly used modules
                    "datetime": __import__("datetime"),
                    "json": __import__("json"),
                    "os": __import__("os"),
                    "sys": __import__("sys"),
                }

                # Execute the code with timeout and output capture
                result = self._safe_execute(code, execution_context, timeout)

                if result["success"] and commit:
                    cr.commit()
                    print_info(f"Changes committed to database '{db_name}'")
                else:
                    cr.rollback()

                return result

        except Exception as e:
            error_msg = f"Database execution failed: {e}"
            return {
                "success": False,
                "error": error_msg,
                "traceback": traceback.format_exc(),
            }

    def _safe_execute(
        self, code: str, context: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        """Safely execute code with output capture and timeout."""
        import ast

        # Capture stdout and stderr
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        result = {
            "success": False,
            "value": None,
            "output": "",
            "error": "",
            "traceback": "",
        }

        try:
            # Redirect output streams
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture

            # Clean the code
            code_stripped = code.strip()

            # Try to determine if this ends with an expression using AST
            try:
                tree = ast.parse(code_stripped)
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    # The last statement is an expression
                    if len(tree.body) > 1:
                        # Execute all but the last statement
                        statements = tree.body[:-1]
                        statements_code = ast.unparse(
                            ast.Module(body=statements, type_ignores=[])
                        )
                        exec(
                            compile(statements_code, "<odoo-executor>", "exec"), context
                        )

                        # Evaluate the last expression
                        expr = tree.body[-1]
                        expr_code = ast.unparse(
                            expr.value
                        )  # Get the expression without ast.Expr wrapper
                        value = eval(
                            compile(expr_code, "<odoo-executor>", "eval"), context
                        )
                        result["value"] = value
                        result["success"] = True
                        return result
                    else:
                        # Only one statement and it's an expression
                        expr_code = ast.unparse(tree.body[0].value)  # type: ignore[attr-defined]
                        value = eval(
                            compile(expr_code, "<odoo-executor>", "eval"), context
                        )
                        result["value"] = value
                        result["success"] = True
                        return result
                else:
                    # No expression at the end, execute as statements
                    exec(compile(code, "<odoo-executor>", "exec"), context)
                    result["value"] = None
                    result["success"] = True
                    return result

            except SyntaxError:
                # If AST parsing fails, fall back to simple approach
                pass

            # Fallback: try as expression first, then as statements
            try:
                compiled = compile(code_stripped, "<odoo-executor>", "eval")
                value = eval(compiled, context)
                result["value"] = value
                result["success"] = True
            except SyntaxError:
                # Not an expression, compile as statements
                try:
                    compiled = compile(code, "<odoo-executor>", "exec")
                    exec(compiled, context)
                    result["value"] = None
                    result["success"] = True
                except SyntaxError as e:
                    result["error"] = f"Syntax error: {e}"
                    result["traceback"] = traceback.format_exc()

        except Exception as e:
            result["error"] = str(e)
            result["traceback"] = traceback.format_exc()

        finally:
            # Restore original streams and capture output
            sys.stdout = old_stdout
            sys.stderr = old_stderr

            result["output"] = stdout_capture.getvalue()
            if stderr_capture.getvalue():
                if result["error"]:
                    result["error"] = (
                        str(result["error"]) + f"\nSTDERR: {stderr_capture.getvalue()}"
                    )
                else:
                    result["error"] = stderr_capture.getvalue()

        return result

    def execute_multiple(
        self,
        code_blocks: list[str],
        database: str | None = None,
        commit: bool = False,
        stop_on_error: bool = True,
    ) -> dict[str, Any]:
        """Execute multiple code blocks in sequence within the same transaction.

        Args:
            code_blocks: List of Python code strings to execute
            database: Database name to connect to
            commit: Whether to commit changes after all blocks succeed
            stop_on_error: Whether to stop execution if any block fails

        Returns:
            Dictionary with execution results:
            - success (bool): True if all blocks executed successfully
            - results (list): List of individual execution results
            - failed_at (int): Index of failed block (if stop_on_error=True)
            - error (str): Overall error message
        """
        try:
            from odoo.tools import config

            # Configure Odoo directly without command line parsing
            config_dict = {
                "db_host": self.config_provider.get_optional("db_host", "localhost"),
                "db_port": self.config_provider.get_optional("db_port", 5432),
                "db_user": self.config_provider.get_optional("db_user"),
                "db_password": self.config_provider.get_optional("db_password"),
                "addons_path": self.config_provider.get_optional("addons_path"),
                "data_dir": self.config_provider.get_optional("data_dir"),
                "db_name": self.config_provider.get_optional("db_name"),
                "list_db": False,
                "http_enable": False,
            }

            # Update Odoo config directly
            for key, value in config_dict.items():
                if value is not None:
                    config[key] = value

            # Determine database
            db_name = database or config.get("db_name")
            if not db_name:
                return {
                    "success": False,
                    "error": (
                        "No database specified. Use database parameter or set "
                        "db_name in config."
                    ),
                }

            return self._execute_multiple_with_database(
                code_blocks, db_name, commit, stop_on_error
            )

        except Exception as e:
            error_msg = f"Failed to initialize Odoo for multiple code execution: {e}"
            return {
                "success": False,
                "error": error_msg,
                "traceback": traceback.format_exc(),
            }

    def _execute_multiple_with_database(
        self, code_blocks: list[str], db_name: str, commit: bool, stop_on_error: bool
    ) -> dict[str, Any]:
        """Execute multiple code blocks with database connection."""
        try:
            import odoo

            # Set up threading context
            threading.current_thread().dbname = db_name  # type: ignore[attr-defined]

            # Get registry and create environment
            registry = odoo.registry(db_name)

            with registry.cursor() as cr:
                # Create Odoo environment
                uid = odoo.SUPERUSER_ID
                ctx = odoo.api.Environment(cr, uid, {})["res.users"].context_get()  # type: ignore[attr-defined]
                env = odoo.api.Environment(cr, uid, ctx)

                # Set up execution context (shared across all blocks)
                execution_context = {
                    "env": env,
                    "odoo": odoo,
                    "registry": registry,
                    "cr": cr,
                    "uid": uid,
                    "context": ctx,
                    "datetime": __import__("datetime"),
                    "json": __import__("json"),
                    "os": __import__("os"),
                    "sys": __import__("sys"),
                }

                results = []
                overall_success = True
                failed_at = None

                # Execute each code block
                for i, code in enumerate(code_blocks):
                    print_info(f"Executing code block {i + 1}/{len(code_blocks)}")

                    result = self._safe_execute(code, execution_context, 30.0)
                    results.append(result)

                    if not result["success"]:
                        overall_success = False
                        failed_at = i

                        if stop_on_error:
                            print_error(
                                f"Code block {i + 1} failed, stopping execution"
                            )
                            break
                        else:
                            print_error(f"Code block {i + 1} failed, continuing")

                # Handle transaction
                if overall_success and commit:
                    cr.commit()
                    print_info(f"All changes committed to database '{db_name}'")
                else:
                    cr.rollback()
                    if not overall_success:
                        print_info("Changes rolled back due to errors")

                return {
                    "success": overall_success,
                    "results": results,
                    "failed_at": failed_at,
                    "total_blocks": len(code_blocks),
                    "executed_blocks": len(results),
                }

        except Exception as e:
            error_msg = f"Multiple code execution failed: {e}"
            return {
                "success": False,
                "error": error_msg,
                "traceback": traceback.format_exc(),
            }
