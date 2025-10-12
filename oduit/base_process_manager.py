# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import re
from abc import ABC, abstractmethod
from collections.abc import Generator
from typing import TYPE_CHECKING, Any

from .output import print_error, print_info

if TYPE_CHECKING:
    from .builders import CommandOperation


class BaseProcessManager(ABC):
    """Abstract base class for all process managers.

    This class defines the common interface and shared functionality for
    process managers that execute commands in different ways (subprocess,
    embedded, mock/demo, etc.).

    All concrete implementations must provide the core execution methods
    while optionally overriding shared utility methods for customization.
    """

    @abstractmethod
    def run_command(
        self,
        cmd: list[str],
        stop_on_error: bool = False,
        compact: bool = False,
        verbose: bool = False,
        suppress_output: bool = False,
    ) -> dict[str, Any]:
        """Execute a command and return structured results.

        Args:
            cmd: Command to execute as list of strings (e.g., ['ls', '-la'])
            stop_on_error: If True, terminate on first error encountered
            compact: If True, use compact output formatting
            verbose: If True, print the command being executed
            suppress_output: If True, suppress all output to console

        Returns:
            Dict containing execution results with keys:
            - success (bool): True if command executed successfully
            - return_code (int): Process exit code (0 for success)
            - output (str): Combined stdout/stderr output
            - command (str): The executed command as string
            - error (str): Error message if execution failed (optional)
        """

    def run_command_yielding(
        self,
        cmd: list[str],
        stop_on_error: bool = False,
        compact: bool = False,
        verbose: bool = False,
        suppress_output: bool = False,
    ) -> Generator[dict[str, Any], None, None]:
        """Generator version of run_command that yields lines as they arrive.

        Default implementation calls run_command and yields the final result.
        Concrete implementations may override for true line-by-line streaming.

        Args:
            cmd: Command to execute
            stop_on_error: Stop execution on first error pattern
            compact: Only show relevant lines (dots, errors, warnings)
            verbose: Print command before execution
            suppress_output: Don't print lines to console (only yield them)

        Yields:
            dict: For each line: {
                'line': str,           # Raw line content
                'formatted': str,      # Colorized/formatted line
                'should_show': bool,   # Whether line should be shown in compact mode
                'is_error': bool,      # Whether line matches error patterns
                'process_running': bool # Whether process is still active
            }

        Final yield: {
            'result': dict,        # Final command result (same as run_command)
            'process_running': False
        }
        """
        result = self.run_command(cmd, stop_on_error, compact, verbose, suppress_output)
        yield {"result": result, "process_running": False}

    @abstractmethod
    def run_operation(
        self,
        command_operation: "CommandOperation",
        verbose: bool = False,
        suppress_output: bool = False,
    ) -> dict[str, Any]:
        """Execute a CommandOperation directly.

        Args:
            command_operation: Structured command operation with metadata
            verbose: Enable verbose output
            suppress_output: Suppress output to console

        Returns:
            Dict containing execution results
        """

    @abstractmethod
    def run_shell_command(
        self, cmd: list[str] | str, verbose: bool = False, capture_output: bool = False
    ) -> dict[str, Any]:
        """Execute a shell command that may receive piped input.

        Args:
            cmd: Either a list of command arguments or a string to be evaluated by shell
            verbose: Print command before execution
            capture_output: Capture stdout/stderr instead of inheriting

        Returns:
            Dict with execution results (format similar to run_command)
        """

    @staticmethod
    @abstractmethod
    def run_interactive_shell(cmd: list[str]) -> int:
        """Run an interactive shell session.

        Args:
            cmd: Command to execute interactively

        Returns:
            int: Exit code of the interactive session
        """

    # Shared utility methods that can be overridden

    def _create_result(
        self,
        success: bool,
        return_code: int,
        output: str,
        command: str,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Create standardized result dictionary.

        Args:
            success: Whether the command succeeded
            return_code: Process exit code
            output: Command output
            command: The executed command as string
            error: Optional error message

        Returns:
            Standardized result dictionary
        """
        result = {
            "success": success,
            "return_code": return_code,
            "output": output,
            "command": command,
        }
        if error is not None:
            result["error"] = error
        return result

    def _validate_command(self, cmd: list[str]) -> bool:
        """Validate command format and content.

        Args:
            cmd: Command list to validate

        Returns:
            bool: True if command is valid

        Raises:
            ValueError: If command format is invalid
        """
        if not cmd:
            raise ValueError("Command cannot be empty")
        if not isinstance(cmd, list):
            raise ValueError("Command must be a list of strings")
        if not all(isinstance(arg, str) for arg in cmd):
            raise ValueError("All command arguments must be strings")
        return True

    def _colorize_log_line(self, line: str) -> str:
        """Add ANSI colors to common log levels (INFO/WARNING/ERROR).

        Can be overridden by concrete implementations for custom colorization.

        Args:
            line: Log line to colorize

        Returns:
            str: Colorized line with ANSI escape codes
        """

        # Use cautious, single-substitution replacements to avoid over-coloring
        # Colors: INFO=blue(34), WARNING=yellow(33), ERROR=red(31), DOTS=green(32)
        def repl_once(pattern: re.Pattern, color_code: str, text: str) -> str:
            m = pattern.search(text)
            if not m:
                return text
            start, end = m.span(1)
            return (
                text[:start]
                + f"\033[{color_code}m"
                + m.group(1)
                + "\033[0m"
                + text[end:]
            )

        # Match levels as standalone tokens to reduce false hits
        patterns = [
            (re.compile(r"(\bINFO\b)"), "34"),
            (re.compile(r"(\bWARNING\b)"), "33"),
            (re.compile(r"(\bERROR\b)"), "31"),
            (re.compile(r"( \.\.\.+)"), "32"),  # Space + 3+ dots
        ]

        colored = line
        for pat, code in patterns:
            colored = repl_once(pat, code, colored)
        return colored

    def _should_show_line_in_compact(self, line: str) -> bool:
        """Determine if line should be shown in compact mode.

        Can be overridden by concrete implementations for custom filtering.

        Args:
            line: Log line to evaluate

        Returns:
            bool: True if line should be shown in compact mode
        """
        failure_patterns = [
            re.compile(r"\bFAIL:\s", re.IGNORECASE),
            re.compile(r"\bERROR:\s", re.IGNORECASE),
        ]

        return (
            " ..." in line
            or any(p.search(line) for p in failure_patterns)
            or "odoo.tests.stats:" in line
            or "odoo.tests.result:" in line
        )

    def _handle_verbose_output(
        self, cmd: list[str], suppress_output: bool = False
    ) -> None:
        """Handle verbose command output.

        Args:
            cmd: Command being executed
            suppress_output: Whether to suppress output
        """
        if not suppress_output:
            print_info(f"Running command: {' '.join(cmd)}")

    def _handle_error_output(
        self, error_msg: str, suppress_output: bool = False
    ) -> None:
        """Handle error output.

        Args:
            error_msg: Error message to output
            suppress_output: Whether to suppress output
        """
        if not suppress_output:
            print_error(error_msg)


class ProcessManagerFactory:
    """Factory for creating appropriate process manager instances."""

    @staticmethod
    def create_manager(
        manager_type: str = "system", **kwargs: Any
    ) -> "BaseProcessManager":
        """Create a process manager instance.

        Args:
            manager_type: Type of manager to create ("system", "demo")
            **kwargs: Additional arguments passed to manager constructor

        Returns:
            BaseProcessManager: Appropriate manager instance

        Raises:
            ValueError: If manager_type is not recognized
        """
        # Import classes locally to avoid circular imports
        if manager_type == "demo":
            from .demo_process_manager import DemoProcessManager

            return DemoProcessManager(**kwargs)
        elif manager_type == "system":
            from .process_manager import ProcessManager

            return ProcessManager(**kwargs)
        else:
            raise ValueError(
                f"Unknown manager type: {manager_type}. "
                f"Valid types: 'system', 'demo', 'embedded'"
            )
