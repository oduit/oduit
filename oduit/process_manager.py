# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import getpass
import os
import re
import select
import signal
import subprocess
import sys
from collections.abc import Generator
from typing import TYPE_CHECKING, Any

from . import output
from .base_process_manager import BaseProcessManager
from .output import print_error, print_info, print_warning

if TYPE_CHECKING:
    from .builders import CommandOperation

# Platform detection
IS_WINDOWS = sys.platform == "win32"
IS_UNIX = not IS_WINDOWS

# Platform-specific imports with fallbacks
# PTY support is required for proper interactive shell handling on Unix systems
HAS_PTY = False
pty = None
termios = None
tty = None

if IS_UNIX:
    try:
        import pty  # type: ignore[assignment]
        import termios  # type: ignore[assignment]
        import tty  # type: ignore[assignment]

        # Verify PTY functionality is actually available
        # Some Unix systems may have the modules but lack PTY support
        try:
            master_fd, slave_fd = pty.openpty()  # type: ignore[attr-defined]
            os.close(master_fd)
            os.close(slave_fd)
            HAS_PTY = True
        except (OSError, AttributeError):
            # PTY creation failed - modules exist but functionality is limited
            HAS_PTY = False

    except ImportError:
        # PTY modules not available on this system
        HAS_PTY = False
        pty = None
        termios = None
        tty = None


class ProcessManager(BaseProcessManager):
    """Cross-platform process execution manager for Odoo operations.

    Provides comprehensive process management functionality including:
    - Command execution with output streaming and error handling
    - Cross-platform sudo authentication via stdin
    - Interactive shell support with pseudo-terminal (PTY) handling
    - Real-time output colorization and formatting
    - JSON-structured logging for programmatic consumption
    - Signal-safe process termination and cleanup

    This class handles the complexities of running Odoo commands across
    different operating systems while providing consistent interfaces
    for both interactive and automated usage scenarios.

    Attributes:
        _sudo_password: Cached sudo password for repeated operations

    Example:
        >>> pm = ProcessManager()
        >>> result = pm.run_command(['echo', 'hello world'])
        >>> print(result['success'])  # True
        >>> print(result['output'])   # 'hello world\\n'

        >>> # Interactive shell
        >>> pm.run_interactive_shell(['bash'])
    """

    _sudo_password: str | None

    def __init__(self) -> None:
        self._sudo_password = None

    def clear_sudo_password(self) -> None:
        """Clear cached sudo password from memory."""
        self._sudo_password = None

    def _get_sudo_password(self) -> str:
        """Get sudo password from cache, env var, or interactive prompt."""
        if self._sudo_password is not None:
            return self._sudo_password

        env_password = os.environ.get("SUDO_PASSWORD")
        if env_password:
            self._sudo_password = env_password
            return self._sudo_password

        self._sudo_password = getpass.getpass("Sudo password: ")
        return self._sudo_password

    @staticmethod
    def _write_process_stdin(process: Any, stdin_data: str | None) -> None:
        """Write optional stdin data to process and close stdin."""
        if stdin_data is None or process.stdin is None:
            return

        process.stdin.write(stdin_data)
        process.stdin.flush()
        process.stdin.close()

    def run_operation(
        self,
        command_operation: "CommandOperation",
        verbose: bool = False,
        suppress_output: bool = False,
    ) -> dict[str, Any]:
        """Execute a CommandOperation directly.

        For regular ProcessManager, this builds the command from the operation
        and executes it normally with enhanced result processing.

        Args:
            command_operation: Structured command operation with metadata
            verbose: Enable verbose output
            suppress_output: Suppress output to console

        Returns:
            Dict containing execution results
        """
        from .operation_result import OperationResult

        if verbose and not suppress_output:
            print_info(f"Executing {command_operation.operation_type} operation")

        # Create OperationResult from CommandOperation
        result_builder = OperationResult.from_operation(command_operation)

        try:
            # Execute the command using the regular process manager
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

                # Add warnings if captured
                if "warnings" in process_result and process_result["warnings"]:
                    result_builder.set_custom_data(warnings=process_result["warnings"])

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

    def _spawn_process_with_optional_sudo(
        self, cmd: list[str]
    ) -> tuple[Any, str | None]:
        """Spawn subprocess handling sudo -S via stdin.

        Returns (process, stdin_data).
        """
        is_sudo_command = bool(cmd) and cmd[0] == "sudo" and "-S" in cmd

        if is_sudo_command:
            sudo_password = self._get_sudo_password()
            process = self._create_subprocess(cmd, stdin_pipe=True)
            return process, f"{sudo_password}\n"

        # Non-sudo command
        process = self._create_subprocess(cmd)
        return process, None

    def _get_process_kwargs(self) -> dict[str, Any]:
        """Get platform-appropriate process creation kwargs"""
        if IS_WINDOWS:
            return {"creationflags": 0x00000200}  # CREATE_NEW_PROCESS_GROUP
        else:
            return {"preexec_fn": os.setsid}

    def _create_subprocess(
        self,
        cmd: list[str],
        env: dict[str, str] | None = None,
        stdin_pipe: bool = False,
    ) -> Any:
        """Create subprocess with platform-appropriate settings"""
        kwargs = self._get_process_kwargs()
        if env:
            kwargs["env"] = env

        stdin_target = subprocess.PIPE if stdin_pipe else None

        return subprocess.Popen(
            cmd,
            stdin=stdin_target,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            **kwargs,
        )

    def _handle_line_output(
        self, line: str, should_show_line: bool, compact: bool, suppress_output: bool
    ) -> None:
        """Handle output for a single line"""
        if suppress_output:
            return

        if output._formatter.format_type == "json":
            if should_show_line or not compact:
                self._parse_and_output_odoo_log(line)
        else:
            if should_show_line:
                print(self._colorize_log_line(line), end="")

    def _collect_error_context(
        self, process: Any, suppress_output: bool, info_pattern: Any
    ) -> list[str]:
        """Collect additional lines for error context"""
        context_lines = []
        remaining = 20

        while remaining > 0:
            try:
                r, _, _ = select.select([process.stdout], [], [], 0.5)
            except Exception:
                break
            if not r:
                break
            try:
                next_line = process.stdout.readline()
            except Exception:
                break
            if not next_line:
                break

            context_lines.append(next_line)

            # In error context, always show lines regardless of compact mode
            # But still respect suppress_output mode
            if not suppress_output:
                if output._formatter.format_type == "json":
                    self._parse_and_output_odoo_log(next_line)
                else:
                    print(self._colorize_log_line(next_line), end="")

            # Stop if we encounter an INFO line (error message is over)
            if info_pattern.search(next_line):
                break

            remaining -= 1

        return context_lines

    def _terminate_process_on_error(self, process: Any, suppress_output: bool) -> None:
        """Terminate process when error is detected"""
        if not suppress_output:
            print_error("Failure detected in output. Aborting...")
        self._terminate_process_cross_platform(process)

    def _terminate_process_cross_platform(self, process: Any) -> None:
        """Terminate process with platform-appropriate method"""
        try:
            if IS_WINDOWS:
                # Windows: Terminate process tree using taskkill
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    capture_output=True,
                )
            else:
                # Unix: Kill process group
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except Exception:
            # Fallback to simple terminate
            process.terminate()

    def _parse_and_output_odoo_log(self, line: str) -> None:
        """Parse Odoo log line and output using OutputFormatter."""
        import json
        from datetime import datetime

        # Skip if not in JSON mode
        if output._formatter.format_type != "json":
            return

        # Try to parse as Odoo log line using OutputFormatter
        if output._formatter._is_odoo_log_line(line):
            parsed_log = output._formatter._parse_odoo_log_line(line)
            if parsed_log:
                print(json.dumps(parsed_log))
                return

        # Try to parse as coverage report line
        if output._formatter._is_coverage_report_line(line):
            parsed_coverage = output._formatter._parse_coverage_report_line(line)
            if parsed_coverage:
                print(json.dumps(parsed_coverage))
                return

        # For non-matching lines (like other process output), output as structured data
        output_data = {
            "type": "log",
            "source": "process",
            "level": "info",
            "message": line.strip(),
            "timestamp": datetime.now().isoformat(),
        }
        print(json.dumps(output_data))

    def _stream_output_and_maybe_abort(
        self,
        process: Any,
        stop_on_error: bool,
        compact: bool = False,
        suppress_output: bool = False,
        warnings: list[str] | None = None,
    ) -> list[str]:
        """Stream stdout lines and abort on first failure pattern if requested.

        Returns collected output lines.
        """
        # Pattern indicating a test failure line in Odoo output
        failure_patterns = [
            re.compile(r"\\bFAIL:\\s", re.IGNORECASE),
            re.compile(r"\\bERROR:\\s", re.IGNORECASE),
        ]

        # Pattern indicating an INFO line (end of error message)
        info_pattern = re.compile(r"\\bINFO:\\s", re.IGNORECASE)

        # Important warning patterns to capture
        warning_patterns = [
            re.compile(r"invalid module names, ignored:"),
            re.compile(r"module.*: not installable, skipped"),
            re.compile(r"Some modules are not loaded"),
        ]

        if not process.stdout:
            return []

        collected_output = []
        for line in process.stdout:
            collected_output.append(line)

            # Capture important warnings
            if warnings is not None:
                for pattern in warning_patterns:
                    if pattern.search(line):
                        # Extract the warning message
                        warning_msg = line.strip()
                        if warning_msg not in warnings:
                            warnings.append(warning_msg)

            # Check if we should show this line in compact mode
            should_show_line = True
            if compact:
                should_show_line = self._should_show_line_in_compact(
                    line,
                )

            # Handle output
            self._handle_line_output(line, should_show_line, compact, suppress_output)

            if stop_on_error and any(p.search(line) for p in failure_patterns):
                # Collect error context
                context_lines = self._collect_error_context(
                    process, suppress_output, info_pattern
                )
                collected_output.extend(context_lines)

                # Terminate process
                self._terminate_process_on_error(process, suppress_output)
                break

        return collected_output

    def run_command(
        self,
        cmd: list[str],
        stop_on_error: bool = False,
        compact: bool = False,
        verbose: bool = False,
        suppress_output: bool = False,
    ) -> dict[str, Any]:
        """Execute a command with comprehensive output handling and error management.

        This method provides a unified interface for running system commands with
        proper error handling, output streaming, and optional sudo support.

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
            - error (str): Error message if execution failed

        Raises:
            KeyboardInterrupt: Re-raised after proper process cleanup

        Examples:
            >>> pm = ProcessManager()
            >>> result = pm.run_command(['echo', 'hello'])
            >>> print(result['success'])  # True
            >>> print(result['output'])   # 'hello\\n'

            >>> result = pm.run_command(['false'])  # Command that fails
            >>> print(result['success'])    # False
            >>> print(result['return_code'])  # 1
        """
        if verbose and not suppress_output:
            print_info(f"Running command: {' '.join(cmd)}")
        process = None
        stdin_data = None
        output_lines = []
        warnings: list[str] = []

        try:
            process, stdin_data = self._spawn_process_with_optional_sudo(cmd)
            self._write_process_stdin(process, stdin_data)
            output_lines = self._stream_output_and_maybe_abort(
                process, stop_on_error, compact, suppress_output, warnings
            )
            process.wait()

            if process.returncode != 0:
                if not suppress_output:
                    print_error(f"Command exited with code {process.returncode}")
                return {
                    "success": False,
                    "return_code": process.returncode,
                    "output": "".join(output_lines),
                    "command": " ".join(cmd),
                    "warnings": warnings,
                }

            return {
                "success": True,
                "return_code": 0,
                "output": "".join(output_lines),
                "command": " ".join(cmd),
                "warnings": warnings,
            }

        except KeyboardInterrupt:
            if not suppress_output:
                print_error("Interrupted by user. Terminating subprocess...")
            if process:
                self._terminate_process_cross_platform(process)
            return {
                "success": False,
                "error": "Interrupted by user",
                "output": "".join(output_lines),
                "command": " ".join(cmd),
                "warnings": warnings,
            }

        except FileNotFoundError as e:
            error_msg = f"Command not successful: {cmd[0]} due to {e}"
            if not suppress_output:
                print_error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "command": " ".join(cmd),
                "warnings": warnings,
            }
        except Exception as e:
            error_msg = f"Error running command: {e}"
            if not suppress_output:
                print_error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "output": "".join(output_lines),
                "command": " ".join(cmd),
                "warnings": warnings,
            }

    def _stream_output_yielding(
        self,
        process: Any,
        stop_on_error: bool,
        compact: bool = False,
        suppress_output: bool = False,
    ) -> Generator[dict[str, Any], None, None]:
        """Generator version of _stream_output_and_maybe_abort that yields lines

        Yields:
            dict: For each line: {
                'line': str,           # Raw line content
                'formatted': str,      # Colorized/formatted line
                'should_show': bool,   # Whether line should be shown in compact mode
                'is_error': bool,      # Whether line matches error patterns
                'process_running': bool # Whether process is still active
                'is_context': bool     # Whether this is error context (optional)
            }
        """
        # Pattern indicating a test failure line in Odoo output
        failure_patterns = [
            re.compile(r"\\bFAIL:\\s", re.IGNORECASE),
            re.compile(r"\\bERROR:\\s", re.IGNORECASE),
        ]

        # Pattern indicating an INFO line (end of error message)
        info_pattern = re.compile(r"\\bINFO:\\s", re.IGNORECASE)

        if not process.stdout:
            return

        for line in process.stdout:
            # Check if we should show this line in compact mode
            should_show_line = True
            if compact:
                should_show_line = self._should_show_line_in_compact(
                    line,
                )

            is_error = any(p.search(line) for p in failure_patterns)

            # Yield line information
            yield {
                "line": line,
                "formatted": self._colorize_log_line(line),
                "should_show": should_show_line,
                "is_error": is_error,
                "process_running": True,
            }

            # Handle output if not suppress_output
            self._handle_line_output(line, should_show_line, compact, suppress_output)

            if stop_on_error and is_error:
                # Yield error context lines
                context_lines = self._collect_error_context(
                    process, suppress_output, info_pattern
                )
                for context_line in context_lines:
                    yield {
                        "line": context_line,
                        "formatted": self._colorize_log_line(context_line),
                        "should_show": True,
                        "is_error": False,
                        "process_running": True,
                        "is_context": True,
                    }

                # Terminate process
                self._terminate_process_on_error(process, suppress_output)
                break

    def run_command_yielding(
        self,
        cmd: list[str],
        stop_on_error: bool = False,
        compact: bool = False,
        verbose: bool = False,
        suppress_output: bool = False,
    ) -> Generator[dict[str, Any], None, None]:
        """Generator version of run_command that yields lines as they arrive

        Args:
            cmd: Command to execute
            stop_on_error: Stop execution on first error pattern
            compact: Only show relevant lines (dots, errors, warnings)
            verbose: Print command before execution
            suppress_output: Don't print lines to console (only yield them)

        Yields:
            For each line:

            - dict: {'line': str, 'formatted': str, 'should_show': bool,
              'is_error': bool, 'process_running': bool}

            Final yield:

            - dict: {'result': dict, 'process_running': False}
        """
        if verbose and not suppress_output:
            print_info(f"Running command: {' '.join(cmd)}")
        process = None
        stdin_data = None
        output_lines = []

        try:
            process, stdin_data = self._spawn_process_with_optional_sudo(cmd)
            self._write_process_stdin(process, stdin_data)

            # Yield from the streaming generator
            for item in self._stream_output_yielding(
                process, stop_on_error, compact, suppress_output
            ):
                line = item.get("line")
                if line is not None:
                    output_lines.append(line)
                yield item

            process.wait()

            if process.returncode != 0:
                if not suppress_output:
                    print_error(f"Command exited with code {process.returncode}")
                yield {
                    "result": {
                        "success": False,
                        "return_code": process.returncode,
                        "output": "".join(output_lines),
                        "command": " ".join(cmd),
                    },
                    "process_running": False,
                }
            else:
                yield {
                    "result": {
                        "success": True,
                        "return_code": 0,
                        "output": "".join(output_lines),
                        "command": " ".join(cmd),
                    },
                    "process_running": False,
                }

        except KeyboardInterrupt:
            if not suppress_output:
                print_error("Interrupted by user. Terminating subprocess...")
            if process:
                self._terminate_process_cross_platform(process)
            yield {
                "result": {
                    "success": False,
                    "error": "Interrupted by user",
                    "output": "".join(output_lines),
                    "command": " ".join(cmd),
                },
                "process_running": False,
            }

        except FileNotFoundError:
            error_msg = f"Command not found: {cmd[0]}"
            if not suppress_output:
                print_error(error_msg)
            yield {
                "result": {
                    "success": False,
                    "error": error_msg,
                    "command": " ".join(cmd),
                },
                "process_running": False,
            }
        except Exception as e:
            error_msg = f"Error running command: {e}"
            if not suppress_output:
                print_error(error_msg)
            yield {
                "result": {
                    "success": False,
                    "error": error_msg,
                    "output": "".join(output_lines),
                    "command": " ".join(cmd),
                },
                "process_running": False,
            }

    def run_shell_command(
        self,
        cmd: list[str] | str,
        verbose: bool = False,
        capture_output: bool = False,
        allow_shell: bool = False,
        input_data: str | None = None,
    ) -> dict[str, Any]:
        """Run a shell command that may receive piped input

        Args:
            cmd: Either a list of command arguments or a string to be evaluated by shell
            verbose: Print command before execution
            capture_output: Capture stdout/stderr instead of inheriting
            allow_shell: Allow shell string evaluation when cmd is a string
            input_data: Optional data to send to stdin
        """
        # Determine if cmd is a string (shell evaluation) or list (direct execution)
        use_shell = isinstance(cmd, str)

        if use_shell and not allow_shell:
            error_msg = "String commands require allow_shell=True"
            print_error(error_msg)
            return {"success": False, "error": error_msg}

        if (
            not use_shell
            and isinstance(cmd, list)
            and cmd
            and cmd[0] == "sudo"
            and "-S" in cmd
            and input_data is None
        ):
            input_data = f"{self._get_sudo_password()}\n"

        stdin_target = subprocess.PIPE if input_data is not None else None

        if verbose:
            if use_shell:
                print_info(f"Running shell command: {cmd}")
            else:
                print_info(f"Running shell command: {' '.join(cmd)}")

        process = None
        try:
            if capture_output:
                # For JSON format, capture output instead of inheriting
                process = subprocess.Popen(
                    cmd,
                    shell=use_shell,
                    stdin=stdin_target,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    **self._get_process_kwargs(),
                )

                # Wait for completion and capture output
                stdout, stderr = process.communicate(input=input_data)
                return_code = process.returncode

                result = {
                    "success": return_code == 0,
                    "return_code": return_code,
                    "stdout": stdout,
                    "stderr": stderr,
                    "command": cmd if use_shell else " ".join(cmd),
                }

                if return_code != 0:
                    result["error"] = f"Shell command exited with code {return_code}"

                return result
            else:
                # For shell commands, we want stdin to be inherited and
                # stdout/stderr to go directly to the terminal
                process = subprocess.Popen(
                    cmd,
                    shell=use_shell,
                    stdin=stdin_target,
                    stdout=None,
                    stderr=None,
                    text=True,
                    **self._get_process_kwargs(),
                )

                # Wait for the process to complete
                if input_data is not None:
                    process.communicate(input=input_data)
                    return_code = process.returncode
                else:
                    return_code = process.wait()

                if return_code != 0:
                    print_error(f"Shell command exited with code {return_code}")
                    return {
                        "success": False,
                        "return_code": return_code,
                        "command": cmd if use_shell else " ".join(cmd),
                    }

                return {
                    "success": True,
                    "return_code": 0,
                    "command": cmd if use_shell else " ".join(cmd),
                }

        except KeyboardInterrupt:
            print_error("Interrupted by user. Terminating subprocess...")
            if process:
                self._terminate_process_cross_platform(process)
            return {
                "success": False,
                "error": "Interrupted by user",
                "command": cmd if use_shell else " ".join(cmd),
            }

        except FileNotFoundError:
            if use_shell:
                error_msg = f"Shell command failed: {cmd}"
            else:
                error_msg = f"Command not found: {cmd[0]}"
            print_error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "command": cmd if use_shell else " ".join(cmd),
            }
        except Exception as e:
            error_msg = f"Error running shell command: {e}"
            print_error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "command": cmd if use_shell else " ".join(cmd),
            }

    @staticmethod
    def run_interactive_shell(cmd: list[str]) -> int:
        """Run an interactive shell command with proper cross-platform handling"""
        print_info(f"Running interactive shell: {' '.join(cmd)}")

        if IS_WINDOWS:
            # Windows: Simple subprocess without PTY
            try:
                process = subprocess.Popen(
                    cmd,
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    creationflags=0x00000200,  # CREATE_NEW_PROCESS_GROUP
                )
                return process.wait()
            except Exception as e:
                print_error(f"Error running interactive shell: {e}")
                return 1

        elif not HAS_PTY:
            # Unix without PTY support - fallback
            try:
                process = subprocess.Popen(
                    cmd,
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    preexec_fn=os.setsid,
                )
                return process.wait()
            except Exception as e:
                print_error(f"Error running interactive shell: {e}")
                return 1

        else:
            # Unix with PTY support - original implementation
            import pty
            import termios
            import tty

            old_tty = None
            try:
                old_tty = termios.tcgetattr(sys.stdin)
                tty.setraw(sys.stdin.fileno())
            except (termios.error, AttributeError) as e:
                print_warning(f"Could not configure terminal: {e}")
                old_tty = None

            # Open pseudo-terminal to interact with subprocess
            master_fd, slave_fd = pty.openpty()

            try:
                # Use os.setsid to make it run in a new process group
                p = subprocess.Popen(
                    cmd,
                    preexec_fn=os.setsid,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    universal_newlines=True,
                )

                os.close(slave_fd)  # Close slave once p is using it

                # Interactive loop to handle I/O
                while p.poll() is None:
                    try:
                        r, w, exc = select.select([sys.stdin, master_fd], [], [], 0.1)
                        if sys.stdin in r:
                            try:
                                data = os.read(sys.stdin.fileno(), 10240)
                                if data:
                                    os.write(master_fd, data)
                            except OSError:
                                # PTY closed or process terminated
                                break
                        elif master_fd in r:
                            try:
                                data = os.read(master_fd, 10240)
                                if data:
                                    os.write(sys.stdout.fileno(), data)
                                else:
                                    # EOF from process
                                    break
                            except OSError:
                                # PTY closed or process terminated
                                break
                    except OSError:
                        # Select error or PTY issues
                        break

                # Drain any remaining output
                try:
                    while True:
                        r, w, exc = select.select([master_fd], [], [], 0.1)
                        if master_fd in r:
                            data = os.read(master_fd, 10240)
                            if data:
                                os.write(sys.stdout.fileno(), data)
                            else:
                                break
                        else:
                            break
                except OSError:
                    pass

                return p.returncode or 0

            finally:
                # Restore terminal settings
                if old_tty and termios:
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)

                os.close(master_fd)
