# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Embedded Odoo server management for direct Odoo execution.

This module provides a class that runs Odoo directly within the current process
instead of spawning external odoo-bin subprocesses. It integrates with the
existing configuration system and handles PID file management.
"""

import atexit
import csv
import logging
import os
import sys
import threading
from typing import Any

from .config_provider import ConfigProvider
from .output import print_error, print_info, print_warning


class OdooEmbeddedManager:
    """Embedded Odoo server manager for direct in-process execution.

    This class runs Odoo directly by importing and calling odoo.service.server.start()
    instead of spawning external odoo-bin processes. It provides better integration
    and control over the Odoo instance while maintaining compatibility with the
    existing configuration system.

    Features:
    - Direct Odoo execution without subprocess overhead
    - Proper PID file handling based on Odoo's server.py implementation
    - Integration with ConfigProvider for parameter management
    - Thread-safe server management
    - Graceful shutdown handling

    Attributes:
        config_provider: ConfigProvider instance for accessing configuration
        _server_thread: Thread running the Odoo server
        _server_pid: PID of the server process
        _is_running: Flag indicating if server is active
    """

    def __init__(self, config_provider: ConfigProvider):
        """Initialize the embedded Odoo manager.

        Args:
            config_provider: ConfigProvider instance with Odoo configuration
        """
        self.config_provider = config_provider
        self._server_thread: threading.Thread | None = None
        self._server_pid: int | None = None
        self._is_running = False
        self._logger = logging.getLogger("oduit.embedded")

    def _check_root_user(self) -> None:
        """Warn if the process's user is 'root' (on POSIX system)."""
        if os.name == "posix":
            import getpass

            if getpass.getuser() == "root":
                print_warning("Running as user 'root' is a security risk.")

    def _check_postgres_user(self) -> None:
        """Exit if the configured database user is 'postgres'."""
        db_user = self.config_provider.get_optional("db_user") or os.environ.get(
            "PGUSER"
        )
        if db_user == "postgres":
            print_error(
                "Using the database user 'postgres' is a security risk, aborting."
            )
            sys.exit(1)

    def _setup_pid_file(self) -> None:
        """Create a file with the process id written in it."""
        pidfile = self.config_provider.get_optional("pidfile")
        if pidfile:
            pid = os.getpid()
            self._server_pid = pid
            try:
                with open(pidfile, "w") as fd:
                    fd.write(str(pid))
                atexit.register(self._rm_pid_file, pid)
                print_info(f"PID file created: {pidfile}")
            except OSError as e:
                print_error(f"Failed to create PID file {pidfile}: {e}")

    def _rm_pid_file(self, main_pid: int) -> None:
        """Remove the PID file if this is the main process."""
        pidfile = self.config_provider.get_optional("pidfile")
        if pidfile and main_pid == os.getpid():
            try:
                os.unlink(pidfile)
                print_info(f"PID file removed: {pidfile}")
            except OSError as e:
                print_warning(f"Failed to remove PID file {pidfile}: {e}")

    def _configure_csv_limits(self) -> None:
        """Configure CSV field size limits for Odoo attachments."""
        # Set to 500MiB to handle large attachments
        csv.field_size_limit(500 * 1024 * 1024)

    def _prepare_odoo_config(self) -> list[str]:
        """Prepare Odoo configuration arguments from ConfigProvider."""
        return self.config_provider.get_odoo_params_list([])

    def _report_configuration(self) -> None:
        """Log server configuration information."""
        try:
            import odoo

            print_info(f"Odoo version {odoo.release.version}")

            # Log configuration values
            db_host = self.config_provider.get_optional("db_host", "localhost")
            db_port = self.config_provider.get_optional("db_port", "5432")
            db_user = self.config_provider.get_optional("db_user", "odoo")
            print_info(f"Database: {db_user}@{db_host}:{db_port}")

            addons_path = self.config_provider.get_optional("addons_path")
            if addons_path:
                print_info(f"Addons path: {addons_path}")

        except ImportError:
            print_error("Odoo not available - ensure it's installed and in PYTHONPATH")
            raise

    def _run_odoo_server(self, args: list[str], stop_after_init: bool = False) -> int:
        """Run the Odoo server with the given arguments.

        Args:
            args: Command line arguments for Odoo configuration
            stop_after_init: Whether to stop after initialization

        Returns:
            Exit code from the Odoo server
        """
        try:
            import odoo
            import odoo.service.server
            import odoo.tools.config
            from psycopg2 import ProgrammingError, errorcodes

            # Parse configuration
            odoo.tools.config.parse_config(args)

            config = odoo.tools.config

            # Set up database preloading
            preload = []
            if config["db_name"]:
                preload = config["db_name"].split(",")
                for db_name in preload:
                    try:
                        odoo.service.db._create_empty_database(db_name)  # type: ignore[attr-defined]
                        config["init"]["base"] = True
                    except ProgrammingError as err:
                        if err.pgcode == errorcodes.INSUFFICIENT_PRIVILEGE:
                            self._logger.info(
                                "Could not determine if database %s exists, "
                                "skipping auto-creation: %s",
                                db_name,
                                err,
                            )
                        else:
                            raise err
                    except odoo.service.db.DatabaseExists:
                        pass

            # Handle translation export/import
            if config.get("translate_out"):
                self._export_translation(config)
                return 0

            if config.get("translate_in"):
                self._import_translation(config)
                return 0

            # Configure multiprocessing if workers are specified
            if config.get("workers"):
                odoo.multi_process = True

            # Start the server
            print_info("Starting embedded Odoo server...")
            self._is_running = True

            return odoo.service.server.start(preload=preload, stop=stop_after_init)  # type: ignore[no-any-return]

        except Exception as e:
            print_error(f"Failed to start Odoo server: {e}")
            raise
        finally:
            self._is_running = False

    def _export_translation(self, config: Any) -> None:
        """Export translations to file."""
        try:
            import odoo
            import odoo.modules.registry
            import odoo.tools

            dbname = config["db_name"]

            if config["language"]:
                msg = f"language {config['language']}"
            else:
                msg = "new language"
            print_info(
                f"Exporting translation file for {msg} to {config['translate_out']}"
            )

            fileformat = os.path.splitext(config["translate_out"])[-1][1:].lower()
            if fileformat == "pot":
                fileformat = "po"

            with open(config["translate_out"], "wb") as buf:
                registry = odoo.modules.registry.Registry.new(dbname)
                with registry.cursor() as cr:
                    odoo.tools.trans_export(
                        config["language"],
                        config["translate_modules"] or ["all"],
                        buf,
                        fileformat,
                        cr,
                    )

            print_info("Translation file written successfully")
        except Exception as e:
            print_error(f"Failed to export translations: {e}")
            raise

    def _import_translation(self, config: Any) -> None:
        """Import translations from file."""
        try:
            import odoo
            import odoo.modules.registry
            import odoo.tools.translate

            overwrite = config["overwrite_existing_translations"]
            dbname = config["db_name"]

            print_info(f"Importing translation from {config['translate_in']}")

            registry = odoo.modules.registry.Registry.new(dbname)
            with registry.cursor() as cr:
                translation_importer = odoo.tools.translate.TranslationImporter(cr)
                translation_importer.load_file(
                    config["translate_in"], config["language"]
                )
                translation_importer.save(overwrite=overwrite)

            print_info("Translation imported successfully")
        except Exception as e:
            print_error(f"Failed to import translations: {e}")
            raise

    def start_server(
        self, stop_after_init: bool = False, run_in_thread: bool = False
    ) -> dict[str, Any]:
        """Start the embedded Odoo server.

        Args:
            stop_after_init: Stop server after initialization
            run_in_thread: Run server in separate thread (for non-blocking execution)

        Returns:
            Dictionary with execution results:
            - success (bool): True if server started successfully
            - thread (Thread): Server thread if run_in_thread=True
            - pid (int): Process ID
            - error (str): Error message if startup failed
        """
        if self._is_running:
            return {"success": False, "error": "Server is already running"}

        try:
            # Perform pre-startup checks
            self._check_root_user()
            self._check_postgres_user()
            self._configure_csv_limits()
            self._setup_pid_file()
            self._report_configuration()

            # Prepare configuration arguments
            args = self._prepare_odoo_config()

            if run_in_thread:
                # Start server in separate thread
                self._server_thread = threading.Thread(
                    target=self._run_odoo_server,
                    args=(args, stop_after_init),
                    daemon=False,
                )
                self._server_thread.start()

                return {
                    "success": True,
                    "thread": self._server_thread,
                    "pid": os.getpid(),
                }
            else:
                # Run server in current thread (blocking)
                exit_code = self._run_odoo_server(args, stop_after_init)

                return {
                    "success": exit_code == 0,
                    "exit_code": exit_code,
                    "pid": os.getpid(),
                }

        except Exception as e:
            error_msg = f"Failed to start Odoo server: {e}"
            print_error(error_msg)
            return {"success": False, "error": error_msg}

    def stop_server(self, timeout: float = 30.0) -> dict[str, Any]:
        """Stop the running Odoo server.

        Args:
            timeout: Maximum time to wait for server shutdown

        Returns:
            Dictionary with shutdown results:
            - success (bool): True if server stopped successfully
            - error (str): Error message if shutdown failed
        """
        if not self._is_running:
            return {"success": True, "message": "Server is not running"}

        try:
            if self._server_thread and self._server_thread.is_alive():
                # For threaded execution, we need to signal shutdown
                # This is a simplified approach - in practice, you might need
                # more sophisticated shutdown signaling
                print_info("Stopping Odoo server...")

                # Join with timeout
                self._server_thread.join(timeout=timeout)

                if self._server_thread.is_alive():
                    print_warning("Server thread did not stop within timeout")
                    return {
                        "success": False,
                        "error": f"Server did not stop within {timeout} seconds",
                    }
                else:
                    print_info("Odoo server stopped successfully")
                    return {"success": True}
            else:
                # Direct execution - server should have already stopped
                return {"success": True}

        except Exception as e:
            error_msg = f"Error stopping server: {e}"
            print_error(error_msg)
            return {"success": False, "error": error_msg}

    def is_running(self) -> bool:
        """Check if the server is currently running.

        Returns:
            True if server is running, False otherwise
        """
        return self._is_running and (
            self._server_thread is None or self._server_thread.is_alive()
        )

    def get_server_info(self) -> dict[str, Any]:
        """Get information about the server state.

        Returns:
            Dictionary with server information:
            - running (bool): Whether server is running
            - pid (int): Process ID if available
            - thread_alive (bool): Whether server thread is alive (if threaded)
        """
        info = {"running": self.is_running(), "pid": self._server_pid or os.getpid()}

        if self._server_thread:
            info["thread_alive"] = self._server_thread.is_alive()

        return info

    def start_shell(
        self, database: str | None = None, extra_args: list[str] | None = None
    ) -> dict[str, Any]:
        """Start an embedded Odoo shell session.

        Args:
            database: Database name for the shell session
            extra_args: Additional command line arguments

        Returns:
            Dictionary with execution results:
            - success (bool): True if shell started successfully
            - output (str): Shell output or success message
            - error (str): Error message if startup failed
        """
        try:
            import code
            import signal
            import threading

            import odoo
            import odoo.cli.server
            from odoo.tools import config

            def raise_keyboard_interrupt(*a: Any) -> None:
                raise KeyboardInterrupt()

            # Prepare configuration arguments
            args = self._prepare_odoo_config()
            if extra_args:
                args.extend(extra_args)

            # Configure odoo
            config.parser.prog = "odoo shell"
            config.parse_config(args)

            # Report configuration and start services
            odoo.cli.server.report_configuration()
            odoo.service.server.start(preload=[], stop=True)

            # Set up interrupt handler
            signal.signal(signal.SIGINT, raise_keyboard_interrupt)

            # Set up shell environment
            local_vars = {
                "openerp": odoo,
                "odoo": odoo,
            }

            shell_output = []

            if database or config.get("db_name"):
                db_name = database or config["db_name"]
                threading.current_thread().dbname = db_name  # type: ignore[attr-defined]

                try:
                    registry = odoo.registry(db_name)
                    with registry.cursor() as cr:
                        uid = odoo.SUPERUSER_ID
                        ctx = odoo.api.Environment(cr, uid, {})[
                            "res.users"
                        ].context_get()  # type: ignore[attr-defined]
                        env = odoo.api.Environment(cr, uid, ctx)
                        local_vars["env"] = env  # type: ignore[assignment]
                        local_vars["self"] = env.user

                        # Rollback to avoid transaction warnings
                        cr.rollback()

                        shell_output.append(f"Connected to database '{db_name}'")
                        shell_output.append("Available variables:")
                        for var_name in sorted(local_vars):
                            shell_output.append(f"  {var_name}: {local_vars[var_name]}")

                        # Start interactive console
                        try:
                            import readline
                            import rlcompleter

                            readline.set_completer(
                                rlcompleter.Completer(local_vars).complete
                            )
                            readline.parse_and_bind("tab: complete")
                        except ImportError:
                            shell_output.append(
                                "readline or rlcompleter not available, "
                                "autocomplete disabled."
                            )

                        # Create and start console
                        console = code.InteractiveConsole(
                            locals=local_vars, filename="<odoo-shell>"
                        )

                        shell_output.append("Starting Odoo shell - use Ctrl+D to exit")
                        print_info("\n".join(shell_output))

                        # This will block until user exits
                        console.interact(banner="")

                        # Rollback any uncommitted transactions
                        cr.rollback()

                except Exception as e:
                    error_msg = f"Failed to connect to database '{db_name}': {e}"
                    return {"success": False, "error": error_msg}
            else:
                shell_output.append(
                    "No database specified, use --database parameter "
                    "to connect to a database."
                )
                shell_output.append("Available variables:")
                for var_name in sorted(local_vars):
                    shell_output.append(f"  {var_name}: {local_vars[var_name]}")

                # Start console without database connection
                try:
                    import readline
                    import rlcompleter

                    readline.set_completer(rlcompleter.Completer(local_vars).complete)
                    readline.parse_and_bind("tab: complete")
                except ImportError:
                    shell_output.append(
                        "readline or rlcompleter not available, autocomplete disabled."
                    )

                console = code.InteractiveConsole(
                    locals=local_vars, filename="<odoo-shell>"
                )

                shell_output.append("Starting Odoo shell - use Ctrl+D to exit")
                print_info("\n".join(shell_output))

                # This will block until user exits
                console.interact(banner="")

            return {
                "success": True,
                "output": "Odoo shell session completed successfully",
            }

        except KeyboardInterrupt:
            return {"success": True, "output": "Shell session interrupted by user"}
        except ImportError as e:
            error_msg = f"Odoo not available for shell: {e}"
            print_error(error_msg)
            return {"success": False, "error": error_msg}
        except Exception as e:
            error_msg = f"Failed to start Odoo shell: {e}"
            print_error(error_msg)
            return {"success": False, "error": error_msg}
