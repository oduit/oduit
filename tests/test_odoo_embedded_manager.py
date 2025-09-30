# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from oduit.config_provider import ConfigProvider
from oduit.odoo_embedded_manager import OdooEmbeddedManager


class TestOdooEmbeddedManager(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "db_name": "test_db",
            "addons_path": "/path/to/addons",
            "http_port": "8069",
            "db_host": "localhost",
            "db_port": "5432",
            "db_user": "test_user",
        }
        self.config_provider = ConfigProvider(self.config)
        self.manager = OdooEmbeddedManager(self.config_provider)

    def tearDown(self):
        """Clean up after tests."""
        # Ensure manager is stopped
        if hasattr(self.manager, "_is_running") and self.manager._is_running:
            self.manager._is_running = False

    def test_init(self):
        """Test OdooEmbeddedManager initialization."""
        manager = OdooEmbeddedManager(self.config_provider)

        self.assertEqual(manager.config_provider, self.config_provider)
        self.assertIsNone(manager._server_thread)
        self.assertIsNone(manager._server_pid)
        self.assertFalse(manager._is_running)
        self.assertIsInstance(manager._logger, logging.Logger)
        self.assertEqual(manager._logger.name, "oduit.embedded")

    @patch("getpass.getuser")
    @patch("oduit.odoo_embedded_manager.print_warning")
    def test_check_root_user_warning(self, mock_print_warning, mock_getuser):
        """Test warning when running as root user on POSIX systems."""
        mock_getuser.return_value = "root"

        with patch("os.name", "posix"):
            self.manager._check_root_user()

        mock_print_warning.assert_called_once_with(
            "Running as user 'root' is a security risk."
        )

    @patch("getpass.getuser")
    @patch("oduit.odoo_embedded_manager.print_warning")
    def test_check_root_user_no_warning_non_posix(
        self, mock_print_warning, mock_getuser
    ):
        """Test no warning on non-POSIX systems."""
        with patch("os.name", "nt"):
            self.manager._check_root_user()

        mock_print_warning.assert_not_called()

    @patch("oduit.odoo_embedded_manager.print_error")
    @patch("sys.exit")
    def test_check_postgres_user_exit(self, mock_exit, mock_print_error):
        """Test exit when configured database user is 'postgres'."""
        config = {"db_user": "postgres"}
        config_provider = ConfigProvider(config)
        manager = OdooEmbeddedManager(config_provider)

        manager._check_postgres_user()

        mock_print_error.assert_called_once_with(
            "Using the database user 'postgres' is a security risk, aborting."
        )
        mock_exit.assert_called_once_with(1)

    @patch.dict(os.environ, {"PGUSER": "postgres"})
    @patch("oduit.odoo_embedded_manager.print_error")
    @patch("sys.exit")
    def test_check_postgres_user_env_exit(self, mock_exit, mock_print_error):
        """Test exit when PGUSER environment variable is 'postgres'."""
        config = {}  # No db_user in config, should check environment
        config_provider = ConfigProvider(config)
        manager = OdooEmbeddedManager(config_provider)

        manager._check_postgres_user()

        mock_print_error.assert_called_once_with(
            "Using the database user 'postgres' is a security risk, aborting."
        )
        mock_exit.assert_called_once_with(1)

    def test_check_postgres_user_safe(self):
        """Test no exit when database user is safe."""
        # Should not raise any exceptions or call sys.exit
        with patch("sys.exit") as mock_exit:
            self.manager._check_postgres_user()
            mock_exit.assert_not_called()

    @patch("atexit.register")
    @patch("oduit.odoo_embedded_manager.print_info")
    def test_setup_pid_file_success(self, mock_print_info, mock_register):
        """Test successful PID file creation."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            pid_file_path = tmp_file.name

        config = {"pidfile": pid_file_path}
        config_provider = ConfigProvider(config)
        manager = OdooEmbeddedManager(config_provider)

        try:
            manager._setup_pid_file()

            # Check that PID was set
            self.assertEqual(manager._server_pid, os.getpid())

            # Check PID file contents
            with open(pid_file_path) as f:
                self.assertEqual(f.read().strip(), str(os.getpid()))

            # Check that atexit was registered
            mock_register.assert_called_once()

            # Check print_info was called
            mock_print_info.assert_called_once_with(
                f"PID file created: {pid_file_path}"
            )

        finally:
            # Clean up
            if os.path.exists(pid_file_path):
                os.unlink(pid_file_path)

    def test_setup_pid_file_no_pidfile(self):
        """Test PID file setup when no pidfile is configured."""
        config = {}
        config_provider = ConfigProvider(config)
        manager = OdooEmbeddedManager(config_provider)

        manager._setup_pid_file()

        # Should not set PID
        self.assertIsNone(manager._server_pid)

    @patch("oduit.odoo_embedded_manager.print_error")
    def test_setup_pid_file_error(self, mock_print_error):
        """Test PID file creation error handling."""
        config = {"pidfile": "/invalid/path/pidfile"}
        config_provider = ConfigProvider(config)
        manager = OdooEmbeddedManager(config_provider)

        manager._setup_pid_file()

        # Should log error
        mock_print_error.assert_called_once()
        self.assertIn("Failed to create PID file", mock_print_error.call_args[0][0])

    @patch("oduit.odoo_embedded_manager.print_info")
    def test_rm_pid_file_success(self, mock_print_info):
        """Test successful PID file removal."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            pid_file_path = tmp_file.name

        config = {"pidfile": pid_file_path}
        config_provider = ConfigProvider(config)
        manager = OdooEmbeddedManager(config_provider)

        current_pid = os.getpid()
        manager._rm_pid_file(current_pid)

        # Check that file was removed
        self.assertFalse(os.path.exists(pid_file_path))

        # Check print_info was called
        mock_print_info.assert_called_once_with(f"PID file removed: {pid_file_path}")

    @patch("oduit.odoo_embedded_manager.print_warning")
    def test_rm_pid_file_error(self, mock_print_warning):
        """Test PID file removal error handling."""
        config = {"pidfile": "/nonexistent/pidfile"}
        config_provider = ConfigProvider(config)
        manager = OdooEmbeddedManager(config_provider)

        current_pid = os.getpid()
        manager._rm_pid_file(current_pid)

        # Should log warning
        mock_print_warning.assert_called_once()
        self.assertIn("Failed to remove PID file", mock_print_warning.call_args[0][0])

    def test_rm_pid_file_wrong_pid(self):
        """Test PID file removal when PID doesn't match."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            pid_file_path = tmp_file.name

        config = {"pidfile": pid_file_path}
        config_provider = ConfigProvider(config)
        manager = OdooEmbeddedManager(config_provider)

        try:
            # Call with different PID (should not remove file)
            manager._rm_pid_file(99999)

            # Check that file still exists
            self.assertTrue(os.path.exists(pid_file_path))

        finally:
            # Clean up
            if os.path.exists(pid_file_path):
                os.unlink(pid_file_path)

    @patch("csv.field_size_limit")
    def test_configure_csv_limits(self, mock_field_size_limit):
        """Test CSV field size limit configuration."""
        self.manager._configure_csv_limits()

        # Should set limit to 500MiB
        mock_field_size_limit.assert_called_once_with(500 * 1024 * 1024)

    def test_prepare_odoo_config(self):
        """Test preparation of Odoo configuration arguments."""
        result = self.manager._prepare_odoo_config()

        # Should return result from config_provider.get_odoo_params_list()
        expected = self.config_provider.get_odoo_params_list([])
        self.assertEqual(result, expected)

    @patch("oduit.odoo_embedded_manager.print_info")
    def test_report_configuration_success(self, mock_print_info):
        """Test successful configuration reporting."""
        mock_odoo = MagicMock()
        mock_odoo.release.version = "17.0"

        with patch.dict("sys.modules", {"odoo": mock_odoo}):
            self.manager._report_configuration()

        # Check that version info was printed
        mock_print_info.assert_any_call("Odoo version 17.0")
        mock_print_info.assert_any_call("Database: test_user@localhost:5432")
        mock_print_info.assert_any_call("Addons path: /path/to/addons")

    @unittest.skip("Skip problematic import test for now")
    @patch("oduit.odoo_embedded_manager.print_error")
    def test_report_configuration_import_error(self, mock_print_error):
        """Test configuration reporting when Odoo is not available."""
        # Temporarily remove odoo from modules and patch import
        original_modules = sys.modules.copy()

        # Remove odoo related modules if they exist
        modules_to_remove = [
            key for key in sys.modules.keys() if key.startswith("odoo")
        ]
        for module in modules_to_remove:
            del sys.modules[module]

        try:
            with patch("builtins.__import__") as mock_import:

                def side_effect(name, *args, **kwargs):
                    if name == "odoo":
                        raise ImportError("No module named 'odoo'")
                    return original_modules.get(name)

                mock_import.side_effect = side_effect

                with self.assertRaises(ImportError):
                    self.manager._report_configuration()

                mock_print_error.assert_called_once_with(
                    "Odoo not available - ensure it's installed and in PYTHONPATH"
                )
        finally:
            # Restore original modules
            sys.modules.clear()
            sys.modules.update(original_modules)

    @patch("oduit.odoo_embedded_manager.print_info")
    def test_run_odoo_server_export_translation(self, mock_print_info):
        """Test translation export functionality."""
        mock_odoo = MagicMock()
        mock_tools_config = MagicMock()
        mock_tools_config.get.side_effect = lambda key: {
            "translate_out": "/path/to/export.po"
        }.get(key)
        mock_odoo.tools.config = mock_tools_config
        mock_odoo.tools.config.parse_config = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "odoo": mock_odoo,
                "odoo.service.server": MagicMock(),
                "odoo.tools.config": mock_tools_config,
                "psycopg2": MagicMock(),
            },
        ):
            with patch.object(self.manager, "_export_translation") as mock_export:
                result = self.manager._run_odoo_server(
                    ["--translate-out=/path/to/export.po"]
                )

        mock_export.assert_called_once()
        self.assertEqual(result, 0)

    def test_is_running_false(self):
        """Test is_running when server is not running."""
        self.assertFalse(self.manager.is_running())

    def test_is_running_true_no_thread(self):
        """Test is_running when server is running without thread."""
        self.manager._is_running = True
        self.assertTrue(self.manager.is_running())

    def test_is_running_true_with_thread(self):
        """Test is_running when server is running with thread."""
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True

        self.manager._is_running = True
        self.manager._server_thread = mock_thread

        self.assertTrue(self.manager.is_running())

    def test_is_running_thread_dead(self):
        """Test is_running when thread has died."""
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = False

        self.manager._is_running = True
        self.manager._server_thread = mock_thread

        self.assertFalse(self.manager.is_running())

    def test_get_server_info_not_running(self):
        """Test get_server_info when server is not running."""
        result = self.manager.get_server_info()

        expected = {
            "running": False,
            "pid": os.getpid(),
        }
        self.assertEqual(result, expected)

    def test_get_server_info_with_thread(self):
        """Test get_server_info when server has a thread."""
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True

        self.manager._is_running = True
        self.manager._server_thread = mock_thread
        self.manager._server_pid = 12345

        result = self.manager.get_server_info()

        expected = {
            "running": True,
            "pid": 12345,
            "thread_alive": True,
        }
        self.assertEqual(result, expected)

    def test_start_server_already_running(self):
        """Test start_server when server is already running."""
        self.manager._is_running = True

        result = self.manager.start_server()

        expected = {"success": False, "error": "Server is already running"}
        self.assertEqual(result, expected)

    @patch.object(OdooEmbeddedManager, "_check_root_user")
    @patch.object(OdooEmbeddedManager, "_check_postgres_user")
    @patch.object(OdooEmbeddedManager, "_configure_csv_limits")
    @patch.object(OdooEmbeddedManager, "_setup_pid_file")
    @patch.object(OdooEmbeddedManager, "_report_configuration")
    @patch.object(OdooEmbeddedManager, "_prepare_odoo_config")
    @patch.object(OdooEmbeddedManager, "_run_odoo_server")
    def test_start_server_blocking_success(
        self,
        mock_run_server,
        mock_prepare_config,
        mock_report_config,
        mock_setup_pid,
        mock_configure_csv,
        mock_check_postgres,
        mock_check_root,
    ):
        """Test successful blocking server start."""
        mock_prepare_config.return_value = ["--db-name=test"]
        mock_run_server.return_value = 0

        result = self.manager.start_server(stop_after_init=True, run_in_thread=False)

        # Check all setup methods were called
        mock_check_root.assert_called_once()
        mock_check_postgres.assert_called_once()
        mock_configure_csv.assert_called_once()
        mock_setup_pid.assert_called_once()
        mock_report_config.assert_called_once()

        # Check server was started
        mock_run_server.assert_called_once_with(["--db-name=test"], True)

        expected = {
            "success": True,
            "exit_code": 0,
            "pid": os.getpid(),
        }
        self.assertEqual(result, expected)

    @patch.object(OdooEmbeddedManager, "_check_root_user")
    @patch.object(OdooEmbeddedManager, "_check_postgres_user")
    @patch.object(OdooEmbeddedManager, "_configure_csv_limits")
    @patch.object(OdooEmbeddedManager, "_setup_pid_file")
    @patch.object(OdooEmbeddedManager, "_report_configuration")
    @patch.object(OdooEmbeddedManager, "_prepare_odoo_config")
    @patch("threading.Thread")
    def test_start_server_threaded_success(
        self,
        mock_thread_class,
        mock_prepare_config,
        mock_report_config,
        mock_setup_pid,
        mock_configure_csv,
        mock_check_postgres,
        mock_check_root,
    ):
        """Test successful threaded server start."""
        mock_prepare_config.return_value = ["--db-name=test"]
        mock_thread = MagicMock()
        mock_thread_class.return_value = mock_thread

        result = self.manager.start_server(run_in_thread=True)

        # Check thread was created and started
        mock_thread_class.assert_called_once_with(
            target=self.manager._run_odoo_server,
            args=(["--db-name=test"], False),
            daemon=False,
        )
        mock_thread.start.assert_called_once()

        # Check result
        expected = {
            "success": True,
            "thread": mock_thread,
            "pid": os.getpid(),
        }
        self.assertEqual(result, expected)
        self.assertEqual(self.manager._server_thread, mock_thread)

    @patch("oduit.odoo_embedded_manager.print_error")
    @patch.object(
        OdooEmbeddedManager, "_check_root_user", side_effect=Exception("Test error")
    )
    def test_start_server_exception(self, mock_check_root, mock_print_error):
        """Test start_server exception handling."""
        result = self.manager.start_server()

        mock_print_error.assert_called_once_with(
            "Failed to start Odoo server: Test error"
        )
        expected = {
            "success": False,
            "error": "Failed to start Odoo server: Test error",
        }
        self.assertEqual(result, expected)

    def test_stop_server_not_running(self):
        """Test stop_server when server is not running."""
        result = self.manager.stop_server()

        expected = {"success": True, "message": "Server is not running"}
        self.assertEqual(result, expected)

    @patch("oduit.odoo_embedded_manager.print_info")
    def test_stop_server_threaded_success(self, mock_print_info):
        """Test successful threaded server stop."""
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True

        self.manager._is_running = True
        self.manager._server_thread = mock_thread

        # Mock join to simulate successful stop
        mock_thread.join.side_effect = lambda timeout: setattr(
            mock_thread, "is_alive", lambda: False
        )

        result = self.manager.stop_server(timeout=1.0)

        mock_thread.join.assert_called_once_with(timeout=1.0)
        # Check that both messages were printed
        mock_print_info.assert_any_call("Stopping Odoo server...")
        mock_print_info.assert_any_call("Odoo server stopped successfully")
        expected = {"success": True}
        self.assertEqual(result, expected)

    @patch("oduit.odoo_embedded_manager.print_warning")
    def test_stop_server_timeout(self, mock_print_warning):
        """Test stop_server timeout."""
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True  # Simulates thread not stopping

        self.manager._is_running = True
        self.manager._server_thread = mock_thread

        result = self.manager.stop_server(timeout=0.1)

        expected = {
            "success": False,
            "error": "Server did not stop within 0.1 seconds",
        }
        self.assertEqual(result, expected)
        mock_print_warning.assert_called_once_with(
            "Server thread did not stop within timeout"
        )

    def test_stop_server_no_thread(self):
        """Test stop_server when there's no thread (direct execution)."""
        self.manager._is_running = True
        self.manager._server_thread = None

        result = self.manager.stop_server()

        expected = {"success": True}
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
