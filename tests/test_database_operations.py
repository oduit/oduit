# Copyright (C) 2026 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from oduit.odoo_operations import OdooOperations


class TestDatabaseOperationsService(unittest.TestCase):
    def _build_ops(self) -> OdooOperations:
        ops = OdooOperations(
            {
                "python_bin": "/usr/bin/python3",
                "odoo_bin": "/opt/odoo/odoo-bin",
                "db_name": "test_db",
                "db_user": "odoo",
                "db_password": "secret",
                "db_host": "localhost",
                "db_port": 5432,
            }
        )
        ops.process_manager = MagicMock()
        ops.process_manager.run_operation.return_value = {
            "success": True,
            "return_code": 0,
            "stdout": "",
            "stderr": "",
        }
        ops.process_manager.run_command.return_value = {
            "success": True,
            "return_code": 0,
            "stdout": "",
            "stderr": "",
        }
        ops.execute_code = MagicMock(return_value={"success": True, "value": {}})
        return ops

    def test_create_db_uses_legacy_init_after_createdb(self):
        ops = self._build_ops()

        result = ops.create_db(suppress_output=True)

        create_operation = ops.process_manager.run_operation.call_args.args[0]
        init_command = ops.process_manager.run_command.call_args.args[0]
        init_command_str = " ".join(init_command)

        self.assertIn("createdb", " ".join(create_operation.command))
        self.assertIn("-i", init_command)
        self.assertIn("base", init_command)
        self.assertIn("--stop-after-init", init_command)
        self.assertIn("--no-http", init_command)
        self.assertNotIn(" db init ", f" {init_command_str} ")
        self.assertIn("command", result)
        self.assertIn("init_command", result)
        self.assertIn("init_stdout", result)
        self.assertIn("init_stderr", result)
        self.assertIn("stdout", result)
        self.assertIn("stderr", result)
        self.assertIn("return_code", result)
        self.assertIn("success", result)

    def test_create_db_legacy_init_includes_demo_and_language(self):
        ops = self._build_ops()

        ops.create_db(
            suppress_output=True,
            with_demo=True,
            language="de_DE",
        )

        init_command = ops.process_manager.run_command.call_args.args[0]
        self.assertIn("--with-demo", init_command)
        self.assertIn("--load-language=de_DE", init_command)

    def test_create_db_country_runs_post_init_update(self):
        ops = self._build_ops()
        ops.execute_code = MagicMock(
            return_value={"success": True, "value": {"country_code": "DE"}}
        )

        result = ops.create_db(
            suppress_output=True,
            country="DE",
        )

        self.assertEqual(ops.execute_code.call_count, 2)
        self.assertTrue(result["success"])
        self.assertIn("country_result", result)
        self.assertIn("admin_result", result)
        self.assertTrue(result["country_result"]["success"])

    def test_create_db_country_failure_marks_result_failed(self):
        ops = self._build_ops()
        ops.execute_code = MagicMock(
            return_value={"success": False, "error": "Country 'DE' not found"}
        )

        result = ops.create_db(
            suppress_output=True,
            country="DE",
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["return_code"], 1)
        self.assertIn("error", result)
        self.assertIn("Country 'DE' not found", result["error"])

    def test_create_db_honors_db_user_override_for_createdb(self):
        ops = self._build_ops()

        ops.create_db(suppress_output=True, db_user="custom_user")

        create_operation = ops.process_manager.run_operation.call_args.args[0]
        self.assertIn('-O "custom_user"', " ".join(create_operation.command))

    def test_create_db_rejects_conflicting_demo_flags(self):
        ops = self._build_ops()

        with self.assertRaises(ValueError):
            ops.create_db(
                suppress_output=True,
                with_demo=True,
                without_demo=True,
            )

        ops.process_manager.run_operation.assert_not_called()
        ops.process_manager.run_command.assert_not_called()

    def test_create_db_legacy_without_demo_explicit(self):
        ops = self._build_ops()

        ops.create_db(suppress_output=True, without_demo=True)

        init_command = ops.process_manager.run_command.call_args.args[0]
        self.assertIn("--without-demo=all", init_command)
        self.assertNotIn("--with-demo", init_command)

    def test_create_db_legacy_admin_update_runs_after_init(self):
        ops = self._build_ops()
        ops.execute_code = MagicMock(
            return_value={"success": True, "value": {"user_id": 1}}
        )

        result = ops.create_db(
            suppress_output=True,
            username="demo",
            password="secret",
        )

        ops.execute_code.assert_called_once()
        _args, kwargs = ops.execute_code.call_args
        self.assertTrue(kwargs.get("commit"))
        self.assertIn("base.user_admin", _args[0])
        self.assertIn("demo", _args[0])
        self.assertNotIn("password", result)
        self.assertTrue(result["admin_result"]["success"])

    def test_create_db_odoo19_uses_native_db_init_not_createdb(self):
        ops = self._build_ops()

        ops.create_db(
            suppress_output=True,
            with_demo=True,
            country="DE",
            language="de_DE",
            username="root",
            password="secret",
            odoo_series=SimpleNamespace(value="19.0"),
        )

        ops.process_manager.run_operation.assert_not_called()
        ops.execute_code.assert_not_called()
        native_command = ops.process_manager.run_command.call_args.args[0]
        self.assertIn("db", native_command)
        self.assertIn("init", native_command)
        self.assertIn("test_db", native_command)
        self.assertIn("--with-demo", native_command)
        self.assertIn("--country", native_command)
        self.assertIn("DE", native_command)
        self.assertIn("--language", native_command)
        self.assertIn("de_DE", native_command)
        self.assertIn("--username", native_command)
        self.assertIn("root", native_command)
        self.assertIn("--password", native_command)
        self.assertIn("secret", native_command)

    def test_create_db_unknown_series_uses_legacy(self):
        ops = self._build_ops()

        ops.create_db(suppress_output=True, odoo_series=None)

        create_operation = ops.process_manager.run_operation.call_args.args[0]
        init_command = ops.process_manager.run_command.call_args.args[0]
        self.assertIn("createdb", " ".join(create_operation.command))
        self.assertIn("-i", init_command)
        self.assertIn("base", init_command)

    def test_create_db_installs_extension_after_legacy_init(self):
        ops = self._build_ops()
        result = ops.create_db(
            extension="vector", suppress_output=True, with_sudo=False
        )
        self.assertTrue(result["success"])
        calls = ops.process_manager.run_operation.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertIn("createdb", " ".join(calls[0].args[0].command))
        self.assertIn(
            'CREATE EXTENSION IF NOT EXISTS "vector";', calls[1].args[0].command
        )
        self.assertEqual(result["extensions"], ["vector"])

    def test_create_db_odoo19_installs_extension_after_native_init(self):
        ops = self._build_ops()
        result = ops.create_db(
            extensions=["vector"],
            suppress_output=True,
            with_sudo=False,
            odoo_series=SimpleNamespace(value="19.0"),
        )
        self.assertTrue(result["success"])
        self.assertIn("init", ops.process_manager.run_command.call_args.args[0])
        extension_operation = ops.process_manager.run_operation.call_args.args[0]
        self.assertIn(
            'CREATE EXTENSION IF NOT EXISTS "vector";', extension_operation.command
        )

    def test_create_db_extension_failure_reports_database_created(self):
        ops = self._build_ops()
        ops.process_manager.run_operation.side_effect = [
            {"success": True, "return_code": 0},
            {
                "success": False,
                "return_code": 1,
                "stderr": 'permission denied to create extension "vector"',
            },
        ]
        result = ops.create_db(
            extensions=["vector"], suppress_output=True, with_sudo=False
        )
        self.assertFalse(result["success"])
        self.assertTrue(result["database_created"])
        self.assertIn("Database was created", result["error"])
        self.assertEqual(
            result["extension_results"][0]["error_type"],
            "ExtensionInsufficientPrivilege",
        )

    def test_create_db_supports_multiple_extensions_in_order(self):
        ops = self._build_ops()
        result = ops.create_db(
            extensions=["vector", "pg_trgm", "vector"],
            suppress_output=True,
            with_sudo=False,
        )
        operations = [
            call.args[0] for call in ops.process_manager.run_operation.call_args_list
        ]
        self.assertEqual(len(operations), 3)
        self.assertIn("createdb", " ".join(operations[0].command))
        self.assertIn('"vector"', operations[1].command[9])
        self.assertIn('"pg_trgm"', operations[2].command[9])
        self.assertEqual(result["extensions"], ["vector", "pg_trgm"])

    def test_create_db_preserves_legacy_singular_extension_argument(self):
        ops = self._build_ops()
        result = ops.create_db(
            extension="vector", suppress_output=True, with_sudo=False
        )
        self.assertEqual(result["extensions"], ["vector"])
        self.assertEqual(len(result["extension_results"]), 1)

    def test_install_db_extension_success(self):
        ops = self._build_ops()
        result = ops.install_db_extension(
            "vector", with_sudo=False, suppress_output=True
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["operation"], "install_db_extension")
        self.assertEqual(result["database"], "test_db")
        self.assertEqual(result["extension"], "vector")
        self.assertFalse(result["with_sudo"])
        operation = ops.process_manager.run_operation.call_args.args[0]
        self.assertIn('CREATE EXTENSION IF NOT EXISTS "vector";', operation.command)

    def test_install_db_extension_failure_classifies_privilege(self):
        ops = self._build_ops()
        ops.process_manager.run_operation.return_value = {
            "success": False,
            "return_code": 1,
            "stdout": "",
            "stderr": 'permission denied to create extension "vector"',
        }
        result = ops.install_db_extension("vector", suppress_output=True)
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "ExtensionInsufficientPrivilege")
        self.assertIn("--with-sudo", result["remediation"][0])

    def test_install_db_extension_raise_on_error_attaches_result(self):
        from oduit.exceptions import DatabaseOperationError

        ops = self._build_ops()
        ops.process_manager.run_operation.return_value = {
            "success": False,
            "return_code": 1,
            "stdout": "",
            "stderr": 'extension "vector" is not available',
        }
        with self.assertRaises(DatabaseOperationError) as context:
            ops.install_db_extension(
                "vector", suppress_output=True, raise_on_error=True
            )
        self.assertEqual(
            context.exception.operation_result["error_type"],
            "ExtensionNotAvailable",
        )

    def test_install_db_extension_forwards_db_user(self):
        ops = self._build_ops()
        ops.install_db_extension(
            "vector", with_sudo=False, db_user="custom", suppress_output=True
        )
        operation = ops.process_manager.run_operation.call_args.args[0]
        self.assertIn("-U", operation.command)
        self.assertIn("custom", operation.command)


if __name__ == "__main__":
    unittest.main()
