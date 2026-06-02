# Copyright (C) 2026 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import unittest
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

        ops.execute_code.assert_called_once()
        self.assertTrue(result["success"])
        self.assertIn("country_result", result)
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


if __name__ == "__main__":
    unittest.main()
