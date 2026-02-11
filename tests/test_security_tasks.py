import sys
import types
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from oduit.odoo_code_executor import OdooCodeExecutor
from oduit.odoo_operations import OdooOperations
from oduit.process_manager import ProcessManager


class TestSec1ShellExecution(unittest.TestCase):
    def test_execute_python_code_uses_stdin_with_list_command(self) -> None:
        config = {
            "odoo_bin": "odoo-bin",
            "db_name": "test_db",
            "addons_path": "./addons",
            "shell_interface": "python",
        }
        ops = OdooOperations(config)
        payload = 'print("x")\nprint("$(uname); `id`; ;")'

        with patch.object(ops.process_manager, "run_shell_command") as mock_shell:
            mock_shell.return_value = {
                "success": True,
                "return_code": 0,
                "stdout": "x\n",
                "stderr": "",
            }

            result = ops.execute_python_code(
                python_code=payload,
                capture_output=True,
                suppress_output=True,
                shell_interface="python",
            )

        self.assertTrue(result["success"])
        called_command = mock_shell.call_args.args[0]
        self.assertIsInstance(called_command, list)
        self.assertEqual(mock_shell.call_args.kwargs["input_data"], f"{payload}\n")
        self.assertNotIn("full_command", result)

    @patch("oduit.process_manager.subprocess.Popen")
    def test_string_shell_command_requires_opt_in(self, mock_popen: MagicMock) -> None:
        pm = ProcessManager()
        result = pm.run_shell_command("echo test", capture_output=True)

        self.assertFalse(result["success"])
        self.assertIn("allow_shell=True", result["error"])
        mock_popen.assert_not_called()


class TestSec2SudoHandling(unittest.TestCase):
    def test_spawn_process_with_optional_sudo_uses_stdin_password(self) -> None:
        pm = ProcessManager()
        fake_process = MagicMock()

        with (
            patch.object(pm, "_get_sudo_password", return_value="secret") as mock_get,
            patch.object(
                pm, "_create_subprocess", return_value=fake_process
            ) as mock_create,
        ):
            process, stdin_data = pm._spawn_process_with_optional_sudo(
                ["sudo", "-S", "whoami"]
            )

        self.assertIs(process, fake_process)
        self.assertEqual(stdin_data, "secret\n")
        mock_get.assert_called_once_with()
        mock_create.assert_called_once_with(["sudo", "-S", "whoami"], stdin_pipe=True)

    def test_run_command_writes_password_to_stdin(self) -> None:
        pm = ProcessManager()
        process = MagicMock()
        process.stdin = MagicMock()
        process.returncode = 0

        with (
            patch.object(
                pm,
                "_spawn_process_with_optional_sudo",
                return_value=(process, "secret\n"),
            ),
            patch.object(pm, "_stream_output_and_maybe_abort", return_value=[]),
        ):
            result = pm.run_command(["sudo", "-S", "true"], suppress_output=True)

        self.assertTrue(result["success"])
        process.stdin.write.assert_called_once_with("secret\n")
        process.stdin.flush.assert_called_once_with()
        process.stdin.close.assert_called_once_with()

    def test_clear_sudo_password(self) -> None:
        pm = ProcessManager()
        pm._sudo_password = "secret"
        pm.clear_sudo_password()
        self.assertIsNone(pm._sudo_password)


class TestSec3TrustedExecution(unittest.TestCase):
    def test_execute_code_requires_allow_unsafe(self) -> None:
        executor = OdooCodeExecutor(MagicMock())
        result = executor.execute_code("1 + 1")

        self.assertFalse(result["success"])
        self.assertIn("allow_unsafe", result["error"])

    def test_execute_multiple_requires_allow_unsafe(self) -> None:
        executor = OdooCodeExecutor(MagicMock())
        result = executor.execute_multiple(["1 + 1"])

        self.assertFalse(result["success"])
        self.assertIn("allow_unsafe", result["error"])

    @unittest.skipIf(sys.platform == "win32", "SIGALRM timeout test is Unix-only")
    def test_execute_trusted_times_out(self) -> None:
        executor = OdooCodeExecutor(MagicMock())
        result = executor._execute_trusted("while True: pass", {}, 0.1)

        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"].lower())

    def test_execute_with_database_rolls_back_on_failure(self) -> None:
        executor = OdooCodeExecutor(MagicMock())
        cursor = MagicMock()

        class FakeCursorContext:
            def __enter__(self) -> MagicMock:
                return cursor

            def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
                return False

        class FakeRegistry:
            def cursor(self) -> FakeCursorContext:
                return FakeCursorContext()

        class FakeEnvironment:
            def __getitem__(self, item: str) -> Any:
                return types.SimpleNamespace(context_get=lambda: {})

        odoo_stub = types.SimpleNamespace(
            SUPERUSER_ID=1,
            registry=lambda db_name: FakeRegistry(),
            api=types.SimpleNamespace(
                Environment=lambda cr, uid, ctx: FakeEnvironment()
            ),
        )

        with (
            patch.dict(sys.modules, {"odoo": odoo_stub}),
            patch.object(
                executor,
                "_execute_trusted",
                return_value={
                    "success": False,
                    "value": None,
                    "output": "",
                    "error": "Execution timed out",
                    "traceback": "",
                },
            ),
        ):
            result = executor._execute_with_database(
                "while True: pass",
                "test_db",
                commit=True,
                timeout=0.1,
            )

        self.assertFalse(result["success"])
        cursor.rollback.assert_called_once_with()
        cursor.commit.assert_not_called()
