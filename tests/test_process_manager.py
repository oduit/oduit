import re
from unittest.mock import MagicMock, patch

from oduit.builders import CommandOperation
from oduit.process_manager import ProcessManager


class TestProcessManagerRunOperation:
    def test_run_operation_basic(self) -> None:
        pm = ProcessManager()
        operation = CommandOperation(
            command=["echo", "test"],
            operation_type="shell",
            is_odoo_command=False,
        )

        with patch.object(pm, "run_command") as mock_run:
            mock_run.return_value = {"success": True, "output": "test\n"}
            result = pm.run_operation(operation)

        assert result["success"] is True
        mock_run.assert_called_once()

    def test_run_operation_with_verbose(self) -> None:
        pm = ProcessManager()
        operation = CommandOperation(
            command=["echo", "test"],
            operation_type="shell",
            is_odoo_command=False,
        )

        with patch.object(pm, "run_command") as mock_run:
            mock_run.return_value = {"success": True}
            pm.run_operation(operation, verbose=True)

        mock_run.assert_called_once()

    def test_run_operation_suppress_output(self) -> None:
        pm = ProcessManager()
        operation = CommandOperation(
            command=["echo", "test"],
            operation_type="shell",
            is_odoo_command=False,
        )

        with patch.object(pm, "run_command") as mock_run:
            mock_run.return_value = {"success": True}
            pm.run_operation(operation, suppress_output=True)

        mock_run.assert_called_once()


class TestProcessManagerInitialization:
    def test_init_creates_instance(self) -> None:
        pm = ProcessManager()
        assert pm is not None
        assert hasattr(pm, "_sudo_password")
        assert pm._sudo_password is None


class TestCommandOperation:
    def test_command_operation_creation(self) -> None:
        operation = CommandOperation(
            command=["odoo-bin", "-i", "sale"],
            operation_type="install",
            database="test_db",
            modules=["sale"],
            is_odoo_command=True,
        )

        assert operation.command == ["odoo-bin", "-i", "sale"]
        assert operation.operation_type == "install"
        assert operation.database == "test_db"
        assert operation.modules == ["sale"]
        assert operation.is_odoo_command is True

    def test_command_operation_defaults(self) -> None:
        operation = CommandOperation(
            command=["echo", "test"],
            operation_type="shell",
        )

        assert operation.database is None
        assert operation.modules == []
        assert operation.test_tags is None
        assert operation.extra_args == []
        assert operation.is_odoo_command is True
        assert operation.expected_result_fields == {}
        assert operation.result_parsers == []


class TestProcessManagerRunShellCommand:
    def test_run_shell_command_capture_output_returns_standard_shape(self) -> None:
        pm = ProcessManager()
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("hello\n", "")
        mock_process.returncode = 0

        with patch("oduit.process_manager.subprocess.Popen", return_value=mock_process):
            result = pm.run_shell_command(["echo", "hello"], capture_output=True)

        assert result["success"] is True
        assert result["return_code"] == 0
        assert result["stdout"] == "hello\n"
        assert result["stderr"] == ""
        assert result["output"] == "hello\n"
        assert result["command"] == "echo hello"

    def test_run_shell_command_nonzero_exit_has_error_and_shape(self) -> None:
        pm = ProcessManager()
        mock_process = MagicMock()
        mock_process.wait.return_value = 2

        with patch("oduit.process_manager.subprocess.Popen", return_value=mock_process):
            result = pm.run_shell_command(["false"], capture_output=False)

        assert result["success"] is False
        assert result["return_code"] == 2
        assert result["stdout"] == ""
        assert result["stderr"] == ""
        assert result["output"] == ""
        assert "error" in result

    def test_run_shell_command_string_requires_allow_shell(self) -> None:
        pm = ProcessManager()

        with patch("oduit.process_manager.subprocess.Popen") as mock_popen:
            result = pm.run_shell_command("echo hello", capture_output=True)

        assert result["success"] is False
        assert result["return_code"] == 1
        assert result["command"] == "echo hello"
        assert result["stdout"] == ""
        assert result["stderr"] == ""
        assert result["output"] == ""
        assert "allow_shell=True" in result["error"]
        mock_popen.assert_not_called()

    def test_run_shell_command_command_not_found_has_standard_shape(self) -> None:
        pm = ProcessManager()

        with patch(
            "oduit.process_manager.subprocess.Popen",
            side_effect=FileNotFoundError("missing"),
        ):
            result = pm.run_shell_command(["missing-cmd"], capture_output=True)

        assert result["success"] is False
        assert result["return_code"] == 127
        assert result["command"] == "missing-cmd"
        assert result["stdout"] == ""
        assert result["stderr"] == ""
        assert result["output"] == ""
        assert "Command not found" in result["error"]


class TestProcessManagerCrossPlatform:
    def test_collect_error_context_returns_empty_on_windows(self) -> None:
        pm = ProcessManager()
        process = MagicMock()
        process.stdout = MagicMock()

        with patch("oduit.process_manager.IS_WINDOWS", True):
            result = pm._collect_error_context(
                process, suppress_output=True, info_pattern=re.compile(r"\\bINFO:\\s")
            )

        assert result == []
