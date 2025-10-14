from unittest.mock import patch

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
