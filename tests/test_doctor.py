import json
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from oduit.cli_typer import app


def _make_executable(path: Path) -> str:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def _make_addon(
    addons_dir: Path, module_name: str, version: str = "17.0.1.0.0"
) -> None:
    module_dir = addons_dir / module_name
    module_dir.mkdir()
    (module_dir / "__manifest__.py").write_text(
        str(
            {
                "name": module_name.replace("_", " ").title(),
                "version": version,
                "depends": ["base"],
            }
        )
    )


def _doctor_config(tmp_path: Path) -> dict[str, str]:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "sale")

    python_bin = _make_executable(tmp_path / "python3")
    odoo_bin = _make_executable(tmp_path / "odoo-bin")
    coverage_bin = _make_executable(tmp_path / "coverage")

    return {
        "python_bin": python_bin,
        "odoo_bin": odoo_bin,
        "coverage_bin": coverage_bin,
        "addons_path": str(addons_dir),
        "db_name": "test_db",
        "db_host": "localhost",
        "db_user": "odoo",
    }


def _mock_ops(mock_odoo_ops: MagicMock, version_result: dict, db_result: dict) -> None:
    ops = MagicMock()
    ops.get_odoo_version.return_value = version_result
    ops.db_exists.return_value = db_result
    mock_odoo_ops.return_value = ops


class TestDoctorCommand:
    def setup_method(self) -> None:
        self.runner = CliRunner()

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_doctor_with_env_success(
        self,
        mock_config_loader_class: MagicMock,
        mock_odoo_ops: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _doctor_config(tmp_path)
        loader = MagicMock()
        loader.load_config.return_value = config
        loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
        mock_config_loader_class.return_value = loader

        _mock_ops(
            mock_odoo_ops,
            {
                "success": True,
                "version": "17.0",
                "return_code": 0,
                "command": [config["python_bin"], config["odoo_bin"], "--version"],
                "stdout": "Odoo 17.0",
                "stderr": "",
            },
            {
                "success": True,
                "exists": True,
                "return_code": 0,
                "command": ["psql", "-lqt"],
                "database": "test_db",
                "stdout": "",
                "stderr": "",
            },
        )

        result = self.runner.invoke(app, ["--env", "dev", "doctor"])

        assert result.exit_code == 0
        assert "Config source: env" in result.output
        assert "Detected Odoo version 17.0" in result.output
        assert "Database 'test_db' exists" in result.output
        mock_odoo_ops.return_value.db_exists.assert_called_once_with(
            with_sudo=False, suppress_output=True
        )

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_doctor_with_local_config(
        self,
        mock_config_loader_class: MagicMock,
        mock_odoo_ops: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _doctor_config(tmp_path)
        loader = MagicMock()
        loader.has_local_config.return_value = True
        loader.load_local_config.return_value = config
        loader.get_local_config_path.return_value = str(tmp_path / ".oduit.toml")
        mock_config_loader_class.return_value = loader

        _mock_ops(
            mock_odoo_ops,
            {
                "success": True,
                "version": "17.0",
                "return_code": 0,
                "command": [config["python_bin"], config["odoo_bin"], "--version"],
                "stdout": "Odoo 17.0",
                "stderr": "",
            },
            {
                "success": True,
                "exists": True,
                "return_code": 0,
                "command": ["psql", "-lqt"],
                "database": "test_db",
                "stdout": "",
                "stderr": "",
            },
        )

        result = self.runner.invoke(app, ["doctor"])

        assert result.exit_code == 0
        assert "Config source: local" in result.output
        assert str(tmp_path / ".oduit.toml") in result.output

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_doctor_missing_odoo_bin(
        self,
        mock_config_loader_class: MagicMock,
        mock_odoo_ops: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _doctor_config(tmp_path)
        config["odoo_bin"] = str(tmp_path / "missing-odoo-bin")
        loader = MagicMock()
        loader.load_config.return_value = config
        loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
        mock_config_loader_class.return_value = loader

        _mock_ops(
            mock_odoo_ops,
            {
                "success": False,
                "version": None,
                "return_code": 127,
                "error": "missing odoo-bin",
            },
            {
                "success": True,
                "exists": True,
                "return_code": 0,
                "database": "test_db",
            },
        )

        result = self.runner.invoke(app, ["--env", "dev", "doctor"])

        assert result.exit_code == 1
        assert (
            "Configured odoo_bin does not exist or is not executable" in result.output
        )

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_doctor_invalid_addons_path(
        self,
        mock_config_loader_class: MagicMock,
        mock_odoo_ops: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _doctor_config(tmp_path)
        config["addons_path"] = str(tmp_path / "missing-addons")
        loader = MagicMock()
        loader.load_config.return_value = config
        loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
        mock_config_loader_class.return_value = loader

        _mock_ops(
            mock_odoo_ops,
            {
                "success": True,
                "version": "17.0",
                "return_code": 0,
                "stdout": "Odoo 17.0",
                "stderr": "",
            },
            {
                "success": True,
                "exists": True,
                "return_code": 0,
                "database": "test_db",
            },
        )

        result = self.runner.invoke(app, ["--env", "dev", "doctor"])

        assert result.exit_code == 1
        assert "Configured addons paths are invalid" in result.output

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_doctor_version_detection_failure(
        self,
        mock_config_loader_class: MagicMock,
        mock_odoo_ops: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _doctor_config(tmp_path)
        loader = MagicMock()
        loader.load_config.return_value = config
        loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
        mock_config_loader_class.return_value = loader

        _mock_ops(
            mock_odoo_ops,
            {
                "success": False,
                "version": None,
                "return_code": 1,
                "error": "version probe failed",
            },
            {
                "success": True,
                "exists": True,
                "return_code": 0,
                "database": "test_db",
            },
        )

        result = self.runner.invoke(app, ["--env", "dev", "doctor"])

        assert result.exit_code == 1
        assert "Failed to detect Odoo version" in result.output

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_doctor_db_check_failure(
        self,
        mock_config_loader_class: MagicMock,
        mock_odoo_ops: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _doctor_config(tmp_path)
        loader = MagicMock()
        loader.load_config.return_value = config
        loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
        mock_config_loader_class.return_value = loader

        _mock_ops(
            mock_odoo_ops,
            {
                "success": True,
                "version": "17.0",
                "return_code": 0,
                "stdout": "Odoo 17.0",
                "stderr": "",
            },
            {
                "success": False,
                "exists": False,
                "return_code": 2,
                "error": "psql failed",
                "database": "test_db",
            },
        )

        result = self.runner.invoke(app, ["--env", "dev", "doctor"])

        assert result.exit_code == 1
        assert "Database existence check failed" in result.output

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_doctor_db_missing_without_connection_failure(
        self,
        mock_config_loader_class: MagicMock,
        mock_odoo_ops: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _doctor_config(tmp_path)
        loader = MagicMock()
        loader.load_config.return_value = config
        loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
        mock_config_loader_class.return_value = loader

        _mock_ops(
            mock_odoo_ops,
            {
                "success": True,
                "version": "17.0",
                "return_code": 0,
                "stdout": "Odoo 17.0",
                "stderr": "",
            },
            {
                "success": True,
                "exists": False,
                "return_code": 0,
                "database": "test_db",
                "stdout": "",
                "stderr": "",
            },
        )

        result = self.runner.invoke(app, ["--env", "dev", "doctor"])

        assert result.exit_code == 0
        assert "Database 'test_db' does not exist" in result.output

    @patch("oduit.cli_typer.OdooOperations")
    @patch("oduit.cli_typer.ConfigLoader")
    def test_doctor_json_output_structure(
        self,
        mock_config_loader_class: MagicMock,
        mock_odoo_ops: MagicMock,
        tmp_path: Path,
    ) -> None:
        config = _doctor_config(tmp_path)
        loader = MagicMock()
        loader.load_config.return_value = config
        loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
        mock_config_loader_class.return_value = loader

        _mock_ops(
            mock_odoo_ops,
            {
                "success": True,
                "version": "17.0",
                "return_code": 0,
                "stdout": "Odoo 17.0",
                "stderr": "",
            },
            {
                "success": True,
                "exists": True,
                "return_code": 0,
                "database": "test_db",
            },
        )

        result = self.runner.invoke(app, ["--env", "dev", "--json", "doctor"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["schema_version"] == "2.0"
        assert payload["type"] == "doctor_report"
        assert payload["success"] is True
        assert payload["read_only"] is True
        assert payload["safety_level"] == "safe_read_only"
        assert "warnings" in payload
        assert "errors" in payload
        assert "remediation" in payload
        assert "data" in payload
        assert "meta" in payload
        assert payload["source"]["kind"] == "env"
        assert isinstance(payload["checks"], list)
        assert payload["summary"]["ok"] >= 1
