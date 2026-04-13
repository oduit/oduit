import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from oduit.cli.app import app


def _mock_config() -> dict[str, str]:
    return {
        "db_name": "test_db",
        "addons_path": "/test/addons",
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }


def test_exec_json_output_is_enveloped() -> None:
    runner = CliRunner()
    loader = MagicMock()
    loader.load_config.return_value = _mock_config()
    ops = MagicMock()
    ops.execute_code.return_value = {
        "success": True,
        "operation": "execute_code",
        "read_only": False,
        "safety_level": "unsafe_arbitrary_execution",
        "value": {"count": 3},
        "output": "",
        "commit": False,
    }

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations", return_value=ops),
    ):
        result = runner.invoke(app, ["--env", "dev", "--json", "exec", "1 + 2"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "code_execution"
    assert payload["operation"] == "execute_code"
    assert payload["read_only"] is False
    assert payload["safety_level"] == "unsafe_arbitrary_execution"
    assert payload["value"]["count"] == 3


def test_inspect_ref_text_output() -> None:
    runner = CliRunner()
    loader = MagicMock()
    loader.load_config.return_value = _mock_config()
    ops = MagicMock()
    ops.inspect_ref.return_value = {
        "success": True,
        "operation": "inspect_ref",
        "xmlid": "base.action_partner_form",
        "model": "ir.actions.act_window",
        "res_id": 7,
        "display_name": "Partners",
        "read_only": True,
        "safety_level": "safe_read_only",
    }

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations", return_value=ops),
    ):
        result = runner.invoke(
            app, ["--env", "dev", "inspect", "ref", "base.action_partner_form"]
        )

    assert result.exit_code == 0
    assert "XMLID: base.action_partner_form" in result.output
    assert "Model: ir.actions.act_window" in result.output


def test_inspect_modules_names_only_text() -> None:
    runner = CliRunner()
    loader = MagicMock()
    loader.load_config.return_value = _mock_config()
    ops = MagicMock()
    ops.inspect_modules.return_value = {
        "success": True,
        "operation": "inspect_modules",
        "names": ["base", "sale"],
        "modules": [
            {"name": "base", "state": "installed"},
            {"name": "sale", "state": "installed"},
        ],
        "read_only": True,
        "safety_level": "safe_read_only",
    }

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations", return_value=ops),
    ):
        result = runner.invoke(
            app, ["--env", "dev", "inspect", "modules", "--names-only"]
        )

    assert result.exit_code == 0
    assert result.output.strip().splitlines() == ["base", "sale"]


def test_db_table_not_found_exits_non_zero() -> None:
    runner = CliRunner()
    loader = MagicMock()
    loader.load_config.return_value = _mock_config()
    ops = MagicMock()
    ops.describe_table.return_value = {
        "success": False,
        "operation": "describe_table",
        "error": "Table 'missing_table' was not found",
        "error_type": "NotFoundError",
        "read_only": True,
        "safety_level": "safe_read_only",
    }

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations", return_value=ops),
    ):
        result = runner.invoke(app, ["--env", "dev", "db", "table", "missing_table"])

    assert result.exit_code == 1
    assert "missing_table" in result.output


def test_manifest_check_json_output_for_path(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_dir = tmp_path / "my_module"
    addon_dir.mkdir()
    (addon_dir / "__manifest__.py").write_text(
        str({"name": "My Module", "version": "17.0.1.0.0", "depends": ["base"]})
    )
    loader = MagicMock()
    loader.load_config.return_value = {
        **_mock_config(),
        "addons_path": str(tmp_path),
    }

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            ["--env", "dev", "--json", "manifest", "check", str(addon_dir)],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "manifest_validation"
    assert payload["operation"] == "manifest_check"
    assert payload["module"] == "my_module"


def test_manifest_show_json_includes_manifest_data(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_dir = tmp_path / "my_module"
    addon_dir.mkdir()
    (addon_dir / "__manifest__.py").write_text(
        str(
            {
                "name": "My Module",
                "version": "17.0.1.0.0",
                "depends": ["base"],
                "license": "LGPL-3",
            }
        )
    )
    loader = MagicMock()
    loader.load_config.return_value = {
        **_mock_config(),
        "addons_path": str(tmp_path),
    }

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            ["--env", "dev", "--json", "manifest", "show", str(addon_dir)],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "manifest"
    assert payload["operation"] == "manifest_show"
    assert payload["manifest_data"]["license"] == "LGPL-3"
