import json
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from oduit.cli.app import app


def _make_executable(path: Path) -> str:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def _agent_config(tmp_path: Path, addons_path: str) -> dict[str, str]:
    return {
        "python_bin": _make_executable(tmp_path / "python3"),
        "odoo_bin": _make_executable(tmp_path / "odoo-bin"),
        "coverage_bin": _make_executable(tmp_path / "coverage"),
        "addons_path": addons_path,
        "db_name": "test_db",
        "db_host": "localhost",
        "db_user": "odoo",
    }


def _loader_with_config(config: dict[str, str], tmp_path: Path) -> MagicMock:
    loader = MagicMock()
    loader.load_config.return_value = config
    loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
    return loader


def _make_addon(
    addons_dir: Path, module_name: str, depends: list[str] | None = None
) -> Path:
    module_dir = addons_dir / module_name
    module_dir.mkdir(parents=True)
    (module_dir / "__manifest__.py").write_text(
        str(
            {
                "name": module_name,
                "version": "17.0.1.0.0",
                "depends": depends or ["base"],
            }
        )
    )
    return module_dir


def test_agent_workflow_for_partner_field_change(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = _make_addon(addons_dir, "my_partner")
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    name2 = fields.Char()\n"
    )
    (addon_dir / "tests").mkdir()
    (addon_dir / "tests" / "test_partner.py").write_text(
        "MODEL = 'res.partner'\nFIELD = 'email3'\n"
    )
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.cli.app.OdooOperations.get_model_fields",
            return_value=MagicMock(
                success=True,
                error=None,
                error_type=None,
                to_dict=lambda: {
                    "success": True,
                    "operation": "get_model_fields",
                    "model": "res.partner",
                    "field_names": ["name", "email"],
                    "field_definitions": {"name": {"type": "char"}},
                },
            ),
        ),
        patch(
            "oduit.cli.app.OdooOperations.run_tests",
            return_value={
                "success": True,
                "operation": "test",
                "return_code": 0,
                "total_tests": 1,
                "passed_tests": 1,
                "failed_tests": 0,
                "error_tests": 0,
                "failures": [],
                "command": ["odoo-bin", "--test-tags", "/my_partner"],
            },
        ),
    ):
        inspect_payload = json.loads(
            runner.invoke(
                app, ["--env", "dev", "agent", "inspect-addon", "my_partner"]
            ).output
        )
        fields_payload = json.loads(
            runner.invoke(
                app,
                [
                    "--env",
                    "dev",
                    "agent",
                    "get-model-fields",
                    "res.partner",
                    "--attributes",
                    "string,type,required",
                ],
            ).output
        )
        locate_payload = json.loads(
            runner.invoke(
                app,
                [
                    "--env",
                    "dev",
                    "agent",
                    "locate-model",
                    "res.partner",
                    "--module",
                    "my_partner",
                ],
            ).output
        )
        plan_payload = json.loads(
            runner.invoke(
                app, ["--env", "dev", "agent", "plan-update", "my_partner"]
            ).output
        )
        tests_payload = json.loads(
            runner.invoke(
                app,
                [
                    "--env",
                    "dev",
                    "agent",
                    "test-summary",
                    "--allow-mutation",
                    "--module",
                    "my_partner",
                    "--test-tags",
                    "/my_partner",
                ],
            ).output
        )

    inspect_data = inspect_payload["data"]
    fields_data = fields_payload["data"]
    locate_data = locate_payload["data"]
    plan_data = plan_payload["data"]
    tests_data = tests_payload["data"]

    assert inspect_data["module_path"].endswith("my_partner")
    assert "email3" not in fields_data["field_names"]
    assert locate_data["candidates"][0]["path"].endswith("models/res_partner.py")
    assert plan_data["module"] == "my_partner"
    assert tests_payload["success"] is True
    assert tests_data["selected_modules"] == ["my_partner"]


def test_prepare_addon_change_matches_partner_field_planning_flow(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = _make_addon(addons_dir, "my_partner")
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    name2 = fields.Char()\n"
    )
    (addon_dir / "tests").mkdir()
    (addon_dir / "tests" / "test_partner.py").write_text(
        "MODEL = 'res.partner'\nFIELD = 'email3'\n"
    )
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.cli.app.OdooOperations.get_model_fields",
            return_value=MagicMock(
                success=True,
                error=None,
                error_type=None,
                to_dict=lambda: {
                    "success": True,
                    "operation": "get_model_fields",
                    "model": "res.partner",
                    "field_names": ["name", "email"],
                    "field_definitions": {"name": {"type": "char"}},
                },
            ),
        ),
        patch(
            "oduit.cli.app.OdooOperations.get_model_views",
            return_value=MagicMock(
                error=None,
                error_type=None,
                warnings=[],
                remediation=[],
                to_dict=lambda: {
                    "model": "res.partner",
                    "requested_types": [],
                    "primary_views": [],
                    "extension_views": [],
                    "view_counts": {
                        "total": 0,
                        "primary": 0,
                        "extension": 0,
                    },
                },
            ),
        ),
    ):
        payload = json.loads(
            runner.invoke(
                app,
                [
                    "--env",
                    "dev",
                    "agent",
                    "prepare-addon-change",
                    "my_partner",
                    "--model",
                    "res.partner",
                    "--field",
                    "email3",
                ],
            ).output
        )

    assert payload["success"] is True
    data = payload["data"]
    assert data["steps"]["locate_model"]["data"]["candidates"][0]["path"].endswith(
        "models/res_partner.py"
    )
    assert data["steps"]["locate_field"]["data"]["insertion_candidate"][
        "path"
    ].endswith("models/res_partner.py")
    assert data["steps"]["list_addon_tests"]["data"]["tests"][0]["path"].endswith(
        "tests/test_partner.py"
    )
    assert data["recommended_next_steps"][-2].startswith(
        "Run `oduit --env dev agent validate-addon-change my_partner"
    )


def test_agent_install_module_dry_run_payload_has_data_nesting(tmp_path: Path) -> None:
    """Verify install-module --dry-run nests module info under payload["data"]."""
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "my_mod", depends=["base"])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        payload = json.loads(
            runner.invoke(
                app,
                ["--env", "dev", "agent", "install-module", "my_mod", "--dry-run"],
            ).output
        )

    assert payload["type"] == "addon_inspection"
    assert payload["operation"] == "install_module"
    assert payload["read_only"] is True
    assert payload["safety_level"] == "safe_read_only"
    data = payload["data"]
    assert data["module"] == "my_mod"
    assert data["planned_action"] == "install"
    assert data["dry_run"] is True


def test_agent_validate_addon_change_failure_payload_has_data_nesting(
    tmp_path: Path,
) -> None:
    """Verify validate-addon-change failure nests verification_summary under data."""
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "bad_mod", depends=["nonexistent_dep"])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    install_state = MagicMock()
    install_state.success = True
    install_state.record_found = False
    install_state.state = "uninstalled"
    install_state.installed = False
    install_state.database = "test_db"
    install_state.error = None
    install_state.error_type = None

    install_result = {
        "success": False,
        "operation": "install",
        "error": "dependency not found",
        "error_type": "DependencyError",
        "return_code": 1,
    }

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.cli.app.OdooOperations.get_addon_install_state",
            return_value=install_state,
        ),
        patch(
            "oduit.cli.app.OdooOperations.install_module",
            return_value=install_result,
        ),
    ):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "validate-addon-change",
                "bad_mod",
                "--allow-mutation",
                "--install-if-needed",
            ],
        )
        payload = json.loads(result.output.splitlines()[-1])

    assert result.exit_code == 1
    assert payload["success"] is False
    assert payload["type"] == "addon_change_validation"
    assert payload["operation"] == "validate_addon_change"
    assert payload["read_only"] is False
    assert payload["safety_level"] == "controlled_runtime_mutation"
    data = payload["data"]
    assert data["module"] == "bad_mod"
    assert data["verification_summary"]["failed_step"] is not None
    assert payload["errors"]
    assert payload["remediation"]
