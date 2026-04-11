import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from oduit import ConfigError
from oduit.api_models import AddonInstallState, ModelViewInventory, ModelViewRecord
from oduit.cli.app import app
from oduit.config_provider import ConfigProvider

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"


def _make_executable(path: Path) -> str:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | 0o100)
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
        "db_password": "super-secret",
    }


def _loader_with_config(config: dict[str, str], tmp_path: Path) -> MagicMock:
    loader = MagicMock()
    loader.load_config.return_value = config
    loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
    details = SimpleNamespace(
        config=config,
        canonical_config=ConfigProvider(config).to_sectioned_dict(),
        raw_shape="sectioned",
        normalized_shape="sectioned",
        shape_version="1.0",
        format_type="toml",
        config_path=str(tmp_path / "dev.toml"),
        deprecation_warnings=(),
    )
    loader.load_config_details.return_value = details
    loader.load_local_config_details.return_value = details
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


def _matches_type(expected: str, value: object) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return True


def _validate_schema(schema: dict, payload: object) -> None:
    schema_type = schema.get("type")
    if isinstance(schema_type, str):
        assert _matches_type(schema_type, payload)
    if "const" in schema:
        assert payload == schema["const"]
    if "enum" in schema:
        assert payload in schema["enum"]
    if isinstance(payload, dict):
        for key in schema.get("required", []):
            assert key in payload
        for key, subschema in schema.get("properties", {}).items():
            if key in payload:
                _validate_schema(subschema, payload[key])
    if isinstance(payload, list) and "items" in schema:
        for item in payload:
            _validate_schema(schema["items"], item)


def test_agent_schema_files_exist_and_are_valid_json() -> None:
    expected = [
        SCHEMAS / "result-envelope.schema.json",
        SCHEMAS / "agent" / "environment-context.schema.json",
        SCHEMAS / "agent" / "addon-info.schema.json",
        SCHEMAS / "agent" / "addon-inspection.schema.json",
        SCHEMAS / "agent" / "update-plan.schema.json",
        SCHEMAS / "agent" / "addon-change-context.schema.json",
        SCHEMAS / "agent" / "addon-change-preflight.schema.json",
        SCHEMAS / "agent" / "recommended-test-plan.schema.json",
        SCHEMAS / "agent" / "query-result.schema.json",
        SCHEMAS / "agent" / "model-source-location.schema.json",
        SCHEMAS / "agent" / "field-source-location.schema.json",
        SCHEMAS / "agent" / "addon-test-inventory.schema.json",
        SCHEMAS / "agent" / "addon-model-inventory.schema.json",
        SCHEMAS / "agent" / "model-extension-inventory.schema.json",
        SCHEMAS / "agent" / "model-view-inventory.schema.json",
        SCHEMAS / "agent" / "addon-root-resolution.schema.json",
        SCHEMAS / "agent" / "addon-file-inventory.schema.json",
        SCHEMAS / "agent" / "addon-install-checks.schema.json",
        SCHEMAS / "agent" / "model-existence.schema.json",
        SCHEMAS / "agent" / "field-existence.schema.json",
        SCHEMAS / "agent" / "addon-change-validation.schema.json",
    ]
    for schema_path in expected:
        assert schema_path.exists(), schema_path
        json.loads(schema_path.read_text())


def test_agent_payloads_validate_against_published_schemas(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale")
    addon_dir = _make_addon(addons_dir, "my_partner")
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
    )
    (addon_dir / "tests").mkdir()
    (addon_dir / "tests" / "test_partner.py").write_text("MODEL = 'res.partner'\n")
    (addon_dir / "i18n").mkdir()
    (addon_dir / "i18n" / "de.po").write_text('msgid ""\nmsgstr ""\n')
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.cli.app.OdooOperations.get_odoo_version",
            return_value={"success": True, "version": "17.0"},
        ),
        patch(
            "oduit.odoo_operations.OdooOperations.query_model",
            side_effect=[
                MagicMock(
                    success=True,
                    records=[
                        {
                            "name": "email3",
                            "ttype": "char",
                            "relation": False,
                            "modules": "my_partner",
                            "state": "base",
                        }
                    ],
                    error=None,
                ),
                MagicMock(success=True, records=[], error=None),
                MagicMock(
                    success=True,
                    records=[{"name": "my_partner", "state": "installed"}],
                    error=None,
                    error_type=None,
                ),
                MagicMock(
                    success=True,
                    records=[{"name": "my_partner", "state": "installed"}],
                    error=None,
                    error_type=None,
                ),
            ],
        ),
        patch(
            "oduit.cli.app.OdooOperations.get_odoo_version",
            return_value={"success": True, "version": "17.0"},
        ),
        patch(
            "oduit.cli.app.OdooOperations.db_exists",
            return_value={"success": True, "exists": True},
        ),
        patch(
            "oduit.cli.app.OdooOperations.get_addon_install_state",
            return_value=AddonInstallState(
                success=True,
                operation="get_addon_install_state",
                module="my_partner",
                record_found=True,
                state="installed",
                installed=True,
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
            },
        ),
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
                    "attributes": ["string", "type", "required"],
                    "field_names": ["email3", "name"],
                    "field_definitions": {
                        "email3": {"type": "char", "required": False},
                        "name": {"type": "char", "required": True},
                    },
                },
            ),
        ),
        patch(
            "oduit.cli.app.OdooOperations.get_model_views",
            return_value=ModelViewInventory(
                model="res.partner",
                requested_types=["form"],
                primary_views=[
                    ModelViewRecord(
                        id=7,
                        name="res.partner.form",
                        view_type="form",
                        mode="primary",
                        priority=16,
                        arch_db="<form/>",
                    )
                ],
                view_counts={"total": 1, "primary": 1, "extension": 0, "form": 1},
            ),
        ),
    ):
        payloads = {
            "environment-context.schema.json": json.loads(
                runner.invoke(app, ["--env", "dev", "agent", "context"]).output
            ),
            "addon-inspection.schema.json": json.loads(
                runner.invoke(
                    app,
                    ["--env", "dev", "agent", "inspect-addon", "my_partner"],
                ).output
            ),
            "addon-info.schema.json": json.loads(
                runner.invoke(
                    app,
                    ["--env", "dev", "agent", "addon-info", "my_partner"],
                ).output
            ),
            "update-plan.schema.json": json.loads(
                runner.invoke(
                    app,
                    ["--env", "dev", "agent", "plan-update", "my_partner"],
                ).output
            ),
            "addon-change-context.schema.json": json.loads(
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
                        "--types",
                        "form",
                    ],
                ).output
            ),
            "addon-change-preflight.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "preflight-addon-change",
                        "my_partner",
                        "--model",
                        "res.partner",
                        "--field",
                        "email3",
                    ],
                ).output
            ),
            "recommended-test-plan.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "recommend-tests",
                        "--module",
                        "my_partner",
                        "--paths",
                        "models/res_partner.py,tests/test_partner.py",
                    ],
                ).output
            ),
            "model-source-location.schema.json": json.loads(
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
            ),
            "field-source-location.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "locate-field",
                        "res.partner",
                        "email3",
                        "--module",
                        "my_partner",
                    ],
                ).output
            ),
            "addon-test-inventory.schema.json": json.loads(
                runner.invoke(
                    app,
                    ["--env", "dev", "agent", "list-addon-tests", "my_partner"],
                ).output
            ),
            "addon-model-inventory.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "list-addon-models",
                        "my_partner",
                    ],
                ).output
            ),
            "model-extension-inventory.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "find-model-extensions",
                        "res.partner",
                    ],
                ).output
            ),
            "model-view-inventory.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "get-model-views",
                        "res.partner",
                        "--types",
                        "form",
                    ],
                ).output
            ),
            "addon-root-resolution.schema.json": json.loads(
                runner.invoke(
                    app,
                    ["--env", "dev", "agent", "resolve-addon-root", "my_partner"],
                ).output
            ),
            "addon-file-inventory.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "get-addon-files",
                        "my_partner",
                        "--globs",
                        "models/*.py,tests/*.py",
                    ],
                ).output
            ),
            "addon-install-checks.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "check-addons-installed",
                        "--modules",
                        "my_partner,x_sale",
                    ],
                ).output
            ),
            "model-existence.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "check-model-exists",
                        "res.partner",
                        "--module",
                        "my_partner",
                    ],
                ).output
            ),
            "field-existence.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "check-field-exists",
                        "res.partner",
                        "email3",
                        "--module",
                        "my_partner",
                    ],
                ).output
            ),
            "addon-change-validation.schema.json": json.loads(
                runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "validate-addon-change",
                        "my_partner",
                        "--allow-mutation",
                    ],
                ).output
            ),
        }

    envelope_schema = json.loads((SCHEMAS / "result-envelope.schema.json").read_text())
    for schema_name, payload in payloads.items():
        assert payload["schema_version"] == "2.0"
        command_schema = json.loads((SCHEMAS / "agent" / schema_name).read_text())
        _validate_schema(envelope_schema, payload)
        _validate_schema(command_schema, payload)


def test_resolve_config_redacts_sensitive_values(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(app, ["--env", "dev", "agent", "resolve-config"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "config_resolution"
    assert payload["effective_config"]["db_password"] == "***redacted***"
    assert (
        payload["normalized_config"]["odoo_params"]["db_password"] == "***redacted***"
    )
    assert payload["config_shape"]["normalized_shape"] == "sectioned"


def test_validate_addon_change_failure_payload_validates_against_schema(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "my_partner")
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.inspect_addon.return_value = MagicMock(
            to_dict=lambda: {"module": "my_partner", "exists": True},
            warnings=[],
            remediation=[],
        )
        ops.list_duplicates.return_value = {}
        ops.get_addon_install_state.return_value = MagicMock(
            success=True,
            module="my_partner",
            record_found=True,
            state="installed",
            installed=True,
        )
        ops.run_tests.return_value = {
            "success": True,
            "operation": "test",
            "return_code": 0,
            "total_tests": 1,
            "passed_tests": 1,
            "failed_tests": 0,
            "error_tests": 0,
            "failures": [],
        }
        ops.list_addon_tests.side_effect = ConfigError("invalid discovery inputs")
        ops.get_odoo_version.return_value = {"success": True, "version": "17.0"}
        ops.db_exists.return_value = {"success": True, "exists": True}
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "validate-addon-change",
                "my_partner",
                "--allow-mutation",
                "--discover-tests",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    envelope_schema = json.loads((SCHEMAS / "result-envelope.schema.json").read_text())
    command_schema = json.loads(
        (SCHEMAS / "agent" / "addon-change-validation.schema.json").read_text()
    )
    _validate_schema(envelope_schema, payload)
    _validate_schema(command_schema, payload)
    assert payload["verification_summary"]["failed_step"] == "discovered_tests"
    assert payload["error_type"] == "ConfigError"
