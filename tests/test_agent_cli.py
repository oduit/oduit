import json
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from oduit import ConfigError
from oduit.api_models import (
    AddonInstallState,
    InstalledAddonInventory,
    InstalledAddonRecord,
    ModelViewInventory,
    ModelViewRecord,
    QueryModelResult,
)
from oduit.cli.app import app
from oduit.config_provider import ConfigProvider
from oduit.odoo_operations import OdooOperations


def _make_executable(path: Path) -> str:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def _make_addon(
    addons_dir: Path,
    module_name: str,
    depends: list[str] | None = None,
    version: str = "17.0.1.0.0",
) -> None:
    module_dir = addons_dir / module_name
    module_dir.mkdir()
    (module_dir / "__manifest__.py").write_text(
        str(
            {
                "name": module_name.replace("_", " ").title(),
                "version": version,
                "depends": depends or ["base"],
            }
        )
    )


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


READ_ONLY_PARITY_SUCCESS_CASES = [
    pytest.param(
        "inspect_ref",
        ["inspect-ref", "base.action_partner_form"],
        {
            "success": True,
            "operation": "inspect_ref",
            "xmlid": "base.action_partner_form",
            "exists": True,
            "model": "ir.actions.act_window",
            "res_id": 7,
            "display_name": "Partners",
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "xmlid_inspection",
        ("xmlid", "base.action_partner_form"),
        id="inspect-ref",
    ),
    pytest.param(
        "inspect_modules",
        ["inspect-modules", "--state", "installed"],
        {
            "success": True,
            "operation": "inspect_modules",
            "modules": [{"name": "sale", "state": "installed"}],
            "names": ["sale"],
            "total": 1,
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "module_inspection",
        ("total", 1),
        id="inspect-modules",
    ),
    pytest.param(
        "inspect_subtypes",
        ["inspect-subtypes", "res.partner"],
        {
            "success": True,
            "operation": "inspect_subtypes",
            "model": "res.partner",
            "subtypes": [{"name": "Partner Created"}],
            "total": 1,
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "subtype_inventory",
        ("model", "res.partner"),
        id="inspect-subtypes",
    ),
    pytest.param(
        "inspect_model",
        ["inspect-model", "res.partner"],
        {
            "success": True,
            "operation": "inspect_model",
            "model": "res.partner",
            "exists": True,
            "table": "res_partner",
            "field_count": 5,
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "model_inspection",
        ("table", "res_partner"),
        id="inspect-model",
    ),
    pytest.param(
        "inspect_field",
        ["inspect-field", "res.partner", "email", "--with-db"],
        {
            "success": True,
            "operation": "inspect_field",
            "model": "res.partner",
            "field": "email",
            "exists": True,
            "field_type": "char",
            "db_table_name": "res_partner",
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "field_inspection",
        ("field_type", "char"),
        id="inspect-field",
    ),
    pytest.param(
        "describe_table",
        ["db-table", "res_partner"],
        {
            "success": True,
            "operation": "describe_table",
            "table_name": "res_partner",
            "columns": [{"column_name": "id", "ordinal_position": 1}],
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "table_description",
        ("table_name", "res_partner"),
        id="db-table",
    ),
    pytest.param(
        "describe_column",
        ["db-column", "res_partner", "email"],
        {
            "success": True,
            "operation": "describe_column",
            "table_name": "res_partner",
            "column": {"column_name": "email", "data_type": "character varying"},
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "column_description",
        ("table_name", "res_partner"),
        id="db-column",
    ),
    pytest.param(
        "list_constraints",
        ["db-constraints", "sale_order"],
        {
            "success": True,
            "operation": "list_constraints",
            "table_name": "sale_order",
            "constraints": [{"name": "sale_order_pkey"}],
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "constraint_inventory",
        ("table_name", "sale_order"),
        id="db-constraints",
    ),
    pytest.param(
        "list_tables",
        ["db-tables", "--like", "res_%"],
        {
            "success": True,
            "operation": "list_tables",
            "pattern": "res_%",
            "tables": ["res_partner"],
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "table_inventory",
        ("pattern", "res_%"),
        id="db-tables",
    ),
    pytest.param(
        "inspect_m2m",
        ["db-m2m", "res.partner", "category_id"],
        {
            "success": True,
            "operation": "inspect_m2m",
            "model": "res.partner",
            "field": "category_id",
            "relation_table": "res_partner_res_category_rel",
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "m2m_inspection",
        ("relation_table", "res_partner_res_category_rel"),
        id="db-m2m",
    ),
    pytest.param(
        "performance_slow_queries",
        ["performance-slow-queries", "--limit", "5"],
        {
            "success": True,
            "operation": "performance_slow_queries",
            "queries": [{"calls": 3, "total_time": 12.5}],
            "limit": 5,
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "slow_query_metrics",
        ("limit", 5),
        id="performance-slow-queries",
    ),
    pytest.param(
        "performance_table_scans",
        ["performance-table-scans", "--limit", "7"],
        {
            "success": True,
            "operation": "performance_table_scans",
            "tables": [{"table_name": "res_partner", "seq_scan": 3}],
            "limit": 7,
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "table_scan_metrics",
        ("limit", 7),
        id="performance-table-scans",
    ),
    pytest.param(
        "performance_indexes",
        ["performance-indexes", "--limit", "9"],
        {
            "success": True,
            "operation": "performance_indexes",
            "tables": [{"table_name": "res_partner", "idx_scan": 9}],
            "limit": 9,
            "read_only": True,
            "safety_level": "safe_read_only",
        },
        "index_usage_metrics",
        ("limit", 9),
        id="performance-indexes",
    ),
]


@pytest.mark.parametrize(
    "method_name,command_args,method_result,result_type,expected_pair",
    READ_ONLY_PARITY_SUCCESS_CASES,
)
def test_agent_read_only_parity_commands_wrap_operation_results(
    tmp_path: Path,
    method_name: str,
    command_args: list[str],
    method_result: dict[str, object],
    result_type: str,
    expected_pair: tuple[str, object],
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    config["needs_mutation_flag"] = True
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(OdooOperations, method_name, return_value=method_result),
    ):
        result = runner.invoke(app, ["--env", "dev", "agent", *command_args])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == result_type
    assert payload["success"] is True
    assert payload["read_only"] is True
    assert payload["safety_level"] == "safe_read_only"
    assert payload[expected_pair[0]] == expected_pair[1]


@pytest.mark.parametrize(
    "method_name,command_args,result_type",
    [
        pytest.param(
            "inspect_ref", ["inspect-ref", "base.missing"], "xmlid_inspection"
        ),
        pytest.param(
            "inspect_modules",
            ["inspect-modules", "--state", "installed"],
            "module_inspection",
        ),
        pytest.param(
            "inspect_subtypes", ["inspect-subtypes", "res.partner"], "subtype_inventory"
        ),
        pytest.param(
            "inspect_model", ["inspect-model", "res.partner"], "model_inspection"
        ),
        pytest.param(
            "inspect_field",
            ["inspect-field", "res.partner", "email"],
            "field_inspection",
        ),
        pytest.param(
            "describe_table", ["db-table", "res_partner"], "table_description"
        ),
        pytest.param(
            "describe_column",
            ["db-column", "res_partner", "email"],
            "column_description",
        ),
        pytest.param(
            "list_constraints", ["db-constraints", "sale_order"], "constraint_inventory"
        ),
        pytest.param("list_tables", ["db-tables"], "table_inventory"),
        pytest.param(
            "inspect_m2m", ["db-m2m", "res.partner", "category_id"], "m2m_inspection"
        ),
        pytest.param(
            "performance_slow_queries",
            ["performance-slow-queries"],
            "slow_query_metrics",
        ),
        pytest.param(
            "performance_table_scans",
            ["performance-table-scans"],
            "table_scan_metrics",
        ),
        pytest.param(
            "performance_indexes",
            ["performance-indexes"],
            "index_usage_metrics",
        ),
    ],
)
def test_agent_read_only_parity_commands_surface_failures(
    tmp_path: Path,
    method_name: str,
    command_args: list[str],
    result_type: str,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    config["needs_mutation_flag"] = True
    loader = _loader_with_config(config, tmp_path)
    method_result = {
        "success": False,
        "operation": method_name,
        "error": "runtime unavailable",
        "error_type": "QueryError",
        "read_only": True,
        "safety_level": "safe_read_only",
    }

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(OdooOperations, method_name, return_value=method_result),
    ):
        result = runner.invoke(app, ["--env", "dev", "agent", *command_args])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["type"] == result_type
    assert payload["success"] is False
    assert payload["error"] == "runtime unavailable"
    assert payload["error_type"] == "QueryError"
    assert payload["read_only"] is True
    assert payload["safety_level"] == "safe_read_only"


def test_agent_inspect_cron_defaults_to_read_only(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(
            OdooOperations,
            "inspect_cron",
            return_value={
                "success": True,
                "operation": "inspect_cron",
                "xmlid": "base.ir_cron_autovacuum",
                "trigger_requested": False,
                "triggered": False,
                "read_only": True,
                "safety_level": "safe_read_only",
            },
        ) as inspect_cron,
    ):
        result = runner.invoke(
            app,
            ["--env", "dev", "agent", "inspect-cron", "base.ir_cron_autovacuum"],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "cron_inspection"
    assert payload["read_only"] is True
    assert payload["safety_level"] == "safe_read_only"
    inspect_cron.assert_called_once_with(
        "base.ir_cron_autovacuum",
        trigger=False,
        database=None,
        timeout=30.0,
    )


def test_agent_inspect_cron_requires_allow_mutation_for_trigger(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    config["needs_mutation_flag"] = True
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(OdooOperations, "inspect_cron") as inspect_cron,
    ):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "inspect-cron",
                "base.ir_cron_autovacuum",
                "--trigger",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["type"] == "cron_inspection"
    assert payload["error_type"] == "ConfirmationRequired"
    assert payload["read_only"] is False
    assert payload["safety_level"] == "controlled_runtime_mutation"
    inspect_cron.assert_not_called()


def test_agent_inspect_cron_reports_runtime_mutation_when_triggered(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(
            OdooOperations,
            "inspect_cron",
            return_value={
                "success": True,
                "operation": "inspect_cron",
                "xmlid": "base.ir_cron_autovacuum",
                "trigger_requested": True,
                "triggered": True,
                "read_only": False,
                "safety_level": "controlled_runtime_mutation",
            },
        ) as inspect_cron,
    ):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "inspect-cron",
                "base.ir_cron_autovacuum",
                "--trigger",
                "--allow-mutation",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "cron_inspection"
    assert payload["triggered"] is True
    assert payload["read_only"] is False
    assert payload["safety_level"] == "controlled_runtime_mutation"
    inspect_cron.assert_called_once_with(
        "base.ir_cron_autovacuum",
        trigger=True,
        database=None,
        timeout=30.0,
    )


def test_agent_manifest_commands_use_shared_manifest_resolution(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)
    manifest = SimpleNamespace(
        name="Sale",
        version="17.0.1.0.0",
        summary="Sales",
        author="The Team",
        website="https://example.com",
        license="LGPL-3",
        installable=True,
        auto_install=False,
        codependencies=["base"],
        python_dependencies=[],
        binary_dependencies=[],
        get_raw_data=lambda: {"name": "Sale"},
    )

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.cli.agent.read_only.build_manifest_result",
            return_value=(
                {
                    "success": True,
                    "operation": "manifest_check",
                    "target": "sale",
                    "module": "sale",
                    "module_path": "/addons/sale",
                    "warning_count": 0,
                    "warnings": [],
                    "read_only": True,
                },
                manifest,
            ),
        ),
    ):
        check_result = runner.invoke(
            app, ["--env", "dev", "agent", "manifest-check", "sale"]
        )
        show_result = runner.invoke(
            app, ["--env", "dev", "agent", "manifest-show", "sale"]
        )

    check_payload = json.loads(check_result.output)
    show_payload = json.loads(show_result.output)
    assert check_result.exit_code == 0
    assert check_payload["type"] == "manifest_validation"
    assert check_payload["warning_count"] == 0
    assert show_result.exit_code == 0
    assert show_payload["type"] == "manifest"
    assert show_payload["manifest_data"]["name"] == "Sale"
    assert show_payload["read_only"] is True
    assert show_payload["safety_level"] == "safe_read_only"


@pytest.mark.parametrize(
    "command_name,result_type",
    [
        ("manifest-check", "manifest_validation"),
        ("manifest-show", "manifest"),
    ],
)
def test_agent_manifest_commands_surface_shared_failures(
    tmp_path: Path,
    command_name: str,
    result_type: str,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.cli.agent.read_only.build_manifest_result",
            return_value=(
                {
                    "success": False,
                    "operation": "manifest_check",
                    "target": "missing",
                    "error": "manifest missing",
                    "error_type": "ManifestNotFoundError",
                    "read_only": True,
                },
                None,
            ),
        ),
    ):
        result = runner.invoke(app, ["--env", "dev", "agent", command_name, "missing"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["type"] == result_type
    assert payload["success"] is False
    assert payload["error_type"] == "ManifestNotFoundError"
    assert payload["read_only"] is True
    assert payload["safety_level"] == "safe_read_only"


def test_agent_context_returns_structured_snapshot(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_a = tmp_path / "addons_a"
    addons_b = tmp_path / "addons_b"
    addons_a.mkdir()
    addons_b.mkdir()
    _make_addon(addons_a, "base", depends=[])
    _make_addon(addons_a, "x_sale", depends=["base"])
    _make_addon(addons_a, "x_sale_ext", depends=["x_sale"])
    _make_addon(addons_a, "dup_mod", depends=["base"])
    _make_addon(addons_b, "dup_mod", depends=["base"])

    config = _agent_config(tmp_path, f"{addons_a},{addons_b}")
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(
            OdooOperations,
            "get_odoo_version",
            return_value={"success": True, "version": "17.0"},
        ),
    ):
        result = runner.invoke(app, ["--env", "dev", "agent", "context"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "environment_context"
    assert payload["operation"] == "agent_context"
    assert payload["read_only"] is True
    assert payload["safety_level"] == "safe_read_only"
    assert payload["environment"]["name"] == "dev"
    assert payload["available_module_count"] == 4
    assert payload["duplicate_modules"]["dup_mod"]
    assert payload["doctor_summary"]["ok"] >= 1


def test_agent_resolve_config_returns_canonical_shape_metadata(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(
            OdooOperations,
            "get_odoo_version",
            return_value={"success": True, "version": "17.0"},
        ),
    ):
        result = runner.invoke(app, ["--env", "dev", "agent", "resolve-config"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "config_resolution"
    assert payload["environment"]["format"] == "toml"
    assert payload["config_shape"] == {
        "raw_shape": "sectioned",
        "normalized_shape": "sectioned",
        "shape_version": "1.0",
        "source_format": "toml",
    }
    assert payload["deprecation_warnings"] == []
    assert (
        payload["normalized_config"]["binaries"]["python_bin"] == config["python_bin"]
    )
    assert (
        payload["normalized_config"]["odoo_params"]["db_password"] == "***redacted***"
    )


def test_agent_resolve_config_warns_for_legacy_flat_shape(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)
    deprecation_warning = (
        "Legacy flat config keys are deprecated; prefer sectioned TOML "
        "with [binaries] and [odoo_params]."
    )
    loader.resolve_config_path.return_value = (str(tmp_path / "dev.yaml"), "yaml")
    loader.load_config_details.return_value = SimpleNamespace(
        config=config,
        canonical_config=ConfigProvider(config).to_sectioned_dict(),
        raw_shape="legacy_flat",
        normalized_shape="sectioned",
        shape_version="1.0",
        format_type="yaml",
        config_path=str(tmp_path / "dev.yaml"),
        deprecation_warnings=(deprecation_warning,),
    )

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(
            OdooOperations,
            "get_odoo_version",
            return_value={"success": True, "version": "17.0"},
        ),
    ):
        result = runner.invoke(app, ["--env", "dev", "agent", "resolve-config"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["environment"]["format"] == "yaml"
    assert payload["config_shape"]["raw_shape"] == "legacy_flat"
    assert payload["deprecation_warnings"] == [deprecation_warning]
    assert deprecation_warning in payload["warnings"]


def test_agent_inspect_addon_returns_dependency_snapshot(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    _make_addon(addons_dir, "x_sale_ext", depends=["x_sale"])

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app, ["--env", "dev", "agent", "inspect-addon", "x_sale"]
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_inspection"
    assert payload["operation"] == "inspect_addon"
    assert payload["module"] == "x_sale"
    assert payload["addon_type"] == "custom"
    assert payload["direct_dependencies"] == ["base"]
    assert payload["reverse_dependencies"] == ["x_sale_ext"]
    assert payload["install_order_slice"] == ["base", "x_sale"]


def test_agent_addon_info_returns_combined_summary(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "my_partner", depends=["base"])
    addon_dir = addons_dir / "my_partner"
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class PartnerScore(models.Model):\n"
        "    _name = 'x.partner.score'\n"
        "    _inherit = 'mail.thread'\n"
        "    partner_id = fields.Many2one('res.partner')\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    score = fields.Integer()\n"
    )
    (addon_dir / "tests").mkdir()
    (addon_dir / "tests" / "test_partner.py").write_text("assert True\n")
    (addon_dir / "i18n").mkdir()
    (addon_dir / "i18n" / "de.po").write_text('msgid ""\nmsgstr ""\n')

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.odoo_operations.OdooOperations.query_model",
            return_value=QueryModelResult(
                success=True,
                operation="query_model",
                model="ir.module.module",
                records=[{"name": "my_partner", "state": "installed"}],
                database="test_db",
            ),
        ),
    ):
        result = runner.invoke(
            app, ["--env", "dev", "agent", "addon-info", "my_partner"]
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_info"
    assert payload["operation"] == "addon_info"
    assert payload["module"] == "my_partner"
    assert payload["models"] == ["x.partner.score"]
    assert payload["inherit_models"] == ["mail.thread", "res.partner"]
    assert payload["languages"] == ["de"]
    assert payload["installed_state"]["installed"] is True
    assert payload["test_cases"][0]["path"].endswith("tests/test_partner.py")


def test_agent_plan_update_returns_risk_summary(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    _make_addon(addons_dir, "x_sale_ext", depends=["x_sale"])

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(app, ["--env", "dev", "agent", "plan-update", "x_sale"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "update_plan"
    assert payload["operation"] == "plan_update"
    assert payload["impact_set"] == ["x_sale_ext"]
    assert payload["backup_advised"] is True
    assert payload["write_protect_db"] is False
    assert payload["agent_write_protect_db"] is False
    assert payload["needs_mutation_flag"] is False
    assert payload["agent_needs_mutation_flag"] is False
    assert payload["human_runtime_db_mutation_policy"] == "allow"
    assert payload["human_runtime_db_mutation_allowed"] is True
    assert payload["human_runtime_db_mutation_requires_flag"] is False
    assert payload["agent_runtime_db_mutation_policy"] == "allow"
    assert payload["agent_runtime_db_mutation_allowed"] is True
    assert payload["agent_runtime_db_mutation_requires_flag"] is False
    assert payload["risk_score"] > 0
    assert payload["risk_level"] in {"low", "medium", "high"}
    assert payload["recommended_sequence"]


def test_agent_plan_update_exposes_explicit_policy_flags(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    _make_addon(addons_dir, "x_sale_ext", depends=["x_sale"])

    config = _agent_config(tmp_path, str(addons_dir))
    config["write_protect_db"] = True
    config["agent_write_protect_db"] = True
    config["needs_mutation_flag"] = True
    config["agent_needs_mutation_flag"] = True
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(app, ["--env", "dev", "agent", "plan-update", "x_sale"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["backup_advised"] is True
    assert payload["write_protect_db"] is True
    assert payload["agent_write_protect_db"] is True
    assert payload["needs_mutation_flag"] is True
    assert payload["agent_needs_mutation_flag"] is True
    assert payload["human_runtime_db_mutation_policy"] == "forbidden"
    assert payload["human_runtime_db_mutation_allowed"] is False
    assert payload["human_runtime_db_mutation_requires_flag"] is False
    assert payload["agent_runtime_db_mutation_policy"] == "forbidden"
    assert payload["agent_runtime_db_mutation_allowed"] is False
    assert payload["agent_runtime_db_mutation_requires_flag"] is False


def test_prepare_addon_change_bundles_read_only_planning_steps(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "my_partner"
    _make_addon(addons_dir, "my_partner", depends=["base"])
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
                    "attributes": ["string", "type", "required"],
                    "field_names": ["name", "email"],
                    "field_definitions": {"name": {"type": "char"}},
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
                    )
                ],
                view_counts={"total": 1, "primary": 1, "extension": 0, "form": 1},
            ),
        ),
    ):
        result = runner.invoke(
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
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_change_context"
    assert payload["operation"] == "prepare_addon_change"
    assert payload["module"] == "my_partner"
    assert payload["model"] == "res.partner"
    assert payload["field"] == "email3"
    assert payload["steps"]["context"]["success"] is True
    assert payload["steps"]["inspect_addon"]["success"] is True
    assert payload["steps"]["plan_update"]["success"] is True
    assert payload["steps"]["locate_model"]["success"] is True
    assert payload["steps"]["list_addon_tests"]["data"]["tests"][0]["path"].endswith(
        "tests/test_partner.py"
    )
    assert payload["steps"]["get_model_fields"]["data"]["field_names"] == [
        "name",
        "email",
    ]
    assert payload["recommended_next_steps"]


def test_agent_query_model_wraps_odoo_query(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.query_model.return_value = MagicMock(
            success=True,
            error=None,
            error_type=None,
            to_dict=lambda: {
                "success": True,
                "operation": "query_model",
                "model": "res.partner",
                "count": 1,
                "records": [{"id": 7, "name": "Azure Interior"}],
            },
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "query-model",
                "res.partner",
                "--domain-json",
                '[["customer_rank", ">", 0]]',
                "--fields",
                "name,email",
                "--limit",
                "5",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "query_result"
    assert payload["operation"] == "query_model"
    assert payload["read_only"] is True
    assert payload["count"] == 1
    ops.query_model.assert_called_once_with(
        "res.partner",
        domain=[["customer_rank", ">", 0]],
        fields=["name", "email"],
        limit=5,
        database=None,
        timeout=30.0,
    )


def test_agent_list_installed_addons_returns_structured_payload(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.list_installed_addons.return_value = InstalledAddonInventory(
            success=True,
            operation="list_installed_addons",
            addons=[
                InstalledAddonRecord(
                    module="x_sale",
                    state="installed",
                    installed=True,
                    shortdesc="Sales",
                )
            ],
            total=1,
            states=["installed"],
            modules_filter=["x_sale"],
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "list-installed-addons",
                "--modules",
                "x_sale",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "installed_addon_inventory"
    assert payload["operation"] == "list_installed_addons"
    assert payload["addons"][0]["module"] == "x_sale"
    assert payload["states"] == ["installed"]
    assert payload["modules_filter"] == ["x_sale"]
    ops.list_installed_addons.assert_called_once_with(
        modules=["x_sale"],
        states=None,
    )


def test_agent_list_installed_addons_surfaces_query_failure(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.list_installed_addons.return_value = InstalledAddonInventory(
            success=False,
            operation="list_installed_addons",
            states=["installed"],
            error="database unavailable",
            error_type="QueryError",
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(app, ["--env", "dev", "agent", "list-installed-addons"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["type"] == "installed_addon_inventory"
    assert payload["success"] is False
    assert payload["error"] == "database unavailable"
    assert payload["error_type"] == "QueryError"


def test_agent_query_model_invalid_domain_json_is_structured(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "query-model",
                "res.partner",
                "--domain-json",
                "not-json",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["type"] == "query_result"
    assert payload["success"] is False
    assert payload["error_type"] == "CommandError"
    assert payload["error_code"] == "input.invalid_json"
    assert "must be valid JSON" in payload["error"]


def test_agent_get_model_views_returns_primary_and_extension_views(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.get_model_views.return_value = ModelViewInventory(
            model="dvo.dvo",
            requested_types=["form", "tree"],
            primary_views=[
                ModelViewRecord(
                    id=1501,
                    name="DVO Form",
                    view_type="form",
                    mode="primary",
                    priority=16,
                    arch_db="<form/>",
                )
            ],
            extension_views=[
                ModelViewRecord(
                    id=1508,
                    name="dvo.dvo.view.dvo",
                    view_type="form",
                    mode="extension",
                    priority=101,
                    inherit_id=[1501, "DVO Form"],
                    arch_db="<xpath/>",
                )
            ],
            view_counts={"total": 2, "primary": 1, "extension": 1, "form": 2},
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "get-model-views",
                "dvo.dvo",
                "--types",
                "form,tree",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "model_view_inventory"
    assert payload["operation"] == "get_model_views"
    assert payload["requested_types"] == ["form", "tree"]
    assert payload["primary_views"][0]["name"] == "DVO Form"
    assert payload["extension_views"][0]["inherit_id"] == [1501, "DVO Form"]
    ops.get_model_views.assert_called_once_with(
        "dvo.dvo",
        view_types=["form", "tree"],
        database=None,
        timeout=30.0,
        include_arch=True,
    )


def test_agent_get_model_views_summary_omits_arch_db(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.get_model_views.return_value = ModelViewInventory(
            model="dvo.dvo",
            primary_views=[
                ModelViewRecord(
                    id=1501,
                    name="DVO Form",
                    view_type="form",
                    mode="primary",
                    priority=16,
                    arch_db="<form/>",
                )
            ],
            view_counts={"total": 1, "primary": 1, "extension": 0, "form": 1},
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "get-model-views",
                "dvo.dvo",
                "--summary",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"] is True
    assert "arch_db" not in payload["primary_views"][0]
    ops.get_model_views.assert_called_once_with(
        "dvo.dvo",
        view_types=None,
        database=None,
        timeout=30.0,
        include_arch=False,
    )


def test_agent_get_model_views_query_failure_is_structured(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.get_model_views.return_value = ModelViewInventory(
            model="dvo.dvo",
            error="database unavailable",
            error_type="QueryError",
            warnings=["Failed to query model views: database unavailable"],
            remediation=[
                "Verify database access and model name, then retry the view query."
            ],
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            ["--env", "dev", "agent", "get-model-views", "dvo.dvo"],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["type"] == "model_view_inventory"
    assert payload["success"] is False
    assert payload["error"] == "database unavailable"
    assert payload["error_type"] == "QueryError"


@pytest.mark.parametrize(
    ("command", "args", "ops_method", "result_type", "expected_operation"),
    [
        (
            "read-record",
            ["res.partner", "7", "--fields", "name,email"],
            "read_record",
            "record_result",
            "read_record",
        ),
        (
            "search-count",
            ["res.partner", "--domain-json", '[["is_company", "=", true]]'],
            "search_count",
            "count_result",
            "search_count",
        ),
        (
            "get-model-fields",
            ["res.partner", "--attributes", "string,type"],
            "get_model_fields",
            "model_fields",
            "get_model_fields",
        ),
    ],
)
def test_agent_query_subcommands_use_odoo_query(
    tmp_path: Path,
    command: str,
    args: list[str],
    ops_method: str,
    result_type: str,
    expected_operation: str,
) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        getattr(ops, ops_method).return_value = MagicMock(
            success=True,
            error=None,
            error_type=None,
            to_dict=lambda: {
                "success": True,
                "operation": expected_operation,
                "model": "res.partner",
            },
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(app, ["--env", "dev", "agent", command, *args])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == result_type
    assert payload["operation"] == expected_operation
    assert payload["read_only"] is True
    assert getattr(ops, ops_method).called


def test_agent_test_summary_normalizes_failures(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.run_tests.return_value = {
            "success": False,
            "operation": "test",
            "return_code": 1,
            "total_tests": 3,
            "passed_tests": 1,
            "failed_tests": 1,
            "error_tests": 1,
            "failures": [
                {
                    "test_name": "TestSale.test_flow",
                    "file": "/tmp/test_sale.py",
                    "line": 42,
                    "function_name": "test_flow",
                    "source_line": "self.assertEqual(total, expected_total)",
                    "broken_line_count": 2,
                    "failure_excerpt": (
                        "/tmp/test_sale.py:42: self.assertEqual(total, expected_total)"
                    ),
                    "error_message": "AssertionError: expected value",
                }
            ],
            "stdout": (
                "Traceback (most recent call last):\n"
                '  File "/tmp/test_sale.py", line 42, in test_flow\n'
                "AssertionError: expected value\n"
            ),
            "error": "Tests failed",
            "error_type": "TestFailure",
        }
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "test-summary",
                "--allow-mutation",
                "--module",
                "x_sale",
                "--test-tags",
                "/x_sale",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["type"] == "test_summary"
    assert payload["operation"] == "test_summary"
    assert payload["read_only"] is True
    assert payload["safety_level"] == "safe_read_only"
    assert payload["error_code"] == "runtime.test_failure"
    assert payload["generated_at"] == payload["timestamp"]
    assert payload["selected_modules"] == ["x_sale"]
    assert payload["failed_tests"] == 1
    assert payload["error_tests"] == 1
    assert payload["failure_details"]
    assert payload["traceback_summary"]
    assert payload["traceback_summary"][0]["source_line"] is not None
    assert payload["traceback_summary"][0]["broken_line_count"] >= 1
    assert payload["traceback_summary"][0]["failure_excerpt"]
    assert payload["error_output_excerpt"]
    assert "AssertionError: expected value" in payload["error_output_excerpt"]
    assert payload["suggested_next_steps"]


def test_agent_test_summary_includes_error_output_excerpt_without_failures(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.run_tests.return_value = {
            "success": False,
            "operation": "test",
            "return_code": 1,
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "error_tests": 1,
            "failures": [],
            "stdout": (
                "odoo.modules.loading: loading 1 modules...\n"
                "Traceback (most recent call last):\n"
                '  File "/tmp/odoo/addons/module.py", line 1, in <module>\n'
                "ValueError: missing dependency\n"
            ),
            "error": "Tests failed",
            "error_type": "TestFailure",
        }
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "test-summary",
                "--allow-mutation",
                "--install",
                "x_sale",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload.get("failure_details", []) == []
    assert payload["error_output_excerpt"]
    assert payload["error_output_excerpt"][-1] == "ValueError: missing dependency"


def test_agent_test_summary_preserves_parser_warnings_and_raw_failure_excerpt(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.run_tests.return_value = {
            "success": False,
            "operation": "test",
            "return_code": 1,
            "total_tests": 1,
            "passed_tests": 0,
            "failed_tests": 1,
            "error_tests": 0,
            "warnings": [
                "Partially parsed failure 'BasicTestCase.test_missing_location'; "
                "preserved raw_failure_excerpt."
            ],
            "failures": [
                {
                    "test_name": "BasicTestCase.test_missing_location",
                    "file": None,
                    "line": None,
                    "function_name": None,
                    "source_line": None,
                    "broken_line_count": 0,
                    "failure_excerpt": None,
                    "raw_failure_excerpt": [
                        "FAIL: BasicTestCase.test_missing_location",
                        "Traceback (most recent call last):",
                        "AssertionError: expected truthy value",
                    ],
                    "error_message": "AssertionError: expected truthy value",
                }
            ],
            "stdout": "AssertionError: expected truthy value\n",
            "error": "Tests failed",
            "error_type": "TestFailure",
        }
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "test-summary",
                "--allow-mutation",
                "--module",
                "x_sale",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["warnings"] == [
        "Partially parsed failure 'BasicTestCase.test_missing_location'; "
        "preserved raw_failure_excerpt."
    ]
    assert payload["failure_details"][0]["raw_failure_excerpt"] == [
        "FAIL: BasicTestCase.test_missing_location",
        "Traceback (most recent call last):",
        "AssertionError: expected truthy value",
    ]
    assert payload["traceback_summary"][0]["raw_failure_excerpt"] == [
        "FAIL: BasicTestCase.test_missing_location",
        "Traceback (most recent call last):",
        "AssertionError: expected truthy value",
    ]


def test_agent_create_addon_reports_source_mutation(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.create_addon.return_value = {
            "success": True,
            "operation": "create_addon",
            "return_code": 0,
        }
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "create-addon",
                "x_custom",
                "--allow-mutation",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_creation"
    assert payload["read_only"] is False
    assert payload["safety_level"] == "controlled_source_mutation"


def test_agent_uninstall_module_dry_run_returns_planning_payload(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    config["allow_uninstall"] = True
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="crm",
            record_found=True,
            state="installed",
            installed=True,
            database="test_db",
        )
        ops.list_installed_dependents.return_value = InstalledAddonInventory(
            success=True,
            operation="list_installed_dependents",
            addons=[
                InstalledAddonRecord(
                    module="sale_crm",
                    state="installed",
                    installed=True,
                )
            ],
            total=1,
            states=["installed"],
            modules_filter=["sale_crm"],
            database="test_db",
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            ["--env", "dev", "agent", "uninstall-module", "crm", "--dry-run"],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "module_uninstallation"
    assert payload["read_only"] is True
    assert payload["planned_action"] == "uninstall"
    assert payload["config_allows_uninstall"] is True
    assert payload["allow_uninstall_flag"] is False
    assert payload["dependent_modules"] == ["sale_crm"]
    assert payload["blocked"] is True


def test_agent_uninstall_module_requires_allow_uninstall(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    config["allow_uninstall"] = True
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        mock_ops_class.return_value = MagicMock()

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "uninstall-module",
                "crm",
                "--allow-mutation",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error_type"] == "ConfirmationRequired"
    assert payload["read_only"] is False
    assert payload["safety_level"] == "controlled_runtime_mutation"


def test_agent_uninstall_module_reports_runtime_mutation(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    config["allow_uninstall"] = True
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.uninstall_module.return_value = {
            "success": True,
            "operation": "uninstall_module",
            "module": "crm",
            "previous_state": "installed",
            "final_state": "uninstalled",
            "uninstalled": True,
        }
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "uninstall-module",
                "crm",
                "--allow-mutation",
                "--allow-uninstall",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "module_uninstallation"
    assert payload["read_only"] is False
    assert payload["safety_level"] == "controlled_runtime_mutation"
    ops.uninstall_module.assert_called_once_with(
        "crm",
        suppress_output=True,
        compact=False,
        log_level=None,
        allow_uninstall=True,
    )


def test_agent_validate_addon_change_aggregates_runtime_verification(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.inspect_addon.return_value = MagicMock(
            to_dict=lambda: {"module": "x_sale", "exists": True},
            warnings=[],
            remediation=[],
        )
        ops.list_duplicates.return_value = {}
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="x_sale",
            record_found=True,
            state="installed",
            installed=True,
        )
        ops.update_module.return_value = {
            "success": True,
            "operation": "update_module",
            "return_code": 0,
        }
        ops.run_tests.return_value = {
            "success": True,
            "operation": "test",
            "return_code": 0,
            "total_tests": 5,
            "passed_tests": 5,
            "failed_tests": 0,
            "error_tests": 0,
            "failures": [],
        }
        ops.list_addon_tests.return_value = MagicMock(
            to_dict=lambda: {"module": "x_sale", "tests": []},
            warnings=[],
            remediation=[],
        )
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
                "x_sale",
                "--allow-mutation",
                "--update",
                "--discover-tests",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_change_validation"
    assert payload["safety_level"] == "controlled_runtime_mutation"
    assert payload["requested_actions"]["test_tags"] == "/x_sale"
    assert payload["mutation_action"]["action"] == "update"
    assert payload["sub_results"]["module_tests"]["success"] is True
    assert payload["sub_results"]["discovered_tests"]["data"]["executed"] is False
    for step in payload["sub_results"].values():
        assert isinstance(step["duration_ms"], int)
        assert step["duration_ms"] >= 0
    ops.get_addon_install_state.assert_called_once_with("x_sale")
    ops.update_module.assert_called_once()
    ops.run_tests.assert_called_once_with(
        module="x_sale",
        stop_on_error=False,
        install=None,
        update=None,
        coverage=None,
        test_file=None,
        test_tags="/x_sale",
        compact=False,
        suppress_output=True,
        log_level=None,
    )


def test_agent_preflight_addon_change_returns_read_only_snapshot(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "x_sale"
    _make_addon(addons_dir, "x_sale", depends=["base"])
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
    )
    (addon_dir / "tests").mkdir()
    (addon_dir / "tests" / "test_partner.py").write_text("MODEL = 'res.partner'\n")
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(
            OdooOperations,
            "get_odoo_version",
            return_value={"success": True, "version": "17.0"},
        ),
        patch.object(
            OdooOperations,
            "db_exists",
            return_value={"success": True, "exists": True},
        ),
        patch.object(
            OdooOperations,
            "get_addon_install_state",
            return_value=AddonInstallState(
                success=True,
                operation="get_addon_install_state",
                module="x_sale",
                record_found=True,
                state="installed",
                installed=True,
            ),
        ),
    ):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "preflight-addon-change",
                "x_sale",
                "--model",
                "res.partner",
                "--field",
                "email3",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_change_preflight"
    assert payload["read_only"] is True
    assert payload["safety_level"] == "safe_read_only"
    assert payload["ready_for_mutation"] is True
    assert payload["preflight_summary"].get("failed_step") is None
    assert payload["sub_results"]["field_source"]["success"] is True
    assert payload["sub_results"]["addon_tests"]["success"] is True
    assert payload["sub_results"]["field_source"]["data"]["field"] == "email3"
    assert payload["sub_results"]["addon_tests"]["data"]["module"] == "x_sale"
    for step in payload["sub_results"].values():
        assert isinstance(step["duration_ms"], int)
        assert step["duration_ms"] >= 0


def test_agent_preflight_addon_change_rejects_field_without_model(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "preflight-addon-change",
                "x_sale",
                "--field",
                "email3",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["success"] is False
    assert payload["error_type"] == "ValidationError"
    assert "`--field` requires `--model`." == payload["error"]


def test_agent_resolve_addon_root_returns_unique_root(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app, ["--env", "dev", "agent", "resolve-addon-root", "x_sale"]
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_root_resolution"
    assert payload["unique"] is True
    assert payload["addon_root"].endswith("addons/x_sale")


def test_agent_get_addon_files_returns_filtered_inventory(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "x_sale"
    _make_addon(addons_dir, "x_sale", depends=["base"])
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "res_partner.py").write_text("MODEL = 'res.partner'\n")
    (addon_dir / "tests").mkdir()
    (addon_dir / "tests" / "test_partner.py").write_text("assert True\n")
    (addon_dir / "views").mkdir()
    (addon_dir / "views" / "res_partner_views.xml").write_text("<odoo/>")
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "get-addon-files",
                "x_sale",
                "--globs",
                "models/*.py,tests/*.py",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_file_inventory"
    assert payload["files"] == ["models/res_partner.py", "tests/test_partner.py"]


def test_agent_check_addons_installed_returns_runtime_states(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.get_addon_install_state.side_effect = [
            AddonInstallState(
                success=True,
                operation="get_addon_install_state",
                module="x_sale",
                record_found=True,
                state="installed",
                installed=True,
            ),
            AddonInstallState(
                success=True,
                operation="get_addon_install_state",
                module="crm",
                record_found=False,
                state="uninstalled",
                installed=False,
            ),
        ]
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "check-addons-installed",
                "--modules",
                "x_sale,crm",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_install_checks"
    assert payload["installed_modules"] == ["x_sale"]
    assert payload["not_installed_modules"] == ["crm"]


def test_agent_check_addons_installed_preserves_empty_lists(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="x_sale",
            record_found=True,
            state="installed",
            installed=True,
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "check-addons-installed",
                "--modules",
                "x_sale",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["installed_modules"] == ["x_sale"]
    assert payload["not_installed_modules"] == []
    assert payload["unknown_modules"] == []


def test_agent_check_model_exists_reports_source_and_runtime(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "my_partner"
    _make_addon(addons_dir, "my_partner", depends=["base"])
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
    )
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.cli.app.OdooOperations.get_model_fields",
            return_value=MagicMock(
                success=True,
                field_names=["email3"],
                field_definitions={"email3": {"modules": "my_partner"}},
            ),
        ),
    ):
        result = runner.invoke(
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
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "model_existence"
    assert payload["exists"] is True
    assert payload["source_exists"] is True
    assert payload["runtime_exists"] is True
    assert payload["source_addon_candidates"] == ["my_partner"]


def test_agent_get_addon_files_preserves_empty_globs(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app, ["--env", "dev", "agent", "get-addon-files", "x_sale"]
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["globs"] == []
    assert "__manifest__.py" in payload["files"]


def test_agent_check_field_exists_reports_runtime_and_source(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "my_partner"
    _make_addon(addons_dir, "my_partner", depends=["base"])
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
    )
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.cli.app.OdooOperations.get_model_fields",
            return_value=MagicMock(
                success=True,
                field_names=["email3"],
                field_definitions={"email3": {"modules": "my_partner"}},
            ),
        ),
    ):
        result = runner.invoke(
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
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "field_existence"
    assert payload["exists"] is True
    assert payload["runtime_exists"] is True
    assert payload["source_exists"] is True
    assert payload["runtime_source_modules"] == ["my_partner"]


def test_agent_validate_addon_change_installs_when_needed(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.inspect_addon.return_value = MagicMock(
            to_dict=lambda: {"module": "x_sale", "exists": True},
            warnings=[],
            remediation=[],
        )
        ops.list_duplicates.return_value = {}
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="x_sale",
            record_found=True,
            state="uninstalled",
            installed=False,
        )
        ops.install_module.return_value = {
            "success": True,
            "operation": "install_module",
            "return_code": 0,
        }
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
                "x_sale",
                "--allow-mutation",
                "--install-if-needed",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["installed_state"]["installed"] is False
    assert payload["mutation_action"]["action"] == "install"
    ops.get_addon_install_state.assert_called_once_with("x_sale")
    ops.install_module.assert_called_once()
    ops.update_module.assert_not_called()


def test_agent_validate_addon_change_fails_when_doctor_fails(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    config = _agent_config(tmp_path, str(addons_dir))
    config["odoo_bin"] = str(tmp_path / "missing-odoo-bin")
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(
            OdooOperations,
            "get_odoo_version",
            return_value={"success": True, "version": "17.0"},
        ),
        patch.object(
            OdooOperations,
            "db_exists",
            return_value={"success": True, "exists": True},
        ),
    ):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "validate-addon-change",
                "x_sale",
                "--allow-mutation",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["success"] is False
    assert payload["verification_summary"]["failed_step"] == "doctor"
    assert "Doctor found" in payload["error"]
    assert "odoo_bin" in payload["error"]
    assert payload["error_type"] == "DoctorCheckError"
    assert payload["sub_results"]["doctor"]["success"] is False
    assert payload["remediation"]


def test_agent_validate_addon_change_fails_when_target_module_is_duplicated(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_a = tmp_path / "addons_a"
    addons_b = tmp_path / "addons_b"
    addons_a.mkdir()
    addons_b.mkdir()
    _make_addon(addons_a, "base", depends=[])
    _make_addon(addons_a, "x_sale", depends=["base"])
    _make_addon(addons_b, "x_sale", depends=["base"])
    config = _agent_config(tmp_path, f"{addons_a},{addons_b}")
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch.object(
            OdooOperations,
            "get_odoo_version",
            return_value={"success": True, "version": "17.0"},
        ),
        patch.object(
            OdooOperations,
            "db_exists",
            return_value={"success": True, "exists": True},
        ),
    ):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "validate-addon-change",
                "x_sale",
                "--allow-mutation",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["success"] is False
    assert payload["verification_summary"]["failed_step"] == "duplicates"
    assert payload["error_type"] == "DuplicateModuleError"
    assert payload["error_code"] == "module.duplicate_name"
    assert (
        payload["sub_results"]["duplicates"]["data"]["target_module_duplicated"] is True
    )
    assert payload["remediation"]


def test_agent_validate_addon_change_surfaces_installed_state_query_failure(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.inspect_addon.return_value = MagicMock(
            to_dict=lambda: {"module": "x_sale", "exists": True},
            warnings=[],
            remediation=[],
        )
        ops.list_duplicates.return_value = {}
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=False,
            operation="get_addon_install_state",
            module="x_sale",
            record_found=False,
            state="unknown",
            installed=False,
            error="database unavailable",
            error_type="QueryError",
        )
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
                "x_sale",
                "--allow-mutation",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["success"] is False
    assert payload["verification_summary"]["failed_step"] == "installed_state"
    assert payload["error"] == "database unavailable"
    assert payload["error_type"] == "QueryError"
    assert payload["error_code"] == "runtime.query_failed"
    assert payload["sub_results"]["installed_state"]["success"] is False
    assert (
        "Verify database access and retry the module-state lookup."
        in payload["remediation"]
    )


def test_agent_validate_addon_change_surfaces_module_action_failure(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.inspect_addon.return_value = MagicMock(
            to_dict=lambda: {"module": "x_sale", "exists": True},
            warnings=[],
            remediation=[],
        )
        ops.list_duplicates.return_value = {}
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="x_sale",
            record_found=True,
            state="uninstalled",
            installed=False,
        )
        ops.install_module.return_value = {
            "success": False,
            "operation": "install_module",
            "return_code": 1,
            "error": "module install failed",
            "error_type": "ModuleOperationError",
        }
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
                "x_sale",
                "--allow-mutation",
                "--install-if-needed",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["success"] is False
    assert payload["verification_summary"]["failed_step"] == "module_action"
    assert payload["error"] == "module install failed"
    assert payload["error_type"] == "ModuleOperationError"
    assert payload["error_code"] == "runtime.module_operation_failed"
    assert payload["sub_results"]["module_action"]["success"] is False
    assert payload["sub_results"]["module_action"]["read_only"] is False
    assert payload["sub_results"]["module_action"]["safety_level"] == (
        "controlled_runtime_mutation"
    )
    assert (
        "Inspect the module-action error before retrying verification."
        in payload["remediation"]
    )
    ops.run_tests.assert_not_called()


def test_agent_validate_addon_change_surfaces_test_failure(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.inspect_addon.return_value = MagicMock(
            to_dict=lambda: {"module": "x_sale", "exists": True},
            warnings=[],
            remediation=[],
        )
        ops.list_duplicates.return_value = {}
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="x_sale",
            record_found=True,
            state="installed",
            installed=True,
        )
        ops.run_tests.return_value = {
            "success": False,
            "operation": "test",
            "return_code": 1,
            "error": "failed test run",
            "error_type": "TestFailure",
            "total_tests": 1,
            "passed_tests": 0,
            "failed_tests": 1,
            "error_tests": 0,
            "failures": [],
        }
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
                "x_sale",
                "--allow-mutation",
                "--discover-tests",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["success"] is False
    assert payload["verification_summary"]["failed_step"] == "module_tests"
    assert payload["error"] == "failed test run"
    assert payload["error_type"] == "TestFailure"
    assert payload["error_code"] == "runtime.test_failure"
    assert payload["sub_results"]["module_tests"]["success"] is False
    assert payload["sub_results"]["discovered_tests"]["skipped"] is True
    assert payload["sub_results"]["discovered_tests"]["data"]["reason"] == (
        "skipped_after_failed_required_step"
    )


def test_agent_validate_addon_change_surfaces_discovered_tests_failure(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.inspect_addon.return_value = MagicMock(
            to_dict=lambda: {"module": "x_sale", "exists": True},
            warnings=[],
            remediation=[],
        )
        ops.list_duplicates.return_value = {}
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="x_sale",
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
                "x_sale",
                "--allow-mutation",
                "--discover-tests",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["success"] is False
    assert payload["verification_summary"]["failed_step"] == "discovered_tests"
    assert payload["error"] == "invalid discovery inputs"
    assert payload["error_type"] == "ConfigError"
    assert payload["sub_results"]["discovered_tests"]["success"] is False
    assert (
        "Verify the addon path and test discovery inputs before retrying."
        in (payload["remediation"])
    )


def test_agent_validate_addon_change_skips_module_action_when_already_installed(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.inspect_addon.return_value = MagicMock(
            to_dict=lambda: {"module": "x_sale", "exists": True},
            warnings=[],
            remediation=[],
        )
        ops.list_duplicates.return_value = {}
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="x_sale",
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
                "x_sale",
                "--allow-mutation",
                "--install-if-needed",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["mutation_action"] == {
        "action": "none",
        "performed": False,
        "reason": "module_already_installed",
    }
    assert payload["sub_results"]["module_action"]["skipped"] is True
    ops.install_module.assert_not_called()
    ops.update_module.assert_not_called()


def test_agent_validate_addon_change_prefers_install_when_update_is_requested(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.inspect_addon.return_value = MagicMock(
            to_dict=lambda: {"module": "x_sale", "exists": True},
            warnings=[],
            remediation=[],
        )
        ops.list_duplicates.return_value = {}
        ops.get_addon_install_state.return_value = AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="x_sale",
            record_found=False,
            state="uninstalled",
            installed=False,
        )
        ops.install_module.return_value = {
            "success": True,
            "operation": "install_module",
            "return_code": 0,
        }
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
                "x_sale",
                "--allow-mutation",
                "--install-if-needed",
                "--update",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["mutation_action"] == {
        "action": "install",
        "performed": True,
        "reason": "module_not_installed",
    }
    ops.install_module.assert_called_once()
    ops.update_module.assert_not_called()


def test_agent_test_summary_module_uses_fast_test_tags_semantics(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.run_tests.return_value = {
            "success": True,
            "operation": "test",
            "return_code": 0,
            "total_tests": 5,
            "passed_tests": 5,
            "failed_tests": 0,
            "error_tests": 0,
            "failures": [],
        }
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "test-summary",
                "--allow-mutation",
                "--module",
                "x_sale",
            ],
        )

    assert result.exit_code == 0
    ops.run_tests.assert_called_once_with(
        module="x_sale",
        stop_on_error=False,
        install=None,
        update=None,
        coverage=None,
        test_file=None,
        test_tags=None,
        compact=False,
        suppress_output=True,
        log_level=None,
    )
    payload = json.loads(result.output)
    assert payload["selected_modules"] == ["x_sale"]
    assert payload["selection"].get("install") is None
