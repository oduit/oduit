from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oduit import (
    AddonDocumentation,
    AddonInfo,
    AddonInspection,
    AddonInstallState,
    DependencyGraphDocumentation,
    EnvironmentContext,
    InstalledAddonInventory,
    InstalledAddonRecord,
    ModelDocumentation,
    ModelFieldsResult,
    ModuleNotFoundError,
    ModuleUninstallError,
    OdooOperations,
    QueryModelResult,
    RecordReadResult,
    SearchCountResult,
    UpdatePlan,
)


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


def _config(tmp_path: Path, addons_path: str) -> dict[str, str]:
    python_bin = tmp_path / "python3"
    python_bin.write_text("#!/bin/sh\nexit 0\n")
    python_bin.chmod(0o755)

    odoo_bin = tmp_path / "odoo-bin"
    odoo_bin.write_text("#!/bin/sh\nexit 0\n")
    odoo_bin.chmod(0o755)

    return {
        "python_bin": str(python_bin),
        "odoo_bin": str(odoo_bin),
        "addons_path": addons_path,
        "db_name": "test_db",
        "db_host": "localhost",
        "db_user": "odoo",
    }


def _test_execution_result(success: bool, output: str) -> dict[str, object]:
    return {
        "success": success,
        "return_code": 0 if success else 1,
        "output": output,
        "stdout": output,
        "stderr": "",
    }


def _port_conflict_output(port: int) -> str:
    return (
        "OSError: [Errno 98] Address already in use\n"
        f"Port {port} is in use by another program\n"
        "Either identify and stop that program, or start the server with a "
        "different port.\n"
    )


def test_get_environment_context_returns_typed_object(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    with patch.object(
        ops,
        "get_odoo_version",
        return_value={"success": True, "version": "17.0"},
    ):
        context = ops.get_environment_context(
            env_name="dev",
            config_source="env",
            config_path="/tmp/dev.toml",
        )

    assert isinstance(context, EnvironmentContext)
    assert context.environment.name == "dev"
    assert context.odoo.version == "17.0"
    assert context.available_module_count == 2
    assert context.addons_paths.valid == [str(addons_dir)]
    assert context.to_dict()["environment"]["source"] == "env"


def test_inspect_addon_returns_typed_object(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    _make_addon(addons_dir, "x_sale_ext", depends=["x_sale"])

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    inspection = ops.inspect_addon("x_sale")

    assert isinstance(inspection, AddonInspection)
    assert inspection.module == "x_sale"
    assert inspection.direct_dependencies == ["base"]
    assert inspection.reverse_dependencies == ["x_sale_ext"]
    assert inspection.install_order_slice == ["base", "x_sale"]


def test_addon_info_returns_combined_summary(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "my_partner"
    _make_addon(addons_dir, "my_partner", depends=["base"])
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
    (addon_dir / "i18n" / "fr.po").write_text('msgid ""\nmsgstr ""\n')

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    with patch.object(
        ops,
        "query_model",
        return_value=QueryModelResult(
            success=True,
            operation="query_model",
            model="ir.module.module",
            records=[{"name": "my_partner", "state": "installed"}],
            database="test_db",
        ),
    ):
        info = ops.addon_info("my_partner")

    assert isinstance(info, AddonInfo)
    assert info.module == "my_partner"
    assert info.depends == ["base"]
    assert info.models == ["x.partner.score"]
    assert info.inherit_models == ["mail.thread", "res.partner"]
    assert info.test_count == 1
    assert info.test_cases[0].path.endswith("tests/test_partner.py")
    assert info.languages == ["de", "fr"]
    assert info.installed_state is not None
    assert info.installed_state.installed is True


def test_plan_update_returns_typed_object(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    _make_addon(addons_dir, "x_sale_ext", depends=["x_sale"])

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    plan = ops.plan_update("x_sale")

    assert isinstance(plan, UpdatePlan)
    assert plan.impact_set == ["x_sale_ext"]
    assert plan.backup_advised is True
    assert plan.write_protect_db is False
    assert plan.agent_write_protect_db is False
    assert plan.needs_mutation_flag is False
    assert plan.agent_needs_mutation_flag is False
    assert plan.human_runtime_db_mutation_policy == "allow"
    assert plan.human_runtime_db_mutation_allowed is True
    assert plan.human_runtime_db_mutation_requires_flag is False
    assert plan.agent_runtime_db_mutation_policy == "allow"
    assert plan.agent_runtime_db_mutation_allowed is True
    assert plan.agent_runtime_db_mutation_requires_flag is False
    assert plan.risk_score > 0
    assert isinstance(plan.inspection, AddonInspection)


def test_build_addon_documentation_returns_typed_bundle(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "my_partner"
    _make_addon(addons_dir, "my_partner", depends=["base"])
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    score = fields.Integer()\n"
    )
    (addon_dir / "tests").mkdir()
    (addon_dir / "tests" / "test_partner.py").write_text("assert True\n")

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    bundle = ops.build_addon_documentation("my_partner", source_only=True)

    assert isinstance(bundle, AddonDocumentation)
    assert bundle.module == "my_partner"
    assert bundle.addon_info is not None
    assert bundle.addon_info.installed_state is None
    assert any(diagram.kind == "dependency_graph" for diagram in bundle.diagrams)
    assert "Addon documentation: my_partner" in bundle.markdown


def test_build_addon_documentation_relativizes_paths_under_prefix(
    tmp_path: Path,
) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "my_partner"
    _make_addon(addons_dir, "my_partner", depends=["base"])
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    score = fields.Integer()\n"
    )
    (addon_dir / "tests").mkdir()
    (addon_dir / "tests" / "test_partner.py").write_text("assert True\n")

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    bundle = ops.build_addon_documentation(
        "my_partner",
        source_only=True,
        path_prefix=str(tmp_path),
    )

    assert bundle.addon_info is not None
    assert bundle.addon_info.module_path == "addons/my_partner"
    assert bundle.model_inventory is not None
    assert bundle.model_inventory.addon_root == "addons/my_partner"
    assert (
        bundle.model_inventory.models[0].path == "addons/my_partner/models/partner.py"
    )
    assert (
        bundle.addon_info.test_cases[0].path
        == "addons/my_partner/tests/test_partner.py"
    )
    assert "addons/my_partner/models/partner.py" in bundle.markdown
    assert str(tmp_path / "addons" / "my_partner") not in bundle.markdown


def test_build_model_documentation_returns_typed_bundle(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "my_partner"
    _make_addon(addons_dir, "my_partner", depends=["base"])
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    score = fields.Integer()\n"
    )

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    bundle = ops.build_model_documentation("res.partner", source_only=True)

    assert isinstance(bundle, ModelDocumentation)
    assert bundle.model == "res.partner"
    assert bundle.field_metadata is None
    assert bundle.extension_inventory is not None
    assert "Model documentation: res.partner" in bundle.markdown


def test_build_model_documentation_keeps_absolute_paths_outside_prefix(
    tmp_path: Path,
) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = addons_dir / "my_partner"
    _make_addon(addons_dir, "my_partner", depends=["base"])
    model_path = addon_dir / "models" / "partner.py"
    model_path.parent.mkdir()
    model_path.write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    score = fields.Integer()\n"
    )

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    bundle = ops.build_model_documentation(
        "res.partner",
        source_only=True,
        path_prefix=str(tmp_path / "outside"),
    )

    assert bundle.extension_inventory is not None
    assert Path(bundle.extension_inventory.source_extensions[0].path) == model_path


def test_build_dependency_graph_documentation_returns_typed_bundle(
    tmp_path: Path,
) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    _make_addon(addons_dir, "x_sale_ext", depends=["x_sale"])

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    bundle = ops.build_dependency_graph_documentation(["x_sale"], source_only=True)

    assert isinstance(bundle, DependencyGraphDocumentation)
    assert bundle.modules == ["x_sale"]
    assert bundle.dependency_graph["nodes"] == ["base", "x_sale"]
    assert "Dependency graph documentation" in bundle.markdown


def test_inspect_addon_missing_module_raises(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    ops = OdooOperations(_config(tmp_path, str(addons_dir)))

    with pytest.raises(ModuleNotFoundError):
        ops.inspect_addon("missing_module")


def test_query_model_returns_typed_result(tmp_path: Path) -> None:
    ops = OdooOperations(_config(tmp_path, str(tmp_path / "addons")))
    with patch("oduit.odoo_operations.OdooQuery") as mock_query_class:
        query = MagicMock()
        query.query_model.return_value = {
            "success": True,
            "operation": "query_model",
            "model": "res.partner",
            "count": 1,
            "ids": [7],
            "records": [{"id": 7, "name": "Azure Interior"}],
            "fields": ["name"],
            "limit": 5,
        }
        mock_query_class.return_value = query

        result = ops.query_model("res.partner", fields=["name"], limit=5)

    assert isinstance(result, QueryModelResult)
    assert result.success is True
    assert result.count == 1
    assert result.records == [{"id": 7, "name": "Azure Interior"}]


@pytest.mark.parametrize(
    ("records", "record_found", "state", "installed"),
    [
        ([{"name": "sale", "state": "installed"}], True, "installed", True),
        ([{"name": "sale", "state": "uninstalled"}], True, "uninstalled", False),
        ([], False, "uninstalled", False),
    ],
)
def test_get_addon_install_state_returns_typed_result(
    tmp_path: Path,
    records: list[dict[str, object]],
    record_found: bool,
    state: str,
    installed: bool,
) -> None:
    ops = OdooOperations(_config(tmp_path, str(tmp_path / "addons")))
    with patch("oduit.odoo_operations.OdooQuery") as mock_query_class:
        query = MagicMock()
        query.query_model.return_value = {
            "success": True,
            "operation": "query_model",
            "model": "ir.module.module",
            "records": records,
            "database": "test_db",
        }
        mock_query_class.return_value = query

        result = ops.get_addon_install_state("sale")

    assert isinstance(result, AddonInstallState)
    assert result.success is True
    assert result.module == "sale"
    assert result.record_found is record_found
    assert result.state == state
    assert result.installed is installed
    query.query_model.assert_called_once_with(
        "ir.module.module",
        domain=[["name", "=", "sale"]],
        fields=["name", "state"],
        limit=1,
        database=None,
        timeout=30.0,
    )


def test_get_addon_install_state_propagates_query_failure(tmp_path: Path) -> None:
    ops = OdooOperations(_config(tmp_path, str(tmp_path / "addons")))
    with patch("oduit.odoo_operations.OdooQuery") as mock_query_class:
        query = MagicMock()
        query.query_model.return_value = {
            "success": False,
            "operation": "query_model",
            "model": "ir.module.module",
            "database": "other_db",
            "error": "database unavailable",
            "error_type": "QueryError",
        }
        mock_query_class.return_value = query

        result = ops.get_addon_install_state(
            "sale",
            database="other_db",
            timeout=12.0,
        )

    assert isinstance(result, AddonInstallState)
    assert result.success is False
    assert result.module == "sale"
    assert result.error == "database unavailable"
    assert result.error_type == "QueryError"
    query.query_model.assert_called_once_with(
        "ir.module.module",
        domain=[["name", "=", "sale"]],
        fields=["name", "state"],
        limit=1,
        database="other_db",
        timeout=12.0,
    )


def test_list_installed_addons_defaults_to_installed_filter(tmp_path: Path) -> None:
    ops = OdooOperations(_config(tmp_path, str(tmp_path / "addons")))
    with patch("oduit.odoo_operations.OdooQuery") as mock_query_class:
        query = MagicMock()
        query.query_model.return_value = {
            "success": True,
            "operation": "query_model",
            "model": "ir.module.module",
            "records": [
                {
                    "name": "sale",
                    "state": "installed",
                    "shortdesc": "Sales",
                    "application": True,
                    "auto_install": False,
                },
                {
                    "name": "base",
                    "state": "installed",
                    "shortdesc": "Base",
                    "application": 1,
                    "auto_install": 0,
                },
            ],
            "database": "test_db",
        }
        mock_query_class.return_value = query

        result = ops.list_installed_addons()

    assert isinstance(result, InstalledAddonInventory)
    assert result.success is True
    assert result.states == ["installed"]
    assert result.total == 2
    assert [addon.module for addon in result.addons] == ["base", "sale"]
    assert isinstance(result.addons[0], InstalledAddonRecord)
    assert result.addons[0].application is True
    assert result.addons[0].auto_install is False
    query.query_model.assert_called_once_with(
        "ir.module.module",
        domain=[["state", "in", ["installed"]]],
        fields=["name", "state", "shortdesc", "application", "auto_install"],
        limit=500,
        database=None,
        timeout=30.0,
    )


def test_list_installed_addons_supports_module_and_state_filters(
    tmp_path: Path,
) -> None:
    ops = OdooOperations(_config(tmp_path, str(tmp_path / "addons")))
    with patch("oduit.odoo_operations.OdooQuery") as mock_query_class:
        query = MagicMock()
        query.query_model.return_value = {
            "success": True,
            "operation": "query_model",
            "model": "ir.module.module",
            "records": [
                {
                    "name": "sale",
                    "state": "to_upgrade",
                    "shortdesc": "Sales",
                }
            ],
            "database": "alt_db",
        }
        mock_query_class.return_value = query

        result = ops.list_installed_addons(
            modules=["sale", "crm"],
            states=["installed", "to_upgrade"],
            database="alt_db",
            timeout=9.0,
        )

    assert isinstance(result, InstalledAddonInventory)
    assert result.success is True
    assert result.states == ["installed", "to_upgrade"]
    assert result.modules_filter == ["sale", "crm"]
    assert result.addons[0].state == "to_upgrade"
    query.query_model.assert_called_once_with(
        "ir.module.module",
        domain=[
            ["state", "in", ["installed", "to_upgrade"]],
            ["name", "in", ["sale", "crm"]],
        ],
        fields=["name", "state", "shortdesc", "application", "auto_install"],
        limit=500,
        database="alt_db",
        timeout=9.0,
    )


def test_list_installed_dependents_filters_reverse_dependencies(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "crm", depends=["base"])
    _make_addon(addons_dir, "sale_crm", depends=["crm"])
    _make_addon(addons_dir, "crm_iap", depends=["crm"])
    _make_addon(addons_dir, "website", depends=["base"])

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    with patch("oduit.odoo_operations.OdooQuery") as mock_query_class:
        query = MagicMock()
        query.query_model.return_value = {
            "success": True,
            "operation": "query_model",
            "model": "ir.module.module",
            "records": [
                {
                    "name": "sale_crm",
                    "state": "installed",
                    "shortdesc": "Sale CRM",
                }
            ],
            "database": "test_db",
        }
        mock_query_class.return_value = query

        result = ops.list_installed_dependents("crm")

    assert isinstance(result, InstalledAddonInventory)
    assert result.success is True
    assert result.operation == "list_installed_dependents"
    assert result.modules_filter == ["crm_iap", "sale_crm"]
    assert [addon.module for addon in result.addons] == ["sale_crm"]
    query.query_model.assert_called_once_with(
        "ir.module.module",
        domain=[
            ["state", "in", ["installed"]],
            ["name", "in", ["crm_iap", "sale_crm"]],
        ],
        fields=["name", "state", "shortdesc", "application", "auto_install"],
        limit=500,
        database=None,
        timeout=30.0,
    )


def test_list_installed_dependents_handles_no_reverse_dependencies(
    tmp_path: Path,
) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "crm", depends=["base"])

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))

    result = ops.list_installed_dependents("crm")

    assert isinstance(result, InstalledAddonInventory)
    assert result.success is True
    assert result.operation == "list_installed_dependents"
    assert result.total == 0
    assert result.modules_filter == []
    assert result.addons == []


def test_run_tests_retries_when_configured_http_port_is_occupied(
    tmp_path: Path,
) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _config(tmp_path, str(addons_dir))
    config["http_port"] = 8481
    ops = OdooOperations(config)
    ops.process_manager = MagicMock()
    ops.process_manager.run_operation.side_effect = [
        _test_execution_result(False, _port_conflict_output(8481)),
        _test_execution_result(True, "Ran 1 test in 0.10s\nOK\n"),
    ]

    with patch.object(
        ops._runtime_service,
        "_find_available_http_port",
        return_value=8482,
    ):
        result = ops.run_tests(module="x_sale")

    first_operation = ops.process_manager.run_operation.call_args_list[0].args[0]
    second_operation = ops.process_manager.run_operation.call_args_list[1].args[0]
    assert ops.process_manager.run_operation.call_count == 2
    assert "--http-port=8481" in first_operation.command
    assert "--http-port=8482" in second_operation.command
    assert result["success"] is True
    assert result["http_port"] == 8482
    assert result["http_port_auto_retried"] is True
    assert result["http_port_retry_count"] == 1
    assert result["http_port_attempts"] == [8481, 8482]


def test_run_tests_does_not_retry_for_unrelated_failure(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _config(tmp_path, str(addons_dir))
    config["http_port"] = 8481
    ops = OdooOperations(config)
    ops.process_manager = MagicMock()
    ops.process_manager.run_operation.return_value = _test_execution_result(
        False,
        "FAIL: test_example\nAssertionError: boom\n",
    )

    result = ops.run_tests(module="x_sale")

    operation = ops.process_manager.run_operation.call_args.args[0]
    assert ops.process_manager.run_operation.call_count == 1
    assert "--http-port=8481" in operation.command
    assert result["success"] is False
    assert result["http_port_auto_retried"] is False
    assert result["http_port_attempts"] == [8481]


def test_run_tests_stops_after_http_port_retry_cap(tmp_path: Path) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _config(tmp_path, str(addons_dir))
    config["http_port"] = 8481
    ops = OdooOperations(config)
    ops.process_manager = MagicMock()
    ops.process_manager.run_operation.side_effect = [
        _test_execution_result(False, _port_conflict_output(8481)),
        _test_execution_result(False, _port_conflict_output(8482)),
        _test_execution_result(False, _port_conflict_output(8483)),
        _test_execution_result(False, _port_conflict_output(8484)),
        _test_execution_result(False, _port_conflict_output(8485)),
    ]

    with patch.object(
        ops._runtime_service,
        "_find_available_http_port",
        side_effect=[8482, 8483, 8484, 8485],
    ):
        result = ops.run_tests(module="x_sale")

    assert ops.process_manager.run_operation.call_count == 5
    assert result["success"] is False
    assert result["http_port_auto_retried"] is True
    assert result["http_port_retry_count"] == 4
    assert result["http_port_attempts"] == [8481, 8482, 8483, 8484, 8485]


def test_run_tests_runs_coverage_report_only_after_successful_retry(
    tmp_path: Path,
) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    config = _config(tmp_path, str(addons_dir))
    config["http_port"] = 8481
    config["coverage_bin"] = "/usr/bin/coverage"
    ops = OdooOperations(config)
    ops.process_manager = MagicMock()
    ops.process_manager.run_operation.side_effect = [
        _test_execution_result(False, _port_conflict_output(8481)),
        _test_execution_result(True, "Ran 1 test in 0.10s\nOK\n"),
    ]
    ops.process_manager.run_command.return_value = _test_execution_result(
        True,
        "Name Stmts Miss Cover Missing\nTOTAL 10 0 100%\n",
    )

    with patch.object(
        ops._runtime_service,
        "_find_available_http_port",
        return_value=8482,
    ):
        ops.run_tests(coverage="x_sale")

    assert [call[0] for call in ops.process_manager.mock_calls] == [
        "run_operation",
        "run_operation",
        "run_command",
    ]
    ops.process_manager.run_command.assert_called_once_with(
        ["/usr/bin/coverage", "report", "-m"],
        verbose=False,
        suppress_output=False,
    )


def test_run_tests_retries_without_explicit_configured_http_port(
    tmp_path: Path,
) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = _config(tmp_path, str(addons_dir))
    ops = OdooOperations(config)
    ops.process_manager = MagicMock()
    ops.process_manager.run_operation.side_effect = [
        _test_execution_result(False, _port_conflict_output(8491)),
        _test_execution_result(True, "Ran 1 test in 0.10s\nOK\n"),
    ]

    with patch.object(
        ops._runtime_service,
        "_find_available_http_port",
        return_value=8492,
    ):
        result = ops.run_tests(module="x_sale")

    first_operation = ops.process_manager.run_operation.call_args_list[0].args[0]
    second_operation = ops.process_manager.run_operation.call_args_list[1].args[0]
    assert "--http-port=8491" not in first_operation.command
    assert "--http-port=8492" in second_operation.command
    assert result["success"] is True
    assert result["http_port_auto_retried"] is True
    assert result["http_port_attempts"] == [8491, 8492]


def test_module_uninstall_error_is_exported() -> None:
    exc = ModuleUninstallError("failed")

    assert str(exc) == "failed"


def test_uninstall_module_requires_config_opt_in(tmp_path: Path) -> None:
    ops = OdooOperations(_config(tmp_path, str(tmp_path / "addons")))

    result = ops.uninstall_module("sale", allow_uninstall=True)

    assert result["success"] is False
    assert result["error_type"] == "ConfigError"
    assert "allow_uninstall=true" in result["error"]


def test_uninstall_module_requires_explicit_flag(tmp_path: Path) -> None:
    config = _config(tmp_path, str(tmp_path / "addons"))
    config["allow_uninstall"] = True
    ops = OdooOperations(config)

    result = ops.uninstall_module("sale")

    assert result["success"] is False
    assert result["error_type"] == "ConfirmationRequired"


def test_uninstall_module_fails_when_module_not_installed(tmp_path: Path) -> None:
    config = _config(tmp_path, str(tmp_path / "addons"))
    config["allow_uninstall"] = True
    ops = OdooOperations(config)

    with (
        patch.object(
            ops,
            "get_addon_install_state",
            return_value=AddonInstallState(
                success=True,
                operation="get_addon_install_state",
                module="sale",
                record_found=True,
                state="uninstalled",
                installed=False,
                database="test_db",
            ),
        ),
        patch("oduit.odoo_operations.OdooCodeExecutor") as mock_executor_class,
    ):
        result = ops.uninstall_module("sale", allow_uninstall=True)

    assert result["success"] is False
    assert result["error_type"] == "ModuleUninstallError"
    assert "not installed" in result["error"]
    mock_executor_class.assert_not_called()


def test_uninstall_module_blocks_installed_dependents(tmp_path: Path) -> None:
    config = _config(tmp_path, str(tmp_path / "addons"))
    config["allow_uninstall"] = True
    ops = OdooOperations(config)

    with (
        patch.object(
            ops,
            "get_addon_install_state",
            return_value=AddonInstallState(
                success=True,
                operation="get_addon_install_state",
                module="crm",
                record_found=True,
                state="installed",
                installed=True,
                database="test_db",
            ),
        ),
        patch.object(
            ops,
            "list_installed_dependents",
            return_value=InstalledAddonInventory(
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
            ),
        ),
    ):
        result = ops.uninstall_module("crm", allow_uninstall=True)

    assert result["success"] is False
    assert result["error_type"] == "ModuleUninstallError"
    assert result["dependent_modules"] == ["sale_crm"]


def test_uninstall_module_returns_structured_result(tmp_path: Path) -> None:
    config = _config(tmp_path, str(tmp_path / "addons"))
    config["allow_uninstall"] = True
    ops = OdooOperations(config)

    with (
        patch.object(
            ops,
            "get_addon_install_state",
            return_value=AddonInstallState(
                success=True,
                operation="get_addon_install_state",
                module="crm",
                record_found=True,
                state="installed",
                installed=True,
                database="test_db",
            ),
        ),
        patch.object(
            ops,
            "list_installed_dependents",
            return_value=InstalledAddonInventory(
                success=True,
                operation="list_installed_dependents",
                addons=[],
                total=0,
                states=["installed"],
                modules_filter=[],
                database="test_db",
            ),
        ),
        patch("oduit.odoo_operations.OdooCodeExecutor") as mock_executor_class,
    ):
        executor = MagicMock()
        executor._execute_generated_code.return_value = {
            "success": True,
            "value": {
                "module": "crm",
                "record_found": True,
                "previous_state": "installed",
                "final_state": "uninstalled",
                "uninstalled": True,
            },
        }
        mock_executor_class.return_value = executor

        result = ops.uninstall_module("crm", allow_uninstall=True)

    assert result["success"] is True
    assert result["previous_state"] == "installed"
    assert result["final_state"] == "uninstalled"
    assert result["uninstalled"] is True
    executor._execute_generated_code.assert_called_once()
    _, kwargs = executor._execute_generated_code.call_args
    assert kwargs["database"] == "test_db"
    assert kwargs["commit"] is True


def test_uninstall_module_raise_on_error_raises(tmp_path: Path) -> None:
    config = _config(tmp_path, str(tmp_path / "addons"))
    config["allow_uninstall"] = True
    ops = OdooOperations(config)

    with patch.object(
        ops,
        "get_addon_install_state",
        return_value=AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module="sale",
            record_found=True,
            state="uninstalled",
            installed=False,
            database="test_db",
        ),
    ):
        with pytest.raises(ModuleUninstallError):
            ops.uninstall_module("sale", allow_uninstall=True, raise_on_error=True)


@pytest.mark.parametrize(
    ("method_name", "query_method", "result_class", "return_value", "args", "kwargs"),
    [
        (
            "read_record",
            "read_record",
            RecordReadResult,
            {
                "success": True,
                "operation": "read_record",
                "model": "res.partner",
                "record_id": 7,
                "found": True,
                "record": {"id": 7, "name": "Azure Interior"},
                "fields": ["name"],
            },
            ("res.partner", 7),
            {"fields": ["name"]},
        ),
        (
            "search_count",
            "search_count",
            SearchCountResult,
            {
                "success": True,
                "operation": "search_count",
                "model": "res.partner",
                "domain": [("is_company", "=", True)],
                "count": 3,
            },
            ("res.partner",),
            {"domain": [("is_company", "=", True)]},
        ),
        (
            "get_model_fields",
            "get_model_fields",
            ModelFieldsResult,
            {
                "success": True,
                "operation": "get_model_fields",
                "model": "res.partner",
                "attributes": ["string"],
                "field_names": ["id", "name"],
                "field_definitions": {"name": {"string": "Name"}},
            },
            ("res.partner",),
            {"attributes": ["string"]},
        ),
    ],
)
def test_query_delegation_methods_return_typed_results(
    tmp_path: Path,
    method_name: str,
    query_method: str,
    result_class: type,
    return_value: dict,
    args: tuple,
    kwargs: dict,
) -> None:
    ops = OdooOperations(_config(tmp_path, str(tmp_path / "addons")))
    with patch("oduit.odoo_operations.OdooQuery") as mock_query_class:
        query = MagicMock()
        getattr(query, query_method).return_value = return_value
        mock_query_class.return_value = query

        result = getattr(ops, method_name)(*args, **kwargs)

    assert isinstance(result, result_class)
    assert result.success is True
