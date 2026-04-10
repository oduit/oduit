from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oduit import (
    AddonInspection,
    AddonInstallState,
    EnvironmentContext,
    InstalledAddonInventory,
    InstalledAddonRecord,
    ModelFieldsResult,
    ModuleNotFoundError,
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
    assert plan.risk_score > 0
    assert isinstance(plan.inspection, AddonInspection)


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
