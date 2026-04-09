import json
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from oduit.cli_typer import app
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
    }


def _loader_with_config(config: dict[str, str], tmp_path: Path) -> MagicMock:
    loader = MagicMock()
    loader.load_config.return_value = config
    loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
    return loader


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
        patch("oduit.cli_typer.ConfigLoader", return_value=loader),
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


def test_agent_inspect_addon_returns_dependency_snapshot(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    _make_addon(addons_dir, "x_sale_ext", depends=["x_sale"])

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli_typer.ConfigLoader", return_value=loader):
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


def test_agent_plan_update_returns_risk_summary(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    _make_addon(addons_dir, "x_sale", depends=["base"])
    _make_addon(addons_dir, "x_sale_ext", depends=["x_sale"])

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli_typer.ConfigLoader", return_value=loader):
        result = runner.invoke(app, ["--env", "dev", "agent", "plan-update", "x_sale"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "update_plan"
    assert payload["operation"] == "plan_update"
    assert payload["impact_set"] == ["x_sale_ext"]
    assert payload["backup_advised"] is True
    assert payload["risk_score"] > 0
    assert payload["risk_level"] in {"low", "medium", "high"}
    assert payload["recommended_sequence"]


def test_agent_query_model_wraps_odoo_query(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli_typer.ConfigLoader", return_value=loader),
        patch("oduit.cli_typer.OdooOperations") as mock_ops_class,
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


def test_agent_query_model_invalid_domain_json_is_structured(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli_typer.ConfigLoader", return_value=loader):
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
    assert "must be valid JSON" in payload["error"]


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
        patch("oduit.cli_typer.ConfigLoader", return_value=loader),
        patch("oduit.cli_typer.OdooOperations") as mock_ops_class,
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
        patch("oduit.cli_typer.ConfigLoader", return_value=loader),
        patch("oduit.cli_typer.OdooOperations") as mock_ops_class,
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
    assert payload["read_only"] is False
    assert payload["safety_level"] == "controlled_mutation"
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
        patch("oduit.cli_typer.ConfigLoader", return_value=loader),
        patch("oduit.cli_typer.OdooOperations") as mock_ops_class,
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
                "--install",
                "x_sale",
            ],
        )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload.get("failure_details", []) == []
    assert payload["error_output_excerpt"]
    assert payload["error_output_excerpt"][-1] == "ValueError: missing dependency"


def test_agent_test_summary_module_uses_fast_test_tags_semantics(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config = _agent_config(tmp_path, str(tmp_path / "addons"))
    loader = _loader_with_config(config, tmp_path)

    with (
        patch("oduit.cli_typer.ConfigLoader", return_value=loader),
        patch("oduit.cli_typer.OdooOperations") as mock_ops_class,
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
