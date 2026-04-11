import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oduit.cli.app import app


def _invoke_agent(monkeypatch: pytest.MonkeyPatch, *args: str) -> tuple[int, dict]:
    monkeypatch.chdir(Path(__file__).parent)
    runner = CliRunner()
    result = runner.invoke(app, list(args))
    return result.exit_code, json.loads(result.output)


def _assert_payload_shape(
    payload: dict,
    *,
    payload_type: str,
    operation: str,
    read_only: bool,
    safety_level: str,
) -> None:
    assert payload["type"] == payload_type
    assert payload["operation"] == operation
    assert payload["read_only"] is read_only
    assert payload["safety_level"] == safety_level


@pytest.mark.integration
def test_agent_smoke_commands_emit_expected_envelopes(
    integration_config: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del integration_config

    exit_code, context_payload = _invoke_agent(monkeypatch, "agent", "context")
    assert exit_code == 0
    _assert_payload_shape(
        context_payload,
        payload_type="environment_context",
        operation="agent_context",
        read_only=True,
        safety_level="safe_read_only",
    )
    assert context_payload["available_module_count"] >= 5

    exit_code, inspect_payload = _invoke_agent(
        monkeypatch, "agent", "inspect-addon", "e"
    )
    assert exit_code == 0
    _assert_payload_shape(
        inspect_payload,
        payload_type="addon_inspection",
        operation="inspect_addon",
        read_only=True,
        safety_level="safe_read_only",
    )
    assert inspect_payload["module"] == "e"
    assert inspect_payload["module_path"].endswith("integration_tests/myaddons/e")

    exit_code, addon_info_payload = _invoke_agent(
        monkeypatch, "agent", "addon-info", "e"
    )
    assert exit_code == 0
    _assert_payload_shape(
        addon_info_payload,
        payload_type="addon_info",
        operation="addon_info",
        read_only=True,
        safety_level="safe_read_only",
    )
    assert addon_info_payload["module"] == "e"
    assert addon_info_payload["test_cases"]

    exit_code, locate_model_payload = _invoke_agent(
        monkeypatch,
        "agent",
        "locate-model",
        "test.dummy",
        "--module",
        "e",
    )
    assert exit_code == 0
    _assert_payload_shape(
        locate_model_payload,
        payload_type="model_source_location",
        operation="locate_model",
        read_only=True,
        safety_level="safe_read_only",
    )
    assert locate_model_payload["candidates"][0]["path"].endswith(
        "myaddons/e/models.py"
    )

    exit_code, locate_field_payload = _invoke_agent(
        monkeypatch,
        "agent",
        "locate-field",
        "test.dummy",
        "integration_note",
        "--module",
        "e",
    )
    assert exit_code == 0
    _assert_payload_shape(
        locate_field_payload,
        payload_type="field_source_location",
        operation="locate_field",
        read_only=True,
        safety_level="safe_read_only",
    )
    assert locate_field_payload["field"] == "integration_note"
    assert locate_field_payload["candidates"][0]["path"].endswith(
        "myaddons/e/models.py"
    )

    exit_code, addon_tests_payload = _invoke_agent(
        monkeypatch, "agent", "list-addon-tests", "e"
    )
    assert exit_code == 0
    _assert_payload_shape(
        addon_tests_payload,
        payload_type="addon_test_inventory",
        operation="list_addon_tests",
        read_only=True,
        safety_level="safe_read_only",
    )
    assert addon_tests_payload["tests"][0]["path"].endswith(
        "myaddons/e/tests/test_basic.py"
    )

    exit_code, validate_payload = _invoke_agent(
        monkeypatch,
        "agent",
        "validate-addon-change",
        "e",
        "--allow-mutation",
        "--install-if-needed",
        "--discover-tests",
    )
    assert exit_code == 0
    assert validate_payload["success"] is True
    _assert_payload_shape(
        validate_payload,
        payload_type="addon_change_validation",
        operation="validate_addon_change",
        read_only=False,
        safety_level="controlled_runtime_mutation",
    )
    assert (
        validate_payload["sub_results"]["discovered_tests"]["data"][
            "execution_strategy"
        ]
        == "inventory_only"
    )

    exit_code, prepare_payload = _invoke_agent(
        monkeypatch,
        "agent",
        "prepare-addon-change",
        "e",
        "--model",
        "test.dummy",
        "--field",
        "integration_note",
        "--types",
        "form",
    )
    assert exit_code == 0
    assert prepare_payload["success"] is True
    _assert_payload_shape(
        prepare_payload,
        payload_type="addon_change_context",
        operation="prepare_addon_change",
        read_only=True,
        safety_level="safe_read_only",
    )
    assert prepare_payload["steps"]["inspect_addon"]["success"] is True
    assert prepare_payload["steps"]["locate_model"]["success"] is True
    assert prepare_payload["steps"]["locate_field"]["success"] is True
    assert prepare_payload["steps"]["list_addon_tests"]["data"]["tests"]
    assert prepare_payload["steps"]["get_model_fields"]["success"] is True
    assert prepare_payload["steps"]["get_model_views"]["success"] is True

    exit_code, tests_payload = _invoke_agent(
        monkeypatch,
        "agent",
        "test-summary",
        "--allow-mutation",
        "--module",
        "e",
        "--test-tags",
        "/e",
    )
    assert exit_code == 0
    assert tests_payload["success"] is True
    _assert_payload_shape(
        tests_payload,
        payload_type="test_summary",
        operation="test_summary",
        read_only=False,
        safety_level="controlled_runtime_mutation",
    )
    assert tests_payload["selected_modules"] == ["e"]


@pytest.mark.integration
def test_agent_validate_addon_change_reports_dependency_failure(
    integration_config: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del integration_config

    exit_code, payload = _invoke_agent(
        monkeypatch,
        "agent",
        "validate-addon-change",
        "d",
        "--allow-mutation",
        "--install-if-needed",
    )

    assert exit_code == 1
    assert payload["success"] is False
    _assert_payload_shape(
        payload,
        payload_type="addon_change_validation",
        operation="validate_addon_change",
        read_only=False,
        safety_level="controlled_runtime_mutation",
    )
    assert payload["verification_summary"]["failed_step"] is not None
    assert payload["errors"]
    assert payload["remediation"]
