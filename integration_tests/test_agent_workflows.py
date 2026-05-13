import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oduit.cli.app import app
from oduit.config_loader import ConfigLoader
from oduit.odoo_operations import OdooOperations


def _invoke_agent(
    monkeypatch: pytest.MonkeyPatch,
    *args: str,
    config_override: dict[str, Any] | None = None,
) -> tuple[int, dict]:
    monkeypatch.chdir(Path(__file__).parent)
    if config_override is not None:
        patched_config = deepcopy(config_override)

        def _load_local_config(self: ConfigLoader) -> dict[str, Any]:
            del self
            return deepcopy(patched_config)

        monkeypatch.setattr(
            ConfigLoader,
            "load_local_config",
            _load_local_config,
        )
    runner = CliRunner()
    result = runner.invoke(app, list(args))
    payload_lines = [line for line in result.output.splitlines() if line.strip()]
    return result.exit_code, json.loads(payload_lines[-1])


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


def _config_with_overrides(config: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    updated = deepcopy(config)
    updated.update(overrides)
    return updated


def _module_is_installed(ops: OdooOperations, module: str) -> bool:
    state = ops.get_addon_install_state(module)
    assert state.success is True, state.error
    return state.installed


def _set_module_install_state(
    ops: OdooOperations,
    module: str,
    *,
    installed: bool,
) -> None:
    if _module_is_installed(ops, module) is installed:
        return

    if installed:
        result = ops.install_module(module, suppress_output=True)
        assert result["success"] is True, result
    else:
        result = ops.uninstall_module(
            module,
            suppress_output=True,
            allow_uninstall=True,
        )
        assert result["success"] is True, result

    assert _module_is_installed(ops, module) is installed


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
    assert context_payload["data"]["available_module_count"] >= 5

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
    assert inspect_payload["data"]["module"] == "e"
    assert inspect_payload["data"]["module_path"].endswith(
        "integration_tests/myaddons/e"
    )

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
    assert addon_info_payload["data"]["module"] == "e"
    assert addon_info_payload["data"]["test_cases"]

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
    assert locate_model_payload["data"]["candidates"][0]["path"].endswith(
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
    assert locate_field_payload["data"]["field"] == "integration_note"
    assert locate_field_payload["data"]["candidates"][0]["path"].endswith(
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
    assert addon_tests_payload["data"]["tests"][0]["path"].endswith(
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
        validate_payload["data"]["sub_results"]["discovered_tests"]["data"][
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
    assert prepare_payload["data"]["steps"]["inspect_addon"]["success"] is True
    assert prepare_payload["data"]["steps"]["locate_model"]["success"] is True
    assert prepare_payload["data"]["steps"]["locate_field"]["success"] is True
    assert prepare_payload["data"]["steps"]["list_addon_tests"]["data"]["tests"]
    assert prepare_payload["data"]["steps"]["get_model_fields"]["success"] is True
    assert prepare_payload["data"]["steps"]["get_model_views"]["success"] is True

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
        read_only=True,
        safety_level="safe_read_only",
    )
    assert tests_payload["data"]["selected_modules"] == ["e"]


@pytest.mark.integration
def test_agent_real_runtime_matrix_covers_mutation_gates_and_queries(
    integration_config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = "e"
    runtime_config = _config_with_overrides(integration_config, allow_uninstall=True)
    ops = OdooOperations(runtime_config, verbose=False)
    initially_installed = _module_is_installed(ops, module)

    try:
        _set_module_install_state(ops, module, installed=False)

        exit_code, install_plan_payload = _invoke_agent(
            monkeypatch,
            "agent",
            "install-module",
            module,
            "--dry-run",
            config_override=runtime_config,
        )
        assert exit_code == 0
        _assert_payload_shape(
            install_plan_payload,
            payload_type="addon_inspection",
            operation="install_module",
            read_only=True,
            safety_level="safe_read_only",
        )
        assert install_plan_payload["data"]["module"] == module
        assert install_plan_payload["data"]["planned_action"] == "install"

        exit_code, install_payload = _invoke_agent(
            monkeypatch,
            "agent",
            "install-module",
            module,
            "--allow-mutation",
            config_override=runtime_config,
        )
        assert exit_code == 0
        assert install_payload["success"] is True
        _assert_payload_shape(
            install_payload,
            payload_type="module_installation",
            operation="install_module",
            read_only=False,
            safety_level="controlled_runtime_mutation",
        )
        assert install_payload["data"]["module"] == module

        exit_code, installed_payload = _invoke_agent(
            monkeypatch,
            "agent",
            "list-installed-addons",
            "--modules",
            module,
            config_override=runtime_config,
        )
        assert exit_code == 0
        _assert_payload_shape(
            installed_payload,
            payload_type="installed_addon_inventory",
            operation="list_installed_addons",
            read_only=True,
            safety_level="safe_read_only",
        )
        assert any(
            addon["module"] == module and addon["installed"] is True
            for addon in installed_payload["data"]["addons"]
        )

        exit_code, query_payload = _invoke_agent(
            monkeypatch,
            "agent",
            "query-model",
            "ir.module.module",
            "--domain-json",
            f'[["name", "=", "{module}"]]',
            "--fields",
            "name,state",
            "--limit",
            "1",
            config_override=runtime_config,
        )
        assert exit_code == 0
        _assert_payload_shape(
            query_payload,
            payload_type="query_result",
            operation="query_model",
            read_only=True,
            safety_level="safe_read_only",
        )
        assert query_payload["data"]["count"] == 1
        assert query_payload["data"]["records"][0]["name"] == module
        assert query_payload["data"]["records"][0]["state"] == "installed"

        exit_code, update_plan_payload = _invoke_agent(
            monkeypatch,
            "agent",
            "update-module",
            module,
            "--dry-run",
            config_override=runtime_config,
        )
        assert exit_code == 0
        _assert_payload_shape(
            update_plan_payload,
            payload_type="update_plan",
            operation="update_module",
            read_only=True,
            safety_level="safe_read_only",
        )
        assert update_plan_payload["data"]["module"] == module
        assert update_plan_payload["data"]["planned_action"] == "update"

        exit_code, update_payload = _invoke_agent(
            monkeypatch,
            "agent",
            "update-module",
            module,
            "--allow-mutation",
            config_override=runtime_config,
        )
        assert exit_code == 0
        assert update_payload["success"] is True
        _assert_payload_shape(
            update_payload,
            payload_type="module_update",
            operation="update_module",
            read_only=False,
            safety_level="controlled_runtime_mutation",
        )
        assert update_payload["data"]["module"] == module

        exit_code, uninstall_plan_payload = _invoke_agent(
            monkeypatch,
            "agent",
            "uninstall-module",
            module,
            "--dry-run",
            config_override=runtime_config,
        )
        assert exit_code == 0
        _assert_payload_shape(
            uninstall_plan_payload,
            payload_type="module_uninstallation",
            operation="uninstall_module",
            read_only=True,
            safety_level="safe_read_only",
        )
        assert uninstall_plan_payload["data"]["planned_action"] == "uninstall"
        assert uninstall_plan_payload["data"]["config_allows_uninstall"] is True
        assert uninstall_plan_payload["data"]["allow_uninstall_flag"] is False
        assert uninstall_plan_payload["data"]["blocked"] is True
        assert (
            "--allow-uninstall was not provided"
            in uninstall_plan_payload["data"]["blocked_reasons"]
        )

        exit_code, uninstall_payload = _invoke_agent(
            monkeypatch,
            "agent",
            "uninstall-module",
            module,
            "--allow-mutation",
            "--allow-uninstall",
            config_override=runtime_config,
        )
        assert exit_code == 0
        assert uninstall_payload["success"] is True
        _assert_payload_shape(
            uninstall_payload,
            payload_type="module_uninstallation",
            operation="uninstall_module",
            read_only=False,
            safety_level="controlled_runtime_mutation",
        )
        assert uninstall_payload["data"]["module"] == module
        assert uninstall_payload["data"]["uninstalled"] is True

        exit_code, install_state_payload = _invoke_agent(
            monkeypatch,
            "agent",
            "check-addons-installed",
            "--modules",
            module,
            config_override=runtime_config,
        )
        assert exit_code == 0
        _assert_payload_shape(
            install_state_payload,
            payload_type="addon_install_checks",
            operation="check_addons_installed",
            read_only=True,
            safety_level="safe_read_only",
        )
        assert install_state_payload["data"]["installed_modules"] == []
        assert install_state_payload["data"]["not_installed_modules"] == [module]
    finally:
        _set_module_install_state(ops, module, installed=initially_installed)


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
    assert payload["data"]["verification_summary"]["failed_step"] is not None
    assert payload["errors"]
    assert payload["remediation"]
