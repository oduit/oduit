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


@pytest.mark.integration
def test_agent_prepare_addon_change_and_validate_success(
    integration_config: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del integration_config

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
    assert payload["failed_step"] is not None
    assert payload["errors"]
    assert payload["remediation"]
