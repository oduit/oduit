# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

from types import SimpleNamespace
from unittest.mock import patch

import pytest
import typer

from oduit.cli.agent.payloads import (
    agent_fail,
    agent_output_result_to_json,
    agent_payload,
    build_error_output_excerpt,
)
from oduit.cli.agent.services import build_agent_test_summary_details


def test_build_agent_test_summary_details_keeps_raw_excerpt() -> None:
    result = {
        "success": False,
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
        "failed_tests": 1,
        "error_tests": 0,
        "passed_tests": 0,
        "total_tests": 1,
        "return_code": 1,
        "command": ["odoo-bin", "--test-enable"],
    }

    data, warnings, _ = build_agent_test_summary_details(
        result,
        module="x_sale",
        install=None,
        update=None,
        coverage=None,
        test_file=None,
        test_tags=None,
        build_error_output_excerpt_fn=build_error_output_excerpt,
    )

    assert warnings == [
        "Partially parsed failure 'BasicTestCase.test_missing_location'; "
        "preserved raw_failure_excerpt."
    ]
    assert data["failure_details"][0]["raw_failure_excerpt"] == [
        "FAIL: BasicTestCase.test_missing_location",
        "Traceback (most recent call last):",
        "AssertionError: expected truthy value",
    ]
    assert data["traceback_summary"][0]["raw_failure_excerpt"] == [
        "FAIL: BasicTestCase.test_missing_location",
        "Traceback (most recent call last):",
        "AssertionError: expected truthy value",
    ]


def test_build_agent_test_summary_details_merges_coverage_warning() -> None:
    data, warnings, _ = build_agent_test_summary_details(
        {
            "success": True,
            "warnings": ["Parser warning"],
            "failures": [],
            "passed_tests": 1,
            "failed_tests": 0,
            "error_tests": 0,
            "total_tests": 1,
        },
        module=None,
        install=None,
        update=None,
        coverage="x_sale",
        test_file=None,
        test_tags=None,
        build_error_output_excerpt_fn=build_error_output_excerpt,
    )

    assert data["coverage_summary"]["requested"] is True
    assert warnings == [
        "Parser warning",
        "Per-file coverage entries are not currently normalized by run_tests().",
    ]


def test_agent_output_result_to_json_hides_command_by_default() -> None:
    payload = agent_output_result_to_json(
        {
            "success": True,
            "operation": "install_module",
            "command": ["python3", "odoo-bin", "-i", "sale"],
            "stdout": "installed",
        },
        exclude_fields=["stdout"],
        result_type="module_installation",
    )

    assert "command" not in payload
    assert "command" not in payload["data"]
    assert "stdout" not in payload
    assert "stdout" not in payload["data"]


def test_agent_output_result_to_json_preserves_command_when_requested() -> None:
    context = SimpleNamespace(obj={"show_command": True}, parent=None)
    with patch(
        "oduit.cli.agent.payloads.click.get_current_context",
        return_value=context,
    ):
        payload = agent_output_result_to_json(
            {
                "success": True,
                "operation": "install_module",
                "command": ["python3", "odoo-bin", "-i", "sale"],
            },
            result_type="module_installation",
        )

    assert "command" not in payload
    assert payload["data"]["command"] == ["python3", "odoo-bin", "-i", "sale"]


def test_agent_payload_is_not_flattened() -> None:
    payload = agent_payload(
        "addon_info",
        "addon_info",
        {"module": "sale", "depends": ["base"]},
    )

    assert payload["data"]["module"] == "sale"
    assert payload["data"]["depends"] == ["base"]
    assert "module" not in payload
    assert "depends" not in payload
    assert "timestamp" not in payload
    assert "generated_at" not in payload
    assert "timestamp" in payload["meta"]
    assert "generated_at" not in payload["meta"]


def test_agent_fail_uses_canonical_error_shape() -> None:
    emitted: list[dict[str, object]] = []

    with pytest.raises(typer.Exit) as exc_info:
        agent_fail(
            "inspect_addon",
            "addon_inspection",
            "addon missing",
            error_type="ModuleNotFoundError",
            details={"module": "sale"},
            remediation=["Check the module name."],
            emit_payload_fn=emitted.append,
        )

    assert exc_info.value.exit_code == 1
    payload = emitted[0]
    assert payload["error"] == "addon missing"
    assert payload["error_type"] == "ModuleNotFoundError"
    assert payload["data"]["module"] == "sale"
    assert payload["remediation"] == ["Check the module name."]
    assert "module" not in payload
    assert "timestamp" not in payload
    assert "generated_at" not in payload
    assert "timestamp" in payload["meta"]
    assert "generated_at" not in payload["meta"]
