# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

from pathlib import Path

from oduit.operation_result import OperationResult
from oduit.utils import output_result_to_json

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "real_logs"


def _read_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def test_parse_install_results_real_log_fixture() -> None:
    builder = OperationResult("install", module="fastapi_reseller")
    builder.set_custom_data(modules=["fastapi_reseller"])

    result = builder._parse_install_results(
        _read_fixture("install_unmet_dependencies.log")
    )

    assert result["success"] is False
    assert result["total_modules"] == 88
    assert result["modules_loaded"] == 88
    assert result["failed_modules"] == ["fastapi_reseller"]
    assert result["unmet_dependencies"] == [
        {"module": "fastapi_reseller", "dependencies": ["ti4health_shopify"]}
    ]


def test_parse_test_results_real_log_fixture_preserves_structured_excerpt() -> None:
    builder = OperationResult("test", module="dvo")

    result = builder._parse_test_results(_read_fixture("test_failure_dvo.log"))

    assert result["warnings"] == []
    assert result["failed_tests"] == 1
    failure = result["failures"][0]
    assert failure["function_name"] == "test_find_dvo_id"
    assert (
        failure["source_line"] == "self.assertEqual(self.dvo_set1_team1.zone_count, 2)"
    )
    assert failure["failure_excerpt"] == (
        "/home/nahrstaedt/src/odoo17/odoo-17-addons/addons/dvo/tests/test_dvo.py:28: "
        "self.assertEqual(self.dvo_set1_team1.zone_count, 2)"
    )
    assert failure["raw_failure_excerpt"] == [
        "FAIL: TestDVO.test_find_dvo_id",
        "Traceback (most recent call last):",
        (
            'File "/home/nahrstaedt/src/odoo17/odoo-17-addons/addons/dvo/tests/'
            'test_dvo.py", line 28, in test_find_dvo_id'
        ),
        "self.assertEqual(self.dvo_set1_team1.zone_count, 2)",
        "AssertionError: 1 != 2",
    ]


def test_parse_test_results_real_log_fixture_recovers_wrapped_traceback() -> None:
    builder = OperationResult("test", module="test_module")

    result = builder._parse_test_results(
        _read_fixture("test_failure_wrapped_traceback.log")
    )

    assert result["warnings"] == []
    failure = result["failures"][0]
    assert failure["file"] == "/custom/addons/test_module/tests/test_basic.py"
    assert failure["line"] == 28
    assert failure["function_name"] == "test_update_record"
    assert failure["source_line"] == "self.assertTrue(record.active)"
    assert failure["failure_excerpt"] == (
        "/custom/addons/test_module/tests/test_basic.py:28: "
        "self.assertTrue(record.active)"
    )
    assert failure["raw_failure_excerpt"] == [
        "FAIL: BasicTestCase.test_update_record",
        "Traceback (most recent call last):",
        'File "/custom/addons/test_module/tests/test_basic.py", line 28,',
        "in test_update_record",
        "self.assertTrue(record.active)",
        "AssertionError: False is not true",
    ]


def test_parse_test_results_partial_log_emits_warning_and_raw_excerpt() -> None:
    builder = OperationResult("test", module="test_module")

    result = builder._parse_test_results(
        _read_fixture("test_failure_truncated_traceback.log")
    )

    assert result["warnings"] == [
        "Partially parsed failure 'BasicTestCase.test_missing_location'; "
        "preserved raw_failure_excerpt."
    ]
    failure = result["failures"][0]
    assert failure["file"] is None
    assert failure["failure_excerpt"] is None
    assert failure["error_message"] == "AssertionError: expected truthy value"
    assert failure["raw_failure_excerpt"] == [
        "FAIL: BasicTestCase.test_missing_location",
        "Traceback (most recent call last):",
        "AssertionError: expected truthy value",
    ]


def test_process_with_parsers_preserves_existing_and_parser_warnings() -> None:
    builder = OperationResult("test", module="test_module")
    builder.set_custom_data(
        operation_type="test",
        result_parsers=["test"],
        warnings=["Streaming warning"],
    )

    builder.process_with_parsers(_read_fixture("test_failure_truncated_traceback.log"))

    json_output = output_result_to_json(builder.finalize())

    assert json_output["warnings"] == [
        "Streaming warning",
        "Partially parsed failure 'BasicTestCase.test_missing_location'; "
        "preserved raw_failure_excerpt.",
    ]
    assert json_output["failures"][0]["raw_failure_excerpt"] == [
        "FAIL: BasicTestCase.test_missing_location",
        "Traceback (most recent call last):",
        "AssertionError: expected truthy value",
    ]
