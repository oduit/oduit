from unittest.mock import MagicMock

from oduit.odoo_inspector import OdooInspector


def _inspector() -> OdooInspector:
    return OdooInspector(
        {
            "db_name": "test_db",
            "db_user": "odoo",
            "addons_path": "/test/addons",
        }
    )


def test_inspect_ref_missing_becomes_not_found_error() -> None:
    inspector = _inspector()
    inspector._executor._execute_generated_code = MagicMock(
        return_value={
            "success": True,
            "value": {
                "xmlid": "base.missing_xmlid",
                "exists": False,
                "model": None,
                "res_id": None,
                "display_name": None,
            },
            "output": "",
            "error": "",
            "traceback": "",
        }
    )

    result = inspector.inspect_ref("base.missing_xmlid")

    assert result["success"] is False
    assert result["error_type"] == "NotFoundError"
    assert result["xmlid"] == "base.missing_xmlid"


def test_inspect_modules_sorts_and_normalizes_records() -> None:
    inspector = _inspector()
    inspector._query.query_model = MagicMock(
        return_value={
            "success": True,
            "records": [
                {
                    "name": "sale",
                    "state": "installed",
                    "shortdesc": "Sales",
                    "application": 1,
                    "auto_install": 0,
                },
                {
                    "name": "base",
                    "state": "installed",
                    "shortdesc": "Base",
                    "application": True,
                    "auto_install": False,
                },
            ],
            "database": "test_db",
        }
    )

    result = inspector.inspect_modules()

    assert result["success"] is True
    assert result["names"] == ["base", "sale"]
    assert result["modules"][0]["application"] is True
    assert result["modules"][0]["auto_install"] is False


def test_execute_code_rejects_blank_input() -> None:
    result = _inspector().execute_code("   ")

    assert result["success"] is False
    assert result["error_type"] == "ValidationError"
