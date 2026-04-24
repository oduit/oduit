from unittest.mock import MagicMock

from oduit.odoo_query import OdooQuery


def _query() -> OdooQuery:
    return OdooQuery(
        {
            "db_name": "test_db",
            "db_user": "odoo",
            "addons_path": "/test/addons",
        }
    )


def test_query_model_happy_path_uses_generated_code() -> None:
    query = _query()
    query._executor.execute_code = MagicMock(
        side_effect=AssertionError("unsafe path used")
    )
    query._executor._execute_generated_code = MagicMock(
        return_value={
            "success": True,
            "value": {
                "model": "res.partner",
                "count": 1,
                "ids": [7],
                "records": [{"id": 7, "name": "Azure Interior"}],
                "fields": ["name"],
                "limit": 5,
            },
            "output": "",
            "error": "",
            "traceback": "",
        }
    )

    result = query.query_model(
        "res.partner",
        domain=[("customer_rank", ">", 0)],
        fields=["name"],
        limit=5,
    )

    assert result["success"] is True
    assert result["operation"] == "query_model"
    assert result["model"] == "res.partner"
    assert result["count"] == 1
    assert result["ids"] == [7]
    assert result["records"] == [{"id": 7, "name": "Azure Interior"}]
    query._executor._execute_generated_code.assert_called_once()
    _, kwargs = query._executor._execute_generated_code.call_args
    assert kwargs["commit"] is False
    assert kwargs["database"] is None
    assert kwargs["timeout"] == 30.0


def test_query_model_rejects_invalid_model() -> None:
    query = _query()

    result = query.query_model("res.partner; import os")

    assert result["success"] is False
    assert result["error_type"] == "ValidationError"
    assert "invalid characters" in result["error"]


def test_query_model_rejects_invalid_fields() -> None:
    query = _query()

    result = query.query_model("res.partner", fields=["name", "bad-field"])

    assert result["success"] is False
    assert result["error_type"] == "ValidationError"
    assert "fields" in result["error"]


def test_query_model_rejects_invalid_domain() -> None:
    query = _query()

    result = query.query_model("res.partner", domain=[{"bad": object()}])

    assert result["success"] is False
    assert result["error_type"] == "ValidationError"
    assert "literal-safe" in result["error"]


def test_query_model_rejects_limit_over_cap() -> None:
    query = _query()

    result = query.query_model("res.partner", limit=1000)

    assert result["success"] is False
    assert result["error_type"] == "ValidationError"
    assert "less than or equal to 500" in result["error"]


def test_search_count_happy_path() -> None:
    query = _query()
    query._executor._execute_generated_code = MagicMock(
        return_value={
            "success": True,
            "value": {
                "model": "res.partner",
                "domain": [("is_company", "=", True)],
                "count": 12,
            },
            "output": "",
            "error": "",
            "traceback": "",
        }
    )

    result = query.search_count("res.partner", domain=[("is_company", "=", True)])

    assert result["success"] is True
    assert result["operation"] == "search_count"
    assert result["count"] == 12


def test_read_record_rejects_invalid_id() -> None:
    query = _query()

    result = query.read_record("res.partner", 0)

    assert result["success"] is False
    assert result["error_type"] == "ValidationError"
    assert "positive integer" in result["error"]


def test_get_model_fields_happy_path() -> None:
    query = _query()
    query._executor._execute_generated_code = MagicMock(
        return_value={
            "success": True,
            "value": {
                "model": "res.partner",
                "attributes": ["string", "type"],
                "field_names": ["id", "name"],
                "field_definitions": {
                    "id": {"string": "ID", "type": "integer"},
                    "name": {"string": "Name", "type": "char"},
                },
            },
            "output": "",
            "error": "",
            "traceback": "",
        }
    )

    result = query.get_model_fields("res.partner", attributes=["string", "type"])

    assert result["success"] is True
    assert result["operation"] == "get_model_fields"
    assert result["field_names"] == ["id", "name"]
    assert result["field_definitions"]["name"]["type"] == "char"


def test_get_model_fields_with_module_filter() -> None:
    query = _query()
    query._executor._execute_generated_code = MagicMock(
        return_value={
            "success": True,
            "value": {
                "model": "woocommerce.order",
                "attributes": ["string", "type", "modules"],
                "field_names": [
                    "id",
                    "name",
                    "woo_field_a",
                    "woo_field_b",
                ],
                "field_definitions": {
                    "id": {
                        "string": "ID",
                        "type": "integer",
                        "modules": "base",
                    },
                    "name": {
                        "string": "Name",
                        "type": "char",
                        "modules": "base,sale",
                    },
                    "woo_field_a": {
                        "string": "Woo A",
                        "type": "char",
                        "modules": "base,fastapi_newcustomer_shop",
                    },
                    "woo_field_b": {
                        "string": "Woo B",
                        "type": "selection",
                        "modules": "fastapi_newcustomer_shop",
                    },
                },
            },
            "output": "",
            "error": "",
            "traceback": "",
        }
    )

    result = query.get_model_fields(
        "woocommerce.order",
        attributes=["string", "type"],
        module="fastapi_newcustomer_shop",
    )

    assert result["success"] is True
    assert result["module"] == "fastapi_newcustomer_shop"
    assert result["field_names"] == ["woo_field_a", "woo_field_b"]
    assert "woo_field_a" in result["field_definitions"]
    assert "woo_field_b" in result["field_definitions"]
    assert "id" not in result["field_definitions"]
    assert "name" not in result["field_definitions"]


def test_get_model_fields_module_filter_no_match() -> None:
    query = _query()
    query._executor._execute_generated_code = MagicMock(
        return_value={
            "success": True,
            "value": {
                "model": "res.partner",
                "attributes": ["string", "type", "modules"],
                "field_names": ["id", "name"],
                "field_definitions": {
                    "id": {
                        "string": "ID",
                        "type": "integer",
                        "modules": "base",
                    },
                    "name": {
                        "string": "Name",
                        "type": "char",
                        "modules": "base",
                    },
                },
            },
            "output": "",
            "error": "",
            "traceback": "",
        }
    )

    result = query.get_model_fields(
        "res.partner",
        attributes=["string", "type"],
        module="nonexistent_module",
    )

    assert result["success"] is True
    assert result["module"] == "nonexistent_module"
    assert result["field_names"] == []
    assert result["field_definitions"] == {}


def test_get_model_fields_module_adds_modules_attribute() -> None:
    query = _query()
    query._executor._execute_generated_code = MagicMock(
        return_value={
            "success": True,
            "value": {
                "model": "res.partner",
                "attributes": ["string", "modules"],
                "field_names": ["name"],
                "field_definitions": {
                    "name": {
                        "string": "Name",
                        "modules": "base",
                    },
                },
            },
            "output": "",
            "error": "",
            "traceback": "",
        }
    )

    result = query.get_model_fields(
        "res.partner",
        attributes=["string"],
        module="base",
    )

    assert result["success"] is True
    call_args = query._executor._execute_generated_code.call_args
    generated_code = call_args[0][0]
    assert "modules" in generated_code
    assert result["field_names"] == ["name"]


def test_get_model_fields_without_module_no_filtering() -> None:
    query = _query()
    query._executor._execute_generated_code = MagicMock(
        return_value={
            "success": True,
            "value": {
                "model": "res.partner",
                "attributes": ["string", "type"],
                "field_names": ["id", "name"],
                "field_definitions": {
                    "id": {"string": "ID", "type": "integer"},
                    "name": {"string": "Name", "type": "char"},
                },
            },
            "output": "",
            "error": "",
            "traceback": "",
        }
    )

    result = query.get_model_fields("res.partner", attributes=["string", "type"])

    assert result["success"] is True
    assert result.get("module") is None
    assert result["field_names"] == ["id", "name"]
    assert len(result["field_definitions"]) == 2
