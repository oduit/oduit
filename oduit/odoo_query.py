# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Safe read-only query helpers built on top of OdooCodeExecutor."""

import re
from typing import Any

from .config_provider import ConfigProvider
from .odoo_code_executor import OdooCodeExecutor

MAX_QUERY_LIMIT = 500


class OdooQuery:
    """Run structured read-only queries against an Odoo environment.

    This API is intended for common read-heavy tasks where callers should not
    need to pass arbitrary Python code strings. It validates structured input,
    generates minimal trusted code internally, and relies on the executor's
    default rollback behavior.
    """

    _MODEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
    _NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def __init__(self, config: ConfigProvider | dict[str, Any]):
        if isinstance(config, ConfigProvider):
            self.config_provider = config
        else:
            self.config_provider = ConfigProvider(config)

        self._executor = OdooCodeExecutor(self.config_provider)

    def query_model(
        self,
        model: str,
        domain: list[Any] | tuple[Any, ...] | None = None,
        fields: list[str] | tuple[str, ...] | None = None,
        limit: int = 80,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Search records and return read data for the matched result set."""
        validation_error = self._validate_common_inputs(
            model=model,
            domain=domain,
            database=database,
            operation="query_model",
        )
        if validation_error:
            return validation_error

        validated_fields, fields_error = self._validate_name_list(fields, "fields")
        if fields_error:
            return self._validation_error("query_model", fields_error, model=model)

        validated_limit, limit_error = self._validate_limit(limit)
        if limit_error:
            return self._validation_error("query_model", limit_error, model=model)

        query_code = self._build_query_model_code(
            model=model,
            domain=list(domain or []),
            fields=validated_fields,
            limit=validated_limit,
        )
        result = self._executor._execute_generated_code(
            query_code,
            database=database,
            commit=False,
            timeout=timeout,
        )
        return self._finalize_result(
            "query_model",
            result,
            model=model,
            domain=list(domain or []),
            fields=validated_fields,
            limit=validated_limit,
            database=database,
        )

    def read_record(
        self,
        model: str,
        record_id: int,
        fields: list[str] | tuple[str, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Read one record by id."""
        validation_error = self._validate_common_inputs(
            model=model,
            domain=[],
            database=database,
            operation="read_record",
        )
        if validation_error:
            return validation_error

        if (
            isinstance(record_id, bool)
            or not isinstance(record_id, int)
            or record_id <= 0
        ):
            return self._validation_error(
                "read_record",
                "record_id must be a positive integer",
                model=model,
                record_id=record_id,
            )

        validated_fields, fields_error = self._validate_name_list(fields, "fields")
        if fields_error:
            return self._validation_error(
                "read_record",
                fields_error,
                model=model,
                record_id=record_id,
            )

        query_code = self._build_read_record_code(
            model=model,
            record_id=record_id,
            fields=validated_fields,
        )
        result = self._executor._execute_generated_code(
            query_code,
            database=database,
            commit=False,
            timeout=timeout,
        )
        return self._finalize_result(
            "read_record",
            result,
            model=model,
            record_id=record_id,
            fields=validated_fields,
            database=database,
        )

    def search_count(
        self,
        model: str,
        domain: list[Any] | tuple[Any, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Return the number of records matching a domain."""
        validation_error = self._validate_common_inputs(
            model=model,
            domain=domain,
            database=database,
            operation="search_count",
        )
        if validation_error:
            return validation_error

        query_code = self._build_search_count_code(
            model=model, domain=list(domain or [])
        )
        result = self._executor._execute_generated_code(
            query_code,
            database=database,
            commit=False,
            timeout=timeout,
        )
        return self._finalize_result(
            "search_count",
            result,
            model=model,
            domain=list(domain or []),
            database=database,
        )

    def get_model_fields(
        self,
        model: str,
        attributes: list[str] | tuple[str, ...] | None = None,
        module: str | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Inspect field metadata for a model via ``fields_get``."""
        validation_error = self._validate_common_inputs(
            model=model,
            domain=[],
            database=database,
            operation="get_model_fields",
        )
        if validation_error:
            return validation_error

        validated_attributes, attributes_error = self._validate_name_list(
            attributes,
            "attributes",
        )
        if attributes_error:
            return self._validation_error(
                "get_model_fields",
                attributes_error,
                model=model,
            )

        query_attributes = (
            list(validated_attributes) if validated_attributes is not None else []
        )
        if module is not None and "modules" not in query_attributes:
            query_attributes.append("modules")

        query_code = self._build_get_model_fields_code(model, query_attributes or None)
        result = self._executor._execute_generated_code(
            query_code,
            database=database,
            commit=False,
            timeout=timeout,
        )
        final = self._finalize_result(
            "get_model_fields",
            result,
            model=model,
            attributes=validated_attributes,
            database=database,
        )

        if module is not None and final.get("success"):
            final = self._apply_module_filter(final, module)

        return final

    @staticmethod
    def _apply_module_filter(result: dict[str, Any], module: str) -> dict[str, Any]:
        field_definitions = result.get("field_definitions", {})
        filtered: dict[str, dict[str, Any]] = {}
        for field_name, field_def in field_definitions.items():
            modules_raw = field_def.get("modules", "")
            if not isinstance(modules_raw, str):
                continue
            modules_set = {m.strip() for m in modules_raw.split(",") if m.strip()}
            if module in modules_set:
                filtered[field_name] = field_def

        result["field_definitions"] = filtered
        result["field_names"] = sorted(filtered.keys())
        result["module"] = module
        return result

    def _validate_common_inputs(
        self,
        model: str,
        domain: list[Any] | tuple[Any, ...] | None,
        database: str | None,
        operation: str,
    ) -> dict[str, Any] | None:
        model_error = self._validate_model(model)
        if model_error:
            return self._validation_error(operation, model_error, model=model)

        domain_error = self._validate_domain(domain)
        if domain_error:
            return self._validation_error(operation, domain_error, model=model)

        database_error = self._validate_database(database)
        if database_error:
            return self._validation_error(operation, database_error, model=model)

        return None

    def _validate_model(self, model: str) -> str | None:
        if not isinstance(model, str) or not model.strip():
            return "model must be a non-empty string"
        if not self._MODEL_RE.match(model):
            return "model contains invalid characters"
        return None

    def _validate_name_list(
        self,
        values: object | None,
        field_name: str,
    ) -> tuple[list[str] | None, str | None]:
        if values is None:
            return None, None
        if not isinstance(values, list | tuple):
            return None, f"{field_name} must be a list of strings"

        validated_values: list[str] = []
        for value in values:
            if not isinstance(value, str) or not self._NAME_RE.match(value):
                return None, f"{field_name} must contain only valid string identifiers"
            validated_values.append(value)

        return validated_values, None

    def _validate_limit(self, limit: int) -> tuple[int, str | None]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            return 0, "limit must be an integer"
        if limit <= 0:
            return 0, "limit must be greater than zero"
        if limit > MAX_QUERY_LIMIT:
            return 0, f"limit must be less than or equal to {MAX_QUERY_LIMIT}"
        return limit, None

    def _validate_database(self, database: str | None) -> str | None:
        if database is None:
            return None
        if not isinstance(database, str) or not database.strip():
            return "database must be a non-empty string when provided"
        return None

    def _validate_domain(self, domain: object | None) -> str | None:
        if domain is None:
            return None
        if not isinstance(domain, list | tuple):
            return "domain must be a list or tuple"
        if not self._is_safe_literal(domain):
            return "domain must contain only literal-safe values"
        return None

    def _is_safe_literal(self, value: Any) -> bool:
        if isinstance(value, str | int | float | bool) or value is None:
            return True
        if isinstance(value, list | tuple):
            return all(self._is_safe_literal(item) for item in value)
        if isinstance(value, dict):
            return all(
                isinstance(key, str) and self._is_safe_literal(item)
                for key, item in value.items()
            )
        return False

    def _validation_error(
        self,
        operation: str,
        message: str,
        **details: Any,
    ) -> dict[str, Any]:
        result = {
            "success": False,
            "operation": operation,
            "error": message,
            "error_type": "ValidationError",
        }
        for key, value in details.items():
            if value is not None:
                result[key] = value
        return result

    def _finalize_result(
        self,
        operation: str,
        result: dict[str, Any],
        **metadata: Any,
    ) -> dict[str, Any]:
        final_result = result.copy()
        final_result["operation"] = operation

        for key, value in metadata.items():
            if value is not None:
                final_result[key] = value

        if final_result.get("success") and isinstance(final_result.get("value"), dict):
            final_result.update(final_result["value"])

        return final_result

    def _build_query_model_code(
        self,
        model: str,
        domain: list[Any],
        fields: list[str] | None,
        limit: int,
    ) -> str:
        return "\n".join(
            [
                f"_oduit_model = env[{model!r}]",
                f"_oduit_domain = {domain!r}",
                f"_oduit_fields = {fields!r}",
                f"_oduit_records = _oduit_model.search(_oduit_domain, limit={limit})",
                "_oduit_rows = _oduit_records.read(_oduit_fields) "
                "if _oduit_fields is not None else _oduit_records.read()",
                "{",
                f"    'model': {model!r},",
                "    'count': len(_oduit_records),",
                "    'ids': _oduit_records.ids,",
                "    'records': _oduit_rows,",
                "    'fields': _oduit_fields,",
                f"    'limit': {limit},",
                "}",
            ]
        )

    def _build_read_record_code(
        self,
        model: str,
        record_id: int,
        fields: list[str] | None,
    ) -> str:
        return "\n".join(
            [
                f"_oduit_model = env[{model!r}]",
                f"_oduit_fields = {fields!r}",
                f"_oduit_record = _oduit_model.browse({record_id}).exists()",
                "_oduit_row = (",
                "    _oduit_record.read(_oduit_fields)[0]",
                "    if _oduit_record and _oduit_fields is not None",
                "    else (_oduit_record.read()[0] if _oduit_record else None)",
                ")",
                "{",
                f"    'model': {model!r},",
                f"    'record_id': {record_id},",
                "    'found': bool(_oduit_record),",
                "    'record': _oduit_row,",
                "    'fields': _oduit_fields,",
                "}",
            ]
        )

    def _build_search_count_code(self, model: str, domain: list[Any]) -> str:
        return "\n".join(
            [
                f"_oduit_model = env[{model!r}]",
                f"_oduit_domain = {domain!r}",
                "{",
                f"    'model': {model!r},",
                "    'domain': _oduit_domain,",
                "    'count': _oduit_model.search_count(_oduit_domain),",
                "}",
            ]
        )

    def _build_get_model_fields_code(
        self,
        model: str,
        attributes: list[str] | None,
    ) -> str:
        return "\n".join(
            [
                f"_oduit_model = env[{model!r}]",
                f"_oduit_attributes = {attributes!r}",
                "_oduit_field_definitions = "
                "_oduit_model.fields_get(attributes=_oduit_attributes)",
                "{",
                f"    'model': {model!r},",
                "    'attributes': _oduit_attributes,",
                "    'field_names': sorted(_oduit_field_definitions.keys()),",
                "    'field_definitions': _oduit_field_definitions,",
                "}",
            ]
        )
