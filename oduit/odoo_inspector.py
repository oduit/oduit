# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Structured runtime inspection helpers built on top of OdooCodeExecutor."""

from __future__ import annotations

import re
from textwrap import dedent
from typing import Any

from .config_provider import ConfigProvider
from .odoo_code_executor import OdooCodeExecutor
from .odoo_query import OdooQuery
from .schemas import (
    CONTROLLED_RUNTIME_MUTATION,
    SAFE_READ_ONLY,
    UNSAFE_ARBITRARY_EXECUTION,
)


class OdooInspector:
    """Expose structured Odoo inspection workflows for CLI and Python callers."""

    _MODEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
    _NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    _XMLID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_.]*$")

    def __init__(self, config: ConfigProvider | dict[str, Any]):
        if isinstance(config, ConfigProvider):
            self.config_provider = config
        else:
            self.config_provider = ConfigProvider(config)

        self._query = OdooQuery(self.config_provider)
        self._executor = OdooCodeExecutor(self.config_provider)

    def execute_code(
        self,
        code: str,
        *,
        database: str | None = None,
        commit: bool = False,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Execute trusted arbitrary Python within Odoo via the embedded runtime."""
        if not isinstance(code, str) or not code.strip():
            return self._validation_error(
                "execute_code",
                "code must be a non-empty string",
                read_only=False,
                safety_level=UNSAFE_ARBITRARY_EXECUTION,
            )

        database_error = self._validate_database(database)
        if database_error:
            return self._validation_error(
                "execute_code",
                database_error,
                database=database,
                read_only=False,
                safety_level=UNSAFE_ARBITRARY_EXECUTION,
            )

        timeout_value, timeout_error = self._validate_timeout(timeout)
        if timeout_error:
            return self._validation_error(
                "execute_code",
                timeout_error,
                database=database,
                read_only=False,
                safety_level=UNSAFE_ARBITRARY_EXECUTION,
            )

        result = self._executor.execute_code(
            code,
            database=database,
            commit=commit,
            timeout=timeout_value,
            allow_unsafe=True,
        )
        return self._finalize_result(
            "execute_code",
            result,
            database=database,
            commit=commit,
            read_only=False,
            safety_level=UNSAFE_ARBITRARY_EXECUTION,
        )

    def inspect_ref(
        self,
        xmlid: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Resolve one XMLID and return stable record metadata."""
        xmlid_error = self._validate_xmlid(xmlid)
        if xmlid_error:
            return self._validation_error("inspect_ref", xmlid_error, xmlid=xmlid)

        result = self._execute_generated(
            "inspect_ref",
            dedent(
                f"""
                _oduit_xmlid = {xmlid!r}
                try:
                    _oduit_record = env.ref(_oduit_xmlid)
                except ValueError:
                    _oduit_result = {{
                        "xmlid": _oduit_xmlid,
                        "exists": False,
                        "model": None,
                        "res_id": None,
                        "display_name": None,
                    }}
                else:
                    _oduit_result = {{
                        "xmlid": _oduit_xmlid,
                        "exists": True,
                        "model": _oduit_record._name,
                        "res_id": _oduit_record.id,
                        "display_name": getattr(
                            _oduit_record,
                            "display_name",
                            str(_oduit_record),
                        ),
                    }}
                _oduit_result
                """
            ).strip(),
            database=database,
            timeout=timeout,
            xmlid=xmlid,
        )
        return self._require_exists(
            result,
            field_name="xmlid",
            value=xmlid,
            message=f"XMLID {xmlid!r} was not found",
        )

    def inspect_cron(
        self,
        xmlid: str,
        *,
        trigger: bool = False,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Inspect one cron job and optionally trigger it."""
        xmlid_error = self._validate_xmlid(xmlid)
        if xmlid_error:
            return self._validation_error(
                "inspect_cron",
                xmlid_error,
                xmlid=xmlid,
                read_only=not trigger,
                safety_level=(
                    SAFE_READ_ONLY if not trigger else CONTROLLED_RUNTIME_MUTATION
                ),
            )

        result = self._execute_generated(
            "inspect_cron",
            dedent(
                f"""
                _oduit_xmlid = {xmlid!r}
                _oduit_trigger = {trigger!r}
                try:
                    _oduit_record = env.ref(_oduit_xmlid)
                except ValueError:
                    _oduit_result = {{
                        "xmlid": _oduit_xmlid,
                        "exists": False,
                        "is_cron": False,
                        "trigger_requested": _oduit_trigger,
                        "triggered": False,
                    }}
                else:
                    _oduit_is_cron = _oduit_record._name == "ir.cron"
                    _oduit_result = {{
                        "xmlid": _oduit_xmlid,
                        "exists": True,
                        "is_cron": _oduit_is_cron,
                        "model": _oduit_record._name,
                        "res_id": _oduit_record.id,
                        "name": getattr(_oduit_record, "name", None),
                        "active": bool(getattr(_oduit_record, "active", False)),
                        "interval_number": getattr(
                            _oduit_record,
                            "interval_number",
                            None,
                        ),
                        "interval_type": getattr(_oduit_record, "interval_type", None),
                        "numbercall": getattr(_oduit_record, "numbercall", None),
                        "doall": bool(getattr(_oduit_record, "doall", False)),
                        "user_id": (
                            [
                                getattr(_oduit_record.user_id, "id", None),
                                getattr(_oduit_record.user_id, "name", None),
                            ]
                            if getattr(_oduit_record, "user_id", None)
                            else None
                        ),
                        "nextcall": (
                            str(getattr(_oduit_record, "nextcall"))
                            if getattr(_oduit_record, "nextcall", None) else None
                        ),
                        "state": getattr(_oduit_record, "state", None),
                        "code": getattr(_oduit_record, "code", None),
                        "trigger_requested": _oduit_trigger,
                        "triggered": False,
                    }}
                    if _oduit_is_cron and _oduit_trigger:
                        _oduit_record.method_direct_trigger()
                        _oduit_result["triggered"] = True
                _oduit_result
                """
            ).strip(),
            database=database,
            timeout=timeout,
            commit=trigger,
            read_only=not trigger,
            safety_level=(
                SAFE_READ_ONLY if not trigger else CONTROLLED_RUNTIME_MUTATION
            ),
            xmlid=xmlid,
            trigger_requested=trigger,
        )
        result = self._require_exists(
            result,
            field_name="xmlid",
            value=xmlid,
            message=f"Cron XMLID {xmlid!r} was not found",
        )
        if result.get("success") and not result.get("is_cron", False):
            result["success"] = False
            result["error"] = f"XMLID {xmlid!r} does not reference an ir.cron record"
            result["error_type"] = "ValidationError"
        return result

    def inspect_modules(
        self,
        *,
        state: str | None = None,
        names_only: bool = False,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """List runtime addon inventory from ``ir.module.module``."""
        state_filter: list[str] | None = None
        if state is not None:
            name_error = self._validate_name(state, "state")
            if name_error:
                return self._validation_error(
                    "inspect_modules",
                    name_error,
                    state=state,
                )
            state_filter = [state]

        result = self._query.query_model(
            "ir.module.module",
            domain=[["state", "in", state_filter]] if state_filter else [],
            fields=["name", "state", "shortdesc", "application", "auto_install"],
            limit=500,
            database=database,
            timeout=timeout,
        )
        final_result = self._finalize_result(
            "inspect_modules",
            result,
            database=database,
            state=state,
            names_only=names_only,
        )
        if not final_result.get("success"):
            return final_result

        modules = sorted(
            [
                {
                    "name": str(record.get("name", "")),
                    "state": str(record.get("state", "")),
                    "shortdesc": record.get("shortdesc"),
                    "application": self._normalize_optional_bool(
                        record.get("application")
                    ),
                    "auto_install": self._normalize_optional_bool(
                        record.get("auto_install")
                    ),
                }
                for record in final_result.get("records", [])
                if record.get("name")
            ],
            key=lambda record: record["name"],
        )
        final_result["modules"] = modules
        final_result["names"] = [record["name"] for record in modules]
        final_result["total"] = len(modules)
        return final_result

    def inspect_subtypes(
        self,
        model: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """List ``mail.message.subtype`` records for one model."""
        model_error = self._validate_model(model)
        if model_error:
            return self._validation_error("inspect_subtypes", model_error, model=model)

        result = self._query.query_model(
            "mail.message.subtype",
            domain=[["res_model", "=", model]],
            fields=[
                "name",
                "description",
                "default",
                "internal",
                "hidden",
                "sequence",
                "parent_id",
                "relation_field",
                "res_model",
            ],
            limit=500,
            database=database,
            timeout=timeout,
        )
        final_result = self._finalize_result(
            "inspect_subtypes",
            result,
            database=database,
            model=model,
        )
        if not final_result.get("success"):
            return final_result

        subtypes = sorted(
            final_result.get("records", []),
            key=lambda record: (
                int(record.get("sequence", 0) or 0),
                str(record.get("name", "")),
            ),
        )
        final_result["subtypes"] = subtypes
        final_result["total"] = len(subtypes)
        return final_result

    def inspect_model(
        self,
        model: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Inspect model registration metadata."""
        model_error = self._validate_model(model)
        if model_error:
            return self._validation_error("inspect_model", model_error, model=model)

        result = self._execute_generated(
            "inspect_model",
            dedent(
                f"""
                _oduit_model_name = {model!r}
                _oduit_model_class = registry.models.get(_oduit_model_name)
                if _oduit_model_class is None:
                    _oduit_result = {{
                        "model": _oduit_model_name,
                        "exists": False,
                    }}
                else:
                    _oduit_model = env[_oduit_model_name]
                    _oduit_inherits = getattr(_oduit_model, "_inherits", {{}})
                    _oduit_fields = getattr(_oduit_model, "_fields", {{}})
                    _oduit_inherit = getattr(_oduit_model, "_inherit", None)
                    if isinstance(_oduit_inherit, (list, tuple)):
                        _oduit_inherit_list = list(_oduit_inherit)
                    elif _oduit_inherit:
                        _oduit_inherit_list = [_oduit_inherit]
                    else:
                        _oduit_inherit_list = []
                    _oduit_result = {{
                        "model": _oduit_model_name,
                        "exists": True,
                        "registered_name": getattr(
                            _oduit_model,
                            "_name",
                            _oduit_model_name,
                        ),
                        "table": getattr(_oduit_model, "_table", None),
                        "transient": bool(getattr(_oduit_model, "_transient", False)),
                        "abstract": bool(getattr(_oduit_model, "_abstract", False)),
                        "auto": bool(getattr(_oduit_model, "_auto", True)),
                        "rec_name": getattr(_oduit_model, "_rec_name", None),
                        "inherit": _oduit_inherit_list,
                        "inherits": sorted(_oduit_inherits.keys()),
                        "field_count": len(_oduit_fields),
                        "field_names": sorted(_oduit_fields.keys()),
                    }}
                _oduit_result
                """
            ).strip(),
            database=database,
            timeout=timeout,
            model=model,
        )
        return self._require_exists(
            result,
            field_name="model",
            value=model,
            message=f"Model {model!r} is not registered in the active Odoo runtime",
        )

    def inspect_field(
        self,
        model: str,
        field: str,
        *,
        with_db: bool = False,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Inspect one ORM field, optionally including DB-level metadata."""
        model_error = self._validate_model(model)
        if model_error:
            return self._validation_error(
                "inspect_field",
                model_error,
                model=model,
                field=field,
            )

        field_error = self._validate_name(field, "field")
        if field_error:
            return self._validation_error(
                "inspect_field",
                field_error,
                model=model,
                field=field,
            )

        result = self._execute_generated(
            "inspect_field",
            dedent(
                f"""
                _oduit_model_name = {model!r}
                _oduit_field_name = {field!r}
                _oduit_with_db = {with_db!r}
                _oduit_model_class = registry.models.get(_oduit_model_name)
                if _oduit_model_class is None:
                    _oduit_result = {{
                        "model": _oduit_model_name,
                        "field": _oduit_field_name,
                        "model_exists": False,
                        "exists": False,
                    }}
                else:
                    _oduit_model = env[_oduit_model_name]
                    _oduit_fields = getattr(_oduit_model, "_fields", {{}})
                    _oduit_field = _oduit_fields.get(_oduit_field_name)
                    if _oduit_field is None:
                        _oduit_result = {{
                            "model": _oduit_model_name,
                            "field": _oduit_field_name,
                            "model_exists": True,
                            "exists": False,
                        }}
                    else:
                        _oduit_field_type = getattr(_oduit_field, "type", None)
                        _oduit_field_relation = getattr(_oduit_field, "relation", None)
                        _oduit_selection = getattr(_oduit_field, "selection", None)
                        if callable(_oduit_selection):
                            _oduit_selection = None
                        _oduit_related = (
                            list(getattr(_oduit_field, "related", []) or []) or None
                        )
                        _oduit_selection_list = (
                            list(_oduit_selection)
                            if isinstance(_oduit_selection, (list, tuple))
                            else None
                        )
                        _oduit_model_table = getattr(_oduit_model, "_table", None)
                        _oduit_result = {{
                            "model": _oduit_model_name,
                            "field": _oduit_field_name,
                            "model_exists": True,
                            "exists": True,
                            "field_type": _oduit_field_type,
                            "relation": _oduit_field_relation,
                            "comodel_name": getattr(_oduit_field, "comodel_name", None),
                            "required": bool(getattr(_oduit_field, "required", False)),
                            "readonly": bool(getattr(_oduit_field, "readonly", False)),
                            "store": bool(getattr(_oduit_field, "store", False)),
                            "index": bool(getattr(_oduit_field, "index", False)),
                            "translate": bool(
                                getattr(_oduit_field, "translate", False)
                            ),
                            "company_dependent": bool(
                                getattr(_oduit_field, "company_dependent", False)
                            ),
                            "compute": getattr(_oduit_field, "compute", None),
                            "inverse": getattr(_oduit_field, "inverse", None),
                            "related": _oduit_related,
                            "selection": _oduit_selection_list,
                            "db_table_name": _oduit_model_table,
                            "db_column_name": None,
                            "db_column_found": None,
                            "db_column_type": None,
                            "db_data_type": None,
                            "db_nullable": None,
                            "m2m_relation_table": (
                                _oduit_field_relation
                                if _oduit_field_type == "many2many"
                                else None
                            ),
                            "m2m_column1": getattr(_oduit_field, "column1", None),
                            "m2m_column2": getattr(_oduit_field, "column2", None),
                            "relation_table_exists": None,
                        }}
                        if _oduit_with_db and bool(
                            getattr(_oduit_model, "_auto", True)
                        ):
                            if _oduit_field_type == "many2many":
                                if _oduit_field_relation:
                                    cr.execute(
                                        "SELECT EXISTS("
                                        "SELECT 1 FROM information_schema.tables "
                                        "WHERE table_schema = 'public' "
                                        "AND table_name = %s"
                                        ")",
                                        (_oduit_field_relation,),
                                    )
                                    _oduit_result["relation_table_exists"] = bool(
                                        (cr.fetchone() or [False])[0]
                                    )
                            elif bool(getattr(_oduit_field, "store", False)):
                                _oduit_column_name = (
                                    getattr(_oduit_field, "column", None)
                                    or _oduit_field_name
                                )
                                _oduit_result["db_column_name"] = _oduit_column_name
                                cr.execute(
                                    '''
                                    SELECT data_type, udt_name, is_nullable
                                    FROM information_schema.columns
                                    WHERE table_schema = 'public'
                                      AND table_name = %s
                                      AND column_name = %s
                                    ''',
                                    (_oduit_model_table, _oduit_column_name),
                                )
                                _oduit_column_row = cr.fetchone()
                                _oduit_result["db_column_found"] = bool(
                                    _oduit_column_row
                                )
                                if _oduit_column_row:
                                    _oduit_result["db_data_type"] = _oduit_column_row[0]
                                    _oduit_result["db_column_type"] = (
                                        _oduit_column_row[1]
                                    )
                                    _oduit_result["db_nullable"] = (
                                        _oduit_column_row[2] == "YES"
                                    )
                _oduit_result
                """
            ).strip(),
            database=database,
            timeout=timeout,
            model=model,
            field=field,
            with_db=with_db,
        )
        result = self._require_exists(
            result,
            field_name="model",
            value=model,
            exists_field="model_exists",
            message=f"Model {model!r} is not registered in the active Odoo runtime",
        )
        if result.get("success") and not result.get("exists", False):
            result["success"] = False
            result["error"] = f"Field {field!r} was not found on model {model!r}"
            result["error_type"] = "NotFoundError"
        return result

    def inspect_recordset(
        self,
        expression: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Execute a trusted recordset expression as an escape hatch."""
        result = self.execute_code(
            expression,
            database=database,
            commit=False,
            timeout=timeout,
        )
        result["operation"] = "inspect_recordset"
        result["expression"] = expression
        return result

    def describe_table(
        self,
        table_name: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Describe columns for one PostgreSQL table."""
        table_error = self._validate_name(table_name, "table_name")
        if table_error:
            return self._validation_error(
                "describe_table",
                table_error,
                table_name=table_name,
            )

        result = self._execute_generated(
            "describe_table",
            dedent(
                f"""
                _oduit_table_name = {table_name!r}
                cr.execute(
                    '''
                    SELECT
                        column_name,
                        data_type,
                        udt_name,
                        is_nullable,
                        column_default,
                        ordinal_position
                    FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = %s
                    ORDER BY ordinal_position
                    ''',
                    (_oduit_table_name,),
                )
                _oduit_rows = cr.fetchall()
                _oduit_result = {{
                    "table_name": _oduit_table_name,
                    "exists": bool(_oduit_rows),
                    "columns": [
                        {{
                            "column_name": row[0],
                            "data_type": row[1],
                            "udt_name": row[2],
                            "nullable": row[3] == "YES",
                            "default": row[4],
                            "ordinal_position": row[5],
                        }}
                        for row in _oduit_rows
                    ],
                    "column_count": len(_oduit_rows),
                }}
                _oduit_result
                """
            ).strip(),
            database=database,
            timeout=timeout,
            table_name=table_name,
        )
        return self._require_exists(
            result,
            field_name="table_name",
            value=table_name,
            message=f"Table {table_name!r} was not found",
        )

    def describe_column(
        self,
        table_name: str,
        column_name: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Describe one PostgreSQL column."""
        table_error = self._validate_name(table_name, "table_name")
        if table_error:
            return self._validation_error(
                "describe_column",
                table_error,
                table_name=table_name,
                column_name=column_name,
            )
        column_error = self._validate_name(column_name, "column_name")
        if column_error:
            return self._validation_error(
                "describe_column",
                column_error,
                table_name=table_name,
                column_name=column_name,
            )

        result = self._execute_generated(
            "describe_column",
            dedent(
                f"""
                _oduit_table_name = {table_name!r}
                _oduit_column_name = {column_name!r}
                cr.execute(
                    '''
                    SELECT
                        data_type,
                        udt_name,
                        is_nullable,
                        column_default,
                        ordinal_position
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = %s
                      AND column_name = %s
                    ''',
                    (_oduit_table_name, _oduit_column_name),
                )
                _oduit_row = cr.fetchone()
                _oduit_result = {{
                    "table_name": _oduit_table_name,
                    "column_name": _oduit_column_name,
                    "exists": bool(_oduit_row),
                    "column": (
                        {{
                            "column_name": _oduit_column_name,
                            "data_type": _oduit_row[0],
                            "udt_name": _oduit_row[1],
                            "nullable": _oduit_row[2] == "YES",
                            "default": _oduit_row[3],
                            "ordinal_position": _oduit_row[4],
                        }}
                        if _oduit_row else None
                    ),
                }}
                _oduit_result
                """
            ).strip(),
            database=database,
            timeout=timeout,
            table_name=table_name,
            column_name=column_name,
        )
        return self._require_exists(
            result,
            field_name="column_name",
            value=column_name,
            message=f"Column {column_name!r} was not found on table {table_name!r}",
        )

    def list_constraints(
        self,
        table_name: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """List PostgreSQL constraints for one table."""
        table_error = self._validate_name(table_name, "table_name")
        if table_error:
            return self._validation_error(
                "list_constraints",
                table_error,
                table_name=table_name,
            )

        result = self._execute_generated(
            "list_constraints",
            dedent(
                f"""
                _oduit_table_name = {table_name!r}
                cr.execute(
                    "SELECT EXISTS("
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'public' "
                    "AND table_name = %s"
                    ")",
                    (_oduit_table_name,),
                )
                _oduit_exists = bool((cr.fetchone() or [False])[0])
                cr.execute(
                    '''
                    SELECT c.conname, c.contype, pg_get_constraintdef(c.oid)
                    FROM pg_catalog.pg_constraint c
                    JOIN pg_catalog.pg_class t ON t.oid = c.conrelid
                    JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
                    WHERE n.nspname = 'public'
                      AND t.relname = %s
                    ORDER BY c.conname
                    ''',
                    (_oduit_table_name,),
                )
                _oduit_type_names = {{
                    "p": "primary_key",
                    "f": "foreign_key",
                    "u": "unique",
                    "c": "check",
                    "x": "exclusion",
                }}
                _oduit_rows = cr.fetchall()
                _oduit_result = {{
                    "table_name": _oduit_table_name,
                    "exists": _oduit_exists,
                    "constraints": [
                        {{
                            "name": row[0],
                            "constraint_type": _oduit_type_names.get(row[1], row[1]),
                            "definition": row[2],
                        }}
                        for row in _oduit_rows
                    ],
                    "total": len(_oduit_rows),
                }}
                _oduit_result
                """
            ).strip(),
            database=database,
            timeout=timeout,
            table_name=table_name,
        )
        return self._require_exists(
            result,
            field_name="table_name",
            value=table_name,
            message=f"Table {table_name!r} was not found",
        )

    def list_tables(
        self,
        pattern: str | None = None,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """List PostgreSQL tables, optionally filtered by an ILIKE pattern."""
        if pattern is not None and (
            not isinstance(pattern, str) or not pattern.strip()
        ):
            return self._validation_error(
                "list_tables",
                "pattern must be a non-empty string when provided",
                pattern=pattern,
            )

        result = self._execute_generated(
            "list_tables",
            dedent(
                f"""
                _oduit_pattern = {pattern!r}
                _oduit_like = f"%{{_oduit_pattern}}%" if _oduit_pattern else None
                _oduit_query = [
                    "SELECT table_name",
                    "FROM information_schema.tables",
                    "WHERE table_schema = 'public'",
                    "  AND table_type = 'BASE TABLE'",
                ]
                _oduit_params = []
                if _oduit_like is not None:
                    _oduit_query.append("  AND table_name ILIKE %s")
                    _oduit_params.append(_oduit_like)
                _oduit_query.append("ORDER BY table_name")
                cr.execute("\\n".join(_oduit_query), tuple(_oduit_params))
                _oduit_rows = cr.fetchall()
                {{
                    "pattern": _oduit_pattern,
                    "tables": [row[0] for row in _oduit_rows],
                    "total": len(_oduit_rows),
                }}
                """
            ).strip(),
            database=database,
            timeout=timeout,
            pattern=pattern,
        )
        return result

    def inspect_m2m(
        self,
        model: str,
        field: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Inspect Many2many relation-table metadata for one ORM field."""
        field_result = self.inspect_field(
            model,
            field,
            with_db=True,
            database=database,
            timeout=timeout,
        )
        final_result = self._finalize_result(
            "inspect_m2m",
            field_result,
            model=model,
            field=field,
            database=database,
        )
        if not final_result.get("success"):
            return final_result
        if final_result.get("field_type") != "many2many":
            final_result["success"] = False
            final_result["error"] = (
                f"Field {field!r} on model {model!r} is not a many2many field"
            )
            final_result["error_type"] = "ValidationError"
            return final_result

        final_result["relation_table"] = final_result.get("m2m_relation_table")
        final_result["column1"] = final_result.get("m2m_column1")
        final_result["column2"] = final_result.get("m2m_column2")
        return final_result

    def performance_table_scans(
        self,
        *,
        limit: int = 20,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Return tables with the highest sequential scan counts."""
        limit_value, limit_error = self._validate_limit(limit)
        if limit_error:
            return self._validation_error(
                "performance_table_scans",
                limit_error,
                limit=limit,
            )

        return self._execute_generated(
            "performance_table_scans",
            dedent(
                f"""
                _oduit_limit = {limit_value}
                cr.execute(
                    '''
                    SELECT relname, seq_scan, seq_tup_read, idx_scan, n_live_tup
                    FROM pg_stat_user_tables
                    ORDER BY seq_scan DESC, seq_tup_read DESC, relname ASC
                    LIMIT %s
                    ''',
                    (_oduit_limit,),
                )
                _oduit_rows = cr.fetchall()
                {{
                    "limit": _oduit_limit,
                    "tables": [
                        {{
                            "table_name": row[0],
                            "seq_scan": row[1],
                            "seq_tup_read": row[2],
                            "idx_scan": row[3],
                            "n_live_tup": row[4],
                        }}
                        for row in _oduit_rows
                    ],
                    "total": len(_oduit_rows),
                }}
                """
            ).strip(),
            database=database,
            timeout=timeout,
            limit=limit_value,
        )

    def performance_slow_queries(
        self,
        *,
        limit: int = 10,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Return the slowest statements from ``pg_stat_statements`` when available."""
        limit_value, limit_error = self._validate_limit(limit)
        if limit_error:
            return self._validation_error(
                "performance_slow_queries",
                limit_error,
                limit=limit,
            )

        return self._execute_generated(
            "performance_slow_queries",
            dedent(
                f"""
                _oduit_limit = {limit_value}
                cr.execute(
                    "SELECT EXISTS("
                    "SELECT 1 FROM pg_extension "
                    "WHERE extname = 'pg_stat_statements'"
                    ")"
                )
                _oduit_extension_available = bool((cr.fetchone() or [False])[0])
                _oduit_result = {{
                    "limit": _oduit_limit,
                    "extension_available": _oduit_extension_available,
                    "queries": [],
                    "total": 0,
                }}
                if _oduit_extension_available:
                    cr.execute(
                        '''
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_schema = 'public'
                          AND table_name = 'pg_stat_statements'
                        '''
                    )
                    _oduit_columns = {{row[0] for row in cr.fetchall()}}
                    _oduit_total_column = (
                        "total_exec_time"
                        if "total_exec_time" in _oduit_columns
                        else "total_time"
                    )
                    _oduit_mean_column = (
                        "mean_exec_time"
                        if "mean_exec_time" in _oduit_columns
                        else "mean_time"
                    )
                    _oduit_rows_column = "rows" if "rows" in _oduit_columns else None
                    _oduit_select_parts = [
                        "SELECT query, calls,",
                        _oduit_total_column + ",",
                        _oduit_mean_column,
                    ]
                    if _oduit_rows_column:
                        _oduit_select_parts.append(", " + _oduit_rows_column)
                    _oduit_query = "".join(_oduit_select_parts)
                    _oduit_query += (
                        " FROM pg_stat_statements"
                        " ORDER BY " + _oduit_total_column + " DESC"
                        " LIMIT %s"
                    )
                    cr.execute(_oduit_query, (_oduit_limit,))
                    _oduit_rows = cr.fetchall()
                    _oduit_result["queries"] = [
                        {{
                            "query": row[0],
                            "calls": row[1],
                            "total_time": row[2],
                            "mean_time": row[3],
                            "rows": row[4] if len(row) > 4 else None,
                        }}
                        for row in _oduit_rows
                    ]
                    _oduit_result["total"] = len(_oduit_rows)
                _oduit_result
                """
            ).strip(),
            database=database,
            timeout=timeout,
            limit=limit_value,
        )

    def performance_indexes(
        self,
        *,
        limit: int = 20,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Return simple table index-usage metrics."""
        limit_value, limit_error = self._validate_limit(limit)
        if limit_error:
            return self._validation_error(
                "performance_indexes",
                limit_error,
                limit=limit,
            )

        return self._execute_generated(
            "performance_indexes",
            dedent(
                f"""
                _oduit_limit = {limit_value}
                cr.execute(
                    '''
                    SELECT relname, seq_scan, idx_scan, idx_tup_fetch, n_live_tup
                    FROM pg_stat_user_tables
                    ORDER BY idx_scan ASC, seq_scan DESC, relname ASC
                    LIMIT %s
                    ''',
                    (_oduit_limit,),
                )
                _oduit_rows = cr.fetchall()
                {{
                    "limit": _oduit_limit,
                    "tables": [
                        {{
                            "table_name": row[0],
                            "seq_scan": row[1],
                            "idx_scan": row[2],
                            "idx_tup_fetch": row[3],
                            "n_live_tup": row[4],
                            "scan_balance": (
                                float(row[2]) / float(row[1] + row[2])
                                if (row[1] + row[2]) > 0 else None
                            ),
                        }}
                        for row in _oduit_rows
                    ],
                    "total": len(_oduit_rows),
                }}
                """
            ).strip(),
            database=database,
            timeout=timeout,
            limit=limit_value,
        )

    def _execute_generated(
        self,
        operation: str,
        code: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
        commit: bool = False,
        read_only: bool = True,
        safety_level: str = SAFE_READ_ONLY,
        **metadata: Any,
    ) -> dict[str, Any]:
        database_error = self._validate_database(database)
        if database_error:
            return self._validation_error(
                operation,
                database_error,
                read_only=read_only,
                safety_level=safety_level,
                **metadata,
            )

        timeout_value, timeout_error = self._validate_timeout(timeout)
        if timeout_error:
            return self._validation_error(
                operation,
                timeout_error,
                read_only=read_only,
                safety_level=safety_level,
                **metadata,
            )

        result = self._executor._execute_generated_code(
            code,
            database=database,
            commit=commit,
            timeout=timeout_value,
        )
        return self._finalize_result(
            operation,
            result,
            database=database,
            read_only=read_only,
            safety_level=safety_level,
            **metadata,
        )

    @staticmethod
    def _normalize_optional_bool(value: Any) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def _validation_error(
        self,
        operation: str,
        message: str,
        *,
        read_only: bool = True,
        safety_level: str = SAFE_READ_ONLY,
        **details: Any,
    ) -> dict[str, Any]:
        result = {
            "success": False,
            "operation": operation,
            "error": message,
            "error_type": "ValidationError",
            "read_only": read_only,
            "safety_level": safety_level,
        }
        for key, value in details.items():
            if value is not None:
                result[key] = value
        return result

    def _finalize_result(
        self,
        operation: str,
        result: dict[str, Any],
        *,
        read_only: bool = True,
        safety_level: str = SAFE_READ_ONLY,
        **metadata: Any,
    ) -> dict[str, Any]:
        final_result = result.copy()
        final_result["operation"] = operation
        final_result["read_only"] = read_only
        final_result["safety_level"] = safety_level

        for key, value in metadata.items():
            if value is not None:
                final_result[key] = value

        if final_result.get("success") and isinstance(final_result.get("value"), dict):
            final_result.update(final_result["value"])

        return final_result

    @staticmethod
    def _require_exists(
        result: dict[str, Any],
        *,
        field_name: str,
        value: str,
        message: str,
        exists_field: str = "exists",
    ) -> dict[str, Any]:
        if result.get("success") and not result.get(exists_field, False):
            result["success"] = False
            result["error"] = message
            result["error_type"] = "NotFoundError"
            result[field_name] = value
        return result

    def _validate_model(self, value: str) -> str | None:
        return self._validate_pattern(
            value,
            pattern=self._MODEL_RE,
            field_name="model",
            invalid_message="model contains invalid characters",
        )

    def _validate_name(self, value: str, field_name: str) -> str | None:
        return self._validate_pattern(
            value,
            pattern=self._NAME_RE,
            field_name=field_name,
            invalid_message=f"{field_name} contains invalid characters",
        )

    def _validate_xmlid(self, value: str) -> str | None:
        return self._validate_pattern(
            value,
            pattern=self._XMLID_RE,
            field_name="xmlid",
            invalid_message="xmlid must use the form module.record_name",
        )

    @staticmethod
    def _validate_pattern(
        value: str,
        *,
        pattern: re.Pattern[str],
        field_name: str,
        invalid_message: str,
    ) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return f"{field_name} must be a non-empty string"
        if not pattern.match(value):
            return invalid_message
        return None

    @staticmethod
    def _validate_database(database: str | None) -> str | None:
        if database is None:
            return None
        if not isinstance(database, str) or not database.strip():
            return "database must be a non-empty string when provided"
        return None

    @staticmethod
    def _validate_timeout(timeout: float) -> tuple[float, str | None]:
        if isinstance(timeout, bool) or not isinstance(timeout, int | float):
            return 0.0, "timeout must be a number"
        if timeout <= 0:
            return 0.0, "timeout must be greater than zero"
        return float(timeout), None

    @staticmethod
    def _validate_limit(limit: int) -> tuple[int, str | None]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            return 0, "limit must be an integer"
        if limit <= 0:
            return 0, "limit must be greater than zero"
        if limit > 500:
            return 0, "limit must be less than or equal to 500"
        return limit, None
