"""Registration helpers for inspection-oriented CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from ..cli_types import OutputFormat
from ..output import print_error, print_warning
from ..utils import output_result_to_json
from .manifest_support import build_manifest_result
from .runtime_context import AppRegistrationContext

EXEC_FILE_PATH_ARGUMENT = typer.Argument(help="Path to a trusted Python file")


def register_inspection_commands(context: AppRegistrationContext) -> None:  # noqa: C901
    """Register execution, inspection, DB, performance, and manifest commands."""

    app = context.app
    resolve_command_env_config_fn = context.runtime.resolve_command_env_config_fn
    build_odoo_operations_fn = context.runtime.build_odoo_operations_fn

    inspect_app = typer.Typer(help="Runtime model, field, XMLID, and module inspection")
    db_app = typer.Typer(help="Database inspection through the live Odoo connection")
    performance_app = typer.Typer(help="Read-only PostgreSQL performance inspection")
    manifest_app = typer.Typer(help="Manifest inspection and validation")

    app.add_typer(inspect_app, name="inspect")
    app.add_typer(db_app, name="db")
    app.add_typer(performance_app, name="performance")
    app.add_typer(manifest_app, name="manifest")

    def _emit_result(
        global_config: Any,
        result: dict[str, Any],
        *,
        result_type: str,
        text_renderer: Any,
    ) -> None:
        if global_config.format == OutputFormat.JSON:
            print(json.dumps(output_result_to_json(result, result_type=result_type)))
        else:
            if result.get("success"):
                text_renderer(result)
            else:
                print_error(result.get("error", "Command failed"))

        if not result.get("success"):
            raise typer.Exit(1) from None

    def _print_value(value: Any) -> None:
        if isinstance(value, str):
            print(value)
        elif isinstance(value, int | float) and not isinstance(value, bool):
            print(value)
        elif isinstance(value, bool):
            print("true" if value else "false")
        elif value is None:
            print("null")
        else:
            print(json.dumps(value, indent=2, sort_keys=True))

    def _print_pairs(result: dict[str, Any], keys: list[tuple[str, str]]) -> None:
        for key, label in keys:
            if key not in result:
                continue
            value = result.get(key)
            if value is None:
                continue
            if isinstance(value, dict | list):
                formatted = json.dumps(value, indent=2, sort_keys=True)
            else:
                formatted = str(value)
            print(f"{label}: {formatted}")

    def _render_exec_result(result: dict[str, Any], output_mode: str) -> None:
        output_text = result.get("output")
        value = result.get("value")
        if output_mode == "full":
            _print_pairs(
                result,
                [
                    ("database", "Database"),
                    ("commit", "Commit"),
                    ("success", "Success"),
                ],
            )
            if output_text:
                print("Output:")
                print(output_text.rstrip())
            if "value" in result:
                print("Value:")
                _print_value(value)
            return

        if value is not None:
            _print_value(value)
            return
        if output_text:
            print(output_text.rstrip())

    def _render_ref_result(result: dict[str, Any]) -> None:
        _print_pairs(
            result,
            [
                ("xmlid", "XMLID"),
                ("model", "Model"),
                ("res_id", "Record ID"),
                ("display_name", "Display name"),
            ],
        )

    def _render_modules_result(result: dict[str, Any], names_only: bool) -> None:
        modules = result.get("modules", [])
        if names_only:
            for module in result.get("names", []):
                print(module)
            return

        for module in modules:
            line = f"{module['name']} [{module['state']}]"
            shortdesc = module.get("shortdesc")
            if shortdesc:
                line = f"{line} - {shortdesc}"
            print(line)

    def _render_subtypes_result(result: dict[str, Any]) -> None:
        for subtype in result.get("subtypes", []):
            line = str(subtype.get("name", ""))
            relation_field = subtype.get("relation_field")
            if relation_field:
                line = f"{line} [{relation_field}]"
            print(line)

    def _render_model_result(result: dict[str, Any]) -> None:
        _print_pairs(
            result,
            [
                ("model", "Model"),
                ("registered_name", "Registered name"),
                ("table", "Table"),
                ("transient", "Transient"),
                ("abstract", "Abstract"),
                ("auto", "Auto"),
                ("rec_name", "Record name field"),
                ("inherit", "Inherit"),
                ("inherits", "Delegated inherits"),
                ("field_count", "Field count"),
            ],
        )

    def _render_field_result(result: dict[str, Any], with_db: bool) -> None:
        _print_pairs(
            result,
            [
                ("model", "Model"),
                ("field", "Field"),
                ("field_type", "Type"),
                ("comodel_name", "Comodel"),
                ("required", "Required"),
                ("readonly", "Readonly"),
                ("store", "Stored"),
                ("index", "Indexed"),
                ("translate", "Translatable"),
                ("company_dependent", "Company dependent"),
                ("compute", "Compute"),
                ("inverse", "Inverse"),
                ("related", "Related"),
                ("selection", "Selection"),
                ("m2m_relation_table", "M2M relation table"),
                ("m2m_column1", "M2M column1"),
                ("m2m_column2", "M2M column2"),
            ],
        )
        if with_db:
            _print_pairs(
                result,
                [
                    ("db_table_name", "DB table"),
                    ("db_column_name", "DB column"),
                    ("db_column_found", "DB column found"),
                    ("db_column_type", "DB column type"),
                    ("db_data_type", "DB data type"),
                    ("db_nullable", "DB nullable"),
                    ("relation_table_exists", "Relation table exists"),
                ],
            )

    def _render_recordset_result(result: dict[str, Any]) -> None:
        _render_exec_result(result, "value")

    def _render_table_result(result: dict[str, Any]) -> None:
        for column in result.get("columns", []):
            nullable = "NULL" if column.get("nullable") else "NOT NULL"
            default = column.get("default")
            default_suffix = f" default={default}" if default else ""
            print(
                f"{column['ordinal_position']:>2} {column['column_name']}: "
                f"{column['udt_name']} {nullable}{default_suffix}"
            )

    def _render_column_result(result: dict[str, Any]) -> None:
        column = result.get("column", {})
        _print_pairs(
            column,
            [
                ("column_name", "Column"),
                ("udt_name", "Type"),
                ("data_type", "Data type"),
                ("nullable", "Nullable"),
                ("default", "Default"),
                ("ordinal_position", "Ordinal position"),
            ],
        )

    def _render_constraints_result(result: dict[str, Any]) -> None:
        constraints = result.get("constraints", [])
        if not constraints:
            print(f"No constraints found for {result.get('table_name')}")
            return
        for constraint in constraints:
            print(
                f"{constraint['name']} [{constraint['constraint_type']}]: "
                f"{constraint['definition']}"
            )

    def _render_tables_result(result: dict[str, Any]) -> None:
        for table_name in result.get("tables", []):
            print(table_name)

    def _render_performance_records(
        result: dict[str, Any],
        *,
        key: str,
        fields: list[tuple[str, str]],
    ) -> None:
        records = result.get(key, [])
        if key == "queries" and not result.get("extension_available", True):
            print_warning("pg_stat_statements is not installed in the active database")
            return
        for record in records:
            line = ", ".join(
                f"{label}={record[field_name]}"
                for field_name, label in fields
                if record.get(field_name) is not None
            )
            print(line)

    @app.command(name="exec")
    def exec_command(
        ctx: typer.Context,
        code: str = typer.Argument(help="Trusted Python expression or code block"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        commit: bool = typer.Option(
            False, "--commit", help="Commit database changes made by the code"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
        output: str = typer.Option(
            "value",
            "--output",
            help="Choice between 'value' and 'full'",
            show_default=True,
        ),
    ) -> None:
        """Execute trusted Python within Odoo and return a structured result."""
        if output not in {"value", "full"}:
            print_error("output must be either 'value' or 'full'")
            raise typer.Exit(1) from None

        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.execute_code(
            code,
            database=database,
            commit=commit,
            timeout=timeout,
        )
        _emit_result(
            global_config,
            result,
            result_type="code_execution",
            text_renderer=lambda payload: _render_exec_result(payload, output),
        )

    @app.command(name="exec-file")
    def exec_file_command(
        ctx: typer.Context,
        file_path: Path = EXEC_FILE_PATH_ARGUMENT,
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        commit: bool = typer.Option(
            False, "--commit", help="Commit database changes made by the code"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
        output: str = typer.Option(
            "value",
            "--output",
            help="Choice between 'value' and 'full'",
            show_default=True,
        ),
    ) -> None:
        """Execute trusted Python from a file within Odoo."""
        if output not in {"value", "full"}:
            print_error("output must be either 'value' or 'full'")
            raise typer.Exit(1) from None
        if not file_path.exists() or not file_path.is_file():
            print_error(f"Python file {str(file_path)!r} was not found")
            raise typer.Exit(1) from None

        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.execute_code(
            file_path.read_text(),
            database=database,
            commit=commit,
            timeout=timeout,
        )
        result["file_path"] = str(file_path)
        _emit_result(
            global_config,
            result,
            result_type="code_execution",
            text_renderer=lambda payload: _render_exec_result(payload, output),
        )

    @inspect_app.command("ref")
    def inspect_ref_command(
        ctx: typer.Context,
        xmlid: str = typer.Argument(help="External identifier to resolve"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Resolve one XMLID in the active Odoo runtime."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.inspect_ref(xmlid, database=database, timeout=timeout)
        _emit_result(
            global_config,
            result,
            result_type="xmlid_inspection",
            text_renderer=_render_ref_result,
        )

    @inspect_app.command("cron")
    def inspect_cron_command(
        ctx: typer.Context,
        xmlid: str = typer.Argument(help="Cron XMLID to inspect"),
        trigger: bool = typer.Option(
            False, "--trigger", help="Trigger the cron after resolving it"
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect one cron job and optionally trigger it."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.inspect_cron(
            xmlid,
            trigger=trigger,
            database=database,
            timeout=timeout,
        )
        _emit_result(
            global_config,
            result,
            result_type="cron_inspection",
            text_renderer=lambda payload: _print_pairs(
                payload,
                [
                    ("xmlid", "XMLID"),
                    ("name", "Name"),
                    ("active", "Active"),
                    ("interval_number", "Interval"),
                    ("interval_type", "Interval type"),
                    ("nextcall", "Next call"),
                    ("triggered", "Triggered"),
                ],
            ),
        )

    @inspect_app.command("modules")
    def inspect_modules_command(
        ctx: typer.Context,
        state: str | None = typer.Option(
            None, "--state", help="Filter by module state"
        ),
        names_only: bool = typer.Option(
            False, "--names-only", help="Print only module names in text mode"
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect module records from ir.module.module."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.inspect_modules(
            state=state,
            names_only=names_only,
            database=database,
            timeout=timeout,
        )
        _emit_result(
            global_config,
            result,
            result_type="module_inspection",
            text_renderer=lambda payload: _render_modules_result(payload, names_only),
        )

    @inspect_app.command("subtypes")
    def inspect_subtypes_command(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect mail.message.subtype rows for one model."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.inspect_subtypes(model, database=database, timeout=timeout)
        _emit_result(
            global_config,
            result,
            result_type="subtype_inventory",
            text_renderer=_render_subtypes_result,
        )

    @inspect_app.command("model")
    def inspect_model_command(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect one registered model."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.inspect_model(model, database=database, timeout=timeout)
        _emit_result(
            global_config,
            result,
            result_type="model_inspection",
            text_renderer=_render_model_result,
        )

    @inspect_app.command("field")
    def inspect_field_command(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        field: str = typer.Argument(help="Field to inspect"),
        with_db: bool = typer.Option(
            False, "--with-db", help="Include database-level metadata when available"
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect one ORM field."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.inspect_field(
            model,
            field,
            with_db=with_db,
            database=database,
            timeout=timeout,
        )
        _emit_result(
            global_config,
            result,
            result_type="field_inspection",
            text_renderer=lambda payload: _render_field_result(payload, with_db),
        )

    @inspect_app.command("recordset")
    def inspect_recordset_command(
        ctx: typer.Context,
        expression: str = typer.Argument(
            help="Trusted recordset expression to execute"
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Execute a trusted recordset expression as an inspection escape hatch."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.inspect_recordset(expression, database=database, timeout=timeout)
        _emit_result(
            global_config,
            result,
            result_type="recordset_inspection",
            text_renderer=_render_recordset_result,
        )

    @db_app.command("table")
    def db_table_command(
        ctx: typer.Context,
        table_name: str = typer.Argument(help="Table to describe"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Describe one PostgreSQL table."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.describe_table(table_name, database=database, timeout=timeout)
        _emit_result(
            global_config,
            result,
            result_type="table_description",
            text_renderer=_render_table_result,
        )

    @db_app.command("column")
    def db_column_command(
        ctx: typer.Context,
        table_name: str = typer.Argument(help="Table to inspect"),
        column_name: str = typer.Argument(help="Column to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Describe one PostgreSQL column."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.describe_column(
            table_name,
            column_name,
            database=database,
            timeout=timeout,
        )
        _emit_result(
            global_config,
            result,
            result_type="column_description",
            text_renderer=_render_column_result,
        )

    @db_app.command("constraints")
    def db_constraints_command(
        ctx: typer.Context,
        table_name: str = typer.Argument(help="Table to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """List PostgreSQL constraints for one table."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.list_constraints(table_name, database=database, timeout=timeout)
        _emit_result(
            global_config,
            result,
            result_type="constraint_inventory",
            text_renderer=_render_constraints_result,
        )

    @db_app.command("tables")
    def db_tables_command(
        ctx: typer.Context,
        like: str | None = typer.Option(
            None, "--like", help="Filter table names with a case-insensitive pattern"
        ),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """List PostgreSQL tables."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.list_tables(like, database=database, timeout=timeout)
        _emit_result(
            global_config,
            result,
            result_type="table_inventory",
            text_renderer=_render_tables_result,
        )

    @db_app.command("m2m")
    def db_m2m_command(
        ctx: typer.Context,
        model: str = typer.Argument(help="Model to inspect"),
        field: str = typer.Argument(help="Many2many field to inspect"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Inspect the relation table behind a Many2many field."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.inspect_m2m(model, field, database=database, timeout=timeout)
        _emit_result(
            global_config,
            result,
            result_type="m2m_inspection",
            text_renderer=lambda payload: _print_pairs(
                payload,
                [
                    ("model", "Model"),
                    ("field", "Field"),
                    ("relation_table", "Relation table"),
                    ("column1", "Column1"),
                    ("column2", "Column2"),
                    ("relation_table_exists", "Relation table exists"),
                ],
            ),
        )

    @performance_app.command("slow-queries")
    def performance_slow_queries_command(
        ctx: typer.Context,
        limit: int = typer.Option(10, "--limit", help="Number of queries to show"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Read pg_stat_statements when the extension is available."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.performance_slow_queries(
            limit=limit,
            database=database,
            timeout=timeout,
        )
        _emit_result(
            global_config,
            result,
            result_type="slow_query_metrics",
            text_renderer=lambda payload: _render_performance_records(
                payload,
                key="queries",
                fields=[
                    ("calls", "calls"),
                    ("total_time", "total_ms"),
                    ("mean_time", "mean_ms"),
                ],
            ),
        )

    @performance_app.command("table-scans")
    def performance_table_scans_command(
        ctx: typer.Context,
        limit: int = typer.Option(20, "--limit", help="Number of tables to show"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Show tables with high sequential scan counts."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.performance_table_scans(
            limit=limit,
            database=database,
            timeout=timeout,
        )
        _emit_result(
            global_config,
            result,
            result_type="table_scan_metrics",
            text_renderer=lambda payload: _render_performance_records(
                payload,
                key="tables",
                fields=[
                    ("table_name", "table"),
                    ("seq_scan", "seq_scan"),
                    ("seq_tup_read", "seq_tup_read"),
                    ("idx_scan", "idx_scan"),
                ],
            ),
        )

    @performance_app.command("indexes")
    def performance_indexes_command(
        ctx: typer.Context,
        limit: int = typer.Option(20, "--limit", help="Number of tables to show"),
        database: str | None = typer.Option(
            None, "--database", help="Override the configured database"
        ),
        timeout: float = typer.Option(
            30.0, "--timeout", help="Execution timeout in seconds"
        ),
    ) -> None:
        """Show basic table index-usage metrics."""
        global_config, _ = resolve_command_env_config_fn(ctx)
        ops = build_odoo_operations_fn(global_config)
        result = ops.performance_indexes(
            limit=limit,
            database=database,
            timeout=timeout,
        )
        _emit_result(
            global_config,
            result,
            result_type="index_usage_metrics",
            text_renderer=lambda payload: _render_performance_records(
                payload,
                key="tables",
                fields=[
                    ("table_name", "table"),
                    ("seq_scan", "seq_scan"),
                    ("idx_scan", "idx_scan"),
                    ("scan_balance", "scan_balance"),
                ],
            ),
        )

    @manifest_app.command("check")
    def manifest_check_command(
        ctx: typer.Context,
        target: str = typer.Argument(help="Addon name or filesystem path"),
    ) -> None:
        """Validate a manifest file and report structural warnings."""
        global_config, env_config = resolve_command_env_config_fn(ctx)
        result, _ = build_manifest_result(target, env_config)

        def _render_manifest_check(payload: dict[str, Any]) -> None:
            if not payload.get("warnings"):
                print("Manifest is valid")
                return
            print("Manifest is valid with warnings")
            for warning in payload.get("warnings", []):
                print(f"- {warning}")

        _emit_result(
            global_config,
            result,
            result_type="manifest_validation",
            text_renderer=_render_manifest_check,
        )

    @manifest_app.command("show")
    def manifest_show_command(
        ctx: typer.Context,
        target: str = typer.Argument(help="Addon name or filesystem path"),
    ) -> None:
        """Show manifest metadata for an addon or addon path."""
        global_config, env_config = resolve_command_env_config_fn(ctx)
        result, manifest = build_manifest_result(target, env_config)
        if manifest is not None:
            result = {
                **result,
                "operation": "manifest_show",
                "name": manifest.name,
                "version": manifest.version,
                "summary": manifest.summary,
                "author": manifest.author,
                "website": manifest.website,
                "license": manifest.license,
                "installable": manifest.installable,
                "auto_install": manifest.auto_install,
                "depends": manifest.codependencies,
                "python_dependencies": manifest.python_dependencies,
                "binary_dependencies": manifest.binary_dependencies,
                "manifest_data": manifest.get_raw_data(),
            }
        else:
            result["operation"] = "manifest_show"
        _emit_result(
            global_config,
            result,
            result_type="manifest",
            text_renderer=lambda payload: _print_pairs(
                payload,
                [
                    ("module", "Module"),
                    ("module_path", "Module path"),
                    ("name", "Name"),
                    ("version", "Version"),
                    ("summary", "Summary"),
                    ("author", "Author"),
                    ("website", "Website"),
                    ("license", "License"),
                    ("installable", "Installable"),
                    ("auto_install", "Auto install"),
                    ("depends", "Depends"),
                ],
            ),
        )
