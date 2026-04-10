"""Read-only database query commands for agent workflows."""

from typing import Any

import typer


def agent_query_model_command(
    ctx: typer.Context,
    *,
    model: str,
    domain_json: str | None,
    fields: str | None,
    limit: int,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    parse_json_list_option_fn: Any,
    parse_csv_items_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Run a structured read-only model query."""
    operation = "query_model"
    result_type = "query_result"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)

    result = ops.query_model(
        model,
        domain=parse_json_list_option_fn(
            domain_json, "domain_json", operation, result_type
        ),
        fields=parse_csv_items_fn(fields),
        limit=limit,
        database=database,
        timeout=timeout,
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        result.to_dict(),
        success=result.success,
        remediation=(
            [
                "Review the validation error and retry the query with "
                "literal-safe inputs."
            ]
            if not result.success
            else []
        ),
        read_only=True,
        safety_level=safe_read_only,
        error=result.error,
        error_type=result.error_type,
    )
    agent_emit_payload_fn(payload)
    if not result.success:
        raise typer.Exit(1)


def agent_read_record_command(
    ctx: typer.Context,
    *,
    model: str,
    record_id: int,
    fields: str | None,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    parse_csv_items_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Read a single record by id via OdooQuery."""
    operation = "read_record"
    result_type = "record_result"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)

    result = ops.read_record(
        model,
        record_id,
        fields=parse_csv_items_fn(fields),
        database=database,
        timeout=timeout,
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        result.to_dict(),
        success=result.success,
        remediation=(
            ["Verify the record id and field names, then retry the read operation."]
            if not result.success
            else []
        ),
        read_only=True,
        safety_level=safe_read_only,
        error=result.error,
        error_type=result.error_type,
    )
    agent_emit_payload_fn(payload)
    if not result.success:
        raise typer.Exit(1)


def agent_search_count_command(
    ctx: typer.Context,
    *,
    model: str,
    domain_json: str | None,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    parse_json_list_option_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Count records matching a domain via OdooQuery."""
    operation = "search_count"
    result_type = "count_result"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)

    result = ops.search_count(
        model,
        domain=parse_json_list_option_fn(
            domain_json, "domain_json", operation, result_type
        ),
        database=database,
        timeout=timeout,
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        result.to_dict(),
        success=result.success,
        remediation=(
            ["Verify the model name and domain syntax, then retry the search count."]
            if not result.success
            else []
        ),
        read_only=True,
        safety_level=safe_read_only,
        error=result.error,
        error_type=result.error_type,
    )
    agent_emit_payload_fn(payload)
    if not result.success:
        raise typer.Exit(1)


def agent_get_model_fields_command(
    ctx: typer.Context,
    *,
    model: str,
    attributes: str | None,
    database: str | None,
    timeout: float,
    resolve_agent_ops_fn: Any,
    parse_csv_items_fn: Any,
    agent_payload_fn: Any,
    agent_emit_payload_fn: Any,
    safe_read_only: str,
) -> None:
    """Inspect model field metadata via OdooQuery."""
    operation = "get_model_fields"
    result_type = "model_fields"
    _, ops = resolve_agent_ops_fn(ctx, operation, result_type)

    result = ops.get_model_fields(
        model,
        attributes=parse_csv_items_fn(attributes),
        database=database,
        timeout=timeout,
    )
    payload = agent_payload_fn(
        operation,
        result_type,
        result.to_dict(),
        success=result.success,
        remediation=(
            [
                "Verify the model name and requested attributes, then retry "
                "the inspection."
            ]
            if not result.success
            else []
        ),
        read_only=True,
        safety_level=safe_read_only,
        error=result.error,
        error_type=result.error_type,
    )
    agent_emit_payload_fn(payload)
    if not result.success:
        raise typer.Exit(1)
