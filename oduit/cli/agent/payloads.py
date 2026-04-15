"""Agent payload, parsing, and redaction helpers."""

import json
import re
from typing import Any, NoReturn, cast

import click
import typer

from ...schemas import SAFE_READ_ONLY
from ...utils import output_result_to_json


def agent_emit_payload(payload: dict[str, Any]) -> None:
    """Print a structured agent payload."""
    print(json.dumps(payload))


def _agent_show_command_enabled() -> bool:
    """Return whether the current agent invocation opted into command output."""
    ctx = click.get_current_context(silent=True)
    while ctx is not None:
        obj = getattr(ctx, "obj", None)
        if isinstance(obj, dict) and "show_command" in obj:
            return bool(obj["show_command"])
        ctx = ctx.parent
    return False


def _agent_effective_exclude_fields(
    exclude_fields: list[str] | None = None,
) -> list[str] | None:
    """Merge agent defaults with caller-provided field exclusions."""
    effective_exclude_fields = list(exclude_fields or [])
    if not _agent_show_command_enabled() and "command" not in effective_exclude_fields:
        effective_exclude_fields.append("command")
    return effective_exclude_fields or None


def agent_output_result_to_json(
    output: dict[str, Any],
    *,
    additional_fields: dict[str, Any] | None = None,
    exclude_fields: list[str] | None = None,
    include_null_values: bool = False,
    result_type: str = "result",
) -> dict[str, Any]:
    """Build agent JSON payloads with agent-specific field visibility defaults."""
    return output_result_to_json(
        output,
        additional_fields=additional_fields,
        exclude_fields=_agent_effective_exclude_fields(exclude_fields),
        include_null_values=include_null_values,
        result_type=result_type,
        flatten_data=False,
        flatten_meta_aliases=False,
        include_generated_at=False,
    )


def agent_fail(
    operation: str,
    result_type: str,
    message: str,
    *,
    error_type: str = "CommandError",
    details: dict[str, Any] | None = None,
    remediation: list[str] | None = None,
    read_only: bool = True,
    safety_level: str = SAFE_READ_ONLY,
    emit_payload_fn: Any = agent_emit_payload,
) -> NoReturn:
    """Emit a structured agent error payload and exit."""
    payload = agent_output_result_to_json(
        {
            "success": False,
            "operation": operation,
            "error": message,
            "error_type": error_type,
        },
        additional_fields={
            **(details or {}),
            "remediation": remediation or [],
            "read_only": read_only,
            "safety_level": safety_level,
        },
        result_type=result_type,
    )
    emit_payload_fn(payload)
    raise typer.Exit(1) from None


def agent_payload(
    operation: str,
    result_type: str,
    data: dict[str, Any],
    *,
    success: bool = True,
    warnings: list[str] | None = None,
    errors: list[dict[str, Any]] | None = None,
    remediation: list[str] | None = None,
    read_only: bool = True,
    safety_level: str = SAFE_READ_ONLY,
    error: str | None = None,
    error_type: str | None = None,
    include_null_values: bool = False,
    exclude_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Build a structured agent payload using the shared JSON envelope."""
    return agent_output_result_to_json(
        {
            "success": success,
            "operation": operation,
            "error": error,
            "error_type": error_type,
            **data,
        },
        additional_fields={
            "warnings": warnings or [],
            "errors": errors or [],
            "remediation": remediation or [],
            "read_only": read_only,
            "safety_level": safety_level,
        },
        exclude_fields=exclude_fields,
        include_null_values=include_null_values,
        result_type=result_type,
    )


_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def build_error_output_excerpt(
    result: dict[str, Any], *, max_lines: int = 80, max_chars: int = 12000
) -> list[str]:
    """Return a bounded tail excerpt from captured process output."""
    for stream_name in ("stderr", "stdout"):
        stream_value = result.get(stream_name)
        if not isinstance(stream_value, str) or not stream_value.strip():
            continue

        cleaned_lines = [
            _ANSI_ESCAPE_PATTERN.sub("", line.rstrip())
            for line in stream_value.splitlines()
            if line.strip()
        ]
        if not cleaned_lines:
            continue

        excerpt_lines = cleaned_lines[-max_lines:]
        excerpt_text = "\n".join(excerpt_lines)
        if len(excerpt_text) > max_chars:
            excerpt_text = excerpt_text[-max_chars:]
            excerpt_lines = excerpt_text.splitlines()

        return excerpt_lines

    return []


def parse_csv_items(raw_value: str | None) -> list[str] | None:
    """Parse a comma-separated CLI option into a list of strings."""
    if raw_value is None:
        return None
    items = [item.strip() for item in raw_value.split(",") if item.strip()]
    return items or None


def parse_view_types(
    raw_value: str | None,
    operation: str,
    result_type: str,
    *,
    fail_fn: Any,
) -> list[str] | None:
    """Parse and validate requested Odoo view types."""
    values = parse_csv_items(raw_value)
    if values is None:
        return None

    valid_view_types = {"form", "tree", "kanban", "search", "calendar", "graph"}
    invalid = [value for value in values if value not in valid_view_types]
    if invalid:
        fail_fn(
            operation,
            result_type,
            f"Unsupported view type(s): {', '.join(invalid)}",
            error_type="ValidationError",
            remediation=[
                "Use supported view types only: form, tree, kanban, search, "
                "calendar, graph.",
            ],
        )
    return values


def strip_arch_from_model_views(data: dict[str, Any]) -> dict[str, Any]:
    """Remove nested ``arch_db`` fields from model view payloads."""
    result = dict(data)
    for field_name in ("primary_views", "extension_views"):
        views = result.get(field_name)
        if not isinstance(views, list):
            continue
        result[field_name] = [
            {key: value for key, value in view.items() if key != "arch_db"}
            for view in views
            if isinstance(view, dict)
        ]
    return result


def parse_json_list_option(
    raw_value: str | None,
    option_name: str,
    operation: str,
    result_type: str,
    *,
    fail_fn: Any,
) -> list[Any]:
    """Parse a JSON-encoded list option or emit a structured error."""
    if raw_value is None:
        return []

    parsed: Any = None
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        fail_fn(
            operation,
            result_type,
            f"{option_name} must be valid JSON: {exc.msg}",
            details={option_name: raw_value},
            remediation=[
                f"Pass `{option_name}` as a JSON array, for example "
                f'\'["name", "=", "Acme"]\'.',
            ],
        )

    if not isinstance(parsed, list):
        fail_fn(
            operation,
            result_type,
            f"{option_name} must decode to a JSON array",
            details={option_name: raw_value},
            remediation=[
                f"Pass `{option_name}` as a JSON array value.",
            ],
        )

    return cast(list[Any], parsed)


def redact_config_value(key: str, value: Any) -> Any:
    """Redact sensitive configuration values in structured outputs."""
    sensitive_markers = ("password", "secret", "token", "api_key", "key")
    normalized_key = key.lower()
    if any(marker in normalized_key for marker in sensitive_markers):
        return "***redacted***"
    if isinstance(value, dict):
        return {
            inner_key: redact_config_value(inner_key, inner_value)
            for inner_key, inner_value in value.items()
        }
    if isinstance(value, list):
        return [redact_config_value(key, item) for item in value]
    return value


def redact_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return a recursively redacted configuration dictionary."""
    return {key: redact_config_value(key, value) for key, value in config.items()}
