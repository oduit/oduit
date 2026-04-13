"""Structured JSON schema helpers for machine-readable output."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

JSON_SCHEMA_VERSION = "2.0"

SAFE_READ_ONLY = "safe_read_only"
CONTROLLED_RUNTIME_MUTATION = "controlled_runtime_mutation"
CONTROLLED_SOURCE_MUTATION = "controlled_source_mutation"
UNSAFE_ARBITRARY_EXECUTION = "unsafe_arbitrary_execution"

SAFE_READ_ONLY_OPERATIONS = {
    "agent_context",
    "addon_info",
    "doctor",
    "get_odoo_version",
    "inspect_addon",
    "list_db",
    "list_duplicates",
    "plan_update",
    "locate_model",
    "locate_field",
    "list_addon_tests",
    "agent_doctor",
    "agent_list_addons",
    "agent_dependency_graph",
    "inspect_addons",
    "resolve_config",
    "resolve_addon_root",
    "get_addon_files",
    "check_addons_installed",
    "check_model_exists",
    "check_field_exists",
    "print_config",
    "print_manifest",
    "list_manifest_values",
    "install_order",
    "impact_of_update",
    "list_addons",
    "list_installed_addons",
    "get_addon_install_state",
    "list_addon_models",
    "find_model_extensions",
    "get_model_views",
    "preflight_addon_change",
    "list_depends",
    "list_codepends",
    "list_missing",
    "query_model",
    "read_record",
    "search_count",
    "get_model_fields",
    "inspect_ref",
    "inspect_modules",
    "inspect_subtypes",
    "inspect_model",
    "inspect_field",
    "manifest_check",
    "manifest_show",
    "describe_table",
    "describe_column",
    "list_constraints",
    "list_tables",
    "inspect_m2m",
    "performance_table_scans",
    "performance_slow_queries",
    "performance_indexes",
}

CONTROLLED_RUNTIME_MUTATION_OPERATIONS = {
    "install",
    "test_summary",
    "install_module",
    "uninstall_module",
    "update_module",
    "update",
    "test",
    "create_db",
    "drop_db",
    "run_odoo",
    "run_shell",
}

CONTROLLED_SOURCE_MUTATION_OPERATIONS = {
    "create_addon",
    "create_agent_addon",
    "export_lang_module",
    "export_module_language",
}

UNSAFE_OPERATIONS = {
    "execute_python_code",
    "execute_code",
    "execute_multiple",
}

SAFE_READ_ONLY_TYPES = {
    "addon_info",
    "doctor_report",
    "manifest",
    "manifest_values",
    "log",
    "model_source_location",
    "field_source_location",
    "addon_test_inventory",
    "addon_inventory",
    "installed_addon_inventory",
    "addon_model_inventory",
    "model_extension_inventory",
    "model_view_inventory",
    "addon_change_preflight",
    "dependency_graph",
    "config_resolution",
    "addon_root_resolution",
    "addon_file_inventory",
    "addon_install_checks",
    "model_existence",
    "field_existence",
    "duplicate_modules",
    "batch_addon_inspection",
    "xmlid_inspection",
    "module_inspection",
    "subtype_inventory",
    "model_inspection",
    "field_inspection",
    "table_description",
    "column_description",
    "constraint_inventory",
    "table_inventory",
    "m2m_inspection",
    "slow_query_metrics",
    "table_scan_metrics",
    "index_usage_metrics",
    "manifest_validation",
}

COMMON_ENVELOPE_KEYS = {
    "schema_version",
    "type",
    "success",
    "operation",
    "read_only",
    "safety_level",
    "warnings",
    "errors",
    "remediation",
    "error",
    "error_type",
    "error_code",
    "data",
    "meta",
}


def infer_read_only(operation: str | None, payload_type: str) -> bool:
    """Infer whether a JSON payload represents a read-only action."""
    if operation in SAFE_READ_ONLY_OPERATIONS or payload_type in SAFE_READ_ONLY_TYPES:
        return True
    if (
        operation in CONTROLLED_RUNTIME_MUTATION_OPERATIONS
        or operation in CONTROLLED_SOURCE_MUTATION_OPERATIONS
        or operation in UNSAFE_OPERATIONS
    ):
        return False
    return payload_type in {"log", "error", "result"}


def infer_safety_level(operation: str | None, payload_type: str) -> str:
    """Infer the safety level for a JSON payload."""
    if operation in UNSAFE_OPERATIONS:
        return UNSAFE_ARBITRARY_EXECUTION
    if operation in CONTROLLED_SOURCE_MUTATION_OPERATIONS:
        return CONTROLLED_SOURCE_MUTATION
    if operation in CONTROLLED_RUNTIME_MUTATION_OPERATIONS:
        return CONTROLLED_RUNTIME_MUTATION
    if operation in SAFE_READ_ONLY_OPERATIONS or payload_type in SAFE_READ_ONLY_TYPES:
        return SAFE_READ_ONLY
    return (
        SAFE_READ_ONLY
        if infer_read_only(operation, payload_type)
        else CONTROLLED_RUNTIME_MUTATION
    )


def _strip_none_values(value: Any) -> Any:
    """Recursively remove ``None`` values while preserving empty lists."""
    if isinstance(value, dict):
        return {k: _strip_none_values(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_none_values(item) for item in value]
    return value


@dataclass
class ResultMeta:
    """Common metadata shared by structured result payloads."""

    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration: float | None = None

    def to_dict(self, include_null_values: bool = False) -> dict[str, Any]:
        payload = {
            "timestamp": self.timestamp,
            "generated_at": self.timestamp,
            "duration": self.duration,
        }
        if not include_null_values:
            payload = _strip_none_values(payload)
        return payload


@dataclass
class ResultEnvelope:
    """Stable top-level JSON envelope for structured command results."""

    payload_type: str
    success: bool
    operation: str | None = None
    read_only: bool = True
    safety_level: str = SAFE_READ_ONLY
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    error: str | None = None
    error_type: str | None = None
    error_code: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    meta: ResultMeta = field(default_factory=ResultMeta)
    schema_version: str = JSON_SCHEMA_VERSION

    def to_dict(
        self,
        include_null_values: bool = False,
        flatten_data: bool = True,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "type": self.payload_type,
            "success": self.success,
            "operation": self.operation,
            "read_only": self.read_only,
            "safety_level": self.safety_level,
            "warnings": self.warnings,
            "errors": self.errors,
            "remediation": self.remediation,
            "error": self.error,
            "error_type": self.error_type,
            "error_code": self.error_code,
            "data": self.data,
            "meta": self.meta.to_dict(include_null_values=include_null_values),
        }

        if flatten_data:
            for key, value in self.data.items():
                if key not in payload:
                    payload[key] = value

        timestamp = payload["meta"].get("timestamp")
        duration = payload["meta"].get("duration")
        if timestamp is not None:
            payload["timestamp"] = timestamp
            payload["generated_at"] = timestamp
        if duration is not None:
            payload["duration"] = duration

        if not include_null_values:
            payload = _strip_none_values(payload)

        return payload
