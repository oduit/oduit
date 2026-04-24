"""Typed public Python API models for high-level inspection workflows."""

from dataclasses import asdict, dataclass
from dataclasses import field as dataclass_field
from typing import Any


@dataclass
class DictModel:
    """Mixin that exposes a stable ``to_dict()`` helper."""

    def to_dict(self) -> dict[str, Any]:
        """Return the dataclass as a plain dictionary."""
        return asdict(self)


@dataclass
class EnvironmentSource(DictModel):
    """Source metadata for an inspected environment."""

    name: str | None = None
    source: str | None = None
    config_path: str | None = None


@dataclass
class BinaryProbe(DictModel):
    """Resolved binary metadata for an environment."""

    value: str | None = None
    resolved_path: str | None = None
    exists: bool = False
    executable: bool = False
    configured: bool = False
    auto_detected: bool = False


@dataclass
class AddonsPathStatus(DictModel):
    """Resolved addon path information."""

    configured: list[str] = dataclass_field(default_factory=list)
    base: list[str] = dataclass_field(default_factory=list)
    all: list[str] = dataclass_field(default_factory=list)
    valid: list[str] = dataclass_field(default_factory=list)
    invalid: list[str] = dataclass_field(default_factory=list)


@dataclass
class OdooVersionInfo(DictModel):
    """Resolved Odoo version and series information."""

    version: str | None = None
    series: str | None = None


@dataclass
class DatabaseSummary(DictModel):
    """Safe database configuration summary."""

    db_name: str | None = None
    db_host: str | None = None
    db_user: str | None = None


@dataclass
class EnvironmentContext(DictModel):
    """Typed environment snapshot for planning and inspection."""

    environment: EnvironmentSource
    resolved_binaries: dict[str, BinaryProbe]
    addons_paths: AddonsPathStatus
    odoo: OdooVersionInfo
    database: DatabaseSummary
    duplicate_modules: dict[str, list[str]] = dataclass_field(default_factory=dict)
    available_module_count: int = 0
    invalid_addon_paths: list[str] = dataclass_field(default_factory=list)
    missing_critical_config: list[str] = dataclass_field(default_factory=list)
    doctor_summary: dict[str, int] = dataclass_field(default_factory=dict)
    doctor_checks: list[dict[str, Any]] = dataclass_field(default_factory=list)
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class AddonInspection(DictModel):
    """Typed addon inspection payload."""

    module: str
    exists: bool
    module_path: str | None
    addon_type: str
    version_display: str
    manifest: dict[str, Any]
    manifest_fields: list[str]
    direct_dependencies: list[str] = dataclass_field(default_factory=list)
    reverse_dependencies: list[str] = dataclass_field(default_factory=list)
    reverse_dependency_count: int = 0
    install_order_slice: list[str] = dataclass_field(default_factory=list)
    install_order_available: bool = False
    dependency_cycle: list[str] = dataclass_field(default_factory=list)
    missing_dependencies: list[str] = dataclass_field(default_factory=list)
    impacted_modules: list[str] = dataclass_field(default_factory=list)
    series: str | None = None
    python_dependencies: list[str] = dataclass_field(default_factory=list)
    binary_dependencies: list[str] = dataclass_field(default_factory=list)
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class AddonInstallState(DictModel):
    """Typed runtime install-state lookup result for one addon."""

    success: bool
    operation: str
    module: str
    record_found: bool = False
    state: str = "uninstalled"
    installed: bool = False
    database: str | None = None
    error: str | None = None
    error_type: str | None = None


@dataclass
class InstalledAddonRecord(DictModel):
    """One runtime addon record read from ``ir.module.module``."""

    module: str
    state: str
    installed: bool
    shortdesc: str | None = None
    application: bool | None = None
    auto_install: bool | None = None


@dataclass
class InstalledAddonInventory(DictModel):
    """Typed runtime addon inventory for one environment."""

    success: bool
    operation: str
    addons: list[InstalledAddonRecord] = dataclass_field(default_factory=list)
    total: int = 0
    states: list[str] = dataclass_field(default_factory=list)
    modules_filter: list[str] = dataclass_field(default_factory=list)
    database: str | None = None
    error: str | None = None
    error_type: str | None = None
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class UpdatePlan(DictModel):
    """Typed read-only update planning payload."""

    module: str
    exists: bool
    impact_set: list[str] = dataclass_field(default_factory=list)
    impact_count: int = 0
    missing_dependencies: list[str] = dataclass_field(default_factory=list)
    duplicate_name_risk: bool = False
    duplicate_module_locations: list[str] = dataclass_field(default_factory=list)
    dependency_cycle: list[str] = dataclass_field(default_factory=list)
    cycle_risk: bool = False
    ordering_constraints: list[str] = dataclass_field(default_factory=list)
    recommended_sequence: list[str] = dataclass_field(default_factory=list)
    backup_advised: bool = False
    write_protect_db: bool = False
    agent_write_protect_db: bool = False
    needs_mutation_flag: bool = False
    agent_needs_mutation_flag: bool = False
    human_runtime_db_mutation_policy: str = "allow"
    human_runtime_db_mutation_allowed: bool = True
    human_runtime_db_mutation_requires_flag: bool = False
    agent_runtime_db_mutation_policy: str = "allow"
    agent_runtime_db_mutation_allowed: bool = True
    agent_runtime_db_mutation_requires_flag: bool = False
    risk_score: int = 0
    risk_level: str = "low"
    risk_factors: list[str] = dataclass_field(default_factory=list)
    verification_steps: list[str] = dataclass_field(default_factory=list)
    inspection: AddonInspection | None = None
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class QueryModelResult(DictModel):
    """Typed wrapper for ``OdooQuery.query_model()`` results."""

    success: bool
    operation: str
    model: str
    domain: list[Any] = dataclass_field(default_factory=list)
    fields: list[str] | None = None
    limit: int = 0
    count: int = 0
    ids: list[int] = dataclass_field(default_factory=list)
    records: list[dict[str, Any]] = dataclass_field(default_factory=list)
    database: str | None = None
    error: str | None = None
    error_type: str | None = None

    @classmethod
    def from_dict(cls, result: dict[str, Any]) -> "QueryModelResult":
        """Create a typed result from a raw ``OdooQuery`` dictionary."""
        return cls(
            success=bool(result.get("success", False)),
            operation=str(result.get("operation", "query_model")),
            model=str(result.get("model", "")),
            domain=list(result.get("domain", [])),
            fields=result.get("fields"),
            limit=int(result.get("limit", 0) or 0),
            count=int(result.get("count", 0) or 0),
            ids=list(result.get("ids", [])),
            records=list(result.get("records", [])),
            database=result.get("database"),
            error=result.get("error"),
            error_type=result.get("error_type"),
        )


@dataclass
class RecordReadResult(DictModel):
    """Typed wrapper for ``OdooQuery.read_record()`` results."""

    success: bool
    operation: str
    model: str
    record_id: int
    found: bool
    record: dict[str, Any] | None
    fields: list[str] | None = None
    database: str | None = None
    error: str | None = None
    error_type: str | None = None

    @classmethod
    def from_dict(cls, result: dict[str, Any]) -> "RecordReadResult":
        """Create a typed result from a raw ``OdooQuery`` dictionary."""
        return cls(
            success=bool(result.get("success", False)),
            operation=str(result.get("operation", "read_record")),
            model=str(result.get("model", "")),
            record_id=int(result.get("record_id", 0) or 0),
            found=bool(result.get("found", False)),
            record=result.get("record"),
            fields=result.get("fields"),
            database=result.get("database"),
            error=result.get("error"),
            error_type=result.get("error_type"),
        )


@dataclass
class SearchCountResult(DictModel):
    """Typed wrapper for ``OdooQuery.search_count()`` results."""

    success: bool
    operation: str
    model: str
    domain: list[Any] = dataclass_field(default_factory=list)
    count: int = 0
    database: str | None = None
    error: str | None = None
    error_type: str | None = None

    @classmethod
    def from_dict(cls, result: dict[str, Any]) -> "SearchCountResult":
        """Create a typed result from a raw ``OdooQuery`` dictionary."""
        return cls(
            success=bool(result.get("success", False)),
            operation=str(result.get("operation", "search_count")),
            model=str(result.get("model", "")),
            domain=list(result.get("domain", [])),
            count=int(result.get("count", 0) or 0),
            database=result.get("database"),
            error=result.get("error"),
            error_type=result.get("error_type"),
        )


@dataclass
class ModelFieldsResult(DictModel):
    """Typed wrapper for ``OdooQuery.get_model_fields()`` results."""

    success: bool
    operation: str
    model: str
    attributes: list[str] | None = None
    module: str | None = None
    field_names: list[str] = dataclass_field(default_factory=list)
    field_definitions: dict[str, dict[str, Any]] = dataclass_field(default_factory=dict)
    database: str | None = None
    error: str | None = None
    error_type: str | None = None

    @classmethod
    def from_dict(cls, result: dict[str, Any]) -> "ModelFieldsResult":
        """Create a typed result from a raw ``OdooQuery`` dictionary."""
        return cls(
            success=bool(result.get("success", False)),
            operation=str(result.get("operation", "get_model_fields")),
            model=str(result.get("model", "")),
            attributes=result.get("attributes"),
            module=result.get("module"),
            field_names=list(result.get("field_names", [])),
            field_definitions=dict(result.get("field_definitions", {})),
            database=result.get("database"),
            error=result.get("error"),
            error_type=result.get("error_type"),
        )


@dataclass
class ModelViewRecord(DictModel):
    """One database-backed view record for a model."""

    id: int
    name: str
    view_type: str
    mode: str | None = None
    priority: int | None = None
    inherit_id: list[Any] | None = None
    key: str | None = None
    active: bool | None = None
    arch_db: str | None = None


@dataclass
class ModelViewInventory(DictModel):
    """Database-backed view inventory for a model."""

    model: str
    requested_types: list[str] = dataclass_field(default_factory=list)
    primary_views: list[ModelViewRecord] = dataclass_field(default_factory=list)
    extension_views: list[ModelViewRecord] = dataclass_field(default_factory=list)
    view_counts: dict[str, int] = dataclass_field(default_factory=dict)
    database: str | None = None
    error: str | None = None
    error_type: str | None = None
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class SourceEvidence(DictModel):
    """Machine-readable evidence attached to source-location candidates."""

    kind: str
    message: str
    path: str
    line_hint: int | None = None


@dataclass
class ModelSourceCandidate(DictModel):
    """Ranked model source candidate for static source localization."""

    path: str
    class_name: str
    match_kind: str
    declared_model: str
    confidence: float
    match_strength: str = "confirmed"
    evidence: list[SourceEvidence] = dataclass_field(default_factory=list)
    line_hint: int | None = None
    reason: str | None = None


@dataclass
class ModelSourceLocation(DictModel):
    """Static source localization result for one addon/model pair."""

    model: str
    module: str
    addon_root: str
    resolution: str = "not_found"
    ambiguous: bool = False
    ambiguity_reason: str | None = None
    candidates: list[ModelSourceCandidate] = dataclass_field(default_factory=list)
    scanned_python_files: list[str] = dataclass_field(default_factory=list)
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class FieldSourceCandidate(DictModel):
    """Ranked field source candidate for static source localization."""

    path: str
    class_name: str
    field_name: str
    match_kind: str
    declared_model: str
    confidence: float
    match_strength: str = "confirmed"
    evidence: list[SourceEvidence] = dataclass_field(default_factory=list)
    line_hint: int | None = None
    reason: str | None = None


@dataclass
class FieldSourceLocation(DictModel):
    """Static source localization result for one addon/model/field target."""

    model: str
    field: str
    module: str
    addon_root: str
    exists: bool
    resolution: str = "not_found"
    ambiguous: bool = False
    ambiguity_reason: str | None = None
    source_exists: bool = False
    runtime_exists: bool | None = None
    runtime_only: bool = False
    runtime_source_modules: list[str] = dataclass_field(default_factory=list)
    candidates: list[FieldSourceCandidate] = dataclass_field(default_factory=list)
    insertion_candidate: ModelSourceCandidate | None = None
    insertion_line_range: list[int] | None = None
    insertion_reason: str | None = None
    insertion_confidence: float | None = None
    related_files: list[str] = dataclass_field(default_factory=list)
    scanned_python_files: list[str] = dataclass_field(default_factory=list)
    rationale: str | None = None
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class AddonTestFile(DictModel):
    """Ranked addon test file entry."""

    path: str
    test_type: str
    references_model: bool = False
    references_field: bool = False
    confidence: float = 0.0
    ranking_signals: list[str] = dataclass_field(default_factory=list)
    related_paths: list[str] = dataclass_field(default_factory=list)


@dataclass
class AddonTestInventory(DictModel):
    """Static addon test inventory for coding-agent test selection."""

    module: str
    addon_root: str
    model: str | None = None
    field: str | None = None
    tests: list[AddonTestFile] = dataclass_field(default_factory=list)
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class AddonInfo(DictModel):
    """Combined static and runtime addon summary for onboarding workflows."""

    module: str
    module_path: str | None
    addon_type: str
    version_display: str
    summary: str = ""
    description: str = ""
    license: str = ""
    depends: list[str] = dataclass_field(default_factory=list)
    reverse_dependencies: list[str] = dataclass_field(default_factory=list)
    reverse_dependency_count: int = 0
    missing_dependencies: list[str] = dataclass_field(default_factory=list)
    installable: bool = False
    auto_install: bool = False
    models: list[str] = dataclass_field(default_factory=list)
    inherit_models: list[str] = dataclass_field(default_factory=list)
    model_count: int = 0
    test_cases: list[AddonTestFile] = dataclass_field(default_factory=list)
    test_count: int = 0
    languages: list[str] = dataclass_field(default_factory=list)
    installed_state: AddonInstallState | None = None
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class RecommendedTestPlan(DictModel):
    """Changed-file to test recommendation plan for coding-agent workflows."""

    module: str
    addon_root: str
    paths: list[str] = dataclass_field(default_factory=list)
    tests: list[AddonTestFile] = dataclass_field(default_factory=list)
    suggested_test_tags: list[str] = dataclass_field(default_factory=list)
    full_addon_suite_recommended: bool = False
    rationale: list[str] = dataclass_field(default_factory=list)
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class AddonModelEntry(DictModel):
    """One model declaration or extension discovered in addon source."""

    model: str
    relation_kind: str
    class_name: str
    path: str
    line_hint: int | None = None
    added_fields: list[str] = dataclass_field(default_factory=list)
    added_methods: list[str] = dataclass_field(default_factory=list)
    inherited_models: list[str] = dataclass_field(default_factory=list)
    delegated_models: list[str] = dataclass_field(default_factory=list)


@dataclass
class AddonModelInventory(DictModel):
    """Static addon model inventory for coding-agent inspection workflows."""

    module: str
    addon_root: str
    models: list[AddonModelEntry] = dataclass_field(default_factory=list)
    model_count: int = 0
    scanned_python_files: list[str] = dataclass_field(default_factory=list)
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class ModelExtensionSource(DictModel):
    """Static Python source extension for a model across addons."""

    module: str
    addon_root: str
    path: str
    class_name: str
    line_hint: int | None = None
    relation_kind: str = "extends"
    added_fields: list[str] = dataclass_field(default_factory=list)
    added_methods: list[str] = dataclass_field(default_factory=list)
    inherited_models: list[str] = dataclass_field(default_factory=list)
    delegated_models: list[str] = dataclass_field(default_factory=list)


@dataclass
class ModelDeclarationSource(DictModel):
    """Static source declaration for the model itself."""

    module: str
    addon_root: str
    path: str
    class_name: str
    line_hint: int | None = None
    added_fields: list[str] = dataclass_field(default_factory=list)
    added_methods: list[str] = dataclass_field(default_factory=list)


@dataclass
class InstalledModelField(DictModel):
    """Runtime field metadata for one installed model field."""

    name: str
    ttype: str
    relation: str | None = None
    modules: str | None = None
    state: str | None = None


@dataclass
class InstalledViewExtension(DictModel):
    """Installed inherited view metadata for a model."""

    name: str
    key: str | None = None
    priority: int | None = None
    inherit_id: list[Any] | None = None


@dataclass
class ViewExtensionSource(DictModel):
    """Static XML view extension for a model across addons."""

    module: str
    addon_root: str
    path: str
    record_id: str | None = None
    name: str | None = None
    priority: int | None = None
    inherit_ref: str | None = None


@dataclass
class ModelExtensionInventory(DictModel):
    """Combined source and runtime inventory for model extensions."""

    model: str
    base_declarations: list[ModelDeclarationSource] = dataclass_field(
        default_factory=list
    )
    source_extensions: list[ModelExtensionSource] = dataclass_field(
        default_factory=list
    )
    source_extension_modules: list[str] = dataclass_field(default_factory=list)
    installed_fields: list[InstalledModelField] = dataclass_field(default_factory=list)
    installed_extension_fields: list[InstalledModelField] = dataclass_field(
        default_factory=list
    )
    source_view_extensions: list[ViewExtensionSource] = dataclass_field(
        default_factory=list
    )
    installed_view_extensions: list[InstalledViewExtension] = dataclass_field(
        default_factory=list
    )
    installed_extension_modules: list[str] = dataclass_field(default_factory=list)
    scanned_python_files: list[str] = dataclass_field(default_factory=list)
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class DocumentationDiagram(DictModel):
    """Rendered documentation diagram artifact."""

    kind: str
    title: str
    format: str
    content: str


@dataclass
class DocumentSection(DictModel):
    """Rendered documentation section."""

    title: str
    markdown: str
    summary: str = ""
    order: int = 0


@dataclass
class ModelDocumentation(DictModel):
    """Documentation bundle for one model."""

    model: str
    database: str | None = None
    source_only: bool = False
    field_attributes: list[str] = dataclass_field(default_factory=list)
    requested_view_types: list[str] = dataclass_field(default_factory=list)
    extension_inventory: ModelExtensionInventory | None = None
    field_metadata: ModelFieldsResult | None = None
    view_inventory: ModelViewInventory | None = None
    diagrams: list[DocumentationDiagram] = dataclass_field(default_factory=list)
    sections: list[DocumentSection] = dataclass_field(default_factory=list)
    markdown: str = ""
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class AddonDocumentationModel(DictModel):
    """Per-model documentation detail inside one addon bundle."""

    model: str
    relation_kinds: list[str] = dataclass_field(default_factory=list)
    source_entries: list[AddonModelEntry] = dataclass_field(default_factory=list)
    documentation: ModelDocumentation | None = None


@dataclass
class AddonContributionSummary(DictModel):
    """Compact per-addon summary for one shared model."""

    model: str
    module: str
    relation_kinds: list[str] = dataclass_field(default_factory=list)
    class_names: list[str] = dataclass_field(default_factory=list)
    added_fields: list[str] = dataclass_field(default_factory=list)
    added_methods: list[str] = dataclass_field(default_factory=list)
    source_paths: list[str] = dataclass_field(default_factory=list)
    line_hints: list[int] = dataclass_field(default_factory=list)
    shared_model_doc_path: str | None = None
    shared_model_doc_anchor: str | None = None


@dataclass
class SharedModelDocumentation(DictModel):
    """Full shared-model documentation within a multi-addon bundle."""

    model: str
    owning_modules: list[str] = dataclass_field(default_factory=list)
    contributing_modules: list[str] = dataclass_field(default_factory=list)
    documentation: ModelDocumentation | None = None
    output_path: str | None = None
    markdown: str = ""


@dataclass
class AddonDocumentation(DictModel):
    """Documentation bundle for one addon."""

    module: str
    database: str | None = None
    source_only: bool = False
    addon_info: AddonInfo | None = None
    dependency_graph: dict[str, Any] = dataclass_field(default_factory=dict)
    model_inventory: AddonModelInventory | None = None
    models: list[AddonDocumentationModel] = dataclass_field(default_factory=list)
    shared_model_contributions: list[AddonContributionSummary] = dataclass_field(
        default_factory=list
    )
    recommended_tests: dict[str, Any] = dataclass_field(default_factory=dict)
    diagrams: list[DocumentationDiagram] = dataclass_field(default_factory=list)
    sections: list[DocumentSection] = dataclass_field(default_factory=list)
    output_path: str | None = None
    markdown: str = ""
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class MultiAddonDocumentation(DictModel):
    """Documentation bundle for multiple addons in one selected scope."""

    modules: list[str] = dataclass_field(default_factory=list)
    database: str | None = None
    source_only: bool = False
    addon_docs: list[AddonDocumentation] = dataclass_field(default_factory=list)
    shared_models: list[SharedModelDocumentation] = dataclass_field(
        default_factory=list
    )
    index_markdown: str = ""
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)


@dataclass
class DependencyGraphDocumentation(DictModel):
    """Documentation bundle for addon dependency graphs."""

    modules: list[str] = dataclass_field(default_factory=list)
    database: str | None = None
    source_only: bool = False
    installed_only: bool = False
    transitive: bool = True
    dependency_graph: dict[str, Any] = dataclass_field(default_factory=dict)
    installed_addons: InstalledAddonInventory | None = None
    diagrams: list[DocumentationDiagram] = dataclass_field(default_factory=list)
    sections: list[DocumentSection] = dataclass_field(default_factory=list)
    markdown: str = ""
    warnings: list[str] = dataclass_field(default_factory=list)
    remediation: list[str] = dataclass_field(default_factory=list)
