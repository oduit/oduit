import json
from pathlib import Path

from oduit.api_models import AddonDocTarget, TechnicalDocumentation
from oduit.documentation_policy import DocumentationDirectoryPolicy
from oduit.documentation_tracking import (
    TECHNICAL_DOC_METADATA_FILENAME,
    accept_reviewed_technical_documentation,
    build_technical_documentation_metadata,
    compute_document_snapshot,
    compute_source_snapshot,
    inspect_all_technical_documentation_statuses,
    inspect_technical_documentation_status,
    load_technical_documentation_metadata,
    write_technical_documentation_metadata,
)
from oduit.managed_markdown import GeneratedMarkdownBlock, render_generated_block


def _make_addon(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "__manifest__.py").write_text(
        "{'name': 'my_partner', 'version': '17.0.1.0.0', 'depends': ['base']}\n"
    )
    (root / "models").mkdir(exist_ok=True)
    (root / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
    )
    (root / "views").mkdir(exist_ok=True)
    (root / "views" / "res_partner_views.xml").write_text(
        "<odoo><record id='view_partner_form' model='ir.ui.view'/></odoo>\n"
    )


def _technical_bundle(addon_root: Path) -> TechnicalDocumentation:
    return TechnicalDocumentation(
        module="my_partner",
        addon_root=str(addon_root),
        source_addon_root=str(addon_root),
        target=AddonDocTarget(
            module="my_partner",
            addon_root=str(addon_root),
            target_kind="module",
            manifest_path=str(addon_root / "__manifest__.py"),
        ),
        markdown="# Architecture Documentation: my_partner\n",
    )


def _constraints_block() -> GeneratedMarkdownBlock:
    return GeneratedMarkdownBlock(
        id="arc42.constraints",
        renderer="arc42.constraints.v1",
        body=(
            "Derived from oduit evidence:\n\n"
            "| Constraint | Value | Evidence |\n"
            "|---|---|---|\n"
            "| Declared dependencies | `base` | manifest depends |\n"
        ),
        source_payload={"depends": ["base"]},
    )


def test_compute_source_snapshot_is_deterministic_across_creation_order(
    tmp_path: Path,
) -> None:
    addon_a = tmp_path / "a" / "my_partner"
    addon_b = tmp_path / "b" / "my_partner"
    _make_addon(addon_a)
    addon_b.mkdir(parents=True, exist_ok=True)
    (addon_b / "views").mkdir()
    (addon_b / "views" / "res_partner_views.xml").write_text(
        "<odoo><record id='view_partner_form' model='ir.ui.view'/></odoo>\n"
    )
    (addon_b / "models").mkdir()
    (addon_b / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
    )
    (addon_b / "__manifest__.py").write_text(
        "{'name': 'my_partner', 'version': '17.0.1.0.0', 'depends': ['base']}\n"
    )

    snapshot_a = compute_source_snapshot(addon_a, module="my_partner")
    snapshot_b = compute_source_snapshot(addon_b, module="my_partner")

    assert snapshot_a.fingerprint == snapshot_b.fingerprint
    assert [file_entry.path for file_entry in snapshot_a.files] == [
        file_entry.path for file_entry in snapshot_b.files
    ]


def test_ignored_files_do_not_affect_source_fingerprint(tmp_path: Path) -> None:
    addon_root = tmp_path / "addons" / "my_partner"
    _make_addon(addon_root)

    before = compute_source_snapshot(addon_root, module="my_partner")
    (addon_root / "docs").mkdir()
    (addon_root / "docs" / "architecture.md").write_text("# Generated doc\n")
    (addon_root / "docs" / TECHNICAL_DOC_METADATA_FILENAME).write_text(
        json.dumps({"ignored": True})
    )
    (addon_root / "__pycache__").mkdir()
    (addon_root / "__pycache__" / "cache.pyc").write_bytes(b"ignored")

    after = compute_source_snapshot(addon_root, module="my_partner")

    assert after.fingerprint == before.fingerprint


def test_compute_document_snapshot_changes_after_edit(tmp_path: Path) -> None:
    doc_path = tmp_path / "architecture.md"
    doc_path.write_text("# Architecture Documentation\n")

    before = compute_document_snapshot(doc_path)
    doc_path.write_text("# Architecture Documentation\n\nEdited\n")
    after = compute_document_snapshot(doc_path)

    assert before.fingerprint != after.fingerprint


def test_invalid_metadata_returns_metadata_invalid_status(tmp_path: Path) -> None:
    addon_root = tmp_path / "addons" / "my_partner"
    _make_addon(addon_root)
    (addon_root / "docs").mkdir()
    (addon_root / "docs" / TECHNICAL_DOC_METADATA_FILENAME).write_text("{invalid json")

    status = inspect_technical_documentation_status(
        addon_root=addon_root,
        module="my_partner",
    )

    assert status.status == "metadata_invalid"
    assert status.warnings


def test_build_metadata_uses_project_relative_paths_when_base_is_provided(
    tmp_path: Path,
) -> None:
    project_root = tmp_path
    addon_root = project_root / "addons" / "my_partner"
    _make_addon(addon_root)
    docs_dir = addon_root / "docs"
    docs_dir.mkdir()
    doc_path = docs_dir / "architecture.md"
    metadata_path = docs_dir / TECHNICAL_DOC_METADATA_FILENAME
    doc_path.write_text("# Architecture Documentation: my_partner\n")

    metadata = build_technical_documentation_metadata(
        bundle=_technical_bundle(addon_root),
        doc_path=doc_path,
        metadata_path=metadata_path,
        generation_options={
            "path_prefix": ".",
            "path_base": {"path": ".", "source": "local_config"},
        },
        path_base_dir=project_root,
        source_addon_root=addon_root,
    )

    assert metadata.addon_root == "addons/my_partner"
    assert metadata.doc_path == "addons/my_partner/docs/architecture.md"
    assert metadata.metadata_path == "addons/my_partner/docs/architecture.oduit.json"
    assert metadata.generation_options["path_prefix"] == "."
    assert metadata.generation_options["path_base"]["source"] == "local_config"


def test_absolute_metadata_remains_valid_when_status_uses_project_base(
    tmp_path: Path,
) -> None:
    project_root = tmp_path
    addon_root = project_root / "addons" / "my_partner"
    _make_addon(addon_root)
    docs_dir = addon_root / "docs"
    docs_dir.mkdir()
    doc_path = docs_dir / "architecture.md"
    metadata_path = docs_dir / TECHNICAL_DOC_METADATA_FILENAME
    doc_path.write_text("# Architecture Documentation: my_partner\n")

    metadata = build_technical_documentation_metadata(
        bundle=_technical_bundle(addon_root),
        doc_path=doc_path,
        metadata_path=metadata_path,
        generation_options={"path_prefix": str(project_root)},
        source_addon_root=addon_root,
    )
    write_technical_documentation_metadata(metadata, metadata_path)

    status = inspect_technical_documentation_status(
        addon_root=addon_root,
        module="my_partner",
        path_base_dir=project_root,
    )

    assert status.status == "up_to_date"
    assert status.warnings == []
    assert status.generation_count == metadata.generation_count
    assert status.template == metadata.template
    assert status.generation_options == metadata.generation_options
    assert status.evidence_counts == metadata.evidence_counts


def test_accept_reviewed_documentation_updates_snapshot_without_generation_increment(
    tmp_path: Path,
) -> None:
    addon_root = tmp_path / "addons" / "my_partner"
    _make_addon(addon_root)
    docs_dir = addon_root / "docs"
    docs_dir.mkdir()
    doc_path = docs_dir / "architecture.md"
    metadata_path = docs_dir / TECHNICAL_DOC_METADATA_FILENAME
    doc_path.write_text("# Architecture Documentation: my_partner\n")

    metadata = build_technical_documentation_metadata(
        bundle=_technical_bundle(addon_root),
        doc_path=doc_path,
        metadata_path=metadata_path,
        generation_options={},
        source_addon_root=addon_root,
    )
    write_technical_documentation_metadata(metadata, metadata_path)
    baseline_generation_count = metadata.generation_count
    doc_path.write_text(doc_path.read_text() + "\nManual polish.\n")

    accepted = accept_reviewed_technical_documentation(
        addon_root=addon_root,
        module="my_partner",
        metadata_path=metadata_path,
        reviewed_by="manual",
        review_note="Accepted manually polished generated architecture document",
    )
    write_technical_documentation_metadata(accepted, metadata_path)
    status = inspect_technical_documentation_status(
        addon_root=addon_root,
        module="my_partner",
    )

    assert accepted.generation_count == baseline_generation_count
    assert accepted.reviewed_at is not None
    assert accepted.reviewed_by == "manual"
    assert status.status == "up_to_date"


def test_status_selection_prefers_project_relative_directory_over_same_basename(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "project"
    external_root = tmp_path / "external"
    project_addons = project_root / "addons"
    external_addons = external_root / "addons"
    _make_addon(project_addons / "has_crm")
    _make_addon(external_addons / "outside_crm")

    statuses = inspect_all_technical_documentation_statuses(
        addons_path=f"{project_addons},{external_addons}",
        select_dir="addons",
        path_base_dir=project_root,
    )

    assert [status.module for status in statuses] == ["has_crm"]


def test_status_selection_accepts_single_addon_relative_path(tmp_path: Path) -> None:
    project_root = tmp_path
    addons_root = project_root / "addons"
    _make_addon(addons_root / "has_crm")
    _make_addon(addons_root / "has_sales")

    statuses = inspect_all_technical_documentation_statuses(
        addons_path=str(addons_root),
        select_dir="addons/has_crm",
        path_base_dir=project_root,
    )

    assert len(statuses) == 1
    assert statuses[0].module == "has_crm"


def test_status_selection_keeps_legacy_basename_matching(tmp_path: Path) -> None:
    project_root = tmp_path
    custom_addons = project_root / "custom_addons"
    _make_addon(custom_addons / "has_crm")

    statuses = inspect_all_technical_documentation_statuses(
        addons_path=str(custom_addons),
        select_dir="custom_addons",
        path_base_dir=project_root / "unrelated",
    )

    assert len(statuses) == 1
    assert statuses[0].module == "has_crm"


def test_status_scan_filters_with_documentation_policy(tmp_path: Path) -> None:
    native_root = tmp_path / "odoo" / "addons"
    custom_root = tmp_path / "addons"
    _make_addon(native_root / "account")
    _make_addon(custom_root / "has_crm")

    policy = DocumentationDirectoryPolicy(
        configured=True,
        allowed_dirs=(custom_root.resolve(strict=False),),
    )
    statuses = inspect_all_technical_documentation_statuses(
        addons_path=f"{native_root},{custom_root}",
        path_base_dir=tmp_path,
        documentation_policy=policy,
    )

    assert [status.module for status in statuses] == ["has_crm"]


def test_metadata_round_trips_generated_blocks(tmp_path: Path) -> None:
    addon_root = tmp_path / "addons" / "my_partner"
    _make_addon(addon_root)
    docs_dir = addon_root / "docs"
    docs_dir.mkdir()
    doc_path = docs_dir / "architecture.md"
    metadata_path = docs_dir / TECHNICAL_DOC_METADATA_FILENAME
    doc_path.write_text(
        "# Architecture Documentation: my_partner\n\n"
        + render_generated_block(_constraints_block())
        + "\n"
    )

    metadata = build_technical_documentation_metadata(
        bundle=_technical_bundle(addon_root),
        doc_path=doc_path,
        metadata_path=metadata_path,
        generation_options={},
        source_addon_root=addon_root,
    )
    write_technical_documentation_metadata(metadata, metadata_path)
    loaded, warnings = load_technical_documentation_metadata(metadata_path)

    assert warnings == []
    assert loaded is not None
    assert len(loaded.generated_blocks) == 1
    assert loaded.generated_blocks[0].id == "arc42.constraints"
    assert loaded.generated_blocks[0].renderer == "arc42.constraints.v1"


def test_status_reports_generated_blocks_up_to_date_for_fresh_doc(
    tmp_path: Path,
) -> None:
    addon_root = tmp_path / "addons" / "my_partner"
    _make_addon(addon_root)
    docs_dir = addon_root / "docs"
    docs_dir.mkdir()
    doc_path = docs_dir / "architecture.md"
    metadata_path = docs_dir / TECHNICAL_DOC_METADATA_FILENAME
    doc_path.write_text(
        "# Architecture Documentation: my_partner\n\n"
        + render_generated_block(_constraints_block())
        + "\n"
    )
    metadata = build_technical_documentation_metadata(
        bundle=_technical_bundle(addon_root),
        doc_path=doc_path,
        metadata_path=metadata_path,
        generation_options={},
        source_addon_root=addon_root,
    )
    write_technical_documentation_metadata(metadata, metadata_path)

    status = inspect_technical_documentation_status(
        addon_root=addon_root, module="my_partner"
    )

    assert status.generated_blocks_up_to_date is True
    assert status.generated_block_count == 1
    assert status.edited_generated_blocks == []


def test_status_manual_prose_edit_keeps_generated_blocks_up_to_date(
    tmp_path: Path,
) -> None:
    addon_root = tmp_path / "addons" / "my_partner"
    _make_addon(addon_root)
    docs_dir = addon_root / "docs"
    docs_dir.mkdir()
    doc_path = docs_dir / "architecture.md"
    metadata_path = docs_dir / TECHNICAL_DOC_METADATA_FILENAME
    doc_path.write_text(
        "# Architecture Documentation: my_partner\n\n"
        + render_generated_block(_constraints_block())
        + "\n"
    )
    metadata = build_technical_documentation_metadata(
        bundle=_technical_bundle(addon_root),
        doc_path=doc_path,
        metadata_path=metadata_path,
        generation_options={},
        source_addon_root=addon_root,
    )
    write_technical_documentation_metadata(metadata, metadata_path)
    doc_path.write_text(doc_path.read_text() + "\nManual prose edit outside block.\n")

    status = inspect_technical_documentation_status(
        addon_root=addon_root, module="my_partner"
    )

    assert status.status == "document_edited"
    assert status.generated_blocks_up_to_date is True
    assert status.edited_generated_blocks == []


def test_status_edit_inside_generated_block_is_reported(tmp_path: Path) -> None:
    addon_root = tmp_path / "addons" / "my_partner"
    _make_addon(addon_root)
    docs_dir = addon_root / "docs"
    docs_dir.mkdir()
    doc_path = docs_dir / "architecture.md"
    metadata_path = docs_dir / TECHNICAL_DOC_METADATA_FILENAME
    doc_path.write_text(
        "# Architecture Documentation: my_partner\n\n"
        + render_generated_block(_constraints_block())
        + "\n"
    )
    metadata = build_technical_documentation_metadata(
        bundle=_technical_bundle(addon_root),
        doc_path=doc_path,
        metadata_path=metadata_path,
        generation_options={},
        source_addon_root=addon_root,
    )
    write_technical_documentation_metadata(metadata, metadata_path)
    doc_path.write_text(
        doc_path.read_text().replace("manifest depends", "manifest deps")
    )

    status = inspect_technical_documentation_status(
        addon_root=addon_root, module="my_partner"
    )

    assert status.status == "generated_blocks_edited"
    assert status.edited_generated_blocks == ["arc42.constraints"]


def test_status_source_change_reports_stale_generated_block_details(
    tmp_path: Path,
) -> None:
    addon_root = tmp_path / "addons" / "my_partner"
    _make_addon(addon_root)
    docs_dir = addon_root / "docs"
    docs_dir.mkdir()
    doc_path = docs_dir / "architecture.md"
    metadata_path = docs_dir / TECHNICAL_DOC_METADATA_FILENAME
    doc_path.write_text(
        "# Architecture Documentation: my_partner\n\n"
        + render_generated_block(_constraints_block())
        + "\n"
    )
    metadata = build_technical_documentation_metadata(
        bundle=_technical_bundle(addon_root),
        doc_path=doc_path,
        metadata_path=metadata_path,
        generation_options={},
        source_addon_root=addon_root,
    )
    write_technical_documentation_metadata(metadata, metadata_path)
    source_path = addon_root / "models" / "res_partner.py"
    source_path.write_text(source_path.read_text() + "\n# source change\n")

    status = inspect_technical_documentation_status(
        addon_root=addon_root, module="my_partner"
    )

    assert status.status == "generated_blocks_stale"
    assert "arc42.constraints" in status.stale_generated_blocks
