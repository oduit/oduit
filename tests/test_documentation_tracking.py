import json
from pathlib import Path

from oduit.api_models import AddonDocTarget, TechnicalDocumentation
from oduit.documentation_tracking import (
    TECHNICAL_DOC_METADATA_FILENAME,
    build_technical_documentation_metadata,
    compute_document_snapshot,
    compute_source_snapshot,
    inspect_all_technical_documentation_statuses,
    inspect_technical_documentation_status,
    write_technical_documentation_metadata,
)


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
