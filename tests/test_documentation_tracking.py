import json
from pathlib import Path

from oduit.documentation_tracking import (
    TECHNICAL_DOC_METADATA_FILENAME,
    compute_document_snapshot,
    compute_source_snapshot,
    inspect_technical_documentation_status,
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
