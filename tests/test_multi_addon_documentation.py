from pathlib import Path

from oduit import MultiAddonDocumentation, OdooOperations


def _make_addon(
    addons_dir: Path,
    module_name: str,
    depends: list[str] | None = None,
    version: str = "17.0.1.0.0",
) -> Path:
    module_dir = addons_dir / module_name
    module_dir.mkdir()
    (module_dir / "__manifest__.py").write_text(
        str(
            {
                "name": module_name.replace("_", " ").title(),
                "version": version,
                "depends": depends or ["base"],
            }
        )
    )
    return module_dir


def _config(tmp_path: Path, addons_path: str) -> dict[str, str]:
    python_bin = tmp_path / "python3"
    python_bin.write_text("#!/bin/sh\nexit 0\n")
    python_bin.chmod(0o755)

    odoo_bin = tmp_path / "odoo-bin"
    odoo_bin.write_text("#!/bin/sh\nexit 0\n")
    odoo_bin.chmod(0o755)

    return {
        "python_bin": str(python_bin),
        "odoo_bin": str(odoo_bin),
        "addons_path": addons_path,
        "db_name": "test_db",
        "db_host": "localhost",
        "db_user": "odoo",
    }


def _write_model(module_dir: Path, filename: str, content: str) -> None:
    models_dir = module_dir / "models"
    models_dir.mkdir(exist_ok=True)
    (models_dir / filename).write_text(content)


def test_build_addons_documentation_classifies_and_deduplicates_models(
    tmp_path: Path,
) -> None:
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])

    core_demo = _make_addon(addons_dir, "core_demo")
    _write_model(
        core_demo,
        "demo.py",
        "from odoo import fields, models\n\n"
        "class DemoModel(models.Model):\n"
        "    _name = 'x.demo'\n"
        "    name = fields.Char()\n\n"
        "    def _compute_name(self):\n"
        "        return None\n",
    )

    ext_demo = _make_addon(addons_dir, "ext_demo")
    _write_model(
        ext_demo,
        "demo.py",
        "from odoo import fields, models\n\n"
        "class DemoExtension(models.Model):\n"
        "    _inherit = 'x.demo'\n"
        "    score = fields.Integer()\n\n"
        "    def _compute_score(self):\n"
        "        return None\n",
    )
    _write_model(
        ext_demo,
        "partner.py",
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    partner_score = fields.Integer()\n",
    )

    local_demo = _make_addon(addons_dir, "local_demo")
    _write_model(
        local_demo,
        "local.py",
        "from odoo import fields, models\n\n"
        "class LocalDemo(models.Model):\n"
        "    _name = 'x.local'\n"
        "    title = fields.Char()\n",
    )
    _write_model(
        local_demo,
        "users.py",
        "from odoo import fields, models\n\n"
        "class ResUsers(models.Model):\n"
        "    _inherit = 'res.users'\n"
        "    user_flag = fields.Boolean()\n",
    )

    outside_ext = _make_addon(addons_dir, "outside_ext")
    _write_model(
        outside_ext,
        "demo.py",
        "from odoo import fields, models\n\n"
        "class OutsideDemoExtension(models.Model):\n"
        "    _inherit = 'x.demo'\n"
        "    external_name = fields.Char()\n",
    )

    ops = OdooOperations(_config(tmp_path, str(addons_dir)))
    bundle = ops.build_addons_documentation(
        ["core_demo", "ext_demo", "local_demo"],
        source_only=True,
    )

    assert isinstance(bundle, MultiAddonDocumentation)
    assert bundle.modules == ["core_demo", "ext_demo", "local_demo"]

    shared_models = {item.model: item for item in bundle.shared_models}
    assert set(shared_models) == {"res.partner", "res.users", "x.demo"}
    assert shared_models["x.demo"].owning_modules == ["core_demo"]
    assert shared_models["x.demo"].contributing_modules == ["core_demo", "ext_demo"]
    assert shared_models["res.partner"].owning_modules == []
    assert shared_models["res.partner"].contributing_modules == ["ext_demo"]
    assert shared_models["res.users"].owning_modules == []
    assert shared_models["res.users"].contributing_modules == ["local_demo"]
    assert shared_models["x.demo"].markdown.startswith("# Shared model: x.demo")

    x_demo_inventory = shared_models["x.demo"].documentation.extension_inventory
    assert x_demo_inventory is not None
    assert {item.module for item in x_demo_inventory.source_extensions} == {"ext_demo"}
    assert any(
        "Source contributions were limited to selected modules" in warning
        for warning in shared_models["x.demo"].documentation.warnings
    )

    core_addon = next(item for item in bundle.addon_docs if item.module == "core_demo")
    assert core_addon.models == []
    assert {item.model for item in core_addon.shared_model_contributions} == {"x.demo"}

    ext_addon = next(item for item in bundle.addon_docs if item.module == "ext_demo")
    assert ext_addon.models == []
    assert {item.model for item in ext_addon.shared_model_contributions} == {
        "res.partner",
        "x.demo",
    }
    x_demo_contribution = next(
        item for item in ext_addon.shared_model_contributions if item.model == "x.demo"
    )
    assert x_demo_contribution.added_fields == ["score"]
    assert x_demo_contribution.added_methods == ["_compute_score"]
    assert x_demo_contribution.shared_model_doc_path == "../models/x.demo.md"

    local_addon = next(
        item for item in bundle.addon_docs if item.module == "local_demo"
    )
    assert [item.model for item in local_addon.models] == ["x.local"]
    assert {item.model for item in local_addon.shared_model_contributions} == {
        "res.users"
    }
    assert "# Multi-addon documentation bundle" in bundle.index_markdown
