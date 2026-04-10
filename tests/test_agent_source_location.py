import json
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from oduit.cli.app import app


def _make_executable(path: Path) -> str:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def _agent_config(tmp_path: Path, addons_path: str) -> dict[str, str]:
    return {
        "python_bin": _make_executable(tmp_path / "python3"),
        "odoo_bin": _make_executable(tmp_path / "odoo-bin"),
        "coverage_bin": _make_executable(tmp_path / "coverage"),
        "addons_path": addons_path,
        "db_name": "test_db",
        "db_host": "localhost",
        "db_user": "odoo",
        "db_password": "super-secret",
    }


def _loader_with_config(config: dict[str, str], tmp_path: Path) -> MagicMock:
    loader = MagicMock()
    loader.load_config.return_value = config
    loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
    return loader


def _make_addon(
    addons_dir: Path, module_name: str, depends: list[str] | None = None
) -> Path:
    module_dir = addons_dir / module_name
    module_dir.mkdir(parents=True)
    (module_dir / "__manifest__.py").write_text(
        str(
            {
                "name": module_name,
                "version": "17.0.1.0.0",
                "depends": depends or ["base"],
            }
        )
    )
    return module_dir


def test_agent_locate_model_returns_ranked_candidates(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = _make_addon(addons_dir, "my_partner")
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
    )
    (addon_dir / "models" / "other.py").write_text(
        "from odoo import models\n\n"
        "class AnotherPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
    )

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "locate-model",
                "res.partner",
                "--module",
                "my_partner",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "model_source_location"
    assert payload["model"] == "res.partner"
    assert payload["module"] == "my_partner"
    assert payload["candidates"][0]["path"].endswith("models/res_partner.py")
    assert payload["candidates"][0]["match_kind"] == "inherit"


def test_agent_locate_field_reports_existing_field_and_insertion_candidate(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = _make_addon(addons_dir, "my_partner")
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
    )

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        existing = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "locate-field",
                "res.partner",
                "email3",
                "--module",
                "my_partner",
            ],
        )
        missing = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "locate-field",
                "res.partner",
                "phone3",
                "--module",
                "my_partner",
            ],
        )

    existing_payload = json.loads(existing.output)
    missing_payload = json.loads(missing.output)
    assert existing.exit_code == 0
    assert existing_payload["exists"] is True
    assert existing_payload["candidates"][0]["field_name"] == "email3"
    assert missing.exit_code == 0
    assert missing_payload["exists"] is False
    assert missing_payload["insertion_candidate"]["path"].endswith(
        "models/res_partner.py"
    )


def test_agent_list_addon_tests_ranks_references_and_handles_invalid_python(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = _make_addon(addons_dir, "my_partner")
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "broken.py").write_text("class Broken(:\n")
    (addon_dir / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
    )
    (addon_dir / "tests").mkdir()
    (addon_dir / "tests" / "test_partner.py").write_text(
        "def test_partner_email3():\n    model = 'res.partner'\n    field = 'email3'\n"
    )
    (addon_dir / "tests" / "test_other.py").write_text("def test_other():\n    pass\n")

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        tests_result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "list-addon-tests",
                "my_partner",
                "--model",
                "res.partner",
                "--field",
                "email3",
            ],
        )
        locate_result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "locate-model",
                "res.partner",
                "--module",
                "my_partner",
            ],
        )

    tests_payload = json.loads(tests_result.output)
    locate_payload = json.loads(locate_result.output)
    assert tests_result.exit_code == 0
    assert tests_payload["tests"][0]["path"].endswith("tests/test_partner.py")
    assert tests_payload["tests"][0]["references_model"] is True
    assert tests_payload["tests"][0]["references_field"] is True
    assert locate_result.exit_code == 0
    assert locate_payload["warnings"]


def test_agent_list_addon_models_returns_static_inventory(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = _make_addon(addons_dir, "my_partner")
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class PartnerScore(models.Model):\n"
        "    _name = 'x.partner.score'\n"
        "    _inherit = 'mail.thread'\n"
        "    partner_id = fields.Many2one('res.partner')\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    score = fields.Integer()\n"
    )

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            ["--env", "dev", "agent", "list-addon-models", "my_partner"],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_model_inventory"
    assert payload["module"] == "my_partner"
    assert payload["model_count"] == 2
    assert payload["models"][0]["model"] == "res.partner"
    assert payload["models"][0]["relation_kind"] == "extends"
    assert payload["models"][1]["model"] == "x.partner.score"
    assert payload["models"][1]["relation_kind"] == "declares"
    assert payload["models"][1]["inherited_models"] == ["mail.thread"]


def test_agent_find_model_extensions_combines_source_and_runtime_metadata(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    base_dir = _make_addon(addons_dir, "dvo")
    (base_dir / "models").mkdir()
    (base_dir / "models" / "dvo.py").write_text(
        "from odoo import fields, models\n\n"
        "class DVO(models.Model):\n"
        "    _name = 'dvo.dvo'\n"
        "    name = fields.Char()\n"
    )
    ext_dir = _make_addon(addons_dir, "dvo_helpdesk", depends=["dvo"])
    (ext_dir / "models").mkdir()
    (ext_dir / "models" / "dvo.py").write_text(
        "from odoo import fields, models\n\n"
        "class DVO(models.Model):\n"
        "    _inherit = 'dvo.dvo'\n"
        "    helpdesk_team_ids = fields.Many2many('helpdesk.team')\n\n"
        "    def _get_salesman_for_ticket(self):\n"
        "        return False\n"
    )
    (ext_dir / "views").mkdir()
    (ext_dir / "views" / "dvo_dvo_views.xml").write_text(
        "<odoo>\n"
        "  <record id='dvo_dvo_view_form_form_fields' model='ir.ui.view'>\n"
        "    <field name='name'>dvo.dvo.view.dvo</field>\n"
        "    <field name='model'>dvo.dvo</field>\n"
        "    <field name='inherit_id' ref='dvo.dvo_dvo_view_form' />\n"
        "    <field name='priority'>101</field>\n"
        "  </record>\n"
        "</odoo>\n"
    )

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    def _query_side_effect(
        self: object,
        model: str,
        domain: list[object] | None = None,
        fields: list[str] | None = None,
        limit: int = 80,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> MagicMock:
        if model == "ir.model.fields":
            return MagicMock(
                success=True,
                records=[
                    {
                        "name": "name",
                        "ttype": "char",
                        "relation": False,
                        "modules": "dvo",
                        "state": "base",
                    },
                    {
                        "name": "helpdesk_team_ids",
                        "ttype": "many2many",
                        "relation": "helpdesk.team",
                        "modules": "dvo_helpdesk",
                        "state": "base",
                    },
                ],
                error=None,
            )
        if model == "ir.ui.view":
            return MagicMock(
                success=True,
                records=[
                    {
                        "name": "dvo.dvo.view.dvo",
                        "key": False,
                        "priority": 101,
                        "inherit_id": [1501, "DVO Form"],
                    }
                ],
                error=None,
            )
        raise AssertionError(model)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.odoo_operations.OdooOperations.query_model", new=_query_side_effect
        ),
    ):
        result = runner.invoke(
            app,
            ["--env", "dev", "agent", "find-model-extensions", "dvo.dvo"],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "model_extension_inventory"
    assert payload["model"] == "dvo.dvo"
    assert payload["base_declarations"][0]["module"] == "dvo"
    assert payload["source_extensions"][0]["module"] == "dvo_helpdesk"
    assert payload["source_extensions"][0]["added_fields"] == ["helpdesk_team_ids"]
    assert payload["source_extensions"][0]["added_methods"] == [
        "_get_salesman_for_ticket"
    ]
    assert payload["source_view_extensions"][0]["module"] == "dvo_helpdesk"
    assert (
        payload["source_view_extensions"][0]["inherit_ref"] == "dvo.dvo_dvo_view_form"
    )
    assert payload["installed_extension_fields"][0]["modules"] == "dvo_helpdesk"
    assert payload["installed_view_extensions"][0]["priority"] == 101


def test_agent_find_model_extensions_summary_omits_scanned_files(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    _make_addon(addons_dir, "base", depends=[])
    addon_dir = _make_addon(addons_dir, "dvo")
    (addon_dir / "models").mkdir()
    (addon_dir / "models" / "dvo.py").write_text(
        "from odoo import fields, models\n\n"
        "class DVO(models.Model):\n"
        "    _name = 'dvo.dvo'\n"
        "    name = fields.Char()\n"
    )

    config = _agent_config(tmp_path, str(addons_dir))
    loader = _loader_with_config(config, tmp_path)

    def _query_side_effect(
        self: object,
        model: str,
        domain: list[object] | None = None,
        fields: list[str] | None = None,
        limit: int = 80,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> MagicMock:
        return MagicMock(success=True, records=[], error=None)

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch(
            "oduit.odoo_operations.OdooOperations.query_model", new=_query_side_effect
        ),
    ):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "agent",
                "find-model-extensions",
                "dvo.dvo",
                "--summary",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"] is True
    assert payload["base_declaration_count"] == 1
    assert payload["source_extension_count"] == 0
    assert "scanned_python_files" not in payload
