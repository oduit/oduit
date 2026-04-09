import json
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from oduit.cli_typer import app


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

    with patch("oduit.cli_typer.ConfigLoader", return_value=loader):
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

    with patch("oduit.cli_typer.ConfigLoader", return_value=loader):
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

    with patch("oduit.cli_typer.ConfigLoader", return_value=loader):
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

    with patch("oduit.cli_typer.ConfigLoader", return_value=loader):
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
