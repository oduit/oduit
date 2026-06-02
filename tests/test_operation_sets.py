# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import tempfile
import unittest
from pathlib import Path

from oduit.exceptions import ConfigError
from oduit.operation_sets import (
    load_operation_set,
    resolve_operation_set_path,
    validate_operation_set_addons,
)


def _write_toml(tmp_dir: Path, name: str, content: str) -> Path:
    path = tmp_dir / name
    path.write_text(content)
    return path


class TestResolveOperationSetPath(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.sets_dir = Path(self.tmp_dir) / ".oduit" / "sets"
        self.sets_dir.mkdir(parents=True)

    def test_exact_file_path(self):
        path = _write_toml(Path(self.tmp_dir), "myset.toml", "[install]\naddons = []")
        result = resolve_operation_set_path(str(path))
        self.assertEqual(result, path.resolve())

    def test_short_name_with_toml_extension(self):
        _write_toml(self.sets_dir, "base.toml", "[install]\naddons = []")
        result = resolve_operation_set_path("base", base_dir=Path(self.tmp_dir))
        self.assertEqual(result, (self.sets_dir / "base.toml").resolve())

    def test_short_name_without_extension(self):
        _write_toml(self.sets_dir, "base", "[install]\naddons = []")
        result = resolve_operation_set_path("base", base_dir=Path(self.tmp_dir))
        self.assertEqual(result, (self.sets_dir / "base").resolve())

    def test_unresolved_short_name_raises(self):
        with self.assertRaises(ConfigError) as cm:
            resolve_operation_set_path("missing", base_dir=Path(self.tmp_dir))
        self.assertIn("missing", str(cm.exception))
        self.assertIn(".oduit/sets", str(cm.exception))

    def test_non_toml_file_raises_on_load(self):
        path = _write_toml(Path(self.tmp_dir), "set.yaml", "key: value")
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("TOML", str(cm.exception))


class TestKeyValidation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def test_unknown_top_level_key_raises(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "bad.toml",
            'unknown_key = "value"\n[install]\naddons = []\n',
        )
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("top level", str(cm.exception))
        self.assertIn("unknown_key", str(cm.exception))

    def test_unknown_section_key_raises(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "bad.toml",
            "[install]\naddons = []\nbad_key = true\n",
        )
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("install", str(cm.exception))
        self.assertIn("bad_key", str(cm.exception))

    def test_unknown_test_key_raises(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "bad.toml",
            '[test]\ntest_tag = "/sale"\n',
        )
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("test", str(cm.exception))
        self.assertIn("test_tag", str(cm.exception))


class TestSectionParsing(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def test_install_section_normalizes(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[install]\naddons = ["has_base", "has_crm"]\nwith_demo = false\n'
            'language = "de_DE"\nmax_cron_threads = 0\ncompact = true\n',
        )
        op_set = load_operation_set(str(path))
        assert op_set.install is not None
        self.assertEqual(op_set.install.addons, ("has_base", "has_crm"))
        self.assertEqual(op_set.install.language, "de_DE")
        self.assertEqual(op_set.install.max_cron_threads, 0)
        self.assertTrue(op_set.install.compact)

    def test_update_section_normalizes(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[update]\naddons = ["has_base"]\ni18n_overwrite = true\n'
            'language = "de_DE"\ncompact = true\n',
        )
        op_set = load_operation_set(str(path))
        assert op_set.update is not None
        self.assertEqual(op_set.update.addons, ("has_base",))
        self.assertTrue(op_set.update.i18n_overwrite)
        self.assertEqual(op_set.update.language, "de_DE")

    def test_test_section_normalizes(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[test]\ninstall = ["has_base", "has_helpdesk"]\n'
            'update = ["has_helpdesk"]\n'
            'test_tags = ["/has_helpdesk", "/has_helpdesk:TestTicketFlow"]\n'
            "compact = true\nstop_on_error = true\n",
        )
        op_set = load_operation_set(str(path))
        assert op_set.test is not None
        self.assertEqual(op_set.test.install, ("has_base", "has_helpdesk"))
        self.assertEqual(op_set.test.update, ("has_helpdesk",))
        self.assertEqual(
            op_set.test.test_tags,
            ("/has_helpdesk", "/has_helpdesk:TestTicketFlow"),
        )
        self.assertTrue(op_set.test.stop_on_error)

    def test_test_files_resolved_relative_to_set(self):
        # Create a dummy test file
        addon_dir = Path(self.tmp_dir) / "addons" / "has_helpdesk" / "tests"
        addon_dir.mkdir(parents=True)
        test_file = addon_dir / "test_ticket.py"
        test_file.write_text("# test")

        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[test]\ntest_files = ["addons/has_helpdesk/tests/test_ticket.py"]\n',
        )
        op_set = load_operation_set(str(path))
        assert op_set.test is not None
        self.assertEqual(len(op_set.test.test_files), 1)
        self.assertTrue(str(op_set.test.test_files[0]).endswith("test_ticket.py"))
        self.assertEqual(
            op_set.test.test_file_inputs,
            ("addons/has_helpdesk/tests/test_ticket.py",),
        )

    def test_missing_test_files_fails(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[test]\ntest_files = ["nonexistent.py"]\n',
        )
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("nonexistent.py", str(cm.exception))

    def test_missing_test_files_allowed(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[test]\ntest_files = ["nonexistent.py"]\n',
        )
        op_set = load_operation_set(str(path), allow_missing_test_files=True)
        assert op_set.test is not None
        self.assertEqual(len(op_set.test.test_files), 1)

    def test_with_demo_and_without_demo_conflict(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            "[install]\naddons = []\nwith_demo = true\nwithout_demo = true\n",
        )
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("with_demo and without_demo", str(cm.exception))

    def test_test_tags_string_with_commas(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[test]\ntest_tags = "/sale,/sale:TestFlow"\n',
        )
        op_set = load_operation_set(str(path))
        assert op_set.test is not None
        self.assertEqual(op_set.test.test_tags, ("/sale", "/sale:TestFlow"))


class TestAddonValidation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        addons_root = Path(self.tmp_dir) / "addons"
        for name in ("has_base", "has_helpdesk"):
            mod_dir = addons_root / name
            mod_dir.mkdir(parents=True)
            (mod_dir / "__manifest__.py").write_text(
                f'{{"name": "{name}", "version": "19.0.1.0.0", "depends": ["base"]}}'
            )
        self.addons_path = str(addons_root)

    def test_valid_addons_pass(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[install]\naddons = ["has_base", "has_helpdesk"]\n',
        )
        op_set = load_operation_set(str(path))
        # Should not raise
        validate_operation_set_addons(op_set, addons_path=self.addons_path)

    def test_unknown_addon_fails(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[install]\naddons = ["has_base", "has_missing"]\n',
        )
        op_set = load_operation_set(str(path))
        with self.assertRaises(ConfigError) as cm:
            validate_operation_set_addons(op_set, addons_path=self.addons_path)
        self.assertIn("has_missing", str(cm.exception))

    def test_validates_test_pre_install_addons(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[test]\ninstall = ["has_base"]\nupdate = ["has_missing"]\n',
        )
        op_set = load_operation_set(str(path))
        with self.assertRaises(ConfigError) as cm:
            validate_operation_set_addons(op_set, addons_path=self.addons_path)
        self.assertIn("has_missing", str(cm.exception))

    def test_validates_coverage_addon(self):
        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            '[test]\ncoverage = "has_missing"\n',
        )
        op_set = load_operation_set(str(path))
        with self.assertRaises(ConfigError) as cm:
            validate_operation_set_addons(op_set, addons_path=self.addons_path)
        self.assertIn("has_missing", str(cm.exception))


class TestSectionRequirement(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def test_install_mode_requires_install_section(self):
        from oduit.operation_sets import require_section

        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            "[update]\naddons = []\n",
        )
        op_set = load_operation_set(str(path))
        with self.assertRaises(ConfigError):
            require_section(op_set, "install")

    def test_apply_mode_does_not_require_any_section(self):
        from oduit.operation_sets import require_section

        path = _write_toml(
            Path(self.tmp_dir),
            "set.toml",
            "[update]\naddons = []\n",
        )
        op_set = load_operation_set(str(path))
        # Should not raise for apply
        require_section(op_set, "apply")


if __name__ == "__main__":
    unittest.main()
