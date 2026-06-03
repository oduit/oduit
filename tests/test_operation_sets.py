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
    build_operation_set_location_context,
    load_operation_set,
    resolve_operation_set_path,
    resolve_operation_set_write_path,
    validate_operation_set_addons,
    write_operation_set,
)


def _write_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestResolveOperationSetPath(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.project_dir = self.tmp_dir / "project"
        self.project_dir.mkdir()
        self.global_dir = self.tmp_dir / "config"
        self.global_dir.mkdir()

    def _context(
        self,
        *,
        config_path: Path | None = None,
        config_source: str | None = None,
        cwd: Path | None = None,
    ):
        return build_operation_set_location_context(
            cwd=cwd or self.project_dir,
            config_path=str(config_path) if config_path else None,
            config_source=config_source,
            config_dir=str(self.global_dir),
        )

    def test_exact_file_path(self):
        path = _write_file(
            self.project_dir / "myset.toml",
            'kind = "install"\n[install]\naddons = []\n',
        )
        result = resolve_operation_set_path(str(path), context=self._context())
        self.assertEqual(result.path, path.resolve())
        self.assertEqual(result.source, "direct")

    def test_short_name_with_toml_extension_resolves_from_set_dir(self):
        path = _write_file(
            self.global_dir / "sets" / "base.toml",
            'kind = "install"\n[install]\naddons = []\n',
        )
        result = resolve_operation_set_path("base.toml", context=self._context())
        self.assertEqual(result.path, path.resolve())
        self.assertEqual(result.source, "global_config")

    def test_active_env_config_resolution(self):
        config_path = _write_file(self.global_dir / "dev.toml", "name = 'dev'\n")
        path = _write_file(
            self.global_dir / "sets" / "seta.toml",
            'kind = "install"\n[install]\naddons = []\n',
        )
        result = resolve_operation_set_path(
            "seta",
            context=self._context(config_path=config_path, config_source="env"),
        )
        self.assertEqual(result.path, path.resolve())
        self.assertEqual(result.source, "active_config")

    def test_local_config_resolution(self):
        config_path = _write_file(self.project_dir / ".oduit.toml", "name = 'local'\n")
        path = _write_file(
            self.project_dir / ".oduit" / "sets" / "seta.toml",
            'kind = "install"\n[install]\naddons = []\n',
        )
        result = resolve_operation_set_path(
            "seta",
            context=self._context(config_path=config_path, config_source="local"),
        )
        self.assertEqual(result.path, path.resolve())
        self.assertEqual(result.source, "active_config")

    def test_fallback_local_project_resolution(self):
        path = _write_file(
            self.project_dir / ".oduit" / "sets" / "fallback.toml",
            'kind = "install"\n[install]\naddons = []\n',
        )
        result = resolve_operation_set_path("fallback", context=self._context())
        self.assertEqual(result.path, path.resolve())
        self.assertEqual(result.source, "local_project")

    def test_fallback_global_config_resolution(self):
        path = _write_file(
            self.global_dir / "sets" / "global.toml",
            'kind = "install"\n[install]\naddons = []\n',
        )
        result = resolve_operation_set_path(
            "global",
            context=self._context(cwd=self.project_dir / "empty"),
        )
        self.assertEqual(result.path, path.resolve())
        self.assertEqual(result.source, "global_config")

    def test_legacy_no_extension_fallback(self):
        path = _write_file(
            self.project_dir / ".oduit" / "sets" / "legacy",
            'kind = "install"\n[install]\naddons = []\n',
        )
        result = resolve_operation_set_path("legacy", context=self._context())
        self.assertEqual(result.path, path.resolve())

    def test_unresolved_short_name_raises(self):
        with self.assertRaises(ConfigError) as cm:
            resolve_operation_set_path("missing", context=self._context())
        message = str(cm.exception)
        self.assertIn("missing", message)
        self.assertIn(".oduit/sets", message)
        self.assertIn("config/sets", message)


class TestResolveOperationSetWritePath(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.project_dir = self.tmp_dir / "project"
        self.project_dir.mkdir()
        self.global_dir = self.tmp_dir / "config"
        self.global_dir.mkdir()

    def _context(
        self,
        *,
        config_path: Path | None = None,
        config_source: str | None = None,
    ):
        return build_operation_set_location_context(
            cwd=self.project_dir,
            config_path=str(config_path) if config_path else None,
            config_source=config_source,
            config_dir=str(self.global_dir),
        )

    def test_bare_name_writes_to_active_local_set_dir(self):
        config_path = _write_file(self.project_dir / ".oduit.toml", "name = 'local'\n")
        result = resolve_operation_set_write_path(
            "snapshot",
            context=self._context(config_path=config_path, config_source="local"),
        )
        self.assertEqual(
            result.path,
            (self.project_dir / ".oduit" / "sets" / "snapshot.toml").resolve(),
        )
        self.assertEqual(result.source, "active_config")

    def test_explicit_path_writes_exactly_there(self):
        result = resolve_operation_set_write_path(
            "custom/output.toml",
            context=self._context(),
        )
        self.assertEqual(
            result.path,
            (self.project_dir / "custom" / "output.toml").resolve(),
        )
        self.assertEqual(result.source, "explicit")

    def test_existing_file_rejects_without_overwrite(self):
        path = _write_file(
            self.global_dir / "sets" / "snapshot.toml",
            'kind = "install"\n[install]\naddons = []\n',
        )
        with self.assertRaises(ConfigError) as cm:
            resolve_operation_set_write_path(
                "snapshot",
                context=self._context(),
            )
        self.assertIn(str(path.resolve()), str(cm.exception))
        self.assertIn("--overwrite", str(cm.exception))


class TestLoadOperationSet(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())

    def test_missing_kind_raises(self):
        path = _write_file(self.tmp_dir / "bad.toml", "[install]\naddons = []\n")
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("missing required top-level key 'kind'", str(cm.exception))

    def test_invalid_kind_raises(self):
        path = _write_file(
            self.tmp_dir / "bad.toml",
            'kind = "deploy"\n[install]\naddons = []\n',
        )
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("kind must be one of install, update, test", str(cm.exception))

    def test_kind_install_forbids_test_section(self):
        path = _write_file(
            self.tmp_dir / "bad.toml",
            'kind = "install"\n[test]\ntest_tags = ["/sale"]\n',
        )
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("kind 'install' requires [install]", str(cm.exception))
        self.assertIn("forbids [test]", str(cm.exception))

    def test_kind_test_forbids_install_section(self):
        path = _write_file(
            self.tmp_dir / "bad.toml",
            'kind = "test"\n[install]\naddons = ["sale"]\n'
            '[test]\ntest_tags = ["/sale"]\n',
        )
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("kind 'test' requires [test]", str(cm.exception))
        self.assertIn("forbids [install]", str(cm.exception))

    def test_schema_version_defaults_and_metadata_passthrough(self):
        path = _write_file(
            self.tmp_dir / "set.toml",
            'kind = "install"\nname = "snapshot"\n'
            '[metadata]\ncreated_by = "oduit"\n'
            '[source]\ncommand = "list-installed-addons"\n'
            '[install]\naddons = ["sale"]\n',
        )
        operation_set = load_operation_set(str(path))
        self.assertEqual(operation_set.schema_version, 2)
        self.assertEqual(operation_set.kind, "install")
        self.assertEqual(operation_set.metadata["created_by"], "oduit")
        self.assertEqual(operation_set.source["command"], "list-installed-addons")

    def test_non_default_schema_version_raises(self):
        path = _write_file(
            self.tmp_dir / "bad.toml",
            'schema_version = 1\nkind = "install"\n[install]\naddons = []\n',
        )
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("schema_version must be 2", str(cm.exception))

    def test_test_files_resolve_relative_to_set(self):
        test_file = _write_file(
            self.tmp_dir / "addons" / "sale" / "tests" / "test_flow.py",
            "# test\n",
        )
        path = _write_file(
            self.tmp_dir / "set.toml",
            'kind = "test"\n[test]\ntest_files = ["addons/sale/tests/test_flow.py"]\n',
        )
        operation_set = load_operation_set(str(path))
        assert operation_set.test is not None
        self.assertEqual(operation_set.test.test_files, (test_file.resolve(),))

    def test_missing_test_files_allowed(self):
        path = _write_file(
            self.tmp_dir / "set.toml",
            'kind = "test"\n[test]\ntest_files = ["missing.py"]\n',
        )
        operation_set = load_operation_set(str(path), allow_missing_test_files=True)
        assert operation_set.test is not None
        self.assertEqual(operation_set.test.test_file_inputs, ("missing.py",))

    def test_non_toml_file_raises_on_load(self):
        path = _write_file(self.tmp_dir / "set.yaml", "key: value\n")
        with self.assertRaises(ConfigError) as cm:
            load_operation_set(str(path))
        self.assertIn("TOML", str(cm.exception))


class TestWriteOperationSet(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.project_dir = self.tmp_dir / "project"
        self.project_dir.mkdir()
        self.global_dir = self.tmp_dir / "config"
        self.global_dir.mkdir()
        self.context = build_operation_set_location_context(
            cwd=self.project_dir,
            config_path=str(self.global_dir / "dev.toml"),
            config_source="env",
            config_dir=str(self.global_dir),
        )

    def test_install_kind_writes_install_section(self):
        result = write_operation_set(
            "snapshot",
            kind="install",
            addons=["sale", "crm"],
            context=self.context,
        )
        self.assertEqual(result.kind, "install")
        operation_set = load_operation_set("snapshot", context=self.context)
        assert operation_set.install is not None
        self.assertEqual(operation_set.install.addons, ("sale", "crm"))

    def test_update_kind_writes_update_section(self):
        write_operation_set(
            "snapshot_update",
            kind="update",
            addons=["sale"],
            context=self.context,
        )
        operation_set = load_operation_set("snapshot_update", context=self.context)
        assert operation_set.update is not None
        self.assertEqual(operation_set.update.addons, ("sale",))

    def test_test_kind_writes_test_defaults(self):
        write_operation_set(
            "snapshot_tests",
            kind="test",
            addons=["sale", "crm"],
            context=self.context,
        )
        operation_set = load_operation_set("snapshot_tests", context=self.context)
        assert operation_set.test is not None
        self.assertEqual(operation_set.test.install, ("sale", "crm"))
        self.assertEqual(operation_set.test.test_tags, ("/sale", "/crm"))


class TestAddonValidation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        addons_root = self.tmp_dir / "addons"
        for name in ("has_base", "has_helpdesk"):
            module_dir = addons_root / name
            module_dir.mkdir(parents=True)
            (module_dir / "__manifest__.py").write_text(
                f'{{"name": "{name}", "version": "19.0.1.0.0", "depends": ["base"]}}',
                encoding="utf-8",
            )
        self.addons_path = str(addons_root)

    def test_valid_addons_pass(self):
        path = _write_file(
            self.tmp_dir / "set.toml",
            'kind = "install"\n[install]\naddons = ["has_base", "has_helpdesk"]\n',
        )
        operation_set = load_operation_set(str(path))
        validate_operation_set_addons(operation_set, addons_path=self.addons_path)

    def test_unknown_addon_fails(self):
        path = _write_file(
            self.tmp_dir / "set.toml",
            'kind = "install"\n[install]\naddons = ["has_base", "has_missing"]\n',
        )
        operation_set = load_operation_set(str(path))
        with self.assertRaises(ConfigError) as cm:
            validate_operation_set_addons(operation_set, addons_path=self.addons_path)
        self.assertIn("has_missing", str(cm.exception))

    def test_validates_test_pre_install_addons(self):
        path = _write_file(
            self.tmp_dir / "set.toml",
            'kind = "test"\n[test]\ninstall = ["has_base"]\nupdate = ["has_missing"]\n',
        )
        operation_set = load_operation_set(str(path))
        with self.assertRaises(ConfigError) as cm:
            validate_operation_set_addons(operation_set, addons_path=self.addons_path)
        self.assertIn("has_missing", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
