# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.


import pytest

from oduit.manifest import ManifestError
from oduit.manifest_collection import ManifestCollection
from oduit.module_manager import ModuleManager


def test_find_modules_returns_collection(tmp_path):
    """Test that find_modules returns a ManifestCollection."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0", "depends": ["base"]}'
    )

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "1.0.0", "depends": ["base", "module_a"]}'
    )

    manager = ModuleManager(str(addon_dir))
    collection = manager.find_modules()

    assert isinstance(collection, ManifestCollection)
    assert len(collection) == 2
    assert "module_a" in collection
    assert "module_b" in collection


def test_find_modules_with_filter_dir(tmp_path):
    """Test find_modules with filter_dir parameter."""
    addons1 = tmp_path / "addons1"
    addons1.mkdir()

    module_a = addons1 / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0"}'
    )

    addons2 = tmp_path / "addons2"
    addons2.mkdir()

    module_b = addons2 / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "1.0.0"}'
    )

    manager = ModuleManager(f"{addons1},{addons2}")
    collection = manager.find_modules(filter_dir="addons1")

    assert len(collection) == 1
    assert "module_a" in collection
    assert "module_b" not in collection


def test_find_modules_skip_invalid_true(tmp_path):
    """Test find_modules with skip_invalid=True."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text("invalid python syntax {[")

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "1.0.0"}'
    )

    manager = ModuleManager(str(addon_dir))
    collection = manager.find_modules(skip_invalid=True)

    assert len(collection) == 1
    assert "module_b" in collection
    assert "module_a" not in collection


def test_find_modules_skip_invalid_false(tmp_path):
    """Test find_modules with skip_invalid=False raises error."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text("invalid python syntax {[")

    manager = ModuleManager(str(addon_dir))

    with pytest.raises(ManifestError):
        manager.find_modules(skip_invalid=False)


def test_find_modules_skip_dirs_without_manifest(tmp_path):
    """Test that find_modules skips directories without __manifest__.py."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "models.py").write_text("# Some code")

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "1.0.0"}'
    )

    manager = ModuleManager(str(addon_dir))
    collection = manager.find_modules()

    assert len(collection) == 1
    assert "module_b" in collection
    assert "module_a" not in collection


def test_find_modules_skip_files(tmp_path):
    """Test that find_modules skips regular files."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    (addon_dir / "README.md").write_text("# Readme")

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0"}'
    )

    manager = ModuleManager(str(addon_dir))
    collection = manager.find_modules()

    assert len(collection) == 1
    assert "module_a" in collection


def test_find_modules_no_duplicates(tmp_path):
    """Test that find_modules doesn't add duplicates."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0"}'
    )

    # Use the same path twice in addons_path
    manager = ModuleManager(f"{addon_dir},{addon_dir}")
    collection = manager.find_modules()

    assert len(collection) == 1
    assert "module_a" in collection


def test_find_modules_empty_directory(tmp_path):
    """Test find_modules with empty directory."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    manager = ModuleManager(str(addon_dir))
    collection = manager.find_modules()

    assert len(collection) == 0


def test_find_modules_accesses_manifest_properties(tmp_path):
    """Test that manifests in collection can be accessed."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "2.0.0", "depends": ["base", "web"]}'
    )

    manager = ModuleManager(str(addon_dir))
    collection = manager.find_modules()

    manifest = collection["module_a"]
    assert manifest.name == "Module A"
    assert manifest.version == "2.0.0"
    assert manifest.codependencies == ["base", "web"]
