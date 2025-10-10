# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.


import pytest

from oduit.addons_path_manager import AddonsPathManager
from oduit.manifest import Manifest, ManifestError
from oduit.manifest_collection import ManifestCollection


def test_get_collection_from_path_valid_directory(tmp_path):
    """Test getting collection from a valid addon directory."""
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

    manager = AddonsPathManager(str(addon_dir))
    collection = manager.get_collection_from_path(str(addon_dir))

    assert isinstance(collection, ManifestCollection)
    assert len(collection) == 2
    assert "module_a" in collection
    assert "module_b" in collection


def test_get_collection_from_path_skip_files(tmp_path):
    """Test that get_collection_from_path skips regular files."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    (addon_dir / "README.md").write_text("# Readme")

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0"}'
    )

    manager = AddonsPathManager(str(addon_dir))
    collection = manager.get_collection_from_path(str(addon_dir))

    assert len(collection) == 1
    assert "module_a" in collection


def test_get_collection_from_path_skip_dirs_without_manifest(tmp_path):
    """Test that get_collection_from_path skips directories without __manifest__.py."""
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

    manager = AddonsPathManager(str(addon_dir))
    collection = manager.get_collection_from_path(str(addon_dir))

    assert len(collection) == 1
    assert "module_b" in collection
    assert "module_a" not in collection


def test_get_collection_from_path_invalid_manifest_skip(tmp_path):
    """Test get_collection_from_path with skip_invalid=True."""
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

    manager = AddonsPathManager(str(addon_dir))
    collection = manager.get_collection_from_path(str(addon_dir), skip_invalid=True)

    assert len(collection) == 1
    assert "module_b" in collection
    assert "module_a" not in collection


def test_get_collection_from_path_invalid_manifest_raises(tmp_path):
    """Test get_collection_from_path raises ManifestError when skip_invalid=False."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text("invalid python syntax {[")

    manager = AddonsPathManager(str(addon_dir))
    with pytest.raises(ManifestError):
        manager.get_collection_from_path(str(addon_dir), skip_invalid=False)


def test_get_collection_from_paths_multiple_paths(tmp_path):
    """Test getting collection from multiple paths."""
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

    manager = AddonsPathManager(f"{addons1},{addons2}")
    collection = manager.get_collection_from_paths([str(addons1), str(addons2)])

    assert len(collection) == 2
    assert "module_a" in collection
    assert "module_b" in collection


def test_get_collection_from_paths_no_duplicates(tmp_path):
    """Test that get_collection_from_paths doesn't add duplicates."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0"}'
    )

    manager = AddonsPathManager(str(addon_dir))
    collection = manager.get_collection_from_paths([str(addon_dir), str(addon_dir)])

    assert len(collection) == 1
    assert "module_a" in collection


def test_get_all_collections(tmp_path):
    """Test getting all collections from all configured paths."""
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

    manager = AddonsPathManager(f"{addons1},{addons2}")
    collection = manager.get_all_collections()

    assert len(collection) == 2
    assert "module_a" in collection
    assert "module_b" in collection


def test_get_collection_by_filter(tmp_path):
    """Test getting collection filtered by directory basename."""
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

    manager = AddonsPathManager(f"{addons1},{addons2}")
    collection = manager.get_collection_by_filter("addons1")

    assert len(collection) == 1
    assert "module_a" in collection
    assert "module_b" not in collection


def test_find_module_path(tmp_path):
    """Test finding module path."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0"}'
    )

    manager = AddonsPathManager(str(addon_dir))
    path = manager.find_module_path("module_a")

    assert path == str(module_a)


def test_find_module_path_not_found(tmp_path):
    """Test finding non-existent module."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    manager = AddonsPathManager(str(addon_dir))
    path = manager.find_module_path("nonexistent")

    assert path is None


def test_get_manifest(tmp_path):
    """Test getting manifest for a module."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0", "depends": ["base"]}'
    )

    manager = AddonsPathManager(str(addon_dir))
    manifest = manager.get_manifest("module_a")

    assert manifest is not None
    assert isinstance(manifest, Manifest)
    assert manifest.name == "Module A"
    assert manifest.version == "1.0.0"
    assert manifest.codependencies == ["base"]


def test_get_manifest_not_found(tmp_path):
    """Test getting manifest for non-existent module."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    manager = AddonsPathManager(str(addon_dir))
    manifest = manager.get_manifest("nonexistent")

    assert manifest is None


def test_get_module_names(tmp_path):
    """Test getting all module names."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0"}'
    )

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "1.0.0"}'
    )

    manager = AddonsPathManager(str(addon_dir))
    names = manager.get_module_names()

    assert names == ["module_a", "module_b"]


def test_get_module_names_with_filter(tmp_path):
    """Test getting module names with filter."""
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

    manager = AddonsPathManager(f"{addons1},{addons2}")
    names = manager.get_module_names(filter_dir="addons1")

    assert names == ["module_a"]
