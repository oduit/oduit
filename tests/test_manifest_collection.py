# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.


import pytest

from oduit.addons_path_manager import AddonsPathManager
from oduit.manifest import Manifest, ManifestError
from oduit.manifest_collection import ManifestCollection


@pytest.fixture
def sample_manifests():
    """Create sample manifests for testing."""
    manifest_sale = Manifest.from_dict(
        {
            "name": "Sales",
            "version": "1.0.0",
            "depends": ["base", "web"],
            "installable": True,
            "auto_install": False,
        },
        module_name="sale",
    )

    manifest_crm = Manifest.from_dict(
        {
            "name": "CRM",
            "version": "1.0.0",
            "depends": ["base", "sale"],
            "installable": True,
            "auto_install": False,
        },
        module_name="crm",
    )

    manifest_auto = Manifest.from_dict(
        {
            "name": "Auto Install Module",
            "version": "1.0.0",
            "depends": ["base"],
            "installable": True,
            "auto_install": True,
        },
        module_name="auto_module",
    )

    manifest_not_installable = Manifest.from_dict(
        {
            "name": "Not Installable",
            "version": "1.0.0",
            "depends": ["base"],
            "installable": False,
            "auto_install": False,
        },
        module_name="not_installable",
    )

    return {
        "sale": manifest_sale,
        "crm": manifest_crm,
        "auto_module": manifest_auto,
        "not_installable": manifest_not_installable,
    }


@pytest.fixture
def empty_collection():
    """Create an empty ManifestCollection."""
    return ManifestCollection()


@pytest.fixture
def populated_collection(sample_manifests):
    """Create a populated ManifestCollection."""
    collection = ManifestCollection()
    for name, manifest in sample_manifests.items():
        collection.add(name, manifest)
    return collection


def test_init_empty_collection(empty_collection):
    """Test creating an empty ManifestCollection."""
    assert len(empty_collection) == 0


def test_add_manifest(empty_collection, sample_manifests):
    """Test adding a manifest to the collection."""
    empty_collection.add("sale", sample_manifests["sale"])
    assert len(empty_collection) == 1
    assert "sale" in empty_collection


def test_remove_manifest(populated_collection):
    """Test removing a manifest from the collection."""
    populated_collection.remove("sale")
    assert "sale" not in populated_collection
    assert len(populated_collection) == 3


def test_remove_nonexistent_raises_key_error(empty_collection):
    """Test removing a non-existent manifest raises KeyError."""
    with pytest.raises(KeyError):
        empty_collection.remove("nonexistent")


def test_get_manifest(populated_collection, sample_manifests):
    """Test getting a manifest by name."""
    manifest = populated_collection.get("sale")
    assert manifest is not None
    assert manifest.module_name == "sale"


def test_get_nonexistent_returns_none(empty_collection):
    """Test getting a non-existent manifest returns None."""
    assert empty_collection.get("nonexistent") is None


def test_getitem_manifest(populated_collection):
    """Test dict-like access to manifests."""
    manifest = populated_collection["sale"]
    assert manifest.module_name == "sale"


def test_getitem_nonexistent_raises_key_error(empty_collection):
    """Test dict-like access with non-existent key raises KeyError."""
    with pytest.raises(KeyError):
        _ = empty_collection["nonexistent"]


def test_contains(populated_collection):
    """Test __contains__ method."""
    assert "sale" in populated_collection
    assert "crm" in populated_collection
    assert "nonexistent" not in populated_collection


def test_len(populated_collection):
    """Test __len__ method."""
    assert len(populated_collection) == 4


def test_iter(populated_collection):
    """Test iterating over addon names."""
    names = list(populated_collection)
    assert set(names) == {"sale", "crm", "auto_module", "not_installable"}


def test_items(populated_collection):
    """Test items() method."""
    items = list(populated_collection.items())
    assert len(items) == 4
    for name, manifest in items:
        assert isinstance(name, str)
        assert isinstance(manifest, Manifest)


def test_keys(populated_collection):
    """Test keys() method."""
    keys = list(populated_collection.keys())
    assert set(keys) == {"sale", "crm", "auto_module", "not_installable"}


def test_values(populated_collection):
    """Test values() method."""
    values = list(populated_collection.values())
    assert len(values) == 4
    assert all(isinstance(v, Manifest) for v in values)


def test_add_from_path_valid_directory(tmp_path):
    """Test adding manifests from a valid addon directory."""
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

    assert len(collection) == 2
    assert "module_a" in collection
    assert "module_b" in collection


def test_add_from_path_skip_files(tmp_path):
    """Test that add_from_path skips regular files."""
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


def test_add_from_path_skip_dirs_without_manifest(tmp_path):
    """Test that add_from_path skips directories without __manifest__.py."""
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


def test_add_from_path_nonexistent_directory():
    """Test add_from_path with non-existent path."""
    manager = AddonsPathManager("/nonexistent/path")
    collection = manager.get_collection_from_path("/nonexistent/path")
    assert len(collection) == 0


def test_add_from_path_not_a_directory(tmp_path):
    """Test add_from_path when path is a file."""
    file_path = tmp_path / "file.txt"
    file_path.write_text("content")

    manager = AddonsPathManager(str(file_path))
    collection = manager.get_collection_from_path(str(file_path))
    assert len(collection) == 0


def test_add_from_path_invalid_manifest_skip(tmp_path):
    """Test add_from_path with skip_invalid=True."""
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


def test_add_from_path_invalid_manifest_raises(tmp_path):
    """Test add_from_path raises ManifestError when skip_invalid=False."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text("invalid python syntax {[")

    manager = AddonsPathManager(str(addon_dir))
    with pytest.raises(ManifestError):
        manager.get_collection_from_path(str(addon_dir), skip_invalid=False)


def test_get_all_dependencies(populated_collection):
    """Test getting all unique dependencies."""
    deps = populated_collection.get_all_dependencies()
    assert deps == {"base", "web", "sale"}


def test_get_all_dependencies_empty(empty_collection):
    """Test getting dependencies from empty collection."""
    deps = empty_collection.get_all_dependencies()
    assert deps == set()


def test_get_installable_addons(populated_collection):
    """Test getting installable addons."""
    installable = populated_collection.get_installable_addons()
    assert set(installable) == {"sale", "crm", "auto_module"}
    assert "not_installable" not in installable


def test_get_auto_install_addons(populated_collection):
    """Test getting auto-install addons."""
    auto_install = populated_collection.get_auto_install_addons()
    assert auto_install == ["auto_module"]


def test_filter_by_dependency(populated_collection):
    """Test filtering by dependency."""
    filtered = populated_collection.filter_by_dependency("sale")
    assert len(filtered) == 1
    assert "crm" in filtered
    assert "sale" not in filtered


def test_filter_by_dependency_multiple_matches(populated_collection):
    """Test filtering by dependency with multiple matches."""
    filtered = populated_collection.filter_by_dependency("base")
    assert len(filtered) == 4
    assert "sale" in filtered
    assert "crm" in filtered
    assert "auto_module" in filtered
    assert "not_installable" in filtered


def test_filter_by_dependency_no_matches(populated_collection):
    """Test filtering by dependency with no matches."""
    filtered = populated_collection.filter_by_dependency("nonexistent")
    assert len(filtered) == 0


def test_validate_all_no_issues():
    """Test validating all manifests with no issues."""
    collection = ManifestCollection()

    manifest_valid = Manifest.from_dict(
        {
            "name": "Valid Module",
            "version": "1.0.0",
            "summary": "A valid module",
            "depends": ["base"],
        },
        module_name="valid_module",
    )
    collection.add("valid_module", manifest_valid)

    issues = collection.validate_all()
    assert len(issues) == 0


def test_validate_all_with_issues():
    """Test validating all manifests with issues."""
    collection = ManifestCollection()

    manifest_missing_name = Manifest.from_dict(
        {"version": "1.0.0", "depends": ["base"]}, module_name="missing_name"
    )
    collection.add("missing_name", manifest_missing_name)

    manifest_missing_version = Manifest.from_dict(
        {"name": "Missing Version", "depends": ["base"]}, module_name="missing_version"
    )
    collection.add("missing_version", manifest_missing_version)

    issues = collection.validate_all()

    assert len(issues) == 2
    assert "missing_name" in issues
    assert "missing_version" in issues


def test_clear(populated_collection):
    """Test clearing all manifests from collection."""
    populated_collection.clear()
    assert len(populated_collection) == 0


def test_str_representation(populated_collection):
    """Test string representation."""
    s = str(populated_collection)
    assert "ManifestCollection" in s
    assert "4 manifests" in s


def test_repr_representation(populated_collection):
    """Test developer representation."""
    r = repr(populated_collection)
    assert "ManifestCollection" in r
    assert "sale" in r
    assert "crm" in r
    assert "auto_module" in r
    assert "not_installable" in r
