# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

from collections.abc import Iterator

from .manifest import Manifest


class ManifestCollection:
    """Represents a collection of Odoo module manifests."""

    def __init__(self) -> None:
        """Initialize an empty ManifestCollection."""
        self._manifests: dict[str, Manifest] = {}

    def add(self, addon_name: str, manifest: Manifest) -> None:
        """Add a manifest to the collection.

        Args:
            addon_name: Name of the addon
            manifest: Manifest instance to add
        """
        self._manifests[addon_name] = manifest

    def remove(self, addon_name: str) -> None:
        """Remove a manifest from the collection.

        Args:
            addon_name: Name of the addon to remove

        Raises:
            KeyError: If addon_name is not in the collection
        """
        del self._manifests[addon_name]

    def get(self, addon_name: str) -> Manifest | None:
        """Get a manifest by addon name.

        Args:
            addon_name: Name of the addon

        Returns:
            Manifest instance or None if not found
        """
        return self._manifests.get(addon_name)

    def __getitem__(self, addon_name: str) -> Manifest:
        """Get a manifest by addon name using dict-like access.

        Args:
            addon_name: Name of the addon

        Returns:
            Manifest instance

        Raises:
            KeyError: If addon_name is not in the collection
        """
        return self._manifests[addon_name]

    def __contains__(self, addon_name: str) -> bool:
        """Check if an addon is in the collection.

        Args:
            addon_name: Name of the addon to check

        Returns:
            True if addon exists in collection, False otherwise
        """
        return addon_name in self._manifests

    def __len__(self) -> int:
        """Get the number of manifests in the collection.

        Returns:
            Number of manifests
        """
        return len(self._manifests)

    def __iter__(self) -> Iterator[str]:
        """Iterate over addon names in the collection.

        Returns:
            Iterator over addon names
        """
        return iter(self._manifests)

    def items(self) -> Iterator[tuple[str, Manifest]]:
        """Get iterator over (addon_name, manifest) pairs.

        Returns:
            Iterator of tuples containing addon name and Manifest
        """
        return iter(self._manifests.items())

    def keys(self) -> Iterator[str]:
        """Get iterator over addon names.

        Returns:
            Iterator over addon names
        """
        return iter(self._manifests.keys())

    def values(self) -> Iterator[Manifest]:
        """Get iterator over manifests.

        Returns:
            Iterator over Manifest instances
        """
        return iter(self._manifests.values())

    def get_all_dependencies(self) -> set[str]:
        """Get all unique codependencies across all manifests in the collection.

        Returns:
            Set of all codependency names
        """
        all_deps = set()
        for manifest in self._manifests.values():
            all_deps.update(manifest.codependencies)
        return all_deps

    def get_installable_addons(self) -> list[str]:
        """Get list of all installable addon names.

        Returns:
            List of addon names that are installable
        """
        return [
            name for name, manifest in self._manifests.items() if manifest.installable
        ]

    def get_auto_install_addons(self) -> list[str]:
        """Get list of all auto-install addon names.

        Returns:
            List of addon names that are auto-installable
        """
        return [
            name for name, manifest in self._manifests.items() if manifest.auto_install
        ]

    def filter_by_dependency(self, dependency_name: str) -> "ManifestCollection":
        """Create a new collection with only addons that depend on a specific module.

        Args:
            dependency_name: Name of the dependency to filter by

        Returns:
            New ManifestCollection containing only matching addons
        """
        filtered = ManifestCollection()
        for name, manifest in self._manifests.items():
            if manifest.has_dependency(dependency_name):
                filtered.add(name, manifest)
        return filtered

    def validate_all(self) -> dict[str, list[str]]:
        """Validate all manifests in the collection.

        Returns:
            Dictionary mapping addon names to lists of validation warnings
            (only includes addons with warnings)
        """
        issues = {}
        for name, manifest in self._manifests.items():
            warnings = manifest.validate_structure()
            if warnings:
                issues[name] = warnings
        return issues

    def clear(self) -> None:
        """Remove all manifests from the collection."""
        self._manifests.clear()

    def __str__(self) -> str:
        """String representation of the collection."""
        return f"ManifestCollection({len(self._manifests)} manifests)"

    def __repr__(self) -> str:
        """Developer representation of the collection."""
        addon_list = ", ".join(sorted(self._manifests.keys()))
        return f"ManifestCollection([{addon_list}])"
