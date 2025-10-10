# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
from collections.abc import Iterator

from .manifest import Manifest, ManifestError
from .manifest_collection import ManifestCollection


class AddonsPathManager:
    """Manages discovery and loading of Odoo modules from addons paths."""

    def __init__(self, addons_path: str):
        """Initialize AddonsPathManager with comma-separated addons paths.

        Args:
            addons_path: Comma-separated string of addon directory paths
        """
        self.addons_path = addons_path
        self._base_addons_paths_cache: list[str] | None = None

    def _find_odoo_base_addons_paths(self) -> list[str]:
        """Find Odoo base addons paths by looking for odoo-bin in parent dirs.

        Returns:
            List of base addons paths found
        """
        if self._base_addons_paths_cache is not None:
            return self._base_addons_paths_cache

        base_paths = []

        for path in self._parse_paths(self.addons_path):
            path = os.path.abspath(path)

            for subdir in [".", "..", "../..", "../../.."]:
                check_dir = os.path.normpath(os.path.join(path, subdir))
                potential_odoo_bin = os.path.join(check_dir, "odoo-bin")

                if os.path.exists(potential_odoo_bin):
                    base_addons_path = os.path.join(check_dir, "odoo", "addons")
                    if (
                        os.path.isdir(base_addons_path)
                        and base_addons_path not in base_paths
                    ):
                        base_paths.append(base_addons_path)
                    break

        self._base_addons_paths_cache = base_paths
        return base_paths

    def _parse_paths(self, paths: str) -> list[str]:
        """Parse comma-separated paths string into list.

        Args:
            paths: Comma-separated string of paths

        Returns:
            List of non-empty paths
        """
        return [p.strip() for p in paths.split(",") if p.strip()]

    def get_all_paths(self) -> list[str]:
        """Get all addon paths (configured + base Odoo paths).

        Returns:
            List of all addon paths
        """
        return self._parse_paths(self.addons_path) + self._find_odoo_base_addons_paths()

    def get_configured_paths(self) -> list[str]:
        """Get only configured addon paths (excluding base Odoo paths).

        Returns:
            List of configured addon paths
        """
        return self._parse_paths(self.addons_path)

    def _iter_modules_in_path(
        self, path: str, skip_invalid: bool = False
    ) -> Iterator[tuple[str, Manifest]]:
        """Iterate over modules in a single addon path.

        Args:
            path: Path to addon directory
            skip_invalid: If True, skip modules with invalid manifests

        Yields:
            Tuple of (module_name, Manifest)

        Raises:
            ManifestError: If manifest is invalid and skip_invalid is False
        """
        if not os.path.isdir(path):
            return

        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)

            if not os.path.isdir(full_path):
                continue

            manifest_file = os.path.join(full_path, "__manifest__.py")
            if not os.path.exists(manifest_file):
                continue

            try:
                manifest = Manifest(full_path)
                yield entry, manifest
            except ManifestError:
                if not skip_invalid:
                    raise

    def get_collection_from_path(
        self, path: str, skip_invalid: bool = False
    ) -> ManifestCollection:
        """Get ManifestCollection from a specific addon path.

        Args:
            path: Path to addon directory
            skip_invalid: If True, skip modules with invalid manifests

        Returns:
            ManifestCollection containing modules from the specified path

        Raises:
            ManifestError: If manifest is invalid and skip_invalid is False
        """
        collection = ManifestCollection()

        for module_name, manifest in self._iter_modules_in_path(path, skip_invalid):
            collection.add(module_name, manifest)

        return collection

    def get_collection_from_paths(
        self, paths: list[str], skip_invalid: bool = False
    ) -> ManifestCollection:
        """Get ManifestCollection from multiple specific addon paths.

        Args:
            paths: List of addon directory paths
            skip_invalid: If True, skip modules with invalid manifests

        Returns:
            ManifestCollection containing modules from all specified paths
            (duplicates are excluded)

        Raises:
            ManifestError: If manifest is invalid and skip_invalid is False
        """
        collection = ManifestCollection()

        for path in paths:
            for module_name, manifest in self._iter_modules_in_path(path, skip_invalid):
                if module_name not in collection:
                    collection.add(module_name, manifest)

        return collection

    def get_all_collections(self, skip_invalid: bool = False) -> ManifestCollection:
        """Get ManifestCollection from all configured and base addon paths.

        Args:
            skip_invalid: If True, skip modules with invalid manifests

        Returns:
            ManifestCollection containing all modules from all paths
            (duplicates are excluded)

        Raises:
            ManifestError: If manifest is invalid and skip_invalid is False
        """
        return self.get_collection_from_paths(self.get_all_paths(), skip_invalid)

    def get_collection_by_filter(
        self, filter_dir: str, skip_invalid: bool = False
    ) -> ManifestCollection:
        """Get ManifestCollection filtered by directory basename.

        Args:
            filter_dir: Directory basename to filter by
            skip_invalid: If True, skip modules with invalid manifests

        Returns:
            ManifestCollection containing modules from paths matching filter

        Raises:
            ManifestError: If manifest is invalid and skip_invalid is False
        """
        collection = ManifestCollection()

        for path in self.get_all_paths():
            path_basename = os.path.basename(path.rstrip("/"))
            if path_basename == filter_dir:
                for module_name, manifest in self._iter_modules_in_path(
                    path, skip_invalid
                ):
                    if module_name not in collection:
                        collection.add(module_name, manifest)

        return collection

    def find_module_path(self, module_name: str) -> str | None:
        """Find the absolute path to a module.

        Args:
            module_name: Name of the module to find

        Returns:
            Absolute path to module directory or None if not found
        """
        for path in self.get_all_paths():
            if not os.path.isdir(path):
                continue

            module_path = os.path.join(path, module_name)
            if os.path.isdir(module_path) and os.path.exists(
                os.path.join(module_path, "__manifest__.py")
            ):
                return module_path

        return None

    def get_manifest(self, module_name: str) -> Manifest | None:
        """Get the manifest for a module.

        Args:
            module_name: Name of the module

        Returns:
            Manifest instance or None if module not found
        """
        module_path = self.find_module_path(module_name)
        if not module_path:
            return None

        try:
            return Manifest(module_path)
        except ManifestError:
            return None

    def get_module_names(self, filter_dir: str | None = None) -> list[str]:
        """Get sorted list of all module names.

        Args:
            filter_dir: Optional directory basename to filter by

        Returns:
            Sorted list of module names
        """
        module_names: set[str] = set()

        for path in self.get_all_paths():
            if filter_dir:
                path_basename = os.path.basename(path.rstrip("/"))
                if path_basename != filter_dir:
                    continue

            if os.path.isdir(path):
                for entry in os.listdir(path):
                    full_path = os.path.join(path, entry)
                    if os.path.isdir(full_path) and os.path.exists(
                        os.path.join(full_path, "__manifest__.py")
                    ):
                        module_names.add(entry)

        return sorted(module_names)
