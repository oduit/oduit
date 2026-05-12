# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
from collections.abc import Iterator

from manifestoo_core.core_addons import is_core_ce_addon
from manifestoo_core.odoo_series import OdooSeries, detect_from_addon_version

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
        self._detected_odoo_series_cache: OdooSeries | None = None
        self._odoo_series_checked = False

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

    def get_base_addons_paths(self) -> list[str]:
        """Get auto-discovered base Odoo addon paths."""
        return list(self._find_odoo_base_addons_paths())

    def _detect_odoo_series(self) -> OdooSeries | None:
        """Detect the Odoo series from addon manifest versions."""
        if self._odoo_series_checked:
            return self._detected_odoo_series_cache

        self._odoo_series_checked = True
        for path in self.get_all_paths():
            for _, manifest in self._iter_modules_in_path(path, skip_invalid=True):
                if manifest.version:
                    series = detect_from_addon_version(manifest.version)
                    if series:
                        self._detected_odoo_series_cache = series
                        return series

        return None

    @staticmethod
    def _classify_official_module_location(location: str) -> tuple[str, str] | None:
        """Return the checkout root plus location kind for standard Odoo layouts."""
        normalized = os.path.normpath(os.path.abspath(location))
        module_parent = os.path.dirname(normalized)
        parent_name = os.path.basename(module_parent)

        if parent_name == "enterprise":
            return os.path.dirname(module_parent), "enterprise"

        if parent_name != "addons":
            return None

        addons_owner = os.path.basename(os.path.dirname(module_parent))
        if addons_owner == "odoo":
            return os.path.dirname(os.path.dirname(module_parent)), "community"

        return None

    def _is_official_enterprise_mirror_duplicate(
        self,
        module_name: str,
        locations: list[str],
        odoo_series: OdooSeries | None,
    ) -> bool:
        """Return True for standard Odoo CE addons mirrored under enterprise."""
        if odoo_series is None or len(locations) != 2:
            return False
        if not is_core_ce_addon(module_name, odoo_series):
            return False

        classified_locations: list[tuple[str, str]] = []
        for location in locations:
            classified_location = self._classify_official_module_location(location)
            if classified_location is None:
                return False
            classified_locations.append(classified_location)

        roots = {root for root, _ in classified_locations}
        kinds = {kind for _, kind in classified_locations}
        return len(roots) == 1 and kinds == {"community", "enterprise"}

    def find_duplicate_module_names(self) -> dict[str, list[str]]:
        """Return module names that appear in more than one addons path."""
        module_locations: dict[str, list[str]] = {}

        for path in self.get_all_paths():
            if not os.path.isdir(path):
                continue

            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                manifest_file = os.path.join(full_path, "__manifest__.py")
                if os.path.isdir(full_path) and os.path.exists(manifest_file):
                    module_locations.setdefault(entry, []).append(full_path)

        odoo_series = self._detect_odoo_series()
        return {
            module_name: locations
            for module_name, locations in module_locations.items()
            if len(locations) > 1
            and not self._is_official_enterprise_mirror_duplicate(
                module_name, locations, odoo_series
            )
        }

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
