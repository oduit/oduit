from __future__ import annotations

import os
from typing import Any

from manifestoo_core.odoo_series import OdooSeries

from ..addons_path_manager import AddonsPathManager
from ..api_models import (
    AddonInfo,
    AddonInspection,
    AddonsPathStatus,
    DatabaseSummary,
    EnvironmentContext,
    EnvironmentSource,
    OdooVersionInfo,
    UpdatePlan,
)
from ..exceptions import ModuleNotFoundError
from ..module_manager import ModuleManager
from ..source_locator import list_addon_languages
from .base import OperationsService


class DiscoveryOperationsService(OperationsService):
    """Environment, addon discovery, and planning helpers."""

    def get_environment_context(
        self,
        env_name: str | None = None,
        config_source: str | None = None,
        config_path: str | None = None,
        odoo_series: OdooSeries | None = None,
    ) -> EnvironmentContext:
        """Return a typed environment snapshot for planning and inspection.

        Args:
            env_name: Optional display name for the active environment.
            config_source: Optional source description such as ``env`` or ``local``.
            config_path: Optional path to the resolved configuration file.
            odoo_series: Optional pre-detected Odoo series override.

        Returns:
            Typed environment context with resolved binaries, addon paths,
            duplicate modules, and doctor-style summary data.
        """
        env_config = self.operations.env_config
        checks: list[dict[str, Any]] = []
        remediation: list[str] = []
        warnings: list[str] = []

        python_info = type(self.operations)._probe_binary(
            env_config.get("python_bin"), ["python3", "python"]
        )
        odoo_info = type(self.operations)._probe_binary(
            env_config.get("odoo_bin"), ["odoo", "odoo-bin"]
        )
        coverage_info = type(self.operations)._probe_binary(
            env_config.get("coverage_bin"), ["coverage"]
        )

        for name, probe, label in (
            ("python_bin", python_info, "python_bin"),
            ("odoo_bin", odoo_info, "odoo_bin"),
            ("coverage_bin", coverage_info, "coverage_bin"),
        ):
            if probe.exists and probe.executable:
                checks.append(
                    type(self.operations)._build_check(
                        name,
                        "ok",
                        f"{label} resolves correctly",
                        details={"resolved_path": probe.resolved_path},
                    )
                )
            else:
                remediation_text = (
                    f"Configure `{label}` so it points to an executable binary."
                )
                checks.append(
                    type(self.operations)._build_check(
                        name,
                        "error" if name != "coverage_bin" else "warning",
                        f"{label} could not be resolved",
                        details={"configured_value": probe.value},
                        remediation=remediation_text,
                    )
                )
                if name != "coverage_bin":
                    remediation.append(remediation_text)
                    warnings.append(f"{label} could not be resolved")

        addons_path = str(env_config.get("addons_path", ""))
        path_manager = AddonsPathManager(addons_path) if addons_path else None
        configured_paths = path_manager.get_configured_paths() if path_manager else []
        base_paths = path_manager.get_base_addons_paths() if path_manager else []
        all_paths = path_manager.get_all_paths() if path_manager else []
        valid_paths: list[str] = []
        invalid_paths: list[str] = []
        for path in configured_paths:
            absolute_path = os.path.abspath(path)
            if os.path.isdir(absolute_path):
                valid_paths.append(absolute_path)
            else:
                invalid_paths.append(path)

        if invalid_paths:
            remediation_text = (
                "Fix `addons_path` so every configured path exists and is a directory."
            )
            checks.append(
                type(self.operations)._build_check(
                    "addons_path",
                    "error",
                    f"Configured addons paths are invalid: {', '.join(invalid_paths)}",
                    details={"invalid_paths": invalid_paths},
                    remediation=remediation_text,
                )
            )
            remediation.append(remediation_text)
            warnings.append("Configured addons paths contain invalid entries")
        elif configured_paths:
            checks.append(
                type(self.operations)._build_check(
                    "addons_path",
                    "ok",
                    f"Configured addons paths are valid ({len(valid_paths)} path(s))",
                    details={"configured_paths": valid_paths},
                )
            )
        else:
            remediation_text = (
                "Set `addons_path` before running addon inspection commands."
            )
            checks.append(
                type(self.operations)._build_check(
                    "addons_path",
                    "error",
                    "addons_path is not configured",
                    remediation=remediation_text,
                )
            )
            remediation.append(remediation_text)

        duplicate_modules = (
            path_manager.find_duplicate_module_names() if path_manager else {}
        )
        if duplicate_modules:
            remediation_text = (
                "Remove or reorder duplicate addon paths to avoid ambiguous "
                "module resolution."
            )
            checks.append(
                type(self.operations)._build_check(
                    "duplicate_addons",
                    "warning",
                    "Duplicate addon names found: "
                    f"{', '.join(sorted(duplicate_modules))}",
                    details={"duplicates": duplicate_modules},
                    remediation=remediation_text,
                )
            )
            remediation.append(remediation_text)
            warnings.append("Duplicate addon names found")

        module_manager = (
            ModuleManager(addons_path) if addons_path and not invalid_paths else None
        )
        available_module_count = 0
        detected_series = odoo_series
        if module_manager is not None:
            modules = module_manager.find_modules(skip_invalid=True)
            available_module_count = len(modules)
            checks.append(
                type(self.operations)._build_check(
                    "addons_scan",
                    "ok",
                    f"Discovered {available_module_count} addon(s)",
                    details={"module_count": available_module_count},
                )
            )
            if detected_series is None:
                detected_series = module_manager.detect_odoo_series()

        version_result = self.operations.get_odoo_version(suppress_output=True)
        if version_result.get("success") and version_result.get("version"):
            checks.append(
                type(self.operations)._build_check(
                    "odoo_version",
                    "ok",
                    f"Detected Odoo version {version_result['version']}",
                    details={"version": version_result.get("version")},
                )
            )
        else:
            remediation_text = (
                "Check `odoo_bin` and inspect the version command output."
            )
            checks.append(
                type(self.operations)._build_check(
                    "odoo_version",
                    "error",
                    "Failed to detect Odoo version",
                    details={"error": version_result.get("error")},
                    remediation=remediation_text,
                )
            )
            remediation.append(remediation_text)

        db_name = env_config.get("db_name")
        db_user = env_config.get("db_user")
        if db_name:
            status = "ok" if db_user else "warning"
            remediation_text = (
                "Set `db_user` if the default PostgreSQL user is not correct."
            )
            checks.append(
                type(self.operations)._build_check(
                    "db_config",
                    status,
                    f"Database configuration is present for '{db_name}'",
                    details={
                        "db_name": db_name,
                        "db_host": env_config.get("db_host") or "localhost",
                        "db_user": db_user,
                    },
                    remediation=None if db_user else remediation_text,
                )
            )
            if not db_user:
                remediation.append(remediation_text)
                warnings.append("db_user is not configured")
        else:
            checks.append(
                type(self.operations)._build_check(
                    "db_config",
                    "warning",
                    "db_name is not configured",
                    remediation=(
                        "Set `db_name` if this environment should target a database."
                    ),
                )
            )

        summary = {
            "ok": sum(1 for check in checks if check["status"] == "ok"),
            "warning": sum(1 for check in checks if check["status"] == "warning"),
            "error": sum(1 for check in checks if check["status"] == "error"),
        }

        return EnvironmentContext(
            environment=EnvironmentSource(
                name=env_name,
                source=config_source,
                config_path=config_path,
            ),
            resolved_binaries={
                "python_bin": python_info,
                "odoo_bin": odoo_info,
                "coverage_bin": coverage_info,
            },
            addons_paths=AddonsPathStatus(
                configured=configured_paths,
                base=base_paths,
                all=all_paths,
                valid=valid_paths,
                invalid=invalid_paths,
            ),
            odoo=OdooVersionInfo(
                version=version_result.get("version"),
                series=detected_series.value if detected_series else None,
            ),
            database=DatabaseSummary(
                db_name=db_name,
                db_host=env_config.get("db_host") or "localhost",
                db_user=db_user,
            ),
            duplicate_modules=duplicate_modules,
            available_module_count=available_module_count,
            invalid_addon_paths=invalid_paths,
            missing_critical_config=[
                key
                for key in ("python_bin", "odoo_bin", "addons_path")
                if not env_config.get(key)
            ],
            doctor_summary=summary,
            doctor_checks=checks,
            warnings=list(dict.fromkeys(warnings)),
            remediation=list(dict.fromkeys(remediation)),
        )

    def inspect_addon(
        self,
        module_name: str,
        odoo_series: OdooSeries | None = None,
    ) -> AddonInspection:
        """Return a typed inspection payload for one addon.

        Raises:
            ModuleNotFoundError: If the module cannot be found in ``addons_path``.
        """
        addons_path = self.operations.config.get_optional("addons_path")
        module_manager = ModuleManager(str(addons_path or ""))
        detected_series = odoo_series or module_manager.detect_odoo_series()
        manifest = module_manager.get_manifest(module_name)
        if manifest is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )

        warnings: list[str] = []
        remediation: list[str] = []
        reverse_dependencies = module_manager.get_reverse_dependencies(module_name)
        raw_data = manifest.get_raw_data()

        try:
            missing_dependencies = module_manager.find_missing_dependencies(module_name)
        except ValueError as exc:
            missing_dependencies = []
            warnings.append(str(exc))

        dependency_cycle: list[str] = []
        try:
            install_order = module_manager.get_install_order(module_name)
        except ValueError as exc:
            install_order = []
            warnings.append(str(exc))
            dependency_cycle = module_manager.parse_cycle_error(str(exc))
            if dependency_cycle:
                remediation.append(
                    "Break the dependency cycle before attempting installation "
                    "or update."
                )

        if missing_dependencies:
            remediation.append(
                "Resolve missing dependencies before attempting installation or update."
            )

        return AddonInspection(
            module=module_name,
            exists=True,
            module_path=module_manager.find_module_path(module_name),
            addon_type=type(self.operations)._get_addon_type(
                module_name, detected_series
            ),
            version_display=module_manager.get_module_version_display(
                module_name, detected_series
            ),
            manifest=raw_data,
            manifest_fields=sorted(raw_data.keys()),
            direct_dependencies=manifest.codependencies,
            reverse_dependencies=reverse_dependencies,
            reverse_dependency_count=len(reverse_dependencies),
            install_order_slice=install_order,
            install_order_available=bool(install_order),
            dependency_cycle=dependency_cycle,
            missing_dependencies=missing_dependencies,
            impacted_modules=reverse_dependencies,
            series=detected_series.value if detected_series else None,
            python_dependencies=manifest.python_dependencies,
            binary_dependencies=manifest.binary_dependencies,
            warnings=warnings,
            remediation=list(dict.fromkeys(remediation)),
        )

    def addon_info(
        self,
        module_name: str,
        *,
        odoo_series: OdooSeries | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> AddonInfo:
        """Return a combined addon summary for onboarding and planning."""
        inspection = self.operations.inspect_addon(module_name, odoo_series=odoo_series)
        module_manager = self.operations._get_module_manager()
        manifest = module_manager.get_manifest(module_name)
        addon_root = inspection.module_path
        if manifest is None or addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )

        model_inventory = self.operations.list_addon_models(module_name)
        test_inventory = self.operations.list_addon_tests(module_name)
        languages, language_warnings = list_addon_languages(addon_root)
        installed_state = self.operations.get_addon_install_state(
            module_name,
            database=database,
            timeout=timeout,
        )

        declared_models = sorted(
            {
                entry.model
                for entry in model_inventory.models
                if entry.relation_kind == "declares"
            }
        )
        inherit_models = sorted(
            {
                inherited_model
                for entry in model_inventory.models
                for inherited_model in entry.inherited_models
                if inherited_model
            }
        )

        warnings = [
            *inspection.warnings,
            *model_inventory.warnings,
            *test_inventory.warnings,
            *language_warnings,
        ]
        remediation = [
            *inspection.remediation,
            *model_inventory.remediation,
            *test_inventory.remediation,
        ]
        if not installed_state.success:
            warnings.append(
                "Runtime install state was unavailable; static addon info is still "
                "provided."
            )
            remediation.append(
                "Verify database access if installed state matters for this addon."
            )

        return AddonInfo(
            module=module_name,
            module_path=addon_root,
            addon_type=inspection.addon_type,
            version_display=inspection.version_display,
            summary=manifest.summary,
            description=manifest.description,
            license=manifest.license,
            depends=list(inspection.direct_dependencies),
            reverse_dependencies=list(inspection.reverse_dependencies),
            reverse_dependency_count=inspection.reverse_dependency_count,
            missing_dependencies=list(inspection.missing_dependencies),
            installable=manifest.installable,
            auto_install=manifest.auto_install,
            models=declared_models,
            inherit_models=inherit_models,
            model_count=len(declared_models),
            test_cases=list(test_inventory.tests),
            test_count=len(test_inventory.tests),
            languages=languages,
            installed_state=installed_state,
            warnings=list(dict.fromkeys(warnings)),
            remediation=list(dict.fromkeys(remediation)),
        )

    def plan_update(
        self,
        module_name: str,
        odoo_series: OdooSeries | None = None,
    ) -> UpdatePlan:
        """Return a typed, read-only update plan for one addon."""
        inspection = self.operations.inspect_addon(module_name, odoo_series=odoo_series)
        addons_path = self.operations.config.get_required("addons_path")
        duplicate_modules = AddonsPathManager(addons_path).find_duplicate_module_names()
        duplicate_name_risk = module_name in duplicate_modules
        reverse_dependency_count = inspection.reverse_dependency_count
        missing_dependencies = list(inspection.missing_dependencies)
        dependency_cycle = list(inspection.dependency_cycle)

        risk_factors: list[str] = []
        risk_score = 0
        if reverse_dependency_count:
            risk_score += min(reverse_dependency_count * 10, 40)
            risk_factors.append(
                f"{reverse_dependency_count} reverse dependencies would be affected"
            )
        if missing_dependencies:
            risk_score += min(len(missing_dependencies) * 20, 30)
            risk_factors.append("module has missing dependencies")
        if duplicate_name_risk:
            risk_score += 20
            risk_factors.append("module name is duplicated across addons paths")
        if dependency_cycle:
            risk_score += 30
            risk_factors.append("dependency graph contains a cycle")
        if inspection.addon_type == "custom":
            risk_score += 10
            risk_factors.append(
                "custom addon changes should be validated in the target DB"
            )

        risk_level = "low"
        if risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 20:
            risk_level = "medium"

        backup_advised = reverse_dependency_count > 0 or duplicate_name_risk
        verification_steps = [
            f"Run targeted tests for `{module_name}` before and after the update.",
            f"Inspect reverse dependencies for `{module_name}` before "
            "updating dependent addons.",
        ]
        if inspection.reverse_dependencies:
            verification_steps.append(
                "Retest at least one impacted reverse dependency after the update."
            )

        remediation = list(inspection.remediation)
        if backup_advised:
            remediation.append(
                "Take a database backup before updating this module in a "
                "shared environment."
            )

        return UpdatePlan(
            module=module_name,
            exists=True,
            impact_set=list(inspection.reverse_dependencies),
            impact_count=reverse_dependency_count,
            missing_dependencies=missing_dependencies,
            duplicate_name_risk=duplicate_name_risk,
            duplicate_module_locations=duplicate_modules.get(module_name, []),
            dependency_cycle=dependency_cycle,
            cycle_risk=bool(dependency_cycle),
            ordering_constraints=list(inspection.install_order_slice),
            recommended_sequence=[
                "Review dependency and duplicate-module warnings.",
                *(
                    ["Take a database backup."]
                    if backup_advised
                    else ["A dedicated backup is optional for this change."]
                ),
                f"Update `{module_name}`.",
                "Run targeted validation and tests.",
            ],
            backup_advised=backup_advised,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            verification_steps=verification_steps,
            inspection=inspection,
            warnings=list(dict.fromkeys(inspection.warnings)),
            remediation=list(dict.fromkeys(remediation)),
        )

    def inspect_addons(
        self,
        module_names: list[str],
        odoo_series: OdooSeries | None = None,
    ) -> list[AddonInspection]:
        """Return typed inspection payloads for multiple addons."""
        return [
            self.operations.inspect_addon(module_name, odoo_series=odoo_series)
            for module_name in module_names
        ]

    def list_duplicates(self) -> dict[str, list[str]]:
        """Return duplicate module names across configured addon paths."""
        addons_path = self.operations.config.get_required("addons_path")
        return AddonsPathManager(addons_path).find_duplicate_module_names()

    def list_addons_inventory(
        self,
        module_names: list[str],
        odoo_series: OdooSeries | None = None,
    ) -> list[dict[str, Any]]:
        """Return structured addon inventory records."""
        module_manager = self.operations._get_module_manager()
        duplicates = self.operations.list_duplicates()
        detected_series = odoo_series or module_manager.detect_odoo_series()
        inventory: list[dict[str, Any]] = []
        for module_name in module_names:
            manifest = module_manager.get_manifest(module_name)
            if manifest is None:
                continue
            raw_data = manifest.get_raw_data()
            inventory.append(
                {
                    "module": module_name,
                    "module_path": module_manager.find_module_path(module_name),
                    "addon_type": type(self.operations)._get_addon_type(
                        module_name, detected_series
                    ),
                    "version": manifest.version,
                    "summary": manifest.summary,
                    "author": manifest.author,
                    "category": raw_data.get("category"),
                    "license": manifest.license,
                    "depends": list(manifest.codependencies),
                    "python_dependencies": list(manifest.python_dependencies),
                    "binary_dependencies": list(manifest.binary_dependencies),
                    "duplicate_name": module_name in duplicates,
                    "duplicate_locations": duplicates.get(module_name, []),
                }
            )
        return inventory

    def dependency_graph(self, module_names: list[str]) -> dict[str, Any]:
        """Return dependency graph data for one or more addons."""
        module_manager = self.operations._get_module_manager()
        graph: dict[str, set[str]] = {}
        missing_dependencies: dict[str, list[str]] = {}
        cycle: list[str] = []
        warnings: list[str] = []

        for module_name in module_names:
            try:
                subgraph = module_manager.build_dependency_graph(module_name)
                for graph_module, dependencies in subgraph.items():
                    graph.setdefault(graph_module, set()).update(dependencies)
            except ValueError as exc:
                warnings.append(str(exc))
                parsed_cycle = module_manager.parse_cycle_error(str(exc))
                if parsed_cycle:
                    cycle = parsed_cycle
            missing_dependencies[module_name] = (
                module_manager.find_missing_dependencies(module_name)
            )

        nodes = sorted(graph)
        edges = [
            {"source": module_name, "target": dependency}
            for module_name in sorted(graph)
            for dependency in sorted(graph[module_name])
        ]
        install_order: list[str] = []
        if not cycle:
            try:
                install_order = module_manager.sort_modules(nodes, "topological")
            except ValueError as exc:
                warnings.append(str(exc))
                parsed_cycle = module_manager.parse_cycle_error(str(exc))
                if parsed_cycle:
                    cycle = parsed_cycle

        return {
            "modules": module_names,
            "nodes": nodes,
            "edges": edges,
            "missing_dependencies": missing_dependencies,
            "cycles": [cycle] if cycle else [],
            "install_order": install_order,
            "warnings": warnings,
        }
