# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import shutil
from typing import Any

from manifestoo_core.core_addons import is_core_ce_addon, is_core_ee_addon
from manifestoo_core.odoo_series import OdooSeries

from ._operations import (
    DatabaseOperationsService,
    DiscoveryOperationsService,
    DocumentationOperationsService,
    QueryOperationsService,
    RuntimeOperationsService,
    SourceAnalysisOperationsService,
    UnsafeExecutionOperationsService,
)
from .api_models import (
    AddonDocumentation,
    AddonInfo,
    AddonInspection,
    AddonInstallState,
    AddonModelInventory,
    AddonTestInventory,
    BinaryProbe,
    DependencyGraphDocumentation,
    EnvironmentContext,
    FieldSourceLocation,
    InstalledAddonInventory,
    InstalledAddonRecord,
    ModelDocumentation,
    ModelExtensionInventory,
    ModelFieldsResult,
    ModelSourceLocation,
    ModelViewInventory,
    MultiAddonDocumentation,
    QueryModelResult,
    RecordReadResult,
    SearchCountResult,
    UpdatePlan,
)
from .builders import ConfigProvider
from .demo_process_manager import DemoProcessManager
from .module_manager import ModuleManager
from .odoo_code_executor import OdooCodeExecutor
from .odoo_inspector import OdooInspector
from .odoo_query import OdooQuery
from .operation_result import OperationResult
from .process_manager import ProcessManager


class OdooOperations:
    """Compatibility facade over smaller internal Odoo operation services."""

    def __init__(self, env_config: dict, verbose: bool = False):
        from .base_process_manager import BaseProcessManager

        self.result_builder = OperationResult()
        self.verbose = verbose
        self.env_config = env_config
        self._query_helper: OdooQuery | None = None
        self._code_executor: OdooCodeExecutor | None = None
        self._inspector: OdooInspector | None = None

        self.config = ConfigProvider(env_config)
        if env_config.get("demo_mode", False):
            available_modules = env_config.get("available_modules", [])
            self.process_manager: BaseProcessManager = DemoProcessManager(
                available_modules
            )
        else:
            self.process_manager = ProcessManager()

        self._runtime_service = RuntimeOperationsService(self)
        self._database_service = DatabaseOperationsService(self)
        self._discovery_service = DiscoveryOperationsService(self)
        self._documentation_service = DocumentationOperationsService(self)
        self._source_analysis_service = SourceAnalysisOperationsService(self)
        self._query_service = QueryOperationsService(self)
        self._unsafe_execution_service = UnsafeExecutionOperationsService(self)

    def run_odoo(
        self,
        no_http: bool = False,
        dev: str | None = None,
        log_level: str | None = None,
        stop_after_init: bool = False,
    ) -> None:
        """Start the Odoo server with the specified configuration."""
        return self._runtime_service.run_odoo(
            no_http=no_http,
            dev=dev,
            log_level=log_level,
            stop_after_init=stop_after_init,
        )

    def run_shell(
        self,
        shell_interface: str | None = "python",
        no_http: bool = True,
        compact: bool = False,
        log_level: str | None = None,
    ) -> dict:
        """Start an interactive Odoo shell or execute piped commands."""
        return self._runtime_service.run_shell(
            shell_interface=shell_interface,
            no_http=no_http,
            compact=compact,
            log_level=log_level,
        )

    def update_module(
        self,
        module: str,
        no_http: bool = False,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        compact: bool = False,
        log_level: str | None = None,
        max_cron_threads: int | None = None,
        without_demo: str | bool = False,
        stop_after_init: bool = True,
        i18n_overwrite: bool = False,
        language: str | None = None,
    ) -> dict:
        """Update a module and return operation result"""
        return self._runtime_service.update_module(
            module=module,
            no_http=no_http,
            suppress_output=suppress_output,
            raise_on_error=raise_on_error,
            compact=compact,
            log_level=log_level,
            max_cron_threads=max_cron_threads,
            without_demo=without_demo,
            stop_after_init=stop_after_init,
            i18n_overwrite=i18n_overwrite,
            language=language,
        )

    def install_module(
        self,
        module: str,
        verbose: bool = False,
        no_http: bool = False,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        compact: bool = False,
        max_cron_threads: int | None = None,
        log_level: str | None = None,
        without_demo: str | bool = False,
        language: str | None = None,
        with_demo: bool = False,
        stop_after_init: bool = True,
    ) -> dict:
        """Install a module and return operation result"""
        return self._runtime_service.install_module(
            module=module,
            verbose=verbose,
            no_http=no_http,
            suppress_output=suppress_output,
            raise_on_error=raise_on_error,
            compact=compact,
            max_cron_threads=max_cron_threads,
            log_level=log_level,
            without_demo=without_demo,
            language=language,
            with_demo=with_demo,
            stop_after_init=stop_after_init,
        )

    def export_module_language(
        self,
        module: str,
        filename: str,
        language: str,
        no_http: bool = False,
        log_level: str | None = None,
        suppress_output: bool = False,
    ) -> dict:
        """Export language translations for a specific module to a file."""
        return self._runtime_service.export_module_language(
            module=module,
            filename=filename,
            language=language,
            no_http=no_http,
            log_level=log_level,
            suppress_output=suppress_output,
        )

    def run_tests(
        self,
        module: str | None = None,
        stop_on_error: bool = False,
        install: str | None = None,
        update: str | None = None,
        coverage: str | None = None,
        test_file: str | None = None,
        test_tags: str | None = None,
        compact: bool = False,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        log_level: str | None = None,
    ) -> dict:
        """Run tests for a module"""
        return self._runtime_service.run_tests(
            module=module,
            stop_on_error=stop_on_error,
            install=install,
            update=update,
            coverage=coverage,
            test_file=test_file,
            test_tags=test_tags,
            compact=compact,
            suppress_output=suppress_output,
            raise_on_error=raise_on_error,
            log_level=log_level,
        )

    def db_exists(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        db_user: str | None = None,
    ) -> dict:
        """Check if database exists and return operation result"""
        return self._database_service.db_exists(
            with_sudo=with_sudo,
            suppress_output=suppress_output,
            raise_on_error=raise_on_error,
            db_user=db_user,
        )

    def drop_db(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
    ) -> dict:
        """Drop database and return operation result"""
        return self._database_service.drop_db(
            with_sudo=with_sudo,
            suppress_output=suppress_output,
            raise_on_error=raise_on_error,
        )

    def create_db(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        create_role: bool = False,
        alter_role: bool = False,
        extension: str | None = None,
        raise_on_error: bool = False,
        db_user: str | None = None,
    ) -> dict:
        """Create database and return operation result"""
        return self._database_service.create_db(
            with_sudo=with_sudo,
            suppress_output=suppress_output,
            create_role=create_role,
            alter_role=alter_role,
            extension=extension,
            raise_on_error=raise_on_error,
            db_user=db_user,
        )

    def list_db(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        db_user: str | None = None,
    ) -> dict:
        """List all databases and return operation result"""
        return self._database_service.list_db(
            with_sudo=with_sudo,
            suppress_output=suppress_output,
            raise_on_error=raise_on_error,
            db_user=db_user,
        )

    def create_addon(
        self,
        addon_name: str,
        destination: str | None = None,
        template: str | None = None,
        suppress_output: bool = False,
    ) -> dict:
        """Create a new Odoo addon using the scaffold command."""
        return self._source_analysis_service.create_addon(
            addon_name=addon_name,
            destination=destination,
            template=template,
            suppress_output=suppress_output,
        )

    def get_odoo_version(
        self,
        suppress_output: bool = False,
        raise_on_error: bool = False,
    ) -> dict:
        """Get the Odoo version from odoo-bin"""
        return self._runtime_service.get_odoo_version(
            suppress_output=suppress_output, raise_on_error=raise_on_error
        )

    def get_environment_context(
        self,
        env_name: str | None = None,
        config_source: str | None = None,
        config_path: str | None = None,
        odoo_series: OdooSeries | None = None,
    ) -> EnvironmentContext:
        """Return a typed environment snapshot for planning and inspection."""
        return self._discovery_service.get_environment_context(
            env_name=env_name,
            config_source=config_source,
            config_path=config_path,
            odoo_series=odoo_series,
        )

    def inspect_addon(
        self,
        module_name: str,
        odoo_series: OdooSeries | None = None,
    ) -> AddonInspection:
        """Return a typed inspection payload for one addon."""
        return self._discovery_service.inspect_addon(
            module_name=module_name, odoo_series=odoo_series
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
        return self._discovery_service.addon_info(
            module_name=module_name,
            odoo_series=odoo_series,
            database=database,
            timeout=timeout,
        )

    def plan_update(
        self,
        module_name: str,
        odoo_series: OdooSeries | None = None,
    ) -> UpdatePlan:
        """Return a typed, read-only update plan for one addon."""
        return self._discovery_service.plan_update(
            module_name=module_name, odoo_series=odoo_series
        )

    def inspect_addons(
        self,
        module_names: list[str],
        odoo_series: OdooSeries | None = None,
    ) -> list[AddonInspection]:
        """Return typed inspection payloads for multiple addons."""
        return self._discovery_service.inspect_addons(
            module_names=module_names, odoo_series=odoo_series
        )

    def locate_model(
        self,
        module_name: str,
        model: str,
    ) -> ModelSourceLocation:
        """Return static source candidates for a model extension."""
        return self._source_analysis_service.locate_model(
            module_name=module_name, model=model
        )

    def locate_field(
        self,
        module_name: str,
        model: str,
        field_name: str,
    ) -> FieldSourceLocation:
        """Return static field source candidates inside one addon."""
        return self._source_analysis_service.locate_field(
            module_name=module_name, model=model, field_name=field_name
        )

    def list_addon_tests(
        self,
        module_name: str,
        model: str | None = None,
        field_name: str | None = None,
    ) -> AddonTestInventory:
        """Return likely addon test files for one addon."""
        return self._source_analysis_service.list_addon_tests(
            module_name=module_name, model=model, field_name=field_name
        )

    def list_addon_models(self, module_name: str) -> AddonModelInventory:
        """Return a static model inventory for one addon."""
        return self._source_analysis_service.list_addon_models(module_name=module_name)

    def recommend_tests(
        self,
        module_name: str,
        paths: list[str],
    ) -> dict[str, Any]:
        """Return changed-file to test recommendations for one addon."""
        return self._source_analysis_service.recommend_tests(
            module_name=module_name, paths=paths
        )

    def find_model_extensions(
        self,
        model: str,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> ModelExtensionInventory:
        """Return combined source and installed metadata for one model."""
        return self._source_analysis_service.find_model_extensions(
            model=model, database=database, timeout=timeout
        )

    def list_duplicates(self) -> dict[str, list[str]]:
        """Return duplicate module names across configured addon paths."""
        return self._discovery_service.list_duplicates()

    def list_addons_inventory(
        self,
        module_names: list[str],
        odoo_series: OdooSeries | None = None,
    ) -> list[dict[str, Any]]:
        """Return structured addon inventory records."""
        return self._discovery_service.list_addons_inventory(
            module_names=module_names, odoo_series=odoo_series
        )

    def get_addon_install_state(
        self,
        module: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> AddonInstallState:
        """Return the runtime install state for one addon."""
        return self._query_service.get_addon_install_state(
            module=module, database=database, timeout=timeout
        )

    def list_installed_dependents(
        self,
        module: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> InstalledAddonInventory:
        """Return installed addons that depend on the target module."""
        return self._query_service.list_installed_dependents(
            module=module, database=database, timeout=timeout
        )

    def uninstall_module(
        self,
        module: str,
        *,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        compact: bool = False,
        log_level: str | None = None,
        allow_uninstall: bool = False,
        check_dependents: bool = True,
    ) -> dict[str, Any]:
        """Uninstall a module through a trusted runtime action."""
        return self._unsafe_execution_service.uninstall_module(
            module=module,
            suppress_output=suppress_output,
            raise_on_error=raise_on_error,
            compact=compact,
            log_level=log_level,
            allow_uninstall=allow_uninstall,
            check_dependents=check_dependents,
        )

    def list_installed_addons(
        self,
        *,
        modules: list[str] | None = None,
        states: list[str] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> InstalledAddonInventory:
        """Return runtime addon inventory from ``ir.module.module``."""
        return self._query_service.list_installed_addons(
            modules=modules, states=states, database=database, timeout=timeout
        )

    def dependency_graph(self, module_names: list[str]) -> dict[str, Any]:
        """Return dependency graph data for one or more addons."""
        return self._discovery_service.dependency_graph(module_names=module_names)

    def build_addon_documentation(
        self,
        module_name: str,
        *,
        odoo_series: OdooSeries | None = None,
        database: str | None = None,
        timeout: float = 30.0,
        source_only: bool = False,
        include_arch: bool = False,
        field_attributes: list[str] | tuple[str, ...] | None = None,
        view_types: list[str] | tuple[str, ...] | None = None,
        max_models: int | None = None,
        max_fields_per_model: int | None = None,
        path_prefix: str | None = None,
    ) -> AddonDocumentation:
        """Build one addon documentation bundle."""
        return self._documentation_service.build_addon_documentation(
            module_name,
            odoo_series=odoo_series,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            field_attributes=field_attributes,
            view_types=view_types,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_prefix,
        )

    def build_model_documentation(
        self,
        model: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
        source_only: bool = False,
        include_arch: bool = False,
        field_attributes: list[str] | tuple[str, ...] | None = None,
        view_types: list[str] | tuple[str, ...] | None = None,
        max_fields: int | None = None,
        source_modules: list[str] | tuple[str, ...] | None = None,
        path_prefix: str | None = None,
    ) -> ModelDocumentation:
        """Build one model documentation bundle."""
        return self._documentation_service.build_model_documentation(
            model,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            field_attributes=field_attributes,
            view_types=view_types,
            max_fields=max_fields,
            source_modules=source_modules,
            path_prefix=path_prefix,
        )

    def build_addons_documentation(
        self,
        module_names: list[str],
        *,
        odoo_series: OdooSeries | None = None,
        database: str | None = None,
        timeout: float = 30.0,
        source_only: bool = False,
        include_arch: bool = False,
        field_attributes: list[str] | tuple[str, ...] | None = None,
        view_types: list[str] | tuple[str, ...] | None = None,
        max_models: int | None = None,
        max_fields_per_model: int | None = None,
        path_prefix: str | None = None,
    ) -> MultiAddonDocumentation:
        """Build one documentation bundle spanning multiple addons."""
        return self._documentation_service.build_addons_documentation(
            module_names,
            odoo_series=odoo_series,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            field_attributes=field_attributes,
            view_types=view_types,
            max_models=max_models,
            max_fields_per_model=max_fields_per_model,
            path_prefix=path_prefix,
        )

    def build_dependency_graph_documentation(
        self,
        module_names: list[str],
        *,
        database: str | None = None,
        timeout: float = 30.0,
        source_only: bool = False,
        installed_only: bool = False,
        transitive: bool = True,
        path_prefix: str | None = None,
    ) -> DependencyGraphDocumentation:
        """Build dependency graph documentation for one or more addons."""
        return self._documentation_service.build_dependency_graph_documentation(
            module_names,
            database=database,
            timeout=timeout,
            source_only=source_only,
            installed_only=installed_only,
            transitive=transitive,
            path_prefix=path_prefix,
        )

    def query_model(
        self,
        model: str,
        domain: list[Any] | tuple[Any, ...] | None = None,
        fields: list[str] | tuple[str, ...] | None = None,
        limit: int = 80,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> QueryModelResult:
        """Delegate typed read-only model queries to ``OdooQuery``."""
        return self._query_service.query_model(
            model=model,
            domain=domain,
            fields=fields,
            limit=limit,
            database=database,
            timeout=timeout,
        )

    def read_record(
        self,
        model: str,
        record_id: int,
        fields: list[str] | tuple[str, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> RecordReadResult:
        """Delegate typed single-record reads to ``OdooQuery``."""
        return self._query_service.read_record(
            model=model,
            record_id=record_id,
            fields=fields,
            database=database,
            timeout=timeout,
        )

    def search_count(
        self,
        model: str,
        domain: list[Any] | tuple[Any, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> SearchCountResult:
        """Delegate typed count queries to ``OdooQuery``."""
        return self._query_service.search_count(
            model=model, domain=domain, database=database, timeout=timeout
        )

    def get_model_fields(
        self,
        model: str,
        attributes: list[str] | tuple[str, ...] | None = None,
        module: str | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> ModelFieldsResult:
        """Delegate typed field metadata queries to ``OdooQuery``."""
        return self._query_service.get_model_fields(
            model=model,
            attributes=attributes,
            module=module,
            database=database,
            timeout=timeout,
        )

    def get_model_views(
        self,
        model: str,
        view_types: list[str] | tuple[str, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
        include_arch: bool = True,
    ) -> ModelViewInventory:
        """Return primary and extension DB views for one model."""
        return self._query_service.get_model_views(
            model=model,
            view_types=view_types,
            database=database,
            timeout=timeout,
            include_arch=include_arch,
        )

    def execute_python_code(
        self,
        python_code: str,
        no_http: bool = True,
        capture_output: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        shell_interface: str | None = None,
        log_level: str | None = None,
    ) -> dict:
        """Execute Python code in the Odoo shell environment"""
        return self._unsafe_execution_service.execute_python_code(
            python_code=python_code,
            no_http=no_http,
            capture_output=capture_output,
            suppress_output=suppress_output,
            raise_on_error=raise_on_error,
            shell_interface=shell_interface,
            log_level=log_level,
        )

    def execute_code(
        self,
        code: str,
        *,
        database: str | None = None,
        commit: bool = False,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Execute trusted arbitrary Python through the embedded executor."""
        return self._get_inspector().execute_code(
            code,
            database=database,
            commit=commit,
            timeout=timeout,
        )

    def inspect_ref(
        self,
        xmlid: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Resolve one XMLID through the embedded Odoo runtime."""
        return self._get_inspector().inspect_ref(
            xmlid,
            database=database,
            timeout=timeout,
        )

    def inspect_cron(
        self,
        xmlid: str,
        *,
        trigger: bool = False,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Inspect or explicitly trigger one cron job by XMLID."""
        return self._get_inspector().inspect_cron(
            xmlid,
            trigger=trigger,
            database=database,
            timeout=timeout,
        )

    def inspect_modules(
        self,
        *,
        state: str | None = None,
        names_only: bool = False,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Return runtime addon inventory with inspect-command semantics."""
        return self._get_inspector().inspect_modules(
            state=state,
            names_only=names_only,
            database=database,
            timeout=timeout,
        )

    def inspect_subtypes(
        self,
        model: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """List message subtypes registered for one model."""
        return self._get_inspector().inspect_subtypes(
            model,
            database=database,
            timeout=timeout,
        )

    def inspect_model(
        self,
        model: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Inspect runtime model registration metadata."""
        return self._get_inspector().inspect_model(
            model,
            database=database,
            timeout=timeout,
        )

    def inspect_field(
        self,
        model: str,
        field: str,
        *,
        with_db: bool = False,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Inspect runtime field metadata."""
        return self._get_inspector().inspect_field(
            model,
            field,
            with_db=with_db,
            database=database,
            timeout=timeout,
        )

    def inspect_recordset(
        self,
        expression: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Execute a trusted recordset expression as an inspection escape hatch."""
        return self._get_inspector().inspect_recordset(
            expression,
            database=database,
            timeout=timeout,
        )

    def describe_table(
        self,
        table_name: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Describe one PostgreSQL table through the live Odoo connection."""
        return self._get_inspector().describe_table(
            table_name,
            database=database,
            timeout=timeout,
        )

    def describe_column(
        self,
        table_name: str,
        column_name: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Describe one PostgreSQL column through the live Odoo connection."""
        return self._get_inspector().describe_column(
            table_name,
            column_name,
            database=database,
            timeout=timeout,
        )

    def list_constraints(
        self,
        table_name: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """List PostgreSQL constraints for one table."""
        return self._get_inspector().list_constraints(
            table_name,
            database=database,
            timeout=timeout,
        )

    def list_tables(
        self,
        pattern: str | None = None,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """List PostgreSQL tables through the live Odoo connection."""
        return self._get_inspector().list_tables(
            pattern,
            database=database,
            timeout=timeout,
        )

    def inspect_m2m(
        self,
        model: str,
        field: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Inspect Many2many relation-table metadata."""
        return self._get_inspector().inspect_m2m(
            model,
            field,
            database=database,
            timeout=timeout,
        )

    def performance_table_scans(
        self,
        *,
        limit: int = 20,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Return sequential scan metrics for PostgreSQL tables."""
        return self._get_inspector().performance_table_scans(
            limit=limit,
            database=database,
            timeout=timeout,
        )

    def performance_slow_queries(
        self,
        *,
        limit: int = 10,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Return slow-query metrics from ``pg_stat_statements`` when available."""
        return self._get_inspector().performance_slow_queries(
            limit=limit,
            database=database,
            timeout=timeout,
        )

    def performance_indexes(
        self,
        *,
        limit: int = 20,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Return basic index-usage metrics for PostgreSQL tables."""
        return self._get_inspector().performance_indexes(
            limit=limit,
            database=database,
            timeout=timeout,
        )

    def _get_query_helper(self) -> OdooQuery:
        """Return the shared ``OdooQuery`` helper for this environment."""
        if self._query_helper is None:
            self._query_helper = OdooQuery(self.env_config)
        return self._query_helper

    def _get_code_executor(self) -> OdooCodeExecutor:
        """Return the shared trusted code executor for this environment."""
        if self._code_executor is None:
            self._code_executor = OdooCodeExecutor(self.config)
        return self._code_executor

    def _get_inspector(self) -> OdooInspector:
        """Return the shared inspector helper for this environment."""
        if self._inspector is None:
            self._inspector = OdooInspector(self.config)
        return self._inspector

    @staticmethod
    def _normalize_config_bool(value: Any) -> bool:
        """Normalize boolean-like config values."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def _config_allows_uninstall(self) -> bool:
        """Return whether uninstall is enabled for the active environment."""
        return self._normalize_config_bool(
            self.config.get_optional("allow_uninstall", False)
        )

    @staticmethod
    def _build_uninstall_module_code(module: str) -> str:
        """Build trusted code for uninstalling one addon."""
        return "\n".join(
            [
                f"_oduit_module_name = {module!r}",
                "_oduit_module_model = env['ir.module.module']",
                "_oduit_module = _oduit_module_model.search(",
                "    [('name', '=', _oduit_module_name)],",
                "    limit=1,",
                ")",
                "if not _oduit_module:",
                "    raise ValueError(",
                '        f"Module {_oduit_module_name!r} was not found in '
                'ir.module.module"',
                "    )",
                "_oduit_previous_state = _oduit_module.state or 'uninstalled'",
                "if _oduit_previous_state != 'installed':",
                "    raise ValueError(",
                '        f"Module {_oduit_module_name!r} is not installed"',
                "    )",
                "_oduit_module.button_immediate_uninstall()",
                "_oduit_final = _oduit_module_model.search(",
                "    [('name', '=', _oduit_module_name)],",
                "    limit=1,",
                ")",
                "{",
                "    'module': _oduit_module_name,",
                "    'record_found': bool(_oduit_final),",
                "    'previous_state': _oduit_previous_state,",
                "    'final_state': (",
                "        _oduit_final.state if _oduit_final else 'uninstalled'",
                "    ),",
                "    'uninstalled': (",
                "        (not _oduit_final) or _oduit_final.state != 'installed'",
                "    ),",
                "}",
            ]
        )

    @staticmethod
    def _probe_binary(configured_value: Any, fallbacks: list[str]) -> BinaryProbe:
        """Resolve a configured or auto-detected binary into a typed probe."""
        configured_text = str(configured_value) if configured_value else None
        if configured_text:
            resolved_path = configured_text
            auto_detected = False
        else:
            resolved_path = None
            auto_detected = False
            for candidate in fallbacks:
                detected = shutil.which(candidate)
                if detected:
                    resolved_path = detected
                    auto_detected = True
                    break

        exists = bool(resolved_path and os.path.exists(resolved_path))
        executable = bool(resolved_path and os.access(resolved_path, os.X_OK))
        return BinaryProbe(
            value=configured_text,
            resolved_path=resolved_path,
            exists=exists,
            executable=executable,
            configured=configured_text is not None,
            auto_detected=auto_detected,
        )

    @staticmethod
    def _build_check(
        name: str,
        status: str,
        message: str,
        details: dict[str, Any] | None = None,
        remediation: str | None = None,
    ) -> dict[str, Any]:
        """Build a doctor-style check entry for programmatic context output."""
        check: dict[str, Any] = {
            "name": name,
            "status": status,
            "message": message,
        }
        if details:
            check["details"] = details
        if remediation:
            check["remediation"] = remediation
        return check

    @staticmethod
    def _get_addon_type(addon_name: str, odoo_series: OdooSeries | None) -> str:
        """Classify an addon as core CE, core EE, or custom."""
        if odoo_series:
            if is_core_ce_addon(addon_name, odoo_series):
                return "core_ce"
            if is_core_ee_addon(addon_name, odoo_series):
                return "core_ee"
        return "custom"

    def _get_module_manager(self) -> ModuleManager:
        """Return a configured module manager for addon-aware operations."""
        addons_path = self.config.get_required("addons_path")
        return ModuleManager(addons_path)

    @staticmethod
    def _normalize_optional_bool(value: Any) -> bool | None:
        """Normalize Odoo truthy values into optional booleans."""
        if value is None:
            return None
        return bool(value)

    @staticmethod
    def _normalize_optional_str(value: Any) -> str | None:
        """Normalize optional string-like values from query helpers."""
        return value if isinstance(value, str) else None

    @classmethod
    def _normalize_installed_addon_record(
        cls,
        record: dict[str, Any],
    ) -> InstalledAddonRecord:
        """Normalize one ``ir.module.module`` record into the public shape."""
        state = str(record.get("state") or "uninstalled")
        return InstalledAddonRecord(
            module=str(record.get("name") or ""),
            state=state,
            installed=state == "installed",
            shortdesc=(
                str(record["shortdesc"])
                if isinstance(record.get("shortdesc"), str)
                else None
            ),
            application=cls._normalize_optional_bool(record.get("application")),
            auto_install=cls._normalize_optional_bool(record.get("auto_install")),
        )
