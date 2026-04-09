# Public API Inventory

This file is the maintainer-facing inventory of the current public surface.
Use it when updating README, CLI docs, and API examples.

## Top-level exports from `oduit.__init__`

- `ConfigLoader`
- `Manifest`, `ManifestError`, `InvalidManifestError`, `ManifestNotFoundError`
- `ManifestCollection`
- `AddonsPathManager`
- `EnvironmentSource`, `BinaryProbe`, `AddonsPathStatus`, `OdooVersionInfo`
- `DatabaseSummary`, `EnvironmentContext`, `AddonInspection`, `UpdatePlan`
- `QueryModelResult`, `RecordReadResult`, `SearchCountResult`, `ModelFieldsResult`
- `ModuleManager`
- `ConfigError`
- `OdooOperationError`, `ModuleOperationError`, `ModuleUpdateError`, `ModuleInstallError`
- `ModuleNotFoundError`, `DatabaseOperationError`
- `DemoProcessManager`
- `OdooOperations`
- `OdooEmbeddedManager`
- `OdooCodeExecutor`
- `OdooQuery`
- `ProcessManager`
- `OperationResult`
- `OutputFormatter`
- `configure_output`, `print_info`, `print_success`, `print_warning`, `print_error`
- `print_result`, `print_error_result`

## CLI commands in `oduit.cli_typer`

- `doctor`
- `run`
- `shell`
- `install`
- `update`
- `test`
- `create-db`
- `list-db`
- `list-env`
- `print-config`
- `create-addon`
- `list-addons`
- `print-manifest`
- `list-manifest-values`
- `list-depends`
- `install-order`
- `list-codepends`
- `impact-of-update`
- `list-missing`
- `list-duplicates`
- `init`
- `export-lang`
- `version`

## `oduit agent` subcommands in `oduit.cli_typer`

- `context`
- `inspect-addon`
- `plan-update`
- `test-summary`
- `query-model`
- `read-record`
- `search-count`
- `get-model-fields`

## `OdooOperations` methods

- `run_odoo()`
- `run_shell()`
- `update_module()`
- `install_module()`
- `export_module_language()`
- `run_tests()`
- `db_exists()`
- `drop_db()`
- `create_db()`
- `list_db()`
- `create_addon()`
- `get_odoo_version()`
- `get_environment_context()`
- `inspect_addon()`
- `plan_update()`
- `query_model()`
- `read_record()`
- `search_count()`
- `get_model_fields()`
- `execute_python_code()`

## `ModuleManager` methods

- `find_module_dirs()`
- `find_modules()`
- `find_module_path()`
- `get_manifest()`
- `parse_manifest()`
- `get_module_codependencies()`
- `get_direct_dependencies()`
- `build_dependency_graph()`
- `get_dependency_tree()`
- `get_dependencies_at_depth()`
- `get_install_order()`
- `find_missing_dependencies()`
- `get_reverse_dependencies()`
- `detect_odoo_series()`
- `get_module_version_display()`
- `get_formatted_dependency_tree()`
- `sort_modules()`

## `ConfigLoader` methods

- `get_config_path()`
- `has_local_config()`
- `get_local_config_path()`
- `resolve_config_path()`
- `load_local_config()`
- `import_odoo_conf()`
- `load_config()`
- `get_available_environments()`
- `load_demo_config()`

## `ProcessManager` methods

- `clear_sudo_password()`
- `run_operation()`
- `run_command()`
- `run_command_yielding()`
- `run_shell_command()`
- `run_interactive_shell()`

## `OdooCodeExecutor` methods

- `execute_code()`
- `execute_multiple()`

Note:

- `list-codepends` is the shipped CLI name, but its behavior is reverse-dependency
  analysis and includes the selected module itself in the output.
- `get_module_codependencies()` is a compatibility name for direct manifest
  dependencies. Prefer the more explicit terms `direct dependencies` and
  `reverse dependencies` in user-facing docs.
- Arbitrary code execution still requires `allow_unsafe=True`.

## `OdooQuery` methods

- `query_model()`
- `read_record()`
- `search_count()`
- `get_model_fields()`
