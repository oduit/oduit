# Public API Inventory

This file is the maintainer-facing inventory of the current public surface.
Use it when updating README, CLI docs, and API examples.

Use `docs/agent_contract.rst` as the canonical workflow and payload reference
for external coding agents. Keep the inventory below in sync with
`oduit agent --help`.
Use `docs/maintainer/agent_contract_changes.md` to record machine-facing
contract changes such as new stable fields or failure codes.

## Top-level exports from `oduit.__init__`

- `ConfigLoader`
- `Manifest`, `ManifestError`, `InvalidManifestError`, `ManifestNotFoundError`
- `ManifestCollection`
- `AddonsPathManager`
- `EnvironmentSource`, `BinaryProbe`, `AddonsPathStatus`, `OdooVersionInfo`
- `DatabaseSummary`, `EnvironmentContext`, `AddonInstallState`, `AddonInspection`
- `AddonInfo`
- `InstalledAddonRecord`, `InstalledAddonInventory`, `UpdatePlan`
- `QueryModelResult`, `RecordReadResult`, `SearchCountResult`, `ModelFieldsResult`
- `ModuleManager`
- `ConfigError`
- `OdooOperationError`, `ModuleOperationError`, `ModuleUpdateError`, `ModuleInstallError`
- `ModuleUninstallError`
- `ModuleNotFoundError`, `DatabaseOperationError`
- `DemoProcessManager`
- `OdooOperations`
- `OdooEmbeddedManager`
- `OdooCodeExecutor`
- `OdooInspector`
- `OdooQuery`
- `ProcessManager`
- `OperationResult`
- `OutputFormatter`
- `configure_output`, `print_info`, `print_success`, `print_warning`, `print_error`
- `print_result`, `print_error_result`

The command sections below are generated from `oduit.cli.command_inventory`,
which reads the canonical Typer registration surface in `oduit.cli.app`.

## CLI commands in `oduit.cli.app`

| Command                 | Stability tier   | Summary                                                              |
| ----------------------- | ---------------- | -------------------------------------------------------------------- |
| `doctor`                | `human_oriented` | Diagnose environment and configuration issues.                       |
| `run`                   | `human_oriented` | Run Odoo server.                                                     |
| `shell`                 | `human_oriented` | Start Odoo shell.                                                    |
| `install`               | `human_oriented` | Install module.                                                      |
| `update`                | `human_oriented` | Update module.                                                       |
| `uninstall`             | `human_oriented` | Uninstall module.                                                    |
| `test`                  | `human_oriented` | Run module tests with various options.                               |
| `create-db`             | `human_oriented` | Create database.                                                     |
| `list-db`               | `human_oriented` | List all databases.                                                  |
| `list-env`              | `human_oriented` | List available environments.                                         |
| `print-config`          | `human_oriented` | Print environment config.                                            |
| `edit-config`           | `human_oriented` | Open the active config file in the default editor.                   |
| `create-addon`          | `human_oriented` | Create new addon.                                                    |
| `print-manifest`        | `human_oriented` | Print addon manifest information in a table.                         |
| `addon-info`            | `human_oriented` | Print a combined manifest, source, and runtime addon summary.        |
| `list-addons`           | `human_oriented` | List available addons.                                               |
| `list-installed-addons` | `human_oriented` | List installed addons from the active database.                      |
| `list-manifest-values`  | `human_oriented` | List unique values for a manifest field across all addons.           |
| `list-duplicates`       | `human_oriented` | List duplicate addon names across configured addon paths.            |
| `list-depends`          | `human_oriented` | List direct dependencies needed to install a set of modules.         |
| `list-codepends`        | `human_oriented` | List reverse dependencies for a module.                              |
| `install-order`         | `human_oriented` | Return the dependency-resolved install order for one or more addons. |
| `impact-of-update`      | `human_oriented` | Show addons affected by updating a specific module.                  |
| `list-missing`          | `human_oriented` | Find missing dependencies for modules.                               |
| `init`                  | `human_oriented` | Initialize a new oduit environment configuration.                    |
| `export-lang`           | `human_oriented` | Export language module.                                              |
| `version`               | `human_oriented` | Get Odoo version from odoo-bin.                                      |
| `exec`                  | `human_oriented` | Execute trusted Python within Odoo and return a structured result.   |
| `exec-file`             | `human_oriented` | Execute trusted Python from a file within Odoo.                      |
| `inspect`               | `human_oriented` | Runtime model, field, XMLID, and module inspection                   |
| `db`                    | `human_oriented` | Database inspection through the live Odoo connection                 |
| `performance`           | `human_oriented` | Read-only PostgreSQL performance inspection                          |
| `manifest`              | `human_oriented` | Manifest inspection and validation                                   |

## `oduit agent` subcommands in `oduit.cli.app`

| Command                    | Stability tier      | Safety level                  | Summary                                                                |
| -------------------------- | ------------------- | ----------------------------- | ---------------------------------------------------------------------- |
| `context`                  | `stable_for_agents` | `safe_read_only`              | Return a structured environment snapshot for automation.               |
| `inspect-addon`            | `stable_for_agents` | `safe_read_only`              | Return a one-shot addon inspection payload.                            |
| `addon-info`               | `stable_for_agents` | `safe_read_only`              | Return a combined manifest, source, and runtime addon summary.         |
| `plan-update`              | `stable_for_agents` | `safe_read_only`              | Return a structured, read-only update plan for a module.               |
| `prepare-addon-change`     | `beta_for_agents`   | `safe_read_only`              | Bundle the common read-only planning steps for one addon change.       |
| `locate-model`             | `beta_for_agents`   | `safe_read_only`              | Locate likely source files for a model extension inside one addon.     |
| `locate-field`             | `beta_for_agents`   | `safe_read_only`              | Locate an existing field or suggest the best insertion point.          |
| `list-addon-tests`         | `beta_for_agents`   | `safe_read_only`              | List likely tests for an addon, optionally ranked by hints.            |
| `recommend-tests`          | `beta_for_agents`   | `safe_read_only`              | Map changed addon files to recommended tests and test tags.            |
| `list-addon-models`        | `beta_for_agents`   | `safe_read_only`              | List the models declared or extended by one addon.                     |
| `find-model-extensions`    | `beta_for_agents`   | `safe_read_only`              | Find where a model is declared, extended, and installed.               |
| `get-model-views`          | `beta_for_agents`   | `safe_read_only`              | Fetch database-backed primary and extension views for a model.         |
| `doctor`                   | `stable_for_agents` | `safe_read_only`              | Return doctor diagnostics through the standard agent envelope.         |
| `list-addons`              | `stable_for_agents` | `safe_read_only`              | Return structured addon inventory for the active environment.          |
| `list-installed-addons`    | `stable_for_agents` | `safe_read_only`              | Return structured runtime installed-addon inventory.                   |
| `dependency-graph`         | `stable_for_agents` | `safe_read_only`              | Return a structured dependency and reverse-dependency graph.           |
| `inspect-addons`           | `stable_for_agents` | `safe_read_only`              | Inspect multiple addons through the stable agent envelope.             |
| `resolve-config`           | `stable_for_agents` | `safe_read_only`              | Return the resolved configuration with sensitive values redacted.      |
| `resolve-addon-root`       | `stable_for_agents` | `safe_read_only`              | Resolve addon root paths for one module name.                          |
| `get-addon-files`          | `stable_for_agents` | `safe_read_only`              | Return a deterministic file inventory for one addon.                   |
| `check-addons-installed`   | `stable_for_agents` | `safe_read_only`              | Return runtime installed-state checks for one or more addons.          |
| `check-model-exists`       | `beta_for_agents`   | `safe_read_only`              | Check whether a model exists in source discovery and runtime metadata. |
| `check-field-exists`       | `beta_for_agents`   | `safe_read_only`              | Check whether a field exists in runtime metadata and source.           |
| `list-duplicates`          | `stable_for_agents` | `safe_read_only`              | Return duplicate addon names through the standard agent envelope.      |
| `inspect-ref`              | `stable_for_agents` | `safe_read_only`              | Resolve one XMLID through the embedded Odoo runtime.                   |
| `inspect-cron`             | `stable_for_agents` | `controlled_runtime_mutation` | Inspect one cron job and optionally trigger it.                        |
| `inspect-modules`          | `stable_for_agents` | `safe_read_only`              | Inspect module records from ir.module.module.                          |
| `inspect-subtypes`         | `stable_for_agents` | `safe_read_only`              | List message subtypes registered for one model.                        |
| `inspect-model`            | `stable_for_agents` | `safe_read_only`              | Inspect runtime model registration metadata.                           |
| `inspect-field`            | `stable_for_agents` | `safe_read_only`              | Inspect runtime field metadata.                                        |
| `db-table`                 | `stable_for_agents` | `safe_read_only`              | Describe one PostgreSQL table through the live Odoo connection.        |
| `db-column`                | `stable_for_agents` | `safe_read_only`              | Describe one PostgreSQL column through the live Odoo connection.       |
| `db-constraints`           | `stable_for_agents` | `safe_read_only`              | List PostgreSQL constraints for one table.                             |
| `db-tables`                | `stable_for_agents` | `safe_read_only`              | List PostgreSQL tables through the live Odoo connection.               |
| `db-m2m`                   | `stable_for_agents` | `safe_read_only`              | Inspect the relation table behind a Many2many field.                   |
| `performance-slow-queries` | `stable_for_agents` | `safe_read_only`              | Read pg_stat_statements when the extension is available.               |
| `performance-table-scans`  | `stable_for_agents` | `safe_read_only`              | Show tables with high sequential scan counts.                          |
| `performance-indexes`      | `stable_for_agents` | `safe_read_only`              | Show basic table index-usage metrics.                                  |
| `manifest-check`           | `stable_for_agents` | `safe_read_only`              | Validate a manifest file and report structural warnings.               |
| `manifest-show`            | `stable_for_agents` | `safe_read_only`              | Show manifest metadata for an addon or addon path.                     |
| `install-module`           | `stable_for_agents` | `controlled_runtime_mutation` | Install a module with an explicit mutation gate.                       |
| `update-module`            | `stable_for_agents` | `controlled_runtime_mutation` | Update a module with an explicit mutation gate.                        |
| `uninstall-module`         | `stable_for_agents` | `controlled_runtime_mutation` | Uninstall a module with explicit runtime and destructive gates.        |
| `create-addon`             | `stable_for_agents` | `controlled_source_mutation`  | Create a new addon with an explicit mutation gate.                     |
| `export-lang`              | `stable_for_agents` | `controlled_runtime_mutation` | Export language files with an explicit mutation gate.                  |
| `test-summary`             | `stable_for_agents` | `controlled_runtime_mutation` | Run tests and emit a normalized summary payload.                       |
| `validate-addon-change`    | `beta_for_agents`   | `controlled_runtime_mutation` | Validate an addon change with one aggregate structured payload.        |
| `preflight-addon-change`   | `beta_for_agents`   | `safe_read_only`              | Run a cheap read-only addon-change preflight.                          |
| `query-model`              | `stable_for_agents` | `safe_read_only`              | Run a structured read-only model query.                                |
| `read-record`              | `stable_for_agents` | `safe_read_only`              | Read a single record by id via OdooQuery.                              |
| `search-count`             | `stable_for_agents` | `safe_read_only`              | Count records matching a domain via OdooQuery.                         |
| `get-model-fields`         | `stable_for_agents` | `safe_read_only`              | Inspect model field metadata via OdooQuery.                            |

## `OdooOperations` methods

- `run_odoo()`
- `run_shell()`
- `update_module()`
- `install_module()`
- `uninstall_module()`
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
- `addon_info()`
- `plan_update()`
- `get_addon_install_state()`
- `list_installed_dependents()`
- `list_installed_addons()`
- `execute_code()`
- `inspect_ref()`
- `inspect_cron()`
- `inspect_modules()`
- `inspect_subtypes()`
- `inspect_model()`
- `inspect_field()`
- `inspect_recordset()`
- `describe_table()`
- `describe_column()`
- `list_constraints()`
- `list_tables()`
- `inspect_m2m()`
- `performance_table_scans()`
- `performance_slow_queries()`
- `performance_indexes()`
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

## Compatibility facade in `oduit.cli_typer`

- `app`
- `agent_app`
- `main`
- `cli_main`
- `create_global_config()`
- `_check_environment_exists()`
- `_detect_binaries()`
- `_build_initial_config()`
- `_import_or_convert_config()`
- `_normalize_addons_path()`
- `_save_config_file()`
- `_display_config_summary()`

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
