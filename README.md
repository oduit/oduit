[![PyPI - Version](https://img.shields.io/pypi/v/oduit)](https://pypi.org/project/oduit/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/oduit)
![PyPI - Downloads](https://img.shields.io/pypi/dm/oduit)
[![codecov](https://codecov.io/github/oduit/oduit/graph/badge.svg?token=6K8YL60OXJ)](https://codecov.io/github/oduit/oduit)

# oduit

`oduit` is an Odoo CLI and Python utility layer with strong addon,
dependency, and manifest introspection.

It helps with common Odoo workflows such as `run`, `install`, `update`, and
`test`, but its sharper value is in structured automation and addon
intelligence:

- `doctor` for environment diagnostics
- `version` for Odoo version detection
- `list-addons`, `list-installed-addons`, `print-manifest`, `list-manifest-values`
- `list-depends`, `install-order`, `impact-of-update`
- `docs addon`, `docs addons`, `docs model`, `docs dependency-graph`
- `exec`, `inspect`, `db`, `performance`, `manifest`
- structured JSON output for CI and editor integrations

## Installation

```bash
pip install oduit
```

## Without Installing

```bash
uvx oduit
```

## Quick Start

### Migrating an existing `odoo.conf`

When you already have an Odoo config file, generate an oduit TOML config instead
of writing one by hand:

```bash
cd /path/to/odoo-project

uvx oduit init dev \
  --from-conf ./odoo.conf \
  --python-bin ./.venv/bin/python \
  --odoo-bin ./odoo-bin

oduit --env dev print-config
oduit --env dev doctor
oduit --env dev list-addons
```

For a project-local config, write `.oduit.toml` directly:

```bash
oduit init dev --from-conf ./odoo.conf --local
oduit print-config
oduit doctor
```

Use `--dry-run` to preview the generated TOML without writing a file.

The generated file may contain secrets imported from `odoo.conf`; do not commit
it unless that is intentional.

Create a local `.oduit.toml`:

```toml
[binaries]
python_bin = "./venv/bin/python"
odoo_bin = "./odoo/odoo-bin"

[odoo_params]
addons_path = "./addons"
db_name = "project_dev"
allow_uninstall = false
write_protect_db = false
agent_write_protect_db = false
needs_mutation_flag = false
agent_needs_mutation_flag = false

[documentation]
# Only these addon directories may receive addon-local technical docs.
# Useful when addons_path also contains native Odoo or third-party addon roots.
allowed_addon_dirs = ["./addons"]
```

Then run:

```bash
oduit doctor
oduit version
oduit list-addons
oduit list-installed-addons
oduit edit-config
oduit install-order sale,purchase
oduit explain-install-order sale
oduit impact-of-update sale
```

Named environments work the same way via `~/.config/oduit/<env>.toml`:

```bash
oduit --env dev doctor
oduit --env dev run
oduit --env dev test --test-tags /sale
```

### Operation sets

Use operation sets for repeatable install, update, and test plans. They are not
environment configuration; `.oduit.toml` still defines the active Odoo environment.

Store project sets under `.oduit/sets/`:

```text
.oduit/
  sets/
    base.toml
    helpdesk_tests.toml
```

#### Set kinds

Each operation set has exactly one `kind` and exactly one matching table.
Use `schema_version = 2` in every set file.

Install set:

```toml
schema_version = 2
kind = "install"
name = "base install"
description = "Install base project addons"

[install]
addons = ["has_base", "has_helpdesk"]
without_demo = true
compact = true
```

Valid `[install]` keys: `addons`, `with_demo`, `without_demo`, `language`,
`max_cron_threads`, `compact`, `log_level`.
`with_demo` and `without_demo` are mutually exclusive.

Update set:

```toml
schema_version = 2
kind = "update"
name = "helpdesk update"

[update]
addons = ["has_helpdesk"]
without_demo = true
i18n_overwrite = false
compact = true
```

Valid `[update]` keys: `addons`, `without_demo`, `language`, `i18n_overwrite`,
`max_cron_threads`, `compact`, `log_level`, `verify_state`, `retry_missing`,
`one_by_one`, `stop_on_error`, `require_installed`.

Test set:

```toml
schema_version = 2
kind = "test"
name = "helpdesk tests"
description = "Install/update helpdesk addons and run focused tests"

[test]
install = ["has_base", "has_helpdesk"]
update = ["has_helpdesk"]
test_tags = ["/has_helpdesk", "/has_helpdesk:TestTicketFlow"]
test_files = [
  "addons/has_helpdesk/tests/test_ticket_flow.py",
  "addons/has_helpdesk/tests/test_portal.py",
]
coverage = "has_helpdesk"
stop_on_error = true
```

Valid `[test]` keys: `install`, `update`, `test_tags`, `test_files`, `coverage`,
`compact`, `stop_on_error`, `log_level`, `verify_state`, `retry_missing`,
`one_by_one`, `retry_failed_tests`.
Paths inside `test_files` are resolved relative to the set file.

#### Applying sets

```bash
oduit set inspect helpdesk_tests
oduit set apply base --allow-mutation
oduit set list
```

`oduit set apply` uses the set's `kind`. Install and update sets mutate the
runtime database. Test sets only require `--allow-mutation` when they have
`[test].install` or `[test].update`.

#### Robust set application

`oduit set apply` verifies addon state after install and update operations
by default. The verification reads the active database's module registry and
requires every requested addon to end in `installed` state.

For large sets, retry only missing addons after the first batch:

```bash
oduit set apply install.toml --allow-mutation --retry-missing 1
```

For the safest execution mode, apply one addon at a time:

```bash
oduit set apply install.toml --allow-mutation --one-by-one
oduit set apply install.toml --allow-mutation --one-by-one --retry-missing 1
```

For test sets, the same install/update verification is used for
`[test].install` and `[test].update`. Use `--one-by-one` to run test tags
separately and `--retry-failed-tests` to retry failed test units:

```bash
oduit set apply helpdesk_tests --allow-mutation --one-by-one --retry-failed-tests 1
```

Use `--no-verify-state` (the inverse of `--verify-state`) only when runtime
state queries are unavailable
and you explicitly want the older process-result-only behavior.

#### Saving sets from addon-list commands

```bash
oduit list-installed-addons --save-set snapshot --set-kind install
oduit list-addons --select-dir addons --save-set custom_update --set-kind update
oduit list-depends has_helpdesk --save-set helpdesk_deps --set-kind install
oduit list-codepends has_base --save-set base_impact --set-kind update
oduit install-order --from-set snapshot --save-set ordered_snapshot
```

Use `--overwrite` to replace an existing set. Use `--set-name` and
`--set-description` to add display metadata.

`install-order --from-set` reads install/update sets only. It rejects test sets
because a test set can contain both pre-install and pre-update roles.

#### Set lookup resolution

Short names resolve as:

1. the exact file path provided
2. the active config set store
3. `.oduit/sets/<name>.toml`
4. the global config `sets/` directory (`~/.config/oduit/sets/`)

Direct paths with `/`, `\`, or absolute paths do not fall back to set stores if missing.

#### Set write resolution for --save-set

When `--save-set snapshot` is used, oduit writes to:

1. the active config set store if available
2. otherwise the global config `sets/` directory
3. otherwise the local project `.oduit/sets/`

When `--save-set custom/output.toml` or another explicit path is used, oduit writes
exactly there. Existing files require `--overwrite`.

## CLI Highlights

```bash
# Diagnostics
oduit doctor
oduit --env dev doctor
oduit --json doctor

# Version detection
oduit --env dev version

# Addon intelligence
oduit --env dev list-addons
oduit --env dev list-installed-addons
oduit --env dev list-duplicates
oduit --env dev print-manifest sale
oduit --env dev list-manifest-values category
oduit --env dev list-depends sale
oduit --env dev install-order sale,purchase
oduit --env dev explain-install-order sale
oduit --env dev impact-of-update sale
oduit --env dev docs addon sale --source-only --path /workspace
oduit --env dev docs addons --select-dir myaddons --output-dir ./docs-out
oduit --env dev docs dependency-graph --modules sale,purchase

# Runtime inspection and trusted execution
oduit --env dev exec "env['res.partner']._table"
oduit --env dev exec-file scripts/check_runtime.py
oduit --env dev inspect ref base.action_partner_form
oduit --env dev inspect cron base.ir_cron_autovacuum
oduit --env dev inspect modules --state installed --names-only
oduit --env dev inspect model res.partner
oduit --env dev inspect field res.partner email --with-db
oduit --env dev inspect recordset "env['sale.order'].search([], limit=3).mapped('name')"
oduit --env dev db table res_partner
oduit --env dev db constraints sale_order
oduit --env dev db m2m res.partner category_id
oduit --env dev performance table-scans
oduit --env dev performance slow-queries --limit 10
oduit --env dev manifest check sale

# Agent-first inspection
oduit --env dev agent context
oduit --env dev agent inspect-addon sale
oduit --env dev agent addon-doc sale
oduit --env dev agent plan-update sale
oduit --env dev agent inspect-ref base.action_partner_form
oduit --env dev agent inspect-model res.partner
oduit --env dev agent inspect-field res.partner email --with-db
oduit --env dev agent db-table res_partner
oduit --env dev agent manifest-check sale
oduit --env dev agent list-installed-addons --modules sale
oduit --env dev agent explain-install-order --modules sale
oduit --env dev agent get-model-fields res.partner --attributes string,type,required
oduit --env dev agent list-addon-models my_partner
oduit --env dev agent find-model-extensions res.partner --summary
oduit --env dev agent get-model-views res.partner --types form,tree --summary
oduit --env dev agent locate-model res.partner --module my_partner
oduit --env dev agent locate-field res.partner email3 --module my_partner
oduit --env dev agent list-addon-tests my_partner --model res.partner --field email3
oduit --env dev agent resolve-config
oduit --env dev agent query-model res.partner --fields name,email --limit 5
oduit --env dev agent validate-addon-change my_partner --allow-mutation --update --discover-tests
oduit --env dev agent test-summary --module my_partner --test-tags /my_partner
oduit --env dev agent uninstall-module crm --dry-run

# Operations
oduit --env dev install sale
oduit --env dev update sale
oduit --env dev uninstall sale --allow-uninstall
oduit --env dev test --test-tags /sale
oduit --env dev shell
oduit --env dev --non-interactive create-db
oduit --env dev create-db --without-demo --country DE --language de_DE
oduit --env dev create-db --with-demo --username admin --password admin
oduit --env dev create-addon my_custom_module --allow-mutation

# Internationalization
oduit --env dev --odoo-series 18.0 i18n export sale --language de_DE --output /tmp/sale-de.po --allow-mutation
oduit --env dev --odoo-series 19.0 i18n export sale --language de_DE --output /tmp/sale-de.po --allow-mutation
oduit --env dev --odoo-series 19.0 i18n export sale purchase --language de_DE --language fr_FR --allow-mutation
oduit --env dev i18n import /tmp/sale-de.po --language de_DE --overwrite --allow-mutation
oduit --env dev i18n loadlang en es_AR sr@latin --allow-mutation
oduit --env dev export-lang sale --allow-mutation --language de_DE

# Operation sets
oduit --env dev set apply base --allow-mutation --retry-missing 1
oduit --env dev set apply base --allow-mutation --one-by-one
oduit --env dev set inspect helpdesk_tests
oduit --env dev list-installed-addons --save-set snapshot --set-kind install
oduit --env dev install-order --from-set snapshot --save-set ordered_snapshot
```

`create-db` exposes Odoo 19-style initialization flags across supported Odoo
series. On Odoo 19+, oduit uses native `odoo-bin db init`. On older Odoo
versions, oduit emulates equivalent behavior with `createdb` plus
`-i base --stop-after-init` and post-init updates.

## Internationalization

Prefer the new `i18n` command group for translation export, import, and language
loading. `export-lang` remains available as a compatibility alias for one
module/one language source export.

| Odoo series  | Preferred export/import/load surface            | Notes                                                                                                    |
| ------------ | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| 18 and older | legacy flags via `oduit i18n ...`               | export requires exactly one language and `--output`; multi-file import runs one Odoo invocation per file |
| 19 and newer | native `odoo-bin i18n ...` via `oduit i18n ...` | export allows module-local multi-language writes when `--output` is omitted                              |

Source mutation rules:

- `i18n export --output -` is read-only and does not need `--allow-mutation`
- filesystem export outputs require `--allow-mutation`
- Odoo 19+ export without `--output` writes addon-local files and requires `--allow-mutation`
- `i18n import` and `i18n loadlang` mutate the configured database and require `--allow-mutation` when the active policy demands it

Locale values are passed through unchanged. Valid examples include `en`,
`es_AR`, and `sr@latin`.

Migration examples:

```bash
# Preferred command family
oduit --env dev --odoo-series 19.0 i18n export sale --language de_DE --output /tmp/sale-de.po --allow-mutation

# Compatibility alias, still supported for one module/one language
oduit --env dev export-lang sale --allow-mutation --language de_DE
```

## Split addon technical documentation

oduit can generate addon-local Arc42 documentation as a split workflow:

```text
<addon>/docs/architecture.evidence.md
<addon>/docs/architecture.evidence.oduit.json
<addon>/docs/architecture.md
<addon>/docs/architecture.oduit.json
```

`architecture.evidence.md` is deterministic oduit evidence and should not be
manually edited. `architecture.md` is the LLM/human architecture report and is
the right place for reviewed prose, project context, and decisions.

Recommended human CLI workflow:

```bash
oduit --env dev docs technical-evidence @addons/has_base --output-in-addon --source-only --progress
oduit --env dev docs technical-report @addons/has_base --output-in-addon --source-only --progress
oduit --env dev docs technical-diff @addons/has_base --include-diff
oduit --env dev docs technical-check @addons/has_base --include-files
oduit --env dev docs technical-next
oduit --env dev docs technical-status --select-dir addons --only-stale
```

Recommended agent workflow:

```bash
oduit --env dev agent technical-evidence @addons/has_base --allow-mutation --source-only --progress
oduit --env dev agent technical-report @addons/has_base --allow-mutation --source-only --progress
oduit --env dev agent technical-doc-diff @addons/has_base --include-diff
oduit --env dev agent technical-doc-check @addons/has_base --include-files
oduit --env dev agent technical-doc-next
```

Use `--runtime` only when the configured database is a safe development or test
database. Otherwise keep technical documentation source-only.

Use `technical-check` as the CI/script-friendly freshness gate for one addon.
Use `technical-next` to pick the next addon that still needs documentation work.
Use `technical-diff` to compare the report's embedded evidence snapshot against
current deterministic evidence.

`docs technical` and `agent technical-doc` remain available for legacy
monolithic Arc42 files. Prefer `technical-evidence` plus `technical-report` for
new documentation.

Generate runtime evidence once. `technical-report` consumes
`docs/architecture.evidence.md` and should not rerun runtime metadata enrichment
when valid evidence files already exist.

When `[documentation].allowed_addon_dirs` is configured, `technical-next` and
`technical-status` scan only those addon directories; native addons like
`account` are excluded unless explicitly allowlisted.

Runtime DB mutation policy is controlled by explicit config flags:

- `write_protect_db`: block runtime DB mutation for every caller
- `needs_mutation_flag`: require `--allow-mutation` for human runtime DB mutations
- `agent_write_protect_db`: block agent runtime DB mutation even when human mutation is allowed
- `agent_needs_mutation_flag`: require `--allow-mutation` for agent runtime DB mutations

This applies to both classic CLI runtime commands (`install`, `update`, `uninstall`, `test`, `create-db`, `i18n import`, `i18n loadlang`) and agent runtime mutation commands. Source mutations such as `create-addon`, `i18n export`, and `export-lang` still use their own explicit mutation gate.
Plain `test` runs stay read-only; only `test --install/--update`, `agent test-summary --install/--update`, and `agent validate-addon-change` with install/update options enter the runtime DB mutation path.

## Inspection and Agent Workflows

Use the first-class inspection commands before dropping to raw shell snippets.

| Odoo / shell-style workflow                                        | `oduit` replacement                                                   |
| ------------------------------------------------------------------ | --------------------------------------------------------------------- |
| `odoo-bin shell -d db -c "env.ref('base.action_partner_form').id"` | `oduit --env dev inspect ref base.action_partner_form`                |
| `odoo-bin shell -d db -c "env['project.task']._table"`             | `oduit --env dev inspect model project.task`                          |
| `odoo-bin shell -d db -c "env['res.partner']._fields['email']"`    | `oduit --env dev inspect field res.partner email --with-db`           |
| `psql ... -c "\\d res_partner"`                                    | `oduit --env dev db table res_partner`                                |
| ad hoc trusted runtime snippet                                     | `oduit --env dev exec "..."` or `oduit --env dev exec-file script.py` |

Typical read-only workflow:

```bash
oduit --env dev inspect model res.partner
oduit --env dev inspect field res.partner email --with-db
oduit --env dev inspect modules --state installed --names-only
oduit --env dev db table res_partner
oduit --env dev performance table-scans
```

`exec` and `inspect recordset` are trusted arbitrary execution surfaces. They
run with rollback by default; pass `--commit` only when mutation is explicitly
intended.

## Coding Agents

`oduit agent ...` is the primary documented automation surface for external
coding agents.

Use [`docs/agent_contract.md`](docs/agent_contract.md) as the canonical guide
for:

- command sequence
- mutation policy
- payload expectations
- failure handling

Use [`docs/agent_command_inventory.md`](docs/agent_command_inventory.md) for
the generated command matrix and stability tiers, and
[`docs/maintainer/agent_contract_changes.md`](docs/maintainer/agent_contract_changes.md)
for machine-facing contract changes.

Agent commands always emit JSON and do not require the global `--json` flag.
Structured payloads include an explicit `schema_version`, currently `2.0`.
Raw command metadata is hidden by default; pass
`oduit agent --show-command ...` when you need `data.command` for debugging.
Prefer the read-only planning path first: `context`, `resolve-config`,
`resolve-addon-root`, `get-addon-files`, `preflight-addon-change`, and only then
controlled mutation commands such as `validate-addon-change`.
When exact runtime or database parity with the human CLI is needed, use
structured agent commands such as `inspect-ref`, `inspect-model`,
`inspect-field`, `db-table`, `db-column`, `db-constraints`, `db-m2m`,
`performance-slow-queries`, `performance-table-scans`, `performance-indexes`,
`manifest-check`, and `manifest-show`.
For one-shot verification after an addon change, prefer
`oduit --env <env> agent validate-addon-change <module>`, and add
`--allow-mutation` only when using `--install-if-needed` or `--update`.
Destructive uninstall support is disabled by default and requires both
`allow_uninstall = true` in config and `--allow-uninstall` at execution time.
Do not use `execute_python_code()` or `OdooCodeExecutor` for routine agent
workflows; keep them as trusted fallbacks with `allow_unsafe=True`.

Recommended command sequence for an addon field change:

```bash
oduit --env dev agent context
oduit --env dev agent inspect-addon my_partner
oduit --env dev agent get-model-fields res.partner --attributes string,type,required
oduit --env dev agent locate-model res.partner --module my_partner
oduit --env dev agent locate-field res.partner email3 --module my_partner
oduit --env dev agent list-addon-tests my_partner --model res.partner --field email3
oduit --env dev agent validate-addon-change my_partner --allow-mutation --install-if-needed --update --discover-tests
oduit --env dev agent test-summary --module my_partner --test-tags /my_partner
```

For exact runtime/database parity checks during an investigation, use:

```bash
oduit --env dev agent inspect-ref base.action_partner_form
oduit --env dev agent inspect-cron base.ir_cron_autovacuum
oduit --env dev agent inspect-model res.partner
oduit --env dev agent inspect-field res.partner email --with-db
oduit --env dev agent db-table res_partner
oduit --env dev agent manifest-check sale
```

## Python API

### High-Level Operations

```python
from oduit import ConfigLoader, OdooOperations

loader = ConfigLoader()
config = loader.load_config("dev")
ops = OdooOperations(config, verbose=True)

install_result = ops.install_module("sale")
test_result = ops.run_tests(module="sale")
version_result = ops.get_odoo_version(suppress_output=True)
db_result = ops.db_exists(suppress_output=True)

context = ops.get_environment_context(env_name="dev", config_source="env")
addon = ops.inspect_addon("sale")
addon_docs = ops.build_addon_documentation("sale", source_only=True)
plan = ops.plan_update("sale")
state = ops.get_addon_install_state("sale")
installed_addons = ops.list_installed_addons(modules=["sale"])
xmlid = ops.inspect_ref("base.action_partner_form")
model = ops.inspect_model("res.partner")
field = ops.inspect_field("res.partner", "email", with_db=True)
table = ops.describe_table("res_partner")
slow_queries = ops.performance_slow_queries(limit=5)
partners = ops.query_model("res.partner", fields=["name", "email"], limit=5)
extensions = ops.find_model_extensions("res.partner")
views = ops.get_model_views("res.partner", view_types=["form", "tree"])
```

The preferred Python surface is:

- `ConfigLoader` for loading configuration
- `OdooOperations` for high-level operations and typed planning/inspection
- `OdooInspector` for first-class runtime inspection and PostgreSQL metadata
- `OdooQuery` for direct structured read-only model access

Use `execute_python_code()` only for trusted shell-driven execution paths, with
an explicit `shell_interface` argument or `shell_interface` configured in the
environment. Use `OdooCodeExecutor` only for trusted arbitrary execution paths.

### Addon Intelligence

```python
from oduit import ConfigLoader, ModuleManager

loader = ConfigLoader()
config = loader.load_config("dev")
manager = ModuleManager(config["addons_path"])

addons = manager.find_modules()
sale_manifest = manager.get_manifest("sale")
depends = manager.get_direct_dependencies("sale")
install_order = manager.get_install_order("sale", "purchase")
reverse_deps = manager.get_reverse_dependencies("sale")
```

### Safe Read-Only Queries

```python
from oduit import OdooQuery

query = OdooQuery(config)

partners = query.query_model(
    "res.partner",
    domain=[("customer_rank", ">", 0)],
    fields=["name", "email"],
    limit=5,
)

count = query.search_count("res.partner", domain=[("is_company", "=", True)])
fields = query.get_model_fields("res.partner", attributes=["string", "type"])
```

### First-Class Runtime Inspection

```python
from oduit import OdooInspector

inspector = OdooInspector(config)

xmlid = inspector.inspect_ref("base.action_partner_form")
model = inspector.inspect_model("res.partner")
field = inspector.inspect_field("res.partner", "email", with_db=True)
table = inspector.describe_table("res_partner")
indexes = inspector.performance_indexes(limit=10)
```

### Raw Trusted Execution

Use `OdooCodeExecutor` only for trusted arbitrary code.

```python
from oduit.config_provider import ConfigProvider
from oduit.odoo_code_executor import OdooCodeExecutor

executor = OdooCodeExecutor(ConfigProvider(config))
result = executor.execute_code(
    "env['res.partner'].search_count([])",
    allow_unsafe=True,
)
```

`allow_unsafe=True` is still required for arbitrary code execution.

## Configuration

Preferred format: sectioned TOML. oduit is TOML-first, with YAML compatibility
for older configs.

Compatibility support still exists for:

- flat config files
- YAML environment files

For existing Odoo configs, import them with:

```bash
oduit init dev --from-conf /path/to/odoo.conf
oduit --env dev print-config
oduit --env dev doctor
```

You can also write a local project config with:

```bash
oduit init dev --from-conf ./odoo.conf --local
```

## Why Structured Results Matter

`OperationResult`-based workflows can fail semantically even when the process
exit code is `0`, for example when Odoo reports unmet dependencies or test
failures in log output. That parsed structure is available in both Python and
JSON output.

## Development

```bash
pytest
ruff check --fix --exit-non-zero-on-fix --config=.ruff.toml
ruff format --check
```

## License

This project is licensed under the Mozilla Public License 2.0. See
[`LICENSE`](LICENSE).
