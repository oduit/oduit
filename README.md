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

Create a local `.oduit.toml`:

```toml
[binaries]
python_bin = "./venv/bin/python"
odoo_bin = "./odoo/odoo-bin"

[odoo_params]
addons_path = "./addons"
db_name = "project_dev"
```

Then run:

```bash
oduit doctor
oduit version
oduit list-addons
oduit list-installed-addons
oduit install-order sale,purchase
oduit impact-of-update sale
```

Named environments work the same way via `~/.config/oduit/<env>.toml`:

```bash
oduit --env dev doctor
oduit --env dev run
oduit --env dev test --test-tags /sale
```

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
oduit --env dev impact-of-update sale

# Agent-first inspection
oduit --env dev agent context
oduit --env dev agent inspect-addon sale
oduit --env dev agent plan-update sale
oduit --env dev agent list-installed-addons --modules sale
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
oduit --env dev agent test-summary --allow-mutation --module my_partner --test-tags /my_partner

# Operations
oduit --env dev install sale
oduit --env dev update sale
oduit --env dev test --test-tags /sale
oduit --env dev shell
oduit --env dev --non-interactive create-db
oduit --env dev create-addon my_custom_module
oduit --env dev export-lang sale --language de_DE
```

## Coding Agents

`oduit agent ...` is the primary documented automation surface for external
coding agents.

Use [`docs/agent_contract.rst`](docs/agent_contract.rst) as the canonical guide
for:

- command sequence
- mutation policy
- payload expectations
- failure handling

Agent commands always emit JSON and do not require the global `--json` flag.
Structured payloads include an explicit `schema_version`, currently `2.0`.
For one-shot verification after an addon change, prefer
`oduit --env <env> agent validate-addon-change <module> --allow-mutation`.

Recommended command sequence for an addon field change:

```bash
oduit --env dev agent context
oduit --env dev agent inspect-addon my_partner
oduit --env dev agent get-model-fields res.partner --attributes string,type,required
oduit --env dev agent locate-model res.partner --module my_partner
oduit --env dev agent locate-field res.partner email3 --module my_partner
oduit --env dev agent list-addon-tests my_partner --model res.partner --field email3
oduit --env dev agent validate-addon-change my_partner --allow-mutation --install-if-needed --update --discover-tests
oduit --env dev agent test-summary --allow-mutation --module my_partner --test-tags /my_partner
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
plan = ops.plan_update("sale")
state = ops.get_addon_install_state("sale")
installed_addons = ops.list_installed_addons(modules=["sale"])
partners = ops.query_model("res.partner", fields=["name", "email"], limit=5)
extensions = ops.find_model_extensions("res.partner")
views = ops.get_model_views("res.partner", view_types=["form", "tree"])
```

The preferred Python surface is:

- `ConfigLoader` for loading configuration
- `OdooOperations` for high-level operations and typed planning/inspection
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

Preferred format: sectioned TOML.

Compatibility support still exists for:

- flat config files
- YAML environment files

For existing Odoo configs, import them with:

```bash
oduit init dev --from-conf /path/to/odoo.conf
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
