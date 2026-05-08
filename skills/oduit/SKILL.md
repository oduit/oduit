---
name: oduit
description: Use oduit effectively from coding-agent workflows in Odoo repositories. Prefer this skill when inspecting Odoo addons, planning addon changes, checking manifests/dependencies, querying live Odoo metadata, running focused module verification, or using oduit instead of ad-hoc odoo-bin shell/psql snippets.
---

# oduit

## When to use this skill

Use this skill in Odoo repositories when a task needs addon, manifest,
dependency, runtime, or database context and `oduit` is available or can be run
with `uvx oduit`.

Good fits:

- inspect an addon, manifest, dependency tree, install order, or duplicate addon
  names
- locate model or field source files before editing an addon
- inspect live model, field, XMLID, view, table, constraint, or Many2many
  metadata
- plan or verify an addon change with structured JSON output
- run Odoo module tests through a normalized agent payload
- replace ad-hoc `odoo-bin shell`, direct `psql`, or custom runtime snippets with
  first-class inspection commands

Do not use oduit for unrelated Python tests, static linting, or plain file
search. Use normal repo tooling for those.

## First checks

1. Prefer the repository's existing `oduit` command.

   ```bash
   oduit --help
   ```

2. If `oduit` is not installed, use:

   ```bash
   uvx oduit --help
   ```

3. Start with diagnostics:

   ```bash
   oduit doctor
   oduit agent context
   oduit agent resolve-config
   ```

If `context`, `resolve-config`, `doctor`, or `list-duplicates` reports
blockers, handle those before runtime mutation.

## Preferred agent surface

For coding agents, prefer `oduit agent ...` over human-oriented commands and
over the Python API. Agent commands emit one JSON object with a stable envelope.

Stable top-level fields include:

- `schema_version`
- `type`
- `success`
- `read_only`
- `safety_level`
- `warnings`
- `errors`
- `remediation`
- `data`
- `meta`

Read command-specific information from `payload["data"]`. Do not depend on raw
human text output. Pass `oduit agent --show-command ...` only when you need
`data.command` for debugging.

## Read-only discovery commands

Use read-only commands first.

Environment and addon inventory:

```bash
oduit agent context
oduit agent doctor
oduit agent resolve-config
oduit agent list-addons
oduit agent list-installed-addons
oduit agent list-duplicates
oduit agent inspect-addon my_addon
oduit agent addon-info my_addon
oduit agent addon-doc my_addon
oduit agent get-addon-files my_addon
```

Dependency and update planning:

```bash
oduit agent dependency-graph --modules sale,purchase
oduit agent explain-install-order --modules sale
oduit agent plan-update my_addon
oduit agent preflight-addon-change my_addon --model res.partner --field email3
oduit agent prepare-addon-change my_addon --model res.partner --field email3 --types form,tree
```

Source location and test discovery:

```bash
oduit agent locate-model res.partner --module my_addon
oduit agent locate-field res.partner email3 --module my_addon
oduit agent list-addon-tests my_addon --model res.partner --field email3
oduit agent recommend-tests --module my_addon --paths models/res_partner.py,views/res_partner_views.xml
oduit agent list-addon-models my_addon
oduit agent find-model-extensions res.partner --summary
oduit agent get-model-views res.partner --types form,tree --summary
```

Runtime and database inspection:

```bash
oduit agent inspect-ref base.action_partner_form
oduit agent inspect-cron base.ir_cron_autovacuum
oduit agent inspect-modules --state installed --names-only
oduit agent inspect-model res.partner
oduit agent inspect-field res.partner email --with-db
oduit agent db-table res_partner
oduit agent db-column res_partner email
oduit agent db-constraints sale_order
oduit agent db-m2m res.partner category_id
oduit agent performance-table-scans
oduit agent performance-slow-queries --limit 10
oduit agent manifest-check sale
oduit agent manifest-show sale
```

Safe runtime reads:

```bash
oduit agent query-model res.partner --fields name,email --limit 5
oduit agent read-record res.partner 1 --fields name,email
oduit agent search-count res.partner
oduit agent get-model-fields res.partner --attributes string,type,required
```

Prefer these wrappers over `exec`, `exec-file`, `inspect recordset`,
`odoo-bin shell`, or direct SQL.

## Typical addon-change loop

For a change such as adding `email3` to `res.partner` in `my_addon`:

1. Resolve environment and addon context.

   ```bash
   oduit agent context
   oduit agent inspect-addon my_addon
   oduit agent addon-doc my_addon
   ```

2. Inspect runtime model metadata and source locations.

   ```bash
   oduit agent get-model-fields res.partner --attributes string,type,required
   oduit agent get-model-views res.partner --types form,tree --summary
   oduit agent locate-model res.partner --module my_addon
   oduit agent locate-field res.partner email3 --module my_addon
   oduit agent list-addon-tests my_addon --model res.partner --field email3
   ```

3. Plan before editing when the change affects install/update behavior.

   ```bash
   oduit agent plan-update my_addon
   oduit agent prepare-addon-change my_addon --model res.partner --field email3 --types form,tree
   ```

4. Edit the addon source with normal repo tools.

5. Ask oduit for focused verification hints.

   ```bash
   oduit agent recommend-tests --module my_addon --paths models/res_partner.py,views/res_partner_views.xml
   ```

6. Verify with the narrowest useful runtime command.

   ```bash
   oduit agent test-summary --module my_addon --test-tags /my_addon
   ```

7. If the database must be updated or the module may need installation, make
   mutation explicit.

   ```bash
   oduit agent validate-addon-change my_addon --allow-mutation --update --discover-tests
   oduit agent validate-addon-change my_addon --allow-mutation --install-if-needed --update --discover-tests
   ```

## Mutation policy

Default to read-only commands.

Runtime database mutation commands:

- `install-module`
- `update-module`
- `uninstall-module`
- `test-summary` when called with `--install` or `--update`
- `validate-addon-change` when called with install/update options
- `inspect-cron --trigger`

Source mutation commands:

- `create-addon`
- `export-lang`

Rules:

- Pass `--allow-mutation` when using mutation commands.
- Use `--dry-run` first when available.
- `uninstall-module` additionally requires `--allow-uninstall` and
  `allow_uninstall = true` in config.
- `write_protect_db = true` blocks runtime DB mutation for every caller.
- `agent_write_protect_db = true` blocks agent runtime DB mutation.
- `needs_mutation_flag = true` requires `--allow-mutation` for human runtime DB
  mutation.
- `agent_needs_mutation_flag = true` requires `--allow-mutation` for agent
  runtime DB mutation.
- Plain `test-summary` without `--install` or `--update` is read-only.

Never widen destructive behavior silently. If a task needs installation, update,
uninstall, cron triggering, source generation, or translation export, call that
out and use the explicit flags.

## Human CLI fallback

Use human-oriented commands when a person-readable result is enough or when no
agent wrapper exists:

```bash
oduit doctor
oduit version
oduit list-addons
oduit list-installed-addons
oduit print-manifest sale
oduit list-depends sale
oduit install-order sale,purchase
oduit impact-of-update sale
oduit docs addon sale --source-only
oduit inspect model res.partner
oduit inspect field res.partner email --with-db
oduit db table res_partner
oduit manifest check sale
```

Use `--json` with human-oriented commands only when the command supports a
machine-readable shape you have verified. For automation, prefer the agent
commands.

## Trusted arbitrary execution

`oduit exec`, `oduit exec-file`, `inspect recordset`, `OdooCodeExecutor`, and
`execute_python_code()` are trusted arbitrary execution surfaces. Use them only
when first-class `agent`, `inspect`, `db`, `performance`, `manifest`, or
`query-model` commands cannot answer the question.

When using arbitrary execution:

- keep snippets read-only unless mutation is explicitly requested
- rely on rollback-by-default behavior
- pass `--commit` only when mutation is intended and approved
- in Python API use, pass `allow_unsafe=True` explicitly where required

## Python API

Prefer the CLI agent surface for external coding-agent workflows. Use the
Python API only when writing Python integration code inside a project.

Common imports:

```python
from oduit import ConfigLoader, ModuleManager, OdooInspector, OdooOperations, OdooQuery
```

Examples:

```python
loader = ConfigLoader()
config = loader.load_config("dev")

ops = OdooOperations(config, verbose=True)
context = ops.get_environment_context()
addon = ops.inspect_addon("sale")

manager = ModuleManager(config["addons_path"])
addons = manager.find_modules()
install_order = manager.get_install_order("sale", "purchase")

inspector = OdooInspector(config)
model = inspector.inspect_model("res.partner")
table = inspector.describe_table("res_partner")

query = OdooQuery(config)
partners = query.query_model("res.partner", fields=["name", "email"], limit=5)
```

Do not use `execute_python_code()` or `OdooCodeExecutor` for routine agent
automation.

## Verification guidance

Use the narrowest verification that proves the change:

- manifest or dependency change: `manifest-check`, `dependency-graph`,
  `explain-install-order`, or `plan-update`
- source-only addon change: `recommend-tests` then targeted repo tests
- runtime model or field change: `get-model-fields`, `inspect-model`,
  `inspect-field`, and focused `test-summary`
- install/update behavior: `validate-addon-change --allow-mutation --update`
  or `--install-if-needed --update`
- database metadata question: `db-table`, `db-column`, `db-constraints`, or
  `db-m2m`

Report the exact command, success flag, key warnings/errors, and any unresolved
blocker from the JSON payload.
