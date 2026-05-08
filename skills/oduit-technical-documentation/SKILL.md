---
name: oduit-technical-documentation
description: Use oduit to create detailed technical documentation for Odoo addons, models, fields, views, dependencies, and multi-addon architecture. Trigger only when the user asks you to write, generate, update, or improve detailed technical documentation for Odoo code.
---

# oduit technical documentation skill

## What I do

Use `oduit` as the source-discovery and runtime-inspection layer for Odoo technical documentation.

This skill helps you:

- Generate addon-level technical documentation.
- Generate model-level technical documentation.
- Generate multi-addon documentation bundles with deduplicated shared model pages.
- Generate dependency graphs and Mermaid diagrams.
- Enrich documentation with runtime model, field, view, manifest, install-state, and database metadata.
- Convert `oduit` JSON/Markdown output into readable technical documentation for humans.

## When to use me

Use this skill when the user asks for any of the following:

- "write technical documentation for addon `<module>`"
- "document this Odoo module"
- "create architecture documentation for these addons"
- "create model documentation for `<model>`"
- "create a dependency diagram"
- "generate Markdown documentation for a folder of addons"
- "explain how these Odoo addons/models/views relate to each other"
- "produce developer-facing docs from an Odoo codebase"

Do not use this skill for:

- implementing feature changes
- debugging test failures
- installing, updating, or uninstalling addons
- quick one-off factual answers where full documentation is not requested
- production database mutation or any command requiring `--allow-mutation`

All workflows in this skill must be read-only unless the user explicitly asks for a separate mutation task.

## Operating rules

1. Prefer `oduit agent ...` commands for discovery because they return structured payloads.
2. Prefer `oduit docs ...` commands when you need ready-to-commit Markdown files.
3. Run only read-only commands.
4. Do not include raw JSON in the final documentation unless the user explicitly asks for machine-readable output.
5. Do not include raw XML view architecture unless the user asks for it or it is necessary to explain a specific view customization.
6. Use `--source-only` when no usable Odoo database is available, when runtime commands fail, or when the user asks for source-only documentation.
7. Use `--path "$(pwd)"` or another repository root path when generating docs so paths are relative and stable.
8. Limit output size when needed with `--max-models`, `--max-fields`, and `--max-fields-per-model`.

## Basic setup checks

Before generating documentation, identify the oduit environment and confirm that the requested addon/model can be inspected.

Use these commands first:

```bash
oduit agent context
oduit agent resolve-config
oduit agent doctor
```

For one addon:

```bash
oduit agent inspect-addon <module>
oduit agent addon-info <module>
oduit agent resolve-addon-root <module>
oduit agent manifest-show <module>
```

For multiple addons:

```bash
oduit agent list-addons --select-dir <addons_dir_name>
oduit agent check-addons-installed --modules <module_a>,<module_b>
oduit agent dependency-graph --modules <module_a>,<module_b>
```

If any command reports that the addon is not found, inspect the configured `addons_path` and stop. Do not invent module paths.

## Documentation generation commands

### Single addon Markdown

Use this for a full technical documentation page for one addon.

```bash
mkdir -p docs/technical

oduit docs addon <module> \
  --format markdown \
  --output docs/technical/<module>.md \
  --path "$(pwd)"
```

Use runtime enrichment by default. Use source-only mode when there is no reliable database:

```bash
oduit docs addon <module> \
  --source-only \
  --format markdown \
  --output docs/technical/<module>.md \
  --path "$(pwd)"
```

Use limits for large addons:

```bash
oduit docs addon <module> \
  --format markdown \
  --output docs/technical/<module>.md \
  --max-models 40 \
  --max-fields-per-model 120 \
  --view-types form,tree,kanban,search \
  --path "$(pwd)"
```

### Single model Markdown

Use this when the documentation is centered on a model such as `res.partner`.

```bash
mkdir -p docs/technical/models

oduit docs model <model.name> \
  --format markdown \
  --output docs/technical/models/<model_name>.md \
  --field-attributes string,type,required,readonly,store,relation \
  --view-types form,tree,kanban,search \
  --max-fields 150 \
  --path "$(pwd)"
```

Example:

```bash
oduit docs model res.partner \
  --format markdown \
  --output docs/technical/models/res_partner.md \
  --field-attributes string,type,required,readonly,store,relation \
  --view-types form,tree,search \
  --max-fields 150 \
  --path "$(pwd)"
```

### Dependency graph documentation

Use this for architecture docs and install/dependency relationships.

```bash
oduit docs dependency-graph \
  --modules <module_a>,<module_b>,<module_c> \
  --format markdown \
  --output docs/technical/dependency_graph.md \
  --path "$(pwd)"
```

For direct dependencies only:

```bash
oduit docs dependency-graph \
  --modules <module_a>,<module_b>,<module_c> \
  --direct-only \
  --format markdown \
  --output docs/technical/dependency_graph_direct.md \
  --path "$(pwd)"
```

For a raw Mermaid diagram:

```bash
oduit docs dependency-graph \
  --modules <module_a>,<module_b>,<module_c> \
  --format mermaid \
  --output docs/technical/dependency_graph.mmd \
  --path "$(pwd)"
```

### Multi-addon documentation bundle

Use this when documenting a complete custom addons directory or several related modules. This is the preferred workflow for avoiding repeated `res.partner`, `res.users`, and other shared model sections in every addon page.

```bash
mkdir -p docs/technical/addon_bundle

oduit docs addons \
  --select-dir <addons_dir_name> \
  --format markdown \
  --output-dir docs/technical/addon_bundle \
  --max-fields-per-model 120 \
  --path "$(pwd)"
```

For an explicit module list:

```bash
oduit docs addons \
  --modules <module_a>,<module_b>,<module_c> \
  --format markdown \
  --output-dir docs/technical/addon_bundle \
  --max-fields-per-model 120 \
  --path "$(pwd)"
```

Expected output structure:

```text
docs/technical/addon_bundle/
├── index.md
├── bundle.json
├── addons/
│   ├── <module_a>.md
│   └── <module_b>.md
└── models/
    ├── res.partner.md
    └── res.users.md
```

Use `index.md` as the entry point. Use files in `models/` for shared model details and files in `addons/` for addon-specific summaries and links.

## Agent-first discovery commands

Use these when you need structured facts before writing or revising documentation.

### Addon overview

```bash
oduit agent addon-info <module>
oduit agent list-addon-models <module>
oduit agent get-addon-files <module> --globs "__manifest__.py,models/**/*.py,views/**/*.xml,security/**/*.csv,data/**/*.xml"
```

### Model and field facts

```bash
oduit agent check-model-exists <model.name> --module <module>
oduit agent find-model-extensions <model.name> --summary
oduit agent get-model-fields <model.name> \
  --attributes string,type,required,readonly,store,relation \
  --module <module>
oduit agent get-model-views <model.name> --types form,tree,kanban,search --summary
```

### Runtime metadata

```bash
oduit agent inspect-model <model.name>
oduit agent inspect-field <model.name> <field_name> --with-db
oduit agent list-installed-addons --module <module>
```

### Read-only sample data

Use this only when sample records help explain the technical behavior. Keep record limits low.

```bash
oduit agent query-model <model.name> \
  --fields id,display_name,create_date \
  --limit 10

oduit agent search-count <model.name> --domain-json '[["active","=",true]]'
```

Never expose personal, customer, financial, or production data in documentation. Replace sensitive values with sanitized examples.

## Recommended workflow: one addon

1. Run setup checks:

   ```bash
   oduit agent context
   oduit agent doctor
   oduit agent inspect-addon <module>
   oduit agent addon-info <module>
   ```

2. Generate the first draft:

   ```bash
   oduit docs addon <module> \
     --format markdown \
     --output docs/technical/<module>.md \
     --path "$(pwd)"
   ```

3. Inspect model-specific details if the generated draft is too shallow:

   ```bash
   oduit agent list-addon-models <module>
   oduit agent find-model-extensions <model.name> --summary
   oduit agent get-model-fields <model.name> --module <module>
   oduit agent get-model-views <model.name> --summary
   ```

4. Rewrite the generated Markdown into final technical documentation. Keep generated facts, but improve the narrative.

5. Final documentation should normally include:

   - purpose and scope
   - manifest metadata and dependencies
   - installed/runtime state if available
   - model declarations and inherited models
   - key fields grouped by model
   - views, menus, actions, security files, data files, and reports where relevant
   - dependency graph or Mermaid diagram
   - extension points for future development
   - operational notes and known constraints

## Recommended workflow: multiple related addons

1. Identify the module set:

   ```bash
   oduit agent list-addons --select-dir <addons_dir_name>
   ```

2. Generate a deduplicated bundle:

   ```bash
   oduit docs addons \
     --select-dir <addons_dir_name> \
     --format markdown \
     --output-dir docs/technical/<addons_dir_name> \
     --max-fields-per-model 120 \
     --path "$(pwd)"
   ```

3. Open `docs/technical/<addons_dir_name>/index.md`.

4. Use `addons/*.md` for addon-specific docs.

5. Use `models/*.md` for shared model docs. Do not duplicate shared model sections inside each addon page.

6. Add a short manually written architecture overview at the top-level index when the generated output is too mechanical.

## Recommended workflow: architecture or dependency docs

Use dependency docs plus focused model extension inspection.

```bash
oduit docs dependency-graph \
  --modules <module_a>,<module_b>,<module_c> \
  --format markdown \
  --output docs/technical/dependencies.md \
  --path "$(pwd)"

oduit agent dependency-graph --modules <module_a>,<module_b>,<module_c>
oduit agent find-model-extensions <model.name> --summary
```

The final architecture document should explain:

- selected modules and why they belong together
- dependency edges and direct/transitive dependency meaning
- central models and which addons own or extend them
- integration points with core Odoo apps
- cross-addon data flow
- risks from missing dependencies or optional modules

## Writing standards

Produce documentation that a developer can use without reading every source file.

Use this structure for addon docs unless the user requests another format:

```markdown
# <Module technical name> technical documentation

## Purpose

## Installation and dependencies

## Architecture overview

## Models

## Fields

## Views and UI

## Security and access control

## Data, automation, and reports

## External integrations

## Extension points

## Testing and validation notes

## Known limitations
```

For model docs:

```markdown
# <model.name> technical documentation

## Purpose

## Owning addon and extensions

## Field overview

## Computed fields and constraints

## Views

## Security

## Usage patterns

## Extension notes
```

For multi-addon docs:

```markdown
# <Feature or folder name> technical documentation

## Scope

## Addons in this bundle

## Dependency graph

## Shared models

## Addon-by-addon details

## Cross-addon workflows

## Operational notes

## Known limitations
```

## Output handling

When `oduit docs ...` writes Markdown, read the generated file before editing it.

When `oduit agent ...` returns JSON, extract these parts first:

- `success`
- `warnings`
- `errors`
- `remediation`
- `data`
- nested `markdown` fields if present
- `dependency_graph`
- `models`
- `addon_info`
- `extension_inventory`
- `field_metadata`
- `view_inventory`

If the payload is too large:

- rerun with `--summary`
- restrict `--types`
- restrict field attributes
- set `--max-fields`, `--max-models`, or `--max-fields-per-model`
- avoid `--include-arch`

## Error handling

### Missing addon

Run:

```bash
oduit agent list-addons
oduit agent resolve-addon-root <module>
```

Then report the configured `addons_path` problem. Do not fabricate paths.

### Missing or unavailable database

Rerun documentation generation with `--source-only`.

```bash
oduit docs addon <module> --source-only --format markdown --output docs/technical/<module>.md --path "$(pwd)"
```

Clearly state in the document that runtime metadata was unavailable.

### Runtime metadata is incomplete

Use source discovery plus targeted runtime commands:

```bash
oduit agent find-model-extensions <model.name> --summary
oduit agent get-model-fields <model.name> --attributes string,type,required,readonly,store,relation
oduit agent get-model-views <model.name> --summary
```

Document uncertainties explicitly.

### Output is too verbose

Regenerate with limits:

```bash
oduit docs addon <module> \
  --max-models 30 \
  --max-fields-per-model 80 \
  --view-types form,tree,search \
  --format markdown \
  --output docs/technical/<module>.md \
  --path "$(pwd)"
```

## Safety rules

Never run these commands as part of this documentation skill:

```bash
oduit install ...
oduit update ...
oduit uninstall ...
oduit agent install-module ...
oduit agent update-module ...
oduit agent uninstall-module ...
oduit agent validate-addon-change ...
```

Do not use `--allow-mutation`.

Do not run Odoo tests unless the user explicitly asks for validation outside this documentation skill.

Do not expose secrets from config files, database credentials, access tokens, customer records, employee records, invoices, payments, or production data.

## Final response checklist

When returning documentation work to the user, include:

- the generated or edited documentation file path
- whether runtime enrichment was used or `--source-only`
- any warnings or unresolved metadata gaps
- the most important `oduit` commands used
- the next best command only if follow-up inspection is needed
