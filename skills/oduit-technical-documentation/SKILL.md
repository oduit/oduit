---
name: oduit-technical-documentation
description: Use oduit to create or update Arc42 technical architecture documentation for Odoo addons. Trigger when the user asks to generate, write, update, review, or improve technical documentation for Odoo addons, especially addon-local docs/architecture.md files.
---

# oduit Arc42 technical documentation skill

## Purpose

Use `oduit` as the discovery, runtime-inspection, and rendering layer for Odoo addon technical documentation.

The default single-addon output is an Arc42-style Markdown document stored inside the addon:

```text
<addon_root>/docs/architecture.md
```

Example:

```text
@addons/has_base
→ addons/has_base/docs/architecture.md
```

## When to use this skill

Use this skill when the user asks for any of the following:

- create technical documentation for an Odoo addon
- generate Arc42 documentation for an addon
- update `docs/architecture.md` for an addon
- document `@addons/<module>`
- review or improve addon architecture documentation
- produce developer-facing technical docs from an Odoo addon
- explain addon architecture, dependencies, models, views, security, routes, or runtime behavior in a durable documentation file

Do not use this skill for:

- implementing feature changes
- debugging runtime failures unrelated to documentation
- installing, updating, or uninstalling Odoo modules
- running Odoo tests
- quick factual answers where the user is not asking for durable documentation
- production database mutation

## Core rule

For a single addon, prefer the Arc42 technical documentation command.

Do this:

```bash
oduit agent technical-doc @addons/<module>
oduit agent technical-doc @addons/<module> --allow-mutation
```

or, for the human CLI fallback:

```bash
oduit docs technical @addons/<module> --output-in-addon
```

Do not make this the primary workflow:

```bash
oduit docs addon <module> --output docs/technical/<module>.md
```

`oduit docs addon` is a legacy/additional addon summary generator. Use it only for comparison or supplemental detail when the Arc42 document needs extra facts.

## Target syntax

Prefer explicit addon paths for write operations:

```bash
oduit agent technical-doc @addons/has_base --allow-mutation
```

Why:

- `@addons/has_base` makes the write target unambiguous.
- Module names can be duplicated across `addons_path`.
- oduit refuses ambiguous source writes and asks for an explicit path.

Use module names only for read-only preview when ambiguity is unlikely:

```bash
oduit agent technical-doc has_base
```

## Standard setup checks

Before generating or writing documentation, run compact read-only discovery:

```bash
oduit agent context
oduit agent resolve-config
oduit agent doctor
oduit agent resolve-addon-root @addons/<module>
oduit agent addon-info <module>
```

If `doctor` fails only because runtime/database access is unavailable, continue with `--source-only`.

If addon resolution fails, stop and report the configured `addons_path` issue. Do not invent module paths.

## Primary workflow: preview one addon

Use this when the user asks to review, plan, or preview documentation.

```bash
oduit agent technical-doc @addons/<module> \
  --path "$(pwd)"
```

For a source-only preview:

```bash
oduit agent technical-doc @addons/<module> \
  --source-only \
  --path "$(pwd)"
```

When you need the full Markdown in the JSON payload for editing or review:

```bash
oduit agent technical-doc @addons/<module> \
  --include-markdown \
  --path "$(pwd)"
```

Expected behavior:

- operation: `technical_doc_preview`
- read-only: `true`
- safety level: `safe_read_only`
- output hint: `<addon_root>/docs/architecture.md`

## Primary workflow: write addon-local Arc42 documentation

Use this when the user explicitly asks to create, write, update, or fix the addon documentation file.

```bash
oduit agent technical-doc @addons/<module> \
  --allow-mutation \
  --path "$(pwd)"
```

This writes:

```text
<addon_root>/docs/architecture.md
```

If the file already exists and the user asked to update/replace it:

```bash
oduit agent technical-doc @addons/<module> \
  --allow-mutation \
  --force \
  --path "$(pwd)"
```

For source-only generation:

```bash
oduit agent technical-doc @addons/<module> \
  --allow-mutation \
  --source-only \
  --path "$(pwd)"
```

After writing, always read the generated file before finalizing:

```bash
sed -n '1,220p' addons/<module>/docs/architecture.md
```

Then improve the file manually where oduit marks uncertainty or TODOs. Keep generated evidence accurate; add business context only when it is supported by source code, manifests, runtime metadata, or user-provided context.

## Human CLI fallback

Use this when the agent wrapper is unavailable or a person-readable CLI output is enough.

Preview to stdout:

```bash
oduit docs technical @addons/<module> \
  --template arc42 \
  --path "$(pwd)"
```

Write to the addon:

```bash
oduit docs technical @addons/<module> \
  --template arc42 \
  --output-in-addon \
  --path "$(pwd)"
```

Overwrite an existing addon-local doc:

```bash
oduit docs technical @addons/<module> \
  --template arc42 \
  --output-in-addon \
  --force \
  --path "$(pwd)"
```

Source-only fallback:

```bash
oduit docs technical @addons/<module> \
  --template arc42 \
  --source-only \
  --output-in-addon \
  --path "$(pwd)"
```

## Runtime enrichment

Use runtime enrichment by default when a safe development database is available.

Use `--source-only` when:

- no configured database exists;
- runtime inspection fails;
- the user asks for source-only docs;
- the environment is production-like or sensitive;
- database access would expose personal, customer, employee, invoice, payment, or other sensitive data.

Runtime-enriched commands may inspect models, fields, views, installed state, and database-backed metadata. They must remain read-only.

Never include production sample data in documentation.

## Controlling output size

For large addons, constrain generated documentation:

```bash
oduit agent technical-doc @addons/<module> \
  --max-models 40 \
  --max-fields-per-model 120 \
  --types form,tree,kanban,search \
  --path "$(pwd)"
```

For the human CLI:

```bash
oduit docs technical @addons/<module> \
  --output-in-addon \
  --max-models 40 \
  --max-fields-per-model 120 \
  --view-types form,tree,kanban,search \
  --path "$(pwd)"
```

Keep raw XML architecture out by default. Only use `--include-arch` if the user explicitly needs raw view XML or a specific XML customization cannot be explained otherwise.

## Supplemental read-only inspection commands

Use these only when the generated Arc42 draft is incomplete or needs verification.

Addon overview:

```bash
oduit agent inspect-addon <module>
oduit agent addon-info <module>
oduit agent get-addon-files <module> --globs "__manifest__.py,models/**/*.py,views/**/*.xml,security/**/*.csv,data/**/*.xml,controllers/**/*.py"
```

Models and fields:

```bash
oduit agent list-addon-models <module>
oduit agent find-model-extensions <model.name> --summary
oduit agent get-model-fields <model.name> \
  --attributes string,type,required,readonly,store,relation \
  --module <module>
oduit agent get-model-views <model.name> --types form,tree,kanban,search --summary
```

Dependencies:

```bash
oduit agent dependency-graph --modules <module>
oduit agent explain-install-order <module>
```

Runtime facts:

```bash
oduit agent list-installed-addons --module <module>
oduit agent inspect-model <model.name>
oduit agent inspect-field <model.name> <field_name> --with-db
```

Use low limits for any read-only record inspection. Do not place sensitive records into documentation.

## Expected Arc42 document shape

The generated document should follow this structure:

```markdown
# Architecture Documentation: <module>

## 1. Introduction and Goals

## 2. Architecture Constraints

## 3. Context and Scope

## 4. Solution Strategy

## 5. Building Block View

## 6. Runtime View

## 7. Deployment View

## 8. Cross-cutting Concepts

## 9. Architecture Decisions

## 10. Quality Requirements

## 11. Risks and Technical Debt

## Appendix A: oduit Evidence
```

Do not replace this with a generic custom structure such as:

```markdown
## Purpose

## Installation and dependencies

## Architecture overview

## Models

...
```

Those topics can be addressed inside the Arc42 sections, not as a replacement for them.

## Writing standards

After generation, improve readability without breaking evidence fidelity.

The final document should:

- explain the business purpose only when known from the manifest, code, or user context;
- identify Odoo dependencies and why they matter;
- describe owned models and extended models;
- summarize important fields, constraints, computed fields, and model methods;
- document XML records, views, menus, actions, security files, reports, controllers, and data files where detected;
- explain runtime flows inferred from routes, XML records, model methods, cron jobs, mail templates, or server actions;
- document security and access-control implications;
- list risks, missing evidence, TODOs, and technical debt explicitly;
- keep an evidence appendix so future maintainers can trace claims back to oduit-discovered facts.

Use `TODO:` markers for business context that cannot be inferred safely.

## Existing file handling

If `<addon>/docs/architecture.md` already exists:

1. Preview the generated replacement first:

   ```bash
   oduit agent technical-doc @addons/<module> --include-markdown --path "$(pwd)"
   ```

2. Compare with the existing document.

3. Preserve valuable human-written context.

4. Use `--force` only when the user asked to update or replace the file.

Do not overwrite existing architecture documentation silently.

## Multi-addon documentation

For several related addons, still generate one addon-local Arc42 file per addon:

```bash
oduit agent technical-doc @addons/<module_a> --allow-mutation --path "$(pwd)"
oduit agent technical-doc @addons/<module_b> --allow-mutation --path "$(pwd)"
```

Then optionally generate supplemental bundle/dependency docs if useful:

```bash
oduit docs dependency-graph \
  --modules <module_a>,<module_b> \
  --format markdown \
  --output docs/technical/dependency_graph.md \
  --path "$(pwd)"

oduit docs addons \
  --modules <module_a>,<module_b> \
  --format markdown \
  --output-dir docs/technical/addon_bundle \
  --path "$(pwd)"
```

These supplemental outputs do not replace addon-local `docs/architecture.md`.

## Error handling

### Addon not found

Run:

```bash
oduit agent list-addons
oduit agent resolve-addon-root @addons/<module>
```

Report the missing addon or incorrect `addons_path`. Do not fabricate a path.

### Ambiguous module name

Use an explicit addon path:

```bash
oduit agent technical-doc @addons/<module> --allow-mutation
```

Do not write by bare module name when multiple candidate roots exist.

### Runtime/database unavailable

Regenerate source-only:

```bash
oduit agent technical-doc @addons/<module> \
  --source-only \
  --allow-mutation \
  --path "$(pwd)"
```

State in the document that runtime enrichment was unavailable.

### Output too verbose

Regenerate with limits:

```bash
oduit agent technical-doc @addons/<module> \
  --max-models 30 \
  --max-fields-per-model 80 \
  --types form,tree,search \
  --path "$(pwd)"
```

### Existing file

Use `--force` only after confirming replacement/update is intended:

```bash
oduit agent technical-doc @addons/<module> \
  --allow-mutation \
  --force \
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

Do not run Odoo tests unless the user explicitly requests validation outside this documentation skill.

Do not use `--allow-mutation` except for the controlled source-file write to `<addon>/docs/architecture.md`.

Do not expose secrets from config files, database credentials, access tokens, customer records, employee records, invoices, payments, or production data.

## Final response checklist

When reporting back to the user, include:

- the addon documented;
- the generated or edited file path, normally `<addon>/docs/architecture.md`;
- whether runtime enrichment was used or `--source-only`;
- whether the command was preview-only or wrote the file;
- important warnings, TODOs, or unresolved metadata gaps;
- the key oduit commands used.

Do not paste the full documentation into chat unless the user asks for it.
