---
name: oduit-technical-documentation
description: Use oduit split technical documentation workflow deterministic evidence in docs/architecture.evidence.md and LLM/human report in docs/architecture.md.
---

# oduit Arc42 technical documentation skill

## Purpose

Use `oduit` as the discovery, runtime-inspection, and rendering layer for Odoo addon technical documentation.

The primary workflow is split:

```text
<addon_root>/docs/architecture.evidence.md          # generated deterministic evidence
<addon_root>/docs/architecture.evidence.oduit.json  # evidence sidecar
<addon_root>/docs/architecture.md                   # LLM/human report
<addon_root>/docs/architecture.oduit.json           # report sidecar
```

Example:

```text
addons/my_addon
→ addons/my_addon/docs/architecture.md
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

For a single addon, prefer split commands:

Never emit internal reasoning markers such as `Thought:` or `Thinking:` in user-visible output. Report only actions, outcomes, and concise decisions.

Do this:

```bash
oduit agent technical-evidence @addons/<module> --allow-mutation --source-only --progress
oduit agent technical-report @addons/<module> --allow-mutation --source-only --progress
oduit agent technical-doc-diff @addons/<module> --include-diff
oduit agent technical-doc-check @addons/<module> --include-files
```

or, for the human CLI fallback:

```bash
oduit docs technical-evidence @addons/<module> --output-in-addon --source-only --progress
oduit docs technical-report @addons/<module> --output-in-addon --source-only --progress
oduit docs technical-diff @addons/<module> --include-diff
oduit docs technical-check @addons/<module> --include-files
```

Do not make this the primary workflow:

```bash
oduit docs addon <module> --output docs/technical/<module>.md
```

`oduit docs addon` is a legacy/additional addon summary generator. Use it only for comparison or supplemental detail when the Arc42 document needs extra facts.

## Target syntax

Prefer explicit addon paths for write operations:

```bash
oduit agent technical-evidence @addons/my_addon --allow-mutation --source-only
oduit agent technical-report @addons/my_addon --allow-mutation --source-only
```

Why:

- `@addons/my_addon` makes the write target unambiguous.
- Module names can be duplicated across `addons_path`.
- oduit refuses ambiguous source writes and asks for an explicit path.

Use module names only for read-only preview when ambiguity is unlikely:

```bash
oduit agent technical-evidence my_addon
oduit agent technical-report my_addon
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

After `oduit agent resolve-config`, inspect
`[documentation].allowed_addon_dirs`. Never write docs for addons outside that
allowlist.

If `doctor` fails only because runtime/database access is unavailable, continue with `--source-only`.

If addon resolution fails, stop and report the configured `addons_path` issue. Do not invent module paths.

## Primary workflow: split evidence + report

Use this when the user asks to review, plan, or preview documentation.

```bash
oduit agent technical-evidence @addons/<module> --progress
oduit agent technical-report @addons/<module> --progress
oduit agent technical-doc-diff @addons/<module> --include-diff
oduit agent technical-doc-check @addons/<module> --include-files
```

Write evidence:

```bash
oduit agent technical-evidence @addons/<module> \
  --allow-mutation \
  --source-only \
  --progress
```

Write report seed:

```bash
oduit agent technical-report @addons/<module> \
  --allow-mutation \
  --source-only \
  --progress
```

Expected behavior:

Never manually edit `docs/architecture.evidence.md`. LLM/human edits belong in `docs/architecture.md`.
Generate runtime evidence once. `technical-report` must consume
`docs/architecture.evidence.md` and must not rerun runtime metadata enrichment
when valid evidence exists.

If files already exist and the user asked to update/replace them:

```bash
# Replace deterministic evidence.
oduit agent technical-evidence @addons/<module> \
  --allow-mutation \
  --source-only \
  --progress \
  --force

# Replace report seed.
oduit agent technical-report @addons/<module> \
  --allow-mutation \
  --source-only \
  --progress \
  --force
```

Use `technical-report --force` only when replacement is explicitly requested and
useful human-written content in `docs/architecture.md` has been preserved.

Runtime mode (safe dev/test DB only):

```bash
oduit agent technical-evidence @addons/<module> \
  --allow-mutation \
  --runtime \
  --force \
  --progress \
  --max-models 40 \
  --max-fields-per-model 120 \
  --types form,tree,kanban,search

oduit agent technical-report @addons/<module> \
  --allow-mutation \
  --force \
  --progress
```

After writing, always read the generated file before finalizing:

```bash
sed -n '1,220p' addons/<module>/docs/architecture.md
```

Then improve the file manually where oduit marks uncertainty or TODOs. Keep generated evidence accurate; add business context only when it is supported by source code, manifests, runtime metadata, or user-provided context.

After writing, always run a quality pass:

```bash
oduit agent technical-doc-check @addons/<module> --include-files
grep -nE 'thisaddon|projectowner|maintenanceroles|processowner|manifestchanges' addons/<module>/docs/architecture.md || true
grep -n 'TODO:' addons/<module>/docs/architecture.md || true
```

If manual edits were made after generation, either:

- report `document_edited` as expected, or
- run `oduit agent technical-doc-accept @addons/<module> --allow-mutation` to accept the reviewed document snapshot.

## Legacy monolithic workflow (legacy documents)

Use this only for existing legacy docs containing `oduit:generated` blocks.

Use refresh to update only generated evidence blocks while preserving manual prose
outside managed markers.

Preview (default dry-run):

```bash
oduit agent technical-doc-refresh @addons/<module>
oduit docs technical-refresh @addons/<module>
```

Write refreshed blocks:

```bash
oduit agent technical-doc-refresh @addons/<module> --allow-mutation
oduit docs technical-refresh @addons/<module> --write
```

If a managed block was manually edited, refresh reports it and skips overwrite by
default. Force replacement only when the user explicitly wants to discard manual
block edits:

```bash
oduit agent technical-doc-refresh @addons/<module> \
  --allow-mutation \
  --force-edited-blocks
oduit docs technical-refresh @addons/<module> \
  --write \
  --force-edited-blocks
```

## Tracking and freshness

When oduit writes `<addon>/docs/architecture.md`, it also writes:

```text
<addon>/docs/architecture.oduit.json
```

Use this sidecar to check when the document was first tracked, when it was last generated, whether the Markdown was manually edited after generation, and whether addon source files changed after generation.

New sidecars store paths relative to the project base automatically. Prefer a
project-local `.oduit.toml` and explicit addon paths such as
`@addons/<module>` when writing docs.

Check one addon:

```bash
oduit agent technical-doc-check @addons/<module> --include-files
oduit agent technical-doc-status @addons/<module>
```

Check all addons:

```bash
oduit agent technical-doc-status --only-stale
```

Human CLI equivalents:

```bash
oduit docs technical-status @addons/<module>
oduit docs technical-check @addons/<module> --include-files
oduit docs technical-next addons
oduit docs technical-status --only-stale
```

Pick the next addon that still needs work:

```bash
oduit agent technical-doc-next
```

Use `oduit agent technical-doc-next addons` only when intentionally narrowing
the search further.

If `technical-doc-next` returns a native Odoo addon (for example `account`),
the project config is likely missing `[documentation].allowed_addon_dirs`.

If status is `source_changed`, regenerate or manually review the architecture
document. If status is `document_edited`, compare the human edits before
overwriting with `--force`.

`created_at` means the first tracked generation recorded by oduit. Older generated documents without a sidecar are reported as `untracked` until they are regenerated.

## Human CLI fallback

Use this when the agent wrapper is unavailable or a person-readable CLI output is enough.

Preview to stdout:

```bash
oduit docs technical @addons/<module> \
  --template arc42
```

Write to the addon:

```bash
oduit docs technical @addons/<module> \
  --template arc42 \
  --output-in-addon
```

Overwrite an existing addon-local doc:

```bash
oduit docs technical @addons/<module> \
  --template arc42 \
  --output-in-addon \
  --force
```

Source-only fallback:

```bash
oduit docs technical @addons/<module> \
  --template arc42 \
  --source-only \
  --output-in-addon
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

Decide generation mode before the first write and keep it stable for that run:

- use `--runtime` only when the configured database is a safe dev/test database;
- use `--source-only` otherwise;
- do not write source-only first and then overwrite with runtime unless runtime access became available after the first attempt.

Never include production sample data in documentation.

## Controlling output size

For large addons, constrain generated documentation:

```bash
oduit agent technical-doc @addons/<module> \
  --max-models 40 \
  --max-fields-per-model 120 \
  --types form,tree,kanban,search
```

For the human CLI:

```bash
oduit docs technical @addons/<module> \
  --output-in-addon \
  --max-models 40 \
  --max-fields-per-model 120 \
  --view-types form,tree,kanban,search
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
   oduit agent technical-doc-check @addons/<module> --include-files
   oduit agent technical-doc-diff @addons/<module> --include-diff
   ```

2. Compare with the existing document.

3. Preserve valuable human-written context.

4. Use `--force` only when the user asked to update or replace files:

   ```bash
   oduit agent technical-evidence @addons/<module> --allow-mutation --source-only --force --progress
   oduit agent technical-report @addons/<module> --allow-mutation --source-only --force --progress
   ```

Do not overwrite existing architecture documentation silently.

## Multi-addon documentation

For several related addons, still generate one addon-local Arc42 file per addon:

```bash
oduit agent technical-evidence @addons/<module_a> --allow-mutation --source-only --progress
oduit agent technical-report @addons/<module_a> --allow-mutation --source-only --progress
oduit agent technical-evidence @addons/<module_b> --allow-mutation --source-only --progress
oduit agent technical-report @addons/<module_b> --allow-mutation --source-only --progress
```

Then optionally generate supplemental bundle/dependency docs if useful:

```bash
oduit docs dependency-graph \
  --modules <module_a>,<module_b> \
  --format markdown \
  --output docs/technical/dependency_graph.md

oduit docs addons \
  --modules <module_a>,<module_b> \
  --format markdown \
  --output-dir docs/technical/addon_bundle
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
oduit agent technical-evidence @addons/<module> --allow-mutation --source-only --progress
oduit agent technical-report @addons/<module> --allow-mutation --source-only --progress
```

Do not write by bare module name when multiple candidate roots exist.

### Runtime/database unavailable

Regenerate source-only:

```bash
oduit agent technical-evidence @addons/<module> --source-only --allow-mutation --progress
oduit agent technical-report @addons/<module> --source-only --allow-mutation --progress
```

State in the document that runtime enrichment was unavailable.

### Output too verbose

Regenerate with limits:

```bash
oduit agent technical-evidence @addons/<module> \
  --allow-mutation \
  --source-only \
  --progress \
  --max-models 30 \
  --max-fields-per-model 80 \
  --types form,tree,search
oduit agent technical-report @addons/<module> --allow-mutation --source-only --progress
```

### Existing file

Use `--force` only after confirming replacement/update is intended:

```bash
oduit agent technical-evidence @addons/<module> --allow-mutation --source-only --force --progress
oduit agent technical-report @addons/<module> --allow-mutation --source-only --force --progress
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
Do not run full `pytest` for this workflow unless the user explicitly asks.

Use `--allow-mutation` only for controlled documentation source writes:

- `docs/architecture.evidence.md`
- `docs/architecture.evidence.oduit.json`
- `docs/architecture.md`
- `docs/architecture.oduit.json`
- review-acceptance metadata updates via `technical-doc-accept`

Do not expose secrets from config files, database credentials, access tokens, customer records, employee records, invoices, payments, or production data.

## Final response checklist

When reporting back to the user, include:

- `Addon:`
- `Evidence:`
- `Evidence metadata:`
- `Report:`
- `Report metadata:`
- `Diff status:`
- `Generation mode:`
- `Final status:`
- `Evidence manually edited:`
- `Manual edits:`
- `Remaining TODO count:`
- `Warnings:`
- `Commands used:`
- `Tests/validation:`

Do not paste the full documentation into chat unless the user asks for it.
