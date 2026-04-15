# Agent Contract Changes

This page tracks machine-facing changes to the `oduit agent` JSON contract.

## Current stability policy

- **Stable envelope:** `schema_version`, `type`, `operation`, `success`,
  `read_only`, `safety_level`, `warnings`, `errors`, `remediation`, `error`,
  `error_type`, `error_code`, `data`, `meta`
- **Stable command payload location:** command-specific fields live under
  `data`
- **Canonical timestamp:** `meta.timestamp`
- **Soft-stable:** optional debug metadata such as `data.command` and optional
  timing metadata such as `meta.duration`
- **Experimental:** newly introduced command-specific fields inside `data` that
  are not yet called out in the public docs

## Recent changes

### Removed flattened agent payload aliases

- Agent payloads no longer flatten command-specific `data` fields into the root
- The top-level `timestamp` alias is no longer emitted for agent payloads
- The top-level `generated_at` alias is no longer emitted for agent payloads
- `meta.generated_at` is no longer emitted for agent payloads
- Consumers must read command-specific fields from `payload["data"]`
- When `--show-command` is enabled, the raw command is emitted as
  `payload["data"]["command"]`

### Hid raw command metadata by default

- Agent payloads hide raw command metadata by default
- Callers that need the raw command can opt in with `oduit agent --show-command ...`
- The field remains optional debug metadata and is only present under
  `payload["data"]["command"]` when the command produced it

### Added generated command inventories and command tiers

- The canonical `oduit agent` registration surface now drives generated command
  inventory pages
- Command docs now distinguish payload stability from per-command stability
  tiers such as `stable_for_agents` and `beta_for_agents`

### Added read-only preflight and primitive inspection commands

- Added `preflight-addon-change` as a public read-only planning command
- Added `resolve-addon-root`, `get-addon-files`,
  `check-addons-installed`, `check-model-exists`, and
  `check-field-exists`
- New schema artifacts now publish those payload shapes under `schemas/agent/`

### Added per-step timing metadata

- Aggregate preflight and validation payloads now expose `duration_ms` on each
  `sub_results` entry when that step runs

### Added canonical config-shape metadata

- `resolve-config` now exposes `normalized_config` in the canonical sectioned
  shape
- `resolve-config` also reports `config_shape`, `shape_version`, and
  `deprecation_warnings` for legacy flat config files

### Added preserved parser failure excerpts

- Test-oriented structured payloads now preserve `failure_details[].raw_failure_excerpt`
  (and the normalized `traceback_summary[]` counterpart) when traceback parsing
  cannot fully recover the most useful lines
- `warnings` may now include parser diagnostics when result normalization falls
  back to preserved raw excerpts

### Added source-evidence and ambiguity metadata

- `locate-model` and `locate-field` expose `resolution`, `ambiguous`, and
  `ambiguity_reason` inside `payload["data"]`
- Source candidates now include `match_strength` and explicit `evidence`
  entries instead of relying on confidence alone

### Added machine-facing failure codes

- Agent payloads now expose `error_code` alongside `error_type`
- Current core codes include:
  - `config.addons_path_missing`
  - `config.environment_missing`
  - `module.not_found`
  - `module.duplicate_name`
  - `mutation.confirmation_required`
  - `input.invalid_json`
  - `runtime.query_failed`
  - `runtime.test_failure`
  - `runtime.install_dependency_error`

### Canonical generation metadata

- `meta.timestamp` is the only canonical creation timestamp for agent payloads
- `meta.duration` remains optional and may appear when the caller provides it
