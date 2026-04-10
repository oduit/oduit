# Agent Contract Changes

This page tracks machine-facing changes to the `oduit agent` JSON contract.

## 2.x stability policy

- **Stable:** `schema_version`, `type`, `operation`, `success`, `read_only`,
  `safety_level`, `warnings`, `errors`, `remediation`, `error`, `error_type`,
  `error_code`, `data`, `meta`
- **Soft-stable:** additive command-specific fields flattened from `data`, plus
  optional metadata such as `generated_at`, `duration`, `config_source`,
  `database`, and `resolved_addons_path`
- **Experimental:** newly introduced command-specific fields that are not yet
  called out in the public docs

## Recent changes

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

### Added normalized generation metadata

- Structured payloads now expose `generated_at` as an alias of the canonical
  envelope timestamp
- `duration` remains optional and may appear when the caller provides it
