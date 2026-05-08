# AGENTS.md

This file defines how coding agents should work in the `oduit` repository.

## 1. Communication

- Assume the user is technically strong.
- Be direct, concrete, and brief.
- Do not explain obvious Python, Typer, or Odoo basics.
- Do not narrate trivial edits.
- Push back on bad ideas when the tradeoff is real.
- Ask a clarifying question only when ambiguity would likely cause the wrong change.
- Otherwise, proceed.

## 2. Working Style

### 2.1 Prefer the smallest correct change

Default to the narrowest change that solves the actual problem.

Priorities:

1. behavior is correct
2. behavior is verified
3. intent is obvious in code
4. changes stay local
5. public behavior stays stable unless the task requires changing it

Avoid:

- speculative abstractions
- framework-like indirection for a single use case
- broad refactors during feature work
- renaming things without payoff
- changing unrelated CLI output
- changing docs for behavior that did not change
- “cleanup” commits mixed into task work

### 2.2 Preserve existing interfaces unless asked

oduit is both:

- a developer CLI
- a Python library used programmatically
- a tool that may be called by other agents

Therefore, treat these as stability-sensitive:

- command names
- option names
- JSON output shape
- result dictionary keys
- public imports from `oduit.__init__`
- config loading behavior
- `.oduit.toml` local-project workflow

If a change must break one of these, call it out explicitly.

### 2.3 Solve tasks as verifiable outcomes

Translate requests into a concrete loop:

1. identify the affected surface
2. make the smallest coherent code change
3. verify with the narrowest useful test set
4. widen verification only as needed

Examples:

- bugfix -> add or update a failing test, then fix
- CLI change -> test command behavior and exit code
- parser/result change -> test structured result fields, not just raw text
- config change -> test both local and environment config behavior
- manifest/addon discovery change -> test against realistic addon-path scenarios
- docs-only change -> ensure docs reflect actual behavior in code

## 3. Repository-Specific Guidance

### 3.1 What this project is

`oduit` is a Python package for controlling Odoo workflows through configuration, CLI commands, command builders, structured process execution, module/addon inspection, and in-process Odoo code execution.

Important surfaces:

- `oduit/cli_typer.py` — main CLI entrypoint and command wiring
- `oduit/builders.py` — command construction and operation metadata
- `oduit/process_manager.py` and `oduit/base_process_manager.py` — execution layer
- `oduit/operation_result.py` — structured result parsing and normalization
- `oduit/config_loader.py` and `oduit/config_provider.py` — config resolution and access
- `oduit/module_manager.py` and `oduit/addons_path_manager.py` — addon discovery and dependency logic
- `oduit/odoo_operations.py` — high-level orchestration
- `oduit/odoo_code_executor.py` — execute Python inside Odoo and return structured values

When changing behavior, identify which layer owns the concern before editing code.

### 3.2 Respect the architecture

Prefer edits in the correct layer.

- CLI parsing / command UX -> `cli_typer.py`, `cli_types.py`
- command composition -> `builders.py`
- execution mechanics -> `process_manager.py`
- output/result interpretation -> `operation_result.py`
- config discovery/loading -> `config_loader.py`
- config access/validation -> `config_provider.py`
- addon discovery / manifests / dependency analysis -> `module_manager.py`, `addons_path_manager.py`, `manifest*.py`
- high-level workflows -> `odoo_operations.py`
- embedded/in-process Odoo execution -> `odoo_code_executor.py`, `odoo_embedded_manager.py`

Do not put business rules into the CLI when they belong in a reusable lower layer.

### 3.3 Prefer reusable logic over CLI-only fixes

When a task starts from the CLI, check whether the real fix belongs below it.

Good:

- add validation in a reusable config/provider layer
- fix dependency resolution in `ModuleManager`
- improve structured parsing in `OperationResult`
- add metadata to a builder so both CLI and API benefit

Less good:

- patch around a lower-layer bug only in `cli_typer.py`

### 3.4 Treat JSON output as an API

Machine-readable CLI output is part of the contract.

When touching commands that support JSON output:

- preserve key names unless a breaking change is intended
- keep success/error shape consistent
- include structured fields rather than forcing consumers to parse text
- test exit codes and JSON payloads together

Do not casually rewrite human output or JSON field names.

### 3.5 Keep destructive actions deliberate

This tool can operate on databases, addons, and Odoo environments.

Never introduce or widen destructive behavior silently.

Be especially careful with code that can:

- install or update modules
- create or drop databases
- execute arbitrary Odoo code
- write configuration files
- write translation files
- mutate Odoo data with `commit=True` paths

If safety behavior changes, make it explicit in code and tests.

## 4. Testing Expectations

### 4.1 Minimum rule

Every non-trivial behavior change should come with verification.

Prefer the narrowest test that proves the change.

Examples:

- command option bug -> targeted CLI test
- result parser change -> parser/result test
- addon lookup bug -> `ModuleManager` or `AddonsPathManager` test
- config precedence bug -> config loader/provider test
- Odoo code execution behavior -> executor-focused test
- public workflow change -> one integration-style test, not many redundant ones

### 4.2 Test the owned layer first

Prefer tests closest to the changed logic.

- lower-layer fix -> lower-layer unit test
- CLI wiring change -> CLI test
- docs change only -> no code test unless docs exposed a missing behavior guarantee

Do not only test through the CLI when the real change is in a library module.

### 4.3 Verify regressions, not just happy paths

Include error-path checks when relevant:

- missing config
- missing addon/module
- invalid manifest field
- incorrect filter option
- non-zero exit behavior
- JSON error output
- invalid Odoo/database inputs
- no local config present

### 4.4 Avoid oversized test runs unless necessary

Start narrow. Expand only when the change crosses boundaries.

Typical progression:

1. targeted test file
2. related test cluster
3. full suite only for broad or risky changes

## 5. CLI-Specific Rules

### 5.1 Preserve command ergonomics

The CLI is a primary product surface.

Keep these traits intact:

- predictable command names
- clear option semantics
- useful error messages
- stable exit codes
- consistent JSON/text output modes

### 5.2 Do not hide behavior in implicit magic

Helpful defaults are fine.
Surprising behavior is not.

For commands that infer environment, config, or module paths:

- keep inference simple
- keep failure modes obvious
- prefer explicit error messages over silent fallback

### 5.3 Update help text when behavior changes

When adding or changing CLI behavior, update the command help and any relevant docs or examples in the same change.

## 6. Config and Environment Rules

### 6.1 Respect both config flows

oduit supports:

- environment configs in the config directory
- local `.oduit.toml` project config

Do not break one workflow while editing the other.

Test precedence and discovery when changing config behavior.

### 6.2 Validate near the boundary

- parse/normalize in loader code
- validate required values in provider/builder code
- surface friendly errors at the CLI boundary

Do not scatter config assumptions throughout the codebase.

## 7. Odoo-Specific Rules

### 7.1 Distinguish metadata inspection from runtime execution

There is a major difference between:

- reading manifests/addon paths/dependencies
- starting Odoo or running Odoo commands
- executing code inside Odoo

Use the least invasive mechanism that solves the task.

Examples:

- need addon metadata -> prefer `ModuleManager` / manifest APIs
- need command construction -> prefer builders
- need runtime behavior/result parsing -> use process-manager flow
- need direct ORM/query behavior -> use `OdooCodeExecutor` only when necessary

### 7.2 Keep read-only workflows read-only by default

For code execution or operational helpers, default to non-destructive behavior unless the task explicitly requires mutation.

### 7.3 Prefer structured operations over ad-hoc command lists

When adding new operational behavior, prefer the existing builder + operation metadata pattern over raw command assembly spread across the codebase.

## 8. Documentation Rules

### 8.1 Keep docs aligned with reality

If public behavior changes, update the relevant docs:

- `README.md` for user-facing workflows
- `docs/cli.rst` for CLI behavior
- `docs/configuration.rst` for config changes
- API docs for public module/class changes

Do not add aspirational docs that describe behavior the code does not implement.

### 8.2 Examples should be executable in spirit

Keep examples realistic and consistent with current command names, option names, and result fields.

## 9. Code Style Rules

- Follow the existing repository style first.
- Keep functions focused.
- Prefer explicit names over compressed cleverness.
- Add type hints for new or changed public functions.
- Use docstrings where the surrounding code expects them.
- Avoid introducing new dependencies unless explicitly requested.
- Do not reformat unrelated files.
- Do not rename public symbols without a strong reason.
- Do not use git commands or create commits.

## 10. Preferred Verification Commands

Use the narrowest relevant commands first.

```bash
# Run all tests
pytest

# Run a specific test file
pytest tests/test_config_provider.py

# Run with coverage
pytest --cov=oduit --cov-report=term

# Lint
ruff check --fix --exit-non-zero-on-fix --config=.ruff.toml

# Format
ruff format

# Type-check
mypy oduit

# Run pre-commit hooks
pre-commit run --all-files

# Run the CLI
oduit
```

Notes:

- Prefer targeted `pytest` invocation before running the full suite.
- Run `ruff check` and relevant tests before finishing.
- Run `mypy` when touching typed/public/core logic.
- Do not install packages unless the user explicitly asks.

## 11. Packaging Rule for Skills

Skills must stay outside the Python package.

Required direction:

- keep the canonical skill under `skills/oduit/`
- do not mirror skills under `oduit/skills/`
- do not include skills as Python package data
- do not use `importlib.resources` to expose skills from the `oduit` package
- update tests/docs so they expect external skills, not packaged skills

The Python package should provide the CLI/library. Skill installation/distribution belongs outside the package artifact.

## 12. What good agent work looks like here

A strong change in this repo usually has these properties:

- edits the right layer
- preserves CLI/API contracts
- adds or updates focused tests
- keeps JSON output stable
- respects config workflows
- avoids destructive surprises
- updates docs when public behavior changes
- stays small unless a larger redesign is actually required

## 13. What to avoid

- fixing library problems only in CLI wrappers
- changing text/JSON output without tests
- mixing refactors with feature work
- broad style churn
- introducing new abstraction layers “for later”
- using runtime Odoo execution when static manifest/addon inspection is enough
- adding behavior without documenting or testing the public contract
