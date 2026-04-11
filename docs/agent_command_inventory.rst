Agent command inventory
=======================

This page is generated from the canonical agent command registration
surface in ``oduit.cli.app``.

Command tiers:

* ``stable_for_agents``: Recommended machine-facing surface for agents.
* ``beta_for_agents``: Useful for agents, but still evolving in shape or behavior.
* ``human_oriented``: Supported CLI surface, but documented primarily for humans.
* ``compatibility_only``: Retained for migration or import compatibility only.

.. list-table:: Canonical `oduit agent` commands
   :header-rows: 1

   * - Command
     - Stability tier
     - Safety level
     - Summary
   * - ``context``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return a structured environment snapshot for automation.
   * - ``inspect-addon``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return a one-shot addon inspection payload.
   * - ``addon-info``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return a combined manifest, source, and runtime addon summary.
   * - ``plan-update``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return a structured, read-only update plan for a module.
   * - ``prepare-addon-change``
     - ``beta_for_agents``
     - ``safe_read_only``
     - Bundle the common read-only planning steps for one addon change.
   * - ``locate-model``
     - ``beta_for_agents``
     - ``safe_read_only``
     - Locate likely source files for a model extension inside one addon.
   * - ``locate-field``
     - ``beta_for_agents``
     - ``safe_read_only``
     - Locate an existing field or suggest the best insertion point.
   * - ``list-addon-tests``
     - ``beta_for_agents``
     - ``safe_read_only``
     - List likely tests for an addon, optionally ranked by hints.
   * - ``recommend-tests``
     - ``beta_for_agents``
     - ``safe_read_only``
     - Map changed addon files to recommended tests and test tags.
   * - ``list-addon-models``
     - ``beta_for_agents``
     - ``safe_read_only``
     - List the models declared or extended by one addon.
   * - ``find-model-extensions``
     - ``beta_for_agents``
     - ``safe_read_only``
     - Find where a model is declared, extended, and installed.
   * - ``get-model-views``
     - ``beta_for_agents``
     - ``safe_read_only``
     - Fetch database-backed primary and extension views for a model.
   * - ``doctor``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return doctor diagnostics through the standard agent envelope.
   * - ``list-addons``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return structured addon inventory for the active environment.
   * - ``list-installed-addons``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return structured runtime installed-addon inventory.
   * - ``dependency-graph``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return a structured dependency and reverse-dependency graph.
   * - ``inspect-addons``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Inspect multiple addons through the stable agent envelope.
   * - ``resolve-config``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return the resolved configuration with sensitive values redacted.
   * - ``resolve-addon-root``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Resolve addon root paths for one module name.
   * - ``get-addon-files``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return a deterministic file inventory for one addon.
   * - ``check-addons-installed``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return runtime installed-state checks for one or more addons.
   * - ``check-model-exists``
     - ``beta_for_agents``
     - ``safe_read_only``
     - Check whether a model exists in source discovery and runtime metadata.
   * - ``check-field-exists``
     - ``beta_for_agents``
     - ``safe_read_only``
     - Check whether a field exists in runtime metadata and source.
   * - ``list-duplicates``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Return duplicate addon names through the standard agent envelope.
   * - ``install-module``
     - ``stable_for_agents``
     - ``controlled_runtime_mutation``
     - Install a module with an explicit mutation gate.
   * - ``update-module``
     - ``stable_for_agents``
     - ``controlled_runtime_mutation``
     - Update a module with an explicit mutation gate.
   * - ``uninstall-module``
     - ``stable_for_agents``
     - ``controlled_runtime_mutation``
     - Uninstall a module with explicit runtime and destructive gates.
   * - ``create-addon``
     - ``stable_for_agents``
     - ``controlled_source_mutation``
     - Create a new addon with an explicit mutation gate.
   * - ``export-lang``
     - ``stable_for_agents``
     - ``controlled_runtime_mutation``
     - Export language files with an explicit mutation gate.
   * - ``test-summary``
     - ``stable_for_agents``
     - ``controlled_runtime_mutation``
     - Run tests and emit a normalized summary payload.
   * - ``validate-addon-change``
     - ``beta_for_agents``
     - ``controlled_runtime_mutation``
     - Validate an addon change with one aggregate structured payload.
   * - ``preflight-addon-change``
     - ``beta_for_agents``
     - ``safe_read_only``
     - Run a cheap read-only addon-change preflight.
   * - ``query-model``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Run a structured read-only model query.
   * - ``read-record``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Read a single record by id via OdooQuery.
   * - ``search-count``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Count records matching a domain via OdooQuery.
   * - ``get-model-fields``
     - ``stable_for_agents``
     - ``safe_read_only``
     - Inspect model field metadata via OdooQuery.
