Using oduit from a coding agent
================================

``oduit agent ...`` is the primary documented automation surface for external
coding agents. Prefer it over the Python API for editor agents, bots, and
other out-of-process automation.

This page is the single source of truth for:

* command sequence
* mutation policy
* payload expectations
* failure handling

Command Families
----------------

Default to the read-only inspection and planning commands:

* ``context``
* ``inspect-addon``, ``inspect-addons``, and ``addon-doc``
* ``plan-update``
* ``preflight-addon-change``
* ``prepare-addon-change``
* ``locate-model`` and ``locate-field``
* ``list-addon-tests``, ``recommend-tests``, and ``list-addon-models``
* ``find-model-extensions`` and ``get-model-views``
* ``doctor``, ``list-addons``, ``dependency-graph``, ``resolve-config``,
  ``resolve-addon-root``, ``get-addon-files``, ``check-addons-installed``,
  ``check-model-exists``, ``check-field-exists``, and ``list-duplicates``
* direct parity wrappers when exact runtime / DB metadata is needed:
  ``inspect-ref``, ``inspect-modules``, ``inspect-subtypes``,
  ``inspect-model``, ``inspect-field``, ``db-table``, ``db-column``,
  ``db-constraints``, ``db-tables``, ``db-m2m``,
  ``performance-slow-queries``, ``performance-table-scans``,
  ``performance-indexes``, ``manifest-check``, and ``manifest-show``
* ``query-model``, ``read-record``, ``search-count``, and ``get-model-fields``

Only mutate through the controlled mutation commands:

* ``install-module``
* ``uninstall-module``
* ``update-module``
* ``create-addon``
* ``export-lang``
* ``test-summary``

Recommended Command Sequence
----------------------------

For a change like "add ``email3`` to ``res.partner`` in ``my_partner``", use
this loop:

1. Resolve the environment and confirm addon discovery.

   .. code-block:: bash

      oduit --env dev agent context
      oduit --env dev agent inspect-addon my_partner
      oduit --env dev agent addon-doc my_partner

2. Inspect the model from the database and the addon source tree.

   .. code-block:: bash

      oduit --env dev agent get-model-fields res.partner --attributes string,type,required
      oduit --env dev agent get-model-views res.partner --types form,tree --summary
      oduit --env dev agent locate-model res.partner --module my_partner
      oduit --env dev agent locate-field res.partner email3 --module my_partner
      oduit --env dev agent list-addon-tests my_partner --model res.partner --field email3

   Use ``list-addon-models`` or ``find-model-extensions`` when the owning addon
   or the cross-addon extension surface is still unclear.

3. Plan the mutation before changing anything.

   .. code-block:: bash

      oduit --env dev agent plan-update my_partner

   Or bundle the common read-only planning context into one payload:

   .. code-block:: bash

      oduit --env dev agent prepare-addon-change my_partner --model res.partner --field email3 --types form,tree

   After editing specific files, map them back to focused tests:

   .. code-block:: bash

      oduit --env dev agent recommend-tests --module my_partner --paths models/res_partner.py,views/res_partner_views.xml

4. Apply the mutation explicitly.

   .. code-block:: bash

      oduit --env dev agent update-module my_partner --allow-mutation

5. Verify the result with targeted tests.

   .. code-block:: bash

      oduit --env dev agent test-summary --module my_partner --test-tags /my_partner

For runtime spot checks after a change, prefer ``query-model``, ``read-record``,
and ``search-count`` over arbitrary code execution.

When an agent needs direct parity with the human inspection / DB / manifest
commands, use the structured wrappers instead of shell snippets:

.. code-block:: bash

   oduit --env dev agent inspect-ref base.action_partner_form
   oduit --env dev agent inspect-cron base.ir_cron_autovacuum
   oduit --env dev agent inspect-model res.partner
   oduit --env dev agent inspect-field res.partner email --with-db
   oduit --env dev agent db-table res_partner
   oduit --env dev agent manifest-check sale

For a cheap read-only planning and health pass before mutating an addon, use
``preflight-addon-change``:

.. code-block:: bash

   oduit --env dev agent preflight-addon-change my_partner --model res.partner --field email3

For a single end-to-end runtime verification pass after editing one addon, use
``validate-addon-change``:

.. code-block:: bash

   oduit --env dev agent validate-addon-change my_partner --allow-mutation --update --discover-tests

This command inspects the addon, checks environment health and duplicate names,
optionally installs or updates the addon, runs the full module test suite using
``/<module>`` test tags by default, and returns one aggregate payload with
sub-results for each step.

Mutation Policy
---------------

* Default to read-only commands.
* ``install-module``, ``uninstall-module``, ``update-module``,
  ``create-addon``, and ``export-lang`` are controlled mutations.
* ``inspect-cron`` is read-only by default; ``inspect-cron --trigger`` becomes
  a controlled runtime mutation and may require ``--allow-mutation``.
* Runtime DB mutation uses explicit flags:

  * ``write_protect_db`` blocks runtime DB mutation for every caller
  * ``needs_mutation_flag`` requires ``--allow-mutation`` for human runtime DB mutation
  * ``agent_write_protect_db`` blocks runtime DB mutation for agent commands
  * ``agent_needs_mutation_flag`` requires ``--allow-mutation`` for agent runtime DB mutation

* Controlled source mutations still require ``--allow-mutation`` regardless of
  runtime DB policy flags.
* ``uninstall-module`` also requires ``--allow-uninstall`` and
  ``allow_uninstall = true`` in the active environment config.
* ``--dry-run`` is supported by ``install-module``, ``uninstall-module``,
  ``update-module``, ``create-addon``, and ``export-lang``. Their dry runs
  return read-only planning payloads.
* ``test-summary`` stays read-only unless you pass ``--install`` or
  ``--update``. ``validate-addon-change`` only consults runtime DB mutation
  policy when you request install or update work.
* If ``context``, ``resolve-config``, or ``list-duplicates`` reports blockers,
  fix them before mutating.
* Do not use ``execute_python_code()`` or ``OdooCodeExecutor`` for routine
  coding-agent automation. Reserve them for trusted operator-controlled paths.

Payload Expectations
--------------------

Every final-result agent command emits exactly one JSON object on stdout.

Guaranteed top-level keys:

* ``schema_version``
* ``type``
* ``success``
* ``read_only``
* ``safety_level``
* ``warnings``
* ``errors``
* ``remediation``
* ``data``
* ``meta``

When available, commands also include:

* ``operation``
* ``error``
* ``error_type``
* ``error_code``
* ``generated_at``
* command-specific fields such as ``module``, ``count``, or ``candidates``

For source-location commands, prefer explicit decision fields over raw
confidence alone:

* ``resolution``: overall result such as ``confirmed``, ``ambiguous``,
  ``suggested``, or ``not_found``
* ``ambiguous`` / ``ambiguity_reason``: whether the command found multiple
  plausible matches
* candidate ``match_strength`` and ``evidence``: why a candidate was chosen and
  whether it is a confirmed source hit or a best-effort suggestion

``data`` is the canonical command payload container.

For ``2.x`` compatibility, command-specific fields are also flattened to the
top level when they do not collide with envelope keys. That flattened shape is
part of the public ``2.x`` contract and must remain stable within this schema
version.

Compatibility Policy
--------------------

* additive fields are allowed within ``schema_version = 2.x``
* breaking changes require a schema-version bump
* new consumers should prefer reading ``data`` first
* existing consumers may continue using flattened top-level fields in ``2.x``

Payload Stability Tiers
-----------------------

* **stable:** ``schema_version``, ``type``, ``operation``, ``success``,
  ``read_only``, ``safety_level``, ``warnings``, ``errors``, ``remediation``,
  ``error``, ``error_type``, ``error_code``, ``data``, ``meta``
* **soft-stable:** additive flattened command-specific fields and optional
  metadata such as ``generated_at``, ``duration``, ``config_source``,
  ``database``, and ``resolved_addons_path``
* **experimental:** newly introduced command-specific fields not yet called out
  in the public docs

Command Stability Tiers
-----------------------

Use :doc:`agent_command_inventory` for the generated command-by-command tier
matrix.

* ``stable_for_agents``: recommended machine-facing surface for coding agents
* ``beta_for_agents``: useful for agents but still evolving in behavior,
  heuristics, or workflow shape
* ``human_oriented``: supported CLI surface documented primarily for humans
* ``compatibility_only``: retained for migration or import compatibility only

Safety Levels
-------------

* ``safe_read_only``: inspection and analysis only
* ``controlled_runtime_mutation``: explicit commands that mutate database,
  process, or runtime state, gated by flags such as ``--allow-mutation``
* ``controlled_source_mutation``: explicit commands that write or rewrite addon
  source files, also gated by flags such as ``--allow-mutation``
* ``unsafe_arbitrary_execution``: trusted arbitrary code execution only

Published Schemas
-----------------

Published JSON Schema artifacts live under ``schemas/``:

* ``schemas/result-envelope.schema.json``
* ``schemas/agent/environment-context.schema.json``
* ``schemas/agent/addon-info.schema.json``
* ``schemas/agent/addon-documentation.schema.json``
* ``schemas/agent/addon-inspection.schema.json``
* ``schemas/agent/update-plan.schema.json``
* ``schemas/agent/query-result.schema.json``
* ``schemas/agent/model-source-location.schema.json``
* ``schemas/agent/field-source-location.schema.json``
* ``schemas/agent/addon-test-inventory.schema.json``
* ``schemas/agent/addon-model-inventory.schema.json``
* ``schemas/agent/model-extension-inventory.schema.json``
* ``schemas/agent/model-view-inventory.schema.json``
* ``schemas/agent/addon-root-resolution.schema.json``
* ``schemas/agent/addon-file-inventory.schema.json``
* ``schemas/agent/addon-install-checks.schema.json``
* ``schemas/agent/model-existence.schema.json``
* ``schemas/agent/field-existence.schema.json``
* ``schemas/agent/addon-change-preflight.schema.json``
* ``schemas/agent/addon-change-validation.schema.json``
* ``schemas/agent/addon-change-context.schema.json``
* ``schemas/agent/recommended-test-plan.schema.json``
* ``schemas/agent/xmlid-inspection.schema.json``
* ``schemas/agent/cron-inspection.schema.json``
* ``schemas/agent/module-inspection.schema.json``
* ``schemas/agent/subtype-inventory.schema.json``
* ``schemas/agent/model-inspection.schema.json``
* ``schemas/agent/field-inspection.schema.json``
* ``schemas/agent/table-description.schema.json``
* ``schemas/agent/column-description.schema.json``
* ``schemas/agent/constraint-inventory.schema.json``
* ``schemas/agent/table-inventory.schema.json``
* ``schemas/agent/m2m-inspection.schema.json``
* ``schemas/agent/slow-query-metrics.schema.json``
* ``schemas/agent/table-scan-metrics.schema.json``
* ``schemas/agent/index-usage-metrics.schema.json``
* ``schemas/agent/manifest-validation.schema.json``
* ``schemas/agent/manifest.schema.json``

Failure Handling
----------------

* Always read both the process exit status and the payload ``success`` flag.
* Failure payloads still use the same JSON envelope and are emitted before the
  command exits non-zero.
* Prefer ``error`` for the human-readable summary.
* Prefer ``error_type`` for the stable failure category.
* Prefer ``error_code`` for the stable machine-branching key.
* Prefer ``errors`` for structured details.
* Prefer ``remediation`` for next actions the caller can take.
* ``ConfirmationRequired`` means a controlled runtime or source mutation was
  attempted without ``--allow-mutation``.
* ``ConfigError`` usually means the environment config, resolved binaries, or
  ``addons_path`` needs to be fixed before retrying.
* ``ModuleNotFoundError`` means the requested addon was not resolved in the
  active ``addons_path``.
* ``ValidationError`` means an input format such as ``--domain-json`` or a
  repeated filter option could not be parsed safely.

Example failure codes:

* ``config.addons_path_missing``
* ``module.not_found``
* ``mutation.confirmation_required``
* ``runtime.test_failure``
* ``runtime.install_dependency_error``
* ``runtime.uninstall_dependency_blocked``

When ``success = false``, do not guess about the next step. Inspect the
structured payload, follow ``remediation``, reconcile state if needed, and then
rerun the next targeted command.

Example
-------

.. code-block:: json

   {
      "schema_version": "2.0",
      "type": "model_source_location",
      "success": true,
      "operation": "locate_model",
      "read_only": true,
      "safety_level": "safe_read_only",
      "warnings": [],
      "errors": [],
      "remediation": [],
      "data": {
         "model": "res.partner",
         "module": "my_partner",
         "addon_root": "/workspace/addons/my_partner",
         "resolution": "confirmed",
         "ambiguous": false,
         "candidates": [
            {
               "path": "/workspace/addons/my_partner/models/res_partner.py",
               "class_name": "ResPartner",
               "match_kind": "inherit",
               "declared_model": "res.partner",
               "confidence": 0.98,
               "match_strength": "confirmed",
               "evidence": [
                  {
                     "kind": "model_inherit",
                     "message": "Class inherits `res.partner` directly in addon source.",
                     "path": "/workspace/addons/my_partner/models/res_partner.py",
                     "line_hint": 6
                  }
               ],
               "line_hint": 6
            }
         ]
      },
      "meta": {
         "timestamp": "2026-04-09T12:00:00"
      },
       "model": "res.partner",
       "module": "my_partner",
       "addon_root": "/workspace/addons/my_partner",
       "resolution": "confirmed",
       "ambiguous": false,
       "candidates": [
          {
             "path": "/workspace/addons/my_partner/models/res_partner.py",
             "class_name": "ResPartner",
             "match_kind": "inherit",
             "declared_model": "res.partner",
             "confidence": 0.98,
             "match_strength": "confirmed",
             "evidence": [
                {
                   "kind": "model_inherit",
                   "message": "Class inherits `res.partner` directly in addon source.",
                   "path": "/workspace/addons/my_partner/models/res_partner.py",
                   "line_hint": 6
                }
             ],
             "line_hint": 6
          }
       ]
   }
