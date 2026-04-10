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
* ``inspect-addon`` and ``inspect-addons``
* ``plan-update``
* ``locate-model`` and ``locate-field``
* ``list-addon-tests`` and ``list-addon-models``
* ``find-model-extensions`` and ``get-model-views``
* ``doctor``, ``list-addons``, ``dependency-graph``, ``resolve-config``, and
  ``list-duplicates``
* ``query-model``, ``read-record``, ``search-count``, and ``get-model-fields``

Only mutate through the controlled mutation commands:

* ``install-module``
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

4. Apply the mutation explicitly.

   .. code-block:: bash

      oduit --env dev agent update-module my_partner --allow-mutation

5. Verify the result with targeted tests.

   .. code-block:: bash

      oduit --env dev agent test-summary --allow-mutation --module my_partner --test-tags /my_partner

For runtime spot checks after a change, prefer ``query-model``, ``read-record``,
and ``search-count`` over arbitrary code execution.

Mutation Policy
---------------

* Default to read-only commands.
* ``install-module``, ``update-module``, ``create-addon``, ``export-lang``, and
  ``test-summary`` are controlled mutations.
* Controlled mutations require ``--allow-mutation``.
* ``--dry-run`` is supported by ``install-module``, ``update-module``,
  ``create-addon``, and ``export-lang``. Their dry runs return read-only
  planning payloads.
* ``test-summary`` is mutation-gated because it can drive install, update, and
  database-backed test flows.
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
* command-specific fields such as ``module``, ``count``, or ``candidates``

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
* ``schemas/agent/addon-inspection.schema.json``
* ``schemas/agent/update-plan.schema.json``
* ``schemas/agent/query-result.schema.json``
* ``schemas/agent/model-source-location.schema.json``
* ``schemas/agent/field-source-location.schema.json``
* ``schemas/agent/addon-test-inventory.schema.json``
* ``schemas/agent/addon-model-inventory.schema.json``
* ``schemas/agent/model-extension-inventory.schema.json``
* ``schemas/agent/model-view-inventory.schema.json``

Failure Handling
----------------

* Always read both the process exit status and the payload ``success`` flag.
* Failure payloads still use the same JSON envelope and are emitted before the
  command exits non-zero.
* Prefer ``error`` for the human-readable summary.
* Prefer ``error_type`` for the stable failure category.
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
         "candidates": [
            {
               "path": "/workspace/addons/my_partner/models/res_partner.py",
               "class_name": "ResPartner",
               "match_kind": "inherit",
               "declared_model": "res.partner",
               "confidence": 0.98,
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
      "candidates": [
         {
            "path": "/workspace/addons/my_partner/models/res_partner.py",
            "class_name": "ResPartner",
            "match_kind": "inherit",
            "declared_model": "res.partner",
            "confidence": 0.98,
            "line_hint": 6
         }
      ]
   }
