Agent Contract
==============

``oduit agent ...`` is the preferred automation surface for coding agents and
other machine consumers.

Envelope
--------

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
* command-specific fields such as ``module`` or ``count``

Flattening Policy
-----------------

``data`` is the canonical command payload container.

For ``1.x`` compatibility, command-specific fields are also flattened to the
top level when they do not collide with envelope keys. That flattened shape is
part of the public ``1.x`` contract and must remain stable within this schema
version.

Compatibility Policy
--------------------

* additive fields are allowed within ``schema_version = 1.x``
* breaking changes require a schema-version bump
* new consumers should prefer reading ``data`` first
* existing consumers may continue using flattened top-level fields in ``1.x``

Safety Levels
-------------

* ``safe_read_only``: inspection and analysis only
* ``controlled_mutation``: explicit mutation commands gated by flags such as
  ``--allow-mutation``
* ``unsafe_arbitrary_execution``: trusted arbitrary code execution only

Errors And Remediation
----------------------

Failures should prefer:

* ``error`` for the human-readable summary
* ``error_type`` for the stable failure category
* ``errors`` for structured details
* ``remediation`` for next actions the caller can take

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

Example
-------

.. code-block:: json

   {
      "schema_version": "1.0",
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
