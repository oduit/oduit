Agent Output Audit
==================

``scripts/oduit_agent_output_audit.py`` is a standalone measurement script that
runs every ``oduit agent ...`` command against a real Odoo environment and
reports output size, JSON verbosity, duplicate fields, and large strings.

The script is intentionally **external to the oduit package** so it can be run
before changing any command schemas.

Prerequisites
-------------

* ``oduit`` installed and on ``PATH`` (``pip install oduit``).
* A real Odoo project directory with a configured environment — either a local
  ``.oduit.toml`` or a named environment under the oduit config directory.
* The project's Odoo instance must be reachable for commands that contact the
  database (``test-summary``, ``module-info``, ``model-info``, etc.).

Phase 1 — Discovery run (default matrix)
-----------------------------------------

Run from the Odoo project directory:

.. code-block:: bash

   python scripts/oduit_agent_output_audit.py \
     --env dev \
     --module my_addon \
     --out-dir .oduit-output-audit

Output files written to ``.oduit-output-audit/``:

.. code-block:: text

   agent-help.txt
   agent-output-audit.json
   agent-output-audit.jsonl
   agent-output-audit.md
   raw/<name>.stdout.txt
   raw/<name>.stderr.txt

The built-in default matrix covers ``agent --help``, ``agent test-summary``,
and ``agent test-summary --short``.  Commands that fail appear as failed rows in
the report — this is expected when commands do not yet exist in the branch.

Phase 2 — Explicit matrix run
------------------------------

Copy ``scripts/agent-output-matrix.example.json`` to your project and edit it
to match the commands actually available in your branch:

.. code-block:: bash

   cp scripts/agent-output-matrix.example.json agent-output-matrix.json
   # edit agent-output-matrix.json to reflect your branch's agent commands
   python scripts/oduit_agent_output_audit.py \
     --env dev \
     --module my_addon \
     --matrix-file agent-output-matrix.json \
     --out-dir .oduit-output-audit

Phase 3 — Mutating commands
-----------------------------

Commands with ``"mutates": true`` in the matrix are **skipped by default**.
Only run them against a disposable test database:

.. code-block:: bash

   python scripts/oduit_agent_output_audit.py \
     --env disposable_test \
     --module my_addon \
     --matrix-file agent-output-matrix.json \
     --allow-mutating \
     --out-dir .oduit-output-audit-mutating

Reading the report
------------------

Open ``.oduit-output-audit/agent-output-audit.md``.  Start with the
**Output size ranking** table:

* ``combined_bytes`` — total stdout + stderr bytes.
* ``approx_tokens`` — estimated LLM token cost (``ceil(chars / 4)``).
* ``json_minified_bytes`` — minified JSON payload size.
* ``largest_fields`` — top 25 JSON paths by serialized size.
* ``duplicate_value_paths`` — groups of JSON paths that carry identical
  serialized content (≥ 80 bytes).  These identify redundant fields.
* ``large_strings`` — string values ≥ 120 characters.

Raw stdout/stderr files are written to ``raw/`` but should not be pasted into
prompts.  Use the Markdown summary for analysis.

CLI reference
-------------

.. code-block:: text

   python scripts/oduit_agent_output_audit.py [OPTIONS]

   --oduit-bin PATH      oduit binary (default: oduit)
   --env NAME            environment name passed as --env to oduit
   --workdir PATH        run commands from this directory
   --module NAME         addon/module name for {module} substitution
   --test-tags TAGS      test tags for {test_tags} substitution
   --timeout SECONDS     per-command timeout (default: 300)
   --matrix-file PATH    JSON matrix file (default: built-in default matrix)
   --out-dir PATH        output directory (default: .oduit-output-audit)
   --allow-mutating      run specs marked mutates=true
   --skip-discovery      skip the agent --help discovery step

Example matrix file
-------------------

``scripts/agent-output-matrix.example.json`` ships with the repository.
Copy and extend it for your branch:

.. code-block:: json

   {
     "commands": [
       {"name": "agent-help", "args": ["agent", "--help"], "mutates": false, "expect_json": false},
       {"name": "test-summary", "args": ["agent", "test-summary", "--module", "{module}"], "mutates": false, "expect_json": true},
       {"name": "module-info", "args": ["agent", "module-info", "--module", "{module}"], "mutates": false, "expect_json": true}
     ]
   }

The ``{module}`` and ``{test_tags}`` placeholders are expanded from the
``--module`` and ``--test-tags`` CLI arguments.

Output budget targets
---------------------

Use these as initial targets when evaluating the audit report:

.. list-table::
   :header-rows: 1
   :widths: 40 20 20 20

   * - Command class
     - Max JSON bytes
     - Max approx tokens
     - Notes
   * - Status / version / config summary
     - 1,000
     - 250
     - No raw command, no config secrets.
   * - Manifest / module info
     - 2,500
     - 625
     - Cap dependency arrays.
   * - Model / field info
     - 4,000
     - 1,000
     - Include only requested model.
   * - Test summary success
     - 2,000
     - 500
     - Counts and next action only.
   * - Test summary failure
     - 6,000
     - 1,500
     - Compact failure excerpts; raw log as artifact path.
   * - Install/update success
     - 2,500
     - 625
     - Installed modules and warnings only.
   * - Install/update failure
     - 6,000
     - 1,500
     - Actionable error excerpts and raw log artifact path.

These are targets for analysis, not enforced thresholds.  Set regression
thresholds after measuring the current state with this audit script.
