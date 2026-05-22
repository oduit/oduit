Addon technical documentation
=============================

Purpose
-------

oduit can generate addon-local Arc42 documentation in a split workflow:
deterministic evidence plus a human/LLM report.

Files
-----

.. code-block:: text

   <addon>/docs/architecture.evidence.md
   <addon>/docs/architecture.evidence.oduit.json
   <addon>/docs/architecture.md
   <addon>/docs/architecture.oduit.json

``architecture.evidence.md`` is deterministic evidence and should be
regenerated, not hand-edited. ``architecture.md`` is the human/LLM-owned report
that should contain reviewed prose and decisions.

Recommended workflow
--------------------

Agent workflow
~~~~~~~~~~~~~~

.. code-block:: bash

   oduit --env dev agent technical-evidence @addons/my_addon --allow-mutation --source-only
   oduit --env dev agent technical-report @addons/my_addon --allow-mutation --source-only
   oduit --env dev agent technical-doc-diff @addons/my_addon --include-diff
   oduit --env dev agent technical-doc-check @addons/my_addon --include-files

Human CLI workflow
~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   oduit --env dev docs technical-evidence @addons/my_addon --output-in-addon --source-only
   oduit --env dev docs technical-report @addons/my_addon --output-in-addon --source-only
   oduit --env dev docs technical-diff @addons/my_addon --include-diff
   oduit --env dev docs technical-check @addons/my_addon --include-files

Allowed addon directories
-------------------------

Use ``[documentation].allowed_addon_dirs`` to constrain documentation writes and
selection:

.. code-block:: toml

   [documentation]
   allowed_addon_dirs = ["./addons"]

Paths are resolved from the project base: ``.oduit.toml`` directory when
present, then git root, then current working directory.

Freshness and review
--------------------

Use ``technical-status``, ``technical-check``, ``technical-next``,
``technical-diff``, and ``technical-doc-accept`` to manage freshness and
reviewed manual edits.

Legacy workflow
---------------

``docs technical`` and ``agent technical-doc`` are compatibility/legacy
monolithic workflows. Prefer the split workflow for new documentation.
