Which Interface?
================

Use the smallest interface that matches the job.

* human CLI: ``oduit ...`` for interactive work and shell scripts
* agent CLI: ``oduit agent ...`` for structured inspection, planning, source
  localization, and gated mutations
* typed Python API: ``OdooOperations``, ``ModuleManager``, and typed models for
  programmatic integrations inside Python code
* unsafe executor: ``OdooCodeExecutor`` only for trusted arbitrary code, always
  with ``allow_unsafe=True``

Coding-Agent Loop
-----------------

For a change like "add ``email3`` to ``res.partner`` in ``my_partner``", the
recommended sequence is:

.. code-block:: bash

   oduit --env dev agent context
   oduit --env dev agent inspect-addon my_partner
   oduit --env dev agent get-model-fields res.partner --attributes string,type,required
   oduit --env dev agent locate-model res.partner --module my_partner
   oduit --env dev agent locate-field res.partner email3 --module my_partner
   oduit --env dev agent plan-update my_partner
   oduit --env dev agent list-addon-tests my_partner --model res.partner --field email3
   oduit --env dev agent update-module my_partner --allow-mutation
   oduit --env dev agent test-summary --module my_partner --test-tags /my_partner
