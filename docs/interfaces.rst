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

Coding Agents
-------------

For external coding agents, treat ``oduit agent ...`` as the primary
automation surface.

Use :doc:`agent_contract` as the canonical guide for the recommended command
sequence, mutation policy, payload expectations, and failure handling.
