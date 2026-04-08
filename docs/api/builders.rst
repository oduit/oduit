Builders
========

The builders module contains the structured command builders used by
``OdooOperations`` and ``ProcessManager``.

.. automodule:: oduit.builders
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

.. code-block:: python

   from oduit import ConfigLoader, ProcessManager
   from oduit.builders import InstallCommandBuilder, OdooTestCommandBuilder

   loader = ConfigLoader()
   config = loader.load_config("dev")
   manager = ProcessManager()

   install_operation = InstallCommandBuilder(config, "sale").build_operation()
   install_result = manager.run_operation(install_operation, verbose=True)

   test_operation = OdooTestCommandBuilder(config).test_tags("/sale").build_operation()
   test_result = manager.run_operation(test_operation)

Key Concepts
------------

- ``build()`` returns a plain command list for compatibility
- ``build_operation()`` returns a structured ``CommandOperation``
- the structured form carries metadata such as operation type, modules, and
  parser hints for downstream result processing
