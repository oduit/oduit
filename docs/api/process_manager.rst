ProcessManager
==============

``ProcessManager`` executes structured ``CommandOperation`` objects and
low-level commands, with secure-by-default shell execution.

.. automodule:: oduit.process_manager
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

.. code-block:: python

   from oduit import ConfigLoader, ProcessManager
   from oduit.builders import InstallCommandBuilder

   loader = ConfigLoader()
   config = loader.load_config("dev")
   manager = ProcessManager()

   operation = InstallCommandBuilder(config, "sale").build_operation()
   result = manager.run_operation(operation, verbose=True)

   shell_result = manager.run_shell_command(
       ["python", "-c", "print('hello')"],
       capture_output=True,
   )

Key Methods
-----------

- ``run_operation()``: execute a structured command with automatic result parsing
- ``run_command()``: run a direct command list
- ``run_command_yielding()``: stream structured output events
- ``run_shell_command()``: execute list commands safely, or string commands with
  explicit ``allow_shell=True``
- ``clear_sudo_password()``: clear cached sudo credentials

Notes
-----

- ``run_command()`` does not expose a public ``timeout=...`` parameter
- string shell commands require ``allow_shell=True``
- embedded execution is not a supported public ``ProcessManager`` mode
