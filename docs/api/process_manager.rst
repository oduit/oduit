ProcessManager
==============

The ProcessManager class is responsible for managing Odoo processes and operations. It provides enhanced structured operation execution through the new ``run_operation()`` method and maintains backward compatibility with existing command execution methods.

.. automodule:: oduit.process_manager
   :members:
   :undoc-members:
   :show-inheritance:

Class Reference
---------------

.. autoclass:: oduit.ProcessManager
   :members:
   :undoc-members:
   :show-inheritance:

Process Manager Types
---------------------

oduit provides different process manager implementations for various execution strategies:

SystemProcessManager (Default)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The default process manager uses subprocess execution for all commands:

.. code-block:: python

   from oduit.process_manager import ProcessManager

   # Creates SystemProcessManager by default
   pm = ProcessManager()

   # Good for: shell scripting, piped commands, external tools
   result = pm.run_shell_command('echo "Hello" | grep "Hello"', capture_output=True)

**Features:**
- Full subprocess support with piped commands
- Shell scripting capabilities
- Best compatibility with system tools
- Standard subprocess behavior

DemoProcessManager
~~~~~~~~~~~~~~~~~~

For testing and demonstration purposes:

.. code-block:: python

   from oduit.demo_process_manager import DemoProcessManager

   pm = DemoProcessManager(config, available_modules=["base", "sale"])

   # Simulates operations without actually executing them
   result = pm.run_command(["odoo-bin", "-d", "mydb", "-i", "sale"])

**Features:**
- Simulates command execution
- No actual Odoo operations performed
- Useful for testing and demos
- Configurable module availability

Shell Command Execution
-----------------------

The ``run_shell_command()`` method provides flexible shell command execution with different behavior depending on the process manager type:

SystemProcessManager Shell Commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   pm = ProcessManager()  # SystemProcessManager

   # Full shell features supported
   result = pm.run_shell_command('echo "SELECT version();" | psql mydb', capture_output=True)

   # Piped commands work perfectly
   result = pm.run_shell_command('ls -la | grep ".py"', capture_output=True)

**Method Signature:**

.. code-block:: python

   def run_shell_command(
       self,
       cmd: str | list[str],
       verbose: bool = False,
       capture_output: bool = False
   ) -> dict[str, Any]:
       """Execute a shell command.

       Args:
           cmd: Command string or argument list
           verbose: Print command before execution
           capture_output: Capture stdout/stderr instead of inheriting

       Returns:
           Dict with success, return_code, stdout, stderr (if captured)
       """

**Usage Examples:**

.. code-block:: python

   # Basic shell command
   result = pm.run_shell_command("echo 'Hello World'")
   print(f"Success: {result['success']}")

   # Capture output
   result = pm.run_shell_command("ls -la", capture_output=True)
   if result['success']:
       print(f"Output: {result['stdout']}")

   # List command format
   result = pm.run_shell_command(["python", "-c", "print('test')"], capture_output=True)

   # Error handling
   result = pm.run_shell_command("nonexistent_command")
   if not result['success']:
       print(f"Error: {result.get('stderr', 'Unknown error')}")

Enhanced Operation Execution
----------------------------

New run_operation() Method
~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``run_operation()`` method provides structured execution of ``CommandOperation`` objects with enhanced result processing:

.. code-block:: python

   def run_operation(
       self,
       command_operation: CommandOperation,
       verbose: bool = False,
       suppress_output: bool = False,
   ) -> dict[str, Any]:
       """Execute a CommandOperation with enhanced result processing.

       Args:
           command_operation: Structured command operation with metadata
           verbose: Enable verbose output
           suppress_output: Suppress output to console

       Returns:
           Dict containing structured execution results with automatic parsing
       """

Key features:
- Accepts ``CommandOperation`` objects with rich metadata
- Automatic result parsing based on operation type
- Enhanced error handling and structured output
- Maintains compatibility with existing ``run_command()`` interface

Usage Examples
--------------

Enhanced Operation Execution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import ProcessManager
   from oduit.builders import InstallCommandBuilder
   from oduit.config_loader import ConfigProvider

   # Create process manager and config
   config = ConfigProvider()
   pm = ProcessManager()

   # Build structured operation
   builder = InstallCommandBuilder(config, "sale")
   operation = builder.build_operation()

   # Execute with enhanced result processing
   result = pm.run_operation(operation, verbose=True)

   print(f"Success: {result['success']}")
   print(f"Operation Type: {result.get('operation_type')}")
   print(f"Modules Installed: {result.get('modules_installed', [])}")
   if 'parsed_results' in result:
       print(f"Parsed Results: {result['parsed_results']}")

Test Operation with Enhanced Results
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import OdooTestCommandBuilder

   # Build test operation
   builder = OdooTestCommandBuilder(config, "/my_module")
   operation = builder.build_operation()

   # Execute test with automatic result parsing
   result = pm.run_operation(operation)

   print(f"Test Success: {result['success']}")
   print(f"Modules Tested: {result.get('modules_tested', [])}")
   if 'test_results' in result:
       print(f"Test Results: {result['test_results']}")

Update Operation with Metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import UpdateCommandBuilder

   # Build update operation
   builder = UpdateCommandBuilder(config, "purchase")
   operation = builder.build_operation()

   # Execute with structured results
   result = pm.run_operation(operation, verbose=True)

   print(f"Update Success: {result['success']}")
   print(f"Database: {result.get('database')}")
   print(f"Modules Updated: {result.get('modules_updated', [])}")

Database Operations
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import DatabaseCommandBuilder

   # Build database creation operation
   builder = DatabaseCommandBuilder(config)
   builder.create_database("my_new_db")
   operation = builder.build_operation()

   # Execute database operation
   result = pm.run_operation(operation)

   print(f"Database Created: {result['success']}")
   print(f"Operation Type: {result.get('operation_type')}")  # 'create_db'
   print(f"With Sudo: {result.get('with_sudo', False)}")

Backward Compatible Command Execution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Legacy command execution still supported
   result = pm.run_command(['echo', 'hello world'])
   print(result['success'])  # True
   print(result['output'])   # 'hello world\n'

   # Advanced command options
   result = pm.run_command(
       ['python', '-c', 'print("test")'],
       verbose=True,
       stop_on_error=True,
       compact=True
   )

Interactive Shell Support
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Run interactive shell operations
   exit_code = ProcessManager.run_interactive_shell(['bash'])
   print(f"Shell exited with code: {exit_code}")

Streaming Command Execution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Stream output line by line
   for item in pm.run_command_yielding(['python', 'long_script.py']):
       if 'line' in item:
           print(f"Line: {item['line'].strip()}")
           print(f"Is Error: {item['is_error']}")
       elif 'result' in item:
           print(f"Final Result: {item['result']}")

Result Structure
----------------

Enhanced Results from run_operation()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``run_operation()`` method returns structured results with automatic parsing:

.. code-block:: python

   {
       # Standard execution results
       'success': bool,
       'return_code': int,
       'stdout': str,
       'stderr': str,
       'command': str,

       # Operation metadata
       'operation_type': str,        # e.g., 'install', 'test', 'update'
       'database': str | None,
       'modules_installed': list[str],  # For install operations
       'modules_updated': list[str],    # For update operations
       'modules_tested': list[str],     # For test operations

       # Parsed results (when available)
       'parsed_results': dict,       # Operation-specific parsed data
       'test_results': dict,         # For test operations
       'coverage_results': dict,     # For coverage operations

       # Error information (when applicable)
       'error': str,
       'error_type': str
   }

Legacy Results from run_command()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Traditional command execution returns basic results:

.. code-block:: python

   {
       'success': bool,
       'return_code': int,
       'output': str,              # Combined stdout/stderr
       'command': str,
       'error': str               # Error message (if failed)
   }
