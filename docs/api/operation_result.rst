OperationResult
===============

The OperationResult class provides enhanced result processing for Odoo operations with automatic parsing, structured data extraction, and intelligent semantic success detection. It transforms raw command output into structured, programmatically accessible results.

.. automodule:: oduit.operation_result
   :members:
   :undoc-members:
   :show-inheritance:

Class Reference
---------------

.. autoclass:: oduit.OperationResult
   :members:
   :undoc-members:
   :show-inheritance:

Enhanced Result Processing
--------------------------

Factory Method from CommandOperation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``from_operation()`` factory method creates structured results from CommandOperation objects:

.. code-block:: python

   @classmethod
   def from_operation(cls, command_operation: CommandOperation) -> OperationResult:
       """Factory method to create OperationResult from CommandOperation."""

This method automatically:
- Sets up operation metadata (type, modules, database)
- Configures result parsing based on operation type
- Prepares structured result containers

Automatic Result Parsing
~~~~~~~~~~~~~~~~~~~~~~~~

The ``process_with_parsers()`` method provides intelligent parsing based on operation metadata:

.. code-block:: python

   def process_with_parsers(self, output: str, **additional_data: Any) -> OperationResult:
       """Automatically select and apply appropriate parsers based on operation metadata."""

Supported parsers:
- **Install Parser**: Extracts module dependencies, loading statistics, and installation errors
- **Test Parser**: Parses test statistics, failure details, and error tracebacks
- **Coverage Parser**: Extracts coverage metrics and reporting data

Usage Examples
--------------

Creating Results from Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import InstallCommandBuilder
   from oduit.operation_result import OperationResult
   from oduit.config_loader import ConfigProvider

   # Build operation
   config = ConfigProvider()
   builder = InstallCommandBuilder(config, "sale")
   operation = builder.build_operation()

   # Create result from operation
   result_builder = OperationResult.from_operation(operation)

   # Process execution results with automatic parsing
   output = "Some command output..."
   result_builder.set_success(True, 0)
   result_builder.set_output(stdout=output)
   result_builder.process_with_parsers(output)

   # Finalize and get structured result
    final_result = result_builder.finalize()

Install Operation Results
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Install operation with enhanced parsing
   builder = InstallCommandBuilder(config, "purchase")
   operation = builder.build_operation()

   # Execute and get structured results
   result = process_manager.run_operation(operation)

   # Access parsed install information
   print(f"Success: {result['success']}")
   print(f"Modules Loaded: {result.get('modules_loaded', 0)}")
   print(f"Total Modules: {result.get('total_modules', 0)}")

   if result.get('unmet_dependencies'):
       print("Unmet Dependencies:")
       for dep in result['unmet_dependencies']:
           print(f"  {dep['module']}: {dep['dependencies']}")

   if result.get('dependency_errors'):
       print("Dependency Errors:")
       for error in result['dependency_errors']:
            print(f"  - {error}")

Test Operation Results
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Test operation with enhanced parsing
   builder = OdooTestCommandBuilder(config, "/my_module")
   operation = builder.build_operation()

   # Execute and get structured results
   result = process_manager.run_operation(operation)

   # Access parsed test information
   print(f"Test Success: {result['success']}")
   print(f"Total Tests: {result.get('total_tests', 0)}")
   print(f"Passed Tests: {result.get('passed_tests', 0)}")
   print(f"Failed Tests: {result.get('failed_tests', 0)}")
   print(f"Error Tests: {result.get('error_tests', 0)}")

   # Access failure details
   if result.get('failures'):
       print("Test Failures:")
       for failure in result['failures']:
           print(f"  Test: {failure['test_name']}")
           if failure['file']:
               print(f"    File: {failure['file']}:{failure['line']}")
           if failure['error_message']:
               print(f"    Error: {failure['error_message']}")

Manual Result Building
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.operation_result import OperationResult

   # Create result builder manually
   result_builder = OperationResult(
       operation="install",
       module="sale",
       database="demo_db"
   )

   # Chain builder methods
   result = (result_builder
       .set_success(True, 0)
       .set_command(['odoo-bin', '-i', 'sale'])
       .set_output(stdout="Installation completed successfully")
       .set_custom_data(
           installation_time=45.2,
           modules_installed=['sale', 'base']
       )
       .finalize())

   print(f"Duration: {result['duration']}")
   print(f"Installation Time: {result['installation_time']}")

Error Handling and Semantic Success
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # The OperationResult provides semantic success detection
   # Example: Install operation that exits with code 0 but has dependency errors

   output = """
   loading 1 modules...
   module sale: Unmet dependencies: account, stock
   Some modules are not loaded: ['sale']
   """

   result_builder = OperationResult.from_operation(install_operation)
   result_builder.set_success(True, 0)  # Command exited with 0
   result_builder.process_with_parsers(output)

   final_result = result_builder.finalize()

   # Semantic analysis detects this as failure despite exit code 0
   print(f"Success: {final_result['success']}")  # False
   print(f"Error: {final_result['error']}")      # "Module installation failed: ..."

Custom Data and Metadata
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Add custom operation-specific data
   result_builder.set_custom_data(
       benchmark_time=123.45,
       memory_usage="2.1GB",
       custom_metrics={
           "queries_executed": 1247,
           "cache_hits": 892
       }
   )

   # Custom data is preserved alongside standard fields
   final_result = result_builder.finalize()
   print(f"Benchmark: {final_result['benchmark_time']}")
   print(f"Metrics: {final_result['custom_metrics']}")

Result Structure
----------------

Standard Result Fields
~~~~~~~~~~~~~~~~~~~~~~~

All OperationResult instances include these standard fields:

.. code-block:: python

   {
       # Execution results
       'success': bool,              # Overall operation success
       'return_code': int,           # Process exit code
       'stdout': str,                # Standard output
       'stderr': str,                # Error output
       'command': list[str],         # Executed command

       # Operation metadata
       'operation': str,             # Operation type
       'module': str | None,         # Target module
       'database': str | None,       # Target database
       'addon_name': str | None,     # Addon name
       'addons': list[str] | None,   # Multiple addons

       # Error information
       'error': str | None,          # Error message
       'error_type': str | None,     # Error classification

       # Timing
       'duration': float,            # Operation duration in seconds
        'timestamp': str,             # ISO timestamp
    }

Install Operation Results
~~~~~~~~~~~~~~~~~~~~~~~~~~

Install operations provide additional parsed fields:

.. code-block:: python

   {
       # Standard fields...

       # Install-specific parsed results
       'modules_loaded': int,                    # Successfully loaded modules
       'total_modules': int,                     # Total modules processed
       'unmet_dependencies': list[dict],         # Dependency issues
       'failed_modules': list[str],              # Modules that failed to load
       'dependency_errors': list[str],           # Human-readable dependency errors
       'error_messages': list[str],              # Installation error messages
   }

Example unmet_dependencies structure:

.. code-block:: python

   'unmet_dependencies': [
       {
           'module': 'sale_extended',
           'dependencies': ['account', 'stock', 'sale']
       }
    ]

Test Operation Results
~~~~~~~~~~~~~~~~~~~~~~~

Test operations provide detailed test statistics and failure information:

.. code-block:: python

   {
       # Standard fields...

       # Test-specific parsed results
       'total_tests': int,           # Total number of tests run
       'passed_tests': int,          # Number of passed tests
       'failed_tests': int,          # Number of failed tests
       'error_tests': int,           # Number of tests with errors
       'failures': list[dict],       # Detailed failure information
   }

Example failures structure:

.. code-block:: python

   'failures': [
       {
           'test_name': 'FastAPIDemoCase.test_no_key',
           'file': '/path/to/test_file.py',
           'line': 42,
           'error_message': 'AssertionError: Expected value not found',
           'traceback': ['Full traceback lines...']
       }
   ]

Semantic Success Logic
----------------------

Install Operations
~~~~~~~~~~~~~~~~~~~

- **Exit Code Success but Dependency Errors**: Marked as failure if unmet dependencies exist
- **Module Loading Failures**: Marked as failure if modules fail to load
- **Error Messages**: Marked as failure if installation-related ERROR lines are detected

Test Operations
~~~~~~~~~~~~~~~~

- **Test Failures**: Marked as failure if any tests fail, regardless of exit code
- **Test Errors**: Marked as failure if any tests have errors
- **Combines Exit Code and Test Results**: Provides comprehensive success assessment

Custom Operations
~~~~~~~~~~~~~~~~~~

- **Extensible**: Custom parsers can implement domain-specific success logic
- **Override Capability**: Manual success setting takes precedence when needed
- **Metadata-Driven**: Success logic adapts based on operation metadata

This semantic approach ensures that operations are correctly classified as successful or failed based on their actual outcomes, not just process exit codes.
