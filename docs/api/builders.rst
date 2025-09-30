Builders
========

The builders module provides a structured command building system for Odoo operations. It uses command builders that create structured CommandOperation objects containing both the command and associated metadata for enhanced operation management.

.. automodule:: oduit.builders
   :members:
   :undoc-members:
   :show-inheritance:

Core Architecture
-----------------

CommandOperation
~~~~~~~~~~~~~~~~

The ``CommandOperation`` dataclass is the core structure returned by all command builders:

.. code-block:: python

   from oduit.builders import CommandOperation

   @dataclass
   class CommandOperation:
       """Structured command operation containing both command and metadata."""

       command: list[str]              # The actual command to execute
       operation_type: str             # Operation type: 'server', 'test', 'install', etc.
       database: str | None = None     # Target database name
       modules: list[str] = field(default_factory=list)        # Affected modules
       test_tags: str | None = None    # Test tags for test operations
       extra_args: list[str] = field(default_factory=list)     # Additional arguments
       is_odoo_command: bool = True    # Whether this is an Odoo command

       # Result handling metadata
       expected_result_fields: dict[str, Any] = field(default_factory=dict)
       result_parsers: list[str] = field(default_factory=list)

Enhanced Builder Pattern
~~~~~~~~~~~~~~~~~~~~~~~~

All command builders now implement the ``build_operation()`` method that returns a ``CommandOperation`` with structured metadata:

.. code-block:: python

   # Abstract base defines the interface
   class AbstractCommandBuilder:
       @abstractmethod
       def build_operation(self) -> CommandOperation:
           """Build and return a structured CommandOperation with metadata"""
           pass

Usage Examples
--------------

Basic Command Building
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import InstallCommandBuilder
   from oduit.config_loader import ConfigProvider

   # Create config provider
   config = ConfigProvider()

   # Build structured install operation
   builder = InstallCommandBuilder(config, "sale")
   operation = builder.build_operation()

   print(f"Command: {' '.join(operation.command)}")
   print(f"Operation Type: {operation.operation_type}")
   print(f"Modules: {operation.modules}")
   print(f"Database: {operation.database}")

Test Command Building
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import OdooTestCommandBuilder

   # Build test operation with coverage
   builder = OdooTestCommandBuilder(config, "/my_module")
   operation = builder.build_operation()

   print(f"Test Tags: {operation.test_tags}")
   print(f"Modules Tested: {operation.modules}")
   print(f"Result Parsers: {operation.result_parsers}")

Update Command Building
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import UpdateCommandBuilder

   # Build update operation
   builder = UpdateCommandBuilder(config, "purchase")
   operation = builder.build_operation()

   print(f"Operation Type: {operation.operation_type}")
   print(f"Expected Results: {operation.expected_result_fields}")

Database Command Building
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import DatabaseCommandBuilder

   # Build database creation operation
   builder = DatabaseCommandBuilder(config)
   builder.create_database("my_new_db")
   operation = builder.build_operation()

   print(f"Command: {' '.join(operation.command)}")
   print(f"Is Odoo Command: {operation.is_odoo_command}")  # False for direct postgres

Shell Command Building
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import ShellCommandBuilder

   # Build shell operation
   builder = ShellCommandBuilder(config)
   operation = builder.build_operation()

   print(f"Shell Enabled: {operation.expected_result_fields.get('shell_enabled')}")

Language Export Building
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.builders import LanguageCommandBuilder

   # Build language export operation
   builder = LanguageCommandBuilder(config, "sale", "sale_es.po", "es_ES")
   operation = builder.build_operation()

   print(f"Extra Args: {operation.extra_args}")  # [filename, language]
   print(f"Expected Fields: {operation.expected_result_fields}")

Backward Compatibility
~~~~~~~~~~~~~~~~~~~~~~

The legacy ``build()`` method is still supported for backward compatibility:

.. code-block:: python

   # Legacy usage still works
   builder = InstallCommandBuilder(config, "sale")
   command_list = builder.build()  # Returns list[str]

   # Enhanced usage provides structured metadata
   operation = builder.build_operation()  # Returns CommandOperation
