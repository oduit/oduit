Examples
========

This section provides practical examples of using oduit in various scenarios. The examples are organized from basic usage patterns to advanced features, showcasing the enhanced command builder architecture and structured result processing.

.. note::

   The examples demonstrate both the **enhanced architecture** with structured command building and result processing, as well as backward-compatible usage patterns. The enhanced approach is recommended for new projects.

Quick Start Examples
--------------------

Starting Odoo Instance
~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ../examples/simple_shell_example.py
   :language: python
   :caption: Simple Odoo startup example

Basic Module Management
~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ../examples/install_module_example.py
   :language: python
   :caption: Installing modules example

.. literalinclude:: ../examples/update_module_example.py
   :language: python
   :caption: Updating modules example

.. literalinclude:: ../examples/test_module_example.py
   :language: python
   :caption: Running module tests

Enhanced Architecture Examples
------------------------------

The following examples demonstrate the **enhanced command builder architecture** with structured command operations and automatic result processing:

Enhanced Demo Mode
~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ../examples/enhanced_demo_example.py
   :language: python
   :caption: Enhanced demo with structured operations and log streaming

This example showcases:

* **Structured operation results** with automatic parsing
* **Progressive log streaming** with realistic timing
* **Error scenario simulation** with detailed logging
* **Enhanced result processing** beyond simple success/failure

Real-Time Processing
~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ../examples/run_command_yielding_example.py
   :language: python
   :caption: Real-time command output processing with yielding

Features demonstrated:

* **Line-by-line output processing** as commands execute
* **Memory-efficient handling** of large outputs
* **Custom filtering and analysis** of command output
* **Real-time error detection** and response
* **Progress tracking** for long-running operations

Advanced Examples
-----------------

Demo Mode Operations
~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ../examples/demo_mode_example.py
   :language: python
   :caption: Basic demo mode operations

.. literalinclude:: ../examples/demo_comparison.py
   :language: python
   :caption: Demo comparison and analysis

Command Execution Patterns
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ../examples/shell_command_example.py
   :language: python
   :caption: Shell command execution patterns

.. literalinclude:: ../examples/execute_python_example.py
   :language: python
   :caption: Python code execution

.. literalinclude:: ../examples/demo_test_scenarios.py
   :language: python
   :caption: Test scenario demonstrations

Specialized Examples
~~~~~~~~~~~~~~~~~~~~

.. literalinclude:: ../examples/module_manifest_example.py
   :language: python
   :caption: Module manifest handling

.. literalinclude:: ../examples/yield_line_example.py
   :language: python
   :caption: Line-by-line yield processing

.. literalinclude:: ../examples/simple_yield_test.py
   :language: python
   :caption: Simple yielding test

Architecture Benefits
---------------------

Enhanced Command Builder Architecture
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The enhanced architecture provides several key benefits:

**Structured Operations**
  * Commands are built as ``CommandOperation`` objects with rich metadata
  * Operations include command details, expected behavior, and parsing hints
  * Results are automatically processed with domain-specific parsers

**Enhanced Result Processing**
  * Automatic parsing of install/update dependencies and statistics
  * Test result parsing with detailed failure information and tracebacks
  * Semantic success determination beyond simple exit codes
  * Structured output with consistent formatting

**Improved Developer Experience**
  * Type-safe command building with validation
  * Rich result objects with parsed data and metadata
  * Better error reporting with operation context
  * Progressive output streaming for real-time feedback

**Performance Optimizations**
  * Embedded execution mode for reduced overhead
  * Memory-efficient streaming for large outputs
  * Optimized parsing for common operation patterns
  * Reduced subprocess creation when possible

**Backward Compatibility**
  * All existing code continues to work unchanged
  * Gradual migration path to enhanced features
  * Legacy method support maintained
  * Configuration compatibility preserved

Configuration Examples
----------------------

Development Environment
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml
   :caption: development.yaml

   python_bin: "/usr/bin/python3"
   odoo_bin: "/opt/odoo-dev/odoo-bin"
   addons_path: "/opt/odoo-dev/addons,/opt/custom-dev/addons"
   db_name: "odoo_dev"
   db_user: "dev_user"
   db_password: "dev_password"
   xmlrpc_port: 8069
   log_level: "debug"

Production Environment
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml
   :caption: production.yaml

   binaries:
     python_bin: "/usr/bin/python3"
     odoo_bin: "/opt/odoo/odoo-bin"
     coverage_bin: "/usr/bin/coverage"

   odoo_params:
     addons_path: "/opt/odoo/addons,/opt/enterprise/addons,/opt/custom/addons"
     db_name: "odoo_prod"
     db_user: "odoo_user"
     db_password: "secure_password"
     db_host: "db.example.com"
     db_port: 5432
     xmlrpc_port: 8069
     workers: 8
     log_level: "warn"

Testing Environment
~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml
   :caption: testing.yaml

   python_bin: "/usr/bin/python3"
   odoo_bin: "/opt/odoo-test/odoo-bin"
   coverage_bin: "/usr/bin/coverage"
   db_name: "odoo_test"
   db_user: "test_user"
   db_password: "test_password"
   xmlrpc_port: 8070
   log_level: "info"
   without_demo: true
