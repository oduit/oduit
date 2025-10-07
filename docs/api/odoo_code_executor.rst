OdooCodeExecutor
================

The OdooCodeExecutor class provides a way to execute Python code within an Odoo environment and capture results directly as Python objects, without printing to console. It's perfect for programmatic use cases where you want to query data, perform operations, and get results back.

.. automodule:: oduit.odoo_code_executor
   :members:
   :undoc-members:
   :show-inheritance:

Features
--------

- **Direct Result Capture**: Execute code within proper Odoo environment with 'env' variable
- **Return Value Handling**: Capture return values and exceptions as Python objects
- **Smart Compilation**: Support for both single expressions and multi-line code blocks
- **Automatic Database Connection**: Handles database connection and cleanup automatically
- **Thread-Safe Execution**: Proper threading context setup for Odoo
- **Transaction Management**: Read-only by default with optional commit functionality

Basic Usage
-----------

Simple Expression Execution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Execute a single expression and get the result:

.. code-block:: python

    from oduit.config_provider import ConfigProvider
    from oduit.odoo_code_executor import OdooCodeExecutor

    config_provider = ConfigProvider(config_dict)
    executor = OdooCodeExecutor(config_provider)

    # Get partner name
    result = executor.execute_code("env['res.partner'].search([],limit=1).name")
    if result["success"]:
        partner_name = result["value"]  # Returns actual string
        print(f"Partner: {partner_name}")

Multi-line Code with Return Value
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Execute complex code blocks that end with an expression:

.. code-block:: python

    code = """
    partner_count = len(env['res.partner'].search([]))
    customer_count = len(env['res.partner'].search([('is_company', '=', False)]))
    company_count = len(env['res.partner'].search([('is_company', '=', True)]))

    {
        'total_partners': partner_count,
        'customers': customer_count,
        'companies': company_count,
        'ratio': f"{customer_count}/{company_count}" if company_count > 0 else "N/A"
    }
    """

    result = executor.execute_code(code)
    if result["success"]:
        stats = result["value"]  # Returns the dictionary
        print(f"Statistics: {stats}")

Data Modification with Transaction Control
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create or modify data with explicit commit control:

.. code-block:: python

    create_code = """
    partner = env['res.partner'].create({
        'name': 'Test Partner',
        'email': 'test@example.com',
        'is_company': False
    })
    {'id': partner.id, 'name': partner.name, 'email': partner.email}
    """

    # Execute with commit=True to persist changes
    result = executor.execute_code(create_code, commit=True)
    if result["success"]:
        partner_data = result["value"]
        print(f"Created partner: {partner_data}")

Multiple Code Blocks
~~~~~~~~~~~~~~~~~~~~~

Execute multiple related code blocks in sequence within the same transaction:

.. code-block:: python

    code_blocks = [
        "company_partners = env['res.partner'].search([('is_company', '=', True)], limit=3)",
        "partner_names = [p.name for p in company_partners]",
        "{'count': len(partner_names), 'names': partner_names}"
    ]

    result = executor.execute_multiple(code_blocks)
    if result["success"]:
        # Get result from the last block
        final_result = result["results"][-1]["value"]
        print(f"Companies: {final_result}")

Error Handling
--------------

The OdooCodeExecutor provides comprehensive error handling with detailed information:

.. code-block:: python

    result = executor.execute_code("nonexistent_variable + 42")
    if not result["success"]:
        print(f"Error: {result['error']}")
        print(f"Traceback: {result['traceback']}")

Return Value Structure
----------------------

All execution methods return a dictionary with the following structure:

Single Code Execution (``execute_code``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    {
        "success": bool,      # True if execution succeeded
        "value": Any,         # Return value if code was an expression
        "output": str,        # Any stdout output from the code
        "error": str,         # Error message if execution failed
        "traceback": str      # Full traceback if an exception occurred
    }

Multiple Code Execution (``execute_multiple``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    {
        "success": bool,           # True if all blocks executed successfully
        "results": list,           # List of individual execution results
        "failed_at": int,          # Index of failed block (if stop_on_error=True)
        "total_blocks": int,       # Total number of code blocks
        "executed_blocks": int,    # Number of blocks that were executed
        "error": str              # Overall error message (if applicable)
    }

Execution Context
-----------------

When code is executed, the following variables are available in the execution context:

Standard Odoo Variables
~~~~~~~~~~~~~~~~~~~~~~~

- ``env``: Odoo Environment object with all models
- ``odoo``: The odoo module
- ``registry``: Database registry
- ``cr``: Database cursor
- ``uid``: User ID (SUPERUSER_ID)
- ``context``: User context dictionary

Common Python Modules
~~~~~~~~~~~~~~~~~~~~~~

- ``datetime``: Python datetime module
- ``json``: JSON handling module
- ``os``: Operating system interface
- ``sys``: System-specific parameters

Configuration Requirements
--------------------------

The OdooCodeExecutor requires a ConfigProvider with the following configuration:

Required Configuration
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    config = {
        "db_name": "your_database",
        "db_user": "odoo_user",
        "db_password": "password",
        "addons_path": "/path/to/addons",
    }

Optional Configuration
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    config = {
        "db_host": "localhost",     # Default: localhost
        "db_port": 5432,            # Default: 5432
        "data_dir": "~/data",       # Default: ~/.local/share/Odoo
    }

Thread Safety and Performance
-----------------------------

The OdooCodeExecutor is designed to be thread-safe and handles:

- Proper threading context setup with ``setattr(threading.current_thread(), "dbname", db_name)``
- Database connection pooling through Odoo's registry system
- Automatic transaction management (rollback by default)
- Output stream redirection and restoration

Security Considerations
-----------------------

When using OdooCodeExecutor:

- Code is executed with SUPERUSER_ID privileges
- All database operations are performed within transactions
- By default, all changes are rolled back unless ``commit=True`` is specified
- Input code should be trusted as it has full access to the Odoo environment
- Consider implementing additional access controls in production environments

Best Practices
--------------

1. **Always check the success flag** before using result values
2. **Use explicit commit control** - only commit when necessary
3. **Handle errors gracefully** with proper error checking
4. **Keep code blocks focused** - break complex operations into smaller pieces
5. **Test expressions first** before using in production code
6. **Use timeouts** for long-running operations to prevent hanging
