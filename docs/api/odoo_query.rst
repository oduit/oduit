OdooQuery
=========

The ``OdooQuery`` class provides a safe, structured read-only query API for
common Odoo inspection tasks. It builds minimal trusted code internally and
keeps the raw ``OdooCodeExecutor`` safety gate unchanged.

.. automodule:: oduit.odoo_query
   :members:
   :undoc-members:
   :show-inheritance:

Basic Usage
-----------

.. code-block:: python

   from oduit import OdooQuery

   query = OdooQuery(
       {
           "db_name": "mydb",
           "db_user": "odoo",
           "addons_path": "/opt/odoo/addons",
       }
   )

   result = query.query_model(
       "res.partner",
       domain=[("customer_rank", ">", 0)],
       fields=["name", "email"],
       limit=5,
   )

   if result["success"]:
       print(result["records"])

Supported Read Helpers
----------------------

- ``query_model(...)``: search and read matching records
- ``read_record(...)``: read one record by id
- ``search_count(...)``: count matching records
- ``get_model_fields(...)``: inspect field metadata via ``fields_get``

Validation Rules
----------------

- Model names must use safe identifier characters
- Fields and attribute names must be string identifiers
- Domains must contain literal-safe values only
- Query limits must be positive integers and stay within the built-in cap

Relationship To OdooCodeExecutor
--------------------------------

- Use ``OdooQuery`` for common read-only access
- Use ``OdooCodeExecutor`` only for trusted arbitrary code
- ``allow_unsafe=True`` is still required for raw code execution
