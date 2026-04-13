OdooInspector
=============

``OdooInspector`` is the structured runtime inspection API for XMLIDs, cron
records, models, fields, PostgreSQL metadata, and trusted embedded execution.

It builds on ``OdooCodeExecutor`` and ``OdooQuery`` so callers can prefer
first-class inspection methods over ad hoc shell snippets.

.. automodule:: oduit.odoo_inspector
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

.. code-block:: python

   from oduit import ConfigLoader, OdooInspector

   loader = ConfigLoader()
   config = loader.load_config("dev")
   inspector = OdooInspector(config)

   xmlid = inspector.inspect_ref("base.action_partner_form")
   model = inspector.inspect_model("res.partner")
   field = inspector.inspect_field("res.partner", "email", with_db=True)
   table = inspector.describe_table("res_partner")
   scans = inspector.performance_table_scans(limit=10)
