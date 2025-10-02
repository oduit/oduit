DemoProcessManager
==================

The DemoProcessManager extends ProcessManager with demo mode capabilities.

.. automodule:: oduit.demo_process_manager
   :members:
   :undoc-members:
   :show-inheritance:

Class Reference
---------------

.. autoclass:: oduit.DemoProcessManager
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

Demo Mode Operations
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import DemoProcessManager, ConfigLoader

   loader = ConfigLoader()
   config = loader.load_demo_config()
   demo_manager = DemoProcessManager(config)

   # Run demo scenario
   result = demo_manager.run_demo_scenario()
   if result.success:
       print("Demo scenario completed successfully")

   # Run with specific modules
   result = demo_manager.run_demo_scenario(
       modules=['sale', 'purchase'],
       scenario='full_workflow'
   )

Advanced Demo Features
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Setup demo environment
   demo_manager.setup_demo_environment()

   # Run comparison scenarios
   results = demo_manager.run_comparison_scenarios([
       'scenario_a',
       'scenario_b'
   ])

   # Cleanup demo data
   demo_manager.cleanup_demo_data()
