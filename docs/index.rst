Welcome to oduit's documentation!
=================================

**oduit** is an Odoo CLI and Python utility layer focused on two things:

* running common Odoo workflows with structured results
* understanding addons through manifest, dependency, and series introspection

Highlights
----------

* ``oduit doctor`` for setup diagnostics
* structured JSON output for automation and CI
* addon intelligence commands such as ``list-addons``, ``list-depends``,
  ``install-order``, and ``impact-of-update``
* Python APIs for operations, addon analysis, typed planning models, and safe
  read-only queries

Quick Start
-----------

.. code-block:: bash

   oduit --env dev doctor
   oduit --env dev version
   oduit --env dev list-addons
   oduit --env dev install-order sale,purchase

Installation
------------

.. code-block:: bash

   pip install oduit

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   quickstart
   cli
   configuration
   api
   examples
   changelog

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
