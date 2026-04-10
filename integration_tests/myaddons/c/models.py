from odoo import fields, models


class DummyModel(models.Model):
    _name = "test.dummy"
    _description = "Dummy Model for Testing"

    name = fields.Char(required=True)
