from odoo import fields, models


class DummyModel(models.Model):
    _inherit = "test.dummy"

    integration_note = fields.Char()
