from odoo.tests import TransactionCase


class TestModuleE(TransactionCase):
    def test_integration_note_field_exists(self):
        field = self.env["test.dummy"]._fields.get("integration_note")
        self.assertIsNotNone(field)

    def test_model_name_field_exists(self):
        field = self.env["test.dummy"]._fields.get("name")
        self.assertIsNotNone(field)
