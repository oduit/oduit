from odoo.tests import TransactionCase


class TestModuleB(TransactionCase):
    def test_failing_test(self):
        self.assertEqual(1, 2, "This test intentionally fails")

    def test_passing_test(self):
        self.assertEqual(1, 1, "This test passes")
