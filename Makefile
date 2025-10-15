.PHONY: generate-manifests clean-manifests help

ODOO_VERSION ?= 17.0

help:
	@echo "Available targets:"
	@echo "  generate-manifests  - Generate __manifest__.py files from templates (default: ODOO_VERSION=17.0)"
	@echo "  clean-manifests     - Remove generated __manifest__.py files"
	@echo ""
	@echo "Usage examples:"
	@echo "  make generate-manifests"
	@echo "  make generate-manifests ODOO_VERSION=18.0"
	@echo "  make clean-manifests"

generate-manifests:
	@echo "Generating manifests for Odoo $(ODOO_VERSION)..."
	@find integration_tests/myaddons -name "__manifest__.py.tmpl" | while read tmpl; do \
		output="$${tmpl%.tmpl}"; \
		sed "s/{odoo_major}/$(ODOO_VERSION)/g" "$$tmpl" > "$$output"; \
		echo "  Generated $$output"; \
	done
	@echo "Done!"

clean-manifests:
	@echo "Cleaning generated manifests..."
	@find integration_tests/myaddons -name "__manifest__.py" -type f -delete
	@echo "Done!"
