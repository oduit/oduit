#!/usr/bin/env python3
# Copyright (C) 2025 The oduit Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Example demonstrating OdooCodeExecutor for programmatic Odoo code execution.

This example shows how to use OdooCodeExecutor to run Python code within an
Odoo environment and capture results directly as Python objects, without
printing to console.
"""

import sys
import traceback
from pathlib import Path

# Add the parent directory to path so we can import oduit
sys.path.insert(0, str(Path(__file__).parent.parent))

from oduit.config_loader import ConfigLoader
from oduit.config_provider import ConfigProvider
from oduit.odoo_code_executor import OdooCodeExecutor


def main():
    """Demonstrate OdooCodeExecutor functionality."""
    print("=== Odoo Code Executor Examples ===\n")

    try:
        # Initialize config provider with basic Odoo configuration

        config_loader = ConfigLoader()
        basic_config = config_loader.load_config("common-test")
        config_provider = ConfigProvider(basic_config)
        executor = OdooCodeExecutor(config_provider)

        # Example 1: Simple expression - get partner name
        print("1. Getting first partner name:")
        result = executor.execute_code("env['res.partner'].search([],limit=1).name")

        if result["success"]:
            partner_name = result["value"]
            print(f"   Partner name: {partner_name}")
            print(f"   Result type: {type(partner_name)}")
        else:
            print(f"   Error: {result['error']}")

        print()

        # Example 2: Complex query - get partner statistics
        print("2. Getting partner statistics:")
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
            stats = result["value"]
            print(f"   Statistics: {stats}")
            print(f"   Total partners: {stats['total_partners']}")
            print(f"   Customers: {stats['customers']}")
            print(f"   Companies: {stats['companies']}")
        else:
            print(f"   Error: {result['error']}")

        print()

        # Example 3: Creating data (without commit)
        print("3. Creating test partner (no commit):")
        create_code = """
partner = env['res.partner'].create({
    'name': 'Test Partner from Code Executor',
    'email': 'test@example.com',
    'is_company': False
})
{
    'id': partner.id,
    'name': partner.name,
    'email': partner.email
}
"""
        result = executor.execute_code(create_code, commit=False)

        if result["success"]:
            partner_data = result["value"]
            print(f"   Created partner: {partner_data}")
            print("   (Not committed - will be rolled back)")
        else:
            print(f"   Error: {result['error']}")

        print()

        # Example 4: Multiple code blocks in sequence
        print("4. Executing multiple code blocks:")
        code_blocks = [
            "company_partners = env['res.partner'].search("
            "[('is_company', '=', True)], limit=3)",
            "partner_names = [p.name for p in company_partners]",
            "result = {'count': len(partner_names), 'names': partner_names}; result",
        ]

        result = executor.execute_multiple(code_blocks)

        if result["success"]:
            print(
                f"   Executed {result['executed_blocks']}/"
                f"{result['total_blocks']} blocks"
            )
            final_result = result["results"][-1]["value"]  # Get result from last block
            print(f"   Final result: {final_result}")
        else:
            print(f"   Failed at block {result.get('failed_at', 'unknown')}")
            print(f"   Error: {result.get('error', 'Unknown error')}")

        print()

        # Example 5: Error handling
        print("5. Error handling example:")
        result = executor.execute_code("nonexistent_variable + 42")

        if result["success"]:
            print(f"   Unexpected success: {result['value']}")
        else:
            print(f"   Expected error: {result['error']}")
            print("   ✓ Error handled gracefully")

        print()

        # Example 6: Working with dates and json
        print("6. Working with datetime and json:")
        datetime_code = """
import datetime
import json

now = datetime.datetime.now()
data = {
    'timestamp': now.isoformat(),
    'partners_created_today': len(env['res.partner'].search([
        ('create_date', '>=', now.strftime('%Y-%m-%d'))
    ])),
    'database': env.cr.dbname
}
json.dumps(data, indent=2)
"""
        result = executor.execute_code(datetime_code)

        if result["success"]:
            json_output = result["value"]
            print("   JSON output:")
            print(f"   {json_output}")
        else:
            print(f"   Error: {result['error']}")

        print()
        print("=== Summary ===")
        print("✓ OdooCodeExecutor allows running Python code in Odoo environment")
        print("✓ Results are captured as Python objects, not printed output")
        print("✓ Supports both expressions and multi-line code blocks")
        print("✓ Proper error handling and transaction management")
        print("✓ Perfect for programmatic Odoo operations")

    except ImportError as e:
        print(f"Error: Odoo not available - {e}")
        print("Make sure Odoo is installed and in your PYTHONPATH")
        return 1

    except Exception as e:
        print(f"Unexpected error: {e}")
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
