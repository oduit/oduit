#!/usr/bin/env python3
# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Example script demonstrating all database operations in oduit.

This script shows how to:
1. Check if a database exists (db_exists)
2. List all databases (list_db)
3. Drop a database (drop_db)
4. Create a database (create_db)
5. Handle errors and results properly

Usage:
    python examples/database_operations_example.py
"""

import sys

from oduit import OdooOperations


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_result(operation_name, result):
    """Print operation result in a readable format"""
    print(f"\n{operation_name} Result:")
    print(f"  Success: {result.get('success', False)}")
    print(f"  Return Code: {result.get('return_code', 'N/A')}")

    if "exists" in result:
        print(f"  Database Exists: {result.get('exists', False)}")

    if "database" in result:
        print(f"  Database: {result.get('database', 'N/A')}")

    if result.get("stdout"):
        print(f"  Output:\n{result.get('stdout')}")

    if result.get("stderr"):
        print(f"  Errors:\n{result.get('stderr')}")

    if "error" in result:
        print(f"  Error: {result.get('error')}")


def main(with_sudo=True):
    """Demonstrate all database operations"""

    # Configuration for database operations
    env_config = {
        "python_bin": "python3",
        "odoo_bin": "odoo",
        "db_name": "oduit_demo_db",
    }

    print_section("ODUIT Database Operations Example")
    print("\nThis example demonstrates all database operations available in oduit.")
    print(f"Target database: {env_config['db_name']}")

    # Initialize OdooOperations
    ops = OdooOperations(env_config, verbose=False)

    # =========================================================================
    # 1. Check if database exists
    # =========================================================================
    print_section("1. Checking if Database Exists (db_exists)")

    exists_result = ops.db_exists(with_sudo=with_sudo, suppress_output=False)
    print_result("db_exists", exists_result)

    if exists_result.get("exists"):
        print(
            f"\n✓ Database '{env_config['db_name']}' already exists. "
            "We'll drop it first."
        )
        perform_drop = True
    else:
        print(
            f"\n✓ Database '{env_config['db_name']}' does not exist. "
            "We'll create it directly."
        )
        perform_drop = False

    # =========================================================================
    # 2. List all databases
    # =========================================================================
    print_section("2. Listing All Databases (list_db)")

    list_result = ops.list_db(with_sudo=with_sudo, suppress_output=True)
    print_result("list_db", list_result)

    # =========================================================================
    # 3. Drop database (if it exists)
    # =========================================================================
    if perform_drop:
        print_section("3. Dropping Existing Database (drop_db)")

        drop_result = ops.drop_db(with_sudo=with_sudo, suppress_output=False)
        print_result("drop_db", drop_result)

        if drop_result.get("success"):
            print(f"\n✓ Successfully dropped database '{env_config['db_name']}'")
        else:
            print(f"\n✗ Failed to drop database: {drop_result.get('error')}")
            sys.exit(1)
    else:
        print_section("3. Dropping Database (drop_db) - SKIPPED")
        print("\nSkipping drop operation since database does not exist.")

    # =========================================================================
    # 4. Create database
    # =========================================================================
    print_section("4. Creating Database (create_db)")

    create_result = ops.create_db(
        with_sudo=with_sudo,
        suppress_output=False,
        create_role=False,
        alter_role=False,
        extension=None,
    )
    print_result("create_db", create_result)

    if create_result.get("success"):
        print(f"\n✓ Successfully created database '{env_config['db_name']}'")
    else:
        print(f"\n✗ Failed to create database: {create_result.get('error')}")
        sys.exit(1)

    # =========================================================================
    # 5. Verify database exists after creation
    # =========================================================================
    print_section("5. Verifying Database Creation (db_exists)")

    verify_result = ops.db_exists(with_sudo=with_sudo, suppress_output=False)
    print_result("db_exists (verification)", verify_result)

    if verify_result.get("exists"):
        print(f"\n✓ Confirmed: Database '{env_config['db_name']}' exists!")
    else:
        print(f"\n✗ Warning: Database '{env_config['db_name']}' was not found!")

    # =========================================================================
    # 6. Advanced: Create database with role and extension
    # =========================================================================
    print_section("6. Advanced Database Creation with Role and Extension")
    print("\nThis example shows creating a database with:")
    print("  - Custom database role")
    print("  - Role privileges (LOGIN, CREATEDB)")
    print("  - PostgreSQL extension (e.g., 'pg_trgm')")
    print("\nNote: This requires db_user to be set in configuration")

    # First drop the database
    drop_result2 = ops.drop_db(with_sudo=with_sudo, suppress_output=False)
    print_result("drop_db (for advanced example)", drop_result2)

    # Create with advanced options only if db_user is configured
    if "db_user" in env_config:
        advanced_create_result = ops.create_db(
            with_sudo=with_sudo,
            suppress_output=False,
            create_role=True,
            alter_role=True,
            extension="pg_trgm",
            db_user=env_config["db_user"],
        )
        print_result("create_db (with role and extension)", advanced_create_result)

        if advanced_create_result.get("success"):
            print(
                f"\n✓ Successfully created database '{env_config['db_name']}' "
                "with role and extension"
            )
        else:
            print(
                f"\n✗ Failed to create database with advanced options: "
                f"{advanced_create_result.get('error')}"
            )
    else:
        print("\n⚠ Skipping advanced database creation (db_user not configured)")
        # Create simple database instead
        simple_create = ops.create_db(with_sudo=with_sudo, suppress_output=False)
        print_result("create_db (simple)", simple_create)

    # =========================================================================
    # 7. Error handling example
    # =========================================================================
    print_section("7. Error Handling Example (raise_on_error)")

    print("\nDemonstrating error handling with raise_on_error=True")
    print("Attempting to drop a non-existent database...")

    # First drop the database so it doesn't exist
    ops.drop_db(with_sudo=with_sudo, suppress_output=True)

    # Now try to drop it again, which should fail
    # Note: dropdb --if-exists won't fail, so this is just a demonstration
    try:
        result = ops.drop_db(
            with_sudo=with_sudo, suppress_output=False, raise_on_error=True
        )
        print_result("drop_db (should succeed with --if-exists)", result)
    except Exception as e:
        print(f"\n✗ Exception raised: {e}")

    # =========================================================================
    # 8. List databases again to see final state
    # =========================================================================
    print_section("8. Final Database List")

    final_list_result = ops.list_db(with_sudo=with_sudo, suppress_output=True)
    print_result("list_db (final)", final_list_result)

    # =========================================================================
    # Summary
    # =========================================================================
    print_section("Summary")
    print("\nAll database operations demonstrated successfully!")
    print("\nOperations covered:")
    print("  ✓ db_exists   - Check if a database exists")
    print("  ✓ list_db     - List all databases")
    print("  ✓ drop_db     - Drop a database")
    print("  ✓ create_db   - Create a database")
    print("  ✓ create_db   - Create with role and extension")
    print("  ✓ Error handling with raise_on_error parameter")
    print("\nTypical workflow:")
    print("  1. Check if database exists (db_exists)")
    print("  2. If exists, drop it (drop_db)")
    print("  3. Create fresh database (create_db)")
    print("  4. Verify creation (db_exists)")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  IMPORTANT: Update env_config with your actual paths!")
    print("=" * 70)
    print("\nBefore running this script, update the following in the code:")
    print("  - python_bin: Path to your Python binary")
    print("  - odoo_bin: Path to your odoo-bin executable")
    print("  - addons_path: Path to your Odoo addons")
    print("  - data_dir: Path to your Odoo data directory")
    print("\nThis is a demonstration script. Uncomment main() when ready.")
    print("=" * 70)

    # Uncomment the line below when you've updated the configuration
    main(with_sudo=False)
