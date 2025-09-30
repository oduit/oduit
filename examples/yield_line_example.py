#!/usr/bin/env python3
"""
Example demonstrating real-time output processing with ProcessManager.

The run_command_yielding() method enables programmatic access to processed output
in real-time instead of direct printing. This is useful for:
- Capturing formatted log output for further processing
- Building interactive applications that need to handle output programmatically
- Creating custom output filters or analyzers
"""

import json

from oduit.output import _formatter, configure_output
from oduit.process_manager import ProcessManager


def example_basic_usage(pm):
    """Example 1: Basic run_command (standard behavior)."""
    print("1. Standard output behavior (run_command):")
    print("   Running: echo 'Direct output to terminal'")
    result = pm.run_command(["echo", "Direct output to terminal"], verbose=True)
    print(f"   ✓ Command success: {result['success']}")
    print(f"   ✓ Captured output length: {len(result['output'])} chars")
    print()


def example_real_time_capture(pm):
    """Example 2: Using run_command_yielding for real-time output handling."""
    print("2. Real-time output capture (run_command_yielding):")
    print("   Running: echo -e 'Line 1\\nLine 2\\nLine 3'")

    captured_lines = []
    success = None
    for item in pm.run_command_yielding(
        ["echo", "-e", "Line 1\nLine 2\nLine 3"], verbose=True, suppress_output=True
    ):
        if "line" in item:
            line_content = item["line"].strip()
            if line_content:
                captured_lines.append(line_content)
        else:
            # Final result
            result = item.get("result", {})
            success = result.get("success", False)

    if success:
        print("   ✅ Successfully captured lines:")
        for i, line in enumerate(captured_lines, 1):
            print(f"      {i}. {line}")
    else:
        print("   ❌ Command failed")
    print()


def example_json_output_processing(pm):
    """Example 3: JSON formatted output processing."""
    print("3. JSON output processing:")
    original_format = _formatter.format_type
    configure_output("json")

    try:
        print(
            "   Running: python3 -c \"print('INFO: Test message'); "
            "print('ERROR: Test error')\""
        )
        captured_json_lines = []
        success = None
        for item in pm.run_command_yielding(
            [
                "python3",
                "-c",
                "print('INFO: Test message'); print('ERROR: Test error')",
            ],
            verbose=True,
            suppress_output=True,
        ):
            if "line" in item:
                line_content = item["line"].strip()
                if line_content:
                    captured_json_lines.append(line_content)
            else:
                # Final result
                result = item.get("result", {})
                success = result.get("success", False)

        if success:
            print("   ✅ Captured and parsed JSON output:")
            for line in captured_json_lines:
                try:
                    parsed = json.loads(line)
                    print(
                        f"     - {parsed.get('level', 'unknown').upper()}: "
                        f"{parsed.get('message', line)}"
                    )
                except json.JSONDecodeError:
                    print(f"     - Raw: {line}")

    finally:
        # Restore original format
        _formatter.format_type = original_format
    print()


def example_comparison_modes(pm):
    """Example 4: Comparison between direct and captured output."""
    print("4. Direct vs captured output comparison:")
    test_cmd = ["echo", "-e", "Output line 1\nOutput line 2\nOutput line 3"]

    print("   a) Direct output (run_command):")
    print("      Output appears below:")
    result1 = pm.run_command(test_cmd, verbose=False)
    print(
        f"      Result: success={result1['success']}, "
        f"output_len={len(result1['output'])}"
    )
    print()

    print("   b) Real-time captured output (run_command_yielding):")
    lines_captured = []
    success = None

    for item in pm.run_command_yielding(test_cmd, suppress_output=True):
        if "line" in item:
            line_content = item["line"].strip()
            if line_content:
                lines_captured.append(line_content)
        else:
            result = item.get("result", {})
            success = result.get("success", False)

    print("      Captured lines for processing:")
    for i, line in enumerate(lines_captured, 1):
        print(f"      {i}: {line}")

    print(f"   ✅ Both approaches succeeded: {success}")
    print()


def example_simulated_log_processing(pm):
    """Example 5: Simulated Odoo log processing."""
    print("5. Simulated log processing:")
    print("   Processing simulated Odoo logs with filtering and analysis")

    # Create a command that outputs simulated Odoo logs
    logs_cmd = [
        "python3",
        "-c",
        """
import sys
import time
logs = [
    '2023-12-01 10:00:00,123 INFO db_name odoo.modules.loading: '
    'Module loaded successfully',
    '2023-12-01 10:00:01,456 ERROR db_name odoo.sql_db: Database connection failed',
    '2023-12-01 10:00:02,789 INFO db_name odoo.service.server: '
    'Server starting on port 8069'
]
for log in logs:
    print(log)
    sys.stdout.flush()
    time.sleep(0.1)
        """,
    ]

    captured_log_lines = []
    error_count = 0
    success = None

    for item in pm.run_command_yielding(logs_cmd, suppress_output=True):
        if "line" in item:
            line = item["line"].strip()
            if line:
                captured_log_lines.append(line)
                if "ERROR" in line:
                    print(f"   🚨 Error detected: {line}")
                elif "INFO" in line:
                    print(f"   ℹ️  Info: {line}")
        else:
            result = item.get("result", {})
            success = result.get("success", False)

    if success:
        # Advanced processing - parse JSON structured logs
        print("   ✅ Processing structured logs:")
        if _formatter.format_type == "json":
            for line in captured_log_lines:
                try:
                    parsed = json.loads(line)
                    level = parsed.get("level", "unknown").upper()
                    message = parsed.get("message", line)

                    print(f"     [{level}] {message}")
                    if level == "ERROR":
                        error_count += 1
                except json.JSONDecodeError:
                    # Handle plain text logs
                    print(f"     [PLAIN] {line}")
        else:
            print("     📝 Plain text logs captured for processing")

    print(f"   📊 Analysis: {len(captured_log_lines)} lines, {error_count} errors")
    print()


def example_custom_filtering(pm):
    """Example 6: Custom output filtering with real-time processing."""
    print("6. Custom output filtering with run_command_yielding:")

    filter_cmd = [
        "python3",
        "-c",
        """
for i in range(10):
    if i % 2 == 0:
        print(f'KEEP: Important message {i}')
    else:
        print(f'SKIP: Verbose debug {i}')
        """,
    ]

    print("   Running command with mixed output...")
    keep_lines = []
    total_lines = 0
    success = None
    for item in pm.run_command_yielding(filter_cmd, suppress_output=True):
        if "line" in item:
            line_content = item["line"].strip()
            if line_content:
                total_lines += 1
                if "KEEP:" in line_content:
                    keep_lines.append(line_content)
        else:
            # Final result
            result = item.get("result", {})
            success = result.get("success", False)

    if success:
        print("   ✓ Filtered output (only KEEP messages):")
        for line in keep_lines:
            print(f"     {line}")

        print(f"   📊 Filtered {len(keep_lines)} out of {total_lines} lines")
    print()


def main():
    """Main function demonstrating various run_command_yielding usage patterns."""
    pm = ProcessManager()
    print("=== ProcessManager Real-Time Output Examples ===\n")

    example_basic_usage(pm)
    example_real_time_capture(pm)
    example_json_output_processing(pm)
    example_comparison_modes(pm)
    example_simulated_log_processing(pm)
    example_custom_filtering(pm)

    print("=== Summary ===")
    print("✅ run_command_yielding provides:")
    print("   • Real-time line-by-line access to command output")
    print("   • Ability to suppress direct output while capturing content")
    print("   • Support for both formatted JSON and plain text output")
    print("   • Memory-efficient streaming for large outputs")
    print("   • Perfect for building interactive tools and log analyzers")

    return 0


if __name__ == "__main__":
    exit(main())
