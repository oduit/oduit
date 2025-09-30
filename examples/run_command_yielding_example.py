#!/usr/bin/env python3
"""
Example demonstrating the run_command_yielding method in ProcessManager.

The run_command_yielding method is a generator that yields output lines as they arrive,
allowing for real-time processing of command output. This is useful for:
- Real-time log processing and filtering
- Building interactive applications that need to react to command output
- Creating custom progress indicators based on command output
- Processing large amounts of output without storing it all in memory
"""

import time

from oduit.process_manager import ProcessManager


def main():
    # Initialize the process manager
    pm = ProcessManager()

    print("=== ProcessManager run_command_yielding Examples ===\n")

    # Example 1: Basic usage with simple command
    print("1. Basic yielding with echo command:")
    print("   Running: echo -e 'Line 1\\nLine 2\\nLine 3'")

    line_count = 0
    for item in pm.run_command_yielding(
        ["echo", "-e", "Line 1\nLine 2\nLine 3"],
        verbose=True,
        suppress_output=True,  # Suppress direct output to see yielded lines
    ):
        if "line" in item:
            line_count += 1
            line_content = item["line"].strip()
            if line_content:  # Skip empty lines
                print(f"   📝 Yielded line {line_count}: '{line_content}'")
                print(
                    f"      Should show: {item['should_show']}, "
                    f"Is error: {item['is_error']}"
                )
        else:
            # Final result
            result = item["result"]
            print(
                f"   ✅ Final result: Success={result['success']}, "
                f"Return code={result['return_code']}"
            )
    print()

    # Example 2: Error detection with yielding
    print("2. Error detection with yielding:")
    print(
        "   Running: echo -e 'Normal line\\nERROR: Something went wrong\\nAnother line'"
    )

    error_count = 0
    normal_count = 0

    for item in pm.run_command_yielding(
        ["echo", "-e", "Normal line\nERROR: Something went wrong\nAnother line"],
        verbose=True,
        suppress_output=True,
    ):
        if "line" in item:
            line_content = item["line"].strip()
            if line_content:  # Skip empty lines
                if item["is_error"]:
                    error_count += 1
                    print(f"   🚨 ERROR detected: '{line_content}'")
                else:
                    normal_count += 1
                    print(f"   ℹ️  Normal line: '{line_content}'")
        else:
            result = item["result"]
            print(
                f"   📊 Stats: {normal_count} normal lines, {error_count} error lines"
            )
            print(f"   ✅ Command completed: Success={result['success']}")
    print()

    # Example 3: Real-time processing simulation
    print("3. Real-time processing with longer command:")
    print("   Running: python -c with multiple print statements")

    python_code = """
import time
for i in range(5):
    print(f"Processing step {i+1}/5...")
    time.sleep(0.1)
print("Processing complete!")
"""

    start_time = time.time()
    for item in pm.run_command_yielding(
        ["python", "-c", python_code], verbose=False, suppress_output=True
    ):
        if "line" in item:
            line_content = item["line"].strip()
            if line_content:
                elapsed = time.time() - start_time
                print(f"   [{elapsed:.1f}s] {line_content}")
        else:
            result = item["result"]
            total_time = time.time() - start_time
            print(f"   ⏱️  Total execution time: {total_time:.1f}s")
            print(f"   ✅ Success: {result['success']}")
    print()

    # Example 4: Custom output filtering
    print("4. Custom output filtering:")
    print("   Running command and filtering for specific patterns")

    filter_cmd = [
        "echo",
        "-e",
        "INFO: Starting process\nDEBUG: Detailed info\nWARNING: Minor issue\n"
        "ERROR: Critical problem\nINFO: Process complete",
    ]

    important_lines = []
    for item in pm.run_command_yielding(filter_cmd, suppress_output=True):
        if "line" in item:
            line = item["line"].strip()
            # Filter for INFO, WARNING, and ERROR lines only (skip DEBUG)
            if any(level in line for level in ["INFO:", "WARNING:", "ERROR:"]):
                important_lines.append(line)
                level = (
                    "ERROR"
                    if "ERROR:" in line
                    else "WARNING"
                    if "WARNING:" in line
                    else "INFO"
                )
                emoji = "🚨" if level == "ERROR" else "⚠️" if level == "WARNING" else "ℹ️"
                print(f"   {emoji} [{level}] {line}")
        else:
            result = item["result"]
            print(f"   📋 Filtered {len(important_lines)} important lines from output")
    print()

    # Example 5: Memory-efficient processing of large output
    print("5. Memory-efficient processing (simulated large output):")
    print("   Demonstrating how yielding prevents memory buildup")

    # Simulate processing a command that produces lots of output
    large_output_cmd = [
        "python",
        "-c",
        "for i in range(50): print(f'Data line {i:03d}: Some content here')",
    ]

    processed_lines = 0
    memory_friendly_summary = []

    for item in pm.run_command_yielding(large_output_cmd, suppress_output=True):
        if "line" in item:
            processed_lines += 1
            line = item["line"].strip()

            # Process line immediately without storing full content
            if line and "Data line" in line:
                # Extract just the line number for summary
                try:
                    line_num = line.split("Data line ")[1].split(":")[0]
                    if int(line_num) % 10 == 0:  # Every 10th line
                        memory_friendly_summary.append(f"Checkpoint at line {line_num}")
                        print(f"   📍 Processed line {line_num}")
                except (IndexError, ValueError):
                    pass
        else:
            result = item["result"]
            print(f"   ✅ Processed {processed_lines} lines efficiently")
            print(
                f"   💾 Memory summary: {len(memory_friendly_summary)} "
                f"checkpoints stored"
            )

    print("\n=== Summary ===")
    print("✅ run_command_yielding provides:")
    print("   • Real-time line-by-line output processing")
    print("   • Memory-efficient handling of large outputs")
    print("   • Custom filtering and analysis capabilities")
    print("   • Error detection and immediate response")
    print("   • Same error handling and cleanup as run_command")


if __name__ == "__main__":
    main()
