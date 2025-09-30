#!/usr/bin/env python3
"""
Simple test of the run_command_yielding functionality.
"""

import sys

from oduit.process_manager import ProcessManager

sys.dont_write_bytecode = True


def main():
    """Demonstrate run_command_yielding functionality with simple examples."""
    pm = ProcessManager()
    print("=== Simple run_command_yielding demonstration ===\n")

    # 1. Normal execution (run_command) - output goes directly to terminal
    print("1. Normal execution (output to terminal):")
    result = pm.run_command(["echo", "Hello World"], verbose=True)
    print(f"   Result success: {result['success']}")
    print(f"   Result output: '{result['output']}'\\n")

    # 2. Real-time execution (run_command_yielding) - output captured in real-time
    print("2. Real-time execution (output captured):")
    captured_lines = []
    success = None

    for item in pm.run_command_yielding(
        ["echo", "Hello World"], verbose=True, suppress_output=True
    ):
        if "line" in item:
            line_content = item["line"].strip()
            if line_content:
                captured_lines.append(line_content)
                print(f"   📝 Captured: '{line_content}'")
        else:
            # Final result
            result = item.get("result", {})
            success = result.get("success", False)

    print(f"   Result success: {success}")
    if captured_lines:
        print(f"   We captured: {captured_lines[0]}\\n")
    else:
        print("   No output captured\\n")

    # 3. Multi-line command with run_command_yielding
    print("3. Multi-line command capture:")
    captured_lines = []
    success = None

    for item in pm.run_command_yielding(
        ["python3", "-c", "print('Line 1'); print('Line 2'); print('Line 3')"],
        suppress_output=True,
    ):
        if "line" in item:
            line_content = item["line"].strip()
            if line_content:
                captured_lines.append(line_content)
        else:
            # Final result
            result = item.get("result", {})
            success = result.get("success", False)

    print(f"   Success: {success}")
    print("   Captured lines:")
    for i, line in enumerate(captured_lines, 1):
        print(f"   {i}: {line}")

    print("\\n=== run_command_yielding demonstration complete ===")


if __name__ == "__main__":
    exit(main())
