# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import json
import sys
from typing import Any


class OutputFormatter:
    """Handles different output formats and modes."""

    def __init__(self, format_type: str = "text", non_interactive: bool = False):
        self.format_type = format_type.lower()
        self.non_interactive = non_interactive
        self._previous_fields: dict[str, Any] = {}

    def output(
        self, message: str, level: str = "info", data: dict[str, Any] | None = None
    ) -> None:
        """Output a message in the configured format."""
        if self.format_type == "json":
            self._output_json(message, level, data)
        else:
            self._output_text(message, level)

    def _output_json(
        self, message: str, level: str, data: dict[str, Any] | None = None
    ) -> None:
        """Output in JSON format."""
        # Check if this looks like an Odoo log line that needs parsing
        if self._is_odoo_log_line(message):
            parsed_log = self._parse_odoo_log_line(message)
            if parsed_log:
                parsed_log["type"] = "log"
                print(json.dumps(parsed_log))
                return

        # Regular message output
        output_data: dict[str, Any] = {
            "type": "log",
            "level": level,
            "message": message,
            "timestamp": self._get_timestamp(),
        }
        if data:
            output_data["data"] = data

        print(json.dumps(output_data))

    def _is_odoo_log_line(self, message: str) -> bool:
        """Check if a message looks like an Odoo log line."""
        import re

        # Odoo log pattern: YYYY-MM-DD HH:MM:SS,mmm PID LEVEL db_name module: message
        odoo_log_pattern = re.compile(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} \d+ "
            r"(INFO|WARNING|ERROR|DEBUG) \w+ [\w\.]+: "
        )
        return bool(odoo_log_pattern.match(message))

    def _parse_odoo_log_line(self, log_line: str) -> dict[str, Any] | None:
        """Parse an Odoo log line into structured JSON."""
        import re

        # Updated pattern to match the actual Odoo log format
        # Example: 2025-08-21 09:07:24,574 65551 INFO test_db_17_common2
        # odoo.service.server: Starting post tests
        pattern = re.compile(
            r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}),(?P<ms>\d{3}) "
            r"(?P<pid>\d+) (?P<level>\w+) (?P<database>\w+) "
            r"(?P<module>[\w\.]+): (?P<message>.*)"
        )

        match = pattern.match(log_line.strip())
        if not match:
            return None

        # Extract all fields
        level = match.group("level").lower()
        message = match.group("message").strip()
        timestamp = (
            f"{match.group('date')}T{match.group('time')}.{match.group('ms')}000"
        )
        process_id = int(match.group("pid"))
        database = match.group("database")
        module = match.group("module")

        # Full set of fields
        current_fields = {
            "source": "odoo",
            "level": level,
            "timestamp": timestamp,
            "process_id": process_id,
            "database": database,
            "module": module,
            "message": message,
        }

        # Build result with only changed fields (always include message and level)
        result = {
            "level": level,
            "message": message,
        }

        # Check each field against previous values and include if changed
        for field, value in current_fields.items():
            if field in ["level", "message"]:
                # Always include these essential fields
                continue

            # Include field if different from previous value or first time seeing it
            if (
                field not in self._previous_fields
                or self._previous_fields[field] != value
            ):
                result[field] = value
                self._previous_fields[field] = value

        return result

    def _output_text(self, message: str, level: str) -> None:
        """Output in text format."""
        if self.non_interactive:
            # Simple text output without colors for non-interactive mode
            prefix = f"[{level.upper()}]"
            print(f"{prefix} {message}")
        else:
            # Colored output for interactive mode
            if level == "info":
                print("\033[34m[INFO]\033[0m " + message)
            elif level == "success":
                print("\033[32m[OK]\033[0m " + message)
            elif level == "warning":
                print("\033[33m[WARN]\033[0m " + message)
            elif level == "error":
                print("\033[31m[ERROR]\033[0m " + message)
            else:
                print(message)

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime

        return datetime.now().isoformat()

    def _is_coverage_report_line(self, message: str) -> bool:
        """Check if a message looks like a coverage report line."""
        import re

        # Coverage report pattern: file_path statements missing coverage% missing_lines
        # Example: "mail_mail_helper.py 58 3 95% 74, 107, 120"
        coverage_pattern = re.compile(
            r"^[\w\-/\.]+\.py\s+\d+\s+\d+\s+\d+%(?:\s+[\d,\-\s]+)?$"
        )
        return bool(coverage_pattern.match(message.strip()))

    def _parse_coverage_report_line(self, line: str) -> dict[str, Any] | None:
        """Parse a coverage report line into structured JSON."""
        import re

        # Pattern to match coverage report lines
        # Example: "mail_mail_helper.py 58 3 95% 74, 107, 120"
        pattern = re.compile(
            r"^(?P<file_path>[\w\-/\.]+\.py)\s+"
            r"(?P<statements>\d+)\s+"
            r"(?P<missing>\d+)\s+"
            r"(?P<coverage>\d+)%"
            r"(?:\s+(?P<missing_lines>[\d,\-\s]+))?$"
        )

        match = pattern.match(line.strip())
        if not match:
            return None

        missing_lines: list[int] = []
        if match.group("missing_lines"):
            missing_lines_str = match.group("missing_lines").strip()
            if missing_lines_str:
                # Parse ranges like "22-67" and individual lines like "74, 107, 120"
                for part in missing_lines_str.split(","):
                    part = part.strip()
                    if "-" in part:
                        # Handle range like "22-67"
                        start, end = map(int, part.split("-"))
                        missing_lines.extend(range(start, end + 1))
                    else:
                        # Handle individual line
                        missing_lines.append(int(part))

        statements = int(match.group("statements"))
        missing = int(match.group("missing"))
        coverage_pct = int(match.group("coverage"))

        return {
            "source": "coverage",
            "type": "file_coverage",
            "file_path": match.group("file_path"),
            "statements": statements,
            "missing": missing,
            "covered": statements - missing,
            "coverage_percentage": coverage_pct,
            "missing_lines": sorted(missing_lines) if missing_lines else [],
            "timestamp": self._get_timestamp(),
        }

    def print_result(
        self, data: dict[str, Any], message: str = "Operation completed"
    ) -> None:
        """Print operation result with data."""
        if self.format_type == "json":
            # Apply log parsing to the message if needed
            if self._is_odoo_log_line(message):
                parsed_log = self._parse_odoo_log_line(message)
                if parsed_log:
                    result1: dict[str, Any] = {
                        "type": "result",
                        "status": "success",
                        "result": data,
                        "timestamp": self._get_timestamp(),
                        **parsed_log,
                    }
                    print(json.dumps(result1))
                    return

            result2: dict[str, Any] = {
                "type": "result",
                "status": "success",
                "message": message,
                "result": data,
                "timestamp": self._get_timestamp(),
            }
            print(json.dumps(result2))
        else:
            self.output(message, "success")
            if data and not self.non_interactive:
                for key, value in data.items():
                    self.output(f"{key}: {value}", "info")

    def print_error_result(self, error_msg: str, error_code: int = 1) -> None:
        """Print error result and exit with code."""
        if self.format_type == "json":
            # Apply log parsing to the error message if needed
            if self._is_odoo_log_line(error_msg):
                parsed_log = self._parse_odoo_log_line(error_msg)
                if parsed_log:
                    result3: dict[str, Any] = {
                        "type": "error",
                        "status": "error",
                        "error_code": error_code,
                        "timestamp": self._get_timestamp(),
                        **parsed_log,
                    }
                    print(json.dumps(result3))
                    sys.exit(error_code)

            result4: dict[str, Any] = {
                "type": "error",
                "status": "error",
                "message": error_msg,
                "error_code": error_code,
                "timestamp": self._get_timestamp(),
            }
            print(json.dumps(result4))
        else:
            self.output(error_msg, "error")

        sys.exit(error_code)


# Global formatter instance - will be configured by CLI
_formatter = OutputFormatter()


def configure_output(format_type: str = "text", non_interactive: bool = False) -> None:
    """Configure the global output formatter."""
    global _formatter
    _formatter = OutputFormatter(format_type, non_interactive)


def print_info(msg: str, data: dict[str, Any] | None = None) -> None:
    _formatter.output(msg, "info", data)


def print_success(msg: str, data: dict[str, Any] | None = None) -> None:
    _formatter.output(msg, "success", data)


def print_warning(msg: str, data: dict[str, Any] | None = None) -> None:
    _formatter.output(msg, "warning", data)


def print_error(msg: str, data: dict[str, Any] | None = None) -> None:
    _formatter.output(msg, "error", data)


def print_result(data: dict[str, Any], message: str = "Operation completed") -> None:
    """Print operation result with data."""
    _formatter.print_result(data, message)


def print_error_result(error_msg: str, error_code: int = 1) -> None:
    """Print error result and exit with code."""
    _formatter.print_error_result(error_msg, error_code)
