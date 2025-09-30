# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import unittest
from unittest.mock import patch

from oduit.output import print_error, print_info, print_success, print_warning


class TestOutput(unittest.TestCase):
    @patch("builtins.print")
    def test_print_info(self, mock_print):
        """Test print_info function."""
        print_info("Test info message")
        mock_print.assert_called_once_with("\033[34m[INFO]\033[0m Test info message")

    @patch("builtins.print")
    def test_print_success(self, mock_print):
        """Test print_success function."""
        print_success("Test success message")
        mock_print.assert_called_once_with("\033[32m[OK]\033[0m Test success message")

    @patch("builtins.print")
    def test_print_warning(self, mock_print):
        """Test print_warning function."""
        print_warning("Test warning message")
        mock_print.assert_called_once_with("\033[33m[WARN]\033[0m Test warning message")

    @patch("builtins.print")
    def test_print_error(self, mock_print):
        """Test print_error function."""
        print_error("Test error message")
        mock_print.assert_called_once_with("\033[31m[ERROR]\033[0m Test error message")


if __name__ == "__main__":
    unittest.main()
