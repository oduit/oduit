# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

from unittest.mock import patch

import pytest

from oduit.builders import (
    BaseOdooCommandBuilder,
    ConfigProvider,
    DatabaseCommandBuilder,
    InstallCommandBuilder,
    LanguageCommandBuilder,
    OdooTestCommandBuilder,
    OdooTestCoverageCommandBuilder,
    RunCommandBuilder,
    ShellCommandBuilder,
    UpdateCommandBuilder,
)
from oduit.exceptions import ConfigError


@pytest.fixture
def sample_config():
    """Sample configuration for testing"""
    return {
        "python_bin": "/usr/bin/python3",
        "odoo_bin": "/opt/odoo/odoo-bin",
        "db_name": "test_db",
        "addons_path": "/opt/odoo/addons,/opt/custom/addons",
        "log_level": "info",
        "db_user": "odoo",
        "db_password": "password",
        "http_port": 8069,
        "data_dir": "/opt/odoo/data",
        "coverage_bin": "/usr/bin/coverage",
    }


@pytest.fixture
def config_provider(sample_config):
    """ConfigProvider instance for testing"""
    return ConfigProvider(sample_config)


class TestConfigProvider:
    """Tests for ConfigProvider"""

    def test_get_required_existing_key(self, config_provider):
        """Test getting a required key that exists"""
        assert config_provider.get_required("python_bin") == "/usr/bin/python3"

    def test_get_required_missing_key(self, config_provider):
        """Test getting a required key that doesn't exist"""
        with pytest.raises(
            ConfigError, match="Missing required configuration: missing_key"
        ):
            config_provider.get_required("missing_key")

    def test_get_optional_existing_key(self, config_provider):
        """Test getting an optional key that exists"""
        assert config_provider.get_optional("log_level") == "info"

    def test_get_optional_missing_key(self, config_provider):
        """Test getting an optional key that doesn't exist"""
        assert config_provider.get_optional("missing_key") is None
        assert config_provider.get_optional("missing_key", "default") == "default"

    def test_validate_keys_all_present(self, config_provider):
        """Test validation when all required keys are present"""
        config_provider.validate_keys(["python_bin", "odoo_bin"], "test command")

    def test_validate_keys_missing(self, config_provider):
        """Test validation when required keys are missing"""
        with pytest.raises(
            ConfigError,
            match="Missing required configuration for test command: missing_key",
        ):
            config_provider.validate_keys(["python_bin", "missing_key"], "test command")


class TestBaseOdooCommandBuilder:
    """Tests for BaseOdooCommandBuilder"""

    def test_basic_command_structure(self, config_provider):
        """Test basic command structure is built correctly"""
        builder = BaseOdooCommandBuilder(config_provider)
        builder._setup_base_command()
        builder._apply_full_config()
        cmd = builder.build()

        assert cmd[0] == "/usr/bin/python3"
        assert cmd[1] == "/opt/odoo/odoo-bin"
        assert "--database=test_db" in cmd
        assert "--addons-path=/opt/odoo/addons,/opt/custom/addons" in cmd

    def test_expand_addons_path_relative(self, config_provider):
        """Test expansion of relative paths in addons_path"""
        builder = BaseOdooCommandBuilder(config_provider)
        result = builder._expand_addons_path("./addons,.\\custom,/absolute/path")

        assert not result.startswith("./")
        assert not result.startswith(".\\")
        assert "/absolute/path" in result
        paths = result.split(",")
        assert len(paths) == 3
        for path in paths[:2]:
            assert not path.startswith("./")
            assert not path.startswith(".\\")

    def test_expand_addons_path_absolute_only(self, config_provider):
        """Test expansion with only absolute paths"""
        builder = BaseOdooCommandBuilder(config_provider)
        result = builder._expand_addons_path("/opt/odoo/addons,/opt/custom/addons")

        assert result == "/opt/odoo/addons,/opt/custom/addons"

    def test_expand_addons_path_single_relative(self, config_provider):
        """Test expansion with single relative path"""
        import os

        builder = BaseOdooCommandBuilder(config_provider)
        result = builder._expand_addons_path("./addons")

        assert not result.startswith("./")
        assert os.path.isabs(result)

    def test_apply_default_config_expands_paths(self, sample_config):
        """Test that _apply_default_config expands relative paths"""
        config = sample_config.copy()
        config["addons_path"] = "./addons,./custom"
        provider = ConfigProvider(config)

        builder = BaseOdooCommandBuilder(provider)
        builder._setup_base_command()
        builder._apply_default_config()
        cmd = builder.build()

        addons_path_param = [part for part in cmd if part.startswith("--addons-path=")][
            0
        ]
        assert "./addons" not in addons_path_param
        assert "./custom" not in addons_path_param

    def test_fluent_interface(self, config_provider):
        """Test fluent interface works correctly"""
        builder = BaseOdooCommandBuilder(config_provider)
        result = builder.database("new_db").log_level("debug").no_http(True)

        assert result is builder
        cmd = builder.build()
        assert "--database=new_db" in cmd
        assert "--log-level=debug" in cmd
        assert "--no-http" in cmd

    def test_parameter_replacement(self, config_provider):
        """Test that parameters are replaced correctly"""
        builder = BaseOdooCommandBuilder(config_provider)
        builder.database("first_db")
        builder.database("second_db")
        cmd = builder.build()

        # Should only have second_db, not first_db
        assert "--database=second_db" in cmd
        assert "--database=first_db" not in cmd

    def test_flag_toggle(self, config_provider):
        """Test flag can be toggled on and off"""
        builder = BaseOdooCommandBuilder(config_provider)
        builder.no_http(True)
        cmd = builder.build()
        assert "--no-http" in cmd

        builder.no_http(False)
        cmd = builder.build()
        assert "--no-http" not in cmd

    def test_reset_functionality(self, config_provider):
        """Test reset restores builder to initial state"""
        builder = BaseOdooCommandBuilder(config_provider)
        builder.database("custom_db").dev("xml").no_http(True)

        builder.reset()
        builder._apply_full_config()
        cmd = builder.build()

        # Should be back to default config
        assert "--database=test_db" in cmd
        assert "--dev=xml" not in cmd
        assert "--no-http" not in cmd


class TestRunCommandBuilder:
    """Tests for RunCommandBuilder"""

    def test_development_configuration(self, config_provider):
        """Test development configuration"""
        builder = RunCommandBuilder(config_provider)
        builder.dev("all")
        builder.log_level("warn")
        cmd = builder.build()

        assert "--dev=all" in cmd
        assert "--log-level=warn" in cmd

    def test_development_without_compact(self, config_provider):
        """Test development configuration without compact mode"""
        builder = RunCommandBuilder(config_provider)
        builder.dev("all")
        cmd = builder.build()

        assert "--dev=all" in cmd
        assert "--log-level=warn" not in cmd


class TestOdooTestCommandBuilder:
    """Tests for OdooTestCommandBuilder"""

    def test_basic_test_command(self, config_provider):
        """Test basic test command structure"""
        builder = OdooTestCommandBuilder(config_provider)
        cmd = builder.build()

        assert "--stop-after-init" in cmd
        assert "--test-enable" in cmd

    def test_test_module_install(self, config_provider):
        """Test module testing with install"""
        builder = OdooTestCommandBuilder(config_provider)
        builder.test_module("sale", install=True)
        cmd = builder.build()

        assert "-i" in cmd
        assert "sale" in cmd
        assert "--test-tags" in cmd
        assert "/sale" in cmd

    def test_test_module_update(self, config_provider):
        """Test module testing with update"""
        builder = OdooTestCommandBuilder(config_provider)
        builder.test_module("sale", install=False)
        cmd = builder.build()

        assert "-u" in cmd
        assert "sale" in cmd

    def test_test_file(self, config_provider):
        """Test specific test file"""
        builder = OdooTestCommandBuilder(config_provider)
        builder.test_file("test_specific.py")
        cmd = builder.build()

        assert "--test-file" in cmd
        assert "test_specific.py" in cmd

    @patch("oduit.module_manager.ModuleManager.find_module_path")
    def test_with_coverage(self, mock_find_module_path, config_provider):
        """Test coverage configuration"""
        mock_find_module_path.return_value = "/opt/custom/addons/sale"

        builder = OdooTestCoverageCommandBuilder(config_provider, "sale")
        cmd = builder.build()

        assert cmd[0] == "/usr/bin/coverage"
        assert cmd[1] == "run"
        assert "--source=/opt/custom/addons/sale" in cmd


class TestShellCommandBuilder:
    """Tests for ShellCommandBuilder"""

    def test_shell_command_structure(self, config_provider):
        """Test shell command structure"""
        builder = ShellCommandBuilder(config_provider)
        cmd = builder.build()

        assert "shell" in cmd
        assert "--no-http" in cmd

    def test_shell_interface(self, config_provider):
        """Test shell interface configuration"""
        builder = ShellCommandBuilder(config_provider)
        builder.shell_interface("ipython")
        cmd = builder.build()

        assert "--shell-interface=ipython" in cmd


class TestUpdateCommandBuilder:
    """Tests for UpdateCommandBuilder"""

    def test_update_command_structure(self, config_provider):
        """Test update command structure"""
        builder = UpdateCommandBuilder(config_provider, "sale")
        cmd = builder.build()

        assert "-u" in cmd
        assert "sale" in cmd


class TestInstallCommandBuilder:
    """Tests for InstallCommandBuilder"""

    def test_install_command_structure(self, config_provider):
        """Test install command structure"""
        builder = InstallCommandBuilder(config_provider, "sale")
        cmd = builder.build()

        assert "-i" in cmd
        assert "sale" in cmd


class TestLanguageCommandBuilder:
    """Tests for LanguageCommandBuilder"""

    def test_language_command_structure(self, config_provider):
        """Test language command structure"""
        builder = LanguageCommandBuilder(config_provider, "sale", "sale_fr.po", "fr_FR")
        cmd = builder.build()

        assert "--modules=sale" in cmd
        assert "--i18n-export=sale_fr.po" in cmd
        assert any("--language=" in part for part in cmd)
        assert any("fr_FR" in part for part in cmd)
        assert "--no-http" in cmd


class TestDatabaseCommandBuilder:
    """Tests for DatabaseCommandBuilder"""

    def test_drop_command(self, config_provider):
        """Test database drop command"""
        builder = DatabaseCommandBuilder(config_provider)
        cmd = builder.drop_command().build()

        assert cmd == [
            "sudo",
            "-S",
            "su",
            "-",
            "postgres",
            "-c",
            'dropdb --if-exists "test_db"',
        ]

    def test_create_command_with_user(self, config_provider):
        """Test database create command with user"""
        builder = DatabaseCommandBuilder(config_provider)
        cmd = builder.create_command().build()

        assert cmd == [
            "sudo",
            "-S",
            "su",
            "-",
            "postgres",
            "-c",
            'createdb -O "odoo" "test_db"',
        ]

    def test_create_command_without_user(self, config_provider):
        """Test database create command without user"""
        config = config_provider.get_full_config().copy()
        del config["db_user"]
        provider = ConfigProvider(config)

        builder = DatabaseCommandBuilder(provider)
        cmd = builder.create_command().build()

        assert cmd == ["sudo", "-S", "su", "-", "postgres", "-c", 'createdb "test_db"']

    def test_list_db_command_with_sudo(self, config_provider):
        """Test database list command with sudo"""
        builder = DatabaseCommandBuilder(config_provider)
        cmd = builder.list_db_command().build()

        assert cmd == ["sudo", "-S", "su", "-", "postgres", "-c", 'psql -l -U "odoo"']

    def test_list_db_command_with_sudo_and_user(self, config_provider):
        """Test database list command with sudo and db_user"""
        builder = DatabaseCommandBuilder(config_provider)
        cmd = builder.list_db_command(db_user="custom_user").build()

        assert cmd == [
            "sudo",
            "-S",
            "su",
            "-",
            "postgres",
            "-c",
            'psql -l -U "custom_user"',
        ]

    def test_list_db_command_without_sudo(self, config_provider):
        """Test database list command without sudo"""
        builder = DatabaseCommandBuilder(config_provider, with_sudo=False)
        cmd = builder.list_db_command().build()

        assert cmd == ["psql", "-l", "-U", "odoo"]

    def test_list_db_command_without_sudo_with_user(self, config_provider):
        """Test database list command without sudo but with db_user"""
        builder = DatabaseCommandBuilder(config_provider, with_sudo=False)
        cmd = builder.list_db_command(db_user="custom_user").build()

        assert cmd == ["psql", "-l", "-U", "custom_user"]
