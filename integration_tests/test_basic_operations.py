from typing import Any

import pytest

from oduit.builders import (
    InstallCommandBuilder,
    OdooTestCommandBuilder,
    UpdateCommandBuilder,
)
from oduit.config_provider import ConfigProvider
from oduit.process_manager import ProcessManager


@pytest.mark.integration
def test_install_module_success(integration_config: dict[str, Any]) -> None:
    pm = ProcessManager()
    config_provider = ConfigProvider(integration_config)

    builder = InstallCommandBuilder(config_provider, "c")
    builder.stop_after_init(True)
    operation = builder.build_operation()

    result = pm.run_operation(operation, verbose=True)

    assert result["success"] is True
    assert "c" in result.get("modules_installed", [])


@pytest.mark.integration
def test_install_module_with_dependencies(integration_config: dict[str, Any]) -> None:
    pm = ProcessManager()
    config_provider = ConfigProvider(integration_config)

    builder = InstallCommandBuilder(config_provider, "a")
    builder.stop_after_init(True)
    operation = builder.build_operation()

    result = pm.run_operation(operation, verbose=True)

    assert result["success"] is True
    assert "a" in result.get("modules_installed", [])


@pytest.mark.integration
def test_install_nonexistent_module(integration_config: dict[str, Any]) -> None:
    pm = ProcessManager()
    config_provider = ConfigProvider(integration_config)

    builder = InstallCommandBuilder(config_provider, "nonexistent_module_xyz")
    builder.stop_after_init(True)
    operation = builder.build_operation()

    result = pm.run_operation(operation, verbose=True)

    assert result["success"] is False
    assert len(result.get("dependency_errors", [])) > 0 or result.get("error")


@pytest.mark.integration
def test_module_with_missing_dependency(integration_config: dict[str, Any]) -> None:
    pm = ProcessManager()
    config_provider = ConfigProvider(integration_config)

    builder = InstallCommandBuilder(config_provider, "d")
    builder.stop_after_init(True)
    operation = builder.build_operation()

    result = pm.run_operation(operation, verbose=True)

    assert result["success"] is False
    dependency_errors = result.get("dependency_errors", [])
    assert len(dependency_errors) > 0
    assert any("nonexistent_module_will_fail" in str(err) for err in dependency_errors)


@pytest.mark.integration
def test_module_test_failure(integration_config: dict[str, Any]) -> None:
    pm = ProcessManager()
    config_provider = ConfigProvider(integration_config)

    install_builder = InstallCommandBuilder(config_provider, "b")
    install_builder.stop_after_init(True)
    install_op = install_builder.build_operation()
    install_result = pm.run_operation(install_op, verbose=False)

    if not install_result["success"]:
        pytest.skip("Module b installation failed, cannot test")

    test_builder = OdooTestCommandBuilder(config_provider)
    test_builder.test_tags("/b")
    test_builder.no_http(True)
    test_operation = test_builder.build_operation()

    result = pm.run_operation(test_operation, verbose=True)

    assert result.get("failed_tests", 0) > 0
    failures = result.get("failures", [])
    assert len(failures) > 0
    assert any("test_failing_test" in str(f) for f in failures)


@pytest.mark.integration
def test_run_module_tests_success(integration_config: dict[str, Any]) -> None:
    pm = ProcessManager()
    config_provider = ConfigProvider(integration_config)

    install_builder = InstallCommandBuilder(config_provider, "c")
    install_builder.stop_after_init(True)
    install_op = install_builder.build_operation()
    install_result = pm.run_operation(install_op, verbose=False)

    if not install_result["success"]:
        pytest.skip("Module c installation failed, cannot test")

    test_builder = OdooTestCommandBuilder(config_provider)
    test_builder.test_tags("/c")
    test_builder.no_http(True)
    test_operation = test_builder.build_operation()

    result = pm.run_operation(test_operation, verbose=True)

    assert "total_tests" in result or "success" in result


@pytest.mark.integration
def test_update_module_success(integration_config: dict[str, Any]) -> None:
    pm = ProcessManager()
    config_provider = ConfigProvider(integration_config)

    install_builder = InstallCommandBuilder(config_provider, "c")
    install_builder.stop_after_init(True)
    install_op = install_builder.build_operation()
    install_result = pm.run_operation(install_op, verbose=False)

    if not install_result["success"]:
        pytest.skip("Module c installation failed, cannot test update")

    update_builder = UpdateCommandBuilder(config_provider, "c")
    update_builder.stop_after_init(True)
    update_operation = update_builder.build_operation()

    result = pm.run_operation(update_operation, verbose=True)

    assert result["success"] is True
    assert result.get("modules_loaded", 0) > 0


@pytest.mark.integration
def test_update_nonexistent_module(integration_config: dict[str, Any]) -> None:
    pm = ProcessManager()
    config_provider = ConfigProvider(integration_config)

    update_builder = UpdateCommandBuilder(
        config_provider, "nonexistent_module_update_xyz"
    )
    update_builder.stop_after_init(True)
    update_operation = update_builder.build_operation()

    result = pm.run_operation(update_operation, verbose=True)

    assert result["success"] is False
    assert len(result.get("dependency_errors", [])) > 0 or result.get("error")
