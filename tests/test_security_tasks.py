import json
import stat
import sys
import types
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from oduit.api_models import AddonInstallState, InstalledAddonInventory
from oduit.cli.app import app
from oduit.odoo_code_executor import OdooCodeExecutor
from oduit.odoo_operations import OdooOperations
from oduit.process_manager import ProcessManager


class TestSec1ShellExecution(unittest.TestCase):
    def test_execute_python_code_uses_stdin_with_list_command(self) -> None:
        config = {
            "odoo_bin": "odoo-bin",
            "db_name": "test_db",
            "addons_path": "./addons",
            "shell_interface": "python",
        }
        ops = OdooOperations(config)
        payload = 'print("x")\nprint("$(uname); `id`; ;")'

        with patch.object(ops.process_manager, "run_shell_command") as mock_shell:
            mock_shell.return_value = {
                "success": True,
                "return_code": 0,
                "stdout": "x\n",
                "stderr": "",
            }

            result = ops.execute_python_code(
                python_code=payload,
                capture_output=True,
                suppress_output=True,
                shell_interface="python",
            )

        self.assertTrue(result["success"])
        called_command = mock_shell.call_args.args[0]
        self.assertIsInstance(called_command, list)
        self.assertEqual(mock_shell.call_args.kwargs["input_data"], f"{payload}\n")
        self.assertNotIn("full_command", result)

    @patch("oduit.process_manager.subprocess.Popen")
    def test_string_shell_command_requires_opt_in(self, mock_popen: MagicMock) -> None:
        pm = ProcessManager()
        result = pm.run_shell_command("echo test", capture_output=True)

        self.assertFalse(result["success"])
        self.assertIn("allow_shell=True", result["error"])
        mock_popen.assert_not_called()


class TestSec2SudoHandling(unittest.TestCase):
    def test_spawn_process_with_optional_sudo_uses_stdin_password(self) -> None:
        pm = ProcessManager()
        fake_process = MagicMock()

        with (
            patch.object(pm, "_get_sudo_password", return_value="secret") as mock_get,
            patch.object(
                pm, "_create_subprocess", return_value=fake_process
            ) as mock_create,
        ):
            process, stdin_data = pm._spawn_process_with_optional_sudo(
                ["sudo", "-S", "whoami"]
            )

        self.assertIs(process, fake_process)
        self.assertEqual(stdin_data, "secret\n")
        mock_get.assert_called_once_with()
        mock_create.assert_called_once_with(["sudo", "-S", "whoami"], stdin_pipe=True)

    def test_run_command_writes_password_to_stdin(self) -> None:
        pm = ProcessManager()
        process = MagicMock()
        process.stdin = MagicMock()
        process.returncode = 0

        with (
            patch.object(
                pm,
                "_spawn_process_with_optional_sudo",
                return_value=(process, "secret\n"),
            ),
            patch.object(pm, "_stream_output_and_maybe_abort", return_value=[]),
        ):
            result = pm.run_command(["sudo", "-S", "true"], suppress_output=True)

        self.assertTrue(result["success"])
        process.stdin.write.assert_called_once_with("secret\n")
        process.stdin.flush.assert_called_once_with()
        process.stdin.close.assert_called_once_with()

    def test_clear_sudo_password(self) -> None:
        pm = ProcessManager()
        pm._sudo_password = "secret"
        pm.clear_sudo_password()
        self.assertIsNone(pm._sudo_password)


class TestSec3TrustedExecution(unittest.TestCase):
    def test_execute_code_requires_allow_unsafe(self) -> None:
        executor = OdooCodeExecutor(MagicMock())
        result = executor.execute_code("1 + 1")

        self.assertFalse(result["success"])
        self.assertIn("allow_unsafe", result["error"])

    def test_execute_multiple_requires_allow_unsafe(self) -> None:
        executor = OdooCodeExecutor(MagicMock())
        result = executor.execute_multiple(["1 + 1"])

        self.assertFalse(result["success"])
        self.assertIn("allow_unsafe", result["error"])

    @unittest.skipIf(sys.platform == "win32", "SIGALRM timeout test is Unix-only")
    def test_execute_trusted_times_out(self) -> None:
        executor = OdooCodeExecutor(MagicMock())
        result = executor._execute_trusted("while True: pass", {}, 0.1)

        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"].lower())

    def test_execute_with_database_rolls_back_on_failure(self) -> None:
        executor = OdooCodeExecutor(MagicMock())
        cursor = MagicMock()

        class FakeCursorContext:
            def __enter__(self) -> MagicMock:
                return cursor

            def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
                return False

        class FakeRegistry:
            def cursor(self) -> FakeCursorContext:
                return FakeCursorContext()

        class FakeEnvironment:
            def __getitem__(self, item: str) -> Any:
                return types.SimpleNamespace(context_get=lambda: {})

        odoo_stub = types.SimpleNamespace(
            SUPERUSER_ID=1,
            registry=lambda db_name: FakeRegistry(),
            api=types.SimpleNamespace(
                Environment=lambda cr, uid, ctx: FakeEnvironment()
            ),
        )

        with (
            patch.dict(sys.modules, {"odoo": odoo_stub}),
            patch.object(
                executor,
                "_execute_trusted",
                return_value={
                    "success": False,
                    "value": None,
                    "output": "",
                    "error": "Execution timed out",
                    "traceback": "",
                },
            ),
        ):
            result = executor._execute_with_database(
                "while True: pass",
                "test_db",
                commit=True,
                timeout=0.1,
            )

        self.assertFalse(result["success"])
        cursor.rollback.assert_called_once_with()
        cursor.commit.assert_not_called()


class TestSec4AgentBoundaries(unittest.TestCase):
    def _make_executable(self, path: Path) -> str:
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)

    def _agent_config(self, tmp_path: Path, addons_path: str) -> dict[str, str]:
        return {
            "python_bin": self._make_executable(tmp_path / "python3"),
            "odoo_bin": self._make_executable(tmp_path / "odoo-bin"),
            "coverage_bin": self._make_executable(tmp_path / "coverage"),
            "addons_path": addons_path,
            "db_name": "test_db",
            "db_host": "localhost",
            "db_user": "odoo",
        }

    def _loader_with_config(self, config: dict[str, str], tmp_path: Path) -> MagicMock:
        loader = MagicMock()
        loader.load_config.return_value = config
        loader.resolve_config_path.return_value = (str(tmp_path / "dev.toml"), "toml")
        return loader

    def _make_addon(
        self,
        addons_dir: Path,
        module_name: str,
        depends: list[str] | None = None,
    ) -> Path:
        module_dir = addons_dir / module_name
        module_dir.mkdir(parents=True)
        (module_dir / "__manifest__.py").write_text(
            str(
                {
                    "name": module_name,
                    "version": "17.0.1.0.0",
                    "depends": depends or ["base"],
                }
            )
        )
        return module_dir

    def test_agent_mutation_requires_allow_mutation(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            tmp_path = Path.cwd()
            addons_dir = tmp_path / "addons"
            addons_dir.mkdir()
            self._make_addon(addons_dir, "base", depends=[])
            self._make_addon(addons_dir, "sale")
            config = self._agent_config(tmp_path, str(addons_dir))
            loader = self._loader_with_config(config, tmp_path)

            with patch("oduit.cli.app.ConfigLoader", return_value=loader):
                result = runner.invoke(
                    app,
                    ["--env", "dev", "agent", "update-module", "sale"],
                )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["error_type"], "ConfirmationRequired")
        self.assertFalse(payload["read_only"])
        self.assertEqual(payload["safety_level"], "controlled_runtime_mutation")

    def test_agent_test_summary_requires_allow_mutation(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            tmp_path = Path.cwd()
            addons_dir = tmp_path / "addons"
            addons_dir.mkdir()
            self._make_addon(addons_dir, "base", depends=[])
            self._make_addon(addons_dir, "sale")
            config = self._agent_config(tmp_path, str(addons_dir))
            loader = self._loader_with_config(config, tmp_path)

            with patch("oduit.cli.app.ConfigLoader", return_value=loader):
                result = runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "test-summary",
                        "--module",
                        "sale",
                    ],
                )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["error_type"], "ConfirmationRequired")
        self.assertFalse(payload["read_only"])
        self.assertEqual(payload["safety_level"], "controlled_runtime_mutation")

    def test_agent_runtime_mutation_is_auto_allowed_on_test_db(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            tmp_path = Path.cwd()
            addons_dir = tmp_path / "addons"
            addons_dir.mkdir()
            self._make_addon(addons_dir, "base", depends=[])
            self._make_addon(addons_dir, "sale")
            config = self._agent_config(tmp_path, str(addons_dir))
            config["db_risk_level"] = "test"
            loader = self._loader_with_config(config, tmp_path)

            with (
                patch("oduit.cli.app.ConfigLoader", return_value=loader),
                patch.object(
                    OdooOperations,
                    "update_module",
                    return_value={"success": True, "operation": "update_module"},
                ) as mock_update,
            ):
                result = runner.invoke(
                    app,
                    ["--env", "dev", "agent", "update-module", "sale"],
                )

        self.assertEqual(result.exit_code, 0)
        mock_update.assert_called_once()

    def test_agent_runtime_mutation_is_blocked_on_prod_even_with_flag(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            tmp_path = Path.cwd()
            addons_dir = tmp_path / "addons"
            addons_dir.mkdir()
            self._make_addon(addons_dir, "base", depends=[])
            self._make_addon(addons_dir, "sale")
            config = self._agent_config(tmp_path, str(addons_dir))
            config["db_risk_level"] = "prod"
            loader = self._loader_with_config(config, tmp_path)

            with patch("oduit.cli.app.ConfigLoader", return_value=loader):
                result = runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "update-module",
                        "sale",
                        "--allow-mutation",
                    ],
                )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["error_type"], "MutationForbidden")
        self.assertEqual(payload["safety_level"], "controlled_runtime_mutation")

    def test_agent_plan_update_stays_read_only_on_prod(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            tmp_path = Path.cwd()
            addons_dir = tmp_path / "addons"
            addons_dir.mkdir()
            self._make_addon(addons_dir, "base", depends=[])
            self._make_addon(addons_dir, "sale")
            config = self._agent_config(tmp_path, str(addons_dir))
            config["db_risk_level"] = "prod"
            loader = self._loader_with_config(config, tmp_path)

            with patch("oduit.cli.app.ConfigLoader", return_value=loader):
                result = runner.invoke(
                    app,
                    ["--env", "dev", "agent", "plan-update", "sale"],
                )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assertTrue(payload["read_only"])
        self.assertEqual(payload["db_risk_level"], "prod")
        self.assertFalse(payload["runtime_mutation_allowed"])

    def test_agent_create_addon_still_requires_allow_mutation_on_test_db(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            tmp_path = Path.cwd()
            addons_dir = tmp_path / "addons"
            addons_dir.mkdir()
            self._make_addon(addons_dir, "base", depends=[])
            config = self._agent_config(tmp_path, str(addons_dir))
            config["db_risk_level"] = "test"
            loader = self._loader_with_config(config, tmp_path)

            with patch("oduit.cli.app.ConfigLoader", return_value=loader):
                result = runner.invoke(
                    app,
                    ["--env", "dev", "agent", "create-addon", "x_new"],
                )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["error_type"], "ConfirmationRequired")
        self.assertEqual(payload["safety_level"], "controlled_source_mutation")

    def test_agent_create_addon_requires_allow_mutation_as_source_mutation(
        self,
    ) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            tmp_path = Path.cwd()
            addons_dir = tmp_path / "addons"
            addons_dir.mkdir()
            self._make_addon(addons_dir, "base", depends=[])
            config = self._agent_config(tmp_path, str(addons_dir))
            loader = self._loader_with_config(config, tmp_path)

            with patch("oduit.cli.app.ConfigLoader", return_value=loader):
                result = runner.invoke(
                    app,
                    ["--env", "dev", "agent", "create-addon", "x_new"],
                )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["error_type"], "ConfirmationRequired")
        self.assertFalse(payload["read_only"])
        self.assertEqual(payload["safety_level"], "controlled_source_mutation")

    def test_agent_validate_addon_change_requires_allow_mutation(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            tmp_path = Path.cwd()
            addons_dir = tmp_path / "addons"
            addons_dir.mkdir()
            self._make_addon(addons_dir, "base", depends=[])
            self._make_addon(addons_dir, "sale")
            config = self._agent_config(tmp_path, str(addons_dir))
            loader = self._loader_with_config(config, tmp_path)

            with patch("oduit.cli.app.ConfigLoader", return_value=loader):
                result = runner.invoke(
                    app,
                    ["--env", "dev", "agent", "validate-addon-change", "sale"],
                )

        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertEqual(payload["error_type"], "ConfirmationRequired")
        self.assertFalse(payload["read_only"])
        self.assertEqual(payload["safety_level"], "controlled_runtime_mutation")

    def test_agent_locate_model_does_not_use_runtime_execution(self) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem():
            tmp_path = Path.cwd()
            addons_dir = tmp_path / "addons"
            addons_dir.mkdir()
            self._make_addon(addons_dir, "base", depends=[])
            addon_dir = self._make_addon(addons_dir, "my_partner")
            (addon_dir / "models").mkdir()
            (addon_dir / "models" / "res_partner.py").write_text(
                "from odoo import fields, models\n\n"
                "class ResPartner(models.Model):\n"
                "    _inherit = 'res.partner'\n"
                "    email3 = fields.Char()\n"
            )
            config = self._agent_config(tmp_path, str(addons_dir))
            loader = self._loader_with_config(config, tmp_path)

            with (
                patch("oduit.cli.app.ConfigLoader", return_value=loader),
                patch.object(
                    OdooOperations,
                    "execute_python_code",
                    side_effect=AssertionError("runtime execution should not be used"),
                ),
            ):
                result = runner.invoke(
                    app,
                    [
                        "--env",
                        "dev",
                        "agent",
                        "locate-model",
                        "res.partner",
                        "--module",
                        "my_partner",
                    ],
                )

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.output)
        self.assertEqual(payload["type"], "model_source_location")

    def test_uninstall_module_uses_trusted_executor_not_shell_code(self) -> None:
        ops = OdooOperations(
            {
                "addons_path": "./addons",
                "db_name": "test_db",
                "allow_uninstall": True,
            }
        )

        with (
            patch.object(
                ops,
                "execute_python_code",
                side_effect=AssertionError("shell execution should not be used"),
            ),
            patch.object(
                ops,
                "get_addon_install_state",
                return_value=AddonInstallState(
                    success=True,
                    operation="get_addon_install_state",
                    module="sale",
                    record_found=True,
                    state="installed",
                    installed=True,
                    database="test_db",
                ),
            ),
            patch.object(
                ops,
                "list_installed_dependents",
                return_value=InstalledAddonInventory(
                    success=True,
                    operation="list_installed_dependents",
                ),
            ),
            patch("oduit.odoo_operations.OdooCodeExecutor") as mock_executor_class,
        ):
            executor = MagicMock()
            executor._execute_generated_code.return_value = {
                "success": True,
                "value": {
                    "module": "sale",
                    "record_found": True,
                    "previous_state": "installed",
                    "final_state": "uninstalled",
                    "uninstalled": True,
                },
            }
            mock_executor_class.return_value = executor

            result = ops.uninstall_module("sale", allow_uninstall=True)

        self.assertTrue(result["success"])
