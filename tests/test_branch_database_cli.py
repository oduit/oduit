"""Focused classic CLI tests for branch database preparation."""

from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import typer

from oduit.branch_database import (
    BranchDatabaseResolution,
    apply_branch_database_resolution,
)
from oduit.cli.branch_database_support import prepare_branch_database
from oduit.cli.commands.branch_database import (
    branch_database_ensure_command,
    branch_database_gc_command,
    branch_database_status_command,
)
from oduit.cli_types import GlobalConfig, OutputFormat
from oduit.mutation_policy import require_cli_runtime_db_mutation


class _FakeOperations:
    def __init__(
        self,
        database: str,
        existing_databases: set[str],
        calls: list[tuple[str, Any]],
    ) -> None:
        self.database = database
        self.existing_databases = existing_databases
        self.calls = calls

    def db_exists(self, *, suppress_output: bool) -> dict[str, Any]:
        self.calls.append(("exists", self.database))
        return {"success": True, "exists": self.database in self.existing_databases}

    def duplicate_db(
        self,
        database: str,
        *,
        source_database: str,
        neutralize: bool,
        force: bool,
        suppress_output: bool,
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "duplicate",
                {
                    "database": database,
                    "source_database": source_database,
                    "neutralize": neutralize,
                    "force": force,
                },
            )
        )
        if database in self.existing_databases:
            return {"success": False, "error": "Database already exists"}
        self.existing_databases.add(database)
        return {"success": True}


class BranchDatabaseCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.base_config: dict[str, Any] = {
            "odoo_params": {"db_name": "project_dev"},
            "branch_db": {"enabled": True, "base_branch": "main"},
            "needs_mutation_flag": False,
        }
        self.resolution = BranchDatabaseResolution(
            enabled=True,
            branch="feature/task",
            base_branch="main",
            base_database="project_dev",
            database="project_dev_feature_task",
            is_base_branch=False,
            git_root=self.root,
            git_dir=self.root / ".git",
            common_dir=self.root / ".git",
        )
        self.global_config = self._global_config(self.resolution)
        self.databases = {"project_dev"}
        self.calls: list[tuple[str, Any]] = []
        self.errors: list[tuple[str, dict[str, Any]]] = []

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _global_config(self, resolution: BranchDatabaseResolution) -> GlobalConfig:
        return GlobalConfig(
            env_config=apply_branch_database_resolution(self.base_config, resolution),
            base_env_config=dict(self.base_config),
            branch_database=resolution,
            config_path=str(self.root / "oduit.toml"),
        )

    def _build_operations(self, config: GlobalConfig) -> _FakeOperations:
        assert config.env_config is not None
        database = config.env_config["odoo_params"]["db_name"]
        return _FakeOperations(database, self.databases, self.calls)

    def _print_error(
        self,
        _config: GlobalConfig,
        operation: str,
        message: str,
        **details: Any,
    ) -> None:
        self.errors.append((operation, {"message": message, **details}))

    @staticmethod
    def _confirmation_required(*_args: Any, **_kwargs: Any) -> None:
        raise typer.Exit(1)

    def _prepare(
        self,
        *,
        allow_mutation: bool = False,
        config: GlobalConfig | None = None,
    ) -> GlobalConfig:
        return prepare_branch_database(
            config or self.global_config,
            allow_mutation=allow_mutation,
            operation="run",
            action="Odoo server startup",
            build_odoo_operations_fn=self._build_operations,
            require_cli_runtime_db_mutation_fn=require_cli_runtime_db_mutation,
            confirmation_required_error_fn=self._confirmation_required,
            print_command_error_result_fn=self._print_error,
        )

    def test_disabled_branch_database_does_not_check_or_clone(self) -> None:
        disabled = replace(self.resolution, enabled=False)
        config = self._global_config(disabled)

        self.assertIs(self._prepare(config=config), config)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.errors, [])

    def test_existing_branch_database_is_reused_without_mutation_authorization(
        self,
    ) -> None:
        self.databases.add(self.resolution.database)
        self.base_config["needs_mutation_flag"] = True
        config = self._global_config(self.resolution)

        self.assertIs(self._prepare(config=config), config)
        self.assertNotIn("duplicate", [call[0] for call in self.calls])
        self.assertEqual(self.errors, [])

    def test_missing_branch_database_is_duplicated_and_registered(self) -> None:
        self._prepare()

        duplicate_calls = [value for kind, value in self.calls if kind == "duplicate"]
        self.assertEqual(
            duplicate_calls,
            [
                {
                    "database": self.resolution.database,
                    "source_database": "project_dev",
                    "neutralize": False,
                    "force": False,
                }
            ],
        )
        self.assertIn(self.resolution.database, self.databases)
        state_path = self.root / ".git" / "oduit" / "branch-databases.json"
        self.assertTrue(state_path.is_file())

    def test_missing_branch_database_honors_mutation_flag_policy(self) -> None:
        self.base_config["needs_mutation_flag"] = True
        config = self._global_config(self.resolution)

        with self.assertRaises(typer.Exit):
            self._prepare(config=config)

        self.assertNotIn(self.resolution.database, self.databases)
        self.assertNotIn("duplicate", [call[0] for call in self.calls])

        self._prepare(allow_mutation=True, config=config)
        self.assertIn(self.resolution.database, self.databases)

    def test_auto_create_disabled_reports_explicit_ensure_remediation(self) -> None:
        self.base_config["branch_db"]["auto_create"] = False
        config = self._global_config(self.resolution)

        with self.assertRaises(typer.Exit):
            self._prepare(config=config)

        self.assertEqual(
            self.errors[-1][1]["remediation"],
            ["Run `oduit branch-db ensure` to create it."],
        )
        self.assertNotIn("duplicate", [call[0] for call in self.calls])

    def test_missing_base_database_fails_without_clone_or_mutation_gate(self) -> None:
        base_resolution = replace(
            self.resolution,
            branch="main",
            database="project_dev",
            is_base_branch=True,
        )
        config = self._global_config(base_resolution)
        self.databases.clear()

        with self.assertRaises(typer.Exit):
            self._prepare(config=config)

        self.assertNotIn("duplicate", [call[0] for call in self.calls])
        self.assertIn("base database 'project_dev'", self.errors[-1][1]["message"])

    def test_missing_source_base_fails_before_mutation_authorization(self) -> None:
        self.base_config["needs_mutation_flag"] = True
        config = self._global_config(self.resolution)
        self.databases.clear()

        with self.assertRaises(typer.Exit):
            self._prepare(config=config)

        self.assertIn("base database 'project_dev'", self.errors[-1][1]["message"])
        self.assertNotIn("duplicate", [call[0] for call in self.calls])

    def test_status_command_only_checks_database_and_emits_structured_result(
        self,
    ) -> None:
        config = GlobalConfig(format=OutputFormat.JSON)
        manager = MagicMock()
        manager.status.return_value = {
            "success": True,
            "operation": "branch_db_status",
            "enabled": True,
            "branch": "feature",
            "base_branch": "main",
            "base_database": "project_dev",
            "database": "project_dev_feature",
            "is_base_branch": False,
            "exists": False,
            "managed": False,
            "clone_required": True,
        }
        output = StringIO()

        with redirect_stdout(output):
            branch_database_status_command(
                None,
                resolve_command_env_config_fn=lambda _ctx: (config, {}),
                build_branch_database_manager_fn=lambda _config: manager,
                print_command_error_result_fn=self._print_error,
            )

        self.assertEqual(json.loads(output.getvalue())["operation"], "branch_db_status")
        manager.status.assert_called_once_with()
        manager.ensure.assert_not_called()

    def test_ensure_command_forwards_mutation_confirmation_and_result(self) -> None:
        config = GlobalConfig(format=OutputFormat.JSON)
        ensure_fn = MagicMock(
            return_value={
                "success": True,
                "operation": "branch_db_ensure",
                "branch": "feature",
                "base_database": "project_dev",
                "database": "project_dev_feature",
                "created": False,
                "managed": False,
                "neutralized": False,
            }
        )
        output = StringIO()

        with redirect_stdout(output):
            branch_database_ensure_command(
                None,
                allow_mutation=True,
                resolve_command_env_config_fn=lambda _ctx: (config, {}),
                ensure_branch_database_fn=ensure_fn,
                print_command_error_result_fn=self._print_error,
            )

        ensure_fn.assert_called_once_with(
            config,
            allow_mutation=True,
            operation="branch_db_ensure",
            action="branch database creation",
        )
        self.assertFalse(json.loads(output.getvalue())["created"])

    def test_gc_defaults_to_dry_run_without_mutation_authorization(self) -> None:
        config = GlobalConfig(format=OutputFormat.JSON)
        manager = MagicMock()
        manager.gc_candidates.return_value = [{"branch": "old", "database": "old_db"}]
        manager.gc.return_value = {
            "success": True,
            "operation": "branch_db_gc",
            "dry_run": True,
            "candidates": [{"branch": "old", "database": "old_db"}],
            "deleted": [],
            "already_missing": [],
            "errors": [],
        }
        require_mutation = MagicMock()
        output = StringIO()

        with redirect_stdout(output):
            branch_database_gc_command(
                None,
                apply=False,
                allow_mutation=False,
                resolve_command_env_config_fn=lambda _ctx: (config, {}),
                build_branch_database_manager_fn=lambda _config: manager,
                require_cli_runtime_db_mutation_fn=require_mutation,
                confirmation_required_error_fn=self._confirmation_required,
                print_command_error_result_fn=self._print_error,
            )

        manager.gc.assert_called_once_with(apply=False)
        require_mutation.assert_not_called()
        self.assertTrue(json.loads(output.getvalue())["dry_run"])

    def test_gc_apply_with_no_candidates_does_not_require_mutation(self) -> None:
        config = GlobalConfig()
        manager = MagicMock()
        manager.gc_candidates.return_value = []
        manager.gc.return_value = {
            "success": True,
            "operation": "branch_db_gc",
            "dry_run": False,
            "candidates": [],
            "deleted": [],
            "already_missing": [],
            "errors": [],
        }
        require_mutation = MagicMock()
        output = StringIO()

        with redirect_stdout(output):
            branch_database_gc_command(
                None,
                apply=True,
                allow_mutation=False,
                resolve_command_env_config_fn=lambda _ctx: (config, {}),
                build_branch_database_manager_fn=lambda _config: manager,
                require_cli_runtime_db_mutation_fn=require_mutation,
                confirmation_required_error_fn=self._confirmation_required,
                print_command_error_result_fn=self._print_error,
            )

        manager.gc.assert_called_once_with(apply=True)
        require_mutation.assert_not_called()

    def test_gc_apply_requires_mutation_policy_for_candidates(self) -> None:
        config = GlobalConfig()
        manager = MagicMock()
        manager.gc_candidates.return_value = [{"branch": "old", "database": "old_db"}]
        manager.gc.return_value = {
            "success": True,
            "operation": "branch_db_gc",
            "dry_run": False,
            "candidates": [{"branch": "old", "database": "old_db"}],
            "deleted": [{"branch": "old", "database": "old_db"}],
            "already_missing": [],
            "errors": [],
        }
        require_mutation = MagicMock()

        branch_database_gc_command(
            None,
            apply=True,
            allow_mutation=True,
            resolve_command_env_config_fn=lambda _ctx: (config, {}),
            build_branch_database_manager_fn=lambda _config: manager,
            require_cli_runtime_db_mutation_fn=require_mutation,
            confirmation_required_error_fn=self._confirmation_required,
            print_command_error_result_fn=self._print_error,
        )

        require_mutation.assert_called_once()
        manager.gc.assert_called_once_with(apply=True)


if __name__ == "__main__":
    unittest.main()
