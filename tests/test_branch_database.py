"""Tests for branch-aware database resolution and state management."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from oduit.branch_database import (
    BranchDatabaseDetachedHead,
    BranchDatabaseGitError,
    BranchDatabaseManager,
    BranchDatabaseSettings,
    BranchDatabaseStateError,
    BranchDatabaseStateStore,
    apply_branch_database_resolution,
    build_branch_database_name,
    inspect_git_branch,
    list_local_git_branches,
    parse_branch_database_settings,
    resolve_branch_database,
)
from oduit.cli.agent.services import resolve_agent_global_config
from oduit.cli.bootstrap_support import create_global_config
from oduit.exceptions import ConfigError


class TestBranchDatabaseResolution(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.base = Path(self.temporary_directory.name)

    @staticmethod
    def _write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _repository(self, branch: str = "main") -> Path:
        root = self.base / "repo"
        git_dir = root / ".git"
        git_dir.mkdir(parents=True)
        self._write(git_dir / "HEAD", f"ref: refs/heads/{branch}\n")
        return root

    @staticmethod
    def _config(branch_db: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "odoo_params": {"db_name": "project_dev"},
            **({"branch_db": branch_db} if branch_db is not None else {}),
        }

    def test_inspect_normal_repository_and_nested_start_path(self) -> None:
        root = self._repository("feature/fix7")
        nested = root / "addons" / "custom"
        nested.mkdir(parents=True)

        info = inspect_git_branch(nested)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(info.root, root.resolve())
        self.assertEqual(info.git_dir, (root / ".git").resolve())
        self.assertEqual(info.common_dir, info.git_dir)
        self.assertEqual(info.branch, "feature/fix7")
        self.assertFalse(info.detached)

    def test_inspect_worktree_uses_worktree_head_and_common_directory(self) -> None:
        common_root = self._repository("main")
        common_dir = common_root / ".git"
        worktree = self.base / "worktree"
        git_dir = common_dir / "worktrees" / "linked"
        git_dir.mkdir(parents=True)
        worktree.mkdir()
        self._write(worktree / ".git", "gitdir: ../repo/.git/worktrees/linked\n")
        self._write(git_dir / "commondir", "../..\n")
        self._write(git_dir / "HEAD", "ref: refs/heads/feature/worktree\n")

        info = inspect_git_branch(worktree)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(info.root, worktree.resolve())
        self.assertEqual(info.git_dir, git_dir.resolve())
        self.assertEqual(info.common_dir, common_dir.resolve())
        self.assertEqual(info.branch, "feature/worktree")

    def test_detached_head_is_reported(self) -> None:
        root = self._repository()
        self._write(root / ".git" / "HEAD", "abc123\n")

        info = inspect_git_branch(root)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertIsNone(info.branch)
        self.assertTrue(info.detached)

    def test_malformed_git_file_fails_clearly(self) -> None:
        root = self.base / "worktree"
        root.mkdir()
        self._write(root / ".git", "not a gitdir file\n")

        with self.assertRaisesRegex(BranchDatabaseGitError, "Malformed Git worktree"):
            inspect_git_branch(root)

    def test_missing_head_fails_clearly(self) -> None:
        root = self.base / "repo"
        (root / ".git").mkdir(parents=True)

        with self.assertRaisesRegex(BranchDatabaseGitError, "Git HEAD"):
            inspect_git_branch(root)

    def test_no_repository_returns_none(self) -> None:
        directory = self.base / "not-a-repo"
        directory.mkdir()

        self.assertIsNone(inspect_git_branch(directory))

    def test_local_branch_listing_includes_loose_and_packed_refs_only(self) -> None:
        root = self._repository("main")
        git_dir = root / ".git"
        self._write(git_dir / "refs" / "heads" / "main", "main\n")
        self._write(git_dir / "refs" / "heads" / "feature" / "loose", "abc\n")
        self._write(
            git_dir / "packed-refs",
            "# pack-refs with: peeled fully-peeled\n"
            "abc refs/heads/packed\n"
            "def refs/remotes/origin/remote-only\n"
            "^123 peeled-object\n",
        )

        info = inspect_git_branch(root)
        assert info is not None

        self.assertEqual(
            list_local_git_branches(info), {"main", "feature/loose", "packed"}
        )

    def test_config_defaults_and_disabled_configuration(self) -> None:
        self.assertEqual(
            parse_branch_database_settings(self._config()), BranchDatabaseSettings()
        )
        self.assertEqual(
            parse_branch_database_settings(
                self._config({"enabled": False, "base_branch": "stable"})
            ),
            BranchDatabaseSettings(enabled=False, base_branch="stable"),
        )
        self.assertEqual(
            parse_branch_database_settings(self._config({"enabled": True})),
            BranchDatabaseSettings(enabled=True),
        )

    def test_config_rejects_invalid_section_and_empty_base_branch(self) -> None:
        with self.assertRaises(ConfigError):
            parse_branch_database_settings({"branch_db": True})
        with self.assertRaisesRegex(ConfigError, "base_branch"):
            parse_branch_database_settings(self._config({"base_branch": "  "}))
        with self.assertRaisesRegex(ConfigError, "enabled requires"):
            parse_branch_database_settings(
                {"branch_db": {"enabled": True}, "odoo_params": {}}
            )
        with self.assertRaisesRegex(ConfigError, "enabled must be a boolean"):
            parse_branch_database_settings(self._config({"enabled": 1}))

    def test_branch_database_naming_is_stable_and_collision_resistant(self) -> None:
        self.assertEqual(
            build_branch_database_name("project_dev", "fix7"), "project_dev_fix7"
        )

        normalized = build_branch_database_name("project_dev", "feature/fix-7")
        self.assertTrue(normalized.startswith("project_dev_feature_fix_7_"))
        self.assertNotEqual(
            normalized, build_branch_database_name("project_dev", "feature_fix_7")
        )
        self.assertNotEqual(
            build_branch_database_name("project_dev", "fix7"),
            build_branch_database_name("project_dev", "Fix7"),
        )
        self.assertTrue(
            build_branch_database_name("project_dev", "feature/café").startswith(
                "project_dev_feature_cafe_"
            )
        )
        self.assertTrue(
            build_branch_database_name("project_dev", "!!!").startswith(
                "project_dev_branch_"
            )
        )

    def test_branch_database_naming_respects_utf8_identifier_limit(self) -> None:
        branch = "feature/" + "long-name" * 30
        name = build_branch_database_name("project_dev", branch)
        long_base_name = build_branch_database_name("database" * 20, "fix7")

        self.assertLessEqual(len(name.encode("utf-8")), 63)
        self.assertLessEqual(len(long_base_name.encode("utf-8")), 63)
        self.assertRegex(name, r"_[0-9a-f]{8}$")
        self.assertRegex(long_base_name, r"_[0-9a-f]{8}$")
        self.assertEqual(name, build_branch_database_name("project_dev", branch))

    def test_resolution_maps_base_and_feature_branches(self) -> None:
        base_root = self._repository("main")
        base = resolve_branch_database(self._config({"enabled": True}), base_root)
        self.assertTrue(base.is_base_branch)
        self.assertEqual(base.database, "project_dev")

        self._write(base_root / ".git" / "HEAD", "ref: refs/heads/fix7\n")
        feature = resolve_branch_database(self._config({"enabled": True}), base_root)
        self.assertFalse(feature.is_base_branch)
        self.assertEqual(feature.database, "project_dev_fix7")

    def test_disabled_resolution_does_not_require_a_git_repository(self) -> None:
        config = {"odoo_params": {"db_name": "project_dev"}}

        resolution = resolve_branch_database(config, self.base)

        self.assertFalse(resolution.enabled)
        self.assertEqual(resolution.database, "project_dev")
        self.assertEqual(config["odoo_params"]["db_name"], "project_dev")

    def test_enabled_resolution_rejects_detached_head_and_missing_repository(
        self,
    ) -> None:
        root = self._repository()
        self._write(root / ".git" / "HEAD", "deadbeef\n")
        with self.assertRaises(BranchDatabaseDetachedHead):
            resolve_branch_database(self._config({"enabled": True}), root)

        with self.assertRaisesRegex(BranchDatabaseGitError, "no Git repository"):
            resolve_branch_database(self._config({"enabled": True}), self.base)

    def test_apply_resolution_copies_sectioned_config(self) -> None:
        root = self._repository("fix7")
        config = self._config({"enabled": True})
        resolution = resolve_branch_database(config, root)

        effective = apply_branch_database_resolution(config, resolution)

        self.assertEqual(effective["odoo_params"]["db_name"], "project_dev_fix7")
        self.assertEqual(config["odoo_params"]["db_name"], "project_dev")
        self.assertIsNot(effective["odoo_params"], config["odoo_params"])


class TestBranchDatabaseStateAndManager(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.base = Path(self.temporary_directory.name)
        self.root = self.base / "repo"
        self.common_dir = self.root / ".git"
        self.common_dir.mkdir(parents=True)
        self._write(self.common_dir / "HEAD", "ref: refs/heads/fix7\n")
        self._write(self.common_dir / "refs" / "heads" / "main", "main\n")
        self._write(self.common_dir / "refs" / "heads" / "fix7", "feature\n")
        self.config = {
            "odoo_params": {"db_name": "project_dev"},
            "branch_db": {"enabled": True},
        }
        self.resolution = resolve_branch_database(self.config, self.root)
        self.state_store = BranchDatabaseStateStore(
            self.common_dir,
            config_path=self.root / ".oduit.toml",
            base_database="project_dev",
            base_branch="main",
        )
        self.databases = {"project_dev"}
        self.calls: list[tuple[str, str]] = []
        self.fail_duplicate = False
        self.race_duplicate = False
        self.fail_drop = False

    @staticmethod
    def _write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _manager(self, *, auto_create: bool = True) -> BranchDatabaseManager:
        class FakeOperations:
            def __init__(inner_self, config: dict[str, Any]):
                section = config.get("odoo_params", {})
                inner_self.database = section.get("db_name", config.get("db_name"))

            def db_exists(
                inner_self, *, suppress_output: bool = False
            ) -> dict[str, Any]:
                self.calls.append(("exists", inner_self.database))
                return {
                    "success": True,
                    "exists": inner_self.database in self.databases,
                }

            def duplicate_db(
                inner_self,
                target_database: str,
                *,
                source_database: str,
                neutralize: bool,
                force: bool,
                suppress_output: bool,
            ) -> dict[str, Any]:
                self.calls.append(("duplicate", target_database))
                self.assertFalse(force)
                self.assertEqual(source_database, "project_dev")
                if self.race_duplicate:
                    self.databases.add(target_database)
                    return {"success": False, "error": "already exists"}
                if self.fail_duplicate or target_database in self.databases:
                    return {"success": False, "error": "duplicate failed"}
                self.databases.add(target_database)
                return {"success": True}

            def drop_db_with_filestore(
                inner_self, database: str, *, suppress_output: bool = False
            ) -> dict[str, Any]:
                self.calls.append(("drop", database))
                if self.fail_drop:
                    return {"success": False, "error": "drop failed"}
                self.databases.discard(database)
                return {"success": True}

        return BranchDatabaseManager(
            self.config,
            self.resolution,
            BranchDatabaseSettings(enabled=True, auto_create=auto_create),
            FakeOperations,
            config_path=self.root / ".oduit.toml",
            state_store=self.state_store,
        )

    def test_state_absent_round_trip_and_environment_isolation(self) -> None:
        self.assertFalse(self.state_store.path.exists())
        self.assertEqual(self.state_store.records(), {})

        self.state_store.record_created("old", "project_dev_old", "project_dev", False)
        self.assertTrue(self.state_store.is_managed("old", "project_dev_old"))
        self.assertEqual(
            self.state_store.records()["old"]["source_database"], "project_dev"
        )
        self.assertTrue(self.state_store.path.exists())

        other_environment = BranchDatabaseStateStore(
            self.common_dir,
            config_path=self.root / ".oduit.toml",
            base_database="other_db",
            base_branch="main",
        )
        self.assertEqual(other_environment.records(), {})
        other_environment.record_created("old", "other_db_old", "other_db", False)
        self.assertEqual(set(self.state_store.records()), {"old"})
        self.assertEqual(set(other_environment.records()), {"old"})

    def test_state_corruption_fails_safely(self) -> None:
        self.state_store.path.parent.mkdir(parents=True)
        self.state_store.path.write_text("{broken", encoding="utf-8")

        with self.assertRaises(BranchDatabaseStateError):
            self.state_store.records()

    def test_atomic_state_write_leaves_valid_json_and_no_temporary_file(self) -> None:
        self.state_store.record_created("old", "project_dev_old", "project_dev", False)

        state = json.loads(self.state_store.path.read_text(encoding="utf-8"))

        self.assertEqual(state["schema_version"], 1)
        self.assertIn(self.state_store.environment_key, state["environments"])
        self.assertEqual(list(self.state_store.path.parent.glob("*.tmp")), [])

    def test_existing_unmanaged_database_is_not_adopted(self) -> None:
        target = self.resolution.database
        self.databases.add(target)

        result = self._manager().ensure()

        self.assertTrue(result["success"])
        self.assertFalse(result["created"])
        self.assertFalse(result["managed"])
        self.assertNotIn(("duplicate", target), self.calls)
        self.assertEqual(self.state_store.records(), {})

    def test_successful_clone_is_recorded_only_after_target_exists(self) -> None:
        result = self._manager().ensure()

        self.assertTrue(result["success"])
        self.assertTrue(result["created"])
        self.assertTrue(result["managed"])
        self.assertIn(self.resolution.database, self.databases)
        self.assertEqual(
            self.state_store.records()["fix7"]["database"], self.resolution.database
        )
        self.assertIn(("duplicate", self.resolution.database), self.calls)

    def test_failed_duplicate_does_not_record_ownership(self) -> None:
        self.fail_duplicate = True

        result = self._manager().ensure()

        self.assertFalse(result["success"])
        self.assertFalse(result["managed"])
        self.assertEqual(self.state_store.records(), {})

    def test_duplicate_race_reuses_target_without_claiming_ownership(self) -> None:
        self.race_duplicate = True

        result = self._manager().ensure()

        self.assertTrue(result["success"])
        self.assertFalse(result["created"])
        self.assertEqual(result["warning_type"], "concurrent_create_detected")
        self.assertFalse(result["managed"])
        self.assertEqual(self.state_store.records(), {})

    def test_status_is_read_only_and_reports_managed_state(self) -> None:
        self.databases.add(self.resolution.database)

        result = self._manager().status()

        self.assertTrue(result["success"])
        self.assertTrue(result["exists"])
        self.assertFalse(result["managed"])
        self.assertFalse(any(action == "duplicate" for action, _ in self.calls))
        self.assertFalse(any(action == "drop" for action, _ in self.calls))

    def test_gc_candidates_exclude_base_current_and_existing_local_branches(
        self,
    ) -> None:
        self._write(self.common_dir / "refs" / "heads" / "keep", "keep\n")
        for branch, database in (
            ("old", "project_dev_old"),
            ("main", "project_dev"),
            ("fix7", self.resolution.database),
            ("keep", "project_dev_keep"),
        ):
            self.state_store.record_created(branch, database, "project_dev", False)

        self.assertEqual(
            self._manager().gc_candidates(),
            [{"branch": "old", "database": "project_dev_old"}],
        )

    def test_gc_dry_run_does_not_drop_or_remove_records(self) -> None:
        self.state_store.record_created("old", "project_dev_old", "project_dev", False)
        self.databases.add("project_dev_old")

        result = self._manager().gc()

        self.assertTrue(result["success"])
        self.assertTrue(result["dry_run"])
        self.assertEqual(len(result["candidates"]), 1)
        self.assertFalse(any(action == "drop" for action, _ in self.calls))
        self.assertTrue(self.state_store.is_managed("old", "project_dev_old"))

    def test_gc_apply_drops_managed_database_and_removes_record(self) -> None:
        self.state_store.record_created("old", "project_dev_old", "project_dev", False)
        self.databases.add("project_dev_old")

        result = self._manager().gc(apply=True)

        self.assertTrue(result["success"])
        self.assertEqual(
            result["deleted"], [{"branch": "old", "database": "project_dev_old"}]
        )
        self.assertNotIn("project_dev_old", self.databases)
        self.assertEqual(self.state_store.records(), {})
        self.assertIn(("drop", "project_dev_old"), self.calls)

    def test_gc_prunes_missing_database_only_when_applied(self) -> None:
        self.state_store.record_created("old", "project_dev_old", "project_dev", False)

        result = self._manager().gc(apply=True)

        self.assertEqual(
            result["already_missing"],
            [{"branch": "old", "database": "project_dev_old"}],
        )
        self.assertEqual(self.state_store.records(), {})
        self.assertFalse(any(action == "drop" for action, _ in self.calls))

    def test_gc_failed_drop_keeps_registry_entry(self) -> None:
        self.state_store.record_created("old", "project_dev_old", "project_dev", False)
        self.databases.add("project_dev_old")
        self.fail_drop = True

        result = self._manager().gc(apply=True)

        self.assertFalse(result["success"])
        self.assertEqual(len(result["errors"]), 1)
        self.assertTrue(self.state_store.is_managed("old", "project_dev_old"))


class TestBranchDatabaseConfigResolution(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        git_dir = self.root / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/fix7\n", encoding="utf-8")
        self.config = {
            "odoo_params": {"db_name": "project_dev"},
            "branch_db": {"enabled": True},
        }

    def test_classic_config_retains_base_and_resolves_effective_database(self) -> None:
        loader = MagicMock()
        loader.load_config.return_value = self.config
        with patch("oduit.cli.bootstrap_support.Path.cwd", return_value=self.root):
            result = create_global_config(
                env="dev",
                json=False,
                non_interactive=False,
                verbose=False,
                no_http=False,
                odoo_series=None,
                configure_output_fn=MagicMock(),
                config_loader_cls=lambda: loader,
                print_error_fn=MagicMock(),
                echo_fn=MagicMock(),
                resolve_config_source_fn=lambda *_args: ("env", None),
            )

        self.assertEqual(result.base_env_config, self.config)
        self.assertEqual(
            result.env_config["odoo_params"]["db_name"], "project_dev_fix7"
        )
        self.assertEqual(result.branch_database.branch, "fix7")
        self.assertEqual(self.config["odoo_params"]["db_name"], "project_dev")

    def test_agent_config_resolves_effective_database_without_provisioning(
        self,
    ) -> None:
        loader = MagicMock()
        loader.load_config.return_value = self.config
        with patch("oduit.cli.agent.services.Path.cwd", return_value=self.root):
            result = resolve_agent_global_config(
                SimpleNamespace(obj={"env": "dev"}),
                "agent_context",
                "context",
                configure_output_fn=MagicMock(),
                fail_fn=MagicMock(
                    side_effect=AssertionError("unexpected config failure")
                ),
                config_loader_cls=lambda: loader,
                resolve_config_source_fn=lambda *_args: ("env", None),
            )

        self.assertEqual(result.base_env_config, self.config)
        self.assertEqual(
            result.env_config["odoo_params"]["db_name"], "project_dev_fix7"
        )
        self.assertEqual(result.branch_database.branch, "fix7")
        loader.load_config.assert_called_once_with("dev")


if __name__ == "__main__":
    unittest.main()
