"""Branch-aware Odoo database resolution and managed database lifecycle."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .exceptions import ConfigError
from .project_paths import find_git_root


class BranchDatabaseError(Exception):
    """Base error for branch-aware database management."""


class BranchDatabaseGitError(BranchDatabaseError):
    """Raised when Git metadata cannot be read safely."""


class BranchDatabaseDetachedHead(BranchDatabaseGitError):
    """Raised when branch-aware database mode encounters detached HEAD."""


class BranchDatabaseStateError(BranchDatabaseError):
    """Raised when the managed branch database registry is invalid."""


@dataclass(frozen=True)
class GitBranchInfo:
    root: Path
    git_dir: Path
    common_dir: Path
    branch: str | None
    detached: bool


@dataclass(frozen=True)
class BranchDatabaseSettings:
    enabled: bool = False
    base_branch: str = "main"
    auto_create: bool = True
    neutralize: bool = False


@dataclass(frozen=True)
class BranchDatabaseResolution:
    enabled: bool
    branch: str | None
    base_branch: str
    base_database: str
    database: str
    is_base_branch: bool
    git_root: Path | None
    git_dir: Path | None
    common_dir: Path | None


def parse_branch_database_settings(
    env_config: dict[str, Any],
) -> BranchDatabaseSettings:
    """Parse and validate the optional ``branch_db`` configuration section."""
    raw_settings = env_config.get("branch_db", {})
    if not isinstance(raw_settings, dict):
        raise ConfigError("[branch_db] must be a TOML table")

    enabled = raw_settings.get("enabled", False)
    auto_create = raw_settings.get("auto_create", True)
    neutralize = raw_settings.get("neutralize", False)
    base_branch = raw_settings.get("base_branch", "main")

    for key, value in (
        ("enabled", enabled),
        ("auto_create", auto_create),
        ("neutralize", neutralize),
    ):
        if type(value) is not bool:
            raise ConfigError(f"[branch_db].{key} must be a boolean")

    if not isinstance(base_branch, str) or not base_branch.strip():
        raise ConfigError("[branch_db].base_branch must be a non-empty string")

    if enabled:
        section = env_config.get("odoo_params")
        database = section.get("db_name") if isinstance(section, dict) else None
        if not database:
            database = env_config.get("db_name")
        if not isinstance(database, str) or not database.strip():
            raise ConfigError(
                "[branch_db].enabled requires odoo_params.db_name to be configured"
            )
            raise ConfigError(
                "[branch_db].enabled requires odoo_params.db_name to be configured"
            )

    return BranchDatabaseSettings(
        enabled=enabled,
        base_branch=base_branch.strip(),
        auto_create=auto_create,
        neutralize=neutralize,
    )


def _resolve_git_path(raw_path: str, relative_to: Path, label: str) -> Path:
    raw_path = raw_path.strip()
    if not raw_path:
        raise BranchDatabaseGitError(f"Git {label} path is empty")
    value = Path(raw_path).expanduser()
    if not value.is_absolute():
        value = relative_to / value
    resolved = value.resolve(strict=False)
    if not resolved.is_dir():
        raise BranchDatabaseGitError(
            f"Git {label} directory does not exist: {resolved}"
        )
    return resolved


def inspect_git_branch(start: Path) -> GitBranchInfo | None:
    """Read current branch information from repository metadata without Git."""
    root = find_git_root(start)
    if root is None:
        return None

    git_entry = root / ".git"
    if git_entry.is_dir():
        git_dir = git_entry.resolve(strict=False)
    elif git_entry.is_file():
        try:
            git_file = git_entry.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise BranchDatabaseGitError(
                f"Could not read {git_entry}: {error}"
            ) from error
        if not git_file.startswith("gitdir:"):
            raise BranchDatabaseGitError(
                f"Malformed Git worktree file {git_entry}: expected 'gitdir: PATH'"
            )
        git_dir = _resolve_git_path(git_file[len("gitdir:") :], root, "gitdir")
    else:
        raise BranchDatabaseGitError(f"Git metadata is missing at {git_entry}")

    common_dir_file = git_dir / "commondir"
    if common_dir_file.exists():
        try:
            common_dir_value = common_dir_file.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise BranchDatabaseGitError(
                f"Could not read {common_dir_file}: {error}"
            ) from error
        if not common_dir_value:
            raise BranchDatabaseGitError(
                f"Git common directory is empty: {common_dir_file}"
            )
        common_dir = _resolve_git_path(common_dir_value, git_dir, "common")
    else:
        common_dir = git_dir

    head_path = git_dir / "HEAD"
    try:
        head = head_path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise BranchDatabaseGitError(
            f"Could not read Git HEAD at {head_path}: {error}"
        ) from error

    if head.startswith("ref:"):
        ref = head[len("ref:") :].strip()
        if not ref.startswith("refs/heads/") or not ref[len("refs/heads/") :]:
            raise BranchDatabaseGitError(
                f"Git HEAD points to an unsupported ref: {head}"
            )
        branch = ref[len("refs/heads/") :]
        return GitBranchInfo(root, git_dir, common_dir, branch, False)

    if not head:
        raise BranchDatabaseGitError(f"Git HEAD is empty: {head_path}")
    return GitBranchInfo(root, git_dir, common_dir, None, True)


def list_local_git_branches(git_info: GitBranchInfo) -> set[str]:
    """Return local branch names from loose and packed refs in the common dir."""
    branches: set[str] = set()
    refs_root = git_info.common_dir / "refs" / "heads"
    if refs_root.is_dir():
        for ref_path in refs_root.rglob("*"):
            if ref_path.is_file():
                branches.add(ref_path.relative_to(refs_root).as_posix())

    packed_refs = git_info.common_dir / "packed-refs"
    if packed_refs.is_file():
        try:
            lines = packed_refs.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise BranchDatabaseGitError(
                f"Could not read packed Git refs at {packed_refs}: {error}"
            ) from error
        prefix = "refs/heads/"
        for line in lines:
            if not line or line.startswith(("#", "^")):
                continue
            fields = line.split()
            if len(fields) == 2 and fields[1].startswith(prefix):
                branch = fields[1][len(prefix) :]
                if branch:
                    branches.add(branch)
    return branches


def _database_identity_hash(base_database: str, branch: str) -> str:
    identity = f"{base_database}\0{branch}".encode()
    return hashlib.sha256(identity).hexdigest()[:8]


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")[:max_bytes]
    while encoded:
        try:
            return encoded.decode("utf-8")
        except UnicodeDecodeError:
            encoded = encoded[:-1]
    return ""


def build_branch_database_name(base_database: str, branch: str) -> str:
    """Build a deterministic PostgreSQL-safe database identifier for a branch."""
    if not isinstance(base_database, str) or not base_database:
        raise ValueError("base_database must be a non-empty string")
    if not isinstance(branch, str) or not branch:
        raise ValueError("branch must be a non-empty string")

    normalized = unicodedata.normalize("NFKD", branch)
    slug = normalized.encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug).strip("_") or "branch"

    identity_changed = slug != branch
    full_name = f"{base_database}_{slug}"
    truncated = len(full_name.encode("utf-8")) > 63
    suffix_hash = _database_identity_hash(base_database, branch)

    if identity_changed or truncated:
        slug = _truncate_utf8(slug, 53) or "branch"
        suffix = f"{slug}_{suffix_hash}"
        prefix = _truncate_utf8(base_database, 63 - len(suffix.encode("ascii")) - 1)
        result = f"{prefix}_{suffix}" if prefix else f"_{suffix}"
    else:
        result = full_name

    if len(result.encode("utf-8")) > 63:
        raise ValueError("could not fit branch database name within 63 bytes")
    return result


def _configured_database(env_config: dict[str, Any]) -> str:
    section = env_config.get("odoo_params")
    value = section.get("db_name") if isinstance(section, dict) else None
    if value is None:
        value = env_config.get("db_name")
    return value if isinstance(value, str) else ""


def resolve_branch_database(
    env_config: dict[str, Any], start: Path
) -> BranchDatabaseResolution:
    """Resolve the effective database without modifying the supplied config."""
    settings = parse_branch_database_settings(env_config)
    base_database = _configured_database(env_config)
    if not settings.enabled:
        return BranchDatabaseResolution(
            enabled=False,
            branch=None,
            base_branch=settings.base_branch,
            base_database=base_database,
            database=base_database,
            is_base_branch=True,
            git_root=None,
            git_dir=None,
            common_dir=None,
        )

    git_info = inspect_git_branch(start)
    if git_info is None:
        raise BranchDatabaseGitError(
            "Branch-aware database management is enabled, but no Git repository "
            "was found. Disable [branch_db] or run oduit from a local Git repository."
            "Disable [branch_db] or run oduit from a local Git repository."
        )
    if git_info.detached or git_info.branch is None:
        raise BranchDatabaseDetachedHead(
            "Branch-aware database management is enabled, but Git HEAD is detached. "
            "Check out a local branch or disable [branch_db]."
        )

    is_base_branch = git_info.branch == settings.base_branch
    database = (
        base_database
        if is_base_branch
        else build_branch_database_name(base_database, git_info.branch)
    )
    return BranchDatabaseResolution(
        enabled=True,
        branch=git_info.branch,
        base_branch=settings.base_branch,
        base_database=base_database,
        database=database,
        is_base_branch=is_base_branch,
        git_root=git_info.root,
        git_dir=git_info.git_dir,
        common_dir=git_info.common_dir,
    )


def apply_branch_database_resolution(
    env_config: dict[str, Any], resolution: BranchDatabaseResolution
) -> dict[str, Any]:
    """Return a config copy with the effective database applied in memory."""
    result = dict(env_config)
    if not resolution.enabled:
        return result

    section = result.get("odoo_params")
    if isinstance(section, dict):
        effective_section = dict(section)
        effective_section["db_name"] = resolution.database
        result["odoo_params"] = effective_section
    else:
        result["db_name"] = resolution.database
    return result


def branch_database_environment_key(
    config_path: str | Path | None, base_database: str, base_branch: str
) -> str:
    """Return a stable, non-secret key for one config/database/branch identity."""
    resolved_config = (
        str(Path(config_path).expanduser().resolve(strict=False)) if config_path else ""
    )
    identity = json.dumps(
        [resolved_config, base_database, base_branch],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


class BranchDatabaseStateStore:
    """Versioned registry for databases created by branch management."""

    def __init__(
        self,
        common_dir: Path,
        *,
        config_path: str | Path | None,
        base_database: str,
        base_branch: str,
    ):
        self.path = common_dir / "oduit" / "branch-databases.json"
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.environment_key = branch_database_environment_key(
            config_path, base_database, base_branch
        )
        self.base_database = base_database
        self.base_branch = base_branch

    @staticmethod
    def _empty_state() -> dict[str, Any]:
        return {"schema_version": 1, "environments": {}}

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty_state()
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise BranchDatabaseStateError(
                f"Could not read branch database state file {self.path}: {error}"
            ) from error
        if (
            not isinstance(state, dict)
            or state.get("schema_version") != 1
            or not isinstance(state.get("environments"), dict)
        ):
            raise BranchDatabaseStateError(
                f"Unsupported or malformed branch database state file: {self.path}"
            )
        for key, environment in state["environments"].items():
            if (
                not isinstance(key, str)
                or not isinstance(environment, dict)
                or not isinstance(environment.get("databases"), dict)
            ):
                raise BranchDatabaseStateError(
                    f"Malformed environment entry in branch database state: {key!r}"
                )
            for branch, record in environment["databases"].items():
                if (
                    not isinstance(branch, str)
                    or not isinstance(record, dict)
                    or not isinstance(record.get("database"), str)
                    or not isinstance(record.get("source_database"), str)
                    or not isinstance(record.get("created_at"), str)
                    or not isinstance(record.get("neutralized"), bool)
                ):
                    raise BranchDatabaseStateError(
                        f"Malformed database record for branch {branch!r}"
                    )
        return state

    def _environment(self, state: dict[str, Any]) -> dict[str, Any]:
        environments = state["environments"]
        return environments.get(
            self.environment_key,
            {
                "base_database": self.base_database,
                "base_branch": self.base_branch,
                "databases": {},
            },
        )

    def environment(self) -> dict[str, Any]:
        """Return the current environment's registry entry, or an empty entry."""
        return self._environment(self._read())

    def records(self) -> dict[str, dict[str, Any]]:
        """Return a copy of managed records for the current environment."""
        return dict(self.environment()["databases"])

    def is_managed(self, branch: str, database: str) -> bool:
        record = self.records().get(branch)
        return bool(record and record.get("database") == database)

    def _write(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
                json.dump(state, temporary_file, indent=2, sort_keys=True)
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_name, self.path)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

    def _update(self, updater: Callable[[dict[str, Any]], None]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            state = self._read()
            updater(state)
            self._write(state)

    def record_created(
        self,
        branch: str,
        database: str,
        source_database: str,
        neutralized: bool,
    ) -> None:
        """Record a branch database after the caller proves creation succeeded."""
        record = {
            "database": database,
            "source_database": source_database,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "neutralized": neutralized,
        }

        def update(state: dict[str, Any]) -> None:
            environment = self._environment(state)
            environment["databases"][branch] = record
            state["environments"][self.environment_key] = environment

        self._update(update)

    def remove(self, branch: str, database: str | None = None) -> bool:
        """Remove a managed record, optionally requiring its expected DB name."""
        removed = False

        def update(state: dict[str, Any]) -> None:
            nonlocal removed
            environment = self._environment(state)
            record = environment["databases"].get(branch)
            if record is None or (
                database is not None and record.get("database") != database
            ):
                return
            del environment["databases"][branch]
            removed = True
            if environment["databases"]:
                state["environments"][self.environment_key] = environment
            else:
                state["environments"].pop(self.environment_key, None)

        self._update(update)
        return removed


class BranchDatabaseManager:
    """Coordinate database existence, branch cloning, and conservative GC."""

    def __init__(
        self,
        env_config: dict[str, Any],
        resolution: BranchDatabaseResolution,
        settings: BranchDatabaseSettings,
        operations_factory: Callable[[dict[str, Any]], Any],
        *,
        config_path: str | Path | None = None,
        state_store: BranchDatabaseStateStore | None = None,
    ):
        self.env_config = dict(env_config)
        self.resolution = resolution
        self.settings = settings
        self.operations_factory = operations_factory
        self.state_store = state_store
        if self.state_store is None and resolution.common_dir is not None:
            self.state_store = BranchDatabaseStateStore(
                resolution.common_dir,
                config_path=config_path,
                base_database=resolution.base_database,
                base_branch=resolution.base_branch,
            )

    def _operations(self, database: str) -> Any:
        resolution = replace(self.resolution, database=database)
        config = apply_branch_database_resolution(self.env_config, resolution)
        return self.operations_factory(config)

    def _exists(self, database: str) -> tuple[bool | None, dict[str, Any]]:
        result = self._operations(database).db_exists(suppress_output=True)
        if not result or not result.get("success", False):
            return None, result or {"success": False, "error": "Database check failed"}
        return bool(result.get("exists", False)), result

    def _managed(self, database: str) -> bool:
        if (
            self.state_store is None
            or self.resolution.branch is None
            or self.resolution.is_base_branch
        ):
            return False
        return self.state_store.is_managed(self.resolution.branch, database)

    def status(self) -> dict[str, Any]:
        """Return read-only status for the effective database."""
        result: dict[str, Any] = {
            "success": True,
            "operation": "branch_db_status",
            "enabled": self.resolution.enabled,
            "branch": self.resolution.branch,
            "base_branch": self.resolution.base_branch,
            "base_database": self.resolution.base_database,
            "database": self.resolution.database,
            "is_base_branch": self.resolution.is_base_branch,
            "exists": None,
            "managed": False,
            "clone_required": False,
        }
        if not self.resolution.enabled:
            return result

        exists, check = self._exists(self.resolution.database)
        if exists is None:
            result.update(
                {
                    "success": False,
                    "error": check.get("error", "Database existence check failed"),
                    "error_type": check.get("error_type", "DatabaseCheckError"),
                }
            )
            return result
        managed = self._managed(self.resolution.database)
        result.update(
            {
                "exists": exists,
                "managed": managed,
                "clone_required": (
                    not self.resolution.is_base_branch
                    and not exists
                    and self.settings.auto_create
                ),
            }
        )
        return result

    @staticmethod
    def _base_missing_result(database: str) -> dict[str, Any]:
        return {
            "success": False,
            "error": (
                f"Branch database provisioning requires base database {database!r}, "
                "but it does not exist. Create the base database from the "
                "base branch first."
            ),
            "error_type": "BranchDatabaseBaseMissing",
            "remediation": [
                "Switch to the configured base branch and run `oduit create-db`."
            ],
        }

    def ensure(
        self, *, before_duplicate: Callable[[], None] | None = None
    ) -> dict[str, Any]:
        """Ensure the effective database exists without overwriting any target."""
        resolution = self.resolution
        result: dict[str, Any] = {
            "success": True,
            "operation": "branch_db_ensure",
            "enabled": resolution.enabled,
            "branch": resolution.branch,
            "base_database": resolution.base_database,
            "database": resolution.database,
            "created": False,
            "managed": False,
            "neutralized": self.settings.neutralize,
        }
        if not resolution.enabled:
            result["message"] = "Branch-aware database management is disabled."
            return result

        target_exists, target_check = self._exists(resolution.database)
        if target_exists is None:
            return {
                **result,
                "success": False,
                "error": target_check.get("error", "Database existence check failed"),
                "error_type": target_check.get("error_type", "DatabaseCheckError"),
            }
        if resolution.is_base_branch:
            if target_exists:
                return {**result, "managed": False}
            return {
                **result,
                **self._base_missing_result(resolution.base_database),
            }
        if target_exists:
            return {**result, "managed": self._managed(resolution.database)}
        if not self.settings.auto_create:
            return {
                **result,
                "success": False,
                "error": f"Branch database {resolution.database!r} does not exist.",
                "error_type": "BranchDatabaseMissing",
                "remediation": ["Run `oduit branch-db ensure` to create it."],
            }

        base_exists, base_check = self._exists(resolution.base_database)
        if base_exists is None:
            return {
                **result,
                "success": False,
                "error": base_check.get(
                    "error", "Base database existence check failed"
                ),
                "error_type": base_check.get("error_type", "DatabaseCheckError"),
            }
        if not base_exists:
            return {**result, **self._base_missing_result(resolution.base_database)}

        if before_duplicate is not None:
            before_duplicate()
        duplicate = self._operations(resolution.database).duplicate_db(
            resolution.database,
            source_database=resolution.base_database,
            neutralize=self.settings.neutralize,
            force=False,
            suppress_output=True,
        )
        if not duplicate or not duplicate.get("success", False):
            concurrent_exists, _ = self._exists(resolution.database)
            if concurrent_exists:
                return {
                    **result,
                    "success": True,
                    "created": False,
                    "managed": self._managed(resolution.database),
                    "warning": "Another process may have created the branch database.",
                    "warning_type": "concurrent_create_detected",
                }
            return {
                **result,
                "success": False,
                "error": duplicate.get("error", "Odoo database duplication failed")
                if duplicate
                else "Odoo database duplication failed",
                "error_type": duplicate.get(
                    "error_type", "BranchDatabaseDuplicateError"
                )
                if duplicate
                else "BranchDatabaseDuplicateError",
                "duplicate_result": duplicate,
            }

        created_exists, created_check = self._exists(resolution.database)
        if created_exists is not True:
            return {
                **result,
                "success": False,
                "error": created_check.get(
                    "error",
                    "Database duplication succeeded but target is not available",
                ),
                "error_type": "BranchDatabaseDuplicateVerificationError",
                "duplicate_result": duplicate,
            }
        if self.state_store is not None and resolution.branch is not None:
            self.state_store.record_created(
                resolution.branch,
                resolution.database,
                resolution.base_database,
                self.settings.neutralize,
            )
        return {
            **result,
            "created": True,
            "managed": self._managed(resolution.database),
        }

    def gc_candidates(self) -> list[dict[str, str]]:
        """Return stale managed databases without performing database operations."""
        if not self.resolution.enabled or self.state_store is None:
            return []
        if self.resolution.common_dir is None:
            raise BranchDatabaseGitError("Git common directory is unavailable for GC")
        git_info = GitBranchInfo(
            root=self.resolution.git_root or self.resolution.common_dir,
            git_dir=self.resolution.git_dir or self.resolution.common_dir,
            common_dir=self.resolution.common_dir,
            branch=self.resolution.branch,
            detached=False,
        )
        local_branches = list_local_git_branches(git_info)
        candidates = []
        for branch, record in self.state_store.records().items():
            database = record["database"]
            if (
                branch == self.resolution.base_branch
                or branch == self.resolution.branch
                or branch in local_branches
                or database == self.resolution.base_database
                or database == self.resolution.database
            ):
                continue
            candidates.append({"branch": branch, "database": database})
        return sorted(candidates, key=lambda item: (item["branch"], item["database"]))

    def gc(self, *, apply: bool = False) -> dict[str, Any]:
        """List stale managed databases, or explicitly delete them when applied."""
        candidates = self.gc_candidates()
        result: dict[str, Any] = {
            "success": True,
            "operation": "branch_db_gc",
            "dry_run": not apply,
            "candidates": candidates,
            "deleted": [],
            "already_missing": [],
            "errors": [],
        }
        if not apply:
            return result

        if self.state_store is None:
            return result
        for candidate in candidates:
            branch = candidate["branch"]
            database = candidate["database"]
            exists, check = self._exists(database)
            if exists is None:
                result["errors"].append(
                    {
                        **candidate,
                        "error": check.get("error", "Database existence check failed"),
                    }
                )
                continue
            if not exists:
                self.state_store.remove(branch, database)
                result["already_missing"].append(candidate)
                continue

            dropped = self._operations(database).drop_db_with_filestore(
                database, suppress_output=True
            )
            if dropped and dropped.get("success", False):
                self.state_store.remove(branch, database)
                result["deleted"].append(candidate)
            else:
                result["errors"].append(
                    {
                        **candidate,
                        "error": dropped.get("error", "Odoo database drop failed")
                        if dropped
                        else "Odoo database drop failed",
                    }
                )
        result["success"] = not result["errors"]
        return result
