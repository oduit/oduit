from __future__ import annotations

import re
from textwrap import dedent
from typing import Any

from .. import output as _output_module
from ..builders import DatabaseCommandBuilder
from ..exceptions import ConfigError, DatabaseOperationError
from ..output import print_error, print_error_result, print_info
from .base import OperationsService


class DatabaseOperationsService(OperationsService):
    """Database command helpers."""

    @staticmethod
    def _country_update_code(country: str) -> str:
        country_code = country.strip().upper()
        return dedent(
            f"""
            _oduit_country_code = {country_code!r}
            _oduit_country = env["res.country"].search(
                [("code", "=", _oduit_country_code)],
                limit=1,
            )
            if not _oduit_country:
                raise ValueError(
                    f"Country {{_oduit_country_code!r}} not found in res.country"
                )
            _oduit_company = env.company or env["res.company"].search([], limit=1)
            if not _oduit_company:
                raise ValueError("No main company found")
            _oduit_company.country_id = _oduit_country.id
            if _oduit_company.partner_id:
                _oduit_company.partner_id.country_id = _oduit_country.id
            {{
                "country_code": _oduit_country_code,
                "company_id": _oduit_company.id,
                "partner_id": _oduit_company.partner_id.id
                    if _oduit_company.partner_id else None,
            }}
            """
        ).strip()

    def _run_country_post_init_update(self, country: str) -> dict:
        return self.operations.execute_code(
            self._country_update_code(country),
            commit=True,
        )

    @staticmethod
    def _merge_create_db_results(
        *results: dict | None,
    ) -> tuple[bool, int]:
        for result in results:
            if result and not result.get("success", False):
                return False, int(result.get("return_code", 1) or 1)
        return True, 0

    @staticmethod
    def _series_major(odoo_series: Any | None) -> int | None:
        if odoo_series is None:
            return None
        raw = str(getattr(odoo_series, "value", odoo_series))
        match = re.search(r"(\d+)(?:[._]\d+)?", raw)
        return int(match.group(1)) if match else None

    @staticmethod
    def _admin_update_code(
        username: str,
        password: str,
        language: str | None,
    ) -> str:
        return dedent(
            f"""
            _oduit_username = {username!r}
            _oduit_password = {password!r}
            _oduit_language = {language!r}
            _oduit_admin = env.ref("base.user_admin")
            _oduit_values = {{
                "login": _oduit_username,
                "password": _oduit_password,
            }}
            if _oduit_language:
                _oduit_values["lang"] = _oduit_language
            try:
                _oduit_emails = odoo.tools.email_split(_oduit_username)
            except ValueError:
                _oduit_emails = []
            if _oduit_emails:
                _oduit_values["email"] = _oduit_emails[0]
            _oduit_admin.write(_oduit_values)
            {{"login": _oduit_admin.login, "user_id": _oduit_admin.id}}
            """
        ).strip()

    def _run_admin_post_init_update(
        self,
        *,
        username: str,
        password: str,
        language: str | None,
    ) -> dict:
        code = self._admin_update_code(
            username=username,
            password=password,
            language=language,
        )
        return self.operations.execute_code(
            code,
            commit=True,
        )

    def _run_native_create_init(
        self,
        *,
        init_command: list[str],
        suppress_output: bool,
    ) -> dict | None:
        return self.operations.process_manager.run_command(
            init_command,
            verbose=self.operations.verbose,
            suppress_output=suppress_output,
        )

    def _run_legacy_create_init(
        self,
        *,
        create_operation: Any,
        init_command: list[str],
        suppress_output: bool,
        country: str | None,
        username: str,
        password: str,
        language: str | None,
    ) -> tuple[dict | None, dict | None, dict | None, dict | None]:
        create_result = self.operations.process_manager.run_operation(
            create_operation,
            verbose=self.operations.verbose,
            suppress_output=suppress_output,
        )
        if not create_result or not create_result.get("success", False):
            return create_result, None, None, None

        init_result = self.operations.process_manager.run_command(
            init_command,
            verbose=self.operations.verbose,
            suppress_output=suppress_output,
        )
        if not init_result or not init_result.get("success", False):
            return create_result, init_result, None, None

        country_result = None
        if country:
            country_result = self._run_country_post_init_update(country)

        admin_result = self._run_admin_post_init_update(
            username=username,
            password=password,
            language=language,
        )
        return create_result, init_result, country_result, admin_result

    def _run_optional_command(self, command: list[str] | None, warning: str) -> None:
        if not command:
            return
        command_result = self.operations.process_manager.run_command(
            command,
            verbose=self.operations.verbose,
        )
        if command_result and not command_result.get("success", False):
            print_error(
                f"Warning: {warning}: {command_result.get('stderr', '').strip()}"
            )

    def db_exists(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        db_user: str | None = None,
    ) -> dict:
        """Check if database exists and return operation result

        Args:
            with_sudo: Use sudo for database operations (default True)
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error
            db_user: Database user to connect as (optional)

        Returns:
            Dictionary with operation result including success status, exists flag,
            and command details. The 'exists' key indicates if database exists.

        Raises:
            DatabaseOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid

        Example:
            >>> ops = OdooOperations(config)
            >>> result = ops.db_exists()
            >>> if result['exists']:
            >>>     print("Database exists")
        """
        db_name = self.operations.config.get_optional("db_name", "unknown")

        builder = DatabaseCommandBuilder(self.operations.config, with_sudo=with_sudo)
        exists_operation = builder.exists_db_command(db_user=db_user).build_operation()

        try:
            if self.operations.verbose and not suppress_output:
                print_info(f"Checking if database exists: {db_name}")

            exists_result = self.operations.process_manager.run_operation(
                exists_operation,
                verbose=self.operations.verbose,
                suppress_output=suppress_output,
            )

            stdout = exists_result.get("stdout", "") if exists_result else ""
            exists = stdout.strip() == "1"
            check_success = (
                exists_result.get("success", False) if exists_result else False
            )

            final_result = {
                "success": check_success,
                "exists": exists,
                "return_code": exists_result.get("return_code", 1)
                if exists_result
                else 1,
                "command": exists_operation.command,
                "operation": "exists_db",
                "database": db_name,
            }

            if exists_result:
                final_result.update(
                    {
                        "stdout": exists_result.get("stdout", ""),
                        "stderr": exists_result.get("stderr", ""),
                    }
                )
                if exists_result.get("error"):
                    final_result["error"] = exists_result["error"]
                elif not check_success:
                    output = (
                        exists_result.get("stderr") or exists_result.get("stdout") or ""
                    ).strip()
                    if output:
                        final_result["error"] = output

        except ConfigError as e:
            final_result = {
                "success": False,
                "exists": False,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not final_result.get("success", False):
            raise DatabaseOperationError(
                final_result.get("error", "Database exists check operation failed"),
                operation_result=final_result,
            )

        return final_result

    def drop_db(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
    ) -> dict:
        """Drop database and return operation result

        Args:
            with_sudo: Use sudo for database operations (default True)
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error

        Returns:
            Dictionary with operation result including success status and command.

        Raises:
            DatabaseOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid
        """
        db_name = self.operations.config.get_optional("db_name", "unknown")

        builder = DatabaseCommandBuilder(self.operations.config, with_sudo=with_sudo)
        drop_operation = builder.drop_command().build_operation()

        try:
            if self.operations.verbose and not suppress_output:
                print_info(f"Dropping database: {db_name}")

            drop_result = self.operations.process_manager.run_operation(
                drop_operation,
                verbose=self.operations.verbose,
                suppress_output=suppress_output,
            )

            drop_success = drop_result.get("success", False) if drop_result else False

            final_result = {
                "success": drop_success,
                "return_code": drop_result.get("return_code", 1) if drop_result else 1,
                "command": drop_operation.command,
                "operation": "drop_database",
                "database": db_name,
            }

            if drop_result:
                final_result.update(
                    {
                        "stdout": drop_result.get("stdout", ""),
                        "stderr": drop_result.get("stderr", ""),
                    }
                )

        except ConfigError as e:
            final_result = {
                "success": False,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not final_result.get("success", False):
            raise DatabaseOperationError(
                final_result.get("error", "Database drop operation failed"),
                operation_result=final_result,
            )

        return final_result

    def create_db(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        create_role: bool = False,
        alter_role: bool = False,
        extension: str | None = None,
        raise_on_error: bool = False,
        db_user: str | None = None,
        with_demo: bool = False,
        without_demo: bool = False,
        country: str | None = None,
        language: str | None = None,
        username: str = "admin",
        password: str = "admin",
        odoo_series: Any | None = None,
    ) -> dict:
        """Create database and return operation result

        Args:
            with_sudo: Use sudo for database operations (default True)
            suppress_output: Suppress all output (for programmatic use)
            create_role: Create database role before creating database
            alter_role: Alter database role before creating database
            extension: Create extension in database (e.g., 'postgis')
            raise_on_error: Raise exception on failure instead of returning error
            db_user: Database user for role operations (optional)
            with_demo: Initialize with demo data
            without_demo: Explicitly request no demo data
            country: Country ISO code for main company
            language: Default language for initialization
            username: New database admin username
            password: New database admin password
            odoo_series: Explicit Odoo series hint for strategy selection

        Returns:
            Dictionary with operation result including success status and command.

        Raises:
            DatabaseOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid
        """
        if with_demo and without_demo:
            raise ValueError("--with-demo and --without-demo are mutually exclusive")

        db_name = self.operations.config.get_optional("db_name", "unknown")
        use_native_db_init = (self._series_major(odoo_series) or 0) >= 19

        create_result = None
        init_result = None
        country_result = None
        admin_result = None
        cmd_role = None
        cmd_alter = None
        cmd_extension = None

        if create_role:
            builder = DatabaseCommandBuilder(
                self.operations.config, with_sudo=with_sudo
            )
            cmd_role = builder.create_role_command(db_user=db_user).build()
        if alter_role:
            builder = DatabaseCommandBuilder(
                self.operations.config, with_sudo=with_sudo
            )
            cmd_alter = builder.alter_role_command(db_user=db_user).build()
        if extension is not None:
            builder = DatabaseCommandBuilder(
                self.operations.config, with_sudo=with_sudo
            )
            cmd_extension = builder.create_extension_command(extension).build()

        create_operation = None
        if not use_native_db_init:
            create_operation = (
                DatabaseCommandBuilder(self.operations.config, with_sudo=with_sudo)
                .create_command(db_user=db_user)
                .build_operation()
            )

        init_builder = DatabaseCommandBuilder(self.operations.config, with_sudo=False)
        if use_native_db_init:
            init_command = init_builder.native_db_init_command(
                with_demo=with_demo,
                without_demo=without_demo,
                country=country,
                language=language,
                username=username,
                password=password,
            ).build()
        else:
            init_command = init_builder.legacy_init_base_command(
                with_demo=with_demo,
                without_demo=without_demo,
                language=language,
            ).build()

        try:
            if self.operations.verbose and not suppress_output:
                print_info(f"Creating database: {db_name}")

            self._run_optional_command(cmd_role, "Role creation command failed")
            self._run_optional_command(cmd_alter, "Role alteration command failed")
            self._run_optional_command(
                cmd_extension,
                "Extension creation command failed",
            )

            if use_native_db_init:
                init_result = self._run_native_create_init(
                    init_command=init_command,
                    suppress_output=suppress_output,
                )
            else:
                (
                    create_result,
                    init_result,
                    country_result,
                    admin_result,
                ) = self._run_legacy_create_init(
                    create_operation=create_operation,
                    init_command=init_command,
                    suppress_output=suppress_output,
                    country=country,
                    username=username,
                    password=password,
                    language=language,
                )

            success, return_code = self._merge_create_db_results(
                create_result if not use_native_db_init else None,
                init_result,
                country_result,
                admin_result if not use_native_db_init else None,
            )
            final_result = {
                "success": success,
                "return_code": return_code,
                "command": (
                    init_command if use_native_db_init else create_operation.command
                ),
                "init_command": init_command,
                "operation": "create_database",
                "database": db_name,
                "with_demo": with_demo,
                "without_demo": (not with_demo),
                "username": username,
                "password_set": bool(password),
            }

            if create_result:
                final_result.update(
                    {
                        "stdout": create_result.get("stdout", ""),
                        "stderr": create_result.get("stderr", ""),
                    }
                )
            if init_result:
                final_result["init_stdout"] = init_result.get("stdout", "")
                final_result["init_stderr"] = init_result.get("stderr", "")
                final_result["stdout"] = (
                    f"{final_result.get('stdout', '')}{init_result.get('stdout', '')}"
                )
            if country_result:
                final_result["country_result"] = country_result
            if admin_result:
                final_result["admin_result"] = {
                    "success": bool(admin_result.get("success", False)),
                    "username": username,
                    "password_set": bool(password),
                }
            for partial in (create_result, init_result, country_result, admin_result):
                if partial and not partial.get("success", False):
                    error_text = (
                        partial.get("error")
                        or partial.get("stderr")
                        or partial.get("stdout")
                        or "Database operation failed"
                    )
                    normalized_error = str(error_text).strip()
                    final_result["error"] = (
                        normalized_error or "Database operation failed"
                    )
                    break

        except ConfigError as e:
            final_result = {
                "success": False,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not final_result.get("success", False):
            raise DatabaseOperationError(
                final_result.get("error", "Database operation failed"),
                operation_result=final_result,
            )

        return final_result

    def list_db(
        self,
        with_sudo: bool = True,
        suppress_output: bool = False,
        raise_on_error: bool = False,
        db_user: str | None = None,
    ) -> dict:
        """List all databases and return operation result

        Args:
            with_sudo: Use sudo for database operations (default True)
            suppress_output: Suppress all output (for programmatic use)
            raise_on_error: Raise exception on failure instead of returning error
            db_user: Database user to connect as (optional)

        Returns:
            Dictionary with operation result including success status and command.

        Raises:
            DatabaseOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid
        """
        builder = DatabaseCommandBuilder(self.operations.config, with_sudo=with_sudo)
        list_operation = builder.list_db_command(db_user=db_user).build_operation()

        try:
            if self.operations.verbose and not suppress_output:
                print_info("Listing databases...")

            list_result = self.operations.process_manager.run_operation(
                list_operation,
                verbose=self.operations.verbose,
                suppress_output=suppress_output,
            )

            list_success = list_result.get("success", False) if list_result else False

            final_result = {
                "success": list_success,
                "return_code": list_result.get("return_code", 1) if list_result else 1,
                "command": list_operation.command,
                "operation": "list_db",
            }

            if list_result:
                final_result.update(
                    {
                        "stdout": list_result.get("stdout", ""),
                        "stderr": list_result.get("stderr", ""),
                    }
                )

        except ConfigError as e:
            final_result = {
                "success": False,
                "error": str(e),
                "error_type": "ConfigError",
            }
            if not suppress_output:
                if _output_module._formatter.format_type == "json":
                    print_error_result(str(e), 1)
                else:
                    print_error(str(e))

        if raise_on_error and not final_result.get("success", False):
            error_msg = final_result.get("error", "Database list operation failed")
            if not isinstance(error_msg, str):
                error_msg = str(error_msg)
            raise DatabaseOperationError(
                error_msg,
                operation_result=final_result,
            )

        return final_result
