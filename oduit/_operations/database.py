from __future__ import annotations

from .. import output as _output_module
from ..builders import DatabaseCommandBuilder
from ..exceptions import ConfigError, DatabaseOperationError
from ..output import print_error, print_error_result, print_info
from .base import OperationsService


class DatabaseOperationsService(OperationsService):
    """Database command helpers."""

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

        Returns:
            Dictionary with operation result including success status and command.

        Raises:
            DatabaseOperationError: If raise_on_error=True and operation fails
            ConfigError: If configuration is invalid
        """
        db_name = self.operations.config.get_optional("db_name", "unknown")

        create_result = None
        cmd_role = None
        cmd_alter = None
        cmd_extension = None

        builder = DatabaseCommandBuilder(self.operations.config, with_sudo=with_sudo)
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

        builder = DatabaseCommandBuilder(self.operations.config, with_sudo=with_sudo)
        create_operation = builder.create_command().build_operation()

        try:
            if self.operations.verbose and not suppress_output:
                print_info(f"Creating database: {db_name}")

            if cmd_role:
                role_result = self.operations.process_manager.run_command(
                    cmd_role, verbose=self.operations.verbose
                )
                if role_result and not role_result.get("success", False):
                    print_error(
                        f"Warning: Role creation command failed: "
                        f"{role_result.get('stderr', '').strip()}"
                    )
            if cmd_alter:
                alter_result = self.operations.process_manager.run_command(
                    cmd_alter, verbose=self.operations.verbose
                )
                if alter_result and not alter_result.get("success", False):
                    print_error(
                        f"Warning: Role alteration command failed: "
                        f"{alter_result.get('stderr', '').strip()}"
                    )
            if cmd_extension:
                extension_result = self.operations.process_manager.run_command(
                    cmd_extension, verbose=self.operations.verbose
                )
                if extension_result and not extension_result.get("success", False):
                    print_error(
                        f"Warning: Extension creation command failed: "
                        f"{extension_result.get('stderr', '').strip()}"
                    )

            create_result = self.operations.process_manager.run_operation(
                create_operation,
                verbose=self.operations.verbose,
                suppress_output=suppress_output,
            )

            create_success = (
                create_result.get("success", False) if create_result else False
            )

            create_return_code = (
                create_result.get("return_code", 1) if create_result else 1
            )
            final_result = {
                "success": create_success,
                "return_code": create_return_code,
                "command": create_operation.command,
                "operation": "create_database",
                "database": db_name,
            }

            if create_result:
                final_result.update(
                    {
                        "stdout": create_result.get("stdout", ""),
                        "stderr": create_result.get("stderr", ""),
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
