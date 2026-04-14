from pathlib import Path

from oduit.cli.app import agent_app
from oduit.cli.command_inventory import (
    render_agent_inventory_rst,
    render_cli_inventory_rst,
    render_public_api_agent_section_markdown,
    render_public_api_cli_section_markdown,
)

ROOT = Path(__file__).resolve().parent.parent
DOC_FILES = [
    ROOT / "README.md",
    ROOT / "examples" / "README.md",
    ROOT / "examples" / "code_executor_example.py",
    ROOT / "examples" / "execute_python_example.py",
    ROOT / "examples" / "module_manifest_example.py",
    *sorted((ROOT / "docs").rglob("*.md")),
    *sorted((ROOT / "docs").rglob("*.rst")),
]


def _read_docs() -> dict[Path, str]:
    return {path: path.read_text() for path in DOC_FILES}


def _extract_markdown_section(content: str, header: str) -> str:
    lines = content.splitlines()
    start_index = lines.index(header)
    end_index = len(lines)
    for index in range(start_index + 1, len(lines)):
        if lines[index].startswith("## "):
            end_index = index
            break
    return "\n".join(lines[start_index:end_index]).strip()


def test_docs_do_not_reference_removed_or_stale_api_symbols() -> None:
    docs = _read_docs()
    banned_patterns = {
        "list_modules(": "ModuleManager.list_modules() is not implemented",
        "get_module_status(": "ModuleManager.get_module_status() is not implemented",
        "discover_addons(": "ModuleManager.discover_addons() is not implemented",
        "validate_module(": "ModuleManager.validate_module() is not implemented",
        "install_modules(": "Bulk OdooOperations install API is not implemented",
        "update_modules(": "Bulk OdooOperations update API is not implemented",
        "uninstall_modules(": "Bulk uninstall API is not implemented",
        "run_all_tests(": "run_all_tests() is not implemented",
        "create_database(": "Use create_db() instead",
        "drop_database(": "Use drop_db() instead",
        "backup_database(": "backup_database() is not implemented",
        "ModuleManager(config)": "ModuleManager expects addons_path, not a config dict",
        "configure_output(verbose=": "configure_output() no longer accepts verbose=",
        "configure_output(verbose =": "configure_output() no longer accepts verbose=",
        "configure_output(color=": "configure_output() no longer accepts color=",
        "configure_output(color =": "configure_output() no longer accepts color=",
        "use_colors=": "OutputFormatter does not accept use_colors=",
        "timestamp=True": "OutputFormatter does not accept timestamp=",
        'prefix="[ODUIT]"': "OutputFormatter does not accept prefix=",
        "run_demo_scenario(": (
            "DemoProcessManager.run_demo_scenario() is not implemented"
        ),
        "setup_demo_environment(": (
            "DemoProcessManager.setup_demo_environment() is not implemented"
        ),
        "run_comparison_scenarios(": (
            "DemoProcessManager.run_comparison_scenarios() is not implemented"
        ),
        "cleanup_demo_data(": (
            "DemoProcessManager.cleanup_demo_data() is not implemented"
        ),
        "embedded execution mode": "Embedded mode should not be advertised publicly",
        "list-addons --type installed": (
            "Use list-installed-addons for runtime installed-addon inventory"
        ),
        "``--type [all|installed|available]``": (
            "list-addons no longer exposes a --type option"
        ),
        "db_risk_level": "db_risk_level has been removed from the public contract",
    }

    failures: list[str] = []
    for path, content in docs.items():
        for banned, reason in banned_patterns.items():
            if banned in content:
                failures.append(f"{path.relative_to(ROOT)}: {reason}: {banned}")

    assert not failures, "\n".join(failures)


def test_docs_do_not_show_run_command_timeout_signature() -> None:
    docs = _read_docs()
    failures = [
        str(path.relative_to(ROOT))
        for path, content in docs.items()
        if "run_command([" in content and "timeout=" in content
    ]
    assert not failures, (
        "timeout= should not be documented on run_command():\n" + "\n".join(failures)
    )


def test_raw_executor_examples_keep_allow_unsafe_opt_in() -> None:
    targets = [
        ROOT / "README.md",
        ROOT / "docs/api/odoo_code_executor.rst",
        ROOT / "examples" / "code_executor_example.py",
    ]
    failures: list[str] = []

    for path in targets:
        content = path.read_text()
        for marker in ("execute_code(", "execute_multiple("):
            start = 0
            while True:
                index = content.find(marker, start)
                if index == -1:
                    break
                window = content[index : index + 250]
                if "allow_unsafe=True" not in window:
                    failures.append(
                        f"{path.relative_to(ROOT)} missing allow_unsafe near {marker}"
                    )
                start = index + len(marker)

    assert not failures, "\n".join(failures)


def test_execute_python_code_docs_note_shell_interface_requirement() -> None:
    targets = [
        ROOT / "README.md",
        ROOT / "docs/api/odoo_operations.rst",
        ROOT / "examples" / "README.md",
        ROOT / "examples" / "execute_python_example.py",
    ]
    failures = []

    for path in targets:
        content = path.read_text()
        if "execute_python_code" in content and "shell_interface" not in content:
            failures.append(
                f"{path.relative_to(ROOT)} missing shell_interface near "
                "execute_python_code docs"
            )

    assert not failures, "\n".join(failures)


def test_agent_contract_page_covers_required_topics() -> None:
    content = (ROOT / "docs" / "agent_contract.rst").read_text()
    required_markers = [
        "Using oduit from a coding agent",
        "single source of truth",
        "Recommended Command Sequence",
        "Mutation Policy",
        "Payload Expectations",
        "Failure Handling",
        "Stability Tiers",
        "error_code",
        "generated_at",
        '"schema_version": "2.0"',
        "stable_for_agents",
        "controlled_runtime_mutation",
        "controlled_source_mutation",
        "validate-addon-change",
        "oduit --env dev agent context",
        "oduit --env dev agent inspect-addon my_partner",
        "oduit --env dev agent plan-update my_partner",
        (
            "oduit --env dev agent test-summary --module "
            "my_partner --test-tags /my_partner"
        ),
    ]

    failures = [marker for marker in required_markers if marker not in content]
    assert not failures, "Missing markers in docs/agent_contract.rst:\n" + "\n".join(
        failures
    )


def test_generated_command_inventory_pages_match_renderer() -> None:
    assert (
        ROOT / "docs" / "command_inventory.rst"
    ).read_text() == render_cli_inventory_rst()
    assert (ROOT / "docs" / "agent_command_inventory.rst").read_text() == (
        render_agent_inventory_rst()
    )


def test_installation_docs_match_packaging_metadata() -> None:
    content = (ROOT / "docs" / "installation.rst").read_text()
    assert "Python 3.10 or higher" in content
    assert 'pip install -e ".[dev]"' not in content
    assert "typing-extensions" not in content
    for marker in ("PyYAML", "tomli", "tomli-w", "typer", "manifestoo-core"):
        assert marker in content


def test_cli_api_docs_mark_canonical_and_compatibility_modules() -> None:
    cli_app_content = (ROOT / "docs" / "api" / "cli_app.rst").read_text()
    cli_typer_content = (ROOT / "docs" / "api" / "cli_typer.rst").read_text()
    api_index_content = (ROOT / "docs" / "api.rst").read_text()

    assert "canonical Typer composition root" in cli_app_content
    assert "compatibility facade" in cli_typer_content
    assert "canonical CLI composition root" in api_index_content


def test_readme_and_quickstart_show_agent_verification_loop() -> None:
    targets = [
        ROOT / "README.md",
        ROOT / "docs" / "quickstart.rst",
    ]
    required_markers = [
        "oduit --env dev agent context",
        (
            "oduit --env dev agent get-model-fields res.partner --attributes "
            "string,type,required"
        ),
        "oduit --env dev agent locate-model res.partner --module my_partner",
        "oduit --env dev agent validate-addon-change my_partner --allow-mutation",
        (
            "oduit --env dev agent test-summary --module "
            "my_partner --test-tags /my_partner"
        ),
    ]

    for path in targets:
        content = path.read_text()
        missing = [marker for marker in required_markers if marker not in content]
        assert not missing, f"{path.relative_to(ROOT)} missing markers:\n" + "\n".join(
            missing
        )


def test_runtime_addon_docs_use_explicit_installed_inventory_command() -> None:
    targets = [
        ROOT / "README.md",
        ROOT / "docs" / "cli.rst",
        ROOT / "docs" / "maintainer" / "public_api.md",
    ]
    missing = [
        str(path.relative_to(ROOT))
        for path in targets
        if "list-installed-addons" not in path.read_text()
    ]
    assert not missing, (
        "Installed-addon inventory docs should use the explicit runtime command:\n"
        + "\n".join(missing)
    )


def test_runtime_inspection_docs_cover_new_command_surface() -> None:
    targets = [
        ROOT / "README.md",
        ROOT / "docs" / "cli.rst",
        ROOT / "docs" / "quickstart.rst",
    ]
    required_markers = [
        "oduit --env dev exec \"env['res.partner']._table\"",
        "oduit --env dev inspect ref base.action_partner_form",
        "oduit --env dev inspect model res.partner",
        "oduit --env dev inspect field res.partner email --with-db",
        "oduit --env dev db table res_partner",
        "oduit --env dev manifest check sale",
        "oduit --env dev agent inspect-ref base.action_partner_form",
        "oduit --env dev agent inspect-model res.partner",
        "oduit --env dev agent inspect-field res.partner email --with-db",
        "oduit --env dev agent db-table res_partner",
        "oduit --env dev agent manifest-check sale",
    ]

    for path in targets:
        content = path.read_text()
        missing = [marker for marker in required_markers if marker not in content]
        assert not missing, f"{path.relative_to(ROOT)} missing markers:\n" + "\n".join(
            missing
        )


def test_api_docs_include_odoo_inspector_surface() -> None:
    api_index = (ROOT / "docs" / "api.rst").read_text()
    inspector_doc = (ROOT / "docs" / "api" / "odoo_inspector.rst").read_text()
    operations_doc = (ROOT / "docs" / "api" / "odoo_operations.rst").read_text()

    assert "api/odoo_inspector" in api_index
    assert "OdooInspector" in inspector_doc
    assert "inspect_ref()" in operations_doc
    assert "describe_table()" in operations_doc


def test_public_api_inventory_lists_all_agent_commands() -> None:
    content = (ROOT / "docs" / "maintainer" / "public_api.md").read_text()
    cli_header = "## CLI commands in `oduit.cli.app`"
    agent_header = "## `oduit agent` subcommands in `oduit.cli.app`"

    assert _extract_markdown_section(content, cli_header) == (
        render_public_api_cli_section_markdown()
    )
    assert _extract_markdown_section(content, agent_header) == (
        render_public_api_agent_section_markdown()
    )

    actual_commands = {
        command.name for command in agent_app.registered_commands if command.name
    }
    documented_commands = {
        line.split("`")[1]
        for line in render_public_api_agent_section_markdown().splitlines()
        if line.startswith("| `")
    }
    assert documented_commands == actual_commands


def test_agent_contract_change_log_exists() -> None:
    content = (ROOT / "docs" / "maintainer" / "agent_contract_changes.md").read_text()
    required_markers = [
        "Agent Contract Changes",
        "2.x stability policy",
        "error_code",
        "generated_at",
        "runtime.test_failure",
    ]
    missing = [marker for marker in required_markers if marker not in content]
    assert not missing, "\n".join(missing)
