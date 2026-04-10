from pathlib import Path

from oduit.cli_typer import agent_app

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
        '"schema_version": "2.0"',
        "controlled_runtime_mutation",
        "controlled_source_mutation",
        "validate-addon-change",
        "oduit --env dev agent context",
        "oduit --env dev agent inspect-addon my_partner",
        "oduit --env dev agent plan-update my_partner",
        (
            "oduit --env dev agent test-summary --allow-mutation --module "
            "my_partner --test-tags /my_partner"
        ),
    ]

    failures = [marker for marker in required_markers if marker not in content]
    assert not failures, "Missing markers in docs/agent_contract.rst:\n" + "\n".join(
        failures
    )


def test_public_api_inventory_lists_all_agent_commands() -> None:
    content = (ROOT / "docs" / "maintainer" / "public_api.md").read_text().splitlines()
    section_header = "## `oduit agent` subcommands in `oduit.cli_typer`"
    start_index = content.index(section_header) + 1
    documented_commands: set[str] = set()

    for line in content[start_index:]:
        if line.startswith("## "):
            break
        if line.startswith("- `") and line.endswith("`"):
            documented_commands.add(line[3:-1])

    actual_commands = {
        command.name for command in agent_app.registered_commands if command.name
    }
    assert documented_commands == actual_commands
