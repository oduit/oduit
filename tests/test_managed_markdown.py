from __future__ import annotations

from oduit.managed_markdown import (
    GeneratedMarkdownBlock,
    parse_generated_blocks,
    refresh_generated_blocks,
    render_generated_block,
)


def _block(*, depends: list[str] | None = None) -> GeneratedMarkdownBlock:
    values = depends or ["base"]
    body = (
        "Derived from oduit evidence:\n\n"
        "| Constraint | Value | Evidence |\n"
        "|---|---|---|\n"
        f"| Declared dependencies | "
        f"{', '.join(f'`{item}`' for item in values)} "
        "| manifest depends |\n"
    )
    return GeneratedMarkdownBlock(
        id="arc42.constraints",
        renderer="arc42.constraints.v1",
        body=body,
        source_payload={"depends": values},
    )


def test_render_generated_block_has_canonical_marker_metadata() -> None:
    rendered = render_generated_block(_block())
    first_line = rendered.splitlines()[0]
    assert first_line.startswith("<!-- oduit:generated:start {")
    assert '"content_sha256"' in first_line
    assert '"id":"arc42.constraints"' in first_line
    assert '"renderer":"arc42.constraints.v1"' in first_line
    assert '"schema_version":"oduit.generated_markdown_block.v1"' in first_line
    assert '"source_sha256"' in first_line


def test_parse_generated_blocks_returns_block_details() -> None:
    markdown = (
        "## 2. Architecture Constraints\n\n" + render_generated_block(_block()) + "\n"
    )
    parsed = parse_generated_blocks(markdown)
    assert len(parsed) == 1
    assert parsed[0].id == "arc42.constraints"
    assert parsed[0].renderer == "arc42.constraints.v1"
    assert "Declared dependencies" in parsed[0].body
    assert parsed[0].start_line > 0
    assert parsed[0].end_line > parsed[0].start_line


def test_refresh_generated_blocks_keeps_unchanged_content() -> None:
    current = render_generated_block(_block())
    result = refresh_generated_blocks(current, {"arc42.constraints": _block()})
    assert result.changed is False
    assert result.errors == []
    assert result.markdown == current
    assert any(change.status == "unchanged" for change in result.changes)


def test_refresh_generated_blocks_updates_source_changed_unedited_block() -> None:
    current = render_generated_block(_block(depends=["base"]))
    updated = _block(depends=["base", "mail"])
    result = refresh_generated_blocks(current, {"arc42.constraints": updated})
    assert result.errors == []
    assert result.changed is True
    assert "| Declared dependencies | `base`, `mail` |" in result.markdown
    assert any(change.status == "updated" for change in result.changes)


def test_refresh_generated_blocks_blocks_manual_edits_without_force() -> None:
    current = render_generated_block(_block()).replace(
        "manifest depends", "manifest deps"
    )
    result = refresh_generated_blocks(
        current, {"arc42.constraints": _block(depends=["base", "mail"])}
    )
    assert result.changed is False
    assert result.errors
    assert any(change.status == "edited" for change in result.changes)


def test_refresh_generated_blocks_overwrites_manual_edits_with_force() -> None:
    current = render_generated_block(_block()).replace(
        "manifest depends", "manifest deps"
    )
    result = refresh_generated_blocks(
        current,
        {"arc42.constraints": _block(depends=["base", "mail"])},
        overwrite_edited=True,
    )
    assert result.errors == []
    assert result.changed is True
    assert "| Declared dependencies | `base`, `mail` |" in result.markdown


def test_parse_generated_blocks_fails_on_duplicate_ids() -> None:
    one = render_generated_block(_block())
    two = render_generated_block(_block())
    result = refresh_generated_blocks(
        f"{one}\n\n{two}\n", {"arc42.constraints": _block()}
    )
    assert result.errors
    assert "Duplicate generated block id" in result.errors[0]


def test_parse_generated_blocks_fails_on_malformed_start_marker() -> None:
    markdown = (
        "<!-- oduit:generated:start {not-json} -->\n"
        "body\n<!-- oduit:generated:end -->\n"
    )
    result = refresh_generated_blocks(markdown, {"arc42.constraints": _block()})
    assert result.errors
    assert "Malformed generated block marker" in result.errors[0]


def test_refresh_generated_blocks_preserves_unknown_block_with_warning() -> None:
    unknown = GeneratedMarkdownBlock(
        id="arc42.unknown",
        renderer="arc42.unknown.v1",
        body="body\n",
        source_payload={"x": 1},
    )
    markdown = render_generated_block(unknown)
    result = refresh_generated_blocks(markdown, {"arc42.constraints": _block()})
    assert result.errors == []
    assert result.changed is False
    assert result.warnings
    assert any(change.status == "unknown" for change in result.changes)


def test_refresh_generated_blocks_reports_missing_known_blocks_without_insert() -> None:
    markdown = "## Manual only\n"
    result = refresh_generated_blocks(markdown, {"arc42.constraints": _block()})
    assert result.errors == []
    assert result.changed is False
    assert result.warnings
    assert any(change.status == "missing" for change in result.changes)


def test_refresh_generated_blocks_normalizes_crlf_input() -> None:
    markdown = render_generated_block(_block()).replace("\n", "\r\n")
    result = refresh_generated_blocks(markdown, {"arc42.constraints": _block()})
    assert result.errors == []
    assert "\r\n" not in result.markdown
