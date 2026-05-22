from __future__ import annotations

from oduit.managed_markdown import (
    EvidenceSnapshotBlock,
    GeneratedMarkdownBlock,
    parse_evidence_snapshot_blocks,
    parse_generated_blocks,
    refresh_generated_blocks,
    render_evidence_snapshot_block,
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


def test_render_evidence_snapshot_block_has_required_metadata() -> None:
    rendered = render_evidence_snapshot_block(
        EvidenceSnapshotBlock(
            block_id="arc42.addon_overview",
            renderer="arc42.addon_overview.v1",
            evidence_path="docs/architecture.evidence.md",
            evidence_version=3,
            source_sha256="sha256:source",
            content_sha256="sha256:content",
            body="| Item | Count |\n|---|---|\n| File inventory | 58 |\n",
        )
    )
    first_line = rendered.splitlines()[0]
    assert first_line.startswith("<!-- oduit:evidence-snapshot:start {")
    assert '"block_id":"arc42.addon_overview"' in first_line
    assert '"evidence_version":3' in first_line
    assert '"snapshot_sha256"' in first_line


def test_parse_evidence_snapshot_blocks_returns_snapshot_details() -> None:
    markdown = render_evidence_snapshot_block(
        EvidenceSnapshotBlock(
            block_id="arc42.addon_overview",
            renderer="arc42.addon_overview.v1",
            evidence_path="docs/architecture.evidence.md",
            evidence_version=2,
            source_sha256="sha256:source",
            content_sha256="sha256:content",
            body="| Item | Count |\n|---|---|\n| File inventory | 58 |\n",
        )
    )
    parsed = parse_evidence_snapshot_blocks(markdown)
    assert len(parsed) == 1
    assert parsed[0].block_id == "arc42.addon_overview"
    assert parsed[0].renderer == "arc42.addon_overview.v1"
    assert parsed[0].evidence_version == 2
    assert parsed[0].start_line > 0
    assert parsed[0].end_line > parsed[0].start_line


def test_parse_evidence_snapshot_blocks_rejects_malformed_marker() -> None:
    markdown = (
        "<!-- oduit:evidence-snapshot:start {broken-json} -->\n"
        "body\n"
        "<!-- oduit:evidence-snapshot:end -->\n"
    )
    try:
        parse_evidence_snapshot_blocks(markdown)
    except ValueError as exc:
        assert "Malformed evidence snapshot marker" in str(exc)
    else:
        raise AssertionError("Expected parse failure for malformed marker")


def test_parse_evidence_snapshot_blocks_rejects_duplicate_block_ids() -> None:
    block = render_evidence_snapshot_block(
        EvidenceSnapshotBlock(
            block_id="arc42.addon_overview",
            renderer="arc42.addon_overview.v1",
            evidence_path="docs/architecture.evidence.md",
            evidence_version=1,
            source_sha256="sha256:source",
            content_sha256="sha256:content",
            body="x\n",
        )
    )
    try:
        parse_evidence_snapshot_blocks(f"{block}\n\n{block}\n")
    except ValueError as exc:
        assert "Duplicate evidence snapshot block_id" in str(exc)
    else:
        raise AssertionError("Expected duplicate block rejection")


def test_evidence_snapshot_hash_changes_when_body_changes() -> None:
    snapshot = EvidenceSnapshotBlock(
        block_id="arc42.addon_overview",
        renderer="arc42.addon_overview.v1",
        evidence_path="docs/architecture.evidence.md",
        evidence_version=1,
        source_sha256="sha256:source",
        content_sha256="sha256:content",
        body="| Item | Count |\n|---|---|\n| File inventory | 58 |\n",
    )
    edited = EvidenceSnapshotBlock(
        block_id=snapshot.block_id,
        renderer=snapshot.renderer,
        evidence_path=snapshot.evidence_path,
        evidence_version=snapshot.evidence_version,
        source_sha256=snapshot.source_sha256,
        content_sha256=snapshot.content_sha256,
        body="| Item | Count |\n|---|---|\n| File inventory | 60 |\n",
    )
    assert snapshot.snapshot_sha256 != edited.snapshot_sha256
