"""Deterministic managed generated-block helpers for Markdown documents."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "oduit.generated_markdown_block.v1"
START_RE = re.compile(r"^<!--\s*oduit:generated:start\s+({.*})\s*-->\s*$")
END_RE = re.compile(r"^<!--\s*oduit:generated:end\s*-->\s*$")
EVIDENCE_SNAPSHOT_SCHEMA_VERSION = "oduit.evidence_snapshot.v1"
EVIDENCE_SNAPSHOT_START_RE = re.compile(
    r"^<!--\s*oduit:evidence-snapshot:start\s+({.*})\s*-->\s*$"
)
EVIDENCE_SNAPSHOT_END_RE = re.compile(r"^<!--\s*oduit:evidence-snapshot:end\s*-->\s*$")


def normalize_markdown_body(text: str) -> str:
    """Normalize line endings and enforce exactly one trailing newline."""

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.rstrip("\n") + "\n"


def canonical_json_bytes(value: Any) -> bytes:
    """Return stable canonical JSON bytes for hashing."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_text(text: str) -> str:
    """Return prefixed SHA-256 hash of normalized text."""

    return (
        "sha256:"
        + hashlib.sha256(normalize_markdown_body(text).encode("utf-8")).hexdigest()
    )


@dataclass(frozen=True)
class GeneratedMarkdownBlock:
    id: str
    renderer: str
    body: str
    source_payload: Any
    schema_version: str = SCHEMA_VERSION

    @property
    def source_sha256(self) -> str:
        return (
            "sha256:"
            + hashlib.sha256(canonical_json_bytes(self.source_payload)).hexdigest()
        )

    @property
    def content_sha256(self) -> str:
        return sha256_text(self.body)


@dataclass(frozen=True)
class ParsedMarkdownBlock:
    id: str
    renderer: str
    schema_version: str
    start_line: int
    end_line: int
    body: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class EvidenceSnapshotBlock:
    block_id: str
    renderer: str
    evidence_path: str
    evidence_version: int
    source_sha256: str
    content_sha256: str
    body: str
    schema_version: str = EVIDENCE_SNAPSHOT_SCHEMA_VERSION
    copied_at: str | None = None

    @property
    def snapshot_sha256(self) -> str:
        return sha256_text(self.body)


@dataclass(frozen=True)
class ParsedEvidenceSnapshotBlock:
    block_id: str
    renderer: str
    evidence_path: str
    evidence_version: int
    start_line: int
    end_line: int
    body: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class BlockRefreshChange:
    id: str
    renderer: str
    status: str  # unchanged | updated | edited | missing | unknown | malformed
    old_source_sha256: str | None = None
    new_source_sha256: str | None = None
    old_content_sha256: str | None = None
    new_content_sha256: str | None = None


@dataclass(frozen=True)
class BlockRefreshResult:
    markdown: str
    changed: bool
    changes: list[BlockRefreshChange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def render_generated_block(block: GeneratedMarkdownBlock) -> str:
    """Render one managed markdown block with stable marker metadata."""

    metadata = {
        "schema_version": block.schema_version,
        "id": block.id,
        "renderer": block.renderer,
        "source_sha256": block.source_sha256,
        "content_sha256": block.content_sha256,
    }
    json_str = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return (
        "<!-- oduit:generated:start "
        f"{json_str} -->\n"
        f"{normalize_markdown_body(block.body)}"
        "<!-- oduit:generated:end -->"
    )


def parse_generated_blocks(markdown: str) -> list[ParsedMarkdownBlock]:
    """Parse managed markdown blocks line-by-line."""

    blocks: list[ParsedMarkdownBlock] = []
    lines = markdown.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    index = 0
    seen_ids: set[str] = set()
    while index < len(lines):
        start_match = START_RE.match(lines[index])
        if start_match is None:
            index += 1
            continue

        start_line = index + 1
        try:
            metadata = json.loads(start_match.group(1))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Malformed generated block marker at line " f"{start_line}: {exc}"
            ) from exc
        if not isinstance(metadata, dict):
            raise ValueError(
                f"Generated block marker at line {start_line} must contain JSON object."
            )

        block_id = metadata.get("id")
        renderer = metadata.get("renderer")
        schema_version = metadata.get("schema_version")
        if (
            not isinstance(block_id, str)
            or not isinstance(renderer, str)
            or not isinstance(schema_version, str)
        ):
            raise ValueError(
                "Generated block marker missing required string fields "
                f"at line {start_line}."
            )
        if block_id in seen_ids:
            raise ValueError(f"Duplicate generated block id '{block_id}' in document.")
        seen_ids.add(block_id)

        body_lines: list[str] = []
        body_index = index + 1
        while body_index < len(lines) and END_RE.match(lines[body_index]) is None:
            body_lines.append(lines[body_index])
            body_index += 1
        if body_index >= len(lines):
            raise ValueError(f"Missing generated block end marker for '{block_id}'.")

        end_line = body_index + 1
        body = normalize_markdown_body("\n".join(body_lines))
        blocks.append(
            ParsedMarkdownBlock(
                id=block_id,
                renderer=renderer,
                schema_version=schema_version,
                start_line=start_line,
                end_line=end_line,
                body=body,
                metadata=metadata,
            )
        )
        index = body_index + 1

    return blocks


def render_evidence_snapshot_block(snapshot: EvidenceSnapshotBlock) -> str:
    """Render one evidence snapshot marker block for report documents."""

    metadata: dict[str, Any] = {
        "schema_version": snapshot.schema_version,
        "block_id": snapshot.block_id,
        "renderer": snapshot.renderer,
        "evidence_path": snapshot.evidence_path,
        "evidence_version": snapshot.evidence_version,
        "source_sha256": snapshot.source_sha256,
        "content_sha256": snapshot.content_sha256,
        "snapshot_sha256": snapshot.snapshot_sha256,
    }
    if snapshot.copied_at:
        metadata["copied_at"] = snapshot.copied_at
    json_str = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return (
        "<!-- oduit:evidence-snapshot:start "
        f"{json_str} -->\n"
        f"{normalize_markdown_body(snapshot.body)}"
        "<!-- oduit:evidence-snapshot:end -->"
    )


def parse_evidence_snapshot_blocks(markdown: str) -> list[ParsedEvidenceSnapshotBlock]:
    """Parse evidence snapshot blocks line-by-line."""

    blocks: list[ParsedEvidenceSnapshotBlock] = []
    lines = markdown.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    index = 0
    seen_ids: set[str] = set()
    while index < len(lines):
        start_match = EVIDENCE_SNAPSHOT_START_RE.match(lines[index])
        if start_match is None:
            index += 1
            continue

        start_line = index + 1
        try:
            metadata = json.loads(start_match.group(1))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Malformed evidence snapshot marker at line {start_line}: {exc}"
            ) from exc
        if not isinstance(metadata, dict):
            raise ValueError(
                f"Evidence snapshot marker at line {start_line}"
                " must contain JSON object."
            )

        required = {
            "block_id": str,
            "renderer": str,
            "evidence_path": str,
            "source_sha256": str,
            "content_sha256": str,
            "snapshot_sha256": str,
        }
        for field_name, field_type in required.items():
            if not isinstance(metadata.get(field_name), field_type):
                raise ValueError(
                    "Evidence snapshot marker missing required field "
                    f"'{field_name}' at line {start_line}."
                )
        evidence_version = metadata.get("evidence_version")
        if not isinstance(evidence_version, int):
            raise ValueError(
                "Evidence snapshot marker missing required int field "
                f"'evidence_version' at line {start_line}."
            )
        schema_version = metadata.get("schema_version")
        if schema_version != EVIDENCE_SNAPSHOT_SCHEMA_VERSION:
            raise ValueError(
                "Evidence snapshot marker has unsupported schema_version at line "
                f"{start_line}: {schema_version!r}"
            )

        block_id = str(metadata["block_id"])
        if block_id in seen_ids:
            raise ValueError(f"Duplicate evidence snapshot block_id '{block_id}'.")
        seen_ids.add(block_id)

        body_lines: list[str] = []
        body_index = index + 1
        while (
            body_index < len(lines)
            and EVIDENCE_SNAPSHOT_END_RE.match(lines[body_index]) is None
        ):
            body_lines.append(lines[body_index])
            body_index += 1
        if body_index >= len(lines):
            raise ValueError(
                f"Missing evidence snapshot end marker for block_id '{block_id}'."
            )

        body = normalize_markdown_body("\n".join(body_lines))
        blocks.append(
            ParsedEvidenceSnapshotBlock(
                block_id=block_id,
                renderer=str(metadata["renderer"]),
                evidence_path=str(metadata["evidence_path"]),
                evidence_version=evidence_version,
                start_line=start_line,
                end_line=body_index + 1,
                body=body,
                metadata=metadata,
            )
        )
        index = body_index + 1
    return blocks


def _rendered_lines(markdown: str) -> list[str]:
    return markdown.replace("\r\n", "\n").replace("\r", "\n").splitlines(keepends=True)


def _metadata_hash(metadata: Mapping[str, Any], key: str) -> str | None:
    value = metadata.get(key)
    return value if isinstance(value, str) and value.startswith("sha256:") else None


def refresh_generated_blocks(
    markdown: str,
    new_blocks: Mapping[str, GeneratedMarkdownBlock],
    *,
    overwrite_edited: bool = False,
    add_missing: bool = False,
    strict_errors: bool = True,
) -> BlockRefreshResult:
    """Refresh matching managed block bodies and preserve non-managed text."""

    try:
        parsed_blocks = parse_generated_blocks(markdown)
    except ValueError as exc:
        return BlockRefreshResult(
            markdown=markdown,
            changed=False,
            changes=[],
            warnings=[],
            errors=[str(exc)],
        )

    changes: list[BlockRefreshChange] = []
    warnings: list[str] = []
    errors: list[str] = []
    changed = False

    rendered_lines = _rendered_lines(markdown)
    replacement_by_start: dict[int, tuple[int, str]] = {}
    seen_ids = {parsed.id for parsed in parsed_blocks}

    for parsed in parsed_blocks:
        old_source_sha = _metadata_hash(parsed.metadata, "source_sha256")
        old_content_sha = _metadata_hash(parsed.metadata, "content_sha256")
        actual_content_sha = sha256_text(parsed.body)
        new_block = new_blocks.get(parsed.id)

        if new_block is None:
            warnings.append(
                f"Unknown generated block in document preserved: '{parsed.id}'."
            )
            changes.append(
                BlockRefreshChange(
                    id=parsed.id,
                    renderer=parsed.renderer,
                    status="unknown",
                    old_source_sha256=old_source_sha,
                    old_content_sha256=old_content_sha,
                )
            )
            continue

        new_source_sha = new_block.source_sha256
        new_content_sha = new_block.content_sha256
        edited = old_content_sha is None or actual_content_sha != old_content_sha

        if edited and not overwrite_edited:
            message = (
                f"Managed block '{parsed.id}' was manually edited; "
                "use force overwrite to replace it."
            )
            if strict_errors:
                errors.append(message)
            else:
                warnings.append(message)
            changes.append(
                BlockRefreshChange(
                    id=parsed.id,
                    renderer=parsed.renderer,
                    status="edited",
                    old_source_sha256=old_source_sha,
                    new_source_sha256=new_source_sha,
                    old_content_sha256=old_content_sha,
                    new_content_sha256=new_content_sha,
                )
            )
            continue

        if old_source_sha == new_source_sha and actual_content_sha == new_content_sha:
            changes.append(
                BlockRefreshChange(
                    id=parsed.id,
                    renderer=parsed.renderer,
                    status="unchanged",
                    old_source_sha256=old_source_sha,
                    new_source_sha256=new_source_sha,
                    old_content_sha256=actual_content_sha,
                    new_content_sha256=new_content_sha,
                )
            )
            continue

        replacement_by_start[parsed.start_line] = (
            parsed.end_line,
            render_generated_block(new_block) + "\n",
        )
        changed = True
        changes.append(
            BlockRefreshChange(
                id=parsed.id,
                renderer=parsed.renderer,
                status="updated",
                old_source_sha256=old_source_sha,
                new_source_sha256=new_source_sha,
                old_content_sha256=old_content_sha or actual_content_sha,
                new_content_sha256=new_content_sha,
            )
        )

    for block_id, block in new_blocks.items():
        if block_id in seen_ids:
            continue
        message = f"Known generated block missing in document: '{block_id}'."
        if add_missing:
            warnings.append(message + " add_missing is not supported in v1 placement.")
        else:
            warnings.append(message)
        changes.append(
            BlockRefreshChange(
                id=block_id,
                renderer=block.renderer,
                status="missing",
                new_source_sha256=block.source_sha256,
                new_content_sha256=block.content_sha256,
            )
        )

    if errors:
        return BlockRefreshResult(
            markdown=markdown,
            changed=False,
            changes=changes,
            warnings=warnings,
            errors=errors,
        )

    output_lines: list[str] = []
    line_number = 1
    while line_number <= len(rendered_lines):
        replacement = replacement_by_start.get(line_number)
        if replacement is None:
            output_lines.append(rendered_lines[line_number - 1])
            line_number += 1
            continue
        end_line, replacement_text = replacement
        output_lines.append(replacement_text)
        line_number = end_line + 1

    refreshed_markdown = "".join(output_lines)
    return BlockRefreshResult(
        markdown=refreshed_markdown,
        changed=changed,
        changes=changes,
        warnings=warnings,
        errors=errors,
    )
