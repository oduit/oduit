"""Shared CLI helpers for reading and writing operation sets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

import typer

from ...operation_sets import (
    OperationSetKind,
    OperationSetWriteResult,
    write_operation_set,
)
from ...output import print_error
from ..bootstrap_support import resolve_operation_set_location_context


def _compact_mapping(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    compacted: dict[str, Any] = {}
    for key, item in value.items():
        if item is None:
            continue
        if isinstance(item, Mapping):
            nested = _compact_mapping(item)
            if nested:
                compacted[key] = nested
            continue
        compacted[key] = item
    return compacted or None


def normalize_operation_set_kind(
    value: str | None,
    *,
    default: OperationSetKind | None = None,
) -> OperationSetKind:
    if value is None:
        if default is not None:
            return default
        print_error("--set-kind is required when --save-set is used.")
        raise typer.Exit(1) from None
    if value not in {"install", "update", "test"}:
        print_error("--set-kind must be one of: install, update, test.")
        raise typer.Exit(1) from None
    return cast(OperationSetKind, value)


def save_addon_list_as_operation_set(
    *,
    global_config: Any,
    config_loader_cls: Any,
    save_set: str,
    addons: Sequence[str],
    set_kind: str | None,
    overwrite: bool,
    default_kind: OperationSetKind | None = None,
    set_name: str | None = None,
    set_description: str | None = None,
    source: Mapping[str, Any] | None = None,
    options: Mapping[str, Any] | None = None,
) -> OperationSetWriteResult:
    kind = normalize_operation_set_kind(set_kind, default=default_kind)
    context = resolve_operation_set_location_context(
        global_config,
        config_loader_cls=config_loader_cls,
    )
    try:
        return write_operation_set(
            save_set,
            kind=kind,
            addons=addons,
            context=context,
            overwrite=overwrite,
            name=set_name,
            description=set_description,
            source=_compact_mapping(source),
            options=_compact_mapping(options),
        )
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(1) from None
