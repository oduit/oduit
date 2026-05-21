"""Static addon source-location helpers for coding-agent workflows."""

from __future__ import annotations

import ast
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .addons_path_manager import AddonsPathManager
from .api_models import (
    AddonHttpRoute,
    AddonModelEntry,
    AddonModelInventory,
    AddonTechnicalFile,
    AddonTechnicalInventory,
    AddonTestFile,
    AddonTestInventory,
    AddonXmlRecord,
    FieldSourceCandidate,
    FieldSourceLocation,
    ModelDeclarationSource,
    ModelExtensionInventory,
    ModelExtensionSource,
    ModelSourceCandidate,
    ModelSourceLocation,
    RecommendedTestPlan,
    SourceEvidence,
    ViewExtensionSource,
)

_TEXT_MARKER_EXTENSIONS = {
    ".py",
    ".xml",
    ".csv",
    ".js",
    ".ts",
    ".scss",
    ".md",
    ".rst",
}
_TODO_MARKER_PATTERN = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")


def _path_str(path: str | Path) -> str:
    return Path(path).as_posix()


@dataclass
class _ClassScan:
    path: str
    class_name: str
    lineno: int | None
    inherits: list[str] = field(default_factory=list)
    name: str | None = None
    inherits_map: dict[str, str] = field(default_factory=dict)
    field_lines: dict[str, int | None] = field(default_factory=dict)
    method_lines: dict[str, int | None] = field(default_factory=dict)


@dataclass
class _ScanResult:
    classes: list[_ClassScan] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)


@dataclass
class SourceScanCache:
    """Per-command source scan cache keyed by addon root."""

    python_by_root: dict[str, _ScanResult] = field(default_factory=dict)
    view_by_root: dict[str, dict[str, list[ViewExtensionSource]]] = field(
        default_factory=dict
    )

    def python_scan(self, addon_root: str) -> _ScanResult:
        key = _path_str(addon_root)
        if key not in self.python_by_root:
            self.python_by_root[key] = _scan_python_sources(key)
        return self.python_by_root[key]

    def view_extensions_by_model(
        self,
        addon_root: str,
        module: str,
    ) -> dict[str, list[ViewExtensionSource]]:
        key = _path_str(addon_root)
        if key not in self.view_by_root:
            self.view_by_root[key] = _scan_view_extensions_by_model(key, module)
        return self.view_by_root[key]


def _string_literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _string_literals(node: ast.AST | None) -> list[str]:
    literal = _string_literal(node)
    if literal is not None:
        return [literal]
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        values: list[str] = []
        for element in node.elts:
            element_literal = _string_literal(element)
            if element_literal is not None:
                values.append(element_literal)
        return values
    return []


def _string_dict(node: ast.AST | None) -> dict[str, str]:
    if not isinstance(node, ast.Dict):
        return {}
    result: dict[str, str] = {}
    for key, value in zip(node.keys, node.values, strict=False):
        key_literal = _string_literal(key)
        value_literal = _string_literal(value)
        if key_literal is not None and value_literal is not None:
            result[key_literal] = value_literal
    return result


def _iter_assignment_pairs(node: ast.stmt) -> list[tuple[str, ast.AST, int | None]]:
    if isinstance(node, ast.Assign):
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        return [(name, node.value, getattr(node, "lineno", None)) for name in names]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [
            (
                node.target.id,
                node.value if node.value is not None else ast.Constant(value=None),
                getattr(node, "lineno", None),
            )
        ]
    return []


def _is_field_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "fields"
    )


def _scan_python_sources(addon_root: str) -> _ScanResult:
    root = Path(addon_root)
    result = _ScanResult()
    for path in sorted(root.rglob("*.py")):
        path_str = _path_str(path)
        result.scanned_files.append(path_str)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=path_str)
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            result.warnings.append(f"Failed to parse {path_str}: {exc}")
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            class_scan = _ClassScan(
                path=path_str,
                class_name=node.name,
                lineno=getattr(node, "lineno", None),
            )
            for statement in node.body:
                for name, value, lineno in _iter_assignment_pairs(statement):
                    if name == "_inherit":
                        class_scan.inherits.extend(_string_literals(value))
                    elif name == "_name":
                        class_scan.name = _string_literal(value)
                    elif name == "_inherits":
                        class_scan.inherits_map.update(_string_dict(value))
                    elif _is_field_call(value):
                        class_scan.field_lines[name] = lineno
                if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
                    class_scan.method_lines[statement.name] = getattr(
                        statement, "lineno", None
                    )
            if class_scan.inherits or class_scan.name or class_scan.inherits_map:
                result.classes.append(class_scan)
    return result


def _iter_addon_roots(addons_path: str) -> list[tuple[str, str]]:
    addon_roots: list[tuple[str, str]] = []
    seen_roots: set[str] = set()
    for configured_path in AddonsPathManager(addons_path).get_configured_paths():
        base_path = Path(configured_path)
        if not base_path.is_dir():
            continue
        for child in sorted(base_path.iterdir()):
            if not child.is_dir():
                continue
            if not (
                (child / "__manifest__.py").exists()
                or (child / "__openerp__.py").exists()
            ):
                continue
            child_str = _path_str(child)
            if child_str in seen_roots:
                continue
            seen_roots.add(child_str)
            addon_roots.append((child.name, child_str))
    return addon_roots


def _extract_view_model(record: ET.Element) -> str | None:
    model_name = record.get("model")
    if model_name == "ir.ui.view":
        for field in record.findall("field"):
            if field.get("name") == "model" and field.text:
                return field.text.strip()
    return None


def _xml_tag_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _bool_literal(node: ast.AST | None) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _classify_addon_file(relative_path: str) -> str:
    path = Path(relative_path)
    parts = path.parts
    if path.name in {"__manifest__.py", "__openerp__.py"}:
        return "manifest"
    if not parts:
        return "other"

    head = parts[0]
    suffix = path.suffix.lower()
    if head == "models" and suffix == ".py":
        return "model"
    if head == "wizards" and suffix == ".py":
        return "wizard"
    if head == "controllers" and suffix == ".py":
        return "controller"
    if head == "views" and suffix == ".xml":
        return "view"
    if head == "security":
        return "security"
    if head == "data":
        return "data"
    if head == "demo":
        return "demo"
    if head in {"report", "reports"}:
        return "report"
    if head == "static":
        return "test" if "tests" in parts else "static"
    if head == "tests":
        return "test"
    if head in {"i18n", "i18n_extra"} and suffix == ".po":
        return "i18n"
    if head == "migrations":
        return "migration"
    return "other"


def _scan_xml_records(addon_root: str) -> tuple[list[AddonXmlRecord], list[str]]:
    records: list[AddonXmlRecord] = []
    warnings: list[str] = []
    root = Path(addon_root)
    for path in sorted(root.rglob("*.xml")):
        if not path.is_file():
            continue
        path_str = _path_str(path)
        try:
            xml_tree = ET.parse(path)
        except (OSError, ET.ParseError) as exc:
            warnings.append(f"Failed to parse XML file {path_str}: {exc}")
            continue

        xml_root = xml_tree.getroot()
        for element in xml_root.iter():
            tag_name = _xml_tag_name(element.tag)
            if tag_name == "record":
                name = None
                for field in element.findall("field"):
                    if field.get("name") == "name" and field.text:
                        name = field.text.strip()
                        break
                records.append(
                    AddonXmlRecord(
                        path=path_str,
                        record_id=element.get("id"),
                        model=element.get("model"),
                        name=name,
                        xml_tag=tag_name,
                    )
                )
                continue

            if tag_name == "menuitem":
                records.append(
                    AddonXmlRecord(
                        path=path_str,
                        record_id=element.get("id"),
                        name=element.get("name"),
                        xml_tag=tag_name,
                        attributes={
                            key: value
                            for key, value in (
                                ("action", element.get("action")),
                                ("parent", element.get("parent")),
                            )
                            if value
                        },
                    )
                )
                continue

            if tag_name == "report":
                records.append(
                    AddonXmlRecord(
                        path=path_str,
                        record_id=element.get("id"),
                        model=element.get("model"),
                        name=element.get("name"),
                        xml_tag=tag_name,
                        attributes={
                            key: value
                            for key, value in (
                                ("report_type", element.get("report_type")),
                                ("string", element.get("string")),
                            )
                            if value
                        },
                    )
                )
    return records, warnings


def _iter_route_functions(
    tree: ast.AST,
) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    discovered: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.ClassDef):
            for statement in node.body:
                if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
                    discovered.append((node.name, statement))
            continue
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            discovered.append(("<module>", node))
    return discovered


def _scan_http_routes(addon_root: str) -> tuple[list[AddonHttpRoute], list[str]]:
    routes: list[AddonHttpRoute] = []
    warnings: list[str] = []
    controllers_root = Path(addon_root) / "controllers"
    if not controllers_root.is_dir():
        return routes, warnings

    for path in sorted(controllers_root.rglob("*.py")):
        if not path.is_file():
            continue
        path_str = _path_str(path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=path_str)
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            warnings.append(f"Failed to parse controller source {path_str}: {exc}")
            continue

        for class_name, function_node in _iter_route_functions(tree):
            for decorator in function_node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                func = decorator.func
                if isinstance(func, ast.Attribute):
                    is_route = func.attr == "route"
                else:
                    is_route = isinstance(func, ast.Name) and func.id == "route"
                if not is_route:
                    continue

                route_values = _string_literals(
                    decorator.args[0] if decorator.args else None
                )
                if not route_values:
                    for keyword in decorator.keywords:
                        if keyword.arg == "route":
                            route_values = _string_literals(keyword.value)
                            break
                if not route_values:
                    warnings.append(
                        f"Skipped controller route with non-literal route in {path_str}"
                    )
                    continue

                auth = None
                route_type = None
                methods: list[str] = []
                csrf = None
                website = None
                for keyword in decorator.keywords:
                    if keyword.arg == "auth":
                        auth = _string_literal(keyword.value)
                    elif keyword.arg == "type":
                        route_type = _string_literal(keyword.value)
                    elif keyword.arg == "methods":
                        methods = _string_literals(keyword.value)
                    elif keyword.arg == "csrf":
                        csrf = _bool_literal(keyword.value)
                    elif keyword.arg == "website":
                        website = _bool_literal(keyword.value)

                routes.append(
                    AddonHttpRoute(
                        path=path_str,
                        class_name=class_name,
                        method_name=function_node.name,
                        route=route_values[0]
                        if len(route_values) == 1
                        else route_values,
                        auth=auth,
                        route_type=route_type,
                        methods=methods,
                        csrf=csrf,
                        website=website,
                        line_hint=getattr(function_node, "lineno", None),
                    )
                )
    return routes, warnings


def _scan_todo_markers(
    addon_root: str, *, limit: int = 100
) -> tuple[list[SourceEvidence], list[str]]:
    markers: list[SourceEvidence] = []
    warnings: list[str] = []
    root = Path(addon_root)

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _TEXT_MARKER_EXTENSIONS:
            continue
        path_str = _path_str(path)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            warnings.append(f"Failed to read {path_str}: {exc}")
            continue

        for line_number, line in enumerate(lines, start=1):
            match = _TODO_MARKER_PATTERN.search(line)
            if match is None:
                continue
            markers.append(
                SourceEvidence(
                    kind=match.group(1),
                    message=line.strip(),
                    path=path_str,
                    line_hint=line_number,
                )
            )
            if len(markers) >= limit:
                warnings.append(f"Truncated TODO marker inventory at {limit} entries.")
                return markers, warnings

    return markers, warnings


def _scan_view_extensions_by_model(
    addon_root: str, module: str
) -> dict[str, list[ViewExtensionSource]]:
    by_model: dict[str, list[ViewExtensionSource]] = defaultdict(list)
    root = Path(addon_root)
    normalized_addon_root = _path_str(addon_root)
    for path in sorted(root.rglob("*.xml")):
        path_str = _path_str(path)
        try:
            tree = ET.parse(path)
        except (OSError, ET.ParseError):
            continue
        xml_root = tree.getroot()
        for record in xml_root.iter("record"):
            model_name = _extract_view_model(record)
            if not model_name:
                continue
            inherit_ref = None
            name = None
            priority = None
            for field_element in record.findall("field"):
                field_name = field_element.get("name")
                if field_name == "inherit_id":
                    inherit_ref = field_element.get("ref")
                elif field_name == "name" and field_element.text:
                    name = field_element.text.strip()
                elif field_name == "priority" and field_element.text:
                    try:
                        priority = int(field_element.text.strip())
                    except ValueError:
                        priority = None
            if inherit_ref is None:
                continue
            by_model[model_name].append(
                ViewExtensionSource(
                    module=module,
                    addon_root=normalized_addon_root,
                    path=path_str,
                    record_id=record.get("id"),
                    name=name,
                    priority=priority,
                    inherit_ref=inherit_ref,
                )
            )
    return {
        model_name: sorted(
            items,
            key=lambda item: (
                item.module,
                item.path,
                item.record_id or "",
            ),
        )
        for model_name, items in by_model.items()
    }


def _scan_view_extensions(
    addon_root: str, module: str, model: str
) -> list[ViewExtensionSource]:
    return _scan_view_extensions_by_model(addon_root, module).get(model, [])


def list_addon_technical_inventory(
    addon_root: str, module: str
) -> AddonTechnicalInventory:
    """Return a read-only technical inventory for one addon."""

    root = Path(addon_root)
    normalized_addon_root = _path_str(addon_root)
    files: list[AddonTechnicalFile] = []
    warnings: list[str] = []
    remediation: list[str] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        path_str = _path_str(path)
        relative_path = path.relative_to(root).as_posix()
        try:
            size_bytes = path.stat().st_size
        except OSError as exc:
            warnings.append(f"Failed to stat {path_str}: {exc}")
            size_bytes = None
        files.append(
            AddonTechnicalFile(
                path=path_str,
                category=_classify_addon_file(relative_path),
                size_bytes=size_bytes,
            )
        )

    xml_records, xml_warnings = _scan_xml_records(addon_root)
    http_routes, route_warnings = _scan_http_routes(addon_root)
    todo_markers, todo_warnings = _scan_todo_markers(addon_root)
    warnings.extend(xml_warnings)
    warnings.extend(route_warnings)
    warnings.extend(todo_warnings)

    security_files = sorted(
        file_entry.path for file_entry in files if file_entry.category == "security"
    )
    migration_files = sorted(
        file_entry.path for file_entry in files if file_entry.category == "migration"
    )

    if http_routes and not security_files:
        remediation.append(
            "Controllers or routes were detected without matching security files; "
            "review access control manually."
        )
    if todo_markers:
        remediation.append(
            "Review TODO/FIXME/HACK markers before treating the generated "
            "architecture document as complete."
        )
    if warnings:
        remediation.append(
            "Inspect files with parse or read warnings to confirm the inventory is "
            "complete."
        )

    return AddonTechnicalInventory(
        module=module,
        addon_root=normalized_addon_root,
        files=files,
        xml_records=xml_records,
        http_routes=http_routes,
        security_files=security_files,
        migration_files=migration_files,
        todo_markers=todo_markers,
        warnings=warnings,
        remediation=sorted(dict.fromkeys(remediation)),
    )


def list_model_extensions_for_roots(
    addon_roots: Iterable[tuple[str, str]],
    model: str,
    *,
    scan_cache: SourceScanCache | None = None,
) -> ModelExtensionInventory:
    """Return static extension locations for one model across selected addon roots."""
    cache = scan_cache or SourceScanCache()
    base_declarations: list[ModelDeclarationSource] = []
    source_extensions: list[ModelExtensionSource] = []
    source_view_extensions: list[ViewExtensionSource] = []
    scanned_python_files: list[str] = []
    warnings: list[str] = []

    for module, addon_root in addon_roots:
        normalized_addon_root = _path_str(addon_root)
        scan = cache.python_scan(normalized_addon_root)
        scanned_python_files.extend(scan.scanned_files)
        warnings.extend(scan.warnings)
        source_view_extensions.extend(
            cache.view_extensions_by_model(normalized_addon_root, module).get(model, [])
        )
        for class_scan in scan.classes:
            added_fields = sorted(class_scan.field_lines)
            added_methods = sorted(class_scan.method_lines)
            inherited_models = sorted(dict.fromkeys(class_scan.inherits))
            delegated_models = sorted(class_scan.inherits_map)

            if class_scan.name == model:
                base_declarations.append(
                    ModelDeclarationSource(
                        module=module,
                        addon_root=normalized_addon_root,
                        path=class_scan.path,
                        class_name=class_scan.class_name,
                        line_hint=class_scan.lineno,
                        added_fields=added_fields,
                        added_methods=added_methods,
                    )
                )

            relation_kind: str | None = None
            if model in class_scan.inherits:
                relation_kind = "extends"
            elif model in class_scan.inherits_map:
                relation_kind = "delegates"

            if relation_kind is None:
                continue

            source_extensions.append(
                ModelExtensionSource(
                    module=module,
                    addon_root=normalized_addon_root,
                    path=class_scan.path,
                    class_name=class_scan.class_name,
                    line_hint=class_scan.lineno,
                    relation_kind=relation_kind,
                    added_fields=added_fields,
                    added_methods=added_methods,
                    inherited_models=inherited_models,
                    delegated_models=delegated_models,
                )
            )

    base_declarations.sort(key=lambda item: (item.module, item.path, item.class_name))
    source_extensions.sort(
        key=lambda item: (
            item.module,
            0 if item.relation_kind == "extends" else 1,
            item.path,
            item.class_name,
        )
    )
    source_view_extensions.sort(
        key=lambda item: (item.module, item.path, item.record_id or "")
    )
    remediation = (
        []
        if source_extensions or base_declarations or source_view_extensions
        else [
            (
                f"No static source declaration or extension was found for `{model}`; "
                "inspect dynamic model registration or external addon paths manually."
            )
        ]
    )
    return ModelExtensionInventory(
        model=model,
        base_declarations=base_declarations,
        source_extensions=source_extensions,
        source_extension_modules=sorted({item.module for item in source_extensions}),
        source_view_extensions=source_view_extensions,
        scanned_python_files=sorted(dict.fromkeys(scanned_python_files)),
        warnings=sorted(dict.fromkeys(warnings)),
        remediation=remediation,
    )


def list_model_extensions(
    addons_path: str,
    model: str,
    *,
    scan_cache: SourceScanCache | None = None,
) -> ModelExtensionInventory:
    """Return static extension locations for one model across all addons."""
    return list_model_extensions_for_roots(
        _iter_addon_roots(addons_path),
        model,
        scan_cache=scan_cache,
    )


def list_model_extensions_for_addon(
    addon_root: str,
    module: str,
    model: str,
    *,
    scan_cache: SourceScanCache | None = None,
) -> ModelExtensionInventory:
    """Return static extension locations for one model in one addon root."""
    return list_model_extensions_for_roots(
        [(module, addon_root)],
        model,
        scan_cache=scan_cache,
    )


def _base_confidence(path: Path) -> float:
    score = 0.45
    if "models" in path.parts:
        score += 0.35
    if path.name.startswith("res_") or path.stem.endswith("_models"):
        score += 0.05
    if "tests" in path.parts:
        score -= 0.25
    return score


def _candidate_reason(match_kind: str, model: str) -> str:
    reasons = {
        "inherit": f"Class inherits `{model}` directly in addon source.",
        "name": f"Class declares `{model}` as its primary model.",
        "inherits": f"Class delegates to `{model}` through `_inherits`.",
    }
    return reasons.get(match_kind, f"Class is associated with `{model}`.")


def _build_model_candidate_evidence(
    class_scan: _ClassScan,
    *,
    model: str,
    model_hint: str,
    match_kind: str,
) -> list[SourceEvidence]:
    """Build explicit evidence for one model source candidate."""
    evidence = [
        SourceEvidence(
            kind=f"model_{match_kind}",
            message=_candidate_reason(match_kind, model),
            path=class_scan.path,
            line_hint=class_scan.lineno,
        )
    ]
    path = Path(class_scan.path)
    if model_hint in path.stem:
        evidence.append(
            SourceEvidence(
                kind="filename_hint",
                message=f"Filename `{path.name}` resembles `{model}`.",
                path=class_scan.path,
            )
        )
    if class_scan.class_name.lower().replace("_", "") == model_hint.replace("_", ""):
        evidence.append(
            SourceEvidence(
                kind="class_name_hint",
                message=f"Class name `{class_scan.class_name}` resembles `{model}`.",
                path=class_scan.path,
                line_hint=class_scan.lineno,
            )
        )
    return evidence


def locate_model_sources(
    addon_root: str, module: str, model: str
) -> ModelSourceLocation:
    scan = _scan_python_sources(addon_root)
    normalized_addon_root = _path_str(addon_root)
    candidates: list[ModelSourceCandidate] = []
    model_hint = model.replace(".", "_")
    for class_scan in scan.classes:
        path = Path(class_scan.path)
        match_kind: str | None = None
        declared_model: str | None = None
        confidence = _base_confidence(path)
        if model_hint in path.stem:
            confidence += 0.08
        if class_scan.class_name.lower().replace("_", "") == model_hint.replace(
            "_", ""
        ):
            confidence += 0.05

        if model in class_scan.inherits:
            match_kind = "inherit"
            declared_model = model
            confidence += 0.5
        elif class_scan.name == model:
            match_kind = "name"
            declared_model = model
            confidence += 0.42
        elif model in class_scan.inherits_map:
            match_kind = "inherits"
            declared_model = model
            confidence += 0.3

        if match_kind is None or declared_model is None:
            continue

        candidates.append(
            ModelSourceCandidate(
                path=class_scan.path,
                class_name=class_scan.class_name,
                match_kind=match_kind,
                declared_model=declared_model,
                confidence=round(min(confidence, 0.99), 2),
                match_strength="confirmed",
                evidence=_build_model_candidate_evidence(
                    class_scan,
                    model=model,
                    model_hint=model_hint,
                    match_kind=match_kind,
                ),
                line_hint=class_scan.lineno,
                reason=_candidate_reason(match_kind, model),
            )
        )

    candidates.sort(
        key=lambda item: (
            -item.confidence,
            0 if model_hint in Path(item.path).stem else 1,
            item.path,
            item.class_name,
        )
    )
    remediation = (
        []
        if candidates
        else [
            (
                f"Inspect `{module}` manually for dynamic model construction or "
                "uncommon inheritance patterns."
            ),
            "Verify that the requested addon and model name are correct.",
        ]
    )
    ambiguous = len(candidates) > 1
    return ModelSourceLocation(
        model=model,
        module=module,
        addon_root=normalized_addon_root,
        resolution="ambiguous"
        if ambiguous
        else ("confirmed" if candidates else "not_found"),
        ambiguous=ambiguous,
        ambiguity_reason=(
            "Multiple source candidates matched the requested model."
            if ambiguous
            else None
        ),
        candidates=candidates,
        scanned_python_files=scan.scanned_files,
        warnings=scan.warnings,
        remediation=remediation,
    )


def locate_field_sources(
    addon_root: str,
    module: str,
    model: str,
    field_name: str,
) -> FieldSourceLocation:
    scan = _scan_python_sources(addon_root)
    normalized_addon_root = _path_str(addon_root)
    model_location = locate_model_sources(addon_root, module, model)
    field_candidates: list[FieldSourceCandidate] = []
    matching_scans: dict[str, _ClassScan] = {}

    matching_paths = {candidate.path for candidate in model_location.candidates}
    for class_scan in scan.classes:
        if class_scan.path not in matching_paths:
            continue
        matching_scans[class_scan.path] = class_scan
        line_hint = class_scan.field_lines.get(field_name)
        if line_hint is None:
            continue
        match_kind = "inherit" if model in class_scan.inherits else "name"
        evidence = [
            SourceEvidence(
                kind="field_definition",
                message=f"Exact field definition for `{field_name}` found in source.",
                path=class_scan.path,
                line_hint=line_hint,
            ),
            *_build_model_candidate_evidence(
                class_scan,
                model=model,
                model_hint=model.replace(".", "_"),
                match_kind=match_kind,
            ),
        ]
        field_candidates.append(
            FieldSourceCandidate(
                path=class_scan.path,
                class_name=class_scan.class_name,
                field_name=field_name,
                match_kind=match_kind,
                declared_model=model,
                confidence=round(
                    min(
                        _base_confidence(Path(class_scan.path))
                        + (0.45 if match_kind == "inherit" else 0.37),
                        0.99,
                    ),
                    2,
                ),
                match_strength="confirmed",
                evidence=evidence,
                line_hint=line_hint,
                reason=f"Exact field definition for `{field_name}` found in source.",
            )
        )

    field_candidates.sort(
        key=lambda item: (-item.confidence, item.path, item.class_name, item.field_name)
    )
    insertion_candidate = None
    rationale = None
    insertion_line_range = None
    insertion_reason = None
    insertion_confidence = None
    if not field_candidates and model_location.candidates:
        insertion_candidate = model_location.candidates[0]
        insertion_confidence = insertion_candidate.confidence
        insertion_scan = matching_scans.get(insertion_candidate.path)
        if insertion_scan is not None:
            field_lines = sorted(
                line for line in insertion_scan.field_lines.values() if line is not None
            )
            method_lines = sorted(
                line
                for line in insertion_scan.method_lines.values()
                if line is not None
            )
            start_line = field_lines[-1] + 1 if field_lines else insertion_scan.lineno
            end_line = method_lines[0] - 1 if method_lines else None
            if start_line is not None:
                insertion_line_range = (
                    [start_line, end_line] if end_line is not None else [start_line]
                )
        rationale = (
            "No existing field definition was found; the highest-confidence model "
            "extension file is the best insertion point."
        )
        insertion_reason = (
            f"Use `{insertion_candidate.path}` because it has the strongest model "
            "match "
            "for this addon change."
        )

    remediation = []
    if not field_candidates and insertion_candidate is None:
        remediation.extend(model_location.remediation)
    ambiguous = len(field_candidates) > 1 or (
        not field_candidates and bool(model_location.ambiguous)
    )
    resolution = "not_found"
    if field_candidates:
        resolution = "ambiguous" if ambiguous else "confirmed"
    elif insertion_candidate is not None:
        resolution = "suggested"

    return FieldSourceLocation(
        model=model,
        field=field_name,
        module=module,
        addon_root=normalized_addon_root,
        exists=bool(field_candidates),
        resolution=resolution,
        ambiguous=ambiguous,
        ambiguity_reason=(
            "Multiple source candidates matched the requested field."
            if len(field_candidates) > 1
            else (
                "Field was not found and the insertion suggestion inherits model "
                "ambiguity."
                if not field_candidates and model_location.ambiguous
                else None
            )
        ),
        source_exists=bool(field_candidates),
        candidates=field_candidates,
        insertion_candidate=insertion_candidate,
        insertion_line_range=insertion_line_range,
        insertion_reason=insertion_reason,
        insertion_confidence=insertion_confidence,
        related_files=sorted(matching_paths),
        scanned_python_files=scan.scanned_files,
        rationale=rationale,
        warnings=sorted(dict.fromkeys(scan.warnings + model_location.warnings)),
        remediation=remediation,
    )


def list_addon_models(addon_root: str, module: str) -> AddonModelInventory:
    """Return a static inventory of models declared or extended by one addon."""
    scan = _scan_python_sources(addon_root)
    normalized_addon_root = _path_str(addon_root)
    models: list[AddonModelEntry] = []

    for class_scan in scan.classes:
        added_fields = sorted(class_scan.field_lines)
        added_methods = sorted(class_scan.method_lines)
        inherited_models = sorted(dict.fromkeys(class_scan.inherits))
        delegated_models = sorted(class_scan.inherits_map)

        if class_scan.name:
            models.append(
                AddonModelEntry(
                    model=class_scan.name,
                    relation_kind="declares",
                    class_name=class_scan.class_name,
                    path=class_scan.path,
                    line_hint=class_scan.lineno,
                    added_fields=added_fields,
                    added_methods=added_methods,
                    inherited_models=inherited_models,
                    delegated_models=delegated_models,
                )
            )
            continue

        for inherited_model in inherited_models:
            models.append(
                AddonModelEntry(
                    model=inherited_model,
                    relation_kind="extends",
                    class_name=class_scan.class_name,
                    path=class_scan.path,
                    line_hint=class_scan.lineno,
                    added_fields=added_fields,
                    added_methods=added_methods,
                    inherited_models=inherited_models,
                    delegated_models=delegated_models,
                )
            )

        for delegated_model in delegated_models:
            models.append(
                AddonModelEntry(
                    model=delegated_model,
                    relation_kind="delegates",
                    class_name=class_scan.class_name,
                    path=class_scan.path,
                    line_hint=class_scan.lineno,
                    added_fields=added_fields,
                    added_methods=added_methods,
                    inherited_models=inherited_models,
                    delegated_models=delegated_models,
                )
            )

    relation_order = {"declares": 0, "extends": 1, "delegates": 2}
    models.sort(
        key=lambda item: (
            item.model,
            relation_order.get(item.relation_kind, 99),
            item.path,
            item.class_name,
        )
    )
    remediation = (
        []
        if models
        else [
            (
                f"No model declarations or extensions were found under `{module}`; "
                "inspect XML, data files, or dynamic model generation manually."
            ),
        ]
    )
    return AddonModelInventory(
        module=module,
        addon_root=normalized_addon_root,
        models=models,
        model_count=len(models),
        scanned_python_files=scan.scanned_files,
        warnings=scan.warnings,
        remediation=remediation,
    )


def list_addon_languages(addon_root: str) -> tuple[list[str], list[str]]:
    """Return translation language codes and non-fatal discovery warnings."""
    i18n_dir = Path(addon_root) / "i18n"
    if not i18n_dir.is_dir():
        return [], []

    languages: set[str] = set()
    warnings: list[str] = []
    for path in sorted(i18n_dir.glob("*.po")):
        if not path.is_file():
            continue
        if path.stem:
            languages.add(path.stem)
            continue
        warnings.append(f"Ignored translation file with empty stem: {path}")
    return sorted(languages), warnings


def _path_tokens(path: Path) -> set[str]:
    tokens: set[str] = set()
    for part in path.with_suffix("").parts:
        normalized = part.replace("-", "_").lower()
        tokens.update(token for token in normalized.split("_") if len(token) >= 3)
    return tokens


def _normalize_changed_paths(root: Path, paths: list[str] | None) -> list[str]:
    if not paths:
        return []

    normalized: list[str] = []
    for raw_path in paths:
        candidate = Path(raw_path)
        if candidate.is_absolute():
            try:
                relative = candidate.relative_to(root)
            except ValueError:
                relative = candidate
        else:
            relative = candidate
        normalized.append(relative.as_posix())
    return sorted(dict.fromkeys(normalized))


def _build_test_entry(
    *,
    path: Path,
    module: str,
    content: str,
    test_type: str,
    model: str | None,
    field_name: str | None,
    changed_paths: list[str] | None,
) -> AddonTestFile:
    lower_content = content.lower()
    normalized_path = path.as_posix()
    lower_path = normalized_path.lower()
    references_model = bool(model and model in content)
    references_field = bool(field_name and field_name in content)
    ranking_signals: list[str] = []
    related_paths: list[str] = []
    confidence = 0.22

    if "tests" in path.parts:
        confidence += 0.22
        ranking_signals.append("lives in the addon test tree")
    if path.name.startswith("test_"):
        confidence += 0.05
        ranking_signals.append("uses standard test naming")
    if module.lower() in lower_path:
        confidence += 0.04
        ranking_signals.append("path includes the addon name")
    if references_model:
        confidence += 0.25
        ranking_signals.append(f"references model `{model}`")
    if references_field:
        confidence += 0.15
        ranking_signals.append(f"references field `{field_name}`")
    if model:
        model_hint = model.replace(".", "_").lower()
        if model_hint in path.stem.lower():
            confidence += 0.08
            ranking_signals.append("filename resembles the target model")
    if field_name and field_name.lower() in lower_path:
        confidence += 0.08
        ranking_signals.append("filename resembles the target field")

    for changed_path in changed_paths or []:
        changed = Path(changed_path)
        top_level = changed.parts[0] if changed.parts else ""
        if top_level == "models" and test_type == "python":
            confidence += 0.08
            ranking_signals.append("python tests are preferred for model changes")
            related_paths.append(changed_path)
        if top_level in {"views", "static"} and test_type in {"xml", "tour", "js"}:
            confidence += 0.08
            ranking_signals.append("UI-oriented tests are preferred for view changes")
            related_paths.append(changed_path)

        matched_tokens = sorted(
            token
            for token in _path_tokens(changed)
            if token in lower_content or token in lower_path
        )
        if matched_tokens:
            confidence += min(len(matched_tokens) * 0.04, 0.16)
            ranking_signals.append(
                "mentions changed path tokens: " + ", ".join(matched_tokens[:4])
            )
            related_paths.append(changed_path)

    return AddonTestFile(
        path=normalized_path,
        test_type=test_type,
        references_model=references_model,
        references_field=references_field,
        confidence=round(min(confidence, 0.99), 2),
        ranking_signals=sorted(dict.fromkeys(ranking_signals)),
        related_paths=sorted(dict.fromkeys(related_paths)),
    )


def _collect_addon_tests(
    addon_root: str,
    module: str,
    model: str | None = None,
    field_name: str | None = None,
    changed_paths: list[str] | None = None,
) -> tuple[list[AddonTestFile], list[str]]:
    root = Path(addon_root)
    tests: list[AddonTestFile] = []
    warnings: list[str] = []
    normalized_paths = _normalize_changed_paths(root, changed_paths)
    patterns = [
        "tests/**/*.py",
        "tests/**/*.yml",
        "tests/**/*.yaml",
        "tests/**/*.js",
        "tests/**/*.xml",
        "static/tests/**/*.js",
        "static/tests/**/*.xml",
        "**/*tour*.js",
    ]
    seen: set[str] = set()

    for pattern in patterns:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            path_str = str(path)
            if path_str in seen:
                continue
            seen.add(path_str)
            suffix = path.suffix.lower()
            test_type = {
                ".py": "python",
                ".yml": "yaml",
                ".yaml": "yaml",
                ".js": "js",
                ".xml": "tour" if "tour" in path_str else "xml",
            }.get(suffix, "unknown")
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"Failed to read {path_str}: {exc}")
                content = ""

            tests.append(
                _build_test_entry(
                    path=path,
                    module=module,
                    content=content,
                    test_type=test_type,
                    model=model,
                    field_name=field_name,
                    changed_paths=normalized_paths,
                )
            )

    tests.sort(key=lambda item: (-item.confidence, item.path))
    return tests, warnings


def list_addon_tests(
    addon_root: str,
    module: str,
    model: str | None = None,
    field_name: str | None = None,
) -> AddonTestInventory:
    normalized_addon_root = _path_str(addon_root)
    tests, warnings = _collect_addon_tests(
        addon_root,
        module,
        model=model,
        field_name=field_name,
    )
    remediation = (
        []
        if tests
        else [
            (
                f"No test files were found under `{module}`; inspect the addon "
                "manually or add targeted tests."
            ),
        ]
    )
    return AddonTestInventory(
        module=module,
        addon_root=normalized_addon_root,
        model=model,
        field=field_name,
        tests=tests,
        warnings=warnings,
        remediation=remediation,
    )


def recommend_tests(
    addon_root: str,
    module: str,
    paths: list[str],
) -> RecommendedTestPlan:
    normalized_addon_root = _path_str(addon_root)
    normalized_paths = _normalize_changed_paths(Path(addon_root), paths)
    tests, warnings = _collect_addon_tests(
        addon_root,
        module,
        changed_paths=normalized_paths,
    )
    high_impact_dirs = {"models", "views", "security", "data"}
    full_addon_suite_recommended = not tests or any(
        Path(path).parts and Path(path).parts[0] in high_impact_dirs
        for path in normalized_paths
    )
    rationale = []
    if normalized_paths:
        rationale.append(
            "Changed paths were matched against test filenames and content."
        )
    if full_addon_suite_recommended:
        rationale.append(
            "A full addon suite is recommended because the changed paths affect "
            "high-impact addon areas or no explicit tests were found."
        )
    remediation = (
        []
        if tests
        else [
            (
                f"No explicit tests were matched for `{module}`; run the addon suite "
                "and inspect nearby test directories manually."
            ),
        ]
    )
    return RecommendedTestPlan(
        module=module,
        addon_root=normalized_addon_root,
        paths=normalized_paths,
        tests=tests,
        suggested_test_tags=[f"/{module}"],
        full_addon_suite_recommended=full_addon_suite_recommended,
        rationale=list(dict.fromkeys(rationale)),
        warnings=warnings,
        remediation=remediation,
    )
