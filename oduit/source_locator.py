"""Static addon source-location helpers for coding-agent workflows."""

from __future__ import annotations

import ast
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from .addons_path_manager import AddonsPathManager
from .api_models import (
    AddonModelEntry,
    AddonModelInventory,
    AddonTestFile,
    AddonTestInventory,
    FieldSourceCandidate,
    FieldSourceLocation,
    ModelDeclarationSource,
    ModelExtensionInventory,
    ModelExtensionSource,
    ModelSourceCandidate,
    ModelSourceLocation,
    ViewExtensionSource,
)


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
        path_str = str(path)
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
            child_str = str(child)
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


def _scan_view_extensions(
    addon_root: str, module: str, model: str
) -> list[ViewExtensionSource]:
    view_extensions: list[ViewExtensionSource] = []
    root = Path(addon_root)
    for path in sorted(root.rglob("*.xml")):
        path_str = str(path)
        try:
            tree = ET.parse(path)
        except (OSError, ET.ParseError):
            continue
        xml_root = tree.getroot()
        for record in xml_root.iter("record"):
            if _extract_view_model(record) != model:
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
            view_extensions.append(
                ViewExtensionSource(
                    module=module,
                    addon_root=addon_root,
                    path=path_str,
                    record_id=record.get("id"),
                    name=name,
                    priority=priority,
                    inherit_ref=inherit_ref,
                )
            )
    return view_extensions


def list_model_extensions(addons_path: str, model: str) -> ModelExtensionInventory:
    """Return static extension locations for one model across all addons."""
    base_declarations: list[ModelDeclarationSource] = []
    source_extensions: list[ModelExtensionSource] = []
    source_view_extensions: list[ViewExtensionSource] = []
    scanned_python_files: list[str] = []
    warnings: list[str] = []

    for module, addon_root in _iter_addon_roots(addons_path):
        scan = _scan_python_sources(addon_root)
        scanned_python_files.extend(scan.scanned_files)
        warnings.extend(scan.warnings)
        source_view_extensions.extend(_scan_view_extensions(addon_root, module, model))
        for class_scan in scan.classes:
            added_fields = sorted(class_scan.field_lines)
            added_methods = sorted(class_scan.method_lines)
            inherited_models = sorted(dict.fromkeys(class_scan.inherits))
            delegated_models = sorted(class_scan.inherits_map)

            if class_scan.name == model:
                base_declarations.append(
                    ModelDeclarationSource(
                        module=module,
                        addon_root=addon_root,
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
                    addon_root=addon_root,
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


def _base_confidence(path: Path) -> float:
    score = 0.45
    if "models" in path.parts:
        score += 0.35
    if path.name.startswith("res_") or path.stem.endswith("_models"):
        score += 0.05
    if "tests" in path.parts:
        score -= 0.25
    return score


def locate_model_sources(
    addon_root: str, module: str, model: str
) -> ModelSourceLocation:
    scan = _scan_python_sources(addon_root)
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
                line_hint=class_scan.lineno,
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
    return ModelSourceLocation(
        model=model,
        module=module,
        addon_root=addon_root,
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
    model_location = locate_model_sources(addon_root, module, model)
    field_candidates: list[FieldSourceCandidate] = []

    matching_paths = {candidate.path for candidate in model_location.candidates}
    for class_scan in scan.classes:
        if class_scan.path not in matching_paths:
            continue
        line_hint = class_scan.field_lines.get(field_name)
        if line_hint is None:
            continue
        match_kind = "inherit" if model in class_scan.inherits else "name"
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
                line_hint=line_hint,
            )
        )

    field_candidates.sort(
        key=lambda item: (-item.confidence, item.path, item.class_name, item.field_name)
    )
    insertion_candidate = None
    rationale = None
    if not field_candidates and model_location.candidates:
        insertion_candidate = model_location.candidates[0]
        rationale = (
            "No existing field definition was found; the highest-confidence model "
            "extension file is the best insertion point."
        )

    remediation = []
    if not field_candidates and insertion_candidate is None:
        remediation.extend(model_location.remediation)

    return FieldSourceLocation(
        model=model,
        field=field_name,
        module=module,
        addon_root=addon_root,
        exists=bool(field_candidates),
        candidates=field_candidates,
        insertion_candidate=insertion_candidate,
        related_files=sorted(matching_paths),
        scanned_python_files=scan.scanned_files,
        rationale=rationale,
        warnings=sorted(dict.fromkeys(scan.warnings + model_location.warnings)),
        remediation=remediation,
    )


def list_addon_models(addon_root: str, module: str) -> AddonModelInventory:
    """Return a static inventory of models declared or extended by one addon."""
    scan = _scan_python_sources(addon_root)
    models: list[AddonModelEntry] = []

    for class_scan in scan.classes:
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
        addon_root=addon_root,
        models=models,
        model_count=len(models),
        scanned_python_files=scan.scanned_files,
        warnings=scan.warnings,
        remediation=remediation,
    )


def list_addon_tests(
    addon_root: str,
    module: str,
    model: str | None = None,
    field_name: str | None = None,
) -> AddonTestInventory:
    root = Path(addon_root)
    tests: list[AddonTestFile] = []
    warnings: list[str] = []
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

            references_model = bool(model and model in content)
            references_field = bool(field_name and field_name in content)
            confidence = 0.3
            if "tests" in path.parts:
                confidence += 0.3
            if references_model:
                confidence += 0.25
            if references_field:
                confidence += 0.15
            tests.append(
                AddonTestFile(
                    path=path_str,
                    test_type=test_type,
                    references_model=references_model,
                    references_field=references_field,
                    confidence=round(min(confidence, 0.99), 2),
                )
            )

    tests.sort(key=lambda item: (-item.confidence, item.path))
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
        addon_root=addon_root,
        model=model,
        field=field_name,
        tests=tests,
        warnings=warnings,
        remediation=remediation,
    )
