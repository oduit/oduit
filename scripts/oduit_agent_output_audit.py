#!/usr/bin/env python3
"""Measure oduit agent command output size and JSON verbosity.

This script is intentionally external to oduit so it can be copied into a real
Odoo/oduit checkout and run before changing command schemas.

Examples:
  python scripts/oduit_agent_output_audit.py --env dev --module has_datev_export
  python scripts/oduit_agent_output_audit.py --matrix-file agent-output-matrix.json \
      --out-dir .oduit-output-audit
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import math
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
SECRET_PATTERNS = [
    re.compile(
        r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*([^\s,;]+)"
    ),
    re.compile(r"(?i)(postgres(?:ql)?://[^:\s]+:)([^@\s]+)(@)"),
]

DEFAULT_MATRIX = [
    {
        "name": "agent-help",
        "args": ["agent", "--help"],
        "mutates": False,
        "expect_json": False,
    },
    {
        "name": "agent-context",
        "args": ["agent", "context"],
        "mutates": False,
        "expect_json": True,
    },
    {
        "name": "agent-inspect-addon",
        "args": ["agent", "inspect-addon", "{module}"],
        "mutates": False,
        "expect_json": True,
    },
    {
        "name": "agent-inspect-addon-full",
        "args": ["agent", "inspect-addon", "{module}", "--full"],
        "mutates": False,
        "expect_json": True,
    },
    {
        "name": "agent-list-duplicates",
        "args": ["agent", "list-duplicates"],
        "mutates": False,
        "expect_json": True,
    },
    {
        "name": "agent-test-summary",
        "args": ["agent", "test-summary", "--module", "{module}"],
        "mutates": False,
        "expect_json": True,
    },
    {
        "name": "agent-test-summary-short",
        "args": ["agent", "test-summary", "--module", "{module}", "--short"],
        "mutates": False,
        "expect_json": True,
    },
]

DEFAULT_BUDGETS: dict[str, int | None] = {
    "agent-context": 12000,
    "agent-inspect-addon": 6000,
    "agent-inspect-addon-full": None,
}


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def redact(text: str) -> str:
    value = text
    for pat in SECRET_PATTERNS:
        value = pat.sub(
            lambda m: (
                f"{m.group(1)}=<redacted>"
                if len(m.groups()) == 2
                else f"{m.group(1)}<redacted>{m.group(3)}"
            ),
            value,
        )
    return value


def approx_tokens(text: str) -> int:
    # Conservative enough for comparisons; exact tokenizer is not needed here.
    return int(math.ceil(len(text) / 4))


def stable_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def find_json_payload(stdout: str) -> Any | None:
    text = stdout.strip()
    if not text:
        return None
    for candidate in (
        text,
        *reversed([line.strip() for line in text.splitlines() if line.strip()]),
    ):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()
    for idx, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            payload, _end = decoder.raw_decode(text[idx:])
            return payload
        except json.JSONDecodeError:
            continue
    return None


def walk_json(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    items = [(path, value)]
    if isinstance(value, dict):
        for key, child in value.items():
            items.extend(walk_json(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            items.extend(walk_json(child, f"{path}[{idx}]"))
    return items


def json_depth(value: Any) -> int:
    if isinstance(value, dict) and value:
        return 1 + max(json_depth(v) for v in value.values())
    if isinstance(value, list) and value:
        return 1 + max(json_depth(v) for v in value)
    return 1


def summarize_json(value: Any) -> dict[str, Any]:
    nodes = walk_json(value)
    field_sizes: list[dict[str, Any]] = []
    large_strings: list[dict[str, Any]] = []
    repeated: dict[str, list[str]] = defaultdict(list)

    for path, node in nodes:
        encoded = stable_json(node)
        size = len(encoded.encode("utf-8"))
        entry = {"path": path, "type": type(node).__name__, "bytes": size}
        if isinstance(node, list | dict | str):
            entry["length"] = len(node)
        field_sizes.append(entry)

        if isinstance(node, str) and len(node) >= 120:
            large_strings.append(
                {"path": path, "chars": len(node), "preview": node[:160]}
            )

        if size >= 80 and isinstance(node, str | int | float | bool | list | dict):
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]
            repeated[digest].append(path)

    duplicates = [paths for paths in repeated.values() if len(paths) > 1]
    duplicates = sorted(duplicates, key=len, reverse=True)[:20]

    return {
        "json_type": type(value).__name__,
        "json_minified_bytes": len(stable_json(value).encode("utf-8")),
        "json_key_count": sum(
            1 for _p, node in nodes if isinstance(node, dict) for _k in node.keys()
        ),
        "json_node_count": len(nodes),
        "json_max_depth": json_depth(value),
        "top_level_keys": list(value.keys()) if isinstance(value, dict) else [],
        "largest_fields": sorted(field_sizes, key=lambda x: x["bytes"], reverse=True)[
            :25
        ],
        "large_strings": sorted(large_strings, key=lambda x: x["chars"], reverse=True)[
            :25
        ],
        "duplicate_value_paths": duplicates,
    }


def expand_args(args: list[str], module: str, test_tags: str | None) -> list[str]:
    mapping = {
        "module": module,
        "test_tags": test_tags or f"/{module}",
    }
    return [arg.format(**mapping) for arg in args]


def build_command(
    oduit_bin: str,
    env_name: str | None,
    spec: dict[str, Any],
    module: str,
    test_tags: str | None,
) -> list[str]:
    args = expand_args(list(spec["args"]), module=module, test_tags=test_tags)
    cmd = [oduit_bin]
    if env_name and "--env" not in args and "-e" not in args:
        cmd.extend(["--env", env_name])
    cmd.extend(args)
    return cmd


def run_one(
    cmd: list[str], cwd: Path | None, timeout: int, env: dict[str, str]
) -> dict[str, Any]:
    started = _dt.datetime.now().isoformat(timespec="seconds")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        stdout = redact(proc.stdout)
        stderr = redact(proc.stderr)
        return {
            "started_at": started,
            "timed_out": False,
            "return_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = redact(exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = redact(exc.stderr or "") if isinstance(exc.stderr, str) else ""
        return {
            "started_at": started,
            "timed_out": True,
            "return_code": None,
            "stdout": stdout,
            "stderr": stderr,
            "error": f"timeout after {timeout}s",
        }


def measure_record(
    name: str,
    cmd: list[str],
    raw: dict[str, Any],
    expect_json: bool,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    stdout = raw.get("stdout") or ""
    stderr = raw.get("stderr") or ""
    combined = stdout + stderr
    payload = find_json_payload(stdout)
    record: dict[str, Any] = {
        "name": name,
        "cmd": cmd,
        "return_code": raw.get("return_code"),
        "timed_out": raw.get("timed_out", False),
        "expect_json": expect_json,
        "json_ok": payload is not None,
        "stdout_bytes": len(stdout.encode("utf-8")),
        "stderr_bytes": len(stderr.encode("utf-8")),
        "combined_bytes": len(combined.encode("utf-8")),
        "stdout_lines": stdout.count("\n") + (1 if stdout else 0),
        "stderr_lines": stderr.count("\n") + (1 if stderr else 0),
        "approx_tokens": approx_tokens(combined),
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
    }
    if payload is not None:
        record.update(summarize_json(payload))
    elif expect_json:
        record["json_error"] = "No JSON payload could be parsed from stdout."
    if max_bytes is not None:
        record["budget_bytes"] = int(max_bytes)
        if record["combined_bytes"] > int(max_bytes):
            record["budget_exceeded"] = True
    if raw.get("error"):
        record["error"] = raw["error"]
    return record


def discover_agent_help(
    oduit_bin: str,
    env_name: str | None,
    cwd: Path | None,
    timeout: int,
    env: dict[str, str],
) -> dict[str, Any]:
    cmd = [oduit_bin]
    if env_name:
        cmd.extend(["--env", env_name])
    cmd.extend(["agent", "--help"])
    raw = run_one(cmd, cwd, timeout, env)
    text = strip_ansi((raw.get("stdout") or "") + "\n" + (raw.get("stderr") or ""))
    commands: list[str] = []
    in_commands = False
    for line in text.splitlines():
        low = line.strip().lower()
        if low.startswith("commands") or low == "commands:":
            in_commands = True
            continue
        if in_commands:
            m = re.match(r"^\s{1,}([a-z][a-z0-9_-]{1,})\b", line)
            if m and m.group(1) not in {"options", "arguments"}:
                commands.append(m.group(1))
    return {
        "command": cmd,
        "return_code": raw.get("return_code"),
        "discovered_commands": sorted(set(commands)),
        "help_text": text,
    }


def write_markdown_summary(
    out_path: Path, records: list[dict[str, Any]], discovery: dict[str, Any] | None
) -> None:
    rows = sorted(records, key=lambda r: r["combined_bytes"], reverse=True)
    lines = [
        "# oduit agent output audit summary",
        "",
        f"Generated: {_dt.datetime.now().isoformat(timespec='seconds')}",
        "",
    ]
    if discovery:
        lines.extend(
            [
                "## Discovered agent commands",
                "",
                f"Discovery command: `{' '.join(discovery['command'])}`",
                f"Return code: `{discovery.get('return_code')}`",
                "",
            ]
        )
        if discovery.get("discovered_commands"):
            lines.extend(["Commands parsed from help:", ""])
            for cmd in discovery["discovered_commands"]:
                lines.append(f"- `{cmd}`")
            lines.append("")
        else:
            lines.append(
                "No subcommands were parsed from "
                "`oduit agent --help`. Check `agent-help.txt`.\n"
            )

    lines.extend(
        [
            "## Output size ranking",
            "",
            "| Command | rc | JSON | stdout bytes | stderr bytes "
            "| lines | approx tokens | largest JSON field |"
            "|---|---:|:---:|---:|---:|---:|---:|---|",
        ]
    )
    for r in rows:
        largest = ""
        if r.get("largest_fields"):
            f = r["largest_fields"][0]
            largest = f"`{f['path']}` ({f['bytes']} B)"
        lines.append(
            f"| `{r['name']}` | {r.get('return_code')} "
            f"| {'yes' if r.get('json_ok') else 'no'} "
            f"| {r['stdout_bytes']} | {r['stderr_bytes']} "
            f"| {r['stdout_lines'] + r['stderr_lines']} "
            f"| {r['approx_tokens']} | {largest} |"
        )

    lines.extend(["", "## Per-command findings", ""])
    for r in rows:
        lines.extend(
            [
                f"### `{r['name']}`",
                "",
                f"Command: `{' '.join(r['cmd'])}`",
                f"Return code: `{r.get('return_code')}`; "
                f"timed out: `{r.get('timed_out')}`",
                f"Combined bytes: `{r['combined_bytes']}`; "
                f"approx tokens: `{r['approx_tokens']}`",
            ]
        )
        if r.get("json_ok"):
            lines.extend(
                [
                    f"JSON minified bytes: `{r.get('json_minified_bytes')}`",
                    f"JSON key count: `{r.get('json_key_count')}`; "
                    f"max depth: `{r.get('json_max_depth')}`",
                    f"Top-level keys: `{', '.join(r.get('top_level_keys') or [])}`",
                    "",
                    "Largest fields:",
                ]
            )
            for f in (r.get("largest_fields") or [])[:10]:
                lines.append(f"- `{f['path']}`: {f['bytes']} B, type `{f['type']}`")
            duplicates = r.get("duplicate_value_paths") or []
            if duplicates:
                lines.extend(["", "Duplicate value groups:"])
                for group in duplicates[:10]:
                    lines.append("- " + ", ".join(f"`{p}`" for p in group[:8]))
            large_strings = r.get("large_strings") or []
            if large_strings:
                lines.extend(["", "Large strings:"])
                for s in large_strings[:10]:
                    preview = str(s["preview"]).replace("\n", " ")
                    lines.append(f"- `{s['path']}`: {s['chars']} chars — `{preview}`")
        elif r.get("expect_json"):
            lines.append(f"JSON issue: `{r.get('json_error')}`")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def load_matrix(path: Path | None) -> list[dict[str, Any]]:
    if not path:
        matrix = [dict(spec) for spec in DEFAULT_MATRIX]
        for spec in matrix:
            name = str(spec.get("name") or "")
            if "max_bytes" not in spec and name in DEFAULT_BUDGETS:
                spec["max_bytes"] = DEFAULT_BUDGETS[name]
        return matrix
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("commands", [])
    if not isinstance(data, list):
        raise SystemExit(
            "matrix file must be a JSON list or an object with a 'commands' list"
        )
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oduit-bin", default="oduit")
    parser.add_argument(
        "--env",
        dest="env_name",
        default=None,
        help="oduit environment name to pass as --env",
    )
    parser.add_argument(
        "--workdir", type=Path, default=None, help="Run commands from this directory"
    )
    parser.add_argument(
        "--module", default=os.environ.get("ODUIT_AUDIT_MODULE", "base")
    )
    parser.add_argument("--test-tags", default=os.environ.get("ODUIT_AUDIT_TEST_TAGS"))
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--matrix-file", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, default=Path(".oduit-output-audit"))
    parser.add_argument(
        "--allow-mutating", action="store_true", help="Allow specs with mutates=true"
    )
    parser.add_argument("--skip-discovery", action="store_true")
    parser.add_argument("--fail-on-budget", action="store_true")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.setdefault("NO_COLOR", "1")
    env.setdefault("PYTHONUNBUFFERED", "1")

    discovery = None
    if not args.skip_discovery:
        discovery = discover_agent_help(
            args.oduit_bin, args.env_name, args.workdir, min(args.timeout, 60), env
        )
        (args.out_dir / "agent-help.txt").write_text(
            discovery.get("help_text", ""), encoding="utf-8"
        )

    matrix = load_matrix(args.matrix_file)
    records: list[dict[str, Any]] = []
    raw_dir = args.out_dir / "raw"
    raw_dir.mkdir(exist_ok=True)

    for spec in matrix:
        if spec.get("mutates") and not args.allow_mutating:
            continue
        name = spec.get("name") or " ".join(spec.get("args") or [])
        cmd = build_command(
            args.oduit_bin, args.env_name, spec, args.module, args.test_tags
        )
        raw = run_one(cmd, args.workdir, int(spec.get("timeout", args.timeout)), env)
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name).strip("-") or "command"
        (raw_dir / f"{safe_name}.stdout.txt").write_text(
            raw.get("stdout") or "", encoding="utf-8"
        )
        (raw_dir / f"{safe_name}.stderr.txt").write_text(
            raw.get("stderr") or "", encoding="utf-8"
        )
        rec = measure_record(
            name,
            cmd,
            raw,
            bool(spec.get("expect_json", True)),
            (int(spec["max_bytes"]) if spec.get("max_bytes") is not None else None),
        )
        records.append(rec)
        print(
            f"{name}: {rec['combined_bytes']} bytes, "
            f"~{rec['approx_tokens']} tokens, json={rec['json_ok']}"
        )

    jsonl_path = args.out_dir / "agent-output-audit.jsonl"
    jsonl_path.write_text(
        "\n".join(stable_json(r) for r in records) + "\n", encoding="utf-8"
    )
    json_path = args.out_dir / "agent-output-audit.json"
    json_path.write_text(
        json.dumps(
            {"discovery": discovery, "records": records}, indent=2, ensure_ascii=False
        ),
        encoding="utf-8",
    )
    write_markdown_summary(args.out_dir / "agent-output-audit.md", records, discovery)

    print(f"\nWrote {jsonl_path}")
    print(f"Wrote {json_path}")
    print(f"Wrote {args.out_dir / 'agent-output-audit.md'}")
    if args.fail_on_budget and any(r.get("budget_exceeded") for r in records):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
