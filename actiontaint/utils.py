from __future__ import annotations

import json
import re
from pathlib import Path

SOURCE_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx"}
IGNORED_DIRS = {
    ".git",
    ".next",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".turbo",
    ".vercel",
    ".actiontaint",
}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def rel_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def line_number_for_index(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def is_ignored(path: Path) -> bool:
    return any(part in IGNORED_DIRS for part in path.parts)


def top_level_directive(text: str, directive: str) -> bool:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("/*"):
            continue
        return bool(re.fullmatch(rf"['\"]{re.escape(directive)}['\"]\s*;?", line))
    return False


def first_statement_directive(body: str, directive: str) -> bool:
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("/*"):
            continue
        return bool(re.fullmatch(rf"['\"]{re.escape(directive)}['\"]\s*;?", line))
    return False


def find_matching_brace(text: str, open_index: int) -> int | None:
    depth = 0
    quote: str | None = None
    escape = False
    line_comment = False
    block_comment = False
    i = open_index
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue

        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
                continue
            i += 1
            continue

        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def split_top_level_args(text: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escape = False
    for ch in text:
        if quote:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current or text.strip():
        args.append("".join(current).strip())
    return args


def strip_ts_type(param: str) -> tuple[str, str | None]:
    raw = param.strip()
    raw = re.sub(r"^\.\.\.", "", raw)
    if not raw:
        return "", None
    before_default = raw.split("=", 1)[0].strip()
    if ":" in before_default:
        name, type_hint = before_default.split(":", 1)
        return name.strip(), type_hint.strip()
    return before_default.strip(), None


def parse_parameters(params_text: str) -> list[tuple[str, str | None, str]]:
    params: list[tuple[str, str | None, str]] = []
    for item in split_top_level_args(params_text):
        name, type_hint = strip_ts_type(item)
        if name:
            params.append((name, type_hint, item.strip()))
    return params


def is_literal_expr(expr: str) -> bool:
    stripped = expr.strip()
    if stripped.startswith("`") and "${" in stripped:
        return False
    if re.fullmatch(r"\d+(?:\.\d+)?|true|false|null|undefined", stripped):
        return True
    if not stripped or stripped[0] not in {"'", '"', "`"}:
        return False
    quote = stripped[0]
    escape = False
    for index in range(1, len(stripped)):
        ch = stripped[index]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == quote:
            return index == len(stripped) - 1
    return False


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
