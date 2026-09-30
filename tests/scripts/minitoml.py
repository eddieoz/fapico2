#!/usr/bin/env python3
"""The repository's only TOML reader. Stdlib only; Python 3.8+.

Why this exists at all
----------------------

`tests/scripts/` is stdlib-only by house rule, and the policy files the
supply-chain gates read (`deny-graph.toml`, `supply-chain/exemption-reasons.toml`)
are TOML. Python 3.11 has `tomllib`; the interpreter this repository's gates
actually run under here is 3.9, and CI's is 3.12 — so a `tomllib` import would
work in CI and fail locally, which is the worst of both.

The alternative — a `tomllib` path plus a fallback parser — is two readers of
the same file, and two readers is how a gate and its own copy of the rules
drift apart. US-181 made the same argument about a second length parser over
ISO 7816 command headers, and the rule it established is the one followed
here: ONE reader, and it raises on anything it does not model rather than
guessing. A parse failure is a gate failure, never a silent pass.

What it models, deliberately and no more
----------------------------------------

* top-level `key = value` and `[table]` headers, which nest one level
* `key = [ ... ]`, possibly spanning lines
* strings, booleans and integers

Anything else — dotted keys, inline tables, multi-line strings, arrays of
tables — raises `TomlError`. That is a feature: the policy files are ours, and
a construct the reader does not understand is a construct the gates would
silently mis-read.
"""

from __future__ import annotations

import json
from pathlib import Path


class TomlError(Exception):
    """The file uses something this reader does not model."""


def _strip_comment(line: str) -> str:
    """Drop a `#` comment, respecting quoted strings."""
    out, in_str, esc = [], False, False
    for ch in line:
        if esc:
            out.append(ch)
            esc = False
            continue
        if ch == "\\" and in_str:
            out.append(ch)
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            out.append(ch)
            continue
        if ch == "#" and not in_str:
            break
        out.append(ch)
    if in_str:
        raise TomlError(f"unterminated string in: {line!r}")
    return "".join(out)


def _key(raw: str, where: str) -> str:
    key = raw.strip()
    if len(key) >= 2 and key[0] == '"' and key[-1] == '"':
        return json.loads(key)          # the escapes TOML and JSON share
    if not key or " " in key:
        raise TomlError(f"{where}: unsupported key {raw!r}")
    return key


def _scalar(text: str, where: str):
    text = text.strip()
    if text.startswith('"'):
        if not text.endswith('"') or len(text) < 2:
            raise TomlError(f"{where}: unterminated string value: {text!r}")
        return json.loads(text)
    if text in ("true", "false"):
        return text == "true"
    try:
        return int(text)
    except ValueError:
        pass
    raise TomlError(
        f"{where}: unsupported value {text!r} (this reader models strings, "
        f"bools and ints only)"
    )


def _array_items(text: str, where: str) -> tuple[list, bool]:
    """Split an array literal. Returns (items, closed_on_this_line)."""
    text = text.strip()
    if text.startswith("["):
        text = text[1:]
    items, buf, in_str, esc = [], [], False, False
    for ch in text:
        if esc:
            buf.append(ch)
            esc = False
            continue
        if ch == "\\" and in_str:
            buf.append(ch)
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            buf.append(ch)
            continue
        if ch == "," and not in_str:
            items.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if in_str:
        raise TomlError(f"{where}: unterminated string in array: {text!r}")
    tail = "".join(buf).strip()
    closed = tail.endswith("]")
    if closed:
        tail = tail[:-1].strip()
    if tail:
        items.append(tail)
    return [i.strip() for i in items if i.strip()], closed


def read_toml(path) -> dict:
    """Read the subset above. `path` may be a str or a Path.

    Returns a dict of table-name -> dict, plus the top-level keys under the
    table name ``""`` — so a flat file comes back as ``{"": {...}}`` and a
    caller that only ever reads flat files can say so.
    """
    path = Path(path)
    where = path.name
    doc: dict = {"": {}}
    table = ""
    pending_key = None
    pending_items: list = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if pending_key is not None:
            items, closed = _array_items(line, where)
            pending_items.extend(_scalar(i, where) for i in items)
            if closed:
                doc[table][pending_key] = pending_items
                pending_key, pending_items = None, []
            continue
        if line.startswith("[["):
            raise TomlError(
                f"{where}: arrays of tables are not modelled by this reader "
                f"(saw {line!r})"
            )
        if line.startswith("["):
            if not line.endswith("]"):
                raise TomlError(f"{where}: malformed table header {line!r}")
            name = _key(line[1:-1], where)
            if not name:
                raise TomlError(f"{where}: empty table name")
            table = name
            doc.setdefault(table, {})
            continue
        if "=" not in line:
            raise TomlError(f"{where}: neither a table nor a key = value: {line!r}")
        raw_key, _, rest = line.partition("=")
        key = _key(raw_key, where)
        rest = rest.strip()
        if rest.startswith("["):
            items, closed = _array_items(rest, where)
            values = [_scalar(i, where) for i in items]
            if closed:
                doc[table][key] = values
            else:
                pending_key, pending_items = key, values
        else:
            doc[table][key] = _scalar(rest, where)
    if pending_key is not None:
        raise TomlError(f"{where}: array for {pending_key!r} is never closed")
    return doc
