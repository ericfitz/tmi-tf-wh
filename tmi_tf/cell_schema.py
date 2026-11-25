"""TMI conformance for generated diagram cells (#107).

TMI accepts a diagram's cells on create without checking them, then rejects
the same cells on a later PATCH, so a non-conforming diagram cannot be saved
from the UI. `clean_metadata` keeps `_metadata` lists inside the TMI `Metadata`
schema, and `validate_cells` checks every cell against the vendored Node/Edge
schemas (`data/tmi_cell_schema.json`, refreshed by `scripts/sync_cell_schema.py`)
plus the reference invariants the schema cannot express, before anything is
written to TMI.

Error messages carry JSON paths and schema keywords only, never instance
values: cell text is LLM-derived and must not reach notes or logs verbatim.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # pyright: ignore[reportMissingModuleSource]

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).parent / "data" / "tmi_cell_schema.json"

METADATA_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9_./:-]+$")
METADATA_KEY_MAX = 256
METADATA_VALUE_MAX = 1024
METADATA_MAX_ITEMS = 100
LABEL_TEXT_MAX = 256
_ELLIPSIS = "…"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")

NODE_SHAPES = frozenset({"actor", "process", "store", "security-boundary", "text-box"})
EDGE_SHAPES = frozenset({"flow"})
_MAX_REPORTED = 20


class CellSchemaError(ValueError):
    """Generated cells do not conform to the TMI diagram schema."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        shown = "; ".join(problems[:_MAX_REPORTED])
        more = len(problems) - _MAX_REPORTED
        suffix = f"; and {more} more" if more > 0 else ""
        super().__init__(f"{len(problems)} schema violation(s): {shown}{suffix}")


def clean_metadata(entries: Iterable[tuple[str, object]]) -> list[dict[str, str]]:
    """Turn (key, value) pairs into TMI-valid `Metadata` dicts.

    - A value that is None or blank after `str()` is omitted (TMI requires 1+ chars).
    - A key that is not 1-256 chars of `[a-zA-Z0-9_./:-]` is omitted with a warning.
    - A value over 1024 chars is truncated, ending in an ellipsis.
    - A repeated key keeps its first value.
    - At most 100 entries are kept.
    """
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for key, value in entries:
        if value is None:
            continue
        text = str(value)
        if not text.strip():
            continue
        if (
            not isinstance(key, str)
            or len(key) > METADATA_KEY_MAX
            or not METADATA_KEY_PATTERN.fullmatch(key)
        ):
            logger.warning("Dropping metadata entry with an invalid key")
            continue
        if key in seen:
            continue
        text = _truncate(text, METADATA_VALUE_MAX)
        seen.add(key)
        result.append({"key": key, "value": text})
        if len(result) == METADATA_MAX_ITEMS:
            logger.warning("Metadata capped at %d entries", METADATA_MAX_ITEMS)
            break
    return result


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - len(_ELLIPSIS)] + _ELLIPSIS


def clean_text(value: object, limit: int = LABEL_TEXT_MAX) -> str:
    """Make LLM-supplied label text fit TMI's label schema (`^[^\\x00-\\x1F]*$`,
    at most 256 chars): None becomes "", control-character runs become one
    space, the ends are stripped, and over-long text is truncated with an
    ellipsis."""
    if value is None:
        return ""
    return _truncate(_CONTROL.sub(" ", str(value)).strip(), limit)


@cache
def _validators() -> dict[str, Draft202012Validator]:
    document = json.loads(SCHEMA_PATH.read_text())
    out = {}
    for name in ("Node", "Edge"):
        root = dict(document, **{"$ref": f"#/components/schemas/{name}"})
        Draft202012Validator.check_schema(root)
        out[name] = Draft202012Validator(
            root, format_checker=Draft202012Validator.FORMAT_CHECKER
        )
    return out


def _path(prefix: str, parts: Iterable[Any]) -> str:
    return prefix + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in parts)


def validate_cells(cells: list[dict[str, Any]]) -> None:
    """Raise CellSchemaError unless every cell conforms to TMI's Node/Edge schema
    and every reference resolves.

    Invariants beyond the schema: cell ids are unique; every edge has a source
    and a target whose `cell` names a node in `cells`; a terminal on a node that
    declares ports names one of them, and a terminal on a node without ports
    (a trust boundary) has none; every `parent` names a node and every
    `children` id names a cell.
    """
    validators = _validators()
    problems: list[str] = []
    node_ids: set[str] = set()
    node_ports: dict[str, set[str]] = {}
    ids: set[str] = set()

    for i, cell in enumerate(cells):
        where = f"cells[{i}]"
        if not isinstance(cell, dict):
            problems.append(f"{where}: not an object")
            continue
        cell_id = cell.get("id")
        if isinstance(cell_id, str):
            if cell_id in ids:
                problems.append(f"{where}.id: duplicate")
            ids.add(cell_id)
        shape = cell.get("shape")
        if shape in NODE_SHAPES:
            kind = "Node"
            if isinstance(cell_id, str):
                node_ids.add(cell_id)
                items = (cell.get("ports") or {}).get("items") or []
                node_ports[cell_id] = {
                    p["id"] for p in items if isinstance(p, dict) and "id" in p
                }
        elif shape in EDGE_SHAPES:
            kind = "Edge"
        else:
            problems.append(f"{where}.shape: unknown shape")
            continue
        for error in validators[kind].iter_errors(cell):
            problems.append(f"{_path(where, error.absolute_path)}: {error.validator}")

    for i, cell in enumerate(cells):
        if not isinstance(cell, dict):
            continue
        where = f"cells[{i}]"
        if cell.get("shape") in EDGE_SHAPES:
            for end in ("source", "target"):
                terminal = cell.get(end)
                if not isinstance(terminal, dict):
                    problems.append(f"{where}.{end}: missing")
                    continue
                node = terminal.get("cell")
                if node not in node_ids:
                    problems.append(f"{where}.{end}.cell: does not name a node")
                    continue
                declared = node_ports.get(node)
                port = terminal.get("port")
                if declared and port not in declared:
                    problems.append(
                        f"{where}.{end}.port: "
                        + ("missing" if not port else "not a port of its node")
                    )
                elif not declared and port:
                    problems.append(f"{where}.{end}.port: node declares no ports")
        elif cell.get("shape") in NODE_SHAPES:
            parent = cell.get("parent")
            if parent and parent not in node_ids:
                problems.append(f"{where}.parent: does not name a node")
            for j, child in enumerate(cell.get("children") or []):
                if child not in ids:
                    problems.append(f"{where}.children[{j}]: does not name a cell")

    if problems:
        logger.error("Generated DFD cells violate the TMI schema: %s", problems)
        raise CellSchemaError(problems)
