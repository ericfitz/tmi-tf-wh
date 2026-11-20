"""Export an anonymized DFD fixture from a real TMI diagram.

Usage:
  uv run python scripts/export_tmi_dfd.py --threat-model-id ID            # list diagrams
  uv run python scripts/export_tmi_dfd.py --threat-model-id ID --diagram-id ID --out PATH
  uv run python scripts/export_tmi_dfd.py --cells-file cells.json --out PATH   # offline

Reads the diagram's cells, maps them to the DFDBuilder component/flow format,
replaces every id and name with a same-length placeholder, drops geometry and
metadata, and refuses to write if any original string or address-like value
survives. --out is refused if it exists unless --force. Review the output by
hand as well; the leak check is a first pass.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from tmi_tf.config import Config
from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.tmi_client_wrapper import TMIClient

Dfd = dict[str, list[dict[str, Any]]]

SHAPE_TYPE = {
    "security-boundary": "container",
    "process": "service",
    "store": "storage",
    "actor": "actor",
}

_VALID_TYPES = DFDBuilder.BOUNDARY_TYPES | DFDBuilder.LEAF_TYPES

_LEAK_PATTERNS = [
    ("IPv4 address", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ("12-digit run", re.compile(r"\d{12}")),
    (
        "UUID",
        re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        ),
    ),
    ("hostname", re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", re.IGNORECASE)),
]


class ExportError(Exception):
    """The diagram cannot be exported (bad cell, or an anonymization leak)."""


def _is_edge(cell: dict[str, Any]) -> bool:
    return "source" in cell and "target" in cell


def _component_type(cell: dict[str, Any]) -> str:
    cid = cell.get("id")
    data = cell.get("data") or {}
    metadata = data.get("_metadata") if isinstance(data, dict) else None
    if metadata is not None and not isinstance(metadata, list):
        raise ExportError(f"cell {cid}: data._metadata is not a list")
    for item in metadata or []:
        if not isinstance(item, dict):
            raise ExportError(f"cell {cid}: metadata item is not an object")
        if item.get("key") == "component_type":
            value = item.get("value")
            if not isinstance(value, str) or value not in _VALID_TYPES:
                raise ExportError(f"cell {cid}: unknown component_type {value!r}")
            return value
    shape = cell.get("shape")
    if shape not in SHAPE_TYPE:
        raise ExportError(f"cell {cid}: unknown shape {shape!r}")
    return SHAPE_TYPE[shape]


def _text(holder: Any) -> str:
    text = (((holder or {}).get("attrs") or {}).get("text") or {}).get("text")
    return text if isinstance(text, str) else ""


def cells_to_dfd(cells: list[dict[str, Any]]) -> Dfd:
    """Map X6 cells to {"components": [...], "flows": [...]} (not anonymized)."""
    seen: set[Any] = set()
    for i, cell in enumerate(cells):
        cid = cell.get("id")
        if not isinstance(cid, str) or not cid:
            raise ExportError(f"cell at index {i}: missing or non-string id")
        if cid in seen:
            raise ExportError(f"cell {cid}: duplicate cell id")
        seen.add(cid)
    node_ids = {c["id"] for c in cells if not _is_edge(c)}
    components: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    for cell in cells:
        cid = cell.get("id")
        if _is_edge(cell):
            ends = {}
            for end in ("source", "target"):
                ref = (cell.get(end) or {}).get("cell")
                if ref not in node_ids:
                    raise ExportError(f"cell {cid}: {end} {ref!r} is not a node")
                ends[end + "_id"] = ref
            labels = cell.get("labels") or []
            flows.append(
                {
                    "id": cid,
                    "name": _text(labels[0]) if labels else "",
                    **ends,
                    "bidirectional": False,
                }
            )
            continue
        component: dict[str, Any] = {
            "id": cid,
            "name": _text(cell),
            "type": _component_type(cell),
        }
        parent = cell.get("parent")
        if parent is not None:
            if parent == cid:
                raise ExportError(f"cell {cid}: parent is the cell itself")
            if parent not in node_ids:
                raise ExportError(f"cell {cid}: parent {parent!r} is not a node")
            component["parent_id"] = parent
        components.append(component)
    return {"components": components, "flows": flows}


def placeholder(prefix: str, n: int, length: int) -> str:
    """A same-length placeholder: f'{prefix}{n:04d}' truncated or padded with x."""
    return f"{prefix}{n:04d}"[:length].ljust(length, "x")


def anonymize(dfd: Dfd) -> Dfd:
    """Replace ids and names with placeholders; output has only fixture keys."""
    cmap = {c["id"]: f"c{i:04d}" for i, c in enumerate(dfd["components"], 1)}
    components = []
    for i, c in enumerate(dfd["components"], 1):
        out: dict[str, Any] = {
            "id": cmap[c["id"]],
            "name": placeholder("c", i, len(c["name"])),
            "type": c["type"],
        }
        if c.get("parent_id") is not None:
            out["parent_id"] = cmap[c["parent_id"]]
        components.append(out)
    flows = [
        {
            "id": f"f{i:04d}",
            "name": placeholder("f", i, len(f["name"])),
            "source_id": cmap[f["source_id"]],
            "target_id": cmap[f["target_id"]],
            "bidirectional": False,
        }
        for i, f in enumerate(dfd["flows"], 1)
    ]
    return {"components": components, "flows": flows}


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def find_leaks(cells: list[dict[str, Any]], dfd: Dfd) -> list[str]:
    """One message per output string (except type) that echoes the input or looks
    like an address, naming the output component or flow holding it."""
    originals = {s.lower() for s in _strings(cells) if len(s) >= 4}
    leaks = []
    for section, kind in (("components", "component"), ("flows", "flow")):
        for item in dfd[section]:
            for key, value in item.items():
                if key == "type":
                    continue
                for s in _strings(value):
                    low = s.lower()
                    for orig in sorted(o for o in originals if o in low):
                        leaks.append(
                            f"{kind} {item['id']} {key}: contains input string {orig!r}"
                        )
                    for label, pattern in _LEAK_PATTERNS:
                        if pattern.search(s):
                            leaks.append(
                                f"{kind} {item['id']} {key}: matches {label} in {s!r}"
                            )
    return leaks


def export_cells(cells: list[dict[str, Any]]) -> Dfd:
    """cells_to_dfd, anonymize, then find_leaks; any leak raises ExportError."""
    dfd = anonymize(cells_to_dfd(cells))
    leaks = find_leaks(cells, dfd)
    if leaks:
        raise ExportError("anonymization leaks:\n" + "\n".join(leaks))
    return dfd


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--cells-file", help="JSON list of cells (offline)")
    src.add_argument("--threat-model-id", help="threat model to read from TMI")
    p.add_argument("--diagram-id", help="diagram to export (omit to list diagrams)")
    p.add_argument("--out", help="output fixture path")
    p.add_argument("--force", action="store_true", help="overwrite --out")
    return p.parse_args(argv)


def _load_cells(path: str) -> list[dict[str, Any]]:
    try:
        cells = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ExportError(f"cannot read cells file {path}: {e}") from e
    if not isinstance(cells, list) or not all(isinstance(c, dict) for c in cells):
        raise ExportError(f"cells file {path} must be a JSON list of objects")
    return cells


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    listing = args.threat_model_id and not args.diagram_id
    try:
        out = Path(args.out) if args.out else None
        if not listing:
            if out is None:
                raise ExportError("--out is required")
            if out.exists() and not args.force:
                raise ExportError(f"{out} exists; use --force to overwrite")
        if args.cells_file:
            cells = _load_cells(args.cells_file)
        else:
            try:
                client = TMIClient.create_authenticated(Config())
                if listing:
                    for d in client.get_threat_model_diagrams(args.threat_model_id):
                        print(f"{d.id}\t{d.name}")
                    return 0
                cells = client.get_diagram_cells(args.threat_model_id, args.diagram_id)
            except Exception as e:
                raise ExportError(f"TMI request failed: {e}") from e
        assert out is not None
        dfd = export_cells(cells)
        text = json.dumps(dfd, indent=2) + "\n"
        try:
            with open(out, "w" if args.force else "x", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            raise ExportError(f"cannot write {out}: {e}") from e
    except ExportError as e:
        print(str(e), file=sys.stderr)
        return 2
    print(
        f"exported {len(dfd['components'])} components, {len(dfd['flows'])} flows -> {out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
