"""Shared DFD inputs for layout property tests: hand cases, seeded random trees, fixtures.

`python tests/dfd_cases.py` prints a digest of every case's cells in both directions; the
determinism test compares it across processes with different PYTHONHASHSEED values.
"""

import hashlib
import json
import random
import re
from pathlib import Path
from typing import Any

from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.layout import compound

Components = list[dict[str, Any]]
Flows = list[dict[str, Any]]

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "dfd"

BOUNDARY_TYPES = ["tenant", "container", "network"]
LEAF_TYPES = ["gateway", "compute", "service", "storage", "actor"]


def comp(
    id: str, type: str, parent_id: str | None = None, **extra: Any
) -> dict[str, Any]:
    c: dict[str, Any] = {"id": id, "name": id, "type": type}
    if parent_id is not None:
        c["parent_id"] = parent_id
    c.update(extra)
    return c


def flow(
    id: str,
    source_id: str,
    target_id: str,
    name: str = "flow",
    bidirectional: bool = False,
) -> dict[str, Any]:
    return {
        "id": id,
        "name": name,
        "source_id": source_id,
        "target_id": target_id,
        "bidirectional": bidirectional,
    }


def _deep_nesting() -> tuple[Components, Flows]:
    comps = [
        comp("b1", "tenant"),
        comp("b2", "container", "b1"),
        comp("b3", "network", "b2"),
        comp("b4", "network", "b3"),
        comp("l1", "compute", "b4"),
        comp("l2", "storage", "b4"),
        comp("l3", "actor", "b1"),
    ]
    return comps, [flow("f1", "l1", "l2"), flow("f2", "l3", "l1")]


def _long_edge() -> tuple[Components, Flows]:
    comps = [comp(f"c{i}", "compute") for i in range(6)]
    flows = [flow(f"f{i}", f"c{i}", f"c{i + 1}") for i in range(5)]
    flows.append(flow("long", "c0", "c5", name="a long label for the long edge"))
    return comps, flows


HAND_CASES: dict[str, tuple[Components, Flows]] = {
    "empty": ([], []),
    "single_leaf": ([comp("a", "compute")], []),
    "flat_chain": (
        [comp("a", "actor"), comp("b", "service"), comp("c", "storage")],
        [flow("f1", "a", "b"), flow("f2", "b", "c")],
    ),
    "nested_cross_border": (
        [
            comp("t1", "tenant"),
            comp("n1", "network", "t1"),
            comp("n2", "network", "t1"),
            comp("a", "compute", "n1"),
            comp("b", "storage", "n2"),
            comp("u", "actor"),
        ],
        [flow("f1", "a", "b", "query"), flow("f2", "u", "a", "request")],
    ),
    "two_cycle": (
        [comp("a", "compute"), comp("b", "compute")],
        [flow("f1", "a", "b"), flow("f2", "b", "a")],
    ),
    "bidirectional_pair": (
        [comp("a", "compute"), comp("b", "storage")],
        [flow("f1", "a", "b", "sync", bidirectional=True)],
    ),
    "parallel_flows": (
        [comp("a", "compute"), comp("b", "storage")],
        [flow(f"f{i}", "a", "b", f"flow number {i}") for i in range(4)],
    ),
    "edgeless_block": (
        [comp("t1", "tenant")] + [comp(f"c{i}", "compute", "t1") for i in range(9)],
        [],
    ),
    "deep_nesting": _deep_nesting(),
    "boundary_endpoints": (
        [
            comp("t1", "tenant"),
            comp("t2", "tenant"),
            comp("a", "compute", "t1"),
            comp("b", "compute", "t2"),
        ],
        [flow("f1", "t1", "t2"), flow("f2", "a", "t2"), flow("f3", "t1", "b")],
    ),
    "ancestor_and_self_flows": (
        [comp("t1", "tenant"), comp("c1", "compute", "t1"), comp("c2", "compute")],
        [
            flow("f1", "t1", "c1"),
            flow("f2", "c1", "t1"),
            flow("f3", "c1", "c1"),
            flow("f4", "c2", "c1"),
        ],
    ),
    "long_edge": _long_edge(),
}


def random_dfd(seed: int) -> tuple[Components, Flows]:
    rng = random.Random(seed)
    n = rng.randint(5, 40)
    comps: Components = []
    depth: dict[str, int] = {}
    boundaries: list[str] = []
    for i in range(n):
        cid = f"c{i}"
        is_boundary = rng.random() < 0.3
        eligible = [b for b in boundaries if depth[b] < 3]
        parent = rng.choice(eligible) if eligible and rng.random() < 0.8 else None
        depth[cid] = 0 if parent is None else depth[parent] + 1
        if is_boundary and depth[cid] <= 3:
            comps.append(comp(cid, rng.choice(BOUNDARY_TYPES), parent))
            boundaries.append(cid)
        else:
            comps.append(comp(cid, rng.choice(LEAF_TYPES), parent))
    for c in comps:
        c["name"] = "n" * rng.randint(1, 30)
    leaves = [c for c in comps if c["type"] in LEAF_TYPES]
    ids = [c["id"] for c in comps]
    parent_of = {c["id"]: c.get("parent_id") for c in comps}
    flows: Flows = []
    for k in range(int(1.5 * len(leaves))):
        roll = rng.random()
        if flows and roll < 0.1:
            prev = flows[rng.randrange(len(flows))]
            src, dst = prev["source_id"], prev["target_id"]
        elif roll < 0.15:
            src = dst = rng.choice(ids)
        elif roll < 0.25:
            inner = rng.choice(ids)
            outer = parent_of[inner]
            if outer is None:
                outer = inner
            src, dst = (outer, inner) if rng.random() < 0.5 else (inner, outer)
        else:
            src, dst = rng.choice(ids), rng.choice(ids)
        label = "L" * rng.randint(0, 25)
        flows.append(flow(f"f{k}", src, dst, label, bidirectional=rng.random() < 0.15))
    return comps, flows


def fixture_files() -> list[Path]:
    return sorted(FIXTURE_DIR.glob("*.json"))


def load_fixture(path: Path) -> tuple[Components, Flows]:
    data = json.loads(path.read_text())
    return data["components"], data["flows"]


def all_cases() -> list[tuple[str, Components, Flows]]:
    cases: list[tuple[str, Components, Flows]] = []
    for key, (cs, fs) in HAND_CASES.items():
        cases.append((f"hand:{key}", cs, fs))
    for seed in range(30):
        cs, fs = random_dfd(seed)
        cases.append((f"random:{seed}", cs, fs))
    for path in fixture_files():
        cs, fs = load_fixture(path)
        cases.append((f"fixture:{path.stem}", cs, fs))
    return cases


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def normalize_ids(cells: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace each uuid with `n<index of first appearance>`."""
    seen: dict[str, str] = {}

    def swap(m: re.Match[str]) -> str:
        return seen.setdefault(m.group(0), f"n{len(seen)}")

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return _UUID.sub(swap, v)
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        return v

    return walk(cells)


def digest_all() -> str:
    h = hashlib.sha256()
    saved = compound.LAYOUT_DIRECTION
    try:
        for direction in ("LR", "TB"):
            compound.LAYOUT_DIRECTION = direction  # type: ignore[assignment]
            for name, cs, fs in all_cases():
                cells = DFDBuilder(cs, fs).build_cells()
                h.update(f"{direction}:{name}\n".encode())
                h.update(json.dumps(normalize_ids(cells), sort_keys=True).encode())
    finally:
        compound.LAYOUT_DIRECTION = saved
    return h.hexdigest()


if __name__ == "__main__":
    print(digest_all())
