# DFD Layered Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `DFDBuilder`'s fixed-grid placement with a deterministic layered (Sugiyama-style) layout for nested boundaries, ported from Pele to pure Python, with direction-based ports, bend points, and fanned parallel edges.

**Architecture:** A new X6-agnostic package `tmi_tf/layout/` (`layered.py` flat graph, `compound.py` embedding-tree recursion, `pack.py` shelf packing, `routes.py` polyline helpers). `DFDBuilder` normalizes its input, builds layout nodes/edges, calls `compound_layout`, and maps boxes and routes to cells. Two scripts support the work: `scripts/export_tmi_dfd.py` (anonymized fixtures from real diagrams) and `scripts/preview_dfd.py` (SVG preview).

**Tech Stack:** Python 3.13, stdlib only (dataclasses, math, argparse, json, html), uv, ruff, pyright, pytest.

**Spec:** `docs/superpowers/specs/2026-11-20-dfd-layered-layout-design.md` (read it; this plan argues from it).

## Global Constraints

- No new runtime dependency and no native binary. `tmi_tf/layout/` and both scripts use the standard library only.
- `DFDBuilder.build_cells()` keeps its signature and cell format; the caller `tmi_tf/analyzer.py:565` is not edited.
- Determinism: never iterate a `set`/`frozenset`; build dicts only from input-ordered data; every `sorted()` key ends in an input index; no `hash()`, `id()`, `random`, clock, or uuid in layout code (cell ids stay `uuid4`, tests normalize them).
- All node sizes and every emitted coordinate are `int`. The one rounding function is `floor(v + 0.5)`, applied to child top-left corners inside each level before that level's bounding box is computed, and to route points. Never round a centre or a size independently.
- Sizes are at least 40x30 (API minimum). Leaves are 120x60.
- Leaves have exactly four ports `top/right/bottom/left`; boundaries (`tenant`, `container`, `network`) have none, so an edge end on a boundary is `{"cell": id}` only.
- Edge cell schema: `vertices` is a list of `{"x", "y"}`, at most 1000; `router` is `{"name": "normal"}`; `connector` is `{"name": "smooth"}` (no vertices) or `{"name": "rounded"}` (vertices); a label `position` is a 0-1 fraction.
- One layout direction per diagram: `compound.LAYOUT_DIRECTION`, `"LR"` (default, Eric's decision) or `"TB"`. Callers read it as a module attribute at call time (`from tmi_tf.layout import compound` then `compound.LAYOUT_DIRECTION`), never via `from ... import LAYOUT_DIRECTION` or a default argument, so tests can `monkeypatch.setattr` it.
- Spacing constants (defaults of `compound.LayoutOptions`): `node_sep=40`, `edge_sep=20`, `rank_sep=60`, `pad=30`, `pad_top=60`, `label_margin=24`, `origin=50`. Label width estimate lives only in `compound.label_width`: `0` for empty text, else `min(len(text) * 7 + 16, 240)`.
- Not ported from Pele (spec non-goals): `assignTracks`, `spread`, `settle`, `snap`, `alignLabels`, `alignPorts`, `pastLabels`, `emptyRanks`, Pele's `straighten`, label dummy nodes (`Kind.Label`, the `step = 2` path), `groups`/`orderOnly`/`key`/`hint`/`pin`/`span`, `tailDx`/`headDx` offsets, `routeCrossings`, the `flat` pre-pass, snapshots/refine pass, per-group directions, `BT`/`RL`.
- Pele reference sources (read, port, never paste into the repo verbatim as TypeScript): `<repo root>/.local/pele/{layered.ts,compound.ts,components.ts,class_render.ts}`, commit `3a2f075`. `.local/` is git-ignored, so use the main checkout's path even from a worktree.
- Every file that ports Pele code (`layered.py`, `compound.py`, `pack.py`) starts with this header, `<file>` replaced by the Pele source file:

```python
# Portions of this file are a Python port of Pele (https://github.com/obsidianmd/pele),
# src/layout/<file>, commit 3a2f075, used under the MIT License:
#
# Copyright (c) 2026 kepano
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
```

- `tests/fixtures/dfd/` holds only files written by `scripts/export_tmi_dfd.py` from real diagrams (frozen). Synthetic and hand-written inputs live elsewhere (`tests/fixtures/dfd_export/`, `tests/fixtures/dfd_preview/`, `tests/dfd_cases.py`).
- Tasks 2-9 do not wait for real exports: they run on hand-written cases and seeded random trees. The property tests glob `tests/fixtures/dfd/*.json` (sorted) and pick up exports automatically when they land; an empty directory skips those parameters.
- Scripts are loaded in tests with `importlib.util.spec_from_file_location`, as `tests/test_eval_jev.py` does. Voluminous script output goes to files; stdout gets a one-line summary.
- American English. Stage only the files a task names; never `git add -A`.
- Done gate (run and show before every commit; scripts are included, which already passes today and matches CI's `ruff check .`):
  `uv run ruff check tmi_tf/ tests/ scripts/ && uv run ruff format --check tmi_tf/ tests/ scripts/ && uv run pyright && uv run pytest tests/`

## Review Focus

Inputs the spec implies but its test list does not exercise, most likely first. Each has a test in the owning task.

1. A flow between a component and its own ancestor boundary, or from a component to itself: the edge cell is still emitted with default forward ports and no vertices, and the layout is the same as without that flow. (Tasks 4, 5, 8)
2. `sibling_order` missing, a string, a bool, or duplicated across siblings: falls back to input index, never raises `TypeError`. (Task 5)
3. A `parent_id` naming a component that exists but is a leaf type, or was skipped (unknown type, `network_access_control`): the child becomes a root with a warning and its cell has no `parent`. (Task 5)
4. A very long flow label (200 characters): width estimate is capped at 240 so one label cannot stretch every rank gap of its level. (Task 4)
5. Duplicate component ids, and an empty component list: the second duplicate is skipped with a warning; empty input returns `[]`. (Task 5)

---

### Task 1: Export script and its tests

**Files:**
- Create: `scripts/export_tmi_dfd.py`, `tests/test_export_tmi_dfd.py`, `tests/fixtures/dfd_export/synthetic_cells.json`
- Modify: `tmi_tf/tmi_client_wrapper.py` (add one method after `get_threat_model_diagrams`, line 768), `tests/test_tmi_client_wrapper.py`

**Interfaces:**
- Consumes: `tmi_tf.tmi_client_wrapper.TMIClient` (`create_authenticated(config)`, `get_threat_model_diagrams(tm_id) -> list[DiagramListItem]` with `.id`/`.name`, `sub_resources_api.get_threat_model_diagram(threat_model_id=, diagram_id=) -> DfdDiagram`), `tmi_tf.config.Config`.
- Produces:
  - `TMIClient.get_diagram_cells(self, threat_model_id: str, diagram_id: str) -> list[dict[str, Any]]` (through `_call_with_retry`; returns `json.loads(diagram.to_json()).get("cells") or []`. Not `to_dict()`: the generated models type `id`, `parent` and terminal `cell` as `UUID`, so `to_dict()` is not JSON-native).
  - In `scripts/export_tmi_dfd.py`: `class ExportError(Exception)`; `SHAPE_TYPE: dict[str, str]`; `cells_to_dfd(cells: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]`; `placeholder(prefix: str, n: int, length: int) -> str`; `anonymize(dfd: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]`; `find_leaks(cells: list[dict[str, Any]], dfd: dict[str, list[dict[str, Any]]]) -> list[str]`; `export_cells(cells: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]`; `main(argv: list[str] | None = None) -> int`.
  - Fixture file format, consumed by Tasks 5 and 9: `{"components": [{"id", "name", "type", "parent_id"?}], "flows": [{"id", "name", "source_id", "target_id", "bidirectional": false}]}`.

Pinned behavior:
- A cell is an edge if it has both `source` and `target` keys, otherwise a node. Node geometry may be flat (`x/y/width/height`) or nested (`position`/`size`); it is discarded either way. The generated client serializes absent optionals as `null` (`"parent": null`, `"port": null`, `"labels": null`) and adds defaults (`"angle": 0`, `data.security_boundary`); treat `null` as absent.
- Component type: the `component_type` value in `data._metadata` (a list of `{"key", "value"}`) when present, and it must be one of the eight `DFDBuilder` types (`BOUNDARY_TYPES | LEAF_TYPES`), else `ExportError` naming the cell id. Without it, `SHAPE_TYPE = {"security-boundary": "container", "process": "service", "store": "storage", "actor": "actor"}`; any other shape is `ExportError` naming the cell id.
- `parent` maps to `parent_id`. A `parent`, or an edge `source.cell`/`target.cell`, that is not a node in the same diagram is `ExportError` naming the cell id.
- Node name is `attrs.text.text`; flow name is `labels[0].attrs.text.text`, or `""` when there are no labels. Each edge is one flow with `"bidirectional": False`.
- `placeholder`: `base = f"{prefix}{n:04d}"`; shorter lengths truncate, longer lengths pad with `"x"`.
- `anonymize`: components in input order get id `c0001...` and name `placeholder("c", n, len(name))`; flows get id `f0001...` and name `placeholder("f", n, len(name))`; `parent_id`/`source_id`/`target_id` are rewritten; output dicts contain exactly the keys of the fixture format.
- `find_leaks` scans every string value of the output except `type` values and returns one message per hit, naming the id of the output component or flow that holds it: (a) any string value found anywhere in the input cells (nested values included), of length 4 or more, as a case-insensitive substring; (b) regex hits for an IPv4 address, a 12-digit run, a UUID, or a dotted hostname (`[a-z0-9-]+(\.[a-z0-9-]+)+`).
- `export_cells` = `cells_to_dfd` then `anonymize` then `find_leaks`; any leak raises `ExportError` listing all of them.
- CLI: `--cells-file PATH` (offline) or `--threat-model-id ID [--diagram-id ID]`; `--out PATH`; `--force`. With `--threat-model-id` and no `--diagram-id`, print each diagram as `id<TAB>name` and return 0 without writing. `--out` is required otherwise. Returns 0 on success and prints `exported N components, M flows -> PATH`; returns 2 with the message on stderr for `ExportError`, a missing/invalid input file, or an existing `--out` without `--force`. The output is computed fully before the file is opened, so a failed run writes nothing. Second run: refused unless `--force`, which overwrites. Output text is `json.dumps(dfd, indent=2) + "\n"`.

`tests/fixtures/dfd_export/synthetic_cells.json` (hand-written, a JSON list; ids are `00000000-0000-4000-8000-0000000000NN`):

| NN | shape | name / label | parent | `component_type` metadata | notes |
|---|---|---|---|---|---|
| 01 | security-boundary | `acme-prod-account-123456789012` | - | `tenant` | flat geometry |
| 02 | security-boundary | `vpc-10.20.0.0/16` | 01 | `network` | nested `position`/`size` |
| 03 | security-boundary | `eks-cluster` | 02 | none | shape fallback |
| 04 | process | `api.internal.example.com` | 03 | `gateway` | has `ports` |
| 05 | process | `orders-svc` | 03 | none | |
| 06 | store | `orders-db.cluster-abc123.us-east-1.rds.amazonaws.com` | 02 | `storage` | |
| 07 | actor | `Customer` | - | none | `"parent": null`, `"angle": 0`, `data: {"security_boundary": false}` |
| 08 | process | `batch-worker` | 02 | `compute` | extra metadata `{"key": "region", "value": "us-east-1"}` |
| 11 | flow | `HTTPS 443` | | | 07 -> 04, with `port` on both ends |
| 12 | flow | `gRPC` | | | 04 -> 05 |
| 13 | flow | `SQL queries` | | | 05 -> 06 |
| 14 | flow | `result sets` | | | 06 -> 05 |
| 15 | flow | (`"labels": null`) | | | 08 -> 06, `"port": null` on both ends |
| 16 | flow | `enqueue job` | | | 05 -> 08, with `vertices` and `data._metadata` protocol |

- [ ] **Step 1: Write the fixture and the failing tests**

`tests/test_export_tmi_dfd.py` loads the script as `export_tmi_dfd` and the fixture as `CELLS`.

```python
def test_placeholder_keeps_length():
    assert export_tmi_dfd.placeholder("c", 1, 10) == "c0001xxxxx"
    assert export_tmi_dfd.placeholder("f", 12, 3) == "f00"
    assert export_tmi_dfd.placeholder("c", 1, 0) == ""

def test_cells_to_dfd_maps_nodes_and_edges():
    dfd = export_tmi_dfd.cells_to_dfd(CELLS)
    assert [c["type"] for c in dfd["components"]] == [
        "tenant", "network", "container", "gateway", "service", "storage", "actor", "compute"]
    assert dfd["components"][3]["parent_id"] == dfd["components"][2]["id"]
    assert "parent_id" not in dfd["components"][0]
    assert len(dfd["flows"]) == 6 and all(f["bidirectional"] is False for f in dfd["flows"])
    assert dfd["flows"][4]["name"] == ""

def test_anonymize_replaces_names_ids_and_drops_metadata():
    out = export_tmi_dfd.export_cells(CELLS)
    assert [c["id"] for c in out["components"]] == [f"c{n:04d}" for n in range(1, 9)]
    assert out["components"][0]["name"] == "c0001" + "x" * (len("acme-prod-account-123456789012") - 5)
    assert out["flows"][0] == {"id": "f0001", "name": "f0001xxxx", "source_id": "c0007",
                               "target_id": "c0004", "bidirectional": False}
    assert all(set(c) <= {"id", "name", "type", "parent_id"} for c in out["components"])
```

Further tests, one assertion group each:
- `test_unknown_shape_is_error_naming_cell`: change cell 05's shape to `text-box`; `pytest.raises(ExportError, match="0000000005")`.
- `test_unknown_metadata_type_is_error`: cell 04's `component_type` set to `network_access_control`; raises naming the cell.
- `test_edge_to_missing_node_is_error` and `test_missing_parent_is_error`: raise naming the cell.
- `test_find_leaks_clean_export_is_empty`: `find_leaks(CELLS, export_cells(CELLS)) == []`.
- `test_find_leaks_flags_original_name_and_ip`: set one output component name to `api.internal.example.com`, another to `host 10.20.0.5`; both are reported and each message contains the component id.
- `test_export_contains_no_original_strings`: no string of length 4 or more from `CELLS` occurs in any non-`type` output value.
- `test_main_cells_file_writes_fixture` (`tmp_path`, `capsys`): returns 0, stdout is `exported 8 components, 6 flows -> <path>`, file parses and equals `export_cells(CELLS)`.
- `test_main_refuses_overwrite_without_force`: second run returns 2 and the file bytes are unchanged; with `--force` returns 0.
- `test_main_error_leaves_no_file`: a cells file with an unknown shape returns 2, stderr names the cell, `--out` does not exist.
- `test_main_lists_diagrams` and `test_main_fetches_from_tmi`: monkeypatch `export_tmi_dfd.Config` and `export_tmi_dfd.TMIClient.create_authenticated` to return a fake whose `get_threat_model_diagrams` returns two `SimpleNamespace(id=..., name=...)` and whose `get_diagram_cells` returns `CELLS`; no network.
- `test_export_builds_with_dfd_builder`: `DFDBuilder(out["components"], out["flows"]).build_cells()` has 8 node cells and 6 edge cells.

In `tests/test_tmi_client_wrapper.py`:

```python
def test_get_diagram_cells_returns_cell_dicts():
    client = _client()
    client.sub_resources_api.get_threat_model_diagram.return_value.to_json.return_value = (
        '{"cells": [{"id": "n1", "parent": null}]}')
    assert client.get_diagram_cells("tm1", "d1") == [{"id": "n1", "parent": None}]
    client.sub_resources_api.get_threat_model_diagram.assert_called_once_with(
        threat_model_id="tm1", diagram_id="d1")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_export_tmi_dfd.py tests/test_tmi_client_wrapper.py -q`
Expected: FAIL (script file missing; `get_diagram_cells` not defined).

- [ ] **Step 3: Implement `TMIClient.get_diagram_cells` and `scripts/export_tmi_dfd.py`** with the signatures and pinned behavior above. Module docstring gives the usage lines, as `scripts/eval_jev.py` does. Walk nested values recursively for `find_leaks`; keep all collections as lists in input order.

- [ ] **Step 4: Run the tests, then the done gate**

Run: `uv run pytest tests/test_export_tmi_dfd.py tests/test_tmi_client_wrapper.py -q` then the done gate.
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/export_tmi_dfd.py tests/test_export_tmi_dfd.py tests/fixtures/dfd_export/synthetic_cells.json tmi_tf/tmi_client_wrapper.py tests/test_tmi_client_wrapper.py
git commit -m "feat(scripts): export anonymized DFD fixtures from TMI diagrams"
```

**Manual gate after Task 1 (Eric; does not block Tasks 2-9).** Reading the TMI server is Eric's call. The controller sends him the self-test command `uv run pytest tests/test_export_tmi_dfd.py -q` with its actual result, and the line `Approve: run scripts/export_tmi_dfd.py read-only against the TMI server for the threat models Eric names`. After approval: list diagrams with `--threat-model-id`, export 3-6 (small, deep-nested, wide) to `tests/fixtures/dfd/<name>.json`, read each output for hostnames, IPs, account ids and original names (the script's leak check is the first pass, not the only one), run `uv run pytest tests/test_layout_properties.py -q`, and commit the fixtures alone. If the live cell shape differs from the synthetic fixture (for example metadata under another key), stop and report; do not loosen the converter without a test for the new shape.

---

### Task 2: `layered.py` part 1: types, cycle breaking, ranking, layers, crossing reduction

**Files:**
- Create: `tmi_tf/layout/__init__.py` (docstring only), `tmi_tf/layout/layered.py`, `tests/test_layout_layered.py`

**Interfaces:**
- Consumes: Pele `layered.ts`: `orient` (805-843), `rank` (845-947), dummy construction (328-385), initial order (441-466), `reduceCrossings` (`count` 1721, `sweep` 1859-1907, `transpose` 1945-1965, loop 1982-2000), `sortByBary` (208).
- Produces (final shapes; later tasks fill fields, never change signatures):

```python
class Kind(IntEnum):
    NODE = 0
    DUMMY = 1
    START_PORT = 2
    END_PORT = 3

@dataclass
class LNode:
    w: float                 # cross-axis extent
    h: float                 # rank-axis extent
    kind: Kind = Kind.NODE
    x: float = 0.0           # output: centre on the cross axis
    y: float = 0.0           # output: centre on the rank axis
    rank: int = 0            # output

@dataclass
class LEdge:
    tail: int
    head: int
    weight: int = 1          # number of merged parallel flows
    label_w: float = 0.0     # cross-axis width given to each dummy of this edge
    reversed: bool = False   # output of orient()
    points: list[tuple[float, float]] = field(default_factory=list)  # output of layered(), tail-to-head

@dataclass(frozen=True)
class LayeredOptions:
    node_sep: float
    edge_sep: float
    rank_sep: float

@dataclass
class Layers:
    kinds: list[Kind]                 # per vertex; real nodes first (same indices as `nodes`), then dummies
    widths: list[float]
    heights: list[float]
    ranks: list[int]
    segs: list[tuple[int, int, int]]  # (upper vertex, lower vertex, weight), one per rank-to-rank segment
    order: list[list[int]]            # order[r]: vertices of rank r, in cross-axis order
    chains: list[list[int]]           # chains[ei]: dummy vertices of edge ei from its upper end down; [] if it spans one rank

def orient(nodes: list[LNode], edges: list[LEdge]) -> None
def rank(nodes: list[LNode], edges: list[LEdge]) -> None
def build_layers(nodes: list[LNode], edges: list[LEdge]) -> Layers
def count_crossings(layers: Layers) -> int
def reduce_crossings(layers: Layers) -> int
```

Pinned where Pele and the signatures leave a choice:
- `orient`, `rank` and `build_layers` raise `ValueError` for `tail == head` or an index out of range.
- `orient`: iterative DFS, roots in index order, out-edges in edge-list order. An edge whose head is `START_PORT` or whose tail is `END_PORT` is pre-marked reversed and left out of the DFS.
- `rank`: Pele's `rank` with `step = 1` and `minlen = 1`. In the 8 balancing passes "more edges" compares the sum of `weight`. `START_PORT` nodes end at rank 0 (one above the lowest real node), `END_PORT` nodes one below the highest; ranks are normalized so the minimum is 0.
- `build_layers`: an edge's upper end is `tail` unless `reversed`. Dummies are created edge by edge in list order, top rank first; a dummy's width is the edge's `label_w` and its height 0; each segment carries the edge's `weight`. Initial order is Pele's depth-first order; afterwards a rank whose vertices are all `START_PORT` or all `END_PORT` is sorted by vertex index.
- `Layers.order` is the only record of positions: `count_crossings`, `reduce_crossings` and `position` derive positions from it on entry (tests reorder it directly).
- `count_crossings`: two crossing segments count `weight_1 * weight_2`.
- `reduce_crossings`: one attempt only. Up to 24 sweeps, alternating down/up starting down, `bias_right = i % 4 >= 2`, stop after 4 sweeps without improvement, restore the best order; then up to 8 adjacent-swap passes accepting only strict improvements. Barycenter is the weighted mean of neighbor positions; a vertex with no neighbor in the adjacent rank keeps its slot (Pele's `bary = -1` rule); ties keep current order (reversed when `bias_right`). A rank whose vertices are all `START_PORT` or all `END_PORT` is fixed: sweeps and swaps never reorder it. Returns the final crossing count.

- [ ] **Step 1: Write the failing tests**

```python
def graph(n, pairs, kinds=None):
    nodes = [LNode(100, 40, (kinds or {}).get(i, Kind.NODE)) for i in range(n)]
    return nodes, [LEdge(a, b) for a, b in pairs]

def ranks(n, pairs, kinds=None):
    nodes, edges = graph(n, pairs, kinds)
    orient(nodes, edges)
    rank(nodes, edges)
    return [v.rank for v in nodes], edges

def test_orient_reverses_one_edge_of_cycle():
    nodes, edges = graph(3, [(0, 1), (1, 2), (2, 0)])
    orient(nodes, edges)
    assert [e.reversed for e in edges] == [False, False, True]

def test_rank_chain_and_diamond():
    assert ranks(3, [(0, 1), (1, 2)])[0] == [0, 1, 2]
    assert ranks(4, [(0, 1), (0, 2), (1, 3), (2, 3)])[0] == [0, 1, 1, 2]

def test_rank_moves_loose_source_next_to_its_target():
    assert ranks(4, [(0, 1), (1, 2), (3, 2)])[0] == [0, 1, 2, 1]

def test_rank_puts_ports_outside_real_nodes():
    # 0 -> 1 real; 2 is a start port feeding 0; 3 is an end port fed by 1
    r, edges = ranks(4, [(0, 1), (2, 0), (1, 3)], {2: Kind.START_PORT, 3: Kind.END_PORT})
    assert r == [1, 2, 0, 3] and not any(e.reversed for e in edges)

def test_orient_prereverses_edges_against_ports():
    # an edge leaving through the start side, and one entering from the end side
    _, edges = ranks(4, [(0, 1), (0, 2), (3, 1)], {2: Kind.START_PORT, 3: Kind.END_PORT})
    assert [e.reversed for e in edges] == [False, True, True]

def test_build_layers_long_edge_gets_one_dummy_per_skipped_rank():
    nodes, edges = graph(3, [(0, 1), (1, 2), (0, 2)])
    orient(nodes, edges); rank(nodes, edges)
    layers = build_layers(nodes, edges)
    assert len(layers.chains[2]) == 1 and layers.chains[0] == []
    assert layers.kinds[layers.chains[2][0]] == Kind.DUMMY and len(layers.segs) == 4
    assert sorted(layers.order[1]) == sorted([1, layers.chains[2][0]])

def test_reduce_crossings_untangles_a_scrambled_rank():
    nodes, edges = graph(6, [(0, 3), (1, 4), (2, 5)])
    orient(nodes, edges); rank(nodes, edges)
    layers = build_layers(nodes, edges)
    layers.order[1].reverse()
    assert count_crossings(layers) == 3
    assert reduce_crossings(layers) == 0 and count_crossings(layers) == 0

def test_port_ranks_are_fixed_in_list_order():
    # start ports 2, 3 feed 1, 0; end ports 4, 5 are fed by 0, 1: one crossing is unavoidable
    kinds = {2: Kind.START_PORT, 3: Kind.START_PORT, 4: Kind.END_PORT, 5: Kind.END_PORT}
    nodes, edges = graph(6, [(2, 1), (3, 0), (0, 4), (1, 5)], kinds)
    orient(nodes, edges); rank(nodes, edges)
    layers = build_layers(nodes, edges)
    assert reduce_crossings(layers) == 1
    assert layers.order[0] == [2, 3] and layers.order[2] == [4, 5]
```

Also: `test_weighted_crossings_count_products` (two crossing segments with weights 2 and 3 count 6); `test_self_edge_and_bad_index_raise`; `test_same_input_same_order` (two fresh builds of a 12-node seeded `random.Random(7)` DAG give equal `order` and `ranks`).

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_layout_layered.py -q`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement** the types and five functions in `tmi_tf/layout/layered.py`, starting with the Pele header from Global Constraints (`<file>` = `layered.ts`). Use plain lists, not typed arrays; keep Pele's iteration orders exactly, since they are the tie-breaks.

- [ ] **Step 4: Run the tests, then the done gate.** Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/layout/__init__.py tmi_tf/layout/layered.py tests/test_layout_layered.py
git commit -m "feat(layout): layered graph ranking and crossing reduction (Pele port)"
```

---

### Task 3: `layered.py` part 2: coordinates and the `layered()` entry point

**Files:**
- Modify: `tmi_tf/layout/layered.py`, `tests/test_layout_layered.py`

**Interfaces:**
- Consumes: Task 2's `Kind`, `LNode`, `LEdge`, `LayeredOptions`, `Layers`, `orient`, `rank`, `build_layers`, `reduce_crossings`. Pele `layered.ts`: `halfRoom` and `position` (2027-2227), band and point assembly (around 660-760).
- Produces:

```python
@dataclass(frozen=True)
class LayeredResult:
    width: float
    height: float

def position(layers: Layers, opt: LayeredOptions) -> list[float]   # cross-axis centre per vertex
def layered(nodes: list[LNode], edges: list[LEdge], opt: LayeredOptions) -> LayeredResult
```

Pinned:
- `position` is Pele's Brandes-Koepf: four alignments, shift each to the narrowest, each vertex takes the mean of its two middle candidates. Alignment medians are unweighted. Separation between neighbors in a rank is the sum of their half widths plus, per side, `node_sep / 2` for `Kind.NODE` and `edge_sep / 2` for every other kind. Drop the `EFD`/`ETD`/`shift` offset terms (always 0 here).
- `layered`: empty input returns `LayeredResult(0, 0)`. Otherwise `orient`, `rank`, `build_layers`, `reduce_crossings`, `position`; shift so the smallest left edge is 0. Rank axis: one band per rank, as tall as its tallest vertex (a rank of only ports or dummies has height 0), `rank_sep` between bands, every vertex centred in its band. Writes `x`, `y`, `rank` on each node. `width`/`height` are the bounding box of all vertices.
- `LEdge.points`: for each dummy of the edge, `(x, band_top)` then `(x, band_bottom)` of its rank (a single `(x, y)` when the band has no height), listed from tail to head (so reversed for a reversed edge). Two points per dummy keep the route parallel to the nodes beside it instead of cutting their corners.

- [ ] **Step 1: Write the failing tests** (`OPT = LayeredOptions(40, 20, 60)`; nodes are 100 wide, 40 tall)

```python
def run(n, pairs):
    nodes, edges = graph(n, pairs)
    return nodes, edges, layered(nodes, edges, OPT)

def test_empty_and_single():
    assert layered([], [], OPT) == LayeredResult(0, 0)
    nodes, _, size = run(1, [])
    assert (nodes[0].x, nodes[0].y, size) == (50, 20, LayeredResult(100, 40))

def test_chain_is_straight():
    nodes, _, size = run(3, [(0, 1), (1, 2)])
    assert [v.x for v in nodes] == [50, 50, 50]
    assert [v.y for v in nodes] == [20, 120, 220] and size == LayeredResult(100, 240)

def test_diamond_is_symmetric():
    nodes, _, _ = run(4, [(0, 1), (0, 2), (1, 3), (2, 3)])
    assert nodes[1].y == nodes[2].y and abs(nodes[1].x - nodes[2].x) >= 140
    assert nodes[0].x == nodes[3].x == (nodes[1].x + nodes[2].x) / 2

def test_cycle_completes_with_one_reversed_edge():
    nodes, edges, _ = run(3, [(0, 1), (1, 2), (2, 0)])
    assert sum(e.reversed for e in edges) == 1 and sorted(v.rank for v in nodes) == [0, 1, 2]

def test_long_edge_points_run_beside_the_skipped_node():
    nodes, edges, _ = run(3, [(0, 1), (1, 2), (0, 2)])
    (x1, y1), (x2, y2) = edges[2].points
    assert x1 == x2 and (y1, y2) == (100, 140)          # band of rank 1
    assert abs(x1 - nodes[1].x) >= 50 + 30              # half width + (node_sep + edge_sep) / 2
    assert edges[0].points == []

def test_disconnected_parts_do_not_overlap():
    nodes, _, _ = run(4, [(0, 1), (2, 3)])
    assert abs(nodes[0].x - nodes[2].x) >= 140
```

Also `test_random_graphs_keep_invariants`: for `seed in range(20)`, a `random.Random(seed)` graph of 3-25 nodes with random edges (no self edges): every non-reversed edge has `rank[head] > rank[tail]` and every reversed edge the opposite; any two real nodes in one rank are at least `100 + 40` apart on x; every node box lies within `[0, width] x [0, height]`; running `layered` on a fresh copy gives identical `x`, `y`, `rank` and `points`.

- [ ] **Step 2: Run to verify failure.** Run: `uv run pytest tests/test_layout_layered.py -q`. Expected: FAIL (`layered` not defined).
- [ ] **Step 3: Implement `position` and `layered`** as pinned.
- [ ] **Step 4: Run the tests, then the done gate.** Expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add tmi_tf/layout/layered.py tests/test_layout_layered.py
git commit -m "feat(layout): Brandes-Koepf coordinates and layered() entry point"
```

---

### Task 4: `compound.py`: tree recursion, lifted edges, sizing, direction

**Files:**
- Create: `tmi_tf/layout/compound.py`, `tests/test_layout_compound.py`

**Interfaces:**
- Consumes: `layered.LNode`, `LEdge`, `LayeredOptions`, `layered()`. Pele `compound.ts` `compoundLayout`: level tree (419-470), lifting (508-553), `build` (556-611), bottom-up layout and the `tx`/`ty` rotation (732-760), absolute positions (820-833). Spacing reference: `class_render.ts` 25-28.
- Produces (final shapes):

```python
Direction = Literal["LR", "TB"]
Side = Literal["top", "right", "bottom", "left"]
LAYOUT_DIRECTION: Direction = "LR"
EMIT_BORDER_VERTICES: bool = False
LABEL_CHAR_W = 7
LABEL_PAD = 16
LABEL_MAX_W = 240

@dataclass(frozen=True)
class LayoutOptions:
    node_sep: int = 40
    edge_sep: int = 20
    rank_sep: int = 60
    pad: int = 30            # group padding left, right, bottom
    pad_top: int = 60        # group padding top: pad plus 30 for the boundary's own label
    label_margin: int = 24
    origin: int = 50         # absolute x and y of the diagram's top-left corner

@dataclass(frozen=True)
class LayoutNode:
    id: str
    parent: str | None
    w: int                   # leaf: fixed width; group: minimum width
    h: int                   # leaf: fixed height; group: minimum height
    is_group: bool = False

@dataclass(frozen=True)
class LayoutEdge:
    id: str
    source: str
    target: str
    label_w: int = 0

@dataclass
class Box:
    x: int                   # absolute top-left
    y: int
    w: int
    h: int

@dataclass
class EdgeRoute:
    lifted: bool = False     # False: the flow took no part in layout
    level: str | None = None # group whose level holds the lifted edge; None is the virtual root
    a: str = ""              # child of `level` containing the source
    b: str = ""              # child of `level` containing the target
    reversed: bool = False   # cycle breaking reversed a -> b
    rank_a: int = 0
    rank_b: int = 0
    points: list[tuple[int, int]] = field(default_factory=list)      # absolute bend points, source to target
    border_out: list[tuple[int, int]] = field(default_factory=list)  # Task 7: port points, innermost group first
    border_in: list[tuple[int, int]] = field(default_factory=list)   # Task 7: port points, outermost group first

@dataclass
class LayoutResult:
    boxes: dict[str, Box]          # keyed by node id, in input order
    routes: dict[str, EdgeRoute]   # keyed by edge id, in input order
    width: int
    height: int

def label_width(text: str) -> int
def edge_sides(direction: Direction, rank_delta: int, cross_delta: float) -> tuple[Side, Side]
def compound_layout(nodes: list[LayoutNode], edges: list[LayoutEdge], direction: Direction,
                    opt: LayoutOptions | None = None) -> LayoutResult   # None means LayoutOptions()
```

Pinned:
- Input order is the list order of `nodes`; a level's children are the nodes with that parent, in list order. The virtual root level holds all parentless nodes.
- `compound_layout` raises `ValueError` naming the offender for: a duplicate id, an unknown parent, a parent that is not a group, a parent cycle, an edge endpoint that is not a node, a direction other than `"LR"`/`"TB"`. It accepts `source == target`.
- Lifting (spec step 1): `P` is the lowest common ancestor level, `a`/`b` the children of `P` containing source and target. If one end is an ancestor of the other, or `a == b`, the route stays `EdgeRoute()` and the flow adds nothing to any level. Otherwise flows with the same `(P, a, b)` merge into one `LEdge` (first-appearance order) with `weight` = their count; `a -> b` and `b -> a` stay separate edges.
- Coordinate rotation, the only place direction matters inside a level: `layered` works in (x = cross axis, y = rank axis). `TB`: `LNode(w, h)` is the box's `(w, h)` and screen `(x, y) = (lx, ly)`. `LR`: `LNode(w, h)` is the box's `(h, w)` and screen `(x, y) = (ly, lx)`. Everything after the `layered` call (rounding, bounding box, padding, absolute positions) is in screen coordinates.
- Labels: `TB` passes the largest `label_w` of the merged flows as `LEdge.label_w` and uses `opt.rank_sep`. `LR` passes `label_w = 0` and uses, for the whole level, `rank_sep = max(opt.rank_sep, largest label_w among that level's lifted edges + opt.label_margin)`.
- Level result: round each child's top-left and each edge point with `floor(v + 0.5)`; the content box is the bounding box of the children and of the level's edge points (so a group grows to hold the bends of its own edges), shifted to start at (0, 0). Group size: `w = max(node.w, content_w + 2 * pad, 40)`, `h = max(node.h, content_h + pad + pad_top, 30)`; children are offset by `((w - content_w) // 2, pad_top)`. A group with no children has content 0x0. The root level is offset by `(origin, origin)`; `width`/`height` are the root content size.
- Routes of lifted flows: `reversed`, `rank_a`, `rank_b` from the level's layout; `points` are the merged `LEdge.points` rotated, shifted to absolute, rounded, in `a -> b` order.
- `edge_sides`: `TB`: `rank_delta > 0` gives `("bottom", "top")`, `< 0` gives `("top", "bottom")`, `0` gives `("right", "left")` when `cross_delta >= 0` else `("left", "right")`. `LR`: `> 0` `("right", "left")`, `< 0` `("left", "right")`, `0` `("bottom", "top")` when `cross_delta >= 0` else `("top", "bottom")`.

- [ ] **Step 1: Write the failing tests**

```python
def leaf(id, parent=None): return LayoutNode(id, parent, 120, 60)
def group(id, parent=None, w=40, h=30): return LayoutNode(id, parent, w, h, True)
def edge(i, s, t, label_w=0): return LayoutEdge(str(i), s, t, label_w)
def xywh(b): return (b.x, b.y, b.w, b.h)

def test_lr_chain_runs_left_to_right():
    r = compound_layout([leaf("a"), leaf("b"), leaf("c")], [edge(0, "a", "b"), edge(1, "b", "c")], "LR")
    assert [xywh(r.boxes[i]) for i in "abc"] == [(50, 50, 120, 60), (230, 50, 120, 60), (410, 50, 120, 60)]
    assert (r.width, r.height) == (480, 60)

def test_tb_chain_runs_top_to_bottom():
    r = compound_layout([leaf("a"), leaf("b"), leaf("c")], [edge(0, "a", "b"), edge(1, "b", "c")], "TB")
    assert [(r.boxes[i].x, r.boxes[i].y) for i in "abc"] == [(50, 50), (50, 170), (50, 290)]

def test_lr_label_widens_rank_gap():
    r = compound_layout([leaf("a"), leaf("b")], [edge(0, "a", "b", label_w=200)], "LR")
    assert r.boxes["b"].x - (r.boxes["a"].x + 120) == 224

def test_group_wraps_children_with_padding():
    r = compound_layout([group("g"), leaf("a", "g"), leaf("b", "g")], [edge(0, "a", "b")], "LR")
    assert xywh(r.boxes["g"]) == (50, 50, 360, 150)
    assert (r.boxes["a"].x, r.boxes["a"].y) == (80, 110) and r.boxes["b"].x == 260

def test_empty_group_and_minimum_width():
    r = compound_layout([group("g"), group("wide", w=200), leaf("a", "wide")], [], "LR")
    assert (r.boxes["g"].w, r.boxes["g"].h) == (60, 90)
    assert r.boxes["wide"].w == 200 and r.boxes["a"].x == r.boxes["wide"].x + 40

def test_edge_between_nested_leaves_is_lifted_to_the_common_level():
    nodes = [group("g1"), leaf("a", "g1"), group("g2"), leaf("b", "g2")]
    r = compound_layout(nodes, [edge(0, "a", "b")], "LR")
    rt = r.routes["0"]
    assert (rt.lifted, rt.level, rt.a, rt.b, rt.reversed, rt.rank_a, rt.rank_b) == (True, None, "g1", "g2", False, 0, 1)
    assert r.boxes["g2"].x >= r.boxes["g1"].x + r.boxes["g1"].w + 60

def test_ancestor_and_self_flows_take_no_part():          # Review Focus 1
    nodes = [group("g"), leaf("a", "g"), leaf("b", "g")]
    base = compound_layout(nodes, [edge(0, "a", "b")], "LR")
    r = compound_layout(nodes, [edge(0, "a", "b"), edge(1, "g", "a"), edge(2, "b", "g"), edge(3, "a", "a")], "LR")
    assert r.boxes == base.boxes
    assert [r.routes[k].lifted for k in "0123"] == [True, False, False, False]

def test_long_label_is_capped():                           # Review Focus 4
    assert label_width("") == 0 and label_width("HTTPS") == 51 and label_width("x" * 200) == 240

def test_long_edge_points_pass_beside_the_middle_node():
    r = compound_layout([leaf("a"), leaf("b"), leaf("c")],
                        [edge(0, "a", "b"), edge(1, "b", "c"), edge(2, "a", "c")], "LR")
    b = r.boxes["b"]
    (x1, y1), (x2, y2) = r.routes["2"].points
    assert (x1, x2) == (b.x, b.x + b.w) and y1 == y2
    assert y1 <= b.y - 10 or y1 >= b.y + b.h + 10
```

Also: `test_duplicate_flows_merge` (two `a -> b` flows give equal routes and the same boxes as one); `test_two_cycle_reverses_one` (`a -> b`, `b -> a`: exactly one route `reversed`, and it has `rank_b < rank_a`); `test_edge_sides_table` (all eight rows of the `edge_sides` rule); `test_validation_rejects_bad_input` (one `pytest.raises(ValueError, match=<offending id>)` per rejected case above); `test_all_outputs_are_ints`; `test_same_input_same_result` on a 3-level tree in both directions.

- [ ] **Step 2: Run to verify failure.** Run: `uv run pytest tests/test_layout_compound.py -q`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement `tmi_tf/layout/compound.py`** with the Pele header (`<file>` = `compound.ts`). One call to `layered()` per level in this task; packing and ports come in Tasks 6 and 7, so keep "lay out one level" as a private function taking the level's children and merged edges and returning child offsets, content size, ranks and edge points.
- [ ] **Step 4: Run the tests, then the done gate.** Expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add tmi_tf/layout/compound.py tests/test_layout_compound.py
git commit -m "feat(layout): compound layout over nested boundaries with LR/TB direction"
```

---

### Task 5: Wire the layout into `DFDBuilder`; direction-based ports; property tests

**Files:**
- Modify: `tmi_tf/diagram_builder.py` (`build_cells` 97-121, `_create_boundary_cells` 123, `_create_node_cells` 136, `_create_node_cell` 161, `_create_edge_cell` 302, `_get_depth` 446, layout section 462-843), `tests/test_diagram_builder.py`
- Create: `tests/dfd_cases.py`, `tests/test_layout_properties.py`

**Interfaces:**
- Consumes: `compound.LayoutNode`, `LayoutEdge`, `LayoutOptions`, `LayoutResult`, `EdgeRoute`, `compound_layout`, `edge_sides`, `label_width`, and `compound.LAYOUT_DIRECTION` read at call time.
- Produces on `DFDBuilder` (Task 8 and the tests rely on these names):
  - `self._components: list[dict[str, Any]]`: accepted components, input order.
  - `self._parent: dict[str, str | None]`: effective parent per accepted component id.
  - `self._layout: LayoutResult | None`: set by `_auto_layout`; `boxes` keyed by component id, `routes` keyed by `str(flow_index)` for every flow whose two ends have cells.
- Produces in `tests/dfd_cases.py`:

```python
def comp(id: str, type: str, parent_id: str | None = None, **extra: Any) -> dict[str, Any]   # name defaults to id
def flow(id: str, source_id: str, target_id: str, name: str = "flow", bidirectional: bool = False) -> dict[str, Any]
HAND_CASES: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]]
def random_dfd(seed: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]
def fixture_files() -> list[Path]                       # sorted(tests/fixtures/dfd/*.json), [] if none
def load_fixture(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]
def all_cases() -> list[tuple[str, list[dict[str, Any]], list[dict[str, Any]]]]
    # names "hand:<key>", then "random:<seed>" for seeds 0-29, then "fixture:<stem>"
def normalize_ids(cells: list[dict[str, Any]]) -> list[dict[str, Any]]            # uuid -> "n<index of first appearance>"
def digest_all() -> str     # sha256 over json.dumps(normalize_ids(cells), sort_keys=True) of every case, in LR then TB
                            # (sets compound.LAYOUT_DIRECTION and restores it in a finally block)
```

  `HAND_CASES` keys, in order: `empty`, `single_leaf`, `flat_chain`, `nested_cross_border`, `two_cycle`, `bidirectional_pair`, `parallel_flows`, `edgeless_block` (one boundary, 9 leaves, no flows), `deep_nesting` (4 levels), `boundary_endpoints`, `ancestor_and_self_flows`, `long_edge`. `random_dfd` uses `random.Random(seed)`: 5-40 components, depth at most 4, about 1.5 flows per leaf between random components (leaves and boundaries), including some bidirectional, duplicate, self and ancestor-descendant flows. `python tests/dfd_cases.py` prints `digest_all()`.

Pinned builder behavior:
- `build_cells` first normalizes, in this order, logging one warning per rejected item:
  1. A component whose type is not in `BOUNDARY_TYPES | LEAF_TYPES` is skipped (keep the existing `network_access_control` message for that type).
  2. A component whose id was already accepted is skipped.
  3. Effective parent is `None` (root) when `parent_id` is absent, names no accepted component, names a non-boundary component, or names the component itself.
  4. Parent cycles: walk accepted components in input order; any component not reachable from a root gets parent `None`, then its subtree counts as reachable; repeat.
  With no accepted components `build_cells` returns `[]`.
- `_get_depth` and the cell `parent` field use `self._parent` (iterative; no recursion over raw `parent_id`).
- Layout input order: `sorted` by `(0, sibling_order, index)` when `type(sibling_order) is int`, else `(1, 0, index)`. `LayoutNode` for a leaf is `(120, 60)`; for a boundary `w = max(MIN_WIDTH, label_width(name))`, `h = MIN_HEIGHT`, `is_group=True`. The LLM's `rank` field is ignored.
- One `LayoutEdge(str(i), source_id, target_id, label_w)` per flow `i` whose ends both have cells; `label_w` is the largest `label_width` of the labels that flow's cells will carry. Flows with a missing end are skipped with the existing warning.
- `_auto_layout` calls `compound_layout(nodes, edges, compound.LAYOUT_DIRECTION)` and copies each box to its cell's `x`, `y`, `width`, `height`.
- Ports: for flow `i` with route `rt`, `rank_delta = rt.rank_b - rt.rank_a` when `rt.lifted`, else `1`. The forward cell uses `edge_sides(direction, rank_delta, cross_delta)`; the reverse cell of a bidirectional flow uses `edge_sides(direction, -rank_delta, -cross_delta)`. `cross_delta` is target centre minus source centre on the cross axis. An end on a boundary gets no `port`.
- Delete `_place_items_in_grid`, `_order_leaves_by_flow`, `_get_optimal_port`, `_compute_component_size`, `_assign_positions`, `_build_flow_adjacency`, `_get_children`, the constants `BOUNDARY_PADDING`, `NODE_SPACING`, `DEFAULT_BOUNDARY_WIDTH`, `DEFAULT_BOUNDARY_HEIGHT`, and the unused `ceil`/`sqrt` import. Vertices, fan and connector choice are Task 8; leave `router`/`connector` as they are.

- [ ] **Step 1: Write the failing tests**

In `tests/test_diagram_builder.py`, delete `test_flow_connected_peers_have_gap` and `test_boundary_child_occupies_multiple_grid_cells`; leave every other existing test untouched. Add:

```python
from tmi_tf.layout import compound

def ports(edge): return (edge["source"].get("port"), edge["target"].get("port"))

class TestLayeredLayout:
    def test_flow_runs_left_to_right_by_default(self):
        comps = [make_component("t1", "T", "tenant"), make_component("c1", "A", "compute", "t1"),
                 make_component("c2", "B", "storage", "t1"), make_component("c3", "C", "compute", "t1")]
        cells = DFDBuilder(comps, [make_flow("f1", "c1", "c2")]).build_cells()
        c1, c2 = get_cell(cells, "c1"), get_cell(cells, "c2")
        assert c2["x"] >= c1["x"] + c1["width"] + 60
        assert ports(get_edge_cells(cells)[0]) == ("right", "left")

    def test_top_to_bottom_when_direction_is_tb(self, monkeypatch):
        monkeypatch.setattr(compound, "LAYOUT_DIRECTION", "TB")
        comps = [make_component("c1", "A", "compute"), make_component("c2", "B", "storage")]
        cells = DFDBuilder(comps, [make_flow("f1", "c1", "c2")]).build_cells()
        assert get_cell(cells, "c2")["y"] >= get_cell(cells, "c1")["y"] + 60 + 60
        assert ports(get_edge_cells(cells)[0]) == ("bottom", "top")

    def test_back_edge_and_reverse_cell_swap_sides(self):
        comps = [make_component("c1", "A", "compute"), make_component("c2", "B", "compute")]
        cells = DFDBuilder(comps, [make_flow("f1", "c1", "c2"), make_flow("f2", "c2", "c1")]).build_cells()
        assert [ports(e) for e in get_edge_cells(cells)] == [("right", "left"), ("left", "right")]
        cells = DFDBuilder(comps, [make_flow("f1", "c1", "c2", bidirectional=True)]).build_cells()
        assert [ports(e) for e in get_edge_cells(cells)] == [("right", "left"), ("left", "right")]

    def test_inner_boundary_wraps_its_children(self):
        comps = [make_component("t1", "Outer", "tenant"), make_component("c1", "L1", "compute", "t1"),
                 make_component("n1", "Inner", "network", "t1")]
        comps += [make_component(c, c, "compute", "n1") for c in ("c3", "c4", "c5")]
        cells = DFDBuilder(comps, []).build_cells()
        n = get_cell(cells, "n1")
        assert all(is_inside(get_cell(cells, c), n) for c in ["c3", "c4", "c5"])
        assert n["width"] > 120 and n["height"] > 60

    def test_sibling_order_sets_cross_axis_order(self):
        a = {**make_component("a", "A", "compute"), "sibling_order": 1}
        b = {**make_component("b", "B", "compute"), "sibling_order": 0}
        cells = DFDBuilder([a, b], []).build_cells()
        assert get_cell(cells, "b")["y"] < get_cell(cells, "a")["y"] or get_cell(cells, "b")["x"] < get_cell(cells, "a")["x"]
```

`class TestRejection` (use `caplog` at WARNING):
- `test_unknown_type_skipped_with_warning`: type `"lambda"` gives no cell and a warning naming the id.
- `test_duplicate_id_skipped_with_warning` and `test_empty_input_returns_no_cells` (Review Focus 5).
- `test_missing_parent_becomes_root`: `parent_id="nope"`; cell has no `parent` key, a warning names the child.
- `test_leaf_or_skipped_parent_becomes_root` (Review Focus 3): one child under a `compute`, one under a `network_access_control`; neither cell has `parent`.
- `test_parent_cycle_becomes_root`: `n1.parent_id = "n2"`, `n2.parent_id = "n1"` (both `network`); `build_cells` returns, `n1` has no `parent`, `n2`'s parent is `n1`'s cell id, one warning.
- `test_bad_sibling_order_falls_back_to_input_order` (Review Focus 2): siblings with `sibling_order` of `"2"`, `None`, `True`, `1`, `1`; no exception, all cells present.
- `test_ancestor_and_self_flows_still_get_cells` (Review Focus 1): flows `t1 -> c1` (its child), `c1 -> t1`, `c1 -> c1`; three edge cells; a leaf source has port `right`, a leaf target `left`, the boundary end has no `port`.

`tests/test_layout_properties.py`:

```python
CASES = all_cases()

@pytest.mark.parametrize("name,components,flows", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("direction", ["LR", "TB"])
def test_layout_invariants(name, components, flows, direction, monkeypatch):
    monkeypatch.setattr(compound, "LAYOUT_DIRECTION", direction)
    builder = DFDBuilder(components, flows)
    check_invariants(builder, builder.build_cells())
```

`check_invariants` asserts, for node cells grouped by `parent`:
- every child is inside its parent with inset at least 30 left/right/bottom and 60 top;
- for every sibling pair (including roots), `max(gap_x, gap_y) >= 40`;
- every `width >= 40`, `height >= 30`, and `x`, `y`, `width`, `height` are `int`;
- every route in `builder._layout.routes.values()` with `lifted`: `rank_b > rank_a` if not `reversed`, else `rank_b < rank_a`;
- for every edge cell, no point of `cell.get("vertices", [])` lies strictly inside a node cell that is not a proper ancestor (via `parent`) of the edge's source or target cell, and `len(vertices) <= 1000`.

Plus:

```python
def test_fixture_files_are_picked_up():
    assert [n for n, _, _ in CASES if n.startswith("fixture:")] == [f"fixture:{p.stem}" for p in fixture_files()]

def test_output_is_byte_identical_across_processes():
    script = Path(__file__).parent / "dfd_cases.py"
    def run(seed):
        return subprocess.run([sys.executable, str(script)], env={**os.environ, "PYTHONHASHSEED": seed},
                              capture_output=True, text=True, check=True).stdout
    assert run("0") == run("1") == digest_all() + "\n"
```

- [ ] **Step 2: Run to verify failure.** Run: `uv run pytest tests/test_diagram_builder.py tests/test_layout_properties.py -q`. Expected: FAIL (new tests fail against the grid layout; `_layout` missing).
- [ ] **Step 3: Implement** the builder changes as pinned.
- [ ] **Step 4: Run the tests, then the done gate.** Expected: all pass, including every pre-existing test in `tests/test_diagram_builder.py`.
- [ ] **Step 5: Commit**

```bash
git add tmi_tf/diagram_builder.py tests/test_diagram_builder.py tests/dfd_cases.py tests/test_layout_properties.py
git commit -m "feat(dfd): lay out diagrams with the layered layout; ports follow direction"
```

---

### Task 6: `pack.py` and per-level packing of disconnected parts

**Files:**
- Create: `tmi_tf/layout/pack.py`, `tests/test_layout_pack.py`
- Modify: `tmi_tf/layout/compound.py`, `tests/test_layout_compound.py`

**Interfaces:**
- Consumes: Task 4's private "lay out one level" function in `compound.py` (read the file). Pele `components.ts` `wrapComponents` (13-72) for union-find and the row loop.
- Produces in `pack.py` (all in screen coordinates, positions are top-left offsets):

```python
def connected_parts(n: int, pairs: list[tuple[int, int]]) -> list[list[int]]
    # union-find over items 0..n-1; parts ordered by smallest member, members ascending
def shelf_pack(sizes: list[tuple[int, int]], gap: int) -> tuple[list[tuple[int, int]], int, int]
    # positions per input index, total width, total height
def grid_block(sizes: list[tuple[int, int]], gap: int) -> tuple[list[tuple[int, int]], int, int]
```

Pinned:
- `shelf_pack`: place in order of `(-width, index)`; `target = max(widest width, sqrt(1.6 * sum(w * h)))`; items go left to right with `gap` between them; start a new row when `x > 0 and x + w > target`; a row is as tall as its tallest item; `gap` between rows.
- `grid_block`: `cols = ceil(sqrt(n))`, row-major in input order; each column as wide as its widest item, each row as tall as its tallest; `gap` between columns and rows.
- In `compound.py`, per level: split the children with `connected_parts` over the level's merged lifted edges. Every part with two or more children is laid out by its own `layered()` call (node indices renumbered in the same relative order). All single-child parts together form one grid block (`grid_block`, gap `node_sep`), ordered by input order. If the level has one part in total, the result is exactly Task 4's. Otherwise the parts (grid block positioned in the list at its smallest member) go through `shelf_pack` with gap `node_sep`. The `LR` `rank_sep` rule stays per level, not per part. Ranks stay per part (two nodes are only ever compared within one part).
- Write the per-level function so one designated part can be placed first and apart from the packed block; Task 7 uses that for the border part.

- [ ] **Step 1: Write the failing tests**

```python
def test_connected_parts_orders_by_smallest_member():
    assert connected_parts(6, [(4, 1), (2, 5), (5, 3)]) == [[0], [1, 4], [2, 3, 5]]

def test_grid_block_of_five_leaves():
    pos, w, h = grid_block([(120, 60)] * 5, 40)
    assert pos == [(0, 0), (160, 0), (320, 0), (0, 100), (160, 100)] and (w, h) == (440, 160)

def test_shelf_pack_three_parts():
    pos, w, h = shelf_pack([(300, 60), (300, 60), (280, 160)], 40)   # target is about 359.6
    assert pos == [(0, 0), (0, 100), (0, 200)] and (w, h) == (300, 360)

def test_shelf_pack_places_widest_first_and_fills_rows():
    pos, w, h = shelf_pack([(100, 50), (400, 50), (100, 50)], 40)    # target is 400
    assert pos == [(0, 90), (0, 0), (140, 90)] and (w, h) == (400, 140)
```

Also `test_shelf_pack_single_and_empty` (`[(7, 9)]` gives `[(0, 0)], 7, 9`; `[]` gives `[], 0, 0`).

In `tests/test_layout_compound.py`:

```python
def test_edgeless_children_form_a_grid_block():
    nodes = [group("g")] + [leaf(f"l{i}", "g") for i in range(9)]
    for d in ("LR", "TB"):
        g = compound_layout(nodes, [], d).boxes["g"]
        assert (g.w, g.h) == (500, 350)          # 3x3 grid 440x260 plus padding

def test_disconnected_parts_are_shelf_packed():
    nodes = [leaf(i) for i in "abcdxyz"]
    r = compound_layout(nodes, [edge(0, "a", "b"), edge(1, "c", "d")], "LR")
    assert (r.width, r.height) == (300, 360)
    assert r.boxes["c"].y == r.boxes["a"].y + 100 and r.boxes["x"].y == r.boxes["a"].y + 200
    assert r.boxes["y"].x == r.boxes["x"].x + 160 and r.boxes["z"].y == r.boxes["x"].y + 100
```

- [ ] **Step 2: Run to verify failure.** Run: `uv run pytest tests/test_layout_pack.py tests/test_layout_compound.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `pack.py` (Pele header, `<file>` = `components.ts`) and the per-level packing in `compound.py`.
- [ ] **Step 4: Run the tests, `uv run pytest tests/test_layout_properties.py -q`, then the done gate.** Expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add tmi_tf/layout/pack.py tmi_tf/layout/compound.py tests/test_layout_pack.py tests/test_layout_compound.py
git commit -m "feat(layout): pack disconnected parts and edgeless children per level"
```

---

### Task 7: Port nodes for cross-border edges

**Files:**
- Modify: `tmi_tf/layout/compound.py`, `tests/test_layout_compound.py`

**Interfaces:**
- Consumes: `layered.Kind.START_PORT`/`END_PORT`, `orient`, `rank` (already port-aware from Task 2); the per-level function with a designated part (Task 6). Pele `compound.ts`: port creation (543-553), `build` port nodes (588-609), the sides pre-pass (702-730), port placement on the border (771-787).
- Produces: `EdgeRoute.border_out` and `EdgeRoute.border_in` filled; no signature changes.

Pinned:
- Ports: for a lifted flow, every group strictly between the source and the lifted level gets an out-port for that flow, attached to its child that contains (or is) the source; likewise an in-port for every group strictly between the target and the level. A boundary that is itself the flow's end gets no port.
- Sides, a top-down pre-pass with ranking only: for each level, parents before children, run `orient` and `rank` on the level's children and merged lifted edges (no port nodes). If `a` ranks above `b`, every out-port on the source path is an end-side port and every in-port on the target path a start-side port; otherwise the reverse. (Start side is left in `LR`, top in `TB`.)
- Border part (spec "Settled" item 1): in a level that has ports, all children that are the inner child of any port are unioned into one part, the border part, together with everything connected to them by lifted edges. Its `layered()` call gets one zero-size port node per port, appended after the children, `Kind.START_PORT` or `Kind.END_PORT` by side, sorted by `(inner child's index in the level, flow index)`. Port edges have weight 1 and are never merged: out-port `LEdge(inner, port)`, in-port `LEdge(port, inner)`.
- Placement: the border part goes at cross-axis offset 0; all other parts and the grid block are shelf-packed (Task 6) into one block placed after it on the cross axis with gap `node_sep` (below it in `LR`, right of it in `TB`). The level's rank-axis extent is the larger of the two. A child with no edges at all, inside or across, stays in the grid block.
- Port nodes are left out of the content bounding box. A port's final point: cross-axis coordinate from `layered`, moved with the children and clamped to the group's box; rank-axis coordinate snapped to the group's border on its side (`LR`: `x = box.x` or `box.x + box.w`; `TB`: `y = box.y` or `box.y + box.h`). Rounded with the shared rule.
- A port edge that spans several ranks has bend points of its own beside the group's other children. They are kept with the port, as in Pele's `port.route`: `border_out` is, for each group from the innermost outward, that port edge's bend points (child toward port) then the port point; `border_in` is, for each group from the outermost inward, the port point then the bend points (port toward child). These bend points count toward the level's content box like any other edge point, whether or not `EMIT_BORDER_VERTICES` is set, so the flag never changes node geometry.

- [ ] **Step 1: Write the failing tests**

```python
def test_ports_sit_on_the_facing_borders():
    nodes = [leaf("src"), group("g"), leaf("a", "g"), leaf("b", "g"), leaf("dst")]
    r = compound_layout(nodes, [edge(0, "src", "a"), edge(1, "b", "dst")], "LR")
    g = r.boxes["g"]
    [(x_in, y_in)] = r.routes["0"].border_in
    [(x_out, y_out)] = r.routes["1"].border_out
    assert x_in == g.x and x_out == g.x + g.w
    assert g.y <= y_in <= g.y + g.h and g.y <= y_out <= g.y + g.h
    assert r.routes["0"].border_out == [] and r.routes["1"].border_in == []

def test_tb_ports_sit_on_top_and_bottom():
    nodes = [leaf("src"), group("g"), leaf("a", "g")]
    r = compound_layout(nodes, [edge(0, "src", "a")], "TB")
    assert r.routes["0"].border_in[0][1] == r.boxes["g"].y

def test_nested_groups_get_one_port_per_border():
    nodes = [group("o"), group("i", "o"), leaf("a", "i"), leaf("dst")]
    r = compound_layout(nodes, [edge(0, "a", "dst")], "LR")
    out = r.routes["0"].border_out
    assert [p[0] for p in out] == [r.boxes["i"].x + r.boxes["i"].w, r.boxes["o"].x + r.boxes["o"].w]

def test_reversed_lifted_edge_uses_the_start_side():
    nodes = [group("g1"), leaf("a", "g1"), group("g2"), leaf("b", "g2")]
    r = compound_layout(nodes, [edge(0, "a", "b"), edge(1, "b", "a")], "LR")
    back = r.routes["1"]
    assert back.reversed and back.border_out[0][0] == r.boxes["g2"].x      # leaves g2 through its left border
    assert back.border_in[0][0] == r.boxes["g1"].x + r.boxes["g1"].w

def test_ports_keep_inner_child_order():
    nodes = [leaf("s1"), leaf("s2"), group("g"), leaf("a1", "g"), leaf("a2", "g")]
    r = compound_layout(nodes, [edge(0, "s2", "a2"), edge(1, "s1", "a1")], "LR")
    assert r.routes["1"].border_in[0][1] < r.routes["0"].border_in[0][1]   # a1's port above a2's

def test_only_untouched_children_go_to_the_grid_block():
    nodes = [leaf("src"), group("g"), leaf("a", "g"), leaf("p", "g"), leaf("q", "g"), leaf("u", "g")]
    r = compound_layout(nodes, [edge(0, "src", "a"), edge(1, "p", "q")], "LR")
    a, p, u = (r.boxes[k] for k in "apu")
    assert p.y >= a.y + a.h + 40 and u.y >= a.y + a.h + 40                 # border part first on the cross axis

def test_port_edge_bends_pass_beside_siblings():
    # a -> b inside g, and a -> dst: a's port edge skips b's rank
    nodes = [group("g"), leaf("a", "g"), leaf("b", "g"), leaf("dst")]
    r = compound_layout(nodes, [edge(0, "a", "b"), edge(1, "a", "dst")], "LR")
    g, b, out = r.boxes["g"], r.boxes["b"], r.routes["1"].border_out
    assert len(out) == 3 and out[-1][0] == g.x + g.w                      # two bend points, then the port
    assert all(not (b.x < x < b.x + b.w and b.y < y < b.y + b.h) for x, y in out)
    assert all(g.x <= x <= g.x + g.w and g.y <= y <= g.y + g.h for x, y in out)

def test_boundary_endpoint_gets_no_port_of_its_own():
    nodes = [leaf("src"), group("o"), group("g", "o")]
    r = compound_layout(nodes, [edge(0, "src", "g")], "LR")
    assert len(r.routes["0"].border_in) == 1                               # o's border only
```

- [ ] **Step 2: Run to verify failure.** Run: `uv run pytest tests/test_layout_compound.py -q`. Expected: the new tests FAIL (empty `border_in`/`border_out`).
- [ ] **Step 3: Implement** as pinned. The pre-pass decides sides before any level is sized; the bottom-up pass then builds each border part with its port nodes.
- [ ] **Step 4: Run the tests, `uv run pytest tests/test_layout_properties.py tests/test_diagram_builder.py -q`, then the done gate.** Expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add tmi_tf/layout/compound.py tests/test_layout_compound.py
git commit -m "feat(layout): port nodes for edges that cross boundary borders"
```

---

### Task 8: Vertices, fanned parallel edges, connector, label positions

**Files:**
- Create: `tmi_tf/layout/routes.py`, `tests/test_layout_routes.py`
- Modify: `tmi_tf/diagram_builder.py` (`_create_edge_cells`, `_create_edge_cell`), `tests/test_diagram_builder.py`, `tests/test_layout_properties.py`

**Interfaces:**
- Consumes: `DFDBuilder._layout`, `_parent`, `_components` (Task 5); `compound.Box`, `EdgeRoute`, `Direction`, `Side`, `LayoutOptions`, `compound.LAYOUT_DIRECTION` and `compound.EMIT_BORDER_VERTICES` read at call time.
- Produces in `routes.py` (pure functions, not a Pele port, so no Pele header):

```python
Point = tuple[int, int]
MAX_VERTICES = 1000

def side_point(box: Box, side: Side | None) -> Point             # middle of that side; centre when side is None
def straighten(points: list[Point], start: Point, end: Point, tol: float = 0.5) -> list[Point]
def fan_offsets(k: int, edge_sep: int) -> list[float]            # (i - (k - 1) / 2) * edge_sep
def label_positions(k: int) -> list[float]                       # [0.5] for k == 1, else 0.35..0.65 evenly, rounded to 4 places
def gap_midpoint(a: Box, b: Box, source: Box, target: Box, direction: Direction) -> Point
def shift_cross(points: list[Point], offset: float, direction: Direction) -> list[Point]
def drop_blocked(points: list[Point], blockers: list[Box]) -> list[Point]   # removes points strictly inside any blocker
```

- Produces on `DFDBuilder`: `_route_points(self, route: EdgeRoute, forward: bool) -> list[tuple[int, int]]`.

Pinned (spec "Mapping to cells" and "Settled" item 3):
- `_route_points`: `route.points`, wrapped as `border_out + points + border_in` only when `compound.EMIT_BORDER_VERTICES` is true; reversed when `forward` is false; `[]` for a route that is not lifted.
- Order per cell: `_route_points`, then `straighten`, then fanning, then `drop_blocked`, then the vertex cap. `straighten` sees route points only; a fan vertex is never straightened (the middle cell of an odd fan sits exactly on the straight line and must keep its vertex).
- `straighten`: one pass; drop a point whose perpendicular distance to the line through the previous kept point (or `start`) and the next point (or `end`) is under `tol`. `start`/`end` are `side_point` of the source and target boxes with the cell's port sides (`None` for a boundary end). This is the spec's rule, not Pele's `straighten`.
- Fan groups: edge cells are grouped by unordered endpoint pair, `tuple(sorted((source_id, target_id)))`, in a dict in first-appearance order; `i` is the cell's position in its group, `k` the group size. For `k > 1`: a cell that still has route points after `straighten` gets `shift_cross(vertices, fan_offsets(k, 20)[i], direction)`; a cell with none whose route is lifted gets the single vertex `shift_cross([gap_midpoint(...)], ...)`; a cell whose route is not lifted gets none. The shift is along the cross axis (`y` in `LR`, `x` in `TB`) in screen coordinates, the same sign for forward and reverse cells. Its label gets `"position": label_positions(k)[i]`. For `k == 1` vertices are unshifted and the label has no `position` key.
- `gap_midpoint`: rank-axis coordinate is the middle of the gap between the facing borders of `a` and `b` (the route's lifted children); cross-axis coordinate is the mean of the source and target box centres. Rounded with the shared rule.
- After fanning, every cell's vertices go through `drop_blocked` with the boxes of all components that are neither a proper ancestor of the cell's source nor of its target. Then, if more than `routes.MAX_VERTICES` remain, the cell gets no vertices and a warning is logged.
- A cell has a `vertices` key only when the list is non-empty; `connector` follows it as in Global Constraints.

- [ ] **Step 1: Write the failing tests**

`tests/test_layout_routes.py`:

```python
def test_straighten_drops_collinear_points_only():
    assert straighten([(100, 0)], (0, 0), (200, 0)) == []
    assert straighten([(100, 1)], (0, 0), (200, 0)) == [(100, 1)]
    assert straighten([(50, 0), (50, 80), (100, 80)], (0, 0), (100, 160)) == [(50, 0), (50, 80), (100, 80)]

def test_fan_offsets_and_label_positions():
    assert fan_offsets(2, 20) == [-10.0, 10.0] and fan_offsets(3, 20) == [-20.0, 0.0, 20.0]
    assert label_positions(1) == [0.5] and label_positions(2) == [0.35, 0.65]
    assert label_positions(3) == [0.35, 0.5, 0.65]

def test_gap_midpoint_lies_between_the_lifted_children():
    a, b = Box(0, 0, 200, 300), Box(260, 0, 200, 300)
    assert gap_midpoint(a, b, Box(40, 100, 120, 60), Box(300, 200, 120, 60), "LR") == (230, 180)
    assert gap_midpoint(b, a, Box(300, 200, 120, 60), Box(40, 100, 120, 60), "LR") == (230, 180)

def test_shift_cross_and_drop_blocked():
    assert shift_cross([(10, 10)], 10.0, "LR") == [(10, 20)] and shift_cross([(10, 10)], -10.0, "TB") == [(0, 10)]
    assert drop_blocked([(5, 5), (10, 5), (50, 50)], [Box(0, 0, 10, 10)]) == [(10, 5), (50, 50)]

def test_side_point():
    box = Box(100, 100, 120, 60)
    assert [side_point(box, s) for s in ("top", "right", "bottom", "left", None)] == [
        (160, 100), (220, 130), (160, 160), (100, 130), (160, 130)]
```

`tests/test_diagram_builder.py`, `class TestEdgeGeometry`:

```python
def build_edges(specs):
    """Edge cells for two root computes c1, c2 and flows given as (source, target[, bidirectional])."""
    comps = [make_component("c1", "A", "compute"), make_component("c2", "B", "compute")]
    flows = [make_flow(f"f{i}", s[0], s[1], bidirectional=len(s) > 2 and s[2]) for i, s in enumerate(specs)]
    return get_edge_cells(DFDBuilder(comps, flows).build_cells())

class TestEdgeGeometry:
    def test_single_short_edge_is_smooth_without_vertices(self):
        e = build_edges([("c1", "c2")])[0]
        assert "vertices" not in e and e["connector"] == {"name": "smooth"}
        assert "position" not in e["labels"][0] and e["router"] == {"name": "normal"}

    def test_bidirectional_pair_is_fanned(self):
        fwd, rev = build_edges([("c1", "c2", True)])
        (v1,), (v2,) = fwd["vertices"], rev["vertices"]
        assert v1["x"] == v2["x"] and v2["y"] - v1["y"] == 20
        assert [e["labels"][0]["position"] for e in (fwd, rev)] == [0.35, 0.65]
        assert fwd["connector"] == rev["connector"] == {"name": "rounded"}

    def test_three_cells_on_one_pair_share_a_fan(self):
        edges = build_edges([("c1", "c2"), ("c2", "c1"), ("c1", "c2")])
        ys = [e["vertices"][0]["y"] for e in edges]
        assert ys[1] - ys[0] == 20 and ys[2] - ys[1] == 20
        assert [e["labels"][0]["position"] for e in edges] == [0.35, 0.5, 0.65]

    def test_long_edge_does_not_cross_the_node_it_skips(self):
        comps = [make_component(c, c, "compute") for c in ("a", "b", "c")]
        flows = [make_flow("f1", "a", "b"), make_flow("f2", "b", "c"), make_flow("f3", "a", "c")]
        cells = DFDBuilder(comps, flows).build_cells()
        a, b, c = (get_cell(cells, k) for k in "abc")
        skip = get_edge_cells(cells)[2]
        pts = [(a["x"] + a["width"], a["y"] + a["height"] / 2)]              # port "right"
        pts += [(v["x"], v["y"]) for v in skip.get("vertices", [])]
        pts.append((c["x"], c["y"] + c["height"] / 2))                       # port "left"
        for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
            for t in range(101):
                x, y = x1 + (x2 - x1) * t / 100, y1 + (y2 - y1) * t / 100
                assert not (b["x"] < x < b["x"] + b["width"] and b["y"] < y < b["y"] + b["height"])
```

Also: `test_connector_matches_vertices` (over `HAND_CASES`: `rounded` exactly when `vertices` is present); `test_route_points_respects_border_flag` (a builder with a hand-made `EdgeRoute(lifted=True, points=[(5, 5)], border_out=[(1, 1)], border_in=[(9, 9)])`: flag off gives `[(5, 5)]`; flag on, `forward=False` gives `[(9, 9), (5, 5), (1, 1)]`; `EdgeRoute()` gives `[]`); `test_self_and_ancestor_flows_get_no_vertices` (Review Focus 1: a `c1 -> c1` flow twice gives two cells with no `vertices` and label positions `0.35`, `0.65`); `test_too_many_vertices_are_dropped_with_warning` (`monkeypatch.setattr(routes, "MAX_VERTICES", 0)` on the bidirectional case: no `vertices` key, connector `smooth`, a warning per cell).

In `tests/test_layout_properties.py` add to `check_invariants`: `connector` is `rounded` exactly when `vertices` is present, and every label `position`, when present, is between 0.35 and 0.65.

- [ ] **Step 2: Run to verify failure.** Run: `uv run pytest tests/test_layout_routes.py tests/test_diagram_builder.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `routes.py` and the edge-cell changes as pinned. Build all edge-cell specs first (input order), then group, then emit, so fan indices do not depend on emission.
- [ ] **Step 4: Run the tests, `uv run pytest tests/test_layout_properties.py -q`, then the done gate.** Expected: all pass, including the vertex-inside-node property and the cross-process determinism test.
- [ ] **Step 5: Commit**

```bash
git add tmi_tf/layout/routes.py tmi_tf/diagram_builder.py tests/test_layout_routes.py tests/test_diagram_builder.py tests/test_layout_properties.py
git commit -m "feat(dfd): edge vertices, fanned parallel flows, connector and label placement"
```

---

### Task 9: Preview tool, MIT notices, docs

**Files:**
- Create: `scripts/preview_dfd.py`, `tests/test_preview_dfd.py`, `tests/fixtures/dfd_preview/small.json`, `THIRD_PARTY_NOTICES.md`, `tests/test_layout_notices.py`

**Interfaces:**
- Consumes: `DFDBuilder(components, flows).build_cells()`; `compound.LAYOUT_DIRECTION`, `compound.EMIT_BORDER_VERTICES`; `routes.side_point`; `compound.Box`; `dfd_cases.fixture_files`/`load_fixture`; the fixture file format from Task 1.
- Produces: `render_svg(cells: list[dict[str, Any]]) -> str`; `main(argv: list[str] | None = None) -> int`.

Pinned:
- CLI: `uv run python scripts/preview_dfd.py INPUT.json OUT.svg [--direction LR|TB] [--border-vertices]`. `main` sets `compound.LAYOUT_DIRECTION` and `compound.EMIT_BORDER_VERTICES` from the flags (defaults `LR`, false), builds cells, writes `render_svg(cells)`, prints `wrote OUT.svg: N nodes, M edges`, returns 0. A missing file, invalid JSON, or missing `components`/`flows` key returns 2 with the message on stderr and writes nothing. `OUT.svg` is a derived file and is overwritten on every run.
- `render_svg`: `viewBox` is the bounding box of all node cells and vertices plus a 20px margin. Order: boundaries (cells without `ports`) by `zIndex`, as `<rect>` with no fill and a dashed stroke, name as `<text>` inside the top-left corner; then leaves as filled `<rect>` with centred `<text>`; then one `<polyline>` per edge through `side_point(source box, source port)`, its vertices, and `side_point(target box, target port)`, with an arrowhead marker; then each edge label as `<text>` at its `position` fraction (default 0.5) of the polyline's length. Exactly one `<rect>` per node cell and one `<polyline>` per edge cell (the arrowhead is a `<path>` in `<defs>`). All text goes through `html.escape`. No cell ids appear in the output, so two runs on equal input give identical bytes.
- `tests/fixtures/dfd_preview/small.json` (hand-written, fixture format): tenant `t` containing network `n` (containing leaves `a`, `b`) and leaf `c`; root actor `u` named `User <admin> & "ops"`; flows `u -> a`, `a -> b` bidirectional, `b -> c`, `u -> c`.
- `THIRD_PARTY_NOTICES.md` (not `NOTICE`: this repo is Apache-2.0, where a `NOTICE` file carries redistribution obligations of its own): one entry for Pele with the URL, commit `3a2f075`, the three files that contain ported code, and the full MIT text with `Copyright (c) 2026 kepano`. Before writing it, verify the copyright line against upstream: `curl -fsSL https://raw.githubusercontent.com/obsidianmd/pele/3a2f075/LICENSE`. If the fetch fails or the line differs from the header in Global Constraints, stop and report instead of guessing.

- [ ] **Step 1: Write the failing tests**

`tests/test_preview_dfd.py` (loads the script as `preview_dfd`; `SMALL` is the fixture path):

```python
def cells_for(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return DFDBuilder(data["components"], data["flows"]).build_cells()

def test_render_has_one_rect_per_node_and_one_polyline_per_edge():
    svg = preview_dfd.render_svg(cells_for(SMALL))
    assert svg.startswith("<svg") and svg.count("<rect") == 6 and svg.count("<polyline") == 5

def test_text_is_escaped():
    svg = preview_dfd.render_svg(cells_for(SMALL))
    assert "User &lt;admin&gt; &amp; &quot;ops&quot;" in svg and "<admin>" not in svg

def test_render_is_deterministic():
    assert preview_dfd.render_svg(cells_for(SMALL)) == preview_dfd.render_svg(cells_for(SMALL))

def test_main_writes_svg_and_direction_changes_it(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(compound, "LAYOUT_DIRECTION", "LR")       # restored after the test
    monkeypatch.setattr(compound, "EMIT_BORDER_VERTICES", False)
    lr, tb = tmp_path / "lr.svg", tmp_path / "tb.svg"
    assert preview_dfd.main([str(SMALL), str(lr)]) == 0
    assert capsys.readouterr().out.strip() == f"wrote {lr}: 6 nodes, 5 edges"
    assert preview_dfd.main([str(SMALL), str(tb), "--direction", "TB"]) == 0
    assert lr.read_text() != tb.read_text()

def test_main_rejects_bad_input(tmp_path, capsys):
    bad = tmp_path / "bad.json"; bad.write_text("{\"components\": []}")
    assert preview_dfd.main([str(bad), str(tmp_path / "o.svg")]) == 2
    assert "flows" in capsys.readouterr().err and not (tmp_path / "o.svg").exists()
    assert preview_dfd.main([str(tmp_path / "missing.json"), str(tmp_path / "o.svg")]) == 2

@pytest.mark.parametrize("path", fixture_files(), ids=lambda p: p.stem)
def test_exported_fixtures_render(path):
    comps, flows = load_fixture(path)
    assert preview_dfd.render_svg(DFDBuilder(comps, flows).build_cells()).count("<rect") == len(comps)
```

`tests/test_layout_notices.py`:

```python
ROOT = Path(__file__).parent.parent
PORTED = {"layered.py": "layered.ts", "compound.py": "compound.ts", "pack.py": "components.ts"}

def test_ported_files_carry_the_pele_notice():
    for name, source in PORTED.items():
        head = (ROOT / "tmi_tf" / "layout" / name).read_text(encoding="utf-8")[:2000]
        assert "Copyright (c) 2026 kepano" in head and "Permission is hereby granted" in head
        assert f"src/layout/{source}, commit 3a2f075" in head

def test_third_party_notices_lists_pele():
    text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert all(s in text for s in ("obsidianmd/pele", "3a2f075", "Copyright (c) 2026 kepano",
                                   "Permission is hereby granted", *PORTED))
```

- [ ] **Step 2: Run to verify failure.** Run: `uv run pytest tests/test_preview_dfd.py tests/test_layout_notices.py -q`. Expected: FAIL (script and notices file missing).
- [ ] **Step 3: Implement** `scripts/preview_dfd.py`, write the fixture and `THIRD_PARTY_NOTICES.md`.
- [ ] **Step 4: Run the tests, then the done gate, and show its output.** Expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add scripts/preview_dfd.py tests/test_preview_dfd.py tests/fixtures/dfd_preview/small.json THIRD_PARTY_NOTICES.md tests/test_layout_notices.py
git commit -m "feat(scripts): SVG preview for DFD layouts; third-party notice for Pele"
```

- [ ] **Step 6 (controller, not the implementer): follow-ups**

The prompt-wording follow-up is already filed as #98; do not file it again. Propose to Eric (do not edit it on an agent's say-so) two changes to `.claude/CLAUDE.md`: a Modules line for `layout/` with a reworded `diagram_builder.py` line, and the `Done gate:` line extended to `scripts/` as in Global Constraints. Then render LR and TB previews (with and without `--border-vertices`) of `tests/fixtures/dfd_preview/small.json` and every file in `tests/fixtures/dfd/` into the session scratchpad and hand the paths to Eric. Judging direction, deciding `EMIT_BORDER_VERTICES`, the tmi-ux check on a test threat model, and any deploy are Eric's calls.
