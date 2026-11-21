# DFD layered layout: design

Date: 2026-11-20
Status: approved by Eric, 2026-11-20

## Intent

The DFDs that `tmi-tf` writes to TMI are hard to read. `DFDBuilder` places every
component on a fixed 120x60 grid, ignores flow direction, routes every edge as a straight
`smooth` line through any node in the way, and draws both edges of a bidirectional flow
on the same two ports. The server's layout is what a TMI user sees first: tmi-ux only
re-lays out a container when the user drags, embeds or resizes something
(`dfd.component.ts` `_runLayoutCycle`), never on load. So the server layout needs to be
readable as delivered.

Replace the grid placement with a layered (Sugiyama-style) layout, ported from Pele
(https://github.com/obsidianmd/pele, MIT, `src/layout/`, commit `3a2f075`), adapted to
TMI's nested security boundaries and X6 edge cells.

## Goals

- Flows read in one direction across the whole diagram.
- Every child sits inside its parent boundary, siblings never overlap. Both hold by
  construction.
- Components with no flows pack into compact blocks, not one long row.
- Edge ports follow layout direction; edges that skip ranks get bend points
  (`vertices`) that run between nodes, not through them.
- The two edges of a bidirectional flow, and their labels, are visibly separate.
- Identical input gives identical geometry (cell ids aside).

## Non-goals

- Explicit orthogonal edge routing (Pele `assignTracks`), sliding edge ends along a
  side (`spread`/`settle`), `snap`, label dummy nodes, swimlanes, mixed per-group
  directions.
- More than four ports per node: tmi-ux assumes exactly `top/right/bottom/left`
  (`infra-node.service.spec.ts`).
- The flat ordering pre-pass (Pele `compoundLayout` `flat` block). Considered later,
  only if cross-border crossings are still a problem on real diagrams.
- Changes to the LLM prompts, the component/flow schema, or tmi-ux.

## Anti-goals

- A new runtime dependency or native binary in the images (the grype gate scans them).
- Non-deterministic output (iterating sets, or dicts keyed by unordered data).
- Any regression in containment, sibling non-overlap, or the 40x30 API minimum size.

## Constraints

- `DFDBuilder.build_cells()` keeps its signature and cell format; callers are unchanged.
- TMI `Edge` schema (`api-schema/tmi-openapi.json` in `ericfitz/tmi`): `vertices` is an
  array of `{x, y}` (max 1000); `router` is one of `normal|orth|one_side|manhattan|metro|er`;
  `connector` one of `normal|rounded|smooth|jumpover`; label `position` may be a 0-1
  fraction.
- X6 node `x`/`y` are absolute top-left; the layout works in centers and converts at the end.
- Boundaries (`tenant`, `container`, `network`) have no ports; leaves have the four fixed
  ports.
- A close port of Pele code carries Pele's MIT notice (copyright kepano) in each ported
  file's header and in a repo `NOTICE` (or `THIRD_PARTY_NOTICES`) entry.

## Approaches

Considered:

- **A. Port Pele to pure Python** (chosen by Eric, 2026-11-20). No new dependencies, deterministic,
  full control over ports, vertices and packing, fits the existing bottom-up/top-down
  skeleton in `_auto_layout`. Cost: about 1-1.5k lines plus tests, owned by us.
- **B. Graphviz `dot` with clusters.** Proven nested-cluster layout, less code. Rejected:
  adds a native package (and cairo/pango etc.) to the AL2023 and Wolfi images, widening the
  grype surface; a subprocess per diagram; still needs a translation layer from dot splines
  to X6 vertices and four fixed ports.
- **C. Spike both, judge visually.** Rejected in favour of committing to A.
- Dropped without sketching: pure-Python `grandalf` (no compound/cluster support,
  unmaintained); ELK via `elkjs` (needs Node in the image).

**Human decision (Eric, 2026-11-20):** build the layered layout in-house as a Python port of
Pele (approach A), not Graphviz.

## Design

### Package layout

New pure-Python package with no X6 knowledge:

- `tmi_tf/layout/layered.py` - lay out one flat graph (nodes with w/h, weighted edges).
  Ranks run down the y axis; the caller rotates for left-to-right.
- `tmi_tf/layout/compound.py` - recursion over the embedding tree: lifted edges, port
  nodes, bottom-up sizing, top-down absolute positions.
- `tmi_tf/layout/pack.py` - connected-component split and shelf packing.

`DFDBuilder` builds the layout input from components and flows, calls the layout, and maps
results to cells. `_place_items_in_grid`, `_order_leaves_by_flow`, `_get_optimal_port`
(angle-based) and the root-stacking rule in `_auto_layout` are removed.

The top of the diagram is a virtual root level containing all parentless components, so
roots need no special rule.

### Direction

One direction for the whole diagram, a module constant `LAYOUT_DIRECTION` in
`compound.py` (`"LR"` or `"TB"`), default `"LR"`. Both are implemented and tested; the
preview tool renders either.

**Human decision (Eric, 2026-11-20):** the default layout direction is left-to-right.

### Algorithm

**Step 1, lift edges.** Each flow is one layout edge source->target (a bidirectional flow
counts once). Find the lowest common ancestor `P` of the two ends; `a`, `b` are the children
of `P` containing source and target; add `a -> b` to level `P`. If one end is an ancestor of
the other, or `a == b` would be produced, the flow takes no part in layout. Duplicate
`a -> b` edges merge into one with a weight. A flow endpoint that is a boundary is treated as
that boundary's box at its level.

**Step 2, sides for external edges (top-down, ranking only).** For each level, parents
before children: run cycle breaking and ranking only. For each lifted edge `a -> b`, if `a`
ranks above `b` the edge leaves `a` through its end side and enters `b` through its start
side, otherwise the reverse. Every group on the path from a leaf up to `a` (or `b`) inherits
that side for that edge. When a group is laid out, each edge crossing its border becomes a
zero-size port node attached to the inner child leading to the leaf; start-side ports are
forced into a rank above all children, end-side ports below. Ports on one border are ordered
by the cross-axis position of the far end where known.

**Step 3, lay out each level (bottom-up)**, on its children (leaf sizes fixed, group sizes
from recursion) plus port nodes:

1. Cycle breaking (`orient`): DFS in input order, reverse each back edge.
2. Ranking (`rank`): longest path from sources, then up to 8 passes moving each node toward
   the side with more edges within its slack.
3. Long edges: a zero-width dummy node in each rank an edge skips.
4. Ordering (`reduceCrossings`): DFS initial order; alternating down/up barycenter sweeps,
   keep the best order, stop after 4 sweeps without improvement or 24 total; then
   adjacent-swap passes accepting only strict improvements. Ties break toward input order.
5. Cross-axis coordinates (`position`): Brandes-Koepf, four alignments, shift to narrowest,
   each node takes the mean of its two middle candidates. `nodeSep` between real nodes,
   `edgeSep` beside dummies.
6. Rank-axis coordinates: one band per rank, as tall as its tallest node, `rankSep` between
   bands, large enough for an edge label (see Labels).
7. Group size: children's bounding box plus padding, extra top padding for the boundary's
   own label, clamped to at least 40x30.

**Step 4, pack disconnected parts** per level: split children into connected components by
lifted edges (union-find over input order); lay out each separately; children with no edges
at all go into one compact grid block; shelf-pack the parts into rows, widest first, to a
target width of `sqrt(total_area * 1.6)` but never narrower than the widest part. Reference:
Pele `components.ts` `wrapComponents`.

**Step 5, absolute positions (top-down):** add each parent's origin to its children;
convert centers to top-left.

### Mapping to cells

- **Ports by direction.** In TB, an edge whose target is in a lower band uses source
  `bottom`, target `top`; upward uses `top`/`bottom`; same band uses `left`/`right` by
  relative x. LR is the same rotated. "Band" is compared at the edge's lifted level using
  the ranks of `a` and `b`. Boundaries keep `{cell}` only.
- **Vertices.** For an edge that skips ranks at its lifted level, emit the dummy positions
  (absolute) as `vertices`. Drop any vertex within 0.5px of the straight line between its
  neighbours (Pele `straighten`).
- **Border-crossing vertices** (port node positions) are emitted only when module flag
  `EMIT_BORDER_VERTICES` is true. **Human decision (Eric, 2026-11-20):** emitted by default
  (`EMIT_BORDER_VERTICES = True`); measured on 300-component diagrams, edges crossing an
  unrelated node fell from 113/414 to 5/414.
- **Bidirectional flows.** The builder already emits two edge cells. Give each one vertex,
  offset `edgeSep/2` either side of the shared midpoint (perpendicular to the flow
  direction), and label anchors at 0.35 and 0.65 from the canonical source (each cell's
  own `position` is 0.35; the reverse cell measures from its own source, see Settled item 3).
- **Connector/router.** `router: normal` throughout. `connector: smooth` for edges with no
  vertices, `rounded` for edges with vertices.
- **Labels.** Width estimated as `chars * 7px + 16px` (constant in one place). TB: widen
  the dummy width / `nodeSep` for labelled edges. LR: `rankSep >= max label width + margin`
  at that level.

### Preview tool

`scripts/preview_dfd.py`: reads a components/flows JSON, runs `DFDBuilder`, writes an SVG
(rectangles for nodes and boundaries, polylines through ports and vertices, labels) to a
given path. Used to judge direction and border vertices without pushing to TMI. Per the
repo rules it has its own test against a small recorded input. Final judgement is in
tmi-ux on a test threat model, which is Eric's call.

### Tests

Replace `test_flow_connected_peers_have_gap` and
`test_boundary_child_occupies_multiple_grid_cells` (grid-specific). Keep the containment,
overlap, nesting, port and edge tests unchanged. Add:

- `layered.py` unit tests on flat graphs: chain, diamond, cycle, long edge, disconnected,
  empty, single node.
- Property checks over the `tests/fixtures/dfd` diagrams and seeded random trees:
  - every child inside its parent, inset by padding;
  - siblings do not overlap and keep at least `nodeSep` apart;
  - every non-reversed lifted edge has its target in a later rank than its source;
  - no vertex lies inside a node that is not an ancestor of one of the edge's ends;
  - identical input gives byte-identical output with ids normalized;
  - all sizes are at least 40x30.
- Rejection: an unknown component type or a flow referencing a missing component is
  skipped with a warning, as today; a `parent_id` cycle or a missing parent is treated as a
  root with a warning, and has a test.

### Order of work

1. Export script and anonymized fixtures (see Test diagrams).
2. `layered.py` (steps 3.1-3.6) with flat-graph tests.
3. `compound.py` with lifted edges and bottom-up sizing; wire into `DFDBuilder`;
   direction-based ports.
4. Packing (step 4).
5. Port nodes for cross-border edges (step 2).
6. Vertices for long edges and bidirectional pairs; connector choice; labels.
7. Preview tool; review LR (and TB for comparison) on the fixtures.

## Settled after the builder check (Claude's calls, for Eric to check)

1. **Packing with border ports.** Per-level packing is new (Pele packs only whole top-level
   trees). Within a group, port nodes join the union-find, and all ports of a group are
   unioned together, so every child with a cross-border flow lands in one "border part".
   That part is laid out as one layered graph with its ports ranked above/below it. The
   remaining internal-only parts and the edgeless grid block are shelf-packed into a block
   placed beside the border part on the cross axis (after it in input order). The group's
   rank-axis extent is the max of the two; port positions then snap to the group's actual
   border. A child with no edges at all, inside or across, goes in the grid block. Packing
   (step 4 of the work order) is built with this rule in mind, so step 5 adds port nodes to
   an existing union-find rather than reworking it.
2. **Port order on a border.** Single pass only: ports on one border are ordered by the
   inner child's position in its level's input order (then flow order). No refine pass, no
   `routeCrossings`; that and the flat pre-pass stay later options.
3. **Several edge cells on one endpoint pair.** Edge cells are grouped by unordered leaf
   pair (A->B, B->A, two A->B flows, and both halves of a bidirectional flow all share a
   group). A group of k > 1 cells is fanned: each cell's whole vertex list is offset
   perpendicular to the flow direction by `(i - (k-1)/2) * edgeSep`, i in input order; a
   cell with no vertices gets one offset vertex at the midpoint of its route at the lifted
   level (between the two lifted children), not the straight leaf-to-leaf midpoint. Label
   positions are spread evenly across 0.35-0.65, measured from the group's canonical
   source (the source of its first cell), so cells running the opposite way use `1 - p`.
   Any fan vertex that would land inside a node that is not an ancestor of one of the
   edge's ends is dropped (the label stagger remains), so the vertex property test holds unconditionally.
4. **The LLM's `rank` and `sibling_order`.** `prompts/dfd_generation_system.txt` already
   asks for both and states a top-to-bottom direction. The layout ignores `rank` (it
   computes ranks) and uses `sibling_order` (then input index) as the "input order" every
   tie-break and DFS refers to; `sibling_order` is a cross-axis order in either direction.
   The prompt's top-to-bottom wording is now inaccurate but does not affect layout; updating
   it is tracked as a separate GitHub issue, not done in this work.

## Test diagrams

**Human decision (Eric, 2026-11-20):** realistic test diagrams are exported from existing
tmi-tf diagrams on the TMI server, not recorded from new LLM calls or hand-written only.

- `scripts/export_tmi_dfd.py` reads diagrams through `TMIClientWrapper` and reverses the
  cells into `DFDBuilder` input: nodes -> components (`parent` -> `parent_id`; the type
  comes from the cell's metadata where present, otherwise the shape: `security-boundary`
  -> `container`, `process` -> `service`, `store` -> `storage`, `actor` -> `actor`); edges
  -> flows (each edge becomes one unidirectional flow; geometry is discarded). An unknown
  shape is an error naming the cell, not a guess.
- Anonymization, because this repo is public: every name and label is replaced with a
  placeholder of the same length (`c0001...`, `f0001...`), metadata is dropped, and ids are
  renumbered. Before committing, the output is checked for hostnames, IPs, account ids and
  original names (rule E). Lengths are kept because label width drives spacing.
- Output goes to `tests/fixtures/dfd/*.json` (frozen; regenerate only with the script).
  Which threat models to export (aim for 3-6 covering small, deep-nested and wide
  diagrams) is chosen with Eric when the script is run; that read of the TMI server is his
  call.
- Seeded random trees and small hand-written cases supplement them for edge cases.

The property tests and the preview tool run over `tests/fixtures/dfd/`, not
`tests/fixtures/tf/`.

## Left to the builder

- Exact spacing constants (`nodeSep`, `edgeSep`, `rankSep`, padding, label header).
- Internal data structures and function boundaries inside `tmi_tf/layout/`.
- How closely to follow Pele's code structure, provided the notice is carried.
