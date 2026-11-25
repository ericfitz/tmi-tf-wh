"""Tests for TMI cell conformance (#107)."""

import copy
import json
import uuid

import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]

from tmi_tf.cell_schema import (
    METADATA_MAX_ITEMS,
    METADATA_VALUE_MAX,
    SCHEMA_PATH,
    CellSchemaError,
    clean_metadata,
    validate_cells,
)


def _id() -> str:
    return str(uuid.uuid4())


def _node(node_id: str, *, ports: bool = True, shape: str = "process") -> dict:
    cell: dict = {
        "id": node_id,
        "shape": shape,
        "x": 0,
        "y": 0,
        "width": 120,
        "height": 60,
        "data": {"_metadata": [{"key": "component_id", "value": "c1"}]},
    }
    if ports:
        cell["ports"] = {
            "groups": {"right": {"position": "right"}, "left": {"position": "left"}},
            "items": [
                {"id": "right", "group": "right"},
                {"id": "left", "group": "left"},
            ],
        }
    return cell


def _edge(source: str, target: str, sport: str | None, tport: str | None) -> dict:
    src: dict = {"cell": source}
    tgt: dict = {"cell": target}
    if sport is not None:
        src["port"] = sport
    if tport is not None:
        tgt["port"] = tport
    return {
        "id": _id(),
        "shape": "flow",
        "source": src,
        "target": tgt,
        "attrs": {"line": {"targetMarker": {"name": "classic", "size": 8}}},
        "data": {"_metadata": [{"key": "protocol", "value": "HTTPS"}]},
    }


@pytest.fixture
def cells() -> list[dict]:
    a, b, boundary = _id(), _id(), _id()
    return [
        _node(boundary, ports=False, shape="security-boundary"),
        _node(a),
        _node(b),
        _edge(a, b, "right", "left"),
        _edge(a, boundary, "right", None),
    ]


def _problems(cells: list[dict]) -> list[str]:
    with pytest.raises(CellSchemaError) as info:
        validate_cells(cells)
    return info.value.problems


class TestCleanMetadata:
    def test_keeps_valid_entries_in_order(self):
        assert clean_metadata([("a", "1"), ("b.c/d:e-f_g", 2)]) == [
            {"key": "a", "value": "1"},
            {"key": "b.c/d:e-f_g", "value": "2"},
        ]

    @pytest.mark.parametrize("value", [None, "", "   ", "\n\t"])
    def test_omits_empty_values(self, value):
        assert clean_metadata([("port", value)]) == []

    def test_zero_is_a_value(self):
        assert clean_metadata([("port", 0)]) == [{"key": "port", "value": "0"}]

    @pytest.mark.parametrize("key", ["", "has space", "a" * 257, "ünï", "x\n"])
    def test_omits_invalid_keys(self, key):
        assert clean_metadata([(key, "v")]) == []

    def test_omits_non_string_keys(self):
        assert clean_metadata([(1, "v")]) == []  # pyright: ignore[reportArgumentType]

    def test_key_at_max_length_kept(self):
        assert clean_metadata([("a" * 256, "v")])[0]["key"] == "a" * 256

    def test_truncates_long_values(self):
        [entry] = clean_metadata([("d", "x" * 5000)])
        assert len(entry["value"]) == METADATA_VALUE_MAX
        assert entry["value"].endswith("…")

    def test_value_at_max_length_untouched(self):
        [entry] = clean_metadata([("d", "x" * METADATA_VALUE_MAX)])
        assert entry["value"] == "x" * METADATA_VALUE_MAX

    def test_repeated_key_keeps_first(self):
        assert clean_metadata([("k", "1"), ("k", "2")]) == [{"key": "k", "value": "1"}]

    def test_caps_entry_count(self):
        out = clean_metadata((f"k{i}", "v") for i in range(250))
        assert len(out) == METADATA_MAX_ITEMS


class TestValidateCells:
    def test_conforming_cells_pass(self, cells):
        validate_cells(cells)

    def test_empty_list_passes(self):
        validate_cells([])

    def test_empty_metadata_value_rejected(self, cells):
        """The prod bug: {"key": "port", "value": ""} on an edge."""
        cells[3]["data"]["_metadata"].append({"key": "port", "value": ""})
        assert _problems(cells) == ["cells[3].data._metadata[1].value: minLength"]

    def test_bad_metadata_key_rejected(self, cells):
        cells[1]["data"]["_metadata"][0]["key"] = "bad key"
        assert _problems(cells) == ["cells[1].data._metadata[0].key: pattern"]

    def test_unknown_shape_rejected(self, cells):
        cells[1]["shape"] = "cloud"
        assert "cells[1].shape: unknown shape" in _problems(cells)

    def test_non_object_cell_rejected(self, cells):
        cells.append("x")  # pyright: ignore[reportArgumentType]
        assert _problems(cells) == ["cells[5]: not an object"]

    def test_marker_extra_keys_rejected(self, cells):
        cells[3]["attrs"]["line"]["targetMarker"] = {"name": "block", "width": 12}
        assert _problems(cells) == [
            "cells[3].attrs.line.targetMarker: additionalProperties"
        ]

    def test_node_too_small_rejected(self, cells):
        cells[1]["width"] = 10
        assert _problems(cells) == ["cells[1].width: minimum"]

    def test_duplicate_id_rejected(self, cells):
        cells[2]["id"] = cells[1]["id"]
        assert "cells[2].id: duplicate" in _problems(cells)

    def test_dangling_edge_end_rejected(self, cells):
        cells[3]["target"]["cell"] = _id()
        assert _problems(cells) == ["cells[3].target.cell: does not name a node"]

    def test_edge_to_an_edge_rejected(self, cells):
        cells[4]["target"] = {"cell": cells[3]["id"]}
        assert _problems(cells) == ["cells[4].target.cell: does not name a node"]

    def test_missing_terminal_rejected(self, cells):
        del cells[3]["source"]
        problems = _problems(cells)
        assert "cells[3].source: missing" in problems
        assert any(p.startswith("cells[3]: required") for p in problems)

    def test_missing_port_on_ported_node_rejected(self, cells):
        del cells[3]["source"]["port"]
        assert _problems(cells) == ["cells[3].source.port: missing"]

    def test_unknown_port_rejected(self, cells):
        cells[3]["target"]["port"] = "top"
        assert _problems(cells) == ["cells[3].target.port: not a port of its node"]

    def test_port_on_portless_node_rejected(self, cells):
        cells[4]["target"]["port"] = "left"
        assert _problems(cells) == ["cells[4].target.port: node declares no ports"]

    def test_dangling_parent_rejected(self, cells):
        cells[1]["parent"] = _id()
        assert _problems(cells) == ["cells[1].parent: does not name a node"]

    def test_dangling_child_rejected(self, cells):
        cells[0]["children"] = [_id()]
        assert _problems(cells) == ["cells[0].children[0]: does not name a cell"]

    def test_message_carries_paths_not_values(self, cells):
        cells[1]["data"]["_metadata"].append({"key": "k", "value": "x" * 2000})
        with pytest.raises(CellSchemaError) as info:
            validate_cells(cells)
        assert "xxxx" not in str(info.value)
        assert "maxLength" in str(info.value)

    def test_message_is_capped(self, cells):
        for cell in cells[:3]:
            cell["data"]["_metadata"] = [{"key": "k", "value": ""}] * 10
        with pytest.raises(CellSchemaError) as info:
            validate_cells(cells)
        assert len(info.value.problems) == 30
        assert str(info.value).endswith("and 10 more")

    def test_input_is_not_modified(self, cells):
        before = copy.deepcopy(cells)
        validate_cells(cells)
        assert cells == before


def test_vendored_schema_records_its_source():
    document = json.loads(SCHEMA_PATH.read_text())
    assert "ericfitz/tmi@" in document["$comment"]
    assert {"Node", "Edge", "Metadata"} <= set(document["components"]["schemas"])
