"""Tests for scripts/sync_cell_schema.py."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
spec = importlib.util.spec_from_file_location(
    "sync_cell_schema", ROOT / "scripts" / "sync_cell_schema.py"
)
sync = importlib.util.module_from_spec(spec)  # pyright: ignore[reportArgumentType]
spec.loader.exec_module(sync)  # type: ignore[union-attr]

REF = "#/components/schemas/"


def _spec(**schemas) -> dict:
    base = {
        "Node": {"type": "object", "properties": {"data": {"$ref": REF + "Data"}}},
        "Edge": {
            "type": "object",
            "properties": {"source": {"allOf": [{"$ref": REF + "Terminal"}]}},
            "example": {"x": 1},
        },
        "Data": {"type": "object", "x-oapi-codegen-extra-tags": {"a": "b"}},
        "Terminal": {
            "type": "object",
            "properties": {
                "port": {"type": "string", "nullable": True},
                "side": {"type": "string", "enum": ["l", "r"], "nullable": True},
                "nullable": {"type": "boolean"},
            },
        },
        "Unrelated": {"type": "string"},
    }
    base.update(schemas)
    return {"openapi": "3.0.3", "components": {"schemas": base}}


def test_extracts_the_reference_closure_only():
    out = sync.extract(_spec(), "test@1")
    assert set(out["components"]["schemas"]) == {"Node", "Edge", "Data", "Terminal"}
    assert "test@1" in out["$comment"]


def test_converts_openapi_keywords():
    schemas = sync.extract(_spec(), "s")["components"]["schemas"]
    props = schemas["Terminal"]["properties"]
    assert props["port"] == {"type": ["string", "null"]}
    assert props["side"] == {"type": ["string", "null"], "enum": ["l", "r", None]}
    # A property *named* nullable is kept; only the keyword is converted.
    assert props["nullable"] == {"type": "boolean"}
    assert "example" not in schemas["Edge"]
    assert schemas["Data"] == {"type": "object"}


def test_output_validates_with_jsonschema():
    from jsonschema import Draft202012Validator

    doc = sync.extract(_spec(), "s")
    root = dict(doc, **{"$ref": REF + "Edge"})
    Draft202012Validator.check_schema(root)
    validator = Draft202012Validator(root)
    assert validator.is_valid({"source": {"port": None}})
    assert not validator.is_valid({"source": {"port": 3}})


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"openapi": "3.1.0", "components": {"schemas": {}}}, "3.0.x"),
        ({"openapi": "3.0.3", "components": {"schemas": {}}}, "lacks schemas"),
        (_spec(Data={"$ref": REF + "Missing"}), "dangling"),
        (_spec(Data={"$ref": "other.json#/X"}), r"unsupported \$ref"),
    ],
)
def test_rejects_bad_specs(spec, message):
    with pytest.raises(sync.SchemaError, match=message):
        sync.extract(spec, "s")


def test_main_writes_the_file(tmp_path, capsys):
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_spec()))
    out = tmp_path / "out.json"
    assert (
        sync.main(["--spec", str(spec_path), "--source", "s", "--out", str(out)]) == 0
    )
    assert json.loads(out.read_text())["components"]["schemas"]["Node"]
    assert "4 schemas" in capsys.readouterr().out


def test_main_fails_on_a_missing_spec(tmp_path, capsys):
    out = tmp_path / "out.json"
    code = sync.main(
        ["--spec", str(tmp_path / "nope.json"), "--source", "s", "--out", str(out)]
    )
    assert code == 1
    assert not out.exists()
    assert "sync_cell_schema:" in capsys.readouterr().err


def test_vendored_file_is_current_output_format():
    """The checked-in schema has the generator's shape (sorted, 2-space)."""
    path = ROOT / "tmi_tf" / "data" / "tmi_cell_schema.json"
    doc = json.loads(path.read_text())
    assert path.read_text() == json.dumps(doc, indent=2, sort_keys=True) + "\n"
