"""Run id on every object a job creates (#115)."""

import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from test_analyzer import (
    PROFILE,
    TestRunAnalysisEnvironmentSelection,
    _mock_analysis,
    _tmi_with_repo,
    _tree,
)

from tmi_tf.analyzer import run_analysis
from tmi_tf.config import Config
from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.markdown_generator import MarkdownGenerator
from tmi_tf.threat_processor import SecurityThreat

FORBIDDEN_FRAGMENTS = ("llm", "model", "provider", "profile", "token", "cost")


def _run(tmp_path, real_builder=False, **kwargs):
    """One job through the real note/diagram/threat create paths."""
    tree = _tree(tmp_path, ["a"])
    builder_cls: Any = DFDBuilder if real_builder else MagicMock()
    tmi = _tmi_with_repo()
    tmi.create_or_update_note.side_effect = lambda **kw: MagicMock(
        id=f"note-{kw['name'][:18]}"
    )
    tmi.create_or_update_diagram.return_value = "diagram-1"
    analysis = _mock_analysis()
    analysis.security_findings = [{"name": "x"}]
    threats = [
        SecurityThreat(name="t1", description="d", threat_type="Spoofing"),
        SecurityThreat(
            name="t2", description="d", threat_type="Tampering", rule_id="r1"
        ),
    ]
    clone, gh, prov, llm_cls, md, val = TestRunAnalysisEnvironmentSelection()._patches(
        tree
    )
    with (
        clone,
        gh,
        prov,
        llm_cls as llm,
        md as md_cls,
        val,
        patch("tmi_tf.analyzer.DFDLLMGenerator") as dfd_cls,
        patch("tmi_tf.analyzer.DFDBuilder", builder_cls),
        patch(
            "tmi_tf.analyzer.ThreatProcessor.threats_from_findings",
            return_value=threats,
        ),
    ):
        llm.return_value.analyze_repository = MagicMock(return_value=analysis)
        dfd_cls.return_value.generate_structured_components.return_value = {
            "components": [
                {"id": "a", "name": "A", "type": "compute", "subtype": ""},
                {"id": "b", "name": "B", "type": "storage", "subtype": ""},
            ],
            "flows": [
                {
                    "id": "f",
                    "name": "q",
                    "source_id": "a",
                    "target_id": "b",
                    "bidirectional": False,
                }
            ],
        }
        if not real_builder:
            builder_cls.return_value.build_cells.return_value = [{}] * 3
        md_cls.return_value.generate_analysis_report.return_value = "report"
        run_analysis(Config(), "tm1", tmi, PROFILE, **kwargs)
    return tmi, md_cls


def _metadata_by_object(tmi) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    for c in tmi.set_note_metadata.call_args_list:
        out[f"note:{c.kwargs['note_id']}"] = c.kwargs["metadata"]
    for c in tmi.set_diagram_metadata.call_args_list:
        out[f"diagram:{c.kwargs['diagram_id']}"] = c.kwargs["metadata"]
    for i, c in enumerate(tmi.create_threat.call_args_list):
        out[f"threat:{i}"] = c.kwargs["metadata"]
    return out


def _run_ids(objs) -> set[str]:
    ids = set()
    for md in objs.values():
        found = [m["value"] for m in md if m["key"] == "run_id"]
        assert len(found) == 1
        ids.add(found[0])
    return ids


def test_every_create_path_attaches_the_job_run_id(tmp_path):
    rid = str(uuid.uuid4())
    tmi, _ = _run(tmp_path, run_id=rid)
    objs = _metadata_by_object(tmi)
    kinds = {k.split(":")[0] for k in objs}
    assert kinds == {"note", "diagram", "threat"}
    assert sum(k.startswith("note:") for k in objs) == 2  # inventory + analysis
    assert sum(k.startswith("threat:") for k in objs) == 2
    assert _run_ids(objs) == {rid}


def test_no_object_metadata_carries_model_token_or_cost(tmp_path):
    tmi, _ = _run(tmp_path, run_id=str(uuid.uuid4()))
    for md in _metadata_by_object(tmi).values():
        for entry in md:
            assert not any(f in entry["key"].lower() for f in FORBIDDEN_FRAGMENTS)
        assert {m["key"] for m in md} >= {"creation-agent", "creation-timestamp"}


def test_threat_extras_are_kept_next_to_run_id(tmp_path):
    tmi, _ = _run(tmp_path, run_id=str(uuid.uuid4()))
    keys = [
        {m["key"] for m in c.kwargs["metadata"]}
        for c in tmi.create_threat.call_args_list
    ]
    assert "rule-id" in keys[1] and "run_id" in keys[1]


def test_two_runs_get_different_ids_when_none_is_supplied(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    ids_a = _run_ids(_metadata_by_object(_run(a)[0]))
    ids_b = _run_ids(_metadata_by_object(_run(b)[0]))
    assert len(ids_a) == len(ids_b) == 1
    assert ids_a != ids_b
    assert uuid.UUID(next(iter(ids_a)))


def test_sibling_jobs_with_their_own_ids_stay_distinct(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    r1, r2 = str(uuid.uuid4()), str(uuid.uuid4())
    assert _run_ids(_metadata_by_object(_run(a, run_id=r1)[0])) == {r1}
    assert _run_ids(_metadata_by_object(_run(b, run_id=r2)[0])) == {r2}


def test_report_is_generated_with_the_run_id_both_times(tmp_path):
    rid = str(uuid.uuid4())
    _, md_cls = _run(tmp_path, run_id=rid)
    calls = md_cls.return_value.generate_analysis_report.call_args_list
    assert calls and all(c.kwargs["run_id"] == rid for c in calls)


def test_invalid_run_id_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        _run(tmp_path, run_id="not-a-uuid")


def test_report_text_shows_the_run_id():
    from test_markdown_generator import _make_analysis

    rid = str(uuid.uuid4())
    report = MarkdownGenerator().generate_analysis_report(
        "TM", "tm-1", [_make_analysis()], run_id=rid
    )
    assert f"**Run ID**: {rid}" in report


def test_dfd_cells_sent_to_tmi_never_carry_the_run_id(tmp_path):
    rid = str(uuid.uuid4())
    tmi, _ = _run(tmp_path, real_builder=True, run_id=rid)
    cells = tmi.create_or_update_diagram.call_args.kwargs["cells"]
    assert len(cells) >= 3
    assert any(c.get("shape") == "flow" for c in cells)
    assert rid not in str(cells)
    for cell in cells:
        keys = [m["key"] for m in cell.get("data", {}).get("_metadata", [])]
        assert "run_id" not in keys
    # the diagram itself does carry it
    diagram = [
        md for k, md in _metadata_by_object(tmi).items() if k.startswith("diagram")
    ]
    assert [m["value"] for m in diagram[0] if m["key"] == "run_id"] == [rid]


def test_status_note_gets_the_run_id_row_and_metadata(tmp_path):
    rid = str(uuid.uuid4())
    tmi, _ = _run(tmp_path, run_id=rid)
    rows = [c.args[1] for c in tmi.update_status_note.call_args_list]
    assert f"Run ID: {rid}" in rows
    tmi.set_status_note_run_id.assert_called_once_with("tm1", rid)
