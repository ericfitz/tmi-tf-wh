"""Unit tests for the pure route helpers."""

from tmi_tf.layout.compound import Box
from tmi_tf.layout.routes import (
    drop_blocked,
    fan_offsets,
    gap_midpoint,
    label_positions,
    shift_cross,
    side_point,
    straighten,
)


def test_straighten_drops_collinear_points_only():
    assert straighten([(100, 0)], (0, 0), (200, 0)) == []
    assert straighten([(100, 1)], (0, 0), (200, 0)) == [(100, 1)]
    assert straighten([(50, 0), (50, 80), (100, 80)], (0, 0), (100, 160)) == [
        (50, 0),
        (50, 80),
        (100, 80),
    ]


def test_fan_offsets_and_label_positions():
    assert fan_offsets(2, 20) == [-10.0, 10.0] and fan_offsets(3, 20) == [
        -20.0,
        0.0,
        20.0,
    ]
    assert label_positions(1) == [0.5] and label_positions(2) == [0.35, 0.65]
    assert label_positions(3) == [0.35, 0.5, 0.65]


def test_gap_midpoint_lies_between_the_lifted_children():
    a, b = Box(0, 0, 200, 300), Box(260, 0, 200, 300)
    s, t = Box(40, 100, 120, 60), Box(300, 200, 120, 60)
    assert gap_midpoint(a, b, s, t, "LR") == (230, 180)
    assert gap_midpoint(b, a, t, s, "LR") == (230, 180)
    assert gap_midpoint(b, a, s, t, "LR") == (230, 180)


def test_gap_midpoint_tb_and_overlap_fallback():
    a, b = Box(0, 0, 300, 200), Box(0, 260, 300, 200)
    s, t = Box(100, 40, 60, 120), Box(200, 300, 60, 120)
    assert gap_midpoint(a, b, s, t, "TB") == (180, 230)
    assert gap_midpoint(b, a, t, s, "TB") == (180, 230)
    o1, o2 = Box(0, 0, 100, 100), Box(50, 200, 100, 100)
    assert gap_midpoint(o1, o2, o1, o2, "LR") == (75, 150)


def test_shift_cross_and_drop_blocked():
    assert shift_cross([(10, 10)], 10.0, "LR") == [(10, 20)]
    assert shift_cross([(10, 10)], -10.0, "TB") == [(0, 10)]
    assert drop_blocked([(5, 5), (10, 5), (50, 50)], [Box(0, 0, 10, 10)]) == [
        (10, 5),
        (50, 50),
    ]


def test_side_point():
    box = Box(100, 100, 120, 60)
    assert [side_point(box, s) for s in ("top", "right", "bottom", "left", None)] == [
        (160, 100),
        (220, 130),
        (160, 160),
        (100, 130),
        (160, 130),
    ]
