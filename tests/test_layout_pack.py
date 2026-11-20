from tmi_tf.layout.pack import connected_parts, grid_block, shelf_pack


def test_connected_parts_orders_by_smallest_member():
    assert connected_parts(6, [(4, 1), (2, 5), (5, 3)]) == [[0], [1, 4], [2, 3, 5]]


def test_connected_parts_empty_and_no_pairs():
    assert connected_parts(0, []) == []
    assert connected_parts(3, []) == [[0], [1], [2]]


def test_grid_block_of_five_leaves():
    pos, w, h = grid_block([(120, 60)] * 5, 40)
    assert pos == [(0, 0), (160, 0), (320, 0), (0, 100), (160, 100)]
    assert (w, h) == (440, 160)


def test_grid_block_uses_widest_per_column_and_empty():
    pos, w, h = grid_block([(50, 10), (10, 20), (10, 30), (10, 5)], 5)
    assert pos == [(0, 0), (55, 0), (0, 25), (55, 25)] and (w, h) == (65, 55)
    assert grid_block([], 40) == ([], 0, 0)


def test_shelf_pack_three_parts():
    pos, w, h = shelf_pack([(300, 60), (300, 60), (280, 160)], 40)
    assert pos == [(0, 0), (0, 100), (0, 200)] and (w, h) == (300, 360)


def test_shelf_pack_places_widest_first_and_fills_rows():
    pos, w, h = shelf_pack([(100, 50), (400, 50), (100, 50)], 40)
    assert pos == [(0, 90), (0, 0), (140, 90)] and (w, h) == (400, 140)


def test_shelf_pack_single_and_empty():
    assert shelf_pack([(7, 9)], 40) == ([(0, 0)], 7, 9)
    assert shelf_pack([], 40) == ([], 0, 0)
