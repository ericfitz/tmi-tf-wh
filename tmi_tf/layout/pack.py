# Portions of this file are a Python port of Pele (https://github.com/obsidianmd/pele),
# src/layout/components.ts, commit 3a2f075, used under the MIT License:
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

"""Packing of disconnected parts: union-find parts, shelf rows, and a grid block for lone items.

All positions are screen coordinates, top-left offsets of the input rectangles.
"""

from math import ceil, sqrt


def connected_parts(n: int, pairs: list[tuple[int, int]]) -> list[list[int]]:
    """Union-find over items 0..n-1; parts ordered by smallest member, members ascending."""
    parent = list(range(n))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for a, b in pairs:
        ra, rb = root(a), root(b)
        if ra != rb:
            # keep the smaller index as root so order never depends on union order
            parent[max(ra, rb)] = min(ra, rb)
    parts: dict[int, list[int]] = {}
    for i in range(n):
        parts.setdefault(root(i), []).append(i)
    return list(parts.values())


def shelf_pack(
    sizes: list[tuple[int, int]], gap: int
) -> tuple[list[tuple[int, int]], int, int]:
    """Place rectangles widest first into rows; returns positions per input index, width, height."""
    if not sizes:
        return [], 0, 0
    area = sum(w * h for w, h in sizes)
    target = max(max(w for w, _ in sizes), sqrt(1.6 * area))
    order = sorted(range(len(sizes)), key=lambda i: (-sizes[i][0], i))
    pos: list[tuple[int, int]] = [(0, 0)] * len(sizes)
    x = y = row_h = width = 0
    for i in order:
        w, h = sizes[i]
        if x > 0 and x + w > target:
            y += row_h + gap
            x = 0
            row_h = 0
        pos[i] = (x, y)
        width = max(width, x + w)
        row_h = max(row_h, h)
        x += w + gap
    return pos, width, y + row_h


def grid_block(
    sizes: list[tuple[int, int]], gap: int
) -> tuple[list[tuple[int, int]], int, int]:
    """Row-major grid of ceil(sqrt(n)) columns; each column and row as large as its biggest item."""
    n = len(sizes)
    if n == 0:
        return [], 0, 0
    cols = ceil(sqrt(n))
    rows = ceil(n / cols)
    col_w = [0] * cols
    row_h = [0] * rows
    for i, (w, h) in enumerate(sizes):
        col_w[i % cols] = max(col_w[i % cols], w)
        row_h[i // cols] = max(row_h[i // cols], h)
    xs = [sum(col_w[:c]) + gap * c for c in range(cols)]
    ys = [sum(row_h[:r]) + gap * r for r in range(rows)]
    pos = [(xs[i % cols], ys[i // cols]) for i in range(n)]
    return pos, sum(col_w) + gap * (cols - 1), sum(row_h) + gap * (rows - 1)
