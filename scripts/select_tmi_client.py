"""Pick the generated TMI Python client for an image build.

Used at image build time. Copies the newest ``python-client-generated/vX.Y.Z``
whose version is at or above the minimum TMI API schema version the current
build was built against (``deploy/docker/tmi-api-min-version``). The TMI
server's own schema version is deliberately not consulted. No client at or
above the minimum fails the build.
"""

import argparse
import re
import shutil
import sys
from pathlib import Path

_VERSION_DIR = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def parse_version(text: str) -> tuple[int, int, int]:
    major, minor, patch = (int(p) for p in text.strip().lstrip("v").split(".")[:3])
    return major, minor, patch


def select(clients: Path, min_version: str) -> Path:
    floor = parse_version(min_version)
    candidates = []
    for d in clients.iterdir():
        m = _VERSION_DIR.match(d.name)
        if d.is_dir() and m:
            v = tuple(int(g) for g in m.groups())
            if v >= floor:
                candidates.append((v, d))
    if not candidates:
        raise SystemExit(
            f"no python client at or above TMI API {min_version.strip()} in {clients}"
        )
    return max(candidates)[1]


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--min-version-file",
        required=True,
        type=Path,
        help="file holding the minimum TMI API schema version (X.Y.Z)",
    )
    ap.add_argument("--clients", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)
    min_version = args.min_version_file.read_text(encoding="utf-8").strip()
    chosen = select(args.clients, min_version)
    shutil.copytree(chosen, args.out)
    print(f"TMI API minimum {min_version} -> client {chosen.name}", file=sys.stderr)


if __name__ == "__main__":
    main()
