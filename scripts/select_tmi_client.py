"""Pick the generated TMI Python client that matches the TMI API schema version.

Used at image build time. Reads ``info.version`` from tmi-openapi.json (a URL
or a local path) and copies the newest ``python-client-generated/vX.Y.Z``
with the same major.minor and a patch not above the schema's. Patch releases
are API-compatible; a missing major.minor fails the build.
"""

import argparse
import json
import re
import shutil
import sys
import urllib.request
from pathlib import Path

_VERSION_DIR = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def schema_version(source: str) -> str:
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=30) as resp:
            data = json.load(resp)
    else:
        data = json.loads(Path(source).read_text(encoding="utf-8"))
    return str(data["info"]["version"])


def select(clients: Path, version: str) -> Path:
    major, minor, patch = (int(p) for p in version.split(".")[:3])
    candidates = []
    for d in clients.iterdir():
        m = _VERSION_DIR.match(d.name)
        if d.is_dir() and m:
            v = tuple(int(g) for g in m.groups())
            if v[:2] == (major, minor) and v[2] <= patch:
                candidates.append((v, d))
    if not candidates:
        raise SystemExit(
            f"no python client for TMI API {major}.{minor} (<= {version}) in {clients}"
        )
    return max(candidates)[1]


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--schema", required=True, help="tmi-openapi.json URL or path")
    ap.add_argument("--clients", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)
    version = schema_version(args.schema)
    chosen = select(args.clients, version)
    shutil.copytree(chosen, args.out)
    print(f"TMI API schema {version} -> client {chosen.name}", file=sys.stderr)


if __name__ == "__main__":
    main()
