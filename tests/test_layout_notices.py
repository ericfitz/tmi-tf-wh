"""The Pele MIT notice is present in every ported file and in THIRD_PARTY_NOTICES.md."""

from pathlib import Path

ROOT = Path(__file__).parent.parent
MIT_BODY = """Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""
PORTED = {
    "layered.py": "layered.ts",
    "compound.py": "compound.ts",
    "pack.py": "components.ts",
}


def test_ported_files_carry_the_pele_notice():
    for name, source in PORTED.items():
        head = (ROOT / "tmi_tf" / "layout" / name).read_text(encoding="utf-8")[:2000]
        assert (
            "Copyright (c) 2026 kepano" in head
            and "Permission is hereby granted" in head
        )
        assert f"src/layout/{source}, commit 3a2f075" in head


def test_third_party_notices_lists_pele():
    text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert all(
        s in text
        for s in (
            "obsidianmd/pele",
            "3a2f075",
            "Copyright (c) 2026 kepano",
            "Permission is hereby granted",
            *PORTED,
        )
    )


def _norm(text: str) -> str:
    return " ".join(text.split())


def _header_license(path: Path) -> str:
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            break
        lines.append(line[1:].removeprefix(" "))
    text = "\n".join(lines)
    return text.split("Copyright (c) 2026 kepano", 1)[1]


def test_ported_headers_carry_the_full_mit_text():
    for name in PORTED:
        got = _norm(_header_license(ROOT / "tmi_tf" / "layout" / name))
        assert got == _norm(MIT_BODY), name


def test_third_party_notices_carries_the_full_mit_text():
    text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    got = text.split("Copyright (c) 2026 kepano", 1)[1].split("```", 1)[0]
    assert _norm(got) == _norm(MIT_BODY)
