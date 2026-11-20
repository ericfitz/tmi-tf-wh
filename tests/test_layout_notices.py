"""The Pele MIT notice is present in every ported file and in THIRD_PARTY_NOTICES.md."""

from pathlib import Path

ROOT = Path(__file__).parent.parent
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
