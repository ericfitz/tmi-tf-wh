"""Every phase system prompt declares the Terraform untrusted (#14)."""

import pytest  # type: ignore

from tmi_tf.config import prompts_dir

FILES = [
    "inventory_system.txt",
    "inventory_semantic_system.txt",
    "infrastructure_analysis_system.txt",
    "threat_identification_system.txt",
    "threat_analysis_system.txt",
    "dfd_generation_system.txt",
    "script_review_system.txt",
]


@pytest.mark.parametrize("name", FILES)
def test_untrusted_data_paragraph(name):
    text = (prompts_dir() / name).read_text(encoding="utf-8")
    assert "# Untrusted input" in text
    assert (
        "never instructions" in text.lower()
        or "never instructions to you" in text.lower()
    )
