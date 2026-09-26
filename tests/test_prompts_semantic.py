"""The semantic phase-1 prompt templates format with the placeholders Task 5 passes."""

from tmi_tf.config import prompts_dir


def test_semantic_user_template_placeholders():
    template = (prompts_dir() / "inventory_semantic_user.txt").read_text(
        encoding="utf-8"
    )
    rendered = template.format(
        repo_name="r",
        repo_url="u",
        inventory_json='{"components": []}',
        filtered_hcl="x",
    )
    assert '{"components": []}' in rendered
    assert "Pre-extracted inventory" in rendered


def test_semantic_system_prompt_exists_and_names_categories():
    text = (prompts_dir() / "inventory_semantic_system.txt").read_text(encoding="utf-8")
    assert "security_control" in text
    assert "Return ONLY a JSON object" in text
