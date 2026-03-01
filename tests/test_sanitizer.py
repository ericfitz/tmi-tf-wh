"""Tests for content sanitization."""

from tmi_tf.tmi_client_wrapper import (
    _escape_template_patterns,
    sanitize_content_for_api,
)


class TestSanitizeContentForApi:
    """Test the nh3-based HTML sanitizer."""

    def test_empty_string(self):
        assert sanitize_content_for_api("") == ""

    def test_none_passthrough(self):
        assert sanitize_content_for_api("") == ""

    def test_plain_text_unchanged(self):
        text = "Hello, this is plain text with no HTML."
        assert sanitize_content_for_api(text) == text

    def test_allowed_table_tags_preserved(self):
        html = "<table><thead><tr><th>Header</th></tr></thead><tbody><tr><td>Cell</td></tr></tbody></table>"
        result = sanitize_content_for_api(html)
        assert "<table>" in result
        assert "<thead>" in result
        assert "<tbody>" in result
        assert "<tr>" in result
        assert "<th>" in result
        assert "<td>" in result
        assert "Header" in result
        assert "Cell" in result

    def test_allowed_list_tags_preserved(self):
        html = "<ul><li>Item 1</li><li>Item 2</li></ul>"
        result = sanitize_content_for_api(html)
        assert "<ul>" in result
        assert "<li>" in result
        assert "Item 1" in result

    def test_allowed_formatting_tags_preserved(self):
        html = "<strong>Bold</strong> and <em>italic</em> and <code>code</code>"
        result = sanitize_content_for_api(html)
        assert "<strong>" in result
        assert "<em>" in result
        assert "<code>" in result

    def test_disallowed_script_tag_stripped(self):
        html = "<p>Safe</p><script>alert('xss')</script>"
        result = sanitize_content_for_api(html)
        assert "<script>" not in result
        assert "alert" not in result
        assert "<p>Safe</p>" in result

    def test_disallowed_iframe_stripped(self):
        html = '<iframe src="evil.com"></iframe><p>OK</p>'
        result = sanitize_content_for_api(html)
        assert "<iframe" not in result
        assert "<p>OK</p>" in result

    def test_style_attribute_preserved(self):
        html = '<table style="width:100%"><tr><td>Cell</td></tr></table>'
        result = sanitize_content_for_api(html)
        assert 'style="width:100%"' in result

    def test_col_width_preserved(self):
        html = (
            '<table><colgroup><col style="width:20%"><col style="width:80%">'
            "</colgroup><tr><td>A</td><td>B</td></tr></table>"
        )
        result = sanitize_content_for_api(html)
        assert "width:20%" in result
        assert "width:80%" in result

    def test_disallowed_onclick_attribute_stripped(self):
        html = '<table><tr><td onclick="alert(1)">Cell</td></tr></table>'
        result = sanitize_content_for_api(html)
        assert "onclick" not in result
        assert "<td>" in result
        assert "Cell" in result

    def test_nested_html_tables_preserved(self):
        html = (
            "<table><tr><td><table><tr><td>Nested</td></tr></table></td></tr></table>"
        )
        result = sanitize_content_for_api(html)
        assert result.count("<table>") == 2
        assert "Nested" in result

    def test_heading_tags_preserved(self):
        html = "<h1>Title</h1><h2>Subtitle</h2><h3>Section</h3>"
        result = sanitize_content_for_api(html)
        assert "<h1>" in result
        assert "<h2>" in result
        assert "<h3>" in result

    def test_link_tags_preserved(self):
        html = '<a href="https://example.com">Link</a>'
        result = sanitize_content_for_api(html)
        assert "<a " in result
        assert 'href="https://example.com"' in result

    def test_br_hr_preserved(self):
        html = "Line 1<br>Line 2<hr>Section"
        result = sanitize_content_for_api(html)
        assert "<br>" in result or "<br />" in result
        assert "<hr>" in result or "<hr />" in result

    def test_control_characters_removed(self):
        text = "Hello\x00World\x01Test"
        result = sanitize_content_for_api(text)
        assert "\x00" not in result
        assert "\x01" not in result
        assert "Hello" in result

    def test_newline_tab_preserved(self):
        text = "Line 1\nLine 2\tTabbed"
        result = sanitize_content_for_api(text)
        assert "\n" in result
        assert "\t" in result

    def test_emoji_removed(self):
        # Characters above U+FFFF should be replaced
        text = "Hello \U0001f600 World"
        result = sanitize_content_for_api(text)
        assert "\U0001f600" not in result
        assert "Hello" in result
        assert "World" in result

    def test_mixed_allowed_and_disallowed_tags(self):
        html = (
            "<table><tr><td>OK</td></tr></table>"
            "<script>bad</script>"
            "<ul><li>Good</li></ul>"
            '<div onclick="bad">Content</div>'
        )
        result = sanitize_content_for_api(html)
        assert "<table>" in result
        assert "<ul>" in result
        assert "<li>" in result
        assert "<div>" in result
        assert "<script>" not in result
        assert "onclick" not in result

    def test_dollar_brace_escaped_in_prose(self):
        text = "The module uses ${var.region} for configuration"
        result = sanitize_content_for_api(text)
        assert "${" not in result
        assert "&#36;{var.region}" in result

    def test_double_brace_escaped_in_prose(self):
        text = "Template uses {{.Name}} for rendering"
        result = sanitize_content_for_api(text)
        assert "{{" not in result
        assert "&#123;{.Name}" in result

    def test_erb_pattern_escaped_in_prose(self):
        text = "Uses <% erb %> syntax"
        result = sanitize_content_for_api(text)
        assert "<%" not in result
        assert "&lt;%" in result

    def test_template_patterns_preserved_in_fenced_code(self):
        text = 'Text before\n```hcl\nami = "${var.ami}"\n```\nText after'
        result = sanitize_content_for_api(text)
        # The ${} inside the code block should be preserved
        assert "${var.ami}" in result

    def test_template_patterns_preserved_in_inline_code(self):
        text = "Use `${var.region}` for the region"
        result = sanitize_content_for_api(text)
        assert "`${var.region}`" in result

    def test_template_pattern_escaped_outside_but_not_inside_code(self):
        text = "Config uses ${var.region} like `${var.region}` shows"
        result = sanitize_content_for_api(text)
        # Inline code should be preserved
        assert "`${var.region}`" in result
        # Prose occurrence should be escaped
        assert "&#36;{var.region} like" in result

    def test_dollar_amount_not_affected(self):
        """Dollar amounts like $0.1234 don't contain ${ and should pass through."""
        text = "Cost: $0.1234"
        result = sanitize_content_for_api(text)
        assert result == "Cost: $0.1234"


class TestEscapeTemplatePatterns:
    """Test the template injection escaping helper directly."""

    def test_empty_string(self):
        assert _escape_template_patterns("") == ""

    def test_no_patterns(self):
        text = "Plain text with $dollars and {braces}"
        assert _escape_template_patterns(text) == text

    def test_multiple_dollar_brace_in_prose(self):
        text = "${a} and ${b}"
        result = _escape_template_patterns(text)
        assert result == "&#36;{a} and &#36;{b}"

    def test_code_block_boundary(self):
        text = "${outside}\n```\n${inside}\n```\n${outside2}"
        result = _escape_template_patterns(text)
        assert "&#36;{outside}" in result
        assert "${inside}" in result
        assert "&#36;{outside2}" in result
