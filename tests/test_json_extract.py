# tests/test_json_extract.py
"""Tests for JSON extraction utility."""

from tmi_tf.json_extract import extract_json_object, extract_json_array


class TestExtractJsonObject:
    def test_parses_plain_json(self):
        text = '{"key": "value", "count": 42}'
        result = extract_json_object(text)
        assert result == {"key": "value", "count": 42}

    def test_extracts_from_code_block(self):
        text = 'Here is the result:\n```json\n{"key": "value"}\n```\nDone.'
        result = extract_json_object(text)
        assert result == {"key": "value"}

    def test_extracts_from_code_block_without_json_tag(self):
        text = 'Result:\n```\n{"key": "value"}\n```'
        result = extract_json_object(text)
        assert result == {"key": "value"}

    def test_extracts_embedded_json_object(self):
        text = 'The analysis found: {"components": [1, 2]} in the data.'
        result = extract_json_object(text)
        assert result == {"components": [1, 2]}

    def test_returns_none_for_no_json(self):
        result = extract_json_object("no json here")
        assert result is None

    def test_returns_none_for_json_array(self):
        result = extract_json_object('[{"key": "value"}]')
        assert result is None

    def test_returns_none_for_invalid_json(self):
        result = extract_json_object('{"key": broken}')
        assert result is None


class TestExtractJsonArray:
    def test_parses_plain_json_array(self):
        text = '[{"name": "threat1"}, {"name": "threat2"}]'
        result = extract_json_array(text)
        assert result == [{"name": "threat1"}, {"name": "threat2"}]

    def test_extracts_from_code_block(self):
        text = 'Threats:\n```json\n[{"name": "t1"}]\n```'
        result = extract_json_array(text)
        assert result == [{"name": "t1"}]

    def test_extracts_embedded_json_array(self):
        text = 'Found these: [{"id": 1}] in the response.'
        result = extract_json_array(text)
        assert result == [{"id": 1}]

    def test_returns_none_for_no_json(self):
        result = extract_json_array("no json here")
        assert result is None

    def test_returns_none_for_json_object(self):
        result = extract_json_array('{"key": "value"}')
        assert result is None

    def test_returns_empty_list(self):
        result = extract_json_array("[]")
        assert result == []
