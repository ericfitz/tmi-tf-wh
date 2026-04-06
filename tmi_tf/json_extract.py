# tmi_tf/json_extract.py
"""Shared JSON extraction utilities for LLM response parsing."""

import json
import re
from typing import Any


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Extract a JSON object from LLM response text.

    Tries three strategies in order:
    1. Direct json.loads()
    2. Extract from markdown code blocks
    3. Regex match for {...} in text
    """
    # Try parsing directly
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
        # Input is valid JSON but not an object (e.g. an array) — don't fall through
        return None
    except json.JSONDecodeError:
        pass

    # Try extracting from code block
    code_block_pattern = r"```(?:json)?\s*\n(.*?)\n```"
    matches = re.findall(code_block_pattern, text, re.DOTALL)
    for match in matches:
        try:
            result = json.loads(match)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            continue

    # Try finding JSON object in text
    json_pattern = r"\{[\s\S]*\}"
    matches = re.findall(json_pattern, text)
    for match in matches:
        try:
            result = json.loads(match)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            continue

    return None


def extract_json_array(text: str) -> list[dict[str, Any]] | None:
    """Extract a JSON array from LLM response text.

    Tries three strategies in order:
    1. Direct json.loads()
    2. Extract from markdown code blocks
    3. Regex match for [...] in text
    """
    # Try parsing directly
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Try extracting from code block
    code_block_pattern = r"```(?:json)?\s*\n(.*?)\n```"
    matches = re.findall(code_block_pattern, text, re.DOTALL)
    for match in matches:
        try:
            result = json.loads(match)
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            continue

    # Try finding JSON array in text
    json_match = re.search(r"\[[\s\S]*\]", text)
    if json_match:
        try:
            result = json.loads(json_match.group(0))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    return None
