"""Tests for named LLM profiles."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.llm_profiles import (
    LLMProfile,
    ProfileError,
    default_profiles_file,
    load_profiles,
    profile_status,
    resolve_key,
    select_profile,
    vault_secret_map,
)


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "p.yaml"
    p.write_text(text)
    return p


GOOD = """
profiles:
  gpt56cyber: {provider: openai, model: gpt-5.6-cyber, api: responses, auth: api_key, api_key: OPENAI_CYBER_API_KEY}
  opus48: {provider: anthropic, model: claude-opus-4-8, auth: api_key, api_key: ANTHROPIC_API_KEY, base_url: "https://proxy/v1"}
  grok-oci: {provider: oci, model: xai.grok-4, auth: oci}
"""


class TestLoad:
    def test_loads_good_file(self, tmp_path):
        ps = load_profiles(_write(tmp_path, GOOD))
        assert set(ps) == {"gpt56cyber", "opus48", "grok-oci"}
        assert ps["gpt56cyber"].litellm_model == "openai/responses/gpt-5.6-cyber"
        assert ps["opus48"].litellm_model == "anthropic/claude-opus-4-8"
        assert ps["opus48"].base_url == "https://proxy/v1"
        assert ps["grok-oci"].litellm_model == "oci/xai.grok-4"
        assert ps["grok-oci"].api_key is None

    def test_repo_file_is_valid(self):
        assert load_profiles(default_profiles_file())

    @patch.dict(os.environ, {"LLM_PROFILES_FILE": "/elsewhere/p.yaml"})
    def test_file_override(self):
        assert default_profiles_file() == Path("/elsewhere/p.yaml")

    @pytest.mark.parametrize(
        "body,match",
        [
            ("", "profiles"),
            ("foo: 1", "profiles"),
            ("profiles: []", "profiles"),
            ("profiles:\n  x: {provider: openai, model: m, auth: api_key}", "api_key"),
            (
                "profiles:\n  x: {provider: oci, model: m, auth: oci, api_key: K}",
                "api_key",
            ),
            (
                (
                    "profiles:\n  x: {provider: anthropic, model: m, auth: api_key,"
                    " api_key: K, api: responses}"
                ),
                "responses",
            ),
            (
                "profiles:\n  x: {provider: openai, model: m, auth: aws}",
                "not supported yet",
            ),
            ("profiles:\n  x: {provider: openai, model: m, auth: magic}", "auth"),
            ("profiles:\n  x: {provider: nope, model: m, auth: oci}", "provider"),
            (
                "profiles:\n  x: {provider: openai, auth: api_key, api_key: K}",
                "model",
            ),
            (
                (
                    "profiles:\n  x: {provider: openai, model: m, auth: api_key,"
                    " api_key: K, colour: red}"
                ),
                "colour",
            ),
            ("profiles:\n  Bad_Name: {provider: oci, model: m, auth: oci}", "Bad_Name"),
            (
                (
                    "profiles:\n  x: {provider: openai, model: m, auth: api_key,"
                    " api_key: K, api: soap}"
                ),
                "api",
            ),
            ("profiles:\n  x: [1, 2]", "mapping"),
            ("profiles: [unclosed", "p.yaml"),
        ],
    )
    def test_rejects(self, tmp_path, body, match):
        with pytest.raises(ValueError, match=match):
            load_profiles(_write(tmp_path, body))

    def test_error_names_file(self, tmp_path):
        with pytest.raises(ValueError, match="p.yaml"):
            load_profiles(_write(tmp_path, "foo: 1"))

    def test_missing_file_names_file(self, tmp_path):
        with pytest.raises(ValueError, match="nope.yaml"):
            load_profiles(tmp_path / "nope.yaml")


P = {
    "a": LLMProfile("a", "oci", "m", "oci"),
    "b": LLMProfile("b", "oci", "m", "oci"),
}


class TestSelect:
    def test_requested_wins(self):
        assert select_profile(P, "b", "a").name == "b"

    def test_default_used(self):
        assert select_profile(P, None, "a").name == "a"

    def test_none_configured(self):
        with pytest.raises(ProfileError, match="no LLM profile"):
            select_profile(P, None, None)

    def test_unknown_lists_available(self):
        with pytest.raises(
            ProfileError, match=r'unknown LLM profile "zz" \(available: a, b\)'
        ):
            select_profile(P, "zz", "a")

    def test_unknown_name_truncated(self):
        with pytest.raises(ProfileError) as e:
            select_profile(P, "x" * 500, None)
        assert "x" * 65 not in str(e.value)


K = LLMProfile("k", "anthropic", "m", "api_key", api_key="TEST_PROFILE_KEY")


class TestResolveKey:
    def test_returns_value(self):
        with patch.dict(os.environ, {"TEST_PROFILE_KEY": "sk-1"}):
            assert resolve_key(K) == "sk-1"

    @pytest.mark.parametrize("val", [None, "", "placeholder"])
    def test_missing_empty_placeholder(self, val):
        env = {} if val is None else {"TEST_PROFILE_KEY": val}
        with patch.dict(os.environ, env):
            if val is None:
                os.environ.pop("TEST_PROFILE_KEY", None)
            with pytest.raises(
                ProfileError,
                match='LLM profile "k" needs TEST_PROFILE_KEY, which is not set',
            ):
                resolve_key(K)

    def test_oci_has_no_key(self):
        assert resolve_key(P["a"]) is None


def test_profile_status_never_prints_values():
    with patch.dict(os.environ, {"TEST_PROFILE_KEY": "sk-secret"}):
        lines = profile_status({"k": K, "a": P["a"]})
    assert not any("sk-secret" in line for line in lines)
    assert any("k" in line and "usable" in line for line in lines)


def test_profile_status_reports_missing_key():
    os.environ.pop("TEST_PROFILE_KEY", None)
    assert profile_status({"k": K}) == ["LLM profile k: missing key TEST_PROFILE_KEY"]


def test_vault_secret_map():
    assert vault_secret_map({"k": K, "a": P["a"]}) == {
        "test-profile-key": "TEST_PROFILE_KEY"
    }
