"""Tests for the CLI --profile option."""

from unittest.mock import MagicMock, patch

from click.testing import (  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
    CliRunner,
)

from tmi_tf.cli import cli
from tmi_tf.llm_profiles import LLMProfile


def _cfg():
    c = MagicMock(max_repos=3, llm_profile="test")
    c.llm_profiles = {
        "test": LLMProfile("test", "oci", "m", "oci"),
        "other": LLMProfile("other", "oci", "m", "oci"),
    }
    return c


def test_unknown_profile_exits_before_auth():
    with (
        patch("tmi_tf.cli.get_config", return_value=_cfg()),
        patch("tmi_tf.cli.TMIClient") as tc,
    ):
        r = CliRunner().invoke(cli, ["analyze", "tm", "--profile", "nope", "-e", "x"])
    assert r.exit_code == 1
    assert 'unknown LLM profile "nope"' in r.output
    tc.create_authenticated.assert_not_called()


def test_profile_passed_to_run_analysis():
    with (
        patch("tmi_tf.cli.get_config", return_value=_cfg()),
        patch("tmi_tf.cli.TMIClient"),
        patch("tmi_tf.cli.run_analysis", return_value=MagicMock(success=True)) as ra,
    ):
        CliRunner().invoke(cli, ["analyze", "tm", "--profile", "other", "-e", "x"])
    assert ra.call_args.kwargs["profile"].name == "other"


def test_default_profile_used_without_flag():
    with (
        patch("tmi_tf.cli.get_config", return_value=_cfg()),
        patch("tmi_tf.cli.TMIClient"),
        patch("tmi_tf.cli.run_analysis", return_value=MagicMock(success=True)) as ra,
    ):
        CliRunner().invoke(cli, ["analyze", "tm", "-e", "x"])
    assert ra.call_args.kwargs["profile"].name == "test"


def test_config_info_lists_profiles():
    with patch("tmi_tf.cli.get_config", return_value=_cfg()):
        r = CliRunner().invoke(cli, ["config-info"])
    assert "LLM Profile (default): test" in r.output
    assert "LLM profile other: usable (oci/m)" in r.output
