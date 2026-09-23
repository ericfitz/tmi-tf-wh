# LLM Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single `LLM_PROVIDER`/`LLM_MODEL`/`LLM_API_KEY` configuration with named LLM profiles selectable per invocation (`user_data.profile`) or per CLI run (`--profile`).

**Architecture:** A new `tmi_tf/llm_profiles.py` loads and validates `llm-profiles.yaml` into `LLMProfile` objects held on `Config`. `get_llm_provider(profile)` builds a provider that passes the key and base URL to every LiteLLM call. The worker resolves the profile on the parent job (fail fast, before cloning) and stamps its name on every child job.

**Tech Stack:** Python 3.10+, LiteLLM, pyyaml, Click, FastAPI, pytest, Terraform (AWS EKS, OCI).

**Spec:** `docs/superpowers/specs/2026-09-22-llm-profiles-design.md`

## Global Constraints

- Legacy `LLM_PROVIDER`, `LLM_MODEL`, `LLM_API_KEY` are removed everywhere (code, tests, Terraform, docs). `LLM_PROFILE` names the default profile.
- Profile fields: `provider` (anthropic|openai|xai|gemini|oci), `model`, `auth` (api_key|oci; aws|gcp|azure_ad → "not supported yet"), `api_key` (iff `auth: api_key`), `api` (chat default | responses, responses only with openai), `base_url` (optional → LiteLLM `api_base`).
- Profile names match `^[a-z0-9][a-z0-9_-]{0,63}$`.
- LiteLLM model string: `{provider}/{model}`, or `openai/responses/{model}` when `api: responses`.
- Key values are never written to `os.environ` and never logged or put in messages; only variable names are.
- Default file `llm-profiles.yaml` at repo root; override `LLM_PROFILES_FILE`. Containers copy it to `/opt/tmi-tf/llm-profiles.yaml` and set `LLM_PROFILES_FILE` to that path.
- OCI vault secret name for an `api_key` var: lower-case, `_` → `-`.
- Lint/type/test: `uv run ruff check tmi_tf/ tests/`, `uv run ruff format --check tmi_tf/ tests/`, `uv run pyright`, `uv run pytest tests/`.

## Review Focus

1. `user_data.profile` that is not a string (number, list, null) → ignored, default profile used (same as `environments`). Test in Task 4.
2. Profile name with surrounding whitespace (`" gpt56cyber "`) → trimmed and matched. Test in Task 4.
3. Profile key env var present but empty string → treated as missing, error names the var. Test in Task 1.
4. YAML file that is empty or whose top level lacks `profiles` → startup error naming the file. Test in Task 1.
5. Very long / hostile requested profile name → echoed truncated to 64 chars in the failure message. Test in Task 1.

---

### Task 1: Profile module, profile file, Config wiring

**Files:**
- Create: `tmi_tf/llm_profiles.py`, `llm-profiles.yaml`, `tests/test_llm_profiles.py`
- Modify: `tmi_tf/config.py` (remove LLM_PROVIDER/LLM_MODEL/LLM_API_KEY block; add profile fields), `pyproject.toml` (add `pyyaml>=6`), `tests/conftest.py` (add `LLM_PROFILE`, `LLM_PROFILES_FILE` to `_LEAKY_ENV_VARS`), `tests/test_config.py` (delete LLM_API_KEY-mapping tests; drop `LLM_PROVIDER` from remaining env dicts)

**Interfaces:**
- Produces:
  - `class ProfileError(Exception)`
  - `@dataclass(frozen=True) class LLMProfile: name: str; provider: str; model: str; auth: str; api_key: str | None = None; api: str = "chat"; base_url: str | None = None` with property `litellm_model -> str`
  - `load_profiles(path: Path) -> dict[str, LLMProfile]` (raises `ValueError`)
  - `select_profile(profiles: dict[str, LLMProfile], requested: str | None, default: str | None) -> LLMProfile` (raises `ProfileError`)
  - `resolve_key(profile: LLMProfile) -> str | None` (raises `ProfileError`)
  - `profile_status(profiles) -> list[str]` (one log line per profile: usable / missing key VAR)
  - `vault_secret_map(profiles) -> dict[str, str]` (`{"openai-cyber-api-key": "OPENAI_CYBER_API_KEY"}`)
  - `default_profiles_file() -> Path`
  - `Config.llm_profiles: dict[str, LLMProfile]`, `Config.llm_profile: str | None` (from `LLM_PROFILE`)

- [ ] **Step 1: Write failing tests** `tests/test_llm_profiles.py`:

```python
import os
from pathlib import Path
from unittest.mock import patch

import pytest  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.llm_profiles import (
    LLMProfile, ProfileError, load_profiles, profile_status, resolve_key,
    select_profile, vault_secret_map, default_profiles_file,
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

    @pytest.mark.parametrize("body,match", [
        ("", "profiles"),
        ("foo: 1", "profiles"),
        ("profiles: []", "profiles"),
        ("profiles:\n  x: {provider: openai, model: m, auth: api_key}", "api_key"),
        ("profiles:\n  x: {provider: oci, model: m, auth: oci, api_key: K}", "api_key"),
        ("profiles:\n  x: {provider: anthropic, model: m, auth: api_key, api_key: K, api: responses}", "responses"),
        ("profiles:\n  x: {provider: openai, model: m, auth: aws}", "not supported yet"),
        ("profiles:\n  x: {provider: openai, model: m, auth: magic}", "auth"),
        ("profiles:\n  x: {provider: nope, model: m, auth: oci}", "provider"),
        ("profiles:\n  x: {provider: openai, auth: api_key, api_key: K}", "model"),
        ("profiles:\n  x: {provider: openai, model: m, auth: api_key, api_key: K, colour: red}", "colour"),
        ("profiles:\n  Bad_Name: {provider: oci, model: m, auth: oci}", "Bad_Name"),
        ("profiles:\n  x: {provider: openai, model: m, auth: api_key, api_key: K, api: soap}", "api"),
        ("profiles: [unclosed", "p.yaml"),
    ])
    def test_rejects(self, tmp_path, body, match):
        with pytest.raises(ValueError, match=match):
            load_profiles(_write(tmp_path, body))

    def test_error_names_file(self, tmp_path):
        with pytest.raises(ValueError, match="p.yaml"):
            load_profiles(_write(tmp_path, "foo: 1"))


P = {"a": LLMProfile("a", "oci", "m", "oci"), "b": LLMProfile("b", "oci", "m", "oci")}


class TestSelect:
    def test_requested_wins(self):
        assert select_profile(P, "b", "a").name == "b"

    def test_default_used(self):
        assert select_profile(P, None, "a").name == "a"

    def test_none_configured(self):
        with pytest.raises(ProfileError, match="no LLM profile"):
            select_profile(P, None, None)

    def test_unknown_lists_available(self):
        with pytest.raises(ProfileError, match=r'unknown LLM profile "zz" \(available: a, b\)'):
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
            with pytest.raises(ProfileError, match='LLM profile "k" needs TEST_PROFILE_KEY, which is not set'):
                resolve_key(K)

    def test_oci_has_no_key(self):
        assert resolve_key(P["a"]) is None


def test_profile_status_never_prints_values():
    with patch.dict(os.environ, {"TEST_PROFILE_KEY": "sk-secret"}):
        lines = profile_status({"k": K, "a": P["a"]})
    assert not any("sk-secret" in line for line in lines)
    assert any("k" in line and "usable" in line for line in lines)


def test_vault_secret_map():
    assert vault_secret_map({"k": K, "a": P["a"]}) == {"test-profile-key": "TEST_PROFILE_KEY"}
```

- [ ] **Step 2: Run** `uv run pytest tests/test_llm_profiles.py -q` → FAIL (module missing).

- [ ] **Step 3: Implement** `tmi_tf/llm_profiles.py`:

```python
"""Named LLM profiles: provider, model, auth, and endpoint for LiteLLM."""

import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml  # pyright: ignore[reportMissingModuleSource]

PROVIDERS = ("anthropic", "openai", "xai", "gemini", "oci")
AUTHS = ("api_key", "oci")
FUTURE_AUTHS = ("aws", "gcp", "azure_ad")
APIS = ("chat", "responses")
FIELDS = {"provider", "model", "auth", "api_key", "api", "base_url"}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class ProfileError(Exception):
    """A profile cannot be selected or used; message is safe to show invokers."""


@dataclass(frozen=True)
class LLMProfile:
    name: str
    provider: str
    model: str
    auth: str
    api_key: str | None = None
    api: str = "chat"
    base_url: str | None = None

    @property
    def litellm_model(self) -> str:
        if self.api == "responses":
            return f"{self.provider}/responses/{self.model}"
        return f"{self.provider}/{self.model}"


def default_profiles_file() -> Path:
    return Path(
        os.environ.get("LLM_PROFILES_FILE")
        or Path(__file__).parent.parent / "llm-profiles.yaml"
    )


def _parse(name: str, raw: object) -> LLMProfile:
    if not NAME_RE.match(str(name)):
        raise ValueError(f"invalid profile name {name!r}")
    if not isinstance(raw, dict):
        raise ValueError(f"profile {name}: must be a mapping")
    unknown = set(raw) - FIELDS
    if unknown:
        raise ValueError(f"profile {name}: unknown field(s) {', '.join(sorted(unknown))}")
    for field in ("provider", "model", "auth"):
        if not isinstance(raw.get(field), str) or not raw[field]:
            raise ValueError(f"profile {name}: '{field}' is required")
    provider, auth = raw["provider"], raw["auth"]
    api = raw.get("api", "chat")
    if provider not in PROVIDERS:
        raise ValueError(f"profile {name}: provider must be one of {', '.join(PROVIDERS)}")
    if auth in FUTURE_AUTHS:
        raise ValueError(f"profile {name}: auth '{auth}' is not supported yet")
    if auth not in AUTHS:
        raise ValueError(f"profile {name}: auth must be one of {', '.join(AUTHS)}")
    if api not in APIS:
        raise ValueError(f"profile {name}: api must be one of {', '.join(APIS)}")
    if api == "responses" and provider != "openai":
        raise ValueError(f"profile {name}: api 'responses' requires provider openai")
    key = raw.get("api_key")
    if auth == "api_key" and not (isinstance(key, str) and key):
        raise ValueError(f"profile {name}: auth api_key requires 'api_key' (env var name)")
    if auth != "api_key" and key is not None:
        raise ValueError(f"profile {name}: 'api_key' is only valid with auth api_key")
    return LLMProfile(name, provider, raw["model"], auth, key, api, raw.get("base_url"))


def load_profiles(path: Path) -> dict[str, LLMProfile]:
    """Parse and validate a profiles file; ValueError names the file."""
    try:
        data = yaml.safe_load(path.read_text())
        profiles = data.get("profiles") if isinstance(data, dict) else None
        if not isinstance(profiles, dict) or not profiles:
            raise ValueError("top-level 'profiles' mapping is required")
        return {str(n): _parse(str(n), r) for n, r in profiles.items()}
    except (OSError, yaml.YAMLError, ValueError) as e:
        raise ValueError(f"{path}: {e}") from e


def select_profile(
    profiles: dict[str, LLMProfile], requested: str | None, default: str | None
) -> LLMProfile:
    name = requested or default
    if not name:
        raise ProfileError("no LLM profile requested and LLM_PROFILE is not set")
    if name not in profiles:
        raise ProfileError(
            f'unknown LLM profile "{name[:64]}" '
            f"(available: {', '.join(sorted(profiles))})"
        )
    return profiles[name]


def resolve_key(profile: LLMProfile) -> str | None:
    if profile.auth != "api_key":
        return None
    value = os.environ.get(profile.api_key or "")
    if not value or "placeholder" in value:
        raise ProfileError(
            f'LLM profile "{profile.name}" needs {profile.api_key}, which is not set'
        )
    return value


def profile_status(profiles: dict[str, LLMProfile]) -> list[str]:
    lines = []
    for p in profiles.values():
        try:
            resolve_key(p)
            lines.append(f"LLM profile {p.name}: usable ({p.litellm_model})")
        except ProfileError:
            lines.append(f"LLM profile {p.name}: missing key {p.api_key}")
    return lines


def vault_secret_map(profiles: dict[str, LLMProfile]) -> dict[str, str]:
    return {
        p.api_key.lower().replace("_", "-"): p.api_key
        for p in profiles.values()
        if p.api_key
    }
```

`llm-profiles.yaml` (repo root):

```yaml
# Named LLM profiles. Select per invocation with user_data {"profile": "<name>"},
# per CLI run with --profile, or by default with LLM_PROFILE.
# api_key names the env var / secret holding the key (never the key itself).
profiles:
  gpt56cyber:
    provider: openai
    model: gpt-5.6-cyber
    api: responses
    auth: api_key
    api_key: OPENAI_CYBER_API_KEY
  mythos5:
    provider: anthropic
    model: claude-mythos-5
    auth: api_key
    api_key: ANTHROPIC_API_KEY
  fable5:
    provider: anthropic
    model: claude-fable-5
    auth: api_key
    api_key: ANTHROPIC_API_KEY
  opus48:
    provider: anthropic
    model: claude-opus-4-8
    auth: api_key
    api_key: ANTHROPIC_API_KEY
```

`config.py`: replace the "LLM Provider Configuration" block (lines ~62-78) with:

```python
        # LLM profiles (see llm-profiles.yaml); LLM_PROFILE is the default name
        self.llm_profile: str | None = os.getenv("LLM_PROFILE") or None
        self.llm_profiles: dict[str, LLMProfile] = load_profiles(
            default_profiles_file()
        )
```

(import `LLMProfile, default_profiles_file, load_profiles` from `tmi_tf.llm_profiles`), and in `__repr__` replace provider/model with `llm_profile={self.llm_profile}`.

- [ ] **Step 4: Update** `tests/test_config.py` (delete the `LLM_API_KEY` mapping tests; remove `"LLM_PROVIDER": ...` entries from remaining env dicts) and `tests/conftest.py` `_LEAKY_ENV_VARS` (+`LLM_PROFILE`, `LLM_PROFILES_FILE`). Add `pyyaml>=6` to `pyproject.toml` dependencies; `uv sync`.

- [ ] **Step 5: Run** `uv run pytest tests/test_llm_profiles.py tests/test_config.py -q` → PASS.

- [ ] **Step 6: Commit** `feat: LLM profile loader and profiles file`.

### Task 2: Providers built from a profile

**Files:**
- Modify: `tmi_tf/providers/__init__.py` (`LLMProvider.profile` property; `get_llm_provider(profile)`; drop `"llm-api-key"` from `VAULT_SECRET_MAP`), `tmi_tf/providers/llm_base.py` (`profile` arg/property), `tmi_tf/providers/api_key.py` (rewrite), `tmi_tf/providers/oci.py` (`OciLLMProvider(profile)`, delete `OCI_DEFAULT_MODEL`)
- Test: `tests/test_llm_provider.py`, `tests/test_oci_llm_provider.py`, `tests/test_providers.py`

**Interfaces:**
- Consumes: `LLMProfile`, `resolve_key` (Task 1)
- Produces: `get_llm_provider(profile: LLMProfile) -> LLMProvider`; `LLMProvider.profile -> str`; `BaseLLMProvider(provider, model, profile="")`.

- [ ] **Step 1: Failing tests.** Replace `TestApiKeyLLMProvider`/`TestGetLLMProvider` in `tests/test_llm_provider.py`:

```python
from tmi_tf.llm_profiles import LLMProfile, ProfileError
from tmi_tf.providers import get_llm_provider
from tmi_tf.providers.api_key import ApiKeyLLMProvider

CYBER = LLMProfile("gpt56cyber", "openai", "gpt-5.6-cyber", "api_key", "T_CYBER_KEY", "responses")
PROXIED = LLMProfile("px", "anthropic", "claude-opus-4-8", "api_key", "T_PX_KEY", base_url="https://proxy/v1")


class TestApiKeyLLMProvider:
    @patch.dict(os.environ, {"T_CYBER_KEY": "sk-c"})
    def test_model_and_key_per_call(self):
        before = dict(os.environ)
        p = ApiKeyLLMProvider(CYBER)
        assert p.model == "openai/responses/gpt-5.6-cyber"
        assert p.provider == "openai"
        assert p.profile == "gpt56cyber"
        assert p._extra_kwargs == {"api_key": "sk-c"}
        assert dict(os.environ) == before

    @patch.dict(os.environ, {"T_PX_KEY": "sk-p"})
    def test_base_url_becomes_api_base(self):
        assert ApiKeyLLMProvider(PROXIED)._extra_kwargs == {"api_key": "sk-p", "api_base": "https://proxy/v1"}

    def test_missing_key_raises(self):
        os.environ.pop("T_CYBER_KEY", None)
        with pytest.raises(ProfileError, match="T_CYBER_KEY"):
            ApiKeyLLMProvider(CYBER)

    @patch.dict(os.environ, {"T_PX_KEY": "sk-p"})
    def test_complete_passes_key_to_litellm(self):
        with patch("tmi_tf.providers.llm_base.litellm") as ll:
            ll.completion.return_value = iter([])
            ll.stream_chunk_builder.return_value = None
            try:
                ApiKeyLLMProvider(PROXIED).complete("s", "u")
            except Exception:
                pass
            kw = ll.completion.call_args.kwargs
        assert kw["api_key"] == "sk-p" and kw["api_base"] == "https://proxy/v1"
        assert kw["model"] == "anthropic/claude-opus-4-8"


class TestGetLLMProvider:
    @patch.dict(os.environ, {"T_CYBER_KEY": "sk-c"})
    def test_api_key_profile(self):
        assert isinstance(get_llm_provider(CYBER), ApiKeyLLMProvider)

    @patch.dict(os.environ, {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"})
    def test_oci_profile(self):
        with patch("pathlib.Path.exists", return_value=False), patch(
            "oci.auth.signers.get_resource_principals_signer", return_value=MagicMock(region="r")
        ):
            p = get_llm_provider(LLMProfile("g", "oci", "xai.grok-4", "oci"))
        assert p.model == "oci/xai.grok-4" and p.profile == "g"
```

In `tests/test_oci_llm_provider.py` replace `OciLLMProvider(model=None)` / `OciLLMProvider(model="xai.grok-4")` with `OciLLMProvider(OCI)` where `OCI = LLMProfile("g", "oci", "xai.grok-4", "oci")`, and fix any default-model assertion to `"oci/xai.grok-4"`. In `tests/test_providers.py` drop `llm-api-key` from the expected `VAULT_SECRET_MAP` set/assertions and use `{"github-token": "GITHUB_TOKEN"}` in the `load_secrets` error test.

- [ ] **Step 2: Run** `uv run pytest tests/test_llm_provider.py tests/test_oci_llm_provider.py tests/test_providers.py -q` → FAIL.

- [ ] **Step 3: Implement.**

`llm_base.py`: `def __init__(self, provider: str, model: str, profile: str = "")`, store `self._profile`, add `profile` property.

`api_key.py`:

```python
"""API-key LLM provider: key and base URL come from the selected profile."""

import logging

from tmi_tf.llm_profiles import LLMProfile, resolve_key
from tmi_tf.providers.llm_base import BaseLLMProvider

logger = logging.getLogger(__name__)


class ApiKeyLLMProvider(BaseLLMProvider):
    """Passes the profile's key (and base URL) to every LiteLLM call."""

    def __init__(self, profile: LLMProfile) -> None:
        super().__init__(profile.provider, profile.litellm_model, profile.name)
        self._extra_kwargs = {"api_key": resolve_key(profile)}
        if profile.base_url:
            self._extra_kwargs["api_base"] = profile.base_url
        logger.info("LLM profile %s: model=%s", profile.name, self.model)
```

`oci.py`: `OciLLMProvider.__init__(self, profile: LLMProfile)`; `super().__init__(provider="oci", model=profile.litellm_model, profile=profile.name)`; delete model-defaulting and `OCI_DEFAULT_MODEL`; error text `"OCI_COMPARTMENT_ID required for auth oci."`.

`providers/__init__.py`: add `profile` property to `LLMProvider`; remove `"llm-api-key"` from `VAULT_SECRET_MAP`; replace `get_llm_provider`:

```python
def get_llm_provider(profile: "LLMProfile") -> LLMProvider:
    """Create an LLMProvider for a validated profile."""
    if profile.auth == "oci":
        from tmi_tf.providers.oci import OciLLMProvider

        return OciLLMProvider(profile)
    from tmi_tf.providers.api_key import ApiKeyLLMProvider

    return ApiKeyLLMProvider(profile)
```

(`from tmi_tf.llm_profiles import LLMProfile` under `TYPE_CHECKING`).

- [ ] **Step 4: Run** the Step 2 command → PASS.
- [ ] **Step 5: Commit** `feat: build LLM providers from profiles`.

### Task 3: run_analysis takes a profile; metadata and status

**Files:**
- Modify: `tmi_tf/analyzer.py` (`run_analysis(..., profile: LLMProfile, ...)`), `tmi_tf/artifact_metadata.py` (`llm_profile` field + `llm-profile` key; `profile: str = ""` param on both factories)
- Test: `tests/test_analyzer.py`, add metadata test to `tests/test_analyzer.py` or a new `tests/test_artifact_metadata.py`

**Interfaces:**
- Consumes: `get_llm_provider(profile)`, `LLMProvider.profile`
- Produces: `run_analysis(config, threat_model_id, tmi_client, profile, repo_id=None, ...)` — `profile: LLMProfile` is the 4th parameter (all callers pass by keyword).

- [ ] **Step 1: Failing tests.**

```python
# tests/test_artifact_metadata.py
from tmi_tf.artifact_metadata import aggregate_analysis_metadata, create_artifact_metadata


def test_profile_key_emitted():
    md = create_artifact_metadata(provider="openai", model="m", profile="gpt56cyber")
    assert {"key": "llm-profile", "value": "gpt56cyber"} in md.to_metadata_list()


def test_aggregate_carries_profile():
    assert aggregate_analysis_metadata([], "openai", "m", profile="p").llm_profile == "p"
```

In `tests/test_analyzer.py`, every `run_analysis(...)` call gains `profile=LLMProfile("t", "oci", "m", "oci")`; add one assertion in the first run test that `get_llm_provider` was called with that profile (`mock_get.assert_called_once_with(profile)`).

- [ ] **Step 2: Run** `uv run pytest tests/test_artifact_metadata.py tests/test_analyzer.py -q` → FAIL.

- [ ] **Step 3: Implement.** `ArtifactMetadata.llm_profile: str = ""`; list entry `{"key": "llm-profile", "value": self.llm_profile}` after `llm-model`; `create_artifact_metadata(..., profile: str = "")` and `aggregate_analysis_metadata(analyses, provider, model, profile: str = "")` set it. In `analyzer.py`: add `profile: LLMProfile` parameter after `tmi_client`; `llm_provider = get_llm_provider(profile)`; the first status update becomes `f"Analysis started (profile {profile.name}, {llm_provider.model})"`; pass `profile=llm_provider.profile` to the three metadata factory calls. Update the docstring `Args`.

- [ ] **Step 4: Run** Step 2 command → PASS.
- [ ] **Step 5: Commit** `feat: record LLM profile on artifacts`.

### Task 4: Invocation plumbing (webhook → job → worker)

**Files:**
- Modify: `tmi_tf/webhook_handler.py`, `tmi_tf/job.py`, `tmi_tf/server.py` (Job construction), `tmi_tf/worker.py` (`_run_parent`, child branch of `_run_job`)
- Test: `tests/test_webhook_handler.py`, `tests/test_job.py`, `tests/test_worker.py`

**Interfaces:**
- Consumes: `select_profile`, `resolve_key`, `ProfileError`, `Config.llm_profiles`, `Config.llm_profile`, `run_analysis(..., profile=...)`
- Produces: `parse_webhook_payload` result key `"profile"`; `Job.profile: str | None`.

- [ ] **Step 1: Failing tests.**

```python
# tests/test_webhook_handler.py
@pytest.mark.parametrize("raw,expected", [
    (" gpt56cyber ", "gpt56cyber"), ("", None), ("   ", None), (5, None), (["a"], None), (None, None),
])
def test_user_data_profile(raw, expected):
    payload = {"threat_model_id": "tm", "data": {"user_data": {"environments": "aws", "profile": raw}}}
    assert parse_webhook_payload(payload).get("profile") == expected

# tests/test_job.py
def test_profile_round_trips():
    j = Job(job_id="j", threat_model_id="t", event_type="e",
            enqueued_at=datetime.now(timezone.utc), profile="opus48")
    assert Job.from_queue_message(j.to_queue_message()).profile == "opus48"
```

In `tests/test_worker.py`: `_pool()` sets `config.llm_profiles = {"test": LLMProfile("test", "oci", "m", "oci"), "other": LLMProfile("other", "oci", "m2", "oci")}` and `config.llm_profile = "test"`. Add:

```python
class TestProfiles:
    def _run_parent(self, job):
        pool, queue = _pool()
        targets = [FanoutTarget("r1", "u", "aws-public")]
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=targets) as rft,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
            patch("tmi_tf.worker.open_invocation"),
            patch("tmi_tf.worker.mark_child"),
        ):
            asyncio.run(pool._run_job(job, receipt="rc"))
        return queue, rft, cb_cls.return_value

    def test_children_inherit_requested_profile(self):
        queue, _, _ = self._run_parent(_job(profile="other"))
        msgs = queue.consume(max_messages=10)
        assert [m.body["profile"] for m in msgs] == ["other"]

    def test_children_get_default_when_none_requested(self):
        queue, _, _ = self._run_parent(_job())
        assert queue.consume(max_messages=10)[0].body["profile"] == "test"

    def test_unknown_profile_fails_before_fanout(self):
        queue, rft, cb = self._run_parent(_job(profile="nope"))
        rft.assert_not_called()
        assert queue.consume(max_messages=10) == []
        cb.send_status.assert_any_call("failed", 'unknown LLM profile "nope" (available: other, test)')

    def test_child_passes_profile_to_run_analysis(self):
        pool, _ = _pool()
        child = _child("p1:aws-public", ["p1:aws-public"], profile="other")
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.run_analysis", return_value=MagicMock(success=True)) as ra,
            patch("tmi_tf.worker.AddonCallback"),
            patch.object(pool, "_finish_child", new=AsyncMock()),
        ):
            asyncio.run(pool._run_job(child, receipt="rc"))
        assert ra.call_args.kwargs["profile"].name == "other"
```

(Use whatever `MemoryQueueProvider` read method the existing fan-out tests use to inspect enqueued children, if it differs from `consume`.)

- [ ] **Step 2: Run** `uv run pytest tests/test_webhook_handler.py tests/test_job.py tests/test_worker.py -q` → FAIL.

- [ ] **Step 3: Implement.**

`webhook_handler.py` after the scope block:

```python
    profile = user_data.get("profile") if isinstance(user_data, dict) else None
    if isinstance(profile, str) and profile.strip():
        result["profile"] = profile.strip()
```

`job.py`: field `profile: str | None = None`; add `"profile": self.profile` to `to_queue_message` and `profile=data.get("profile")` to `from_queue_message`. `server.py`: `profile=parsed.get("profile")` in the `Job(...)`.

`worker.py` `_run_parent`, first lines:

```python
        try:
            profile = select_profile(
                self.config.llm_profiles, job.profile, self.config.llm_profile
            )
            resolve_key(profile)
        except ProfileError as e:
            logger.error("Parent job %s: %s", job.job_id, e)
            if callback:
                callback.send_status("failed", str(e))
            return
```

and `profile=profile.name` in each child `Job(...)`. Child branch of `_run_job`, before `run_analysis`:

```python
                profile = select_profile(
                    self.config.llm_profiles, job.profile, self.config.llm_profile
                )
```

and pass `profile=profile` to `run_analysis`. (A `ProfileError` there falls into the existing `except Exception` → `_finish_child(job, "failed")`.)

- [ ] **Step 4: Run** Step 2 command, then `uv run pytest tests/ -q` → PASS.
- [ ] **Step 5: Commit** `feat: select LLM profile per invocation`.

### Task 5: CLI `--profile` and server startup

**Files:**
- Modify: `tmi_tf/cli.py` (`analyze --profile`, `config_info`), `tmi_tf/server.py` (lifespan: secret map + status log)
- Test: `tests/test_cli_environment.py` (or new `tests/test_cli_profile.py`), `tests/test_server.py`

**Interfaces:**
- Consumes: `select_profile`, `resolve_key`, `ProfileError`, `profile_status`, `vault_secret_map`, `VAULT_SECRET_MAP`.

- [ ] **Step 1: Failing tests.**

```python
# tests/test_cli_profile.py
from unittest.mock import MagicMock, patch

from click.testing import CliRunner  # pyright: ignore[reportMissingImports]

from tmi_tf.cli import cli
from tmi_tf.llm_profiles import LLMProfile


def _cfg():
    c = MagicMock(max_repos=3, llm_profile="test")
    c.llm_profiles = {"test": LLMProfile("test", "oci", "m", "oci"), "other": LLMProfile("other", "oci", "m", "oci")}
    return c


def test_unknown_profile_exits_before_auth():
    with patch("tmi_tf.cli.get_config", return_value=_cfg()), patch("tmi_tf.cli.TMIClient") as tc:
        r = CliRunner().invoke(cli, ["analyze", "tm", "--profile", "nope", "-e", "x"])
    assert r.exit_code != 0
    assert "unknown LLM profile" in r.output
    tc.create_authenticated.assert_not_called()


def test_profile_passed_to_run_analysis():
    with (
        patch("tmi_tf.cli.get_config", return_value=_cfg()),
        patch("tmi_tf.cli.TMIClient"),
        patch("tmi_tf.cli.run_analysis", return_value=MagicMock(success=True)) as ra,
    ):
        CliRunner().invoke(cli, ["analyze", "tm", "--profile", "other", "-e", "x"])
    assert ra.call_args.kwargs["profile"].name == "other"
```

```python
# tests/test_server.py (new test)
def test_lifespan_loads_profile_secrets(monkeypatch):
    # get_secret_provider returns a mock; assert load_secrets got the base map
    # plus the profile-derived entries, e.g. "openai-cyber-api-key".
```

Implement the server test using the same lifespan harness `tests/test_server.py` already uses; assert `provider.load_secrets.call_args.args[0]` contains `"openai-cyber-api-key": "OPENAI_CYBER_API_KEY"` and `"github-token": "GITHUB_TOKEN"`.

- [ ] **Step 2: Run** `uv run pytest tests/test_cli_profile.py tests/test_server.py -q` → FAIL.

- [ ] **Step 3: Implement.**

`cli.py` `analyze`: add option

```python
@click.option(
    "--profile",
    "-p",
    type=str,
    default=None,
    help="LLM profile from llm-profiles.yaml (default: LLM_PROFILE)",
)
```

Right after `config = get_config()` (before `TMIClient.create_authenticated`):

```python
        try:
            llm_profile = select_profile(config.llm_profiles, profile, config.llm_profile)
            resolve_key(llm_profile)
        except ProfileError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
```

and `profile=llm_profile` in the `run_analysis(...)` call. Make sure the existing outer `except Exception` does not swallow `SystemExit` (it doesn't; `SystemExit` is not an `Exception`). `config_info`: replace the two LLM lines with `print(f"LLM Profile (default): {config.llm_profile or '(none)'}")` followed by `for line in profile_status(config.llm_profiles): print(line)`.

`server.py` lifespan:

```python
    provider = get_secret_provider(config)
    provider.load_secrets({**VAULT_SECRET_MAP, **vault_secret_map(config.llm_profiles)})
    ...
    for line in profile_status(config.llm_profiles):
        logger.info(line)
```

(status logged after the optional config reload).

- [ ] **Step 4: Run** Step 2 command, then full suite → PASS.
- [ ] **Step 5: Commit** `feat: --profile CLI option and profile secrets at startup`.

### Task 6: Containers, Terraform, docs

**Files:**
- Modify: all `deploy/docker/Dockerfile.*` (after each `COPY prompts/ ...` / `ENV PROMPTS_DIR=...` pair add `COPY llm-profiles.yaml /opt/tmi-tf/llm-profiles.yaml` and `ENV LLM_PROFILES_FILE=/opt/tmi-tf/llm-profiles.yaml`)
- Modify: `infra/aws/variables.tf`, `infra/aws/k8s.tf`, `infra/aws/terraform.tfvars.example`, `infra/aws/README.md`, `infra/aws/terraform.tfvars` (untracked-if-ignored; check `git check-ignore`), `infra/oci/variables.tf`, `infra/oci/k8s.tf`, `infra/oci/vault.tf`, `infra/oci/terraform.tfvars.example`, `.env.example`, `README.md`, `.claude/CLAUDE.md`
- Modify (outside repo): `~/Scripts/tmi-tf-wh/write-secrets.sh` → emits `llm_api_keys = { NAME = "..." ... }`; usage `write-secrets.sh [-g GH_FILE] FILE[:VAR][=SECRET_NAME]...` (SECRET_NAME defaults to FILE).

- [ ] **Step 1: AWS Terraform.** `variables.tf`: delete `llm_provider`, `llm_model`, `llm_api_key`; add

```hcl
variable "llm_profile" {
  description = "Default LLM profile name (LLM_PROFILE); see llm-profiles.yaml"
  type        = string
  default     = "gpt56cyber"
}

variable "llm_profiles_yaml" {
  description = "Optional llm-profiles.yaml content overriding the image's file (mounted from a ConfigMap)"
  type        = string
  default     = ""
}

variable "llm_api_keys" {
  description = "LLM API keys keyed by the env var name profiles reference (e.g. OPENAI_CYBER_API_KEY)"
  type        = map(string)
  sensitive   = true
  default     = {}
}
```

`k8s.tf`: secret `data = merge({ WEBHOOK_SECRET = ..., TMI_CLIENT_ID = ..., TMI_CLIENT_SECRET = ..., GITHUB_TOKEN = ... }, var.llm_api_keys)`; replace the `LLM_PROVIDER`/`LLM_MODEL` env blocks with `LLM_PROFILE = var.llm_profile`; add

```hcl
resource "kubernetes_config_map_v1" "llm_profiles" {
  count = var.llm_profiles_yaml == "" ? 0 : 1
  metadata {
    name      = "${var.app_name}-llm-profiles"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }
  data = { "llm-profiles.yaml" = var.llm_profiles_yaml }
}
```

and in the container: a `dynamic "env"` for `LLM_PROFILES_FILE=/etc/tmi-tf/llm-profiles.yaml`, a `dynamic "volume_mount"` (`/etc/tmi-tf`, read-only), and in the pod spec a `dynamic "volume"` with `config_map { name = ... }`, each `for_each = var.llm_profiles_yaml == "" ? [] : [1]`. Keep `infra/aws/terraform.tfvars` at `llm_profile = "gpt56cyber"` (remove `llm_provider`/`llm_model`).

- [ ] **Step 2: OCI Terraform.** Replace `llm_provider` var/env with `llm_profile`/`LLM_PROFILE`; replace the single `oci_vault_secret.llm_api_key` with `for_each = var.llm_api_keys` naming each secret `lower(replace(each.key, "_", "-"))`; update `terraform.tfvars.example`.

- [ ] **Step 3: Validate.** `cd infra/aws && terraform fmt -check && terraform validate`; same for `infra/oci` (`terraform init -backend=false` first if needed). Do not plan/apply.

- [ ] **Step 4: Docs.** `.env.example`: remove the LLM_PROVIDER/LLM_MODEL/LLM_API_KEY lines; add `LLM_PROFILE=gpt56cyber`, `# LLM_PROFILES_FILE=/path/to/llm-profiles.yaml`, and per-key examples (`OPENAI_CYBER_API_KEY=`, `ANTHROPIC_API_KEY=`). `README.md` config table: replace LLM rows with `LLM_PROFILE`, `LLM_PROFILES_FILE`, "keys named by profiles"; add a short "LLM profiles" section (file format table from the spec, `user_data` example `{"environments": "aws", "profile": "gpt56cyber"}`, `--profile`). `.claude/CLAUDE.md` "LLM providers" section: profiles replace `LLM_PROVIDER`. `infra/aws/README.md` + `terraform.tfvars.example`: `llm_api_keys` map and `llm_profile`.

- [ ] **Step 5: Helper script** `~/Scripts/tmi-tf-wh/write-secrets.sh` (back it up first, delete backup after `bash -n` passes): accept multiple `FILE[:VAR][=SECRET_NAME]` args, emit

```hcl
llm_api_keys = {
  OPENAI_CYBER_API_KEY = "..."
  ANTHROPIC_API_KEY    = "..."
}
```

Never echo values.

- [ ] **Step 6: Build image locally** `docker build -f deploy/docker/Dockerfile.aws -t tmi-tf-wh:profiles .` and `docker run --rm tmi-tf-wh:profiles python -c "from tmi_tf.config import Config; print(sorted(Config(env_file=None).llm_profiles))"` → prints profile names. (Skip only if Docker is unavailable; say so.)

- [ ] **Step 7: Commit** `feat: deploy LLM profiles (containers, Terraform, docs)`.

### Task 7: Final verification

- [ ] `uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q` → all clean.
- [ ] `rg -n 'LLM_API_KEY|LLM_MODEL\b|LLM_PROVIDER|llm_api_key\b|llm_model\b|DEFAULT_MODELS|OCI_DEFAULT_MODEL' --glob '!docs/superpowers/**' --glob '!PROGRESS.md' .` → no hits outside historical docs.
- [ ] Whole-branch review (Fable, high effort), fix findings, push branch, open PR.
