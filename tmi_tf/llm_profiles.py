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
# Values shipped in examples and vault seeds; treated as "not set".
PLACEHOLDER_MARKERS = ("placeholder", "your_", "change_me")


class ProfileError(Exception):
    """A profile cannot be selected or used; the message is safe to show invokers."""


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
    """LLM_PROFILES_FILE, else llm-profiles.yaml at the project root."""
    return Path(
        os.environ.get("LLM_PROFILES_FILE")
        or Path(__file__).parent.parent / "llm-profiles.yaml"
    )


def _parse(name: str, raw: object) -> LLMProfile:
    if not NAME_RE.match(name):
        raise ValueError(f"invalid profile name {name!r}")
    if not isinstance(raw, dict):
        raise TypeError(f"profile {name}: must be a mapping")
    unknown = set(raw) - FIELDS
    if unknown:
        raise ValueError(
            f"profile {name}: unknown field(s) {', '.join(sorted(unknown))}"
        )
    for field in ("provider", "model", "auth"):
        if not isinstance(raw.get(field), str) or not raw[field]:
            raise ValueError(f"profile {name}: '{field}' is required")
    provider, auth = raw["provider"], raw["auth"]
    api = raw.get("api", "chat")
    if provider not in PROVIDERS:
        raise ValueError(
            f"profile {name}: provider must be one of {', '.join(PROVIDERS)}"
        )
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
        raise ValueError(
            f"profile {name}: auth api_key requires 'api_key' (env var name)"
        )
    if auth != "api_key" and key is not None:
        raise ValueError(f"profile {name}: 'api_key' is only valid with auth api_key")
    base_url = raw.get("base_url")
    if base_url is not None and not (isinstance(base_url, str) and base_url.strip()):
        raise ValueError(f"profile {name}: 'base_url' must be a non-empty string")
    return LLMProfile(name, provider, raw["model"], auth, key, api, base_url)


def load_profiles(path: Path) -> dict[str, LLMProfile]:
    """Parse and validate a profiles file; the ValueError names the file."""
    try:
        data = yaml.safe_load(path.read_text())
        profiles = data.get("profiles") if isinstance(data, dict) else None
        if not isinstance(profiles, dict) or not profiles:
            raise ValueError("top-level 'profiles' mapping is required")
        return {str(n): _parse(str(n), r) for n, r in profiles.items()}
    except (OSError, yaml.YAMLError, TypeError, ValueError) as e:
        raise ValueError(f"{path}: {e}") from e


def select_profile(
    profiles: dict[str, LLMProfile], requested: str | None, default: str | None
) -> LLMProfile:
    """The requested profile, else the default (LLM_PROFILE)."""
    name = (requested or default or "").strip()
    if not name:
        raise ProfileError("no LLM profile requested and LLM_PROFILE is not set")
    if name not in profiles:
        raise ProfileError(
            f'unknown LLM profile "{name[:64]}" '
            f"(available: {', '.join(sorted(profiles))})"
        )
    return profiles[name]


def resolve_key(profile: LLMProfile) -> str | None:
    """The profile's API key; None for cloud auth. Errors name the var, never the value."""
    if profile.auth != "api_key":
        return None
    value = os.environ.get(profile.api_key or "", "").strip()
    if not value or any(m in value.lower() for m in PLACEHOLDER_MARKERS):
        raise ProfileError(
            f'LLM profile "{profile.name}" needs {profile.api_key}, which is not set'
        )
    return value


def profile_status(profiles: dict[str, LLMProfile]) -> list[str]:
    """One line per profile: usable, or which key is missing."""
    lines = []
    for p in profiles.values():
        try:
            resolve_key(p)
            lines.append(f"LLM profile {p.name}: usable ({p.litellm_model})")
        except ProfileError:
            lines.append(f"LLM profile {p.name}: missing key {p.api_key}")
    return lines


def vault_secret_map(profiles: dict[str, LLMProfile]) -> dict[str, str]:
    """Vault secret name -> env var for every key the profiles reference."""
    return {
        p.api_key.lower().replace("_", "-"): p.api_key
        for p in profiles.values()
        if p.api_key
    }
