"""Offline tests for scripts/addon-profile-param.py (addon `profile` enum sync)."""

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parent.parent
spec = importlib.util.spec_from_file_location(
    "addon_profile_param", ROOT / "scripts" / "addon-profile-param.py"
)
app = importlib.util.module_from_spec(spec)  # pyright: ignore[reportArgumentType]
spec.loader.exec_module(app)  # type: ignore[union-attr]
SyncError = app.SyncError

# Recorded from GET /addons/fed11e3a-... on api.tmi.dev, 2026-11-21.
RECORDED_ADDON = {
    "created_at": "2026-09-14T02:09:35.73082Z",
    "description": "Terraform threat-model webhook: per-environment fan-out",
    "id": "fed11e3a-778c-4eb3-a003-b00737e7c8ca",
    "name": "tmi-tf-wh",
    "objects": ["repository"],
    "parameters": [
        {
            "default_value": "latest",
            "description": "latest (default) | all | comma-separated environment names or globs, e.g. aws-*,oci-public",
            "name": "environments",
            "required": False,
            "type": "string",
        }
    ],
    "webhook_id": "25603436-803a-43e0-8f17-d7d10d508206",
}

PROFILES_YAML = """profiles:
  claude-fable-5-2: {provider: anthropic, model: claude-fable-5-2, auth: api_key, api_key: K}
  gpt-6_2-astra: {provider: openai, model: gpt-6.2-astra, api: responses, auth: api_key, api_key: O}
"""


class FakeResponse:
    def __init__(self, status: int, body: Any = None):
        self.status_code = status
        self._body = body
        self.content = b"" if body is None else json.dumps(body).encode()
        self.text = self.content.decode()

    def json(self) -> Any:
        return self._body


class FakeTMI:
    """In-memory addon store that applies replace-/parameters JSON Patches."""

    def __init__(self, addon: dict[str, Any], patch_status: int = 200):
        self.addon = json.loads(json.dumps(addon))
        self.patch_status = patch_status
        self.calls: list[tuple[str, dict[str, str], Any]] = []

    def request(self, method, url, headers=None, data=None, timeout=None):
        self.calls.append((method, headers or {}, data))
        if method == "GET":
            return FakeResponse(200, self.addon)
        if method == "PATCH":
            if self.patch_status != 200:
                return FakeResponse(self.patch_status, {"error": "forbidden"})
            assert data is not None
            for op in json.loads(data):
                assert op["op"] == "replace" and op["path"] == "/parameters"
                self.addon["parameters"] = op["value"]
            return FakeResponse(200, self.addon)
        raise AssertionError(f"unexpected method {method}")


@pytest.fixture
def profiles_file(tmp_path: Path) -> Path:
    p = tmp_path / "llm-profiles.yaml"
    p.write_text(PROFILES_YAML, encoding="utf-8")
    return p


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeTMI:
    tmi = FakeTMI(RECORDED_ADDON)
    monkeypatch.setattr(app.requests, "request", tmi.request)
    monkeypatch.setenv("TMI_TOKEN", "tok")
    return tmi


def _run(profiles_file: Path, *extra: str) -> int:
    return app.main(["--profiles-file", str(profiles_file), *extra])


class TestBuildProfileParam:
    def test_enum_shape(self):
        p = app.build_profile_param(["a", "b"], "b")
        assert p["type"] == "enum" and p["enum_values"] == ["a", "b"]
        assert p["default_value"] == "b" and p["required"] is False
        assert "metadata_key" not in p

    def test_rejects_unknown_default(self):
        with pytest.raises(SyncError, match="not a profile"):
            app.build_profile_param(["a"], "z")

    def test_rejects_empty(self):
        with pytest.raises(SyncError, match="no profiles"):
            app.build_profile_param([], "a")

    def test_rejects_over_tmi_limit(self):
        names = [f"p{i}" for i in range(51)]
        with pytest.raises(SyncError, match="limit of 50"):
            app.build_profile_param(names, "p0")


class TestMergeParameters:
    def test_appends_and_keeps_environments_verbatim(self):
        new = app.build_profile_param(["a"], "a")
        merged = app.merge_parameters(RECORDED_ADDON["parameters"], new)
        assert merged[0] == RECORDED_ADDON["parameters"][0]
        assert merged[1] == new

    def test_replaces_existing_in_place(self):
        old = app.build_profile_param(["a"], "a")
        new = app.build_profile_param(["a", "b"], "b")
        merged = app.merge_parameters([old, RECORDED_ADDON["parameters"][0]], new)
        assert merged == [new, RECORDED_ADDON["parameters"][0]]

    def test_rejects_duplicate_profile_params(self):
        p = app.build_profile_param(["a"], "a")
        with pytest.raises(SyncError, match="2 parameters"):
            app.merge_parameters([p, p], p)


def test_needs_update_ignores_empty_optional_fields():
    a = [{"name": "x", "type": "string", "description": ""}]
    b = [{"name": "x", "type": "string"}]
    assert not app.needs_update(a, b)
    assert app.needs_update(a, [{"name": "x", "type": "enum"}])


class TestMain:
    def test_dry_run_sends_no_patch(self, fake: FakeTMI, profiles_file: Path, capsys):
        assert _run(profiles_file) == 0
        assert [c[0] for c in fake.calls] == ["GET"]
        patch = json.loads(capsys.readouterr().out)
        values = patch[0]["value"]
        assert values[0]["name"] == "environments"
        assert values[1]["enum_values"] == ["claude-fable-5-2", "gpt-6_2-astra"]
        assert values[1]["default_value"] == "claude-fable-5-2"

    def test_apply_patches_then_rerun_is_noop(self, fake: FakeTMI, profiles_file: Path):
        assert _run(profiles_file, "--apply") == 0
        methods = [c[0] for c in fake.calls]
        assert methods == ["GET", "PATCH", "GET"]
        patch_headers = fake.calls[1][1]
        assert patch_headers["Content-Type"] == "application/json-patch+json"
        assert patch_headers["Authorization"] == "Bearer tok"
        fake.calls.clear()
        assert _run(profiles_file, "--apply") == 0
        assert [c[0] for c in fake.calls] == ["GET"]

    def test_403_fails_with_admin_hint(
        self, monkeypatch: pytest.MonkeyPatch, profiles_file: Path, capsys
    ):
        tmi = FakeTMI(RECORDED_ADDON, patch_status=403)
        monkeypatch.setattr(app.requests, "request", tmi.request)
        monkeypatch.setenv("TMI_TOKEN", "tok")
        assert _run(profiles_file, "--apply") == 1
        assert "administrator" in capsys.readouterr().err

    def test_missing_token(
        self, monkeypatch: pytest.MonkeyPatch, profiles_file: Path, capsys
    ):
        monkeypatch.delenv("TMI_TOKEN", raising=False)
        assert _run(profiles_file) == 1
        assert "TMI_TOKEN" in capsys.readouterr().err

    def test_unknown_default(self, fake: FakeTMI, profiles_file: Path, capsys):
        assert _run(profiles_file, "--default", "fable51") == 1
        assert "not a profile" in capsys.readouterr().err
        assert fake.calls == []

    def test_real_profiles_file_builds_valid_param(self):
        names = list(app.load_profiles(app.default_profiles_file()))
        p = app.build_profile_param(names, app.DEFAULT_PROFILE)
        assert "claude-mythos-5-2" in p["enum_values"]
