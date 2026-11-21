"""Sync the tmi-tf-wh addon's `profile` enum parameter with llm-profiles.yaml.

Reads the addon from TMI, rebuilds its `profile` parameter from the local
profiles file (every other parameter is kept exactly as TMI returned it), and
prints the JSON Patch. With --apply it sends the PATCH (TMI allows it for
administrators only) and re-reads the addon to verify.

Safe to re-run: when the addon already matches, nothing is sent.

Usage:
  TMI_TOKEN=<admin bearer token> uv run python scripts/addon-profile-param.py [--apply]
      [--default claude-fable-5-2] [--base-url https://api.tmi.dev]
      [--addon-id fed11e3a-778c-4eb3-a003-b00737e7c8ca] [--profiles-file PATH]
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import requests

from tmi_tf.llm_profiles import default_profiles_file, load_profiles

DEFAULT_BASE_URL = "https://api.tmi.dev"
DEFAULT_ADDON_ID = "fed11e3a-778c-4eb3-a003-b00737e7c8ca"
DEFAULT_PROFILE = "claude-fable-5-2"
PARAM_NAME = "profile"
PARAM_DESCRIPTION = "LLM profile (model) to run the analysis with"
MAX_ENUM_VALUES = 50  # TMI api/addon_validation.go
MAX_VALUE_LEN = 256


class SyncError(Exception):
    """A precondition failed; the message names what to fix."""


def build_profile_param(names: list[str], default: str) -> dict[str, Any]:
    """The `profile` enum parameter for the given profile names."""
    if not names:
        raise SyncError("no profiles found in the profiles file")
    if len(names) > MAX_ENUM_VALUES:
        raise SyncError(
            f"{len(names)} profiles exceed TMI's limit of {MAX_ENUM_VALUES} enum values"
        )
    too_long = [n for n in names if len(n) > MAX_VALUE_LEN]
    if too_long:
        raise SyncError(f"profile names longer than {MAX_VALUE_LEN}: {too_long}")
    if default not in names:
        raise SyncError(
            f"default {default!r} is not a profile (available: {', '.join(names)})"
        )
    return {
        "name": PARAM_NAME,
        "type": "enum",
        "description": PARAM_DESCRIPTION,
        "enum_values": list(names),
        "default_value": default,
        "required": False,
    }


def merge_parameters(
    current: list[dict[str, Any]], profile_param: dict[str, Any]
) -> list[dict[str, Any]]:
    """Current parameters with `profile` replaced (or appended), order kept."""
    matches = [i for i, p in enumerate(current) if p.get("name") == PARAM_NAME]
    if len(matches) > 1:
        raise SyncError(
            f"addon declares {len(matches)} parameters named {PARAM_NAME!r}"
        )
    merged = [dict(p) for p in current]
    if matches:
        merged[matches[0]] = profile_param
    else:
        merged.append(profile_param)
    return merged


def _normalized(param: dict[str, Any]) -> dict[str, Any]:
    """Drop empty/absent optional fields so TMI's echo compares equal."""
    return {k: v for k, v in param.items() if v not in (None, "", [])}


def needs_update(current: list[dict[str, Any]], desired: list[dict[str, Any]]) -> bool:
    return [_normalized(p) for p in current] != [_normalized(p) for p in desired]


def build_patch(parameters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"op": "replace", "path": "/parameters", "value": parameters}]


def _request(
    method: str, url: str, token: str, patch: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if patch is not None:
        headers["Content-Type"] = "application/json-patch+json"
        data = json.dumps(patch)
    resp = requests.request(method, url, headers=headers, data=data, timeout=30)
    if resp.status_code == 403:
        raise SyncError(
            f"{method} {url}: 403 forbidden (PATCH needs an administrator token)"
        )
    if resp.status_code >= 400:
        raise SyncError(f"{method} {url}: HTTP {resp.status_code}: {resp.text[:500]}")
    if not resp.content:
        return {}
    body = resp.json()
    if not isinstance(body, dict):
        raise SyncError(f"{method} {url}: expected a JSON object")
    return body


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--apply", action="store_true", help="send the PATCH")
    p.add_argument("--default", default=DEFAULT_PROFILE)
    p.add_argument("--base-url", default=DEFAULT_BASE_URL)
    p.add_argument("--addon-id", default=DEFAULT_ADDON_ID)
    p.add_argument("--profiles-file", type=Path, default=None)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        token = os.environ.get("TMI_TOKEN", "").strip()
        if not token:
            raise SyncError("TMI_TOKEN is not set (an administrator bearer token)")
        names = list(load_profiles(args.profiles_file or default_profiles_file()))
        profile_param = build_profile_param(names, args.default)
        url = f"{args.base_url.rstrip('/')}/addons/{args.addon_id}"
        addon = _request("GET", url, token)
        current = addon.get("parameters") or []
        if not isinstance(current, list):
            raise SyncError("addon `parameters` is not a list")
        desired = merge_parameters(current, profile_param)
        if not needs_update(current, desired):
            print(
                f"addon {args.addon_id}: `profile` already matches ({len(names)} profiles)"
            )
            return 0
        patch = build_patch(desired)
        print(json.dumps(patch, indent=2))
        if not args.apply:
            print("dry run; re-run with --apply to send", file=sys.stderr)
            return 0
        _request("PATCH", url, token, patch=patch)
        after = _request("GET", url, token).get("parameters") or []
        if needs_update(after, desired):
            raise SyncError(f"addon parameters after PATCH differ: {json.dumps(after)}")
        print(
            f"addon {args.addon_id}: `profile` updated ({len(names)} profiles, default {args.default})"
        )
        return 0
    except SyncError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
