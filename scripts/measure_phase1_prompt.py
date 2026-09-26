"""Measure phase-1 prompt size before/after static HCL analysis (issue #10).

Reads a local Terraform checkout, resolves one environment exactly like the
pipeline (environment files + relative-source modules), builds both phase-1
prompts and prints their sizes. Never calls an LLM. Files are read only; the
validator/sanitizer is NOT run, so the "before" number includes any user_data
the pipeline would have stripped.

Usage:
  uv run python scripts/measure_phase1_prompt.py /Users/efitz/Projects/tmi/terraform aws-public
"""

import argparse
import json
import sys
from pathlib import Path

from tmi_tf.config import prompts_dir
from tmi_tf.llm_analyzer import format_terraform_contents
from tmi_tf.repo_analyzer import RepositoryAnalyzer
from tmi_tf.tf_filter import filter_terraform, load_registry
from tmi_tf.tf_parser import parse_terraform


def count_tokens(text: str) -> int:
    try:
        import litellm  # pyright: ignore[reportMissingImports]

        return int(litellm.token_counter(model="gpt-4o", text=text))
    except Exception as e:  # no tokenizer available offline
        print(f"token_counter unavailable ({e}); using chars // 4", file=sys.stderr)
        return len(text) // 4


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("terraform_root", type=Path)
    ap.add_argument("environment")
    args = ap.parse_args()
    root = args.terraform_root.resolve()

    envs = RepositoryAnalyzer.detect_environments(root)
    env = next((e for e in envs if e.name == args.environment), None)
    if env is None:
        print(
            f"environment {args.environment!r} not found; available: "
            f"{', '.join(e.name for e in envs) or 'none'}",
            file=sys.stderr,
        )
        return 2

    files = RepositoryAnalyzer.resolve_modules(env, root)
    contents: dict[str, str] = {}
    for f in files:
        try:
            contents[str(f.relative_to(root))] = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            print(f"skipping {f}: {e}", file=sys.stderr)

    prompts = prompts_dir()
    old_system = (prompts / "inventory_system.txt").read_text(encoding="utf-8")
    old_user = (prompts / "inventory_user.txt").read_text(encoding="utf-8")
    new_system = (prompts / "inventory_semantic_system.txt").read_text(encoding="utf-8")
    new_user = (prompts / "inventory_semantic_user.txt").read_text(encoding="utf-8")

    raw_text = format_terraform_contents(contents)
    before = old_system + old_user.format(
        repo_name="measure", repo_url="local", terraform_contents=raw_text
    )

    static = parse_terraform(contents)
    filtered = filter_terraform(static, contents, load_registry())
    filtered_text = format_terraform_contents(filtered.filtered_files)
    inventory_json = json.dumps(filtered.prebuilt_inventory, indent=2)
    after = new_system + new_user.format(
        repo_name="measure",
        repo_url="local",
        inventory_json=inventory_json,
        filtered_hcl=filtered_text,
    )

    before_tokens = count_tokens(before)
    after_tokens = count_tokens(after)
    rows = [
        ("environment", args.environment),
        ("files", len(contents)),
        ("unparsed files", ", ".join(static.unparsed_files) or "none"),
        (
            "resources / data sources / modules",
            f"{len(static.resources)} / {len(static.data_sources)} / {len(static.modules)}",
        ),
        (
            "components in pre-built inventory",
            len(filtered.prebuilt_inventory["components"]),
        ),
        ("attributes omitted", filtered.omitted_attributes),
        ("raw HCL chars", len(raw_text)),
        ("filtered HCL chars", len(filtered_text)),
        ("pre-built inventory JSON chars", len(inventory_json)),
        ("phase-1 prompt chars before -> after", f"{len(before)} -> {len(after)}"),
        ("phase-1 prompt tokens before -> after", f"{before_tokens} -> {after_tokens}"),
        (
            "input delta",
            f"{(after_tokens - before_tokens) / max(before_tokens, 1):+.1%}",
        ),
    ]
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"{k:<{width}}  {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
