"""Script extraction and static rule scan for Terraform scripts (#14)."""

import base64
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # pyright: ignore[reportMissingModuleSource]

from tmi_tf.tf_filter import Registry, _is_block, _script_digest
from tmi_tf.tf_parser import StaticInventory, unquote_literal

logger = logging.getLogger(__name__)

RULES_PATH = Path(__file__).parent / "data" / "script_rules.yaml"
CATEGORIES = frozenset(
    {
        "download_exec",
        "decode_exec",
        "reverse_shell",
        "security_disable",
        "weak_perms",
        "hardcoded_secret",
        "crypto_miner",
        "metadata_creds",
        "persistence",
    }
)
SEVERITIES = ("Low", "Medium", "High", "Critical")
MASKED = "[masked-secret]"
_EVIDENCE_CHARS = 120


@dataclass(frozen=True)
class ScriptRule:
    id: str
    category: str
    title: str
    pattern: re.Pattern[str]
    severity: str
    threat_hint: str
    secret: bool


@dataclass
class RuleHit:
    rule_id: str
    category: str
    title: str
    severity: str
    threat_hint: str
    secret: bool
    evidence: str
    count: int


def load_rules(path: Path = RULES_PATH) -> list[ScriptRule]:
    """Fail fast (like the resource registry) on an invalid rule file."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules: list[ScriptRule] = []
    seen_ids: set[str] = set()
    for entry in raw["rules"]:
        if entry["id"] in seen_ids:
            raise ValueError(f"script rules: duplicate rule id {entry['id']!r}")
        seen_ids.add(entry["id"])
        if entry["category"] not in CATEGORIES:
            raise ValueError(
                f"script rules: {entry['id']} invalid category {entry['category']!r}"
            )
        if entry["severity"] not in SEVERITIES:
            raise ValueError(
                f"script rules: {entry['id']} invalid severity {entry['severity']!r}"
            )
        if entry["threat_hint"] not in ("S", "T", "R", "I", "D", "E"):
            raise ValueError(f"script rules: {entry['id']} invalid threat_hint")
        rules.append(
            ScriptRule(
                id=entry["id"],
                category=entry["category"],
                title=entry["title"],
                pattern=re.compile(entry["pattern"], re.MULTILINE | re.IGNORECASE),
                severity=entry["severity"],
                threat_hint=entry["threat_hint"],
                secret=bool(entry.get("secret", False)),
            )
        )
    return rules


def match_rules(text: str, rules: list[ScriptRule]) -> list[RuleHit]:
    """One grouped hit per rule that matches ``text``.

    ``text`` is scanned in full, uncapped: every rule pattern is written to
    stay linear in input size (bounded, non-overlapping gaps), so there is
    no need to truncate long lines, and doing so would let a payload placed
    past the truncation point evade detection entirely.
    """
    hits: list[RuleHit] = []
    for rule in rules:
        matches = list(rule.pattern.finditer(text))
        if not matches:
            continue
        raw_evidence = matches[0].group(0).strip()
        # Mask any secret a non-secret rule's match happens to contain
        # (e.g. a Bearer token inside a curl-pipe-to-shell command); a
        # secret rule's own match is always fully masked.
        evidence = (
            MASKED
            if rule.secret
            else mask_secrets(raw_evidence, rules)[:_EVIDENCE_CHARS]
        )
        hits.append(
            RuleHit(
                rule.id,
                rule.category,
                rule.title,
                rule.severity,
                rule.threat_hint,
                rule.secret,
                evidence,
                len(matches),
            )
        )
    return hits


def mask_secrets(text: str, rules: list[ScriptRule]) -> str:
    for rule in rules:
        if rule.secret:
            text = rule.pattern.sub(MASKED, text)
    return text


# --- script extraction (#14 task 2) -----------------------------------------


@dataclass
class ScriptBlob:
    id: str
    component_id: str
    attr_path: str
    file: str
    digest: str
    text: str
    raw_text: str | None  # exact source span to replace, None for references
    reference: str | None = None  # file()/templatefile() path, when not inline


_FILE_REF_RE = re.compile(
    r'\b(?:template)?file\(\s*"(?:\$\{path\.(?P<base>module|root|cwd)\}/)?(?P<ref>[^"]+)"'
)
_B64_ENC_RE = re.compile(r'^\$\{base64encode\("((?:[^"\\]|\\.)*)"\)\}$')
_B64_LITERAL_RE = re.compile(r"^[A-Za-z0-9+/=\s]{8,}$")
# Full quoted-literal span (kept, not just the body) so the replacement in
# `omit_scripts` can anchor on the exact same self-delimited token the parsed
# path produces (quotes included) instead of a bare body needing external
# quotes to stay valid HCL.
_LITERAL_UNPARSED_RE = re.compile(
    r'^\s*(?P<attr>[\w-]+)\s*=\s*(?P<full>"(?P<body>(?:[^"\\]|\\.)*)")', re.MULTILINE
)
_HEREDOC_START_LINE_RE = re.compile(
    r"^\s*(?P<attr>[\w-]+)\s*=\s*(?P<open><<-?(?P<marker>\w+))\s*$"
)


def _iter_unparsed_heredocs(text: str):
    """(attr, body, raw span) for each *terminated* heredoc in raw source text.

    A single forward pass over lines, O(len(text)) total. An unterminated
    heredoc consumes the rest of the file looking for its terminator (there is
    no well-defined end otherwise) and yields nothing -- matching how a real
    heredoc parser behaves, and avoiding the O(n^2) blowup of a backtracking
    `.*?` regex retried from every `<<` occurrence in the file.
    """
    lines = text.split("\n")
    i, n = 0, len(lines)
    while i < n:
        m = _HEREDOC_START_LINE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        attr, open_tok, marker = m.group("attr"), m.group("open"), m.group("marker")
        body_lines: list[str] = []
        i += 1
        while i < n and lines[i].strip() != marker:
            body_lines.append(lines[i])
            i += 1
        if i < n:  # terminator line found; otherwise unterminated -- yield nothing
            yield (
                attr,
                "\n".join(body_lines),
                "\n".join([open_tok, *body_lines, lines[i]]),
            )
            i += 1


def _safe_read(
    reference: str, base_dir: Path, tf_contents: dict[str, str], repo_root: Path | None
) -> str:
    """Repo-relative read only: no absolute paths, no `..`, tf_contents first, then disk."""
    if reference.startswith("/") or ".." in Path(reference).parts:
        return ""
    rel = (base_dir / reference).as_posix().removeprefix("./")
    if rel in tf_contents:
        return tf_contents[rel]
    if repo_root is not None:
        target = (repo_root / rel).resolve()
        if repo_root.resolve() in target.parents and target.is_file():
            return target.read_text(encoding="utf-8", errors="replace")
    return ""


def _decode(
    raw: str, attr: str, file: str, tf_contents: dict[str, str], repo_root: Path | None
) -> tuple[str, str | None, str | None]:
    """(text, raw_text span, reference) for one hcl2 value string."""
    m = _FILE_REF_RE.search(raw)
    if raw.startswith("${") and m:
        # `path.module` (and a bare relative path) is file-dir relative;
        # `path.root`/`path.cwd` are repo-root relative.
        base_dir = (
            Path(".") if m.group("base") in ("root", "cwd") else Path(file).parent
        )
        ref = m.group("ref")
        return _safe_read(ref, base_dir, tf_contents, repo_root), None, ref
    m = _B64_ENC_RE.match(raw)
    if m:
        return m.group(1), None, None
    if raw.startswith("${"):
        return "", None, raw[2:-1]  # other expression: reference only
    text = unquote_literal(raw)
    span = text  # heredoc: "<<-EOT ... EOT" without quotes is verbatim source; literal: keep quotes
    if text.startswith("<<"):
        text = "\n".join(text.split("\n")[1:-1])
    else:
        span = raw
    if attr.endswith("_base64") and _B64_LITERAL_RE.match(text):
        try:
            text = base64.b64decode(text, validate=False).decode("utf-8")
        except Exception:
            # Not actually base64 (e.g. an unresolved expression) -- keep the
            # literal text as-is.
            logger.debug(
                "Could not base64-decode %s attribute value", attr, exc_info=True
            )
    return text, span, None


def _walk(
    value: Any, names: frozenset[str], path: str, out: list[tuple[str, Any]]
) -> None:
    """Mirrors tf_filter._hash_scripts's key-matching/block-skip exactly: any
    non-block leaf under a name in ``names`` is collected (string or not --
    e.g. ``user_data = ["curl x | sh"]`` -- so every value the phase-1 filter
    hashes is also extracted here)."""
    if isinstance(value, dict):
        for k, v in value.items():
            key = unquote_literal(k)
            if key.startswith("__"):
                continue
            sub = f"{path}.{key}" if path else key
            if key in names and not _is_block(v):
                out.append((sub, v))
            else:
                _walk(v, names, sub, out)
    elif isinstance(value, list):
        for item in value:
            _walk(item, names, path, out)


def _blob(
    cid: str,
    attr: str,
    file: str,
    raw: Any,
    tf_contents: dict[str, str],
    repo_root: Path | None,
) -> ScriptBlob:
    if isinstance(raw, str):
        text, span, ref = _decode(
            raw, attr.rsplit(".", 1)[-1], file, tf_contents, repo_root
        )
    else:
        # ponytail: non-string script values (list/object literals) are
        # scanned but not omitted from the raw source text -- no source span
        # to anchor a replacement on. Upgrade: a bracket-balanced span finder
        # if omitting these from the raw file becomes required.
        raw = json.dumps(raw, sort_keys=True)
        text, span, ref = raw, None, None
    return ScriptBlob(
        f"{cid}:{attr}", cid, attr, file, _script_digest(raw), text, span, ref
    )


def extract_scripts(
    inventory: StaticInventory,
    tf_contents: dict[str, str],
    registry: Registry,
    repo_root: Path | None = None,
) -> list[ScriptBlob]:
    blobs: list[ScriptBlob] = []
    names = registry.hash_only_attrs
    data_names = names | registry.data_hash_only_attrs
    for r in inventory.resources:
        found: list[tuple[str, Any]] = []
        _walk(r.raw_attributes, names, "", found)
        blobs += [
            _blob(r.address, a, r.file, v, tf_contents, repo_root) for a, v in found
        ]
    for path, parsed in inventory.parsed_files.items():
        for item in parsed.get("data", []):
            for dtype_q, by_name in item.items():
                for name_q, body in by_name.items():
                    cid = f"data.{unquote_literal(dtype_q)}.{unquote_literal(name_q)}"
                    found = []
                    _walk(body, data_names, "", found)
                    blobs += [
                        _blob(cid, a, path, v, tf_contents, repo_root) for a, v in found
                    ]
        for item in parsed.get("module", []):
            for name_q, body in item.items():
                found = []
                _walk(body, names, "", found)
                blobs += [
                    _blob(
                        f"module.{unquote_literal(name_q)}",
                        a,
                        path,
                        v,
                        tf_contents,
                        repo_root,
                    )
                    for a, v in found
                ]
    for path in inventory.unparsed_files:
        text = tf_contents.get(path, "")
        for attr, body, raw_text in _iter_unparsed_heredocs(text):
            if attr in data_names:
                blobs.append(
                    ScriptBlob(
                        f"{path}:{attr}",
                        path,
                        attr,
                        path,
                        _script_digest(raw_text),
                        body,
                        raw_text,
                    )
                )
        for m in _LITERAL_UNPARSED_RE.finditer(text):
            if m.group("attr") in data_names:
                blobs.append(
                    ScriptBlob(
                        f"{path}:{m.group('attr')}",
                        path,
                        m.group("attr"),
                        path,
                        _script_digest(m.group("full")),
                        m.group("body"),
                        m.group("full"),
                    )
                )
    logger.info(
        "Script extraction: %d blob(s) from %d file(s)", len(blobs), len(tf_contents)
    )
    return blobs


def _assignment_pattern(attr_name: str, raw_text: str) -> re.Pattern[str]:
    """Match ``<attr_name> = <raw_text>`` (key optionally quoted) so
    `omit_scripts` only ever replaces that attribute's own value, never any
    other value elsewhere in the file that happens to be textually identical
    (e.g. a `tags.Name` holding the same string as a `user_data` script)."""
    return re.compile(rf'("?\b{re.escape(attr_name)}\b"?\s*=\s*){re.escape(raw_text)}')


def omit_scripts(
    tf_contents: dict[str, str], blobs: list[ScriptBlob]
) -> dict[str, str]:
    """Copy of tf_contents with each blob's raw span replaced by its digest
    marker, anchored to that attribute's own assignment."""
    out = dict(tf_contents)
    for b in blobs:
        if not b.raw_text:
            continue
        text = out.get(b.file, "")
        attr_name = b.attr_path.rsplit(".", 1)[-1]
        marker = b.digest if b.raw_text == b.text else f'"{b.digest}"'
        pattern = _assignment_pattern(attr_name, b.raw_text)
        new_text, count = pattern.subn(
            lambda m, marker=marker: m.group(1) + marker, text, count=1
        )
        if count:
            out[b.file] = new_text
    return out
