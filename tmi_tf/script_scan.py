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
# Matched one already-split line at a time -- never against the whole file
# with re.MULTILINE -- so `^`/`$`/`[ \t]*` can never cross a newline and a
# failed attempt at one line costs at most O(that line's length), regardless
# of how many blank/garbage lines or heredoc starts surround it. The key is
# optionally quoted (`"user_data" = ...`, valid HCL inside an object
# constructor) since both extraction (unparsed files) and omission (any file)
# use these against raw source text. `full`/`open` capture the whole
# self-delimited value span (quotes, or heredoc markers, included) rather
# than just the inner body/marker, so the span is an exact source substring
# `omit_scripts` can find again verbatim.
_LITERAL_LINE_RE = re.compile(
    r'^[ \t]*"?(?P<attr>[\w-]+)"?[ \t]*=[ \t]*(?P<full>"(?P<body>(?:[^"\\]|\\.)*)")'
)
# Omission-side literal finder: every `attr = "..."` on a line, not just one
# at line start, so a key inside an inline object constructor
# (`metadata = { "startup-script" = "...", foo = "x" }`) is found too. The
# key must follow line start or a `{`/`,`/`(`/whitespace delimiter. Other
# strings and `#`/`//` comments are consumed whole (leftmost match) so an
# assignment-shaped fragment inside them is never matched. finditer on one
# line: each failed attempt is bounded by that line, and a string body can
# only fail to close once per line (after the last quote), so linear.
_INLINE_LITERAL_RE = re.compile(
    r'(?:^|(?<=[{,(\s]))"?(?P<attr>[\w-]+)"?[ \t]*=[ \t]*(?P<full>"(?:[^"\\]|\\.)*")'
    r'|"(?:[^"\\]|\\.)*"'
    r"|(?:#|//).*"
)
_HEREDOC_START_LINE_RE = re.compile(
    r'^[ \t]*"?(?P<attr>[\w-]+)"?[ \t]*=[ \t]*(?P<open><<-?(?P<marker>\w+).*)$'
)


def _iter_unparsed_assignments(text: str):
    """(attr, body, raw_text span) for every literal or heredoc assignment
    found in raw source text hcl2 couldn't parse, in one forward pass over
    its lines, O(len(text)) total.

    A heredoc's body lines are consumed atomically and never independently
    re-examined, so an `attr = "..."`-shaped line living inside another
    script's heredoc body is never mistaken for its own assignment. An
    unterminated heredoc consumes the rest of the lines (there's no
    well-defined end otherwise) and ends the scan -- matching how a real
    heredoc parser behaves, and avoiding the O(n^2) blowup of a backtracking
    `.*?` regex retried from every `<<` occurrence in the file.
    """
    lines = text.split("\n")
    i, n = 0, len(lines)
    while i < n:
        m = _HEREDOC_START_LINE_RE.match(lines[i])
        if m:
            attr, open_tok, marker = m.group("attr"), m.group("open"), m.group("marker")
            body_lines: list[str] = []
            j = i + 1
            while j < n and lines[j].strip() != marker:
                body_lines.append(lines[j])
                j += 1
            if j == n:  # unterminated -- no well-defined end, stop scanning
                return
            yield (
                attr,
                "\n".join(body_lines),
                "\n".join([open_tok, *body_lines, lines[j]]),
            )
            i = j + 1
            continue
        m = _LITERAL_LINE_RE.match(lines[i])
        if m:
            yield m.group("attr"), m.group("body"), m.group("full")
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
        for attr, body, raw_text in _iter_unparsed_assignments(text):
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
    logger.info(
        "Script extraction: %d blob(s) from %d file(s)", len(blobs), len(tf_contents)
    )
    return blobs


def _marker_for(b: ScriptBlob) -> str:
    return b.digest if b.raw_text == b.text else f'"{b.digest}"'


def _rebuild_without_scripts(
    text: str, wanted: dict[tuple[str, str], list[ScriptBlob]]
) -> str:
    """One forward pass over ``text``'s lines: each occurrence of a
    ``wanted`` (attr_name, raw_text) key gets its blob's digest marker
    substituted in place -- one occurrence consumed per matching blob, off
    the front of that key's queue, so N blobs sharing an identical
    attribute+value each still redact their own occurrence (and nothing
    else in the file that merely happens to hold the same text). Whatever's
    left in ``wanted``'s queues when this returns are misses -- `_omit`
    collects them.

    O(len(text) + len(wanted)) total: every blob targeting this file is
    looked up against matches found in this single scan, rather than each
    blob re-searching the whole file from scratch (which made `omit_scripts`
    O(blobs x file size)).
    """
    lines = text.split("\n")
    out_lines: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        m = _HEREDOC_START_LINE_RE.match(line)
        if m:
            attr, open_tok, marker_word = (
                m.group("attr"),
                m.group("open"),
                m.group("marker"),
            )
            prefix = line[: m.start("open")]
            body_lines: list[str] = []
            j = i + 1
            while j < n and lines[j].strip() != marker_word:
                body_lines.append(lines[j])
                j += 1
            if j == n:  # unterminated -- copy the rest through, done
                out_lines.extend(lines[i:])
                break
            raw_text = "\n".join([open_tok, *body_lines, lines[j]])
            queue = wanted.get((attr, raw_text))
            if queue:
                out_lines.append(prefix + _marker_for(queue.pop(0)))
            else:
                out_lines.extend(lines[i : j + 1])
            i = j + 1
            continue
        parts: list[str] = []
        pos = 0
        for m in _INLINE_LITERAL_RE.finditer(line):
            queue = m.group("attr") and wanted.get((m.group("attr"), m.group("full")))
            if queue:
                parts += [line[pos : m.start("full")], _marker_for(queue.pop(0))]
                pos = m.end("full")
        out_lines.append("".join(parts) + line[pos:])
        i += 1
    return "\n".join(out_lines)


def _omit(
    tf_contents: dict[str, str], blobs: list[ScriptBlob]
) -> tuple[dict[str, str], list[ScriptBlob]]:
    """Shared implementation for `omit_scripts`/`unomitted`: single source of
    truth for which blobs' anchored spans were actually found and replaced,
    so the two never disagree with each other. One rebuild pass per file."""
    by_file: dict[str, list[ScriptBlob]] = {}
    for b in blobs:
        if b.raw_text:
            by_file.setdefault(b.file, []).append(b)
    out = dict(tf_contents)
    misses: list[ScriptBlob] = []
    for file, file_blobs in by_file.items():
        wanted: dict[tuple[str, str], list[ScriptBlob]] = {}
        for b in file_blobs:
            assert b.raw_text is not None  # by_file only collected truthy raw_text
            attr_name = b.attr_path.rsplit(".", 1)[-1]
            wanted.setdefault((attr_name, b.raw_text), []).append(b)
        out[file] = _rebuild_without_scripts(out.get(file, ""), wanted)
        for queue in wanted.values():
            misses.extend(queue)
    return out, misses


def omit_scripts(
    tf_contents: dict[str, str], blobs: list[ScriptBlob], warn: bool = True
) -> dict[str, str]:
    """Copy of tf_contents with each blob's raw span replaced by its digest
    marker, anchored to that attribute's own assignment.

    A blob whose span can't be found and replaced is logged (id/file only,
    never the script text) rather than failing silently; call
    `unomitted(tf_contents, blobs)` to get that list back programmatically.
    Pass ``warn=False`` when the caller already reports misses itself (e.g.
    one summary warning covering the whole run), so they aren't logged twice.
    """
    out, misses = _omit(tf_contents, blobs)
    if warn:
        for b in misses:
            logger.warning(
                "Script omission: %s (attr %r in %s) not found -- left unredacted",
                b.id,
                b.attr_path.rsplit(".", 1)[-1],
                b.file,
            )
    return out


def unomitted(tf_contents: dict[str, str], blobs: list[ScriptBlob]) -> list[ScriptBlob]:
    """Blobs `omit_scripts(tf_contents, blobs)` would not find and redact
    (same arguments as `omit_scripts`). Never inspects or returns script
    text itself, only the ``ScriptBlob`` records."""
    return _omit(tf_contents, blobs)[1]
