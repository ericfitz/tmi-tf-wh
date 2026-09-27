"""Prompt-injection scan of Terraform metadata and redaction (#14)."""

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Any

from tmi_tf.tf_parser import StaticInventory, clean_value, unquote_literal

logger = logging.getLogger(__name__)

_INSTRUCTION_RE = re.compile(
    r"ignore\s+(?:(?:all|any)(?:\s+of)?\s+)?(?:the\s+)?"
    r"(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)"
    r"|you\s+are\s+now\b|^\s*(?:system|assistant|user)\s*:|\bdisregard\b|new\s+instructions"
    r"|</?untrusted|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<<SYS>>"
    r"|do\s+not\s+(?:report|flag|mention)"
    r"|mark\s+(?:it\s+|this\s+|everything\s+)?as\s+(?:safe|benign)"
    r"|(?:no|zero)\s+(?:threats|findings)",
    re.IGNORECASE | re.MULTILINE,
)
_INVISIBLE_RE = re.compile(
    "[\u200b-\u200f\u2060\ufeff\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]"
)
_SENTENCE_WORDS = 12
_TAG_KEYS = frozenset(
    {"tags", "labels", "freeform_tags", "defined_tags", "tags_all", "annotations"}
)
_STRING_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_MARKER = "[redacted: suspected prompt injection, sha256:{}]"


@dataclass
class MetaString:
    location: str
    file: str
    text: str
    name_like: bool = False
    # False only for text that is *not* wrapped in real quotes at its
    # declaration site: a comment body, or the full raw span of a heredoc.
    # Everything else -- a plain quoted literal, a block label (resource/
    # variable/module name), an unparsed-file literal, or a string-literal
    # leaf extracted from inside an expression (see `_strings`) -- is
    # quoted=True. Drives which source span `redact_contents` matches and
    # how it must be replaced to keep the file parseable.
    quoted: bool = True


@dataclass
class InjectionHit:
    detector: str
    location: str
    file: str
    text: str
    digest: str
    quoted: bool = True


def detect(text: str, name_like: bool = False) -> list[str]:
    found: list[str] = []
    if _INSTRUCTION_RE.search(text):
        found.append("instruction")
    if _INVISIBLE_RE.search(text):
        found.append("invisible_unicode")
    if name_like and len(text.split()) > _SENTENCE_WORDS:
        found.append("sentence")
    return found


def _is_quoted_source(raw: Any) -> bool:
    """True unless ``raw`` (the *pre*-``clean_value`` hcl2 value) is a
    heredoc or an unwrapped expression -- hcl2 represents both as a string
    that isn't a plain quoted literal (a heredoc's synthetic wrapper starts
    ``"<<``; an expression, whether written as ``${...}`` or as a bare call
    like ``merge(...)``, is always stored starting with ``${``). Neither
    form has real quotes around it in source."""
    return isinstance(raw, str) and raw.startswith('"') and not raw.startswith('"<<')


def _is_expression(raw: str) -> bool:
    """Same criterion ``clean_value`` uses to decide a string is *entirely*
    one interpolated expression (as opposed to a plain literal, or a
    literal with an embedded ``${...}`` among other text)."""
    return raw.startswith("${") and raw.endswith("}") and raw.count("${") == 1


def _strings(value: Any, loc: str, out: list[tuple[str, str, bool]]) -> None:
    """(location, text, quoted) for every string leaf under ``value`` (the
    *raw*, pre-``clean_value`` hcl2 structure), recursing through nested
    dicts/lists exactly like ``clean_value`` does, but keeping each leaf's
    raw form just long enough to classify it via ``_is_quoted_source``.

    An expression (`merge(var.t, {Note = "..."})`, a bare reference, ...)
    is re-serialized by hcl2 and essentially never matches the source
    verbatim, so scanning it whole would never find its redaction target
    in the file. Instead extract its string-literal leaves with
    ``_STRING_RE`` and scan/redact each one individually -- `var.t` (no
    quotes) is correctly left alone.
    """
    if isinstance(value, str):
        if _is_expression(value):
            for i, m in enumerate(_STRING_RE.finditer(value)):
                out.append((f"{loc}[expr{i}]", m.group(1), True))
            return
        text = clean_value(value)
        if isinstance(text, str):
            out.append((loc, text, _is_quoted_source(value)))
    elif isinstance(value, dict):
        for k, item in value.items():
            key = unquote_literal(str(k))
            if key.startswith("__"):
                continue
            _strings(item, f"{loc}.{key}", out)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _strings(item, f"{loc}[{i}]", out)


def _var_output_metadata(
    inventory: StaticInventory,
) -> tuple[dict[str, str], list[MetaString]]:
    """(variable name -> file, description/default MetaStrings for both
    variables and outputs), all in one pass over the raw per-file HCL.
    ``ParsedVariable``/``ParsedOutput`` carry no file field, and only the
    already-``clean_value``-d text, which loses the quoted/heredoc/
    expression distinction ``_strings`` needs -- so both are built here
    from ``inventory.parsed_files`` instead, the same way tag values are.
    (Outputs have no bare-name ``MetaString`` of their own -- unlike a
    resource/variable/module, an output isn't addressed by name elsewhere
    -- so no output -> file map is needed.)"""
    var_file: dict[str, str] = {}
    out: list[MetaString] = []
    for path, parsed in inventory.parsed_files.items():
        for item in parsed.get("variable", []):
            for name_q, body in item.items():
                name = unquote_literal(name_q)
                var_file[name] = path
                for key in ("description", "default"):
                    if key not in body:
                        continue
                    pairs: list[tuple[str, str, bool]] = []
                    _strings(body[key], f"variable.{name}.{key}", pairs)
                    out += [
                        MetaString(loc, path, text, quoted=q) for loc, text, q in pairs
                    ]
        for item in parsed.get("output", []):
            for name_q, body in item.items():
                name = unquote_literal(name_q)
                if "description" not in body:
                    continue
                pairs = []
                _strings(body["description"], f"output.{name}.description", pairs)
                out += [MetaString(loc, path, text, quoted=q) for loc, text, q in pairs]
    return var_file, out


def _find_comment_start(line: str) -> tuple[int, str] | None:
    """(position, marker) of the first ``#``/``//``/``/*`` on ``line`` that
    is *not* inside a quoted string, or ``None``. A single forward pass
    tracking quote state: a URL like ``"http://x"`` must not have its
    ``//`` mistaken for a comment start (that false comment's body would
    later be redacted, eating the string's own closing quote and leaving
    the file unparseable)."""
    in_str = False
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            i += 1
            continue
        if c == "#":
            return i, "#"
        if line[i : i + 2] == "//":
            return i, "//"
        if line[i : i + 2] == "/*":
            return i, "/*"
        i += 1
    return None


def _iter_comments(text: str):
    """(1-indexed line, comment body) for every ``#``/``//``/``/* */``
    comment outside a quoted string, in one forward pass over lines --
    O(len(text)) regardless of how many unterminated block comments or
    blank lines ``text`` contains. A backtracking ``/\\*(.*?)\\*/`` regex
    re-scans from every ``/*`` it can't close, which is O(n^2) on
    adversarial input with many of them; this never re-examines a
    character once it has been consumed."""
    lines = text.split("\n")
    in_block = False
    block_start = 0
    block_lines: list[str] = []
    for i, line in enumerate(lines):
        if in_block:
            end = line.find("*/")
            if end == -1:
                block_lines.append(line)
                continue
            block_lines.append(line[:end])
            body = "\n".join(block_lines).strip()
            if body:
                yield block_start, body
            in_block = False
            continue
        found = _find_comment_start(line)
        if found is None:
            continue
        pos, marker = found
        if marker == "/*":
            end = line.find("*/", pos + 2)
            if end == -1:
                in_block, block_start, block_lines = True, i + 1, [line[pos + 2 :]]
            else:
                body = line[pos + 2 : end].strip()
                if body:
                    yield i + 1, body
        else:
            body = line[pos + len(marker) :].strip()
            if body:
                yield i + 1, body


def _provider_default_tags(inventory: StaticInventory) -> list[MetaString]:
    """Tag values from every ``provider "..." { default_tags { ... } }``
    block, walked from the raw per-file HCL (``ParsedProvider.config`` is
    already ``clean_value``-d, losing the quoted/heredoc/expression
    distinction ``_strings`` needs). Handles both the common ``tags = {...}``
    shape and a nested ``tag { key ... value ... }`` block shape for free,
    since ``_strings`` recurses into whatever nested dicts/lists are there."""
    out: list[MetaString] = []
    for path, parsed in inventory.parsed_files.items():
        for item in parsed.get("provider", []):
            for name_q, body in item.items():
                name = unquote_literal(name_q)
                for block in body.get("default_tags", []):
                    if not isinstance(block, dict):
                        continue
                    pairs: list[tuple[str, str, bool]] = []
                    _strings(block, f"provider.{name}.default_tags", pairs)
                    out += [
                        MetaString(loc, path, text, quoted=q) for loc, text, q in pairs
                    ]
    return out


def collect_metadata_strings(
    inventory: StaticInventory, tf_contents: dict[str, str]
) -> list[MetaString]:
    var_file, var_output_meta = _var_output_metadata(inventory)
    out: list[MetaString] = list(var_output_meta)
    for var in inventory.variables:
        out.append(
            MetaString(
                f"variable.{var.name}",
                var_file.get(var.name, ""),
                var.name,
                name_like=True,
            )
        )
    for r in inventory.resources:
        out.append(MetaString(r.address, r.file, r.local_name, name_like=True))
        for key in _TAG_KEYS & set(r.raw_attributes):
            pairs: list[tuple[str, str, bool]] = []
            _strings(r.raw_attributes[key], f"{r.address}.{key}", pairs)
            out += [MetaString(loc, r.file, text, quoted=q) for loc, text, q in pairs]
    for m in inventory.modules:
        out.append(MetaString(f"module.{m.name}", m.file, m.name, name_like=True))
    out += _provider_default_tags(inventory)
    for path, text in sorted(tf_contents.items()):
        if path in inventory.unparsed_files:
            out += [
                MetaString(f"{path}:literal", path, m.group(1))
                for m in _STRING_RE.finditer(text)
            ]
        for line, body in _iter_comments(text):
            out.append(MetaString(f"{path}:{line}", path, body, quoted=False))
    return out


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def scan_metadata(
    inventory: StaticInventory, tf_contents: dict[str, str]
) -> list[InjectionHit]:
    hits: list[InjectionHit] = []
    for ms in collect_metadata_strings(inventory, tf_contents):
        for detector in detect(ms.text, ms.name_like):
            hits.append(
                InjectionHit(
                    detector, ms.location, ms.file, ms.text, _digest(ms.text), ms.quoted
                )
            )
    if hits:
        logger.warning(
            "Metadata scan: %d suspected prompt-injection string(s) found", len(hits)
        )
    return hits


def redaction_marker(text: str) -> str:
    return _MARKER.format(_digest(text))


def _compile(spans, bounded: bool = False) -> re.Pattern[str] | None:
    """One alternation, longest span first so a longer match always wins
    over a shorter one it contains (e.g. flagging `disregard` must not
    also truncate a match against `disregard-this-flag`).

    ``bounded`` (the bare pass only) adds lookarounds so a short bare
    text can never match as a mere substring of a longer identifier or
    literal it isn't equal to -- flagging `disregard` (from a comment)
    must not touch `disregard_me` used as a resource name, a bare
    reference to it (`aws_instance.disregard_me.id`), or an unrelated
    quoted literal (`"disregard_me"`, already excluded by the quoted
    pass's own exact-match requirement, but not by a plain substring
    search). A quote or word character immediately before/after the
    match means it's part of something bigger, so neither side may be
    one.
    """
    spans = sorted(set(spans), key=len, reverse=True)
    if not spans:
        return None
    alt = "|".join(re.escape(s) for s in spans)
    return re.compile(rf'(?<![\w"])(?:{alt})(?![\w"])' if bounded else alt)


def _bare_marker(text: str) -> str:
    """A heredoc span (the only bare-pass text that stands alone as an
    entire attribute value -- expressions are no longer scanned whole,
    see `_strings`) needs its replacement wrapped in quotes to remain a
    valid, self-contained expression; it's the only bare text that starts
    with `<<`. Everything else reaching the bare pass is a comment body,
    which accepts any text as-is -- no need to add quotes there."""
    marker = redaction_marker(text)
    return f'"{marker}"' if text.startswith("<<") else marker


def redact_contents(
    tf_contents: dict[str, str], hits: list[InjectionHit]
) -> dict[str, str]:
    """Replace every occurrence of every hit's exact span, in every file --
    not just the files a hit happens to be attributed to, since the same
    flagged text can legitimately appear in more than one file (a phrase
    flagged from a comment in one file may also sit, quoted, in another
    file's string literal). One compiled alternation per pass, one pass
    per file -- never a per-hit whole-file replace, which is O(hits x
    total size).

    Two passes, in order:

    1. Every flagged text's quoted form (`"text"`) -> a quoted marker, run
       first and against every file, so a legitimately quoted occurrence
       is always caught regardless of which hit (if any) it was
       individually attributed to. Naturally exact-match (the closing
       quote must immediately follow), so it can't clip a longer literal
       that merely contains the text.
    2. The bounded bare form (see `_compile`) of only the texts that had
       at least one *unquoted* occurrence (a comment body, or the full
       raw span of a heredoc) -> `_bare_marker`. A text that was *only*
       ever seen quoted (a resource/variable/module name) never reaches
       this pass, so an unrelated bare reference elsewhere that merely
       contains the same word is never touched.
    """
    if not hits:
        return dict(tf_contents)
    texts = {h.text for h in hits}
    bare_texts = {h.text for h in hits if not h.quoted}
    quoted_pattern = _compile(f'"{t}"' for t in texts)
    bare_pattern = _compile(bare_texts, bounded=True)
    out: dict[str, str] = {}
    for path, text in tf_contents.items():
        if quoted_pattern is not None:
            text = quoted_pattern.sub(
                lambda m: f'"{redaction_marker(m.group(0)[1:-1])}"', text
            )
        if bare_pattern is not None:
            text = bare_pattern.sub(lambda m: _bare_marker(m.group(0)), text)
        out[path] = text
    return out
