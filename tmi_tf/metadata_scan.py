"""Prompt-injection scan of Terraform metadata and redaction (#14)."""

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Any

from tmi_tf.tf_parser import StaticInventory, clean_value, unquote_literal

logger = logging.getLogger(__name__)

_INSTRUCTION_RE = re.compile(
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|prompts|rules)"
    r"|you are now\b|^\s*(system|assistant|user)\s*:|\bdisregard\b|new instructions"
    r"|</?untrusted|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<<SYS>>"
    r"|do not (report|flag|mention)|mark (it |this |everything )?as (safe|benign)"
    r"|(no|zero) (threats|findings)",
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
_LINE_LOC_RE = re.compile(r":(\d+)$")
_MARKER = "[redacted: suspected prompt injection, sha256:{}]"


@dataclass
class MetaString:
    location: str
    file: str
    text: str
    name_like: bool = False


@dataclass
class InjectionHit:
    detector: str
    location: str
    file: str
    text: str
    digest: str


def detect(text: str, name_like: bool = False) -> list[str]:
    found: list[str] = []
    if _INSTRUCTION_RE.search(text):
        found.append("instruction")
    if _INVISIBLE_RE.search(text):
        found.append("invisible_unicode")
    if name_like and len(text.split()) > _SENTENCE_WORDS:
        found.append("sentence")
    return found


def _strings(value: Any, loc: str, out: list[tuple[str, str]]) -> None:
    v = clean_value(value)
    if isinstance(v, str):
        out.append((loc, v))
    elif isinstance(v, dict):
        for k, item in v.items():
            _strings(item, f"{loc}.{unquote_literal(str(k))}", out)
    elif isinstance(v, list):
        for i, item in enumerate(v):
            _strings(item, f"{loc}[{i}]", out)


def _declaration_files(
    inventory: StaticInventory,
) -> tuple[dict[str, str], dict[str, str]]:
    """name -> file for every ``variable``/``output`` block, in one pass over
    the parsed per-file HCL. ``ParsedVariable``/``ParsedOutput`` carry no
    file field, and every entry in ``inventory.variables``/``.outputs`` was
    necessarily parsed from one of these files (an unparsed file never
    populates them), so this always resolves."""
    var_file: dict[str, str] = {}
    output_file: dict[str, str] = {}
    for path, parsed in inventory.parsed_files.items():
        for item in parsed.get("variable", []):
            for name_q in item:
                var_file[unquote_literal(name_q)] = path
        for item in parsed.get("output", []):
            for name_q in item:
                output_file[unquote_literal(name_q)] = path
    return var_file, output_file


def _iter_comments(text: str):
    """(1-indexed line, comment body) for every ``#``/``//``/``/* */``
    comment, in one forward pass over lines -- O(len(text)) regardless of
    how many unterminated block comments or blank lines ``text`` contains.
    A backtracking ``/\\*(.*?)\\*/`` regex re-scans from every ``/*`` it
    can't close, which is O(n^2) on adversarial input with many of them;
    this never re-examines a character once it has been consumed."""
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
        starts = [
            (p, marker)
            for marker in ("#", "//", "/*")
            if (p := line.find(marker)) != -1
        ]
        if not starts:
            continue
        pos, marker = min(starts)
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


def collect_metadata_strings(
    inventory: StaticInventory, tf_contents: dict[str, str]
) -> list[MetaString]:
    var_file, output_file = _declaration_files(inventory)
    out: list[MetaString] = []
    for var in inventory.variables:
        file = var_file.get(var.name, "")
        if var.description:
            out.append(
                MetaString(f"variable.{var.name}.description", file, var.description)
            )
        if isinstance(var.default, str):
            out.append(MetaString(f"variable.{var.name}.default", file, var.default))
        out.append(MetaString(f"variable.{var.name}", file, var.name, name_like=True))
    for o in inventory.outputs:
        if o.description:
            out.append(
                MetaString(
                    f"output.{o.name}.description",
                    output_file.get(o.name, ""),
                    o.description,
                )
            )
    for r in inventory.resources:
        out.append(MetaString(r.address, r.file, r.local_name, name_like=True))
        for key in _TAG_KEYS & set(r.raw_attributes):
            pairs: list[tuple[str, str]] = []
            _strings(r.raw_attributes[key], f"{r.address}.{key}", pairs)
            out += [MetaString(loc, r.file, text) for loc, text in pairs]
    for m in inventory.modules:
        out.append(MetaString(f"module.{m.name}", m.file, m.name, name_like=True))
    for path, text in sorted(tf_contents.items()):
        if path in inventory.unparsed_files:
            out += [
                MetaString(f"{path}:literal", path, m.group(1))
                for m in _STRING_RE.finditer(text)
            ]
            continue
        for line, body in _iter_comments(text):
            out.append(MetaString(f"{path}:{line}", path, body))
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
                InjectionHit(detector, ms.location, ms.file, ms.text, _digest(ms.text))
            )
    if hits:
        logger.warning(
            "Metadata scan: %d suspected prompt-injection string(s) redacted", len(hits)
        )
    return hits


def redaction_marker(text: str) -> str:
    return _MARKER.format(_digest(text))


def _redact_file(text: str, hits: list[InjectionHit]) -> str:
    line_hits: dict[int, list[InjectionHit]] = {}
    literal_hits: list[InjectionHit] = []
    for h in hits:
        m = _LINE_LOC_RE.search(h.location)
        (line_hits.setdefault(int(m.group(1)), []) if m else literal_hits).append(h)
    if line_hits:
        lines = text.split("\n")
        for lineno, lhits in line_hits.items():
            idx = lineno - 1
            if 0 <= idx < len(lines):
                for h in sorted(lhits, key=lambda h: -len(h.text)):
                    lines[idx] = lines[idx].replace(h.text, redaction_marker(h.text), 1)
        text = "\n".join(lines)
    if literal_hits:
        # Quoted-form match: a hit's text is a decoded literal, always
        # double-quoted at its declaration site (attribute value or block
        # label), so matching `"text"` rather than bare `text` can't also
        # clip a *different*, unflagged literal that merely contains this
        # text as a substring (e.g. flagging `disregard` must not also
        # truncate `"disregard-this-flag"`).
        ordered = sorted({h.text for h in literal_hits}, key=len, reverse=True)
        pattern = re.compile("|".join(re.escape(f'"{t}"') for t in ordered))
        markers = {f'"{t}"': f'"{redaction_marker(t)}"' for t in ordered}
        text = pattern.sub(lambda m: markers[m.group(0)], text)
    return text


def redact_contents(
    tf_contents: dict[str, str], hits: list[InjectionHit]
) -> dict[str, str]:
    """Redact each hit's exact span, copying and rebuilding each affected
    file exactly once regardless of how many hits target it (never a
    whole-file ``str.replace`` per hit, which is O(hits x file size))."""
    out = dict(tf_contents)
    by_file: dict[str, list[InjectionHit]] = {}
    for h in hits:
        if h.file in out:
            by_file.setdefault(h.file, []).append(h)
    for file, file_hits in by_file.items():
        out[file] = _redact_file(out[file], file_hits)
    return out
