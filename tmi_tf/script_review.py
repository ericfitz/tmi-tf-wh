"""Isolated LLM script review input/output handling and findings merge (#14)."""

import html
import logging
import secrets
from typing import Any

from tmi_tf.json_extract import extract_json_array
from tmi_tf.metadata_scan import InjectionHit
from tmi_tf.script_scan import (
    CATEGORIES,
    SEVERITIES,
    RuleHit,
    ScriptBlob,
    ScriptRule,
    load_rules,
    mask_secrets,
)

logger = logging.getLogger(__name__)

REVIEW_CAP = 60_000
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_REQUIRED_STR_FIELDS = (
    "script_id",
    "title",
    "category",
    "severity",
    "evidence",
    "reason",
)
_MAX_TITLE = 200
_MAX_REASON = 1000
_MAX_EVIDENCE = 200

_rules_cache: list[ScriptRule] | None = None


def _default_rules() -> list[ScriptRule]:
    """Loaded once and cached: parse_review may be called per-item over a
    large response, and the rule file never changes mid-run."""
    global _rules_cache
    if _rules_cache is None:
        _rules_cache = load_rules()
    return _rules_cache


def _truncate(s: str, limit: int) -> str:
    return s if len(s) <= limit else s[:limit] + "…"


def _log_summary(item: Any) -> str:
    """A bounded, script-text-free summary for warning logs. Only the
    fixed-vocabulary fields (script_id/category/severity) are ever logged --
    never title/evidence/reason, which the LLM (echoing attacker-controlled
    script or metadata text) could otherwise use to push unbounded or
    injected text into logs. Always capped to 80 chars regardless."""
    if isinstance(item, dict):
        summary: Any = {k: item.get(k) for k in ("script_id", "category", "severity")}
    else:
        summary = type(item).__name__
    return repr(summary)[:80]


def _max_sev(hits: list[RuleHit]) -> int:
    return max((_SEV_RANK[h.severity] for h in hits), default=-1)


def build_review_input(
    blobs: list[ScriptBlob],
    static_hits: dict[str, list[RuleHit]],
    cap: int = REVIEW_CAP,
) -> tuple[str, str, list[str], list[str]]:
    """Wrap blobs in nonce-delimited tags; whole blobs, severity desc then size asc, until cap."""
    nonce = secrets.token_hex(6)
    order = sorted(
        blobs, key=lambda b: (-_max_sev(static_hits.get(b.id, [])), len(b.text))
    )
    parts: list[str] = []
    included: list[str] = []
    omitted: list[str] = []
    used = 0
    for b in order:
        hits = (
            ", ".join(f"{h.rule_id} ({h.severity})" for h in static_hits.get(b.id, []))
            or "none"
        )
        # id/file/hits are HTML-escaped so a blob whose id/file/rule-id
        # contains a `"` can never forge a second attribute (e.g. a fake
        # `id="..."`) inside the tag; the nonce is our own hex token, never
        # attacker-influenced, so it needs no escaping.
        esc_id = html.escape(b.id, quote=True)
        esc_file = html.escape(b.file, quote=True)
        esc_hits = html.escape(hits, quote=True)
        chunk = (
            f'<untrusted-script id="{esc_id}" nonce="{nonce}" file="{esc_file}" static_hits="{esc_hits}">\n'
            f"{b.text}\n</untrusted-script-{nonce}>\n"
        )
        if used + len(chunk) > cap:
            omitted.append(b.id)
            continue
        parts.append(chunk)
        included.append(b.id)
        used += len(chunk)
    if omitted:
        logger.warning(
            "Script review: %d blob(s) omitted by the %d-char cap: %s",
            len(omitted),
            cap,
            ", ".join(omitted),
        )
    return "".join(parts), nonce, included, omitted


def parse_review(
    text: str, sent_ids: list[str], rules: list[ScriptRule] | None = None
) -> list[dict[str, Any]]:
    """Strictly validate the LLM's JSON answer: only objects whose
    script_id was actually sent, whose category/severity are in the
    allowed sets, and whose title/evidence/reason are all present strings
    survive; everything else is discarded with a warning. Never trusts
    counts or ids from the LLM -- garbage input, non-string fields (which
    would otherwise crash a membership test with an unhashable value), or
    missing fields all yield []/discard rather than raising.

    Surviving findings have title/reason/evidence length-bounded and
    evidence run through the same secret-masking rules the static scanner
    uses, so an unbounded or credential-bearing LLM answer can't push
    unbounded or secret text into downstream threat descriptions.
    """
    parsed = extract_json_array(text) or []
    sent = set(sent_ids)
    active_rules = rules if rules is not None else _default_rules()
    valid: list[dict[str, Any]] = []
    for item in parsed:
        if not isinstance(item, dict) or any(
            not isinstance(item.get(k), str) for k in _REQUIRED_STR_FIELDS
        ):
            logger.warning(
                "Script review: discarding malformed finding: %s", _log_summary(item)
            )
            continue
        script_id, category, severity = (
            html.unescape(item["script_id"]),
            item["category"],
            item["severity"],
        )
        if script_id not in sent:
            logger.warning(
                "Script review: discarding finding with unknown script_id: %s",
                _log_summary(item),
            )
            continue
        if category not in CATEGORIES | {"other"} or severity not in SEVERITIES:
            logger.warning(
                "Script review: discarding finding with invalid category/severity: %s",
                _log_summary(item),
            )
            continue
        valid.append(
            {
                "script_id": script_id,
                "title": _truncate(item["title"], _MAX_TITLE),
                "category": category,
                "severity": severity,
                "evidence": _truncate(
                    mask_secrets(item["evidence"], active_rules), _MAX_EVIDENCE
                ),
                "reason": _truncate(item["reason"], _MAX_REASON),
            }
        )
    return valid


def merge_findings(
    blobs: list[ScriptBlob],
    static_hits: dict[str, list[RuleHit]],
    llm_findings: list[dict[str, Any]],
    injection_hits: list[InjectionHit],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Raw threats (phase-3a shape + finding_source/rule_id/digest) and note rows."""
    by_id = {b.id: b for b in blobs}
    threats: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    llm_by_key = {(f["script_id"], f["category"]): f for f in llm_findings}
    for sid, hits in static_hits.items():
        b = by_id[sid]
        for h in hits:
            llm = llm_by_key.pop((sid, h.category), None)
            desc = (
                f"Static rule {h.rule_id} ({h.title}) matched {h.count}x in script {b.digest} "
                f"on {b.component_id} ({b.attr_path}, {b.file}). Evidence: {h.evidence}"
            )
            if llm:
                desc += f" LLM review: {llm.get('reason', '')}"
            threats.append(
                {
                    "name": f"{h.title} in {b.component_id} {b.attr_path}",
                    "description": desc,
                    "affected_components": [b.component_id],
                    "finding_source": "static-rule",
                    "rule_id": h.rule_id,
                    "digest": b.digest,
                    "severity": h.severity,
                    "threat_hint": h.threat_hint,
                }
            )
            rows.append(
                {
                    "source": "static-rule",
                    "rule": h.rule_id,
                    "component": b.component_id,
                    "file": b.file,
                    "digest": b.digest,
                    "severity": h.severity,
                }
            )
    for f in llm_by_key.values():
        b = by_id[f["script_id"]]
        threats.append(
            {
                "name": f"{f['title']} in {b.component_id} {b.attr_path}",
                "description": (
                    f"LLM script review of {b.digest} on {b.component_id} ({b.file}): "
                    f"{f.get('reason', '')} Evidence: {str(f.get('evidence', ''))[:200]}"
                ),
                "affected_components": [b.component_id],
                "finding_source": "script-review",
                "rule_id": f["category"],
                "digest": b.digest,
                "severity": f["severity"],
            }
        )
        rows.append(
            {
                "source": "script-review",
                "rule": f["category"],
                "component": b.component_id,
                "file": b.file,
                "digest": b.digest,
                "severity": f["severity"],
            }
        )
    for h in injection_hits:
        threats.append(
            {
                "name": f"Suspected prompt injection in {h.location}",
                "description": (
                    f"Metadata scan detector '{h.detector}' flagged the string at {h.location} "
                    f"({h.file}), sha256:{h.digest}. The string was redacted from all LLM input; "
                    "it may be an attempt to manipulate automated review tooling."
                ),
                "affected_components": [h.location],
                "finding_source": "injection-scan",
                "rule_id": h.detector,
                "digest": h.digest,
                "severity": "Medium",
            }
        )
        rows.append(
            {
                "source": "injection-scan",
                "rule": h.detector,
                "component": h.location,
                "file": h.file,
                "digest": h.digest,
                "severity": "Medium",
            }
        )
    return threats, rows
