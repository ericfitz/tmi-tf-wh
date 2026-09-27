"""Isolated LLM script review input/output handling and findings merge (#14)."""

import logging
import secrets
from typing import Any

from tmi_tf.json_extract import extract_json_array
from tmi_tf.metadata_scan import InjectionHit
from tmi_tf.script_scan import CATEGORIES, SEVERITIES, RuleHit, ScriptBlob

logger = logging.getLogger(__name__)

REVIEW_CAP = 60_000
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


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
        chunk = (
            f'<untrusted-script id="{b.id}" nonce="{nonce}" file="{b.file}" static_hits="{hits}">\n'
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


def parse_review(text: str, sent_ids: list[str]) -> list[dict[str, Any]]:
    """Strictly validate the LLM's JSON answer: only objects whose
    script_id was actually sent and whose category/severity are in the
    allowed sets survive; everything else is discarded with a warning.
    Never trusts counts or ids from the LLM -- garbage input yields []."""
    parsed = extract_json_array(text) or []
    sent = set(sent_ids)
    valid: list[dict[str, Any]] = []
    for item in parsed:
        if not isinstance(item, dict) or item.get("script_id") not in sent:
            logger.warning(
                "Script review: discarding finding with unknown script_id: %r", item
            )
            continue
        if (
            item.get("category") not in CATEGORIES | {"other"}
            or item.get("severity") not in SEVERITIES
        ):
            logger.warning(
                "Script review: discarding finding with invalid category/severity: %r",
                item,
            )
            continue
        valid.append(item)
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
