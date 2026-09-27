"""Script extraction and static rule scan for Terraform scripts (#14)."""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml  # pyright: ignore[reportMissingModuleSource]

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
