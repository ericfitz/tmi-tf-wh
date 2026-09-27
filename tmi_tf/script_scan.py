"""Script extraction and static rule scan for Terraform scripts (#14)."""

import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml  # pyright: ignore[reportMissingModuleSource]

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
    for entry in raw["rules"]:
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
    """One grouped hit per rule that matches ``text``."""
    hits: list[RuleHit] = []
    for rule in rules:
        matches = list(rule.pattern.finditer(text))
        if not matches:
            continue
        evidence = (
            MASKED if rule.secret else matches[0].group(0).strip()[:_EVIDENCE_CHARS]
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
