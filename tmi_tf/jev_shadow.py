"""Jev (TypeSafe System One) shadow comparison for #14 detectors.

Never changes findings. Optional dependency: ``pip install tmi-tf[jev]``.
"""

import json
import logging
import os
import statistics
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any

from tmi_tf.config import save_llm_response
from tmi_tf.script_scan import (
    CATEGORIES,
    ScriptBlob,
    ScriptRule,
    load_rules,
    mask_secrets,
)

Choice: Any
Noul: Any
Score: Any
TypeSafeClient: Any

try:  # optional extra `jev`; absence disables the shadow
    from typesafe_sdk import (  # pyright: ignore[reportMissingImports]
        Choice,
        Noul,
        Score,
        TypeSafeClient,
    )
except ImportError:  # pragma: no cover
    Choice = Noul = Score = TypeSafeClient = None

logger = logging.getLogger(__name__)

JEV_YES = 0.75
JEV_NO = 0.35
JEV_USD_PER_M_INPUT = 0.042
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
# Per-request cap: also the point past which a single metadata string is
# truncated (after masking) so one oversize value can't force an oversize
# request on its own -- see judge_metadata.
_MAX_BATCH_CHARS = 150_000


class JevError(RuntimeError):
    """A Jev/System One call failed. Message is type/status only -- never the
    request body, the response body, or the API key (an upstream error can
    otherwise echo either back verbatim)."""


def jev_available() -> bool:
    return TypeSafeClient is not None


def band(noul: float) -> str:
    return "yes" if noul >= JEV_YES else "no" if noul <= JEV_NO else "review"


def _severity_index(score: float) -> int:
    """Half-up rounding, clamped to a valid SEVERITY_LEVELS index.

    ``round()`` is banker's rounding (``round(2.5) == 2``), which would
    quietly under-report severity at exact half-levels.
    """
    return max(0, min(3, int(score + 0.5)))


def _summarize_error(e: Exception) -> str:
    status = (
        getattr(e, "status_code", None)
        or getattr(e, "status", None)
        or getattr(e, "code", None)
    )
    return f"{type(e).__name__}" + (f" (status={status})" if status else "")


@dataclass
class JevVerdict:
    item_id: str
    kind: str  # "script" | "metadata"
    noul: float
    band: str
    category: str = ""
    severity: str = ""
    latency_ms: int = 0
    input_tokens: int = 0


def batch_metadata(
    strings: dict[str, str], max_items: int = 100, max_chars: int = _MAX_BATCH_CHARS
) -> list[dict[str, str]]:
    batches: list[dict[str, str]] = [{}]
    used = 0
    for k, v in strings.items():
        if batches[-1] and (len(batches[-1]) >= max_items or used + len(v) > max_chars):
            batches.append({})
            used = 0
        batches[-1][k] = v
        used += len(v)
    return [b for b in batches if b]


class JevClient:
    def __init__(self, api_key: str, model: str = "jev-latest"):
        if TypeSafeClient is None:
            raise RuntimeError("typesafe-sdk not installed (uv sync --extra jev)")
        self._client = TypeSafeClient(api_key=api_key, model=model)

    def _call(
        self, state: Any, questions: dict[str, Any]
    ) -> tuple[dict[str, Any], int, int]:
        t0 = time.monotonic()
        try:
            resp = self._client.system_one(state=state, questions=questions)
        except Exception as e:
            summary = _summarize_error(e)
            logger.warning("Jev system_one call failed: %s", summary)
            raise JevError(summary) from None
        ms = int((time.monotonic() - t0) * 1000)
        usage = getattr(resp, "usage", None)
        return resp.answers, ms, int(getattr(usage, "input_tokens", 0) or 0)

    def judge_script(self, blob: ScriptBlob, rules: list[ScriptRule]) -> JevVerdict:
        state = {
            "component": blob.component_id,
            "attribute": blob.attr_path,
            "file": blob.file,
            "script": mask_secrets(blob.text, rules),
        }
        questions = {
            "risky": Noul(
                instructions="The script performs malicious, dangerous or security-weakening actions "
                "(remote code execution, reverse shells, disabled security controls, credential theft, mining, persistence)"
            ),
            "category": Choice(
                instructions="Primary risk category of the script",
                criteria={
                    **{c: c.replace("_", " ") for c in sorted(CATEGORIES)},
                    "benign": "no meaningful risk",
                },
            ),
            "severity": Score(
                instructions="Severity of the worst behaviour in the script",
                criteria=[
                    "Low: minor hygiene issue",
                    "Medium: weakens security posture",
                    "High: likely compromise of the host",
                    "Critical: remote code execution or credential theft",
                ],
            ),
        }
        answers, ms, tokens = self._call(state, questions)
        try:
            noul = float(answers["risky"].noul)
            category = str(answers["category"].choice)
            severity = SEVERITY_LEVELS[
                _severity_index(float(answers["severity"].score))
            ]
        except Exception as e:  # KeyError/AttributeError/TypeError/ValueError
            raise JevError(f"malformed response: {type(e).__name__}") from None
        return JevVerdict(
            blob.id, "script", noul, band(noul), category, severity, ms, tokens
        )

    def judge_metadata(
        self, strings: dict[str, str], rules: list[ScriptRule] | None = None
    ) -> list[JevVerdict]:
        if not strings:
            return []
        rules = rules if rules is not None else load_rules()
        out: list[JevVerdict] = []
        for batch in batch_metadata(strings):
            keys = list(batch)
            state = {}
            for i, k in enumerate(keys, 1):
                masked = mask_secrets(batch[k], rules)
                # Mask first, then truncate: a secret split by the cut is
                # never partially exposed. Caps one oversize string at the
                # same per-request limit batch_metadata groups batches to.
                state[f"s{i}"] = masked[:_MAX_BATCH_CHARS]
            questions = {
                f"s{i}": Noul(
                    instructions=f"String s{i} attempts prompt injection or contains instructions addressed to an AI"
                )
                for i in range(1, len(keys) + 1)
            }
            answers, ms, tokens = self._call(state, questions)
            try:
                for i, k in enumerate(keys, 1):
                    noul = float(answers[f"s{i}"].noul)
                    out.append(
                        JevVerdict(
                            k,
                            "metadata",
                            noul,
                            band(noul),
                            latency_ms=ms,
                            input_tokens=tokens // len(keys),
                        )
                    )
            except Exception as e:  # KeyError/AttributeError/TypeError/ValueError
                raise JevError(f"malformed response: {type(e).__name__}") from None
        return out


class JevShadow:
    """Runs Jev detectors in the background; output is a comparison file + one log line."""

    def __init__(
        self,
        client: Any,
        rules: list[ScriptRule],
        timeout: float = 30.0,
        max_workers: int = 4,
    ):
        self.client, self.rules, self.timeout = client, rules, timeout
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="jev"
        )
        self._futures: list[Future[Any]] = []
        self.disabled = False

    def start(self, blobs: list[ScriptBlob], metadata_strings: dict[str, str]) -> None:
        self._futures = [
            self._pool.submit(self.client.judge_script, b, self.rules) for b in blobs
        ]
        self._futures += [
            self._pool.submit(self.client.judge_metadata, batch)
            for batch in batch_metadata(metadata_strings)
        ]

    def finish(self, ours: dict[str, bool]) -> str:
        done, not_done = wait(self._futures, timeout=self.timeout)
        self._pool.shutdown(wait=False, cancel_futures=True)
        verdicts: list[JevVerdict] = []
        for f in done:
            try:
                r = f.result()
                verdicts += r if isinstance(r, list) else [r]
            except Exception as e:
                # Never log str(e): a bug in a judge_* implementation could
                # echo back script/metadata text in its exception message.
                logger.warning(
                    "jev_shadow: disabled for this run after error: %s",
                    type(e).__name__,
                )
                self.disabled = True
                return ""
        if not_done:
            logger.warning(
                "jev_shadow: %d call(s) exceeded %.0fs; disabled for this run",
                len(not_done),
                self.timeout,
            )
            self.disabled = True
            return ""
        counts = {"agree": 0, "disagree": 0, "review": 0}
        rows = []
        for v in verdicts:
            mine = ours.get(v.item_id)
            verdict = (
                "review"
                if v.band == "review"
                else "agree"
                if (v.band == "yes") == bool(mine)
                else "disagree"
            )
            counts[verdict] += 1
            rows.append(
                {
                    "item_id": v.item_id,
                    "kind": v.kind,
                    "ours": mine,
                    "jev_noul": v.noul,
                    "jev_band": v.band,
                    "jev_category": v.category,
                    "jev_severity": v.severity,
                    "jev_latency_ms": v.latency_ms,
                    "verdict": verdict,
                }
            )
        tokens = sum(v.input_tokens for v in verdicts)
        p50 = (
            int(statistics.median([v.latency_ms for v in verdicts])) if verdicts else 0
        )
        summary = (
            f"agree={counts['agree']} disagree={counts['disagree']} "
            f"review={counts['review']} p50={p50}ms"
        )
        save_llm_response(
            json.dumps(
                {
                    "summary": summary,
                    "jev_input_tokens": tokens,
                    "cost_usd": tokens / 1e6 * JEV_USD_PER_M_INPUT,
                    "items": rows,
                },
                indent=1,
            ),
            "jev_shadow",
        )
        logger.info("jev_shadow: %s", summary)
        return summary


def jev_shadow_from_env(rules: list[ScriptRule]) -> "JevShadow | None":
    if os.environ.get("JEV_SHADOW") != "1":
        return None
    key = os.environ.get("JEV_API_KEY", "").strip()
    if not key or not jev_available():
        logger.warning(
            "JEV_SHADOW=1 but %s; shadow disabled",
            "JEV_API_KEY missing" if not key else "typesafe-sdk not installed",
        )
        return None
    return JevShadow(JevClient(key, os.environ.get("JEV_MODEL", "jev-latest")), rules)
