"""Jev (TypeSafe System One) shadow comparison for #14 detectors.

Never changes findings. Optional dependency: ``pip install tmi-tf[jev]``.
"""

import json
import logging
import os
import queue
import statistics
import threading
import time
from collections.abc import Callable
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
    """Runs Jev detectors in the background; output is a comparison file + one log line.

    Workers are per-run: created fresh in ``start()``, never reused, and
    never joined in ``finish()`` -- not a persistent pool built in
    ``__init__``. ``analyzer.py`` builds one ``LLMAnalyzer``/shadow and
    calls ``analyze_repository`` in a loop over repos, so a persistent
    ``ThreadPoolExecutor`` shut down at the end of the first repo's
    ``finish()`` would raise "cannot schedule new futures after shutdown"
    on every subsequent repo's ``start()``.

    Workers are plain ``daemon=True`` threads pulling from a bounded job
    queue (never a ``ThreadPoolExecutor``): a non-daemon pool thread that's
    still running a hung SDK call past ``finish()``'s timeout is joined by
    ``concurrent.futures`` at interpreter exit, delaying process exit and
    leaking a thread per timed-out run. A daemon thread is simply abandoned
    -- ``finish()`` waits up to ``timeout`` for results and returns without
    joining stragglers, and the straggler can never block process exit.
    """

    def __init__(
        self,
        client: Any,
        rules: list[ScriptRule],
        timeout: float = 30.0,
        max_workers: int = 4,
    ):
        self.client, self.rules, self.timeout, self.max_workers = (
            client,
            rules,
            timeout,
            max_workers,
        )
        self.disabled = False
        self._results: queue.Queue[Any] = queue.Queue()
        self._threads: list[threading.Thread] = []
        self._expected = 0

    @staticmethod
    def _worker(
        jobs: "queue.Queue[Callable[[], Any]]", results: "queue.Queue[Any]"
    ) -> None:
        while True:
            try:
                job = jobs.get_nowait()
            except queue.Empty:
                return
            try:
                results.put(job())
            except Exception as e:  # forwarded to finish(), never raised here
                results.put(e)

    def start(self, blobs: list[ScriptBlob], metadata_strings: dict[str, str]) -> None:
        jobs: queue.Queue[Callable[[], Any]] = queue.Queue()
        for b in blobs:
            jobs.put(lambda b=b: self.client.judge_script(b, self.rules))
        for batch in batch_metadata(metadata_strings):
            jobs.put(lambda batch=batch: self.client.judge_metadata(batch))
        self._expected = jobs.qsize()
        # A fresh queue per run, passed to workers by value (not looked up
        # via self._results at completion time): a straggler abandoned by a
        # prior run's finish() must keep writing to *that* run's queue, not
        # whatever queue self._results has been reassigned to by a later
        # start() -- otherwise its late result could pollute the next run's
        # comparison.
        results: queue.Queue[Any] = queue.Queue()
        self._results = results
        self._threads = [
            threading.Thread(
                target=self._worker, args=(jobs, results), name=f"jev-{i}", daemon=True
            )
            for i in range(min(self.max_workers, self._expected))
        ]
        for t in self._threads:
            t.start()

    def finish(self, ours: dict[str, bool]) -> str:
        deadline = time.monotonic() + self.timeout
        results: list[Any] = []
        while len(results) < self._expected:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                results.append(self._results.get(timeout=remaining))
            except queue.Empty:
                break
        if len(results) < self._expected:
            logger.warning(
                "jev_shadow: %d call(s) exceeded %gs; disabled for this run",
                self._expected - len(results),
                self.timeout,
            )
            self.disabled = True
            return ""
        verdicts: list[JevVerdict] = []
        for r in results:
            if isinstance(r, Exception):
                # Never log str(r): a bug in a judge_* implementation could
                # echo back script/metadata text in its exception message.
                logger.warning(
                    "jev_shadow: disabled for this run after error: %s",
                    type(r).__name__,
                )
                self.disabled = True
                return ""
            verdicts += r if isinstance(r, list) else [r]
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
        rows.sort(key=lambda r: r["item_id"])  # deterministic output
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
        logger.info("JEV_SHADOW not set to 1; jev shadow disabled")
        return None
    key = os.environ.get("JEV_API_KEY", "").strip()
    if not key or not jev_available():
        logger.warning(
            "JEV_SHADOW=1 but %s; shadow disabled",
            "JEV_API_KEY missing" if not key else "typesafe-sdk not installed",
        )
        return None
    # ponytail: JevClient doesn't pass this shadow's `timeout` down to
    # TypeSafeClient -- the real typesafe-sdk isn't installed in this repo,
    # so whether TypeSafeClient.__init__ even accepts a timeout kwarg is
    # unconfirmed (the one usage example available, jev-usecases/src/
    # jev_usecases/client.py, only passes api_key/model). Upgrade once
    # confirmed: JevClient(key, model, timeout=timeout) plumbed through to
    # TypeSafeClient(..., timeout=timeout), so a slow SDK call fails fast
    # instead of relying solely on JevShadow's own thread-level timeout.
    return JevShadow(JevClient(key, os.environ.get("JEV_MODEL", "jev-latest")), rules)
