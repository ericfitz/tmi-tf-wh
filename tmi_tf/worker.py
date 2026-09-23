"""Async worker pool for OCI Queue job processing."""

import asyncio
import logging
import shutil
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tmi_tf.addon_callback import AddonCallback
from tmi_tf.analyzer import resolve_fanout_targets, run_analysis
from tmi_tf.config import Config
from tmi_tf.invocation import (
    all_reported,
    close_invocation,
    compute_deadline,
    lock_for,
    mark_child,
    open_invocation,
    outcome_of,
    read_state,
)
from tmi_tf.job import Job
from tmi_tf.providers import QueueMessage, QueueProvider
from tmi_tf.repo_analyzer import repository_name
from tmi_tf.tmi_client_wrapper import STATUS_NOTE_NAME, AnalysisAborted, TMIClient

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 5


def _is_message_expired(enqueued_at_iso: str, max_age_hours: int) -> bool:
    """Return True if the message is older than max_age_hours.

    Args:
        enqueued_at_iso: ISO-format datetime string (UTC).
        max_age_hours: Maximum allowed age in hours.

    Returns:
        True if the message age >= max_age_hours, False otherwise.
        Returns True (expired) if the timestamp cannot be parsed.
    """
    try:
        enqueued_at = datetime.fromisoformat(enqueued_at_iso)
        # Ensure timezone-aware comparison
        if enqueued_at.tzinfo is None:
            enqueued_at = enqueued_at.replace(tzinfo=timezone.utc)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        return enqueued_at <= cutoff
    except (ValueError, TypeError):
        logger.warning("Could not parse enqueued_at timestamp: %r", enqueued_at_iso)
        return True


class WorkerPool:
    """Async worker pool that polls OCI Queue and dispatches analysis jobs."""

    def __init__(self, queue_client: QueueProvider, config: Config) -> None:
        self.queue_client = queue_client
        self.config = config
        self.max_concurrent = config.max_concurrent_jobs
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._active_jobs: dict[str, Job] = {}
        self._watchdogs: dict[str, asyncio.Task] = {}  # type: ignore[type-arg]
        self._running = False
        # Per-process, never pruned (single replica; a restart clears it along
        # with everything else in-memory).
        self._cancelled: set[str] = set()
        self._tasks: dict[str, asyncio.Task] = {}  # type: ignore[type-arg]
        self._cancel_events: dict[str, threading.Event] = {}
        self._receipts: dict[str, str] = {}
        # invocation_id -> (threat_model_id, callback_url), so abort() can find
        # an invocation with no running job (parent finished, children still
        # queued). Written when the parent opens the invocation and again
        # whenever a child is dequeued; never pruned (see _cancelled above).
        self._invocations: dict[str, tuple[str, str | None]] = {}

    async def start(self) -> None:
        """Start polling loop."""
        self._running = True
        while self._running:
            try:
                await self._poll_and_dispatch()
            except Exception as e:
                logger.error(f"Worker pool error: {e}")
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    async def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False

    async def _poll_and_dispatch(self) -> None:
        """Poll queue, dispatch to workers. Only consume up to available slots."""
        available = self.max_concurrent - len(self._active_jobs)
        if available <= 0:
            return
        # Visibility must cover the whole job, else the queue redelivers it
        # mid-run and DLQs it after maxReceiveCount.
        messages = await asyncio.to_thread(
            self.queue_client.consume,
            max_messages=available,
            visibility_timeout=self.config.job_timeout,
        )
        for msg in messages:
            asyncio.create_task(self._handle_message(msg))

    async def _handle_message(self, msg: QueueMessage) -> None:
        """Check age, dispatch job with timeout."""
        # Check message age
        enqueued_at = msg.body.get("enqueued_at", "")
        if _is_message_expired(enqueued_at, self.config.max_message_age_hours):
            logger.warning(f"Discarding stale message: job_id={msg.body.get('job_id')}")
            await asyncio.to_thread(self.queue_client.delete, msg.receipt)
            return

        job = Job.from_queue_message(msg.body)
        if job.invocation_key in self._cancelled:
            logger.info("Dropping queued job %s: invocation aborted", job.job_id)
            await asyncio.to_thread(self.queue_client.delete, msg.receipt)
            if job.is_child:
                await self._finish_child(job, "aborted")
            return

        job.temp_dir = Path(tempfile.mkdtemp(prefix=f"tmi-tf-{job.job_id}-"))
        if job.is_child and job.siblings and job.deadline:
            self._invocations[job.invocation_key] = (
                job.threat_model_id,
                job.callback_url,
            )
            self._arm_watchdog(
                job.threat_model_id,
                job.job_id.rsplit(":", 1)[0],
                job.siblings,
                job.deadline,
                job.callback_url,
            )

        async with self._semaphore:
            try:
                # A job can sit here a while behind a full pool; the invocation
                # may have been aborted since the first check above.
                if job.invocation_key in self._cancelled:
                    logger.info(
                        "Dropping job %s after semaphore wait: invocation aborted",
                        job.job_id,
                    )
                    await asyncio.to_thread(self.queue_client.delete, msg.receipt)
                    if job.is_child:
                        await self._finish_child(job, "aborted")
                    return
                self._active_jobs[job.job_id] = job
                self._receipts[job.job_id] = msg.receipt
                self._cancel_events[job.job_id] = threading.Event()
                self._tasks[job.job_id] = asyncio.current_task()  # type: ignore[assignment]
                try:
                    await asyncio.wait_for(
                        self._run_job(job, msg.receipt),
                        timeout=self.config.job_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.error(f"Job timed out: job_id={job.job_id}")
                    # Delete message — don't retry timed out jobs
                    try:
                        await asyncio.to_thread(self.queue_client.delete, msg.receipt)
                    except Exception as e:
                        logger.error(f"Failed to delete timed-out message: {e}")
                    # Best-effort status updates
                    if job.is_child:
                        await self._finish_child(job, "failed")
                    else:
                        await self._fire_and_forget_status(
                            job, "failed", "Job timed out"
                        )
                except asyncio.CancelledError:
                    logger.info("Job cancelled: %s", job.job_id)
                    # Do not re-raise; the abort path already did the bookkeeping.
            finally:
                self._active_jobs.pop(job.job_id, None)
                self._receipts.pop(job.job_id, None)
                self._cancel_events.pop(job.job_id, None)
                self._tasks.pop(job.job_id, None)
                if job.temp_dir and job.temp_dir.exists():
                    try:
                        shutil.rmtree(job.temp_dir)
                    except Exception as e:
                        logger.warning(f"Failed to clean up {job.temp_dir}: {e}")

    async def _run_job(self, job: Job, receipt: str) -> None:
        """Run analysis in thread pool."""
        callback = None
        if job.callback_url and self.config.webhook_secret:
            callback = AddonCallback(job.callback_url, self.config.webhook_secret)
            if not job.is_child:
                callback.send_status("in_progress")

        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            tmi_client.cancel_event = self._cancel_events.get(job.job_id)
            if job.is_child:
                # Unique per (repository, environment) so two repos with the
                # same environment name do not overwrite each other (#56).
                suffix = " - ".join(x for x in (job.repo_name, job.environment) if x)
                if suffix:
                    tmi_client.status_note_name = f"{STATUS_NOTE_NAME} - {suffix}"
                result = await asyncio.to_thread(
                    run_analysis,
                    config=self.config,
                    threat_model_id=job.threat_model_id,
                    tmi_client=tmi_client,
                    repo_id=job.repo_id,
                    temp_dir=job.temp_dir,
                    callback=callback,
                    environment=job.environment,
                )
                await self._finish_child(job, "success" if result.success else "failed")
            else:
                await self._run_parent(job, tmi_client, callback)
            # Delete message on completion
            await asyncio.to_thread(self.queue_client.delete, receipt)
        except AnalysisAborted:
            logger.info("Job %s aborted", job.job_id)
        except Exception as e:
            logger.error(f"Job exception: job_id={job.job_id}, error={e}")
            if job.is_child:
                await self._finish_child(job, "failed")
            elif callback:
                callback.send_status("failed", str(e))
            # Don't delete — let visibility timeout handle retry

    async def _run_parent(
        self, job: Job, tmi_client: TMIClient, callback: AddonCallback | None
    ) -> None:
        """Resolve fan-out targets and enqueue one child job per environment."""
        targets = await asyncio.to_thread(
            resolve_fanout_targets,
            self.config,
            job.threat_model_id,
            tmi_client,
            job.scope,
            repo_id=job.repo_id,
            temp_dir=job.temp_dir,
        )
        if not targets:
            logger.info("Parent job %s: no environments matched", job.job_id)
            if callback:
                callback.send_status("completed", "no environments matched")
            return
        now = datetime.now(timezone.utc)
        deadline = compute_deadline(
            now, len(targets), self.max_concurrent, self.config.job_timeout
        )
        children = [
            Job(
                job_id=f"{job.job_id}:{t.environment or 'all'}",
                threat_model_id=job.threat_model_id,
                event_type=job.event_type,
                enqueued_at=now,
                repo_id=t.repo_id,
                callback_url=job.callback_url,
                invocation_id=job.invocation_id,
                environment=t.environment,
                repo_name=repository_name(t.repo_url),
                deadline=deadline,
            )
            for t in targets
        ]
        siblings = [c.job_id for c in children]
        for c in children:
            c.siblings = siblings
        await asyncio.to_thread(
            open_invocation,
            tmi_client,
            job.threat_model_id,
            job.job_id,
            siblings,
            deadline,
        )
        self._invocations[job.job_id] = (job.threat_model_id, job.callback_url)
        self._arm_watchdog(
            job.threat_model_id, job.job_id, siblings, deadline, job.callback_url
        )
        enqueued = 0
        for child in children:
            try:
                await asyncio.to_thread(
                    self.queue_client.publish, child.to_queue_message()
                )
                enqueued += 1
            except Exception as e:
                msg = f"Failed to enqueue environment {child.environment!r}: {e}"
                logger.error(msg)
                try:
                    tmi_client.update_status_note(job.threat_model_id, msg)
                    mark_child(tmi_client, job.threat_model_id, child.job_id, "failed")
                except Exception as note_err:
                    logger.error(f"Failed to record enqueue failure: {note_err}")
        if enqueued == 0:
            summary = f"0 succeeded, {len(targets)} failed ({', '.join(siblings)})"
            async with lock_for(job.threat_model_id):
                await asyncio.to_thread(
                    close_invocation,
                    tmi_client,
                    job.threat_model_id,
                    f"Invocation complete: {summary}",
                )
            wd = self._watchdogs.pop(job.threat_model_id, None)
            if wd:
                wd.cancel()
            logger.info("Parent job %s: %s", job.job_id, summary)
            if callback:
                callback.send_status("failed", summary)
            return
        summary = f"enqueued {enqueued} of {len(targets)} environment jobs"
        logger.info("Parent job %s: %s", job.job_id, summary)
        if callback:
            callback.send_status("in_progress", summary)

    async def abort(self, invocation_id: str, reason: str) -> int:
        """Stop every job of an invocation; queued children are dropped when dequeued.

        invocation_id is the parent job id (Job.invocation_key /
        InvocationState.invocation_id) — not Job.invocation_id, which is the
        addon's x-invocation-id delivery header.

        Returns the number of running jobs cancelled, regardless of whether
        the TMI bookkeeping below (marking children, closing the invocation)
        finds anything to do.
        """
        self._cancelled.add(invocation_id)
        victims = [
            j
            for j in list(self._active_jobs.values())
            if j.invocation_key == invocation_id
        ]
        for job in victims:
            ev = self._cancel_events.get(job.job_id)
            if ev:
                ev.set()
            task = self._tasks.get(job.job_id)
            if task:
                task.cancel()
            receipt = self._receipts.get(job.job_id)
            if receipt:
                try:
                    await asyncio.to_thread(self.queue_client.delete, receipt)
                except Exception as e:
                    logger.error(f"Failed to delete message for {job.job_id}: {e}")
            if job.temp_dir and job.temp_dir.exists():
                shutil.rmtree(job.temp_dir, ignore_errors=True)
        wd = self._watchdogs.pop(next((j.threat_model_id for j in victims), ""), None)
        if wd:
            wd.cancel()

        if victims:
            threat_model_id = victims[0].threat_model_id
            callback_url = next(
                (j.callback_url for j in victims if j.callback_url), None
            )
        else:
            # No running job — e.g. the parent already finished and children
            # are still queued. Fall back to what we recorded when the
            # invocation was opened / a child was last dequeued.
            cached = self._invocations.get(invocation_id)
            threat_model_id, callback_url = cached if cached else (None, None)
        if threat_model_id is None:
            return len(victims)

        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            async with lock_for(threat_model_id):
                state = await asyncio.to_thread(read_state, tmi_client, threat_model_id)
                if not state.open or state.invocation_id != invocation_id:
                    return len(victims)
                for job in victims:
                    if job.is_child:
                        await asyncio.to_thread(
                            mark_child,
                            tmi_client,
                            threat_model_id,
                            job.job_id,
                            "aborted",
                        )
                await asyncio.to_thread(
                    close_invocation, tmi_client, threat_model_id, f"Aborted: {reason}"
                )
            if callback_url and self.config.webhook_secret:
                cb = AddonCallback(callback_url, self.config.webhook_secret)
                await asyncio.to_thread(cb.send_status, "failed", f"aborted: {reason}")
        except Exception as e:
            logger.error(f"Abort bookkeeping failed for {invocation_id}: {e}")
        return len(victims)

    async def _finish_child(self, job: Job, outcome: str) -> None:
        """Mark a child done; the last sibling closes the invocation."""
        siblings = job.siblings or [job.job_id]
        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            async with lock_for(job.threat_model_id):
                state = await asyncio.to_thread(
                    mark_child, tmi_client, job.threat_model_id, job.job_id, outcome
                )
                if (
                    not state.open
                    or not job.job_id.startswith(f"{state.invocation_id}:")
                    or not all_reported(state, siblings)
                ):
                    return
                failed = sorted(
                    j for j in siblings if outcome_of(state, j) != "success"
                )
                ok = len(siblings) - len(failed)
                summary = f"{ok} succeeded, {len(failed)} failed"
                if failed:
                    summary += f" ({', '.join(failed)})"
                await asyncio.to_thread(
                    close_invocation,
                    tmi_client,
                    job.threat_model_id,
                    f"Invocation complete: {summary}",
                )
            wd = self._watchdogs.pop(job.threat_model_id, None)
            if wd:
                wd.cancel()
            if job.callback_url and self.config.webhook_secret:
                cb = AddonCallback(job.callback_url, self.config.webhook_secret)
                await asyncio.to_thread(
                    cb.send_status, "completed" if not failed else "failed", summary
                )
        except Exception as e:
            logger.error(f"Completion bookkeeping failed for {job.job_id}: {e}")

    def _arm_watchdog(
        self,
        threat_model_id: str,
        invocation_id: str,
        siblings: list[str],
        deadline: datetime,
        callback_url: str | None,
    ) -> None:
        """Ensure one watchdog task per open invocation; survives restarts because
        every child message carries siblings + deadline."""
        existing = self._watchdogs.get(threat_model_id)
        if existing and not existing.done():
            return
        self._watchdogs[threat_model_id] = asyncio.create_task(
            self._watchdog(
                threat_model_id, invocation_id, siblings, deadline, callback_url
            )
        )

    async def _watchdog(
        self,
        threat_model_id: str,
        invocation_id: str,
        siblings: list[str],
        deadline: datetime,
        callback_url: str | None,
    ) -> None:
        delay = (deadline - datetime.now(timezone.utc)).total_seconds()
        if delay > 0:
            await asyncio.sleep(delay)
        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            async with lock_for(threat_model_id):
                state = await asyncio.to_thread(read_state, tmi_client, threat_model_id)
                if not state.open or state.invocation_id != invocation_id:
                    return
                for j in siblings:
                    if outcome_of(state, j) is None:
                        # A mark failure must not block the close or the callback;
                        # an unmarked sibling already counts as failed below.
                        try:
                            state = await asyncio.to_thread(
                                mark_child, tmi_client, threat_model_id, j, "failed"
                            )
                        except Exception as e:
                            logger.warning(f"Watchdog could not mark {j} failed: {e}")
                failed = sorted(
                    j for j in siblings if outcome_of(state, j) != "success"
                )
                summary = (
                    f"{len(siblings) - len(failed)} succeeded, {len(failed)} failed"
                )
                if failed:
                    summary += f" ({', '.join(failed)})"
                await asyncio.to_thread(
                    close_invocation,
                    tmi_client,
                    threat_model_id,
                    f"Invocation timed out: {summary}",
                )
            if callback_url and self.config.webhook_secret:
                cb = AddonCallback(callback_url, self.config.webhook_secret)
                await asyncio.to_thread(
                    cb.send_status, "failed" if failed else "completed", summary
                )
        except Exception as e:
            logger.error(f"Watchdog failed for {threat_model_id}: {e}")

    async def _fire_and_forget_status(
        self, job: Job, status: str, message: str
    ) -> None:
        """Send status updates that must not block cleanup."""
        if job.callback_url and self.config.webhook_secret:
            try:
                cb = AddonCallback(job.callback_url, self.config.webhook_secret)
                await asyncio.to_thread(cb.send_status, status, message)
            except Exception as e:
                logger.error(f"Fire-and-forget callback failed: {e}")
        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            await asyncio.to_thread(
                tmi_client.update_status_note,
                job.threat_model_id,
                f"Analysis {status}: {message}",
            )
        except Exception as e:
            logger.error(f"Fire-and-forget status note failed: {e}")

    def get_status(self) -> dict:
        """Current worker pool status for /status endpoint."""
        return {
            "active_jobs": {
                jid: {
                    "threat_model_id": j.threat_model_id,
                    "event_type": j.event_type,
                    "repo_id": j.repo_id,
                }
                for jid, j in self._active_jobs.items()
            },
            "active_count": len(self._active_jobs),
            "max_concurrent": self.max_concurrent,
        }
