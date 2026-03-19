"""Async worker pool for OCI Queue job processing."""

import asyncio
import logging
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tmi_tf.addon_callback import AddonCallback
from tmi_tf.analyzer import run_analysis
from tmi_tf.config import Config
from tmi_tf.job import Job
from tmi_tf.queue_client import QueueClient, QueueMessage
from tmi_tf.tmi_client_wrapper import TMIClient

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

    def __init__(self, queue_client: QueueClient, config: Config) -> None:
        self.queue_client = queue_client
        self.config = config
        self.max_concurrent = config.max_concurrent_jobs
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._active_jobs: dict[str, Job] = {}
        self._running = False

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
        messages = await asyncio.to_thread(
            self.queue_client.consume, max_messages=available
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
        job.temp_dir = Path(tempfile.mkdtemp(prefix=f"tmi-tf-{job.job_id}-"))

        async with self._semaphore:
            self._active_jobs[job.job_id] = job
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
                await self._fire_and_forget_status(job, "failed", "Job timed out")
            finally:
                self._active_jobs.pop(job.job_id, None)
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
            callback.send_status("in_progress")

        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            result = await asyncio.to_thread(
                run_analysis,
                config=self.config,
                threat_model_id=job.threat_model_id,
                tmi_client=tmi_client,
                repo_id=job.repo_id,
                temp_dir=job.temp_dir,
                callback=callback,
            )
            if result.success:
                if callback:
                    callback.send_status("completed")
            else:
                if callback:
                    callback.send_status("failed", "; ".join(result.errors))
            # Delete message on completion
            await asyncio.to_thread(self.queue_client.delete, receipt)
        except Exception as e:
            logger.error(f"Job exception: job_id={job.job_id}, error={e}")
            if callback:
                callback.send_status("failed", str(e))
            # Don't delete — let visibility timeout handle retry

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
