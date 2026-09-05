"""Tests for the async worker pool."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from tmi_tf.worker import WorkerPool, _is_message_expired


class TestMessageExpiry:
    def test_fresh_message_not_expired(self):
        enqueued = datetime.now(timezone.utc) - timedelta(hours=1)
        assert _is_message_expired(enqueued.isoformat(), max_age_hours=24) is False

    def test_old_message_expired(self):
        enqueued = datetime.now(timezone.utc) - timedelta(hours=25)
        assert _is_message_expired(enqueued.isoformat(), max_age_hours=24) is True

    def test_exactly_at_boundary(self):
        enqueued = datetime.now(timezone.utc) - timedelta(hours=24)
        assert _is_message_expired(enqueued.isoformat(), max_age_hours=24) is True


class TestWorkerPool:
    def test_init(self):
        pool = WorkerPool(
            queue_client=MagicMock(),
            config=MagicMock(
                max_concurrent_jobs=3, job_timeout=3600, max_message_age_hours=24
            ),
        )
        assert pool.max_concurrent == 3

    def test_get_status_empty(self):
        pool = WorkerPool(
            queue_client=MagicMock(),
            config=MagicMock(
                max_concurrent_jobs=3, job_timeout=3600, max_message_age_hours=24
            ),
        )
        status = pool.get_status()
        assert status["active_count"] == 0
        assert status["max_concurrent"] == 3

    def test_consume_uses_job_timeout_as_visibility(self):
        """Visibility must cover the whole job or SQS/OCI redeliver it mid-run."""
        import asyncio

        queue = MagicMock()
        queue.consume.return_value = []
        pool = WorkerPool(
            queue_client=queue,
            config=MagicMock(
                max_concurrent_jobs=3, job_timeout=1234, max_message_age_hours=24
            ),
        )
        asyncio.run(pool._poll_and_dispatch())
        queue.consume.assert_called_once_with(max_messages=3, visibility_timeout=1234)
