"""Tests for Job dataclass."""

from datetime import datetime, timezone
from pathlib import Path

from tmi_tf.job import Job


class TestJob:
    def test_create_job_minimal(self):
        job = Job(
            job_id="abc-123",
            threat_model_id="tm-456",
            event_type="threat_model.created",
            enqueued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert job.job_id == "abc-123"
        assert job.threat_model_id == "tm-456"
        assert job.repo_id is None
        assert job.callback_url is None
        assert job.invocation_id is None
        assert job.temp_dir is None

    def test_create_job_full(self):
        job = Job(
            job_id="abc-123",
            threat_model_id="tm-456",
            event_type="addon.invoked",
            repo_id="repo-789",
            callback_url="https://api.tmi.dev/invocations/inv-1/status",
            invocation_id="inv-1",
            enqueued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            temp_dir=Path("/tmp/tmi-tf-abc-123"),
        )
        assert job.repo_id == "repo-789"
        assert job.callback_url == "https://api.tmi.dev/invocations/inv-1/status"
        assert job.invocation_id == "inv-1"
        assert job.temp_dir == Path("/tmp/tmi-tf-abc-123")

    def test_job_to_dict_roundtrip(self):
        job = Job(
            job_id="abc-123",
            threat_model_id="tm-456",
            event_type="threat_model.created",
            enqueued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        d = job.to_queue_message()
        restored = Job.from_queue_message(d)
        assert restored.job_id == job.job_id
        assert restored.threat_model_id == job.threat_model_id
        assert restored.enqueued_at == job.enqueued_at
