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


class TestScopeAndEnvironment:
    def _job(self, **kw):
        return Job(
            job_id="j1",
            threat_model_id="tm1",
            event_type="addon.invoked",
            enqueued_at=datetime(2026, 9, 13, tzinfo=timezone.utc),
            **kw,
        )

    def test_defaults_are_parent(self):
        job = self._job()
        assert job.scope is None
        assert job.environment is None
        assert job.is_child is False

    def test_round_trip(self):
        job = self._job(scope="aws-*", environment="aws-public")
        data = job.to_queue_message()
        assert data["scope"] == "aws-*"
        assert data["environment"] == "aws-public"
        back = Job.from_queue_message(data)
        assert back.scope == "aws-*"
        assert back.environment == "aws-public"
        assert back.is_child is True

    def test_empty_environment_is_child(self):
        assert (
            Job.from_queue_message(
                {**self._job(environment="").to_queue_message()}
            ).is_child
            is True
        )

    def test_missing_keys_default_to_none(self):
        data = self._job().to_queue_message()
        data.pop("scope")
        data.pop("environment")
        back = Job.from_queue_message(data)
        assert back.scope is None and back.environment is None


def test_siblings_and_deadline_round_trip():
    deadline = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
    job = Job(
        job_id="p1:aws",
        threat_model_id="tm1",
        event_type="addon.invoked",
        enqueued_at=datetime.now(timezone.utc),
        siblings=["p1:aws", "p1:gcp"],
        deadline=deadline,
    )
    body = job.to_queue_message()
    assert body["siblings"] == ["p1:aws", "p1:gcp"]
    assert body["deadline"] == deadline.isoformat()
    back = Job.from_queue_message(body)
    assert back.siblings == ["p1:aws", "p1:gcp"]
    assert back.deadline == deadline


def test_old_message_without_siblings_or_deadline():
    body = {
        "job_id": "p1",
        "threat_model_id": "tm1",
        "event_type": "addon.invoked",
        "enqueued_at": datetime.now(timezone.utc).isoformat(),
    }
    job = Job.from_queue_message(body)
    assert job.siblings is None
    assert job.deadline is None
