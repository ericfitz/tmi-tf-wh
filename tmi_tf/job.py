"""Job dataclass for webhook-triggered analysis jobs."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class Job:
    """Represents an analysis job extracted from a webhook payload."""

    job_id: str
    threat_model_id: str
    event_type: str
    enqueued_at: datetime
    repo_id: str | None = None
    callback_url: str | None = None
    invocation_id: str | None = None
    temp_dir: Path | None = None
    scope: str | None = None
    environment: str | None = None
    repo_name: str | None = None
    siblings: list[str] | None = None
    deadline: datetime | None = None
    profile: str | None = None

    @property
    def is_child(self) -> bool:
        """A child job analyzes exactly one environment ("" = whole repo)."""
        return self.environment is not None

    @property
    def invocation_key(self) -> str:
        """Parent job id: children are "<parent>:<env>"."""
        return self.job_id.rsplit(":", 1)[0] if self.is_child else self.job_id

    def to_queue_message(self) -> dict:
        """Serialize to dict for OCI Queue message body."""
        return {
            "job_id": self.job_id,
            "threat_model_id": self.threat_model_id,
            "event_type": self.event_type,
            "enqueued_at": self.enqueued_at.isoformat(),
            "repo_id": self.repo_id,
            "callback_url": self.callback_url,
            "invocation_id": self.invocation_id,
            "scope": self.scope,
            "environment": self.environment,
            "repo_name": self.repo_name,
            "siblings": self.siblings,
            "deadline": self.deadline.isoformat() if self.deadline else None,
            "profile": self.profile,
        }

    @classmethod
    def from_queue_message(cls, data: dict) -> "Job":
        """Deserialize from OCI Queue message body."""
        return cls(
            job_id=data["job_id"],
            threat_model_id=data["threat_model_id"],
            event_type=data["event_type"],
            enqueued_at=datetime.fromisoformat(data["enqueued_at"]),
            repo_id=data.get("repo_id"),
            callback_url=data.get("callback_url"),
            invocation_id=data.get("invocation_id"),
            scope=data.get("scope"),
            environment=data.get("environment"),
            repo_name=data.get("repo_name"),
            siblings=data.get("siblings"),
            deadline=(
                datetime.fromisoformat(data["deadline"])
                if data.get("deadline")
                else None
            ),
            profile=data.get("profile"),
        )
