"""Job dataclass for webhook-triggered analysis jobs."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class Job:
    """Represents an analysis job extracted from a webhook payload."""

    job_id: str
    threat_model_id: str
    event_type: str
    enqueued_at: datetime
    repo_id: Optional[str] = None
    callback_url: Optional[str] = None
    invocation_id: Optional[str] = None
    temp_dir: Optional[Path] = None

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
        )
