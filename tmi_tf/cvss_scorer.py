"""CVSS 4.0 vector validation and scoring."""

import logging

from cvss import CVSS4, CVSSError  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

logger = logging.getLogger(__name__)


def score_cvss4_vector(
    vector: str,
) -> tuple[float | None, str | None, str | None]:
    """Validate and score a CVSS 4.0 vector string.

    Args:
        vector: CVSS 4.0 vector string (e.g. "CVSS:4.0/AV:N/AC:L/...")

    Returns:
        Tuple of (score, severity, error).
        On success: (float score, severity label, None)
        On failure: (None, None, error message)
    """
    try:
        c = CVSS4(vector)
        raw_score = c.base_score
        if raw_score is None:
            return None, None, "CVSS4 base_score is None"
        score = float(raw_score)
        severity = c.severities()[0]
        # TMI does not use "None" as a severity level
        if severity == "None":
            severity = "Low"
        return score, severity, None
    except CVSSError as e:
        return None, None, str(e)
    except Exception as e:
        return None, None, str(e)
