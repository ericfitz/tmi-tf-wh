"""API-key LLM provider: the key and base URL come from the selected profile."""

import logging

from tmi_tf.llm_profiles import LLMProfile, resolve_key
from tmi_tf.providers.llm_base import BaseLLMProvider

logger = logging.getLogger(__name__)


class ApiKeyLLMProvider(BaseLLMProvider):
    """Passes the profile's key (and base URL) to every LiteLLM call.

    The key is never written to os.environ: concurrent jobs may use
    different profiles.
    """

    def __init__(self, profile: LLMProfile) -> None:
        super().__init__(profile.provider, profile.litellm_model, profile.name)
        self._extra_kwargs = {"api_key": resolve_key(profile)}
        if profile.base_url:
            self._extra_kwargs["api_base"] = profile.base_url
        logger.info("LLM profile %s: model=%s", profile.name, self.model)
