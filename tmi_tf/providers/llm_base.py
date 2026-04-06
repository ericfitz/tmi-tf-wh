"""Base LLM provider with shared completion logic."""

import logging

import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.config import save_llm_response
from tmi_tf.providers import LLMResponse

logger = logging.getLogger(__name__)

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True  # type: ignore[assignment]
litellm.drop_params = False  # type: ignore[assignment]


class BaseLLMProvider:
    """Base class for LLM providers. Handles the litellm.completion() call."""

    def __init__(self, provider: str, model: str) -> None:
        self._provider = provider
        self._model = model
        self._extra_kwargs: dict = {}  # type: ignore[type-arg]

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return self._provider

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> LLMResponse:
        """Make a single LLM completion call via LiteLLM."""
        prompt_chars = len(system_prompt) + len(user_prompt)
        estimated_tokens = prompt_chars // 4
        logger.info(
            "Calling %s (%s), prompt ~%d chars (~%d tokens est.)",
            self._provider,
            self._model,
            prompt_chars,
            estimated_tokens,
        )

        response = litellm.completion(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            timeout=timeout,
            **self._extra_kwargs,
        )

        # Extract token usage
        usage = getattr(response, "usage", None)
        tokens_in = usage.prompt_tokens if usage else 0
        tokens_out = usage.completion_tokens if usage else 0

        # Extract finish reason
        choices = response.choices  # type: ignore[union-attr]
        finish_reason = (
            getattr(choices[0], "finish_reason", "unknown") if choices else "no_choices"
        )

        # Calculate cost
        try:
            cost = litellm.completion_cost(completion_response=response)
        except Exception:
            cost = 0.0

        logger.info(
            "%s (%s): %d input, %d output tokens, finish_reason=%s, $%.4f",
            self._provider,
            self._model,
            tokens_in,
            tokens_out,
            finish_reason,
            cost,
        )

        if finish_reason == "length":
            logger.warning(
                "Response truncated (finish_reason=length). "
                "max_tokens=%d may be insufficient.",
                max_tokens,
            )

        # Extract content
        content = response.choices[0].message.content  # type: ignore[union-attr]
        if not content:
            logger.warning(
                "Empty response from LLM. finish_reason=%s, tokens_out=%d, model=%s",
                finish_reason,
                tokens_out,
                self._model,
            )
            return LLMResponse(
                text=None,
                input_tokens=tokens_in,
                output_tokens=tokens_out,
                cost=cost,
                finish_reason=finish_reason,
            )

        # Save response for debugging
        response_file = save_llm_response(content, self._provider)
        logger.info("Response saved to %s", response_file)

        return LLMResponse(
            text=content.strip(),
            input_tokens=tokens_in,
            output_tokens=tokens_out,
            cost=cost,
            finish_reason=finish_reason,
        )
