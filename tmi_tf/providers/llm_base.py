"""Base LLM provider with shared completion logic."""

import logging
from typing import Any

import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.config import save_llm_response
from tmi_tf.providers import LLMResponse

logger = logging.getLogger(__name__)

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True  # type: ignore[assignment]
litellm.drop_params = False  # type: ignore[assignment]


def _close_stream(stream: object) -> None:
    """Release the HTTP response behind a LiteLLM sync stream (#90).

    LiteLLM's sync CustomStreamWrapper has no close(). Left to cyclic GC, the
    response's close can run while httpcore holds its connection-pool lock, and
    it re-acquires that non-reentrant lock: the thread deadlocks for good.
    Anthropic's iterator holds a line generator (streaming_response); the
    responses API's holds an iterator whose .response is the httpx.Response.
    Closing twice is a no-op for both.
    """
    inner = getattr(stream, "completion_stream", None)
    wrapped = getattr(inner, "streaming_response", None)
    for obj in (wrapped, getattr(wrapped, "response", None)):
        close = getattr(obj, "close", None)
        if callable(close):
            try:
                close()
            except Exception as e:
                logger.debug("Closing LLM stream failed: %s", e)


def _usage_int(obj: object, name: str) -> int:
    """A usage counter, only when it is a real non-negative int (mocks, None,
    bools and negatives yield 0)."""
    value = getattr(obj, name, None)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


class BaseLLMProvider:
    """Base class for LLM providers. Handles the litellm.completion() call."""

    def __init__(self, provider: str, model: str, profile: str = "") -> None:
        self._provider = provider
        self._model = model
        self._profile = profile
        self._extra_kwargs: dict = {}  # type: ignore[type-arg]

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return self._provider

    @property
    def profile(self) -> str:
        return self._profile

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 64000,
        timeout: float = 1200.0,
        *,
        cache_prefix: str = "",
    ) -> LLMResponse:
        """Make a single LLM completion call via LiteLLM.

        With cache_prefix on Anthropic, the prefix is a cache_control block
        ahead of user_prompt; every other provider gets one plain string
        (prefix + prompt), since unknown fields could be rejected."""
        prompt_chars = len(system_prompt) + len(cache_prefix) + len(user_prompt)
        estimated_tokens = prompt_chars // 4
        logger.info(
            "Calling %s (%s), prompt ~%d chars (~%d tokens est.)",
            self._provider,
            self._model,
            prompt_chars,
            estimated_tokens,
        )

        user_content: str | list[dict[str, Any]]
        if cache_prefix and self._provider == "anthropic":
            user_content = [
                {
                    "type": "text",
                    "text": cache_prefix,
                    "cache_control": {"type": "ephemeral"},
                },
                {"type": "text", "text": user_prompt},
            ]
        else:
            user_content = cache_prefix + user_prompt
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]
        # Stream and reassemble: long outputs (up to 64k tokens) on slower
        # models exceed provider limits for non-streaming responses.
        stream = litellm.completion(
            model=self._model,
            messages=messages,
            max_tokens=max_tokens,
            timeout=timeout,
            stream=True,
            stream_options={"include_usage": True},
            num_retries=0,  # retry.py is the only retry layer (#103)
            **self._extra_kwargs,
        )
        try:
            chunks = list(stream)  # pyright: ignore[reportArgumentType]  # sync call with stream=True; 1.103's return type also lists a Coroutine
        finally:
            _close_stream(stream)
        response = litellm.stream_chunk_builder(chunks, messages=messages)

        # Extract token usage
        usage = getattr(response, "usage", None)
        tokens_in = usage.prompt_tokens if usage else 0
        tokens_out = usage.completion_tokens if usage else 0
        cache_read = _usage_int(usage, "cache_read_input_tokens") or _usage_int(
            getattr(usage, "prompt_tokens_details", None), "cached_tokens"
        )
        cache_creation = _usage_int(usage, "cache_creation_input_tokens")

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
            "%s (%s): %d input (%d cache read, %d cache write), "
            "%d output tokens, finish_reason=%s, $%.4f",
            self._provider,
            self._model,
            tokens_in,
            cache_read,
            cache_creation,
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
                cache_read_tokens=cache_read,
                cache_creation_tokens=cache_creation,
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
            cache_read_tokens=cache_read,
            cache_creation_tokens=cache_creation,
        )
