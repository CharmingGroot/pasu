"""pasu as a LiteLLM guardrail, with streamed tool calls judged before they leave.

LiteLLM's built-in ``generic_guardrail_api`` already speaks to pasu: prompts are
screened on the way in, proposed tool calls are judged on the way out. What it
cannot do is stop a *streamed* tool call in time: LiteLLM forwards chunks to the
client while it consults the guardrail, so a denied call can reach the agent
before the block lands.

This class is ``generic_guardrail_api`` plus one override. For a streamed chat
completion it holds every chunk, assembles the response, asks pasu about its
tool calls, and only then releases the chunks — the same buffering LiteLLM's own
``tool_permission`` guardrail does. Streams it cannot assemble are handed to
LiteLLM's unified path unchanged, which is exactly what ``generic_guardrail_api``
would have done.

All decisions stay in pasu. This file only decides *when* to ask.

Use it by placing this file next to the LiteLLM config and naming it::

    guardrail: pasu_guardrail.PasuGuardrail

See ``config.example.yaml``.
"""

from typing import Any, AsyncGenerator, Dict, List

from litellm.proxy.guardrails.guardrail_hooks.generic_guardrail_api.generic_guardrail_api import (
    GenericGuardrailAPI,
)


class PasuGuardrail(GenericGuardrailAPI):
    async def apply_guardrail(self, inputs, request_data, input_type, logging_obj=None):
        # Declared on this class so LiteLLM routes non-streaming calls through
        # the unified guardrail path, as it does for generic_guardrail_api.
        return await super().apply_guardrail(
            inputs=inputs,
            request_data=request_data,
            input_type=input_type,
            logging_obj=logging_obj,
        )

    async def async_post_call_streaming_iterator_hook(
        self, user_api_key_dict: Any, response: Any, request_data: dict
    ) -> AsyncGenerator[Any, None]:
        from litellm.main import stream_chunk_builder
        from litellm.types.utils import ModelResponse, ModelResponseStream

        chunks: List[Any] = [chunk async for chunk in response]

        if chunks and all(isinstance(c, ModelResponseStream) for c in chunks):
            assembled = stream_chunk_builder(chunks=chunks)
            if isinstance(assembled, ModelResponse):
                tool_calls = _tool_calls(assembled)
                if tool_calls:
                    # Raises GuardrailRaisedException on BLOCKED, before any
                    # chunk has been released.
                    await self.apply_guardrail(
                        inputs={"texts": [], "tool_calls": tool_calls},
                        request_data=request_data,
                        input_type="response",
                    )
                for chunk in chunks:
                    yield chunk
                return

        async for chunk in _unified(self, user_api_key_dict, chunks, request_data):
            yield chunk


def _tool_calls(assembled: Any) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []
    for choice in assembled.choices or []:
        message = getattr(choice, "message", None)
        for call in getattr(message, "tool_calls", None) or []:
            calls.append(call.model_dump(mode="json") if hasattr(call, "model_dump") else dict(call))
    return calls


async def _replay(chunks: List[Any]) -> AsyncGenerator[Any, None]:
    for chunk in chunks:
        yield chunk


async def _unified(guardrail, user_api_key_dict, chunks, request_data):
    """What LiteLLM does for ``generic_guardrail_api`` on a stream it did not
    let this class buffer: the unified guardrail path."""
    from litellm.proxy.guardrails.guardrail_hooks.unified_guardrail.unified_guardrail import (
        UnifiedLLMGuardrails,
    )

    request_data["guardrail_to_apply"] = guardrail
    async for chunk in UnifiedLLMGuardrails().async_post_call_streaming_iterator_hook(
        user_api_key_dict=user_api_key_dict,
        request_data=request_data,
        response=_replay(chunks),
    ):
        yield chunk
