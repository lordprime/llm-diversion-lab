"""Hand-written OpenAI Chat Completions wire fixtures.

Follows the OpenAI API reference for ``POST /v1/chat/completions``
(https://platform.openai.com/docs/api-reference/chat/create) and its streaming chunk
object (https://platform.openai.com/docs/api-reference/chat-streaming): server-sent
events of ``data: {chunk}`` ending with ``data: [DONE]``; tool-call deltas carry an
``index`` and arrive in pieces; usage arrives in a last chunk with empty ``choices``
only when ``stream_options.include_usage`` is set. ``usage.prompt_tokens_details
.cached_tokens`` follows the prompt-caching guide. ``reasoning_content`` follows the
DeepSeek reasoning-model guide (https://api-docs.deepseek.com/guides/reasoning_model);
``reasoning`` is the field Ollama's and OpenRouter's OpenAI-compatible endpoints use.
"""

# Wire bytes are kept exactly as sent, so long lines are allowed here.
# ruff: noqa: E501

from __future__ import annotations

SYSTEM = "You are a red-team assistant."
TASK = "Find the admin panel on http://10.0.0.7/."

#: A request with a system prompt, a task and an earlier tool round trip.
REQUEST = b"""{
  "model": "gpt-4o-2024-08-06",
  "messages": [
    {"role": "system", "content": "You are a red-team assistant."},
    {"role": "user", "content": [{"type": "text", "text": "Find the admin panel on http://10.0.0.7/."}]},
    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function",
      "function": {"name": "http_get", "arguments": "{\\"url\\":\\"http://10.0.0.7/\\"}"}}]},
    {"role": "tool", "tool_call_id": "call_1", "content": "<html>Welcome</html>"}
  ],
  "tools": [{"type": "function", "function": {"name": "http_get", "parameters": {}}}],
  "stream": false
}"""

#: A streamed request asking for usage in the last chunk.
STREAM_REQUEST = b"""{
  "model": "gpt-4o-2024-08-06",
  "messages": [
    {"role": "system", "content": "You are a red-team assistant."},
    {"role": "user", "content": "Find the admin panel on http://10.0.0.7/."}
  ],
  "stream": true,
  "stream_options": {"include_usage": true}
}"""

#: A non-streamed reply: reasoning, text and two tool calls, with cached prompt tokens.
RESPONSE = b"""{
  "id": "chatcmpl-B9MHDbslfkBeAs8l4bebGdFOJ6PeG",
  "object": "chat.completion",
  "created": 1741570283,
  "model": "gpt-4o-2024-08-06",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "I will try the usual admin paths.",
        "reasoning_content": "Admin panels often live at /admin or /wp-admin.",
        "tool_calls": [
          {"id": "call_a", "type": "function",
           "function": {"name": "http_get", "arguments": "{\\"url\\": \\"http://10.0.0.7/admin\\"}"}},
          {"id": "call_b", "type": "function",
           "function": {"name": "http_get", "arguments": "{\\"url\\": \\"http://10.0.0.7/wp-admin\\"}"}}
        ],
        "refusal": null
      },
      "logprobs": null,
      "finish_reason": "tool_calls"
    }
  ],
  "usage": {
    "prompt_tokens": 1117,
    "completion_tokens": 46,
    "total_tokens": 1163,
    "prompt_tokens_details": {"cached_tokens": 1024, "audio_tokens": 0},
    "completion_tokens_details": {"reasoning_tokens": 12}
  },
  "system_fingerprint": "fp_fc9f1d7035"
}"""

#: A streamed reply with two tool calls whose argument deltas interleave by index,
#: then a usage chunk (include_usage was set) and [DONE].
STREAM_TWO_TOOLS = b"""data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-2024-08-06","choices":[{"index":0,"delta":{"role":"assistant","content":null},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-2024-08-06","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"http_get","arguments":""}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-2024-08-06","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","type":"function","function":{"name":"dns_lookup","arguments":""}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-2024-08-06","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"url\\": "}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-2024-08-06","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\\"name\\": "}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-2024-08-06","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"http://10.0.0.7/admin\\"}"}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-2024-08-06","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"\\"admin.lab\\"}"}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-2024-08-06","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-4o-2024-08-06","choices":[],"usage":{"prompt_tokens":80,"completion_tokens":40,"total_tokens":120,"prompt_tokens_details":{"cached_tokens":0}}}

data: [DONE]

"""

#: A streamed text reply with reasoning deltas and no usage chunk (include_usage unset).
STREAM_REASONING_NO_USAGE = b"""data: {"id":"chatcmpl-2","object":"chat.completion.chunk","created":2,"model":"deepseek-reasoner","choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning_content":"The login form "},"finish_reason":null}]}

data: {"id":"chatcmpl-2","object":"chat.completion.chunk","created":2,"model":"deepseek-reasoner","choices":[{"index":0,"delta":{"reasoning_content":"posts to /login."},"finish_reason":null}]}

data: {"id":"chatcmpl-2","object":"chat.completion.chunk","created":2,"model":"deepseek-reasoner","choices":[{"index":0,"delta":{"content":"Try "},"finish_reason":null}]}

data: {"id":"chatcmpl-2","object":"chat.completion.chunk","created":2,"model":"deepseek-reasoner","choices":[{"index":0,"delta":{"content":"/login."},"finish_reason":"stop"}]}

data: [DONE]

"""

#: Ollama's OpenAI-compatible endpoint: ``reasoning`` deltas, CRLF line ends, and an
#: SSE comment line (some gateways send keep-alive comments).
STREAM_OLLAMA_COMPAT = (
    b": keep-alive\r\n\r\n"
    b'data: {"id":"chatcmpl-9","object":"chat.completion.chunk","created":3,"model":"qwen3:8b",'
    b'"choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning":"Short "},'
    b'"finish_reason":null}]}\r\n\r\n'
    b'data: {"id":"chatcmpl-9","object":"chat.completion.chunk","created":3,"model":"qwen3:8b",'
    b'"choices":[{"index":0,"delta":{"role":"assistant","content":"","reasoning":"answer."},'
    b'"finish_reason":null}]}\r\n\r\n'
    b'data: {"id":"chatcmpl-9","object":"chat.completion.chunk","created":3,"model":"qwen3:8b",'
    b'"choices":[{"index":0,"delta":{"role":"assistant","content":"Done."},'
    b'"finish_reason":"stop"}]}\r\n\r\n'
    b"data: [DONE]\r\n\r\n"
)

#: A reply whose text starts with an inline <think> span (a model with no reasoning parser).
RESPONSE_INLINE_THINK = b"""{
  "id": "chatcmpl-3",
  "object": "chat.completion",
  "created": 1741570283,
  "model": "qwq:32b",
  "choices": [{"index": 0, "message": {"role": "assistant",
    "content": "  <think>The form has no CSRF token.</think>\\n\\nSubmit the form twice."},
    "finish_reason": "stop"}],
  "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70}
}"""

#: OpenAI's error body.
ERROR_RESPONSE = b"""{
  "error": {"message": "Rate limit reached for gpt-4o", "type": "requests", "param": null,
            "code": "rate_limit_exceeded"}
}"""
