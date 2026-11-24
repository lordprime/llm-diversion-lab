"""Hand-written Anthropic Messages wire fixtures.

Follows the Anthropic API docs: the Messages API (``POST /v1/messages``,
https://docs.anthropic.com/en/api/messages), streaming messages
(https://docs.anthropic.com/en/docs/build-with-claude/streaming: ``event:`` and
``data:`` lines, ``message_start`` with the input usage, ``content_block_*`` events with
``text_delta``, ``thinking_delta``, ``signature_delta`` and ``input_json_delta``,
``message_delta`` with the final output usage, ``message_stop``, and ``ping``), extended
thinking (``thinking`` and ``redacted_thinking`` blocks) and prompt caching
(``cache_read_input_tokens``, ``cache_creation_input_tokens``).
"""

# Wire bytes are kept exactly as sent, so long lines are allowed here.
# ruff: noqa: E501

from __future__ import annotations

SYSTEM_BLOCKS = ["You are Claude Code, a coding agent.", "Follow the user's instructions."]
TASK = "Audit the login handler in app.py."

#: A request with ``system`` as a list of text blocks and a tool round trip in history.
REQUEST = b"""{
  "model": "claude-sonnet-4-5",
  "max_tokens": 4096,
  "system": [
    {"type": "text", "text": "You are Claude Code, a coding agent."},
    {"type": "text", "text": "Follow the user's instructions.", "cache_control": {"type": "ephemeral"}}
  ],
  "messages": [
    {"role": "user", "content": [{"type": "text", "text": "Audit the login handler in app.py."}]},
    {"role": "assistant", "content": [
      {"type": "thinking", "thinking": "Read the file first.", "signature": "EqQBCgIYAhIM"},
      {"type": "tool_use", "id": "toolu_01", "name": "Read", "input": {"file_path": "app.py"}}
    ]},
    {"role": "user", "content": [
      {"type": "tool_result", "tool_use_id": "toolu_01", "content": [{"type": "text", "text": "def login(): ..."}]}
    ]}
  ],
  "tools": [{"name": "Read", "input_schema": {"type": "object"}}],
  "thinking": {"type": "enabled", "budget_tokens": 2048},
  "stream": false
}"""

#: A request with ``system`` as a plain string.
REQUEST_STRING_SYSTEM = b"""{
  "model": "claude-haiku-4-5",
  "max_tokens": 512,
  "system": "You are a sub-agent that searches files.",
  "messages": [{"role": "user", "content": "Find every call to eval()."}]
}"""

#: A non-streamed reply: thinking, redacted thinking, text and a tool call, with caching.
RESPONSE = b"""{
  "id": "msg_01XFDUDYJgAACzvnptvVoYEL",
  "type": "message",
  "role": "assistant",
  "model": "claude-sonnet-4-5-20250929",
  "content": [
    {"type": "thinking", "thinking": "The handler compares passwords with ==.", "signature": "EqQBCgIYAhIM"},
    {"type": "redacted_thinking", "data": "EmwKAhgBEgy3va3pzix/LafPsn4a"},
    {"type": "text", "text": "The login handler is vulnerable to timing attacks."},
    {"type": "tool_use", "id": "toolu_02", "name": "Grep", "input": {"pattern": "==", "path": "app.py"}}
  ],
  "stop_reason": "tool_use",
  "stop_sequence": null,
  "usage": {
    "input_tokens": 12,
    "cache_creation_input_tokens": 300,
    "cache_read_input_tokens": 5000,
    "output_tokens": 210
  }
}"""

#: The streamed form: thinking (with a signature delta), redacted thinking, text and a
#: tool call whose input arrives as three input_json_delta pieces; a ping in between.
STREAM = b"""event: message_start
data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-5-20250929","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":12,"cache_creation_input_tokens":300,"cache_read_input_tokens":5000,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}

event: ping
data: {"type": "ping"}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"The handler compares "}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"passwords with ==."}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"EqQBCgIYAhIM"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"redacted_thinking","data":"EmwKAhgBEgy3va3pzix"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: content_block_start
data: {"type":"content_block_start","index":2,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"The login handler is "}}

event: content_block_delta
data: {"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"vulnerable to timing attacks."}}

event: content_block_stop
data: {"type":"content_block_stop","index":2}

event: content_block_start
data: {"type":"content_block_start","index":3,"content_block":{"type":"tool_use","id":"toolu_02","name":"Grep","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":"{\\"pattern\\": \\"==\\","}}

event: content_block_delta
data: {"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":" \\"path\\": \\"app.py\\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":3}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":210}}

event: message_stop
data: {"type":"message_stop"}

"""

#: A streamed tool call with no arguments: no input_json_delta at all.
STREAM_EMPTY_TOOL_INPUT = b"""event: message_start
data: {"type":"message_start","message":{"id":"msg_02","type":"message","role":"assistant","content":[],"model":"claude-haiku-4-5","usage":{"input_tokens":40,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_03","name":"ListFiles","input":{}}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9}}

event: message_stop
data: {"type":"message_stop"}

"""

#: A stream that ends mid-way (connection dropped): no message_delta, no message_stop,
#: and the last data line is cut off.
STREAM_TRUNCATED = b"""event: message_start
data: {"type":"message_start","message":{"id":"msg_03","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-5","usage":{"input_tokens":30,"output_tokens":1}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Partial ans"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_del"""

#: An error event in the middle of a stream (the API overloaded).
STREAM_ERROR = b"""event: message_start
data: {"type":"message_start","message":{"id":"msg_04","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-5","usage":{"input_tokens":30,"output_tokens":1}}}

event: error
data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}

"""

#: Anthropic's error body.
ERROR_RESPONSE = b'{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: field required"}}'
