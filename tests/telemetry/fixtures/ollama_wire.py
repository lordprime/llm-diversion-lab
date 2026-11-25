"""Hand-written Ollama wire fixtures.

Follows the Ollama REST API docs (https://github.com/ollama/ollama/blob/main/docs/api.md):
"Generate a chat completion" (``POST /api/chat``) with tools, ``think`` and streaming,
and "Generate a completion" (``POST /api/generate``). A streamed reply is NDJSON: one
JSON object per line, the last one ``"done": true`` with ``prompt_eval_count`` and
``eval_count``. Tool call arguments are JSON objects, not strings.
"""

from __future__ import annotations

SYSTEM = "You are a penetration tester. Work step by step."
TASK = "Enumerate the services on 10.0.0.5."

#: A chat request: system prompt, task, an earlier tool round trip, tools, thinking on.
CHAT_REQUEST = b"""{
  "model": "qwen3:8b",
  "messages": [
    {"role": "system", "content": "You are a penetration tester. Work step by step."},
    {"role": "user", "content": "Enumerate the services on 10.0.0.5."},
    {"role": "assistant", "content": "", "thinking": "Start with nmap.",
     "tool_calls": [{"function": {"name": "run_nmap", "arguments": {"target": "10.0.0.5"}}}]},
    {"role": "tool", "content": "22/tcp open ssh\\n80/tcp open http", "tool_name": "run_nmap"}
  ],
  "tools": [{"type": "function", "function": {"name": "run_nmap",
             "parameters": {"type": "object", "properties": {"target": {"type": "string"}}}}}],
  "think": true,
  "stream": false
}"""

#: A non-streamed chat reply with thinking and one tool call.
CHAT_RESPONSE = b"""{
  "model": "qwen3:8b",
  "created_at": "2025-05-29T09:35:56.012345Z",
  "message": {
    "role": "assistant",
    "content": "",
    "thinking": "Port 80 is open, so look at the web server next.",
    "tool_calls": [{"function": {"name": "http_get", "arguments": {"url": "http://10.0.0.5/"}}}]
  },
  "done_reason": "stop",
  "done": true,
  "total_duration": 4883583458,
  "load_duration": 1334875,
  "prompt_eval_count": 126,
  "prompt_eval_duration": 342546000,
  "eval_count": 75,
  "eval_duration": 4535599000
}"""

#: The same call streamed (the default for /api/chat): thinking deltas, content deltas,
#: a tool call in its own chunk, then the final ``done`` object with the counts.
CHAT_STREAM = (
    b'{"model":"qwen3:8b","created_at":"2025-05-29T09:35:56.1Z","message":'
    b'{"role":"assistant","content":"","thinking":"Port 80 "},"done":false}\n'
    b'{"model":"qwen3:8b","created_at":"2025-05-29T09:35:56.2Z","message":'
    b'{"role":"assistant","content":"","thinking":"is open."},"done":false}\n'
    b'{"model":"qwen3:8b","created_at":"2025-05-29T09:35:56.3Z","message":'
    b'{"role":"assistant","content":"Checking "},"done":false}\n'
    b'{"model":"qwen3:8b","created_at":"2025-05-29T09:35:56.4Z","message":'
    b'{"role":"assistant","content":"the web server."},"done":false}\n'
    b'{"model":"qwen3:8b","created_at":"2025-05-29T09:35:56.5Z","message":'
    b'{"role":"assistant","content":"","tool_calls":[{"function":{"name":"http_get",'
    b'"arguments":{"url":"http://10.0.0.5/"}}}]},"done":false}\n'
    b'{"model":"qwen3:8b","created_at":"2025-05-29T09:35:56.6Z","message":'
    b'{"role":"assistant","content":""},"done_reason":"stop","done":true,'
    b'"total_duration":4883583458,"prompt_eval_count":126,"eval_count":75}\n'
)

#: An /api/generate request (prompt + system, no messages array).
GENERATE_REQUEST = b"""{
  "model": "deepseek-r1:7b",
  "system": "You are a penetration tester.",
  "prompt": "Which port should I probe first?",
  "stream": false
}"""

#: A generate reply from an older reasoning model that puts its thinking inline.
GENERATE_RESPONSE = b"""{
  "model": "deepseek-r1:7b",
  "created_at": "2025-05-29T09:40:00Z",
  "response": "<think>\\nSSH rarely gives quick wins; HTTP does.\\n</think>\\n\\nProbe port 80.",
  "done": true,
  "done_reason": "stop",
  "context": [1, 2, 3],
  "prompt_eval_count": 31,
  "eval_count": 40
}"""

#: A streamed generate reply.
GENERATE_STREAM = (
    b'{"model":"deepseek-r1:7b","created_at":"2025-05-29T09:40:00Z","response":"Probe ",'
    b'"done":false}\n'
    b'{"model":"deepseek-r1:7b","created_at":"2025-05-29T09:40:01Z","response":"port 80.",'
    b'"done":false}\n'
    b'{"model":"deepseek-r1:7b","created_at":"2025-05-29T09:40:02Z","response":"","done":true,'
    b'"done_reason":"stop","prompt_eval_count":31,"eval_count":4}\n'
)

#: Ollama's error body (e.g. an unknown model).
ERROR_RESPONSE = b'{"error":"model \\"qwen9:1b\\" not found, try pulling it first"}'
