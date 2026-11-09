#!/usr/bin/env python3
"""Loopback mock of the Anthropic, OpenAI and Gemini model APIs, for CLIs we
have no live credential for. It sits *behind* swapproxy.py, so the chain is
    CLI --(surrogate)--> swapproxy --(mock real credential)--> mock_upstream
and the mock checks which credential arrived: the mock "real" value means the
swap worked; the surrogate means it leaked through; anything else is a 401.

Every reply is streamed as N small SSE events, 50 ms apart, so the proxy's
chunk timestamps show whether streaming is incremental end to end.
"""
import http.server
import json
import os
import socketserver
import sys
import time

REAL = os.environ["AP_MOCK_REAL"]
SURR = os.environ["AP_SURROGATE"]
WORDS = ["pong"] + [str(i) for i in range(1, 20)]
GAP = 0.05


def log(**kw):
    sys.stdout.write(json.dumps(kw, sort_keys=True) + "\n")
    sys.stdout.flush()


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _cred(self):
        hits = {}
        for k in ("authorization", "x-api-key", "x-goog-api-key", "api-key"):
            v = self.headers.get(k)
            if v is None:
                continue
            hits[k] = "real" if REAL in v else ("SURROGATE" if SURR in v else "other")
        return hits

    def _json(self, status, obj):
        b = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _sse(self, events):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        for name, data in events:
            s = ("event: %s\n" % name if name else "") + "data: %s\n\n" % json.dumps(data)
            b = s.encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(b), b))
            self.wfile.flush()
            time.sleep(GAP)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def do_GET(self):
        self._route(None)

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        self._route(body)

    def _route(self, body):
        cred = self._cred()
        ok = list(cred.values()) == ["real"]
        path = self.path.split("?")[0]
        log(path=path, method=self.command, cred=cred, ok=ok,
            stream=(body or {}).get("stream"), model=(body or {}).get("model"))
        if not ok:
            return self._json(401, {"error": {"type": "authentication_error",
                                              "message": "mock: wrong credential %s" % cred}})
        if path.endswith("/models") and self.command == "GET":
            return self._json(200, {"data": [], "models": [], "object": "list"})
        if path.endswith("/messages/count_tokens"):
            return self._json(200, {"input_tokens": 10})
        if path.endswith("/messages"):
            return self._anthropic(body)
        if path.endswith("/responses"):
            return self._responses(body)
        if path.endswith("/chat/completions"):
            return self._chat(body)
        if ":streamGenerateContent" in path:
            return self._gemini_stream()
        if ":generateContent" in path:
            gc = (body or {}).get("generationConfig") or {}
            # Gemini CLI side calls (router, next-speaker) ask for JSON; answer in kind.
            text = (json.dumps({"reasoning": "mock", "model_choice": "flash",
                                "next_speaker": "user"})
                    if gc.get("responseMimeType") == "application/json" else "pong")
            return self._json(200, {"candidates": [{"content": {"role": "model", "parts": [
                {"text": text}]}, "finishReason": "STOP", "index": 0}],
                "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1,
                                  "totalTokenCount": 2}})
        if ":countTokens" in path:
            return self._json(200, {"totalTokens": 10})
        return self._json(404, {"error": {"message": "mock: no route %s" % path}})

    def _anthropic(self, body):
        model = body.get("model", "mock")
        msg = {"id": "msg_mock", "type": "message", "role": "assistant", "model": model,
               "content": [], "stop_reason": None, "stop_sequence": None,
               "usage": {"input_tokens": 1, "output_tokens": 1}}
        if not body.get("stream"):
            msg["content"] = [{"type": "text", "text": " ".join(WORDS)}]
            msg["stop_reason"] = "end_turn"
            return self._json(200, msg)
        ev = [("message_start", {"type": "message_start", "message": msg}),
              ("content_block_start", {"type": "content_block_start", "index": 0,
                                       "content_block": {"type": "text", "text": ""}})]
        for w in WORDS:
            ev.append(("content_block_delta", {"type": "content_block_delta", "index": 0,
                                               "delta": {"type": "text_delta", "text": w + " "}}))
        ev += [("content_block_stop", {"type": "content_block_stop", "index": 0}),
               ("message_delta", {"type": "message_delta",
                                  "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                  "usage": {"output_tokens": len(WORDS)}}),
               ("message_stop", {"type": "message_stop"})]
        self._sse(ev)

    def _responses(self, body):
        text = " ".join(WORDS)
        item = {"type": "message", "role": "assistant", "id": "msg_mock", "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}]}
        ev = [("response.created", {"type": "response.created",
                                    "response": {"id": "resp_mock", "status": "in_progress"}}),
              ("response.output_item.added", {"type": "response.output_item.added",
                                              "output_index": 0,
                                              "item": dict(item, content=[], status="in_progress")})]
        for w in WORDS:
            ev.append(("response.output_text.delta", {"type": "response.output_text.delta",
                                                      "item_id": "msg_mock", "output_index": 0,
                                                      "content_index": 0, "delta": w + " "}))
        ev += [("response.output_item.done", {"type": "response.output_item.done",
                                              "output_index": 0, "item": item}),
               ("response.completed", {"type": "response.completed", "response": {
                   "id": "resp_mock", "status": "completed", "output": [item],
                   "usage": {"input_tokens": 1, "input_tokens_details": {"cached_tokens": 0},
                             "output_tokens": len(WORDS),
                             "output_tokens_details": {"reasoning_tokens": 0},
                             "total_tokens": 1 + len(WORDS)}}})]
        self._sse(ev)

    def _chat(self, body):
        ev = []
        for i, w in enumerate(WORDS):
            d = {"content": w + " "}
            if i == 0:
                d["role"] = "assistant"
            ev.append((None, {"id": "c1", "object": "chat.completion.chunk", "created": 0,
                              "model": body.get("model", "mock"),
                              "choices": [{"index": 0, "delta": d, "finish_reason": None}]}))
        ev.append((None, {"id": "c1", "object": "chat.completion.chunk", "created": 0,
                          "model": body.get("model", "mock"),
                          "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                          "usage": {"prompt_tokens": 1, "completion_tokens": len(WORDS),
                                    "total_tokens": 1 + len(WORDS)}}))
        self._sse(ev)
        # OpenAI chat streams end with a literal [DONE]; _sse already closed the body,
        # and the AI SDK treats end-of-stream after finish_reason as done.

    def _gemini_stream(self):
        ev = []
        for i, w in enumerate(WORDS):
            c = {"content": {"role": "model", "parts": [{"text": w + " "}]}, "index": 0}
            if i == len(WORDS) - 1:
                c["finishReason"] = "STOP"
            ev.append((None, {"candidates": [c], "usageMetadata": {
                "promptTokenCount": 1, "candidatesTokenCount": i + 1, "totalTokenCount": i + 2},
                "modelVersion": "mock"}))
        self._sse(ev)


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1])
    log(event="mock_start", port=port)
    S(("127.0.0.1", port), H).serve_forever()
