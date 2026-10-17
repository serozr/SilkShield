"""Long-lived parser process. Set limits BEFORE importing the numerical stack.

Protocol on stdin/stdout: the child writes b"R" once it is ready, then for each request reads an
8-byte big-endian length plus the file bytes and answers with an 8-byte length plus a JSON record.
"""
from __future__ import annotations

import json
import os
import resource
import sys


def _read(stream, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def main():
    limit = int(sys.argv[1]) * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    # Replies get a private copy of stdout; anything a library prints goes to stderr (discarded).
    out = os.fdopen(os.dup(1), "wb")
    os.dup2(2, 1)
    inp = sys.stdin.buffer
    from silkscan.features.groups.ember_v3 import load_thrember_features
    from silkscan.inference.predict import record_from_bytes

    load_thrember_features()
    out.write(b"R")
    out.flush()
    while True:
        try:
            data = _read(inp, int.from_bytes(_read(inp, 8), "big"))
        except EOFError:
            return 0
        # No sample bytes, strings, parser exception messages or raw features in logs.
        fatal = False
        try:
            record = record_from_bytes(data)
            result = {"id": record.id, "inputs": dict(record.inputs), "target": dict(record.target)}
            payload = json.dumps(result, allow_nan=False).encode()
        except MemoryError:
            payload, fatal = json.dumps({"error": "MemoryError"}).encode(), True
        except Exception as exc:
            payload = json.dumps({"error": type(exc).__name__}).encode()
        out.write(len(payload).to_bytes(8, "big") + payload)
        out.flush()
        if fatal:
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
