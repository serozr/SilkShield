"""Static PE parsing in a separate, reused process with wall-clock and address-space limits."""
from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import time
from types import MappingProxyType

FAILED = "Static parser failed or exceeded its memory limit"


class ParserProcess:
    """Callable `bytes -> Record` backed by a warm child process (`silkscan.api.parser`).

    The child is killed and replaced after a timeout, a crash or a memory error, and recycled
    after `recycle_after` files. A replacement starts at once so its imports overlap idle time.
    """

    def __init__(self, timeout_s: float = 10, memory_mb: int = 2048, recycle_after: int = 500,
                 start_timeout_s: float = 120):
        self.timeout_s, self.memory_mb = timeout_s, memory_mb
        self.recycle_after, self.start_timeout_s = recycle_after, start_timeout_s
        self.command = [sys.executable, "-m", "silkscan.api.parser", str(memory_mb)]
        self._proc: subprocess.Popen | None = None
        self._ready = False
        self._served = 0

    def start(self) -> None:
        env = dict(os.environ)
        # Avoid numerical libraries reserving several GB for thread stacks in the parser.
        env.update(OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1", MKL_NUM_THREADS="1")
        self._proc = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, env=env)
        self._ready, self._served = False, 0

    def close(self, restart: bool = False) -> None:
        if self._proc is not None:
            self._proc.kill()
            self._proc.communicate()
            self._proc = None
        if restart:
            self.start()

    def _read(self, n: int, deadline: float) -> bytes:
        fd = self._proc.stdout.fileno()
        buf = b""
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise TimeoutError
            chunk = os.read(fd, n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    def __call__(self, data: bytes):
        from silkscan.data.records import Record

        if self._proc is None or self._proc.poll() is not None:
            self.close()
            self.start()
        try:
            if not self._ready:
                if self._read(1, time.monotonic() + self.start_timeout_s) != b"R":
                    raise EOFError
                self._ready = True
            self._proc.stdin.write(len(data).to_bytes(8, "big") + data)
            self._proc.stdin.flush()
            deadline = time.monotonic() + self.timeout_s
            output = self._read(int.from_bytes(self._read(8, deadline), "big"), deadline)
        except TimeoutError:
            self.close(restart=True)
            raise TimeoutError("Static parser exceeded its time limit") from None
        except (EOFError, OSError):
            self.close(restart=True)
            raise RuntimeError(FAILED) from None
        except BaseException:
            self.close()
            raise
        self._served += 1
        if self._served >= self.recycle_after:
            self.close(restart=True)
        try:
            raw = json.loads(output)
        except ValueError:
            raise RuntimeError("Static parser returned an invalid record") from None
        if "error" in raw:
            if raw["error"] == "MemoryError":
                self.close(restart=True)
                raise RuntimeError(FAILED)
            raise RuntimeError(f"Static parser rejected the file ({raw['error']})")
        try:
            return Record(raw["id"], MappingProxyType(raw["inputs"]), MappingProxyType(raw["target"]))
        except (KeyError, TypeError):
            raise RuntimeError("Static parser returned an invalid record") from None
