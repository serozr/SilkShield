"""Nonblocking bounded SSE fanout with ordered, restart-safe event IDs."""
from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass, field


def encode_event(event):
    return f"id: {event['event_id']}\nevent: verdict\ndata: {json.dumps(event['data'])}\n\n"


@dataclass(eq=False)
class Listener:
    queue: asyncio.Queue
    priority: str | None
    closed: asyncio.Event = field(default_factory=asyncio.Event)

    def accepts(self, event):
        return self.priority is None or event["data"]["priority"] <= self.priority


class EventHub:
    def __init__(self, capacity=10000, client_capacity=256, heartbeat_s=15):
        self.buffer = deque(maxlen=capacity)
        self.client_capacity = client_capacity
        self.heartbeat_s = heartbeat_s
        self.listeners = set()

    def publish(self, event):
        self.buffer.append(event)
        for listener in tuple(self.listeners):
            if not listener.accepts(event):
                continue
            try:
                listener.queue.put_nowait(event)
            except asyncio.QueueFull:
                listener.closed.set()
                self.listeners.discard(listener)

    def subscribe(self, last_id=None, priority=None):
        listener = Listener(asyncio.Queue(self.client_capacity), priority)
        self.listeners.add(listener)
        reset = bool(last_id is not None and (
            (not self.buffer and last_id > 0) or
            (self.buffer and (last_id < self.buffer[0]["event_id"] - 1 or last_id > self.buffer[-1]["event_id"]))))
        replay = [e for e in self.buffer if last_id is not None and e["event_id"] > last_id
                  and listener.accepts(e)]
        return listener, replay, reset

    async def stream(self, listener, replay, reset):
        try:
            if reset:
                yield 'event: reset\ndata: {"reason":"event cursor outside retained buffer"}\n\n'
            for event in replay:
                if listener.closed.is_set():
                    return
                yield encode_event(event)
            while not listener.closed.is_set():
                get = asyncio.create_task(listener.queue.get())
                closed = asyncio.create_task(listener.closed.wait())
                try:
                    done, _ = await asyncio.wait((get, closed), timeout=self.heartbeat_s,
                                                 return_when=asyncio.FIRST_COMPLETED)
                    if closed in done:
                        return
                    if get in done:
                        yield encode_event(get.result())
                    else:
                        yield ": heartbeat\n\n"
                finally:
                    get.cancel()
                    closed.cancel()
                    await asyncio.gather(get, closed, return_exceptions=True)
        finally:
            self.listeners.discard(listener)

    def close(self):
        for listener in self.listeners:
            listener.closed.set()
        self.listeners.clear()
