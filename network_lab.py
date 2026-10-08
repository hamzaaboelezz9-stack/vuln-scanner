"""Ephemeral passive greeting servers; every listener is bound to 127.0.0.1."""

import socket
from contextlib import contextmanager
from dataclasses import dataclass, field
from socketserver import BaseRequestHandler, ThreadingTCPServer
from threading import Event, Lock, Thread
from typing import Iterator


@dataclass
class GreetingLab:
    """Synthetic greetings and observed connection counts; no real target data."""

    parts: tuple[bytes, ...]
    delay: float = 0
    silent_seconds: float = 0
    port: int = 0
    connections: int = 0
    received: list[bytes] = field(default_factory=list)
    stopping: Event = field(default_factory=Event)
    lock: Lock = field(default_factory=Lock)


@contextmanager
def greeting_lab(
    parts: tuple[bytes, ...] = (b"SSH-2.0-OpenSSH_9.8p1 synthetic\r\n",), delay: float = 0, silent_seconds: float = 0
) -> Iterator[GreetingLab]:
    """Serve local fragmented/silent/oversized banners and record any unexpected client bytes."""
    lab = GreetingLab(parts, delay, silent_seconds)

    class Handler(BaseRequestHandler):
        """Never implement authentication or modify data; only send synthetic greetings."""

        def handle(self) -> None:
            """Send fixture chunks and verify the scanner sends no application command."""
            with lab.lock:
                lab.connections += 1
            connection: socket.socket = self.request
            try:
                if lab.stopping.wait(lab.silent_seconds):
                    return
                for part in lab.parts:
                    connection.sendall(part)
                    if lab.stopping.wait(lab.delay):
                        break
                connection.settimeout(0.5)
                lab.received.append(connection.recv(4096))
            except (OSError, TimeoutError):
                pass

    server = ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    lab.port = server.server_address[1]
    thread = Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield lab
    finally:
        lab.stopping.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def unused_port() -> int:
    """Select an ephemeral closed fixture port; tests still account for a bind race."""
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]
