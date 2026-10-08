"""Absolute socket deadlines shared by HTTP and handshake-only TLS transports."""

import socket
import time
from threading import Lock, Timer

from scanner.core.errors import TransportError


class IODeadline:
    """Close the currently owned socket when one absolute operation deadline expires."""

    def __init__(self, seconds: float) -> None:
        """Start a daemon watchdog covering connect, headers and slow response streams."""
        self._lock = Lock()
        self._socket: socket.socket | None = None
        self.expired = False
        self._expires_at = time.monotonic() + seconds
        self._timer = Timer(seconds, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self) -> None:
        with self._lock:
            self.expired = True
            if self._socket is not None:
                try:
                    self._socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # A failed/closed peer still needs descriptor cleanup.
                self._socket.close()

    def watch(self, connection: socket.socket) -> None:
        """Transfer watchdog ownership after TLS wraps the underlying TCP socket."""
        with self._lock:
            if self.expired:
                connection.close()
                raise TransportError("Transport operation deadline reached.")
            self._socket = connection

    def remaining(self) -> float:
        """Bound the TLS handshake timeout by time already spent dialing TCP."""
        remaining = self._expires_at - time.monotonic()
        if remaining <= 0:
            raise TransportError("Transport operation deadline reached.")
        return remaining

    def close(self) -> None:
        """Cancel the timer and close any socket left after response cleanup."""
        self._timer.cancel()
        with self._lock:
            if self._socket is not None:
                self._socket.close()
                self._socket = None
