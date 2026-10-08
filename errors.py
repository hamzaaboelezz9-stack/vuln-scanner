"""Stable diagnostics; transport exception strings may contain target secrets."""


class TransportError(RuntimeError):
    """An authorized operation failed without proving a vulnerability."""


class TLSVerificationError(TransportError):
    """The peer certificate or negotiated TLS connection was not trusted."""

    def __init__(self, message: str, verify_code: int | None = None) -> None:
        """Retain only OpenSSL's numeric certificate diagnosis, never its raw message."""
        super().__init__(message)
        self.verify_code = verify_code


class LimitReached(TransportError):
    """A deadline, cancellation or operation budget prevented further work."""


class CheckSkipped(RuntimeError):
    """The check cannot apply to this target or local runtime."""


class RobotsDenied(TransportError):
    """An operator-enabled robots policy disallows the requested path."""
