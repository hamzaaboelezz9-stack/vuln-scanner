"""One bounded concurrent survey shared by all network checks in a scan."""

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from itertools import product
from threading import Event, Lock
from typing import TYPE_CHECKING

from scanner.core.errors import LimitReached, TransportError
from scanner.core.network import MAX_SURFACE_PORTS, PortObservation, PortState
from scanner.safety.policy import ScopeError
from scanner.utils.fingerprints import fingerprint, signatures

if TYPE_CHECKING:
    from scanner.checks.base import CheckContext
    from scanner.safety.authorization import AuthorizedScope

WAIT_SECONDS = 0.1


@dataclass(frozen=True)
class SurveyResult:
    """Immutable records and stable coverage notes; raw greeting data is excluded."""

    observations: tuple[PortObservation, ...]
    planned: int
    incomplete: bool = False
    failed: bool = False


class NetworkSurvey:
    """Allow one owner to collect, while other checks await the same counted probes."""

    def __init__(self, scope: "AuthorizedScope", read_banners: bool) -> None:
        """Bind collection to the approved host/port matrix and selected check needs."""
        self.scope = scope
        self.read_banners = read_banners
        self._lock, self._done = Lock(), Event()
        self._started = False
        self._result = SurveyResult((), len(scope.addresses) * len(scope.ports), incomplete=True)

    def collect(self, context: "CheckContext") -> SurveyResult:
        """Run once; cooperative waits remain subject to scan cancellation/deadline."""
        with self._lock:
            owner = not self._started
            self._started = True
        if owner:
            try:
                self._result = self._collect(context)
            except Exception:
                self._result = SurveyResult((), self._result.planned, incomplete=True, failed=True)
                raise
            finally:
                self._done.set()  # Unexpected owner failures cannot leave waiters blocked.
        else:
            while not self._done.wait(WAIT_SECONDS):
                context.budget.control.checkpoint()
        return self._result

    def _collect(self, context: "CheckContext") -> SurveyResult:
        signatures()  # Fail trusted resource parsing before any target-service connection.
        observations: list[PortObservation] = []
        jobs = iter(product(self.scope.addresses, self.scope.ports))
        planned = len(self.scope.addresses) * len(self.scope.ports)
        incomplete = failed = False
        pool = ThreadPoolExecutor(max_workers=context.config.workers, thread_name_prefix="vulnscan-tcp")
        pending = set()
        stopped = False
        try:
            while True:
                while not stopped and len(pending) < context.config.workers:
                    try:
                        context.budget.control.checkpoint()
                        address, port = next(jobs)
                    except StopIteration:
                        stopped = True
                        break
                    except LimitReached:
                        incomplete = stopped = True
                        break
                    pending.add(pool.submit(context.tcp.probe_port, address, port, self.read_banners))
                if not pending:
                    break
                done, pending = wait(pending, timeout=WAIT_SECONDS, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        probe = future.result()
                        identity = fingerprint(probe.banner) if probe.banner else None
                        observations.append(
                            PortObservation(probe.address, probe.port, probe.state, probe.banner_state, identity)
                        )
                    except (ScopeError, TransportError):
                        incomplete = stopped = True
                    except Exception:
                        # An unexpected plugin/resource error is distinct from an unresponsive host.
                        failed = incomplete = stopped = True
        finally:
            for future in pending:
                future.cancel()
            pool.shutdown(wait=True, cancel_futures=True)
        observations.sort(key=lambda item: (item.address, item.port))
        return SurveyResult(tuple(observations), planned, incomplete or len(observations) != planned, failed)

    def summary(self) -> dict[str, object]:
        """Export counts per host and at most 1024 open-port identities; never raw banners."""
        result = self._result
        opened = [item for item in result.observations if item.state is PortState.OPEN]
        uncertain = [item for item in result.observations if item.state not in {PortState.OPEN, PortState.REFUSED}]
        counts = {address: dict.fromkeys(PortState, 0) for address in self.scope.addresses}
        for item in result.observations:
            counts[item.address][item.state] += 1
        hosts = []
        for address in self.scope.addresses:
            responsive = counts[address][PortState.OPEN] + counts[address][PortState.REFUSED] > 0
            hosts.append(
                {
                    "address": address,
                    "tcp_response": "observed-or-middlebox" if responsive else "unknown",
                    "counts": {state.value: counts[address][state] for state in PortState},
                }
            )
        return {
            "kind": "passive-tcp-connect-survey",
            "planned_pairs": result.planned,
            "observed_pairs": len(result.observations),
            "incomplete": result.incomplete,
            "failed": result.failed,
            "hosts": hosts,
            "open_ports": [item.to_dict() for item in opened[:MAX_SURFACE_PORTS]],
            "open_ports_omitted": max(0, len(opened) - MAX_SURFACE_PORTS),
            "uncertain_ports": [item.to_dict() for item in uncertain[:MAX_SURFACE_PORTS]],
            "uncertain_ports_omitted": max(0, len(uncertain) - MAX_SURFACE_PORTS),
            "application_bytes_sent": 0,
        }
