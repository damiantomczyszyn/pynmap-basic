"""
TCP connect scan (-sT) — odpowiednik scan_engine_connect.cc.

Mechanizm identyczny jak w nmapie:
  1. dla każdego portu tworzymy nieblokujący socket i wołamy connect(),
  2. deskryptory rejestrujemy w selektorze (nmap: select(), my: selectors),
  3. gdy deskryptor staje się gotowy do zapisu, czytamy SO_ERROR,
  4. errno z SO_ERROR tłumaczymy na stan portu (tabela niżej),
  5. brak odpowiedzi w czasie probeTimeout() => retransmisja albo 'filtered'.

Tabela errno -> stan jest przepisana z handleConnectResult()
w scan_engine_connect.cc:

    0 / EISCONN      -> open       (ER_CONACCEPT)
    ECONNREFUSED     -> closed     (ER_CONREFUSED)
    EAGAIN           -> open       (quirk pętli lokalnej w Linuksie)
    EACCES / EPERM   -> filtered   (ER_ADMINPROHIBITED)
    ENOPROTOOPT      -> filtered   (ER_PROTOUNREACH)
    EHOSTUNREACH     -> filtered   (ER_HOSTUNREACH)
    ENETUNREACH      -> filtered   (ER_NETUNREACH)
    ENONET           -> filtered   (ER_DESTUNREACH)
    ETIMEDOUT        -> filtered   (ER_NORESPONSE)
    EHOSTDOWN        -> filtered   (ER_NORESPONSE)

Zaleta -sT: nie wymaga roota. Wada: zestawia pełny trzystopniowy
handshake, więc trafia do logów aplikacji.
"""

from __future__ import annotations

import errno
import selectors
import socket
import time

from .constants import PortState, Reason, ScanType
from .engine import (
    HostReport,
    HostScanStats,
    Probe,
    ScanOptions,
    max_sockets_allowed,
    select_timeout,
)
from .targets import Target
from .timing import ScanPerformanceVars, UltraTimingVals

# ---------------------------------------------------------------------------
# Mapowanie errno -> (stan, powód)
# ---------------------------------------------------------------------------

_ERRNO_MAP: dict[int, tuple[PortState, Reason]] = {
    0: (PortState.OPEN, Reason.CONACCEPT),
    errno.EISCONN: (PortState.OPEN, Reason.CONACCEPT),
    errno.EAGAIN: (PortState.OPEN, Reason.CONACCEPT),
    errno.ECONNREFUSED: (PortState.CLOSED, Reason.CONREFUSED),
    errno.EACCES: (PortState.FILTERED, Reason.ADMINPROHIBITED),
    errno.EPERM: (PortState.FILTERED, Reason.ADMINPROHIBITED),
    errno.ENOPROTOOPT: (PortState.FILTERED, Reason.PROTOUNREACH),
    errno.EHOSTUNREACH: (PortState.FILTERED, Reason.HOSTUNREACH),
    errno.ENETUNREACH: (PortState.FILTERED, Reason.NETUNREACH),
    errno.ETIMEDOUT: (PortState.FILTERED, Reason.NORESPONSE),
    errno.EHOSTDOWN: (PortState.FILTERED, Reason.NORESPONSE),
}

# ENONET nie istnieje na wszystkich platformach (brak np. na macOS)
if hasattr(errno, "ENONET"):
    _ERRNO_MAP[errno.ENONET] = (PortState.FILTERED, Reason.DESTUNREACH)

# EWOULDBLOCK == EAGAIN na Linuksie, ale nie wszędzie
_ERRNO_MAP.setdefault(errno.EWOULDBLOCK, (PortState.OPEN, Reason.CONACCEPT))

_IN_PROGRESS = {errno.EINPROGRESS, errno.EALREADY}
if hasattr(errno, "EWOULDBLOCK"):
    _IN_PROGRESS.add(errno.EWOULDBLOCK)


def classify_connect_errno(code: int) -> tuple[PortState, Reason]:
    """Tłumaczy errno z connect()/SO_ERROR na stan portu."""
    return _ERRNO_MAP.get(code, (PortState.UNKNOWN, Reason.UNKNOWN))


# ---------------------------------------------------------------------------
# Skaner
# ---------------------------------------------------------------------------


class ConnectScanner:
    """
    Silnik connect scanu dla grupy hostów.

    Jak w nmapie skanujemy wiele hostów równolegle w jednej pętli select()
    — dzięki temu okno zatłoczenia działa na poziomie grupy, a nie
    pojedynczego celu.
    """

    def __init__(self, opts: ScanOptions, perf: ScanPerformanceVars | None = None):
        self.opts = opts
        self.perf = perf or opts.build_perf()
        self.max_sockets = max_sockets_allowed()
        self.group_timing = UltraTimingVals.init_for(self.perf, group=True)
        self._selector = selectors.DefaultSelector()
        # fd -> (HostScanStats, Probe)
        self._pending: dict[int, tuple[HostScanStats, Probe]] = {}

    # -- API ----------------------------------------------------------------

    def scan(self, targets: list[Target]) -> list[HostReport]:
        now = time.monotonic()
        hosts = [HostScanStats(t, self.opts, self.perf, now=now) for t in targets]
        reports: list[HostReport] = []

        try:
            incomplete = list(hosts)
            while incomplete:
                now = time.monotonic()

                self._handle_timeouts(incomplete, now)
                self._send_new_probes(incomplete, now)
                self._wait_for_responses(incomplete)

                finished = [h for h in incomplete if h.completed() or h.timed_out]
                for host in finished:
                    self._finish_host(host)
                    reports.append(self._build_report(host))
                    incomplete.remove(host)
        finally:
            self._cleanup()

        # zachowujemy kolejność wejściową celów
        order = {id(t): i for i, t in enumerate(targets)}
        reports.sort(key=lambda r: order.get(id(r.target), 0))
        return reports

    # -- faza 1: retransmisje i timeouty ------------------------------------

    def _handle_timeouts(self, hosts: list[HostScanStats], now: float) -> None:
        """Odpowiednik doAnyOutstandingRetransmits() z scan_engine.cc."""
        for host in hosts:
            if host.host_timed_out(now):
                self._abandon_host(host)
                continue

            for probe in host.expired_probes(now):
                self._close_probe_socket(probe)
                host.register_timeout(probe, now)
                self.group_timing.drop_group(
                    len(self._pending) + 1, self.perf, now
                )

    # -- faza 2: wysyłanie nowych sond --------------------------------------

    def _send_new_probes(self, hosts: list[HostScanStats], now: float) -> None:
        """Odpowiednik doAnyNewProbes() / sendNextScanProbe()."""
        progress = True
        while progress:
            progress = False
            for host in hosts:
                if host.timed_out:
                    continue
                # dwie bramy: limit deskryptorów i grupowe okno zatłoczenia
                if len(self._pending) >= self.max_sockets:
                    return
                if len(self._pending) >= int(self.group_timing.cwnd) + self.perf.low_cwnd:
                    return
                if not host.send_ok(now):
                    continue

                port = host.next_port()
                if port is None:
                    continue

                self._launch_probe(host, port, now)
                progress = True
                now = time.monotonic()

    def _launch_probe(self, host: HostScanStats, port: int, now: float) -> None:
        tryno = host.tryno_by_port.get(port, 0)
        family = host.target.family

        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            if exc.errno in (errno.EMFILE, errno.ENFILE):
                # brak deskryptorów — port wraca do kolejki, spróbujemy później
                host.ports_todo.appendleft(port)
                self.max_sockets = max(8, len(self._pending))
                return
            # Cokolwiek innego dotyczy całego hosta, nie jednego portu:
            # typowy przypadek to EAFNOSUPPORT na maszynie z wyłączonym
            # IPv6 (a getaddrinfo zwraca wtedy adresy AAAA, więc wystarczy
            # podać nazwę DNS). Wcześniej leciał tu goły traceback
            # i ginął cały skan, także pozostałych celów.
            host.ports_todo.appendleft(port)
            self._skip_host(
                host, f"socket({self._family_name(family)}): {exc.strerror or exc}"
            )
            return

        sock.setblocking(False)
        self._configure_socket(sock, host)

        probe = Probe(
            port=port,
            tryno=tryno,
            sent_at=now,
            timeout_at=now + host.probe_timeout_s(),
            sock=sock,
        )

        addr = self._sockaddr(host.target, port)
        code = sock.connect_ex(addr)

        if code in _IN_PROGRESS:
            # typowa droga: czekamy na gotowość do zapisu
            host.register_sent(probe, now, group=self.group_timing)
            try:
                self._selector.register(sock, selectors.EVENT_WRITE)
            except (KeyError, ValueError):  # pragma: no cover - obronnie
                sock.close()
                host.outstanding.pop(probe.key, None)
                host.ports_todo.appendleft(port)
                return
            self._pending[sock.fileno()] = (host, probe)
            return

        # rozstrzygnięte natychmiast (typowe dla localhost i dla RST)
        host.register_sent(probe, now, group=self.group_timing)
        state, reason = classify_connect_errno(code)
        if state is PortState.UNKNOWN:
            state, reason = PortState.FILTERED, Reason.NORESPONSE
        host.register_reply(probe, state, reason, time.monotonic())
        sock.close()

    def _configure_socket(self, sock: socket.socket, host: HostScanStats) -> None:
        """Odpowiednik init_socket() z scan_engine_connect.cc."""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass

        if self.opts.source_ip or self.opts.source_port:
            bind_ip = self.opts.source_ip or (
                "::" if host.target.is_ipv6 else "0.0.0.0"
            )
            try:
                sock.bind((bind_ip, self.opts.source_port or 0))
            except OSError:
                pass

        # Nie chcemy, by jądro trzymało socket w TIME_WAIT po zamknięciu —
        # nmap ustawia SO_LINGER z czasem 0, żeby wysłać RST zamiast FIN.
        try:
            import struct as _struct

            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                _struct.pack("ii", 1, 0),
            )
        except OSError:
            pass

    @staticmethod
    def _sockaddr(target: Target, port: int):
        if target.is_ipv6:
            return (target.ip, port, 0, 0)
        return (target.ip, port)

    # -- faza 3: czekanie na odpowiedzi -------------------------------------

    def _wait_for_responses(self, hosts: list[HostScanStats]) -> None:
        """Odpowiednik waitForResponses() + do_one_select_round()."""
        timeout = self._select_timeout(hosts)

        if not self._pending:
            # Nic nie jest zarejestrowane w selektorze, więc select() nie
            # uśpiłby nas ani na chwilę — a czekać trzeba (--scan-delay).
            if timeout > 0:
                time.sleep(timeout)
            return

        events = self._selector.select(timeout)
        now = time.monotonic()

        for key, _mask in events:
            sock = key.fileobj
            fd = sock.fileno()
            entry = self._pending.pop(fd, None)
            if entry is None:  # pragma: no cover - obronnie
                self._safe_unregister(sock)
                continue

            host, probe = entry
            self._safe_unregister(sock)

            try:
                code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            except OSError as exc:
                code = exc.errno or errno.ETIMEDOUT

            state, reason = classify_connect_errno(code)

            if state is PortState.UNKNOWN:
                # nieznane errno: nmap loguje ostrzeżenie i traktuje jak brak
                # odpowiedzi; robimy to samo, zamiast przerywać skan
                state, reason = PortState.FILTERED, Reason.NORESPONSE

            host.register_reply(probe, state, reason, now)
            self.group_timing.ack(self.perf)
            sock.close()

    def _select_timeout(self, hosts: list[HostScanStats]) -> float:
        """Do najbliższego wygaśnięcia sondy albo końca --scan-delay."""
        return select_timeout(hosts, time.monotonic())

    # -- porządki -----------------------------------------------------------

    def _safe_unregister(self, sock) -> None:
        try:
            self._selector.unregister(sock)
        except (KeyError, ValueError, OSError):
            pass

    def _close_probe_socket(self, probe: Probe) -> None:
        sock = probe.sock
        if sock is None:
            return
        try:
            fd = sock.fileno()
        except OSError:
            fd = -1
        if fd >= 0:
            self._pending.pop(fd, None)
        self._safe_unregister(sock)
        try:
            sock.close()
        except OSError:
            pass
        probe.sock = None

    @staticmethod
    def _family_name(family: int) -> str:
        return {socket.AF_INET: "AF_INET", socket.AF_INET6: "AF_INET6"}.get(
            family, str(family)
        )

    def _skip_host(self, host: HostScanStats, reason: str) -> None:
        """Host nie da się przeskanować — zapisujemy powód i zamykamy go."""
        for probe in list(host.outstanding.values()):
            self._close_probe_socket(probe)
        host.abandon_outstanding()
        host.skip_reason = reason

    def _abandon_host(self, host: HostScanStats) -> None:
        for probe in list(host.outstanding.values()):
            self._close_probe_socket(probe)
        host.abandon_outstanding()
        host.timed_out = True

    def _finish_host(self, host: HostScanStats) -> None:
        for probe in list(host.outstanding.values()):
            self._close_probe_socket(probe)
        # Hosta porzuconego (--host-timeout) ani pominiętego NIE finalizujemy:
        # finalize() dopisuje każdemu niezbadanemu portowi domyślne 'filtered',
        # czyli WYMYŚLA stany dla portów, do których nie poszła ani jedna
        # sonda. W wyjściu tekstowym to nie było widoczne ("Skipping host due
        # to host timeout"), ale -oG i -oJ wypisywały pełną listę portów —
        # i to właśnie te formaty się parsuje. nmap po host-timeout nie
        # raportuje portów hosta.
        if host.skip_reason is None and not host.timed_out:
            host.finalize()

    def _cleanup(self) -> None:
        for _host, probe in list(self._pending.values()):
            self._close_probe_socket(probe)
        self._pending.clear()
        try:
            self._selector.close()
        except OSError:
            pass

    def _build_report(self, host: HostScanStats) -> HostReport:
        return HostReport(
            target=host.target,
            portlist=host.portlist,
            scanned_ports=host.scanned_ports,
            elapsed_s=time.monotonic() - host.start_time,
            probes_sent=host.probes_sent,
            replies_received=host.replies_received,
            timed_out=host.timed_out,
            host_up=host.skip_reason is None,
            skip_reason=host.skip_reason,
        )


def connect_scan(targets: list[Target], opts: ScanOptions) -> list[HostReport]:
    """Wygodny wrapper: jedno wywołanie = przeskanowana grupa celów."""
    opts.scan_type = ScanType.CONNECT
    return ConnectScanner(opts).scan(targets)
