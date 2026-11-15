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
import sys
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

# ---------------------------------------------------------------------------
# Kody Winsock (WSAE*)
# ---------------------------------------------------------------------------
# Na Windowsie connect_ex() i SO_ERROR zwracają kody Winsock z zakresu
# 10000+, a NIE wartości POSIX: połączenie odrzucone to 10061, nie 111.
# Bez tych wpisów każdy zamknięty port wpadał w gałąź "nieznane errno"
# i był raportowany jako `filtered` — czyli -sT na Windowsie dawał wynik
# wyglądający na poprawny, a będący nieprawdą.
#
# Kody są stałe i udokumentowane (Winsock2 error codes), a ich zakres nie
# koliduje z żadną wartością POSIX, więc wpisujemy je liczbowo i
# bezwarunkowo — na Linuksie są po prostu nieużywane.
_WSAEACCES = 10013
_WSAEWOULDBLOCK = 10035
_WSAEINPROGRESS = 10036
_WSAEALREADY = 10037
_WSAENETDOWN = 10050
_WSAENETUNREACH = 10051
_WSAECONNABORTED = 10053
_WSAECONNRESET = 10054
_WSAEISCONN = 10056
_WSAETIMEDOUT = 10060
_WSAECONNREFUSED = 10061
_WSAEHOSTDOWN = 10064
_WSAEHOSTUNREACH = 10065

_ERRNO_MAP.update(
    {
        _WSAEISCONN: (PortState.OPEN, Reason.CONACCEPT),
        _WSAECONNREFUSED: (PortState.CLOSED, Reason.CONREFUSED),
        _WSAECONNRESET: (PortState.CLOSED, Reason.RESETPEER),
        _WSAECONNABORTED: (PortState.CLOSED, Reason.RESETPEER),
        _WSAEACCES: (PortState.FILTERED, Reason.ADMINPROHIBITED),
        _WSAEHOSTUNREACH: (PortState.FILTERED, Reason.HOSTUNREACH),
        _WSAENETUNREACH: (PortState.FILTERED, Reason.NETUNREACH),
        _WSAENETDOWN: (PortState.FILTERED, Reason.NETUNREACH),
        _WSAETIMEDOUT: (PortState.FILTERED, Reason.NORESPONSE),
        _WSAEHOSTDOWN: (PortState.FILTERED, Reason.NORESPONSE),
    }
)

# Ile razy pod rząd tolerujemy porażkę socket() przy pustym zbiorze sond
# w locie, zanim uznamy host za nieskanowalny. Bez takiego limitu nie ma
# nikogo, kto zwolniłby deskryptor, więc kolejne próby to pętla bez postępu.
_FD_FAILURE_LIMIT = 3

# UWAGA: WSAEWOULDBLOCK to na Windowsie normalne "connect() w toku",
# a NIE odpowiednik linuksowego EAGAIN -> open. Trafia więc wyłącznie
# do _IN_PROGRESS; w mapie stanów oznaczałby każdy port jako otwarty.
_IN_PROGRESS = {errno.EINPROGRESS, errno.EALREADY}
if hasattr(errno, "EWOULDBLOCK"):
    _IN_PROGRESS.add(errno.EWOULDBLOCK)
_IN_PROGRESS.update({_WSAEWOULDBLOCK, _WSAEINPROGRESS, _WSAEALREADY})

if sys.platform == "win32":
    # Na Windowsie Python aliasuje socketowe nazwy POSIX na WARTOSCI Winsock:
    # zmierzone na 3.12.10 -> errno.ECONNREFUSED == 10061, nie 111. Z tego
    # wynika, ze errno.EWOULDBLOCK == WSAEWOULDBLOCK == 10035, czyli kod
    # "connect() w toku".
    #
    # Wpis EAGAIN/EWOULDBLOCK -> open jest natomiast quirkiem PETLI LOKALNEJ
    # LINUKSA (patrz docs/port-states.md, sekcja 1). Na Windowsie oznaczalby,
    # ze każde polaczenie W TRAKCIE zestawiania jest raportowane jako port
    # otwarty — czyli falszywe `open` dla portow, ktore moga byc zamkniete.
    for _code in (errno.EAGAIN, errno.EWOULDBLOCK):
        _ERRNO_MAP.pop(_code, None)


def classify_connect_errno(code: int) -> tuple[PortState, Reason]:
    """Tłumaczy errno z connect()/SO_ERROR na stan portu."""
    return _ERRNO_MAP.get(code, (PortState.UNKNOWN, Reason.UNKNOWN))


def connection_established(sock: socket.socket) -> bool:
    """
    Czy gniazdo MA faktycznie zestawione połączenie.

    `SO_ERROR == 0` samo w sobie tego nie dowodzi. Pomiar na Windowsie
    (Python 3.12.10) pokazał gniazdo zgłoszone jako gotowe do zapisu,
    dla którego SO_ERROR zwracał 0, mimo że port był zamknięty — a
    `_ERRNO_MAP[0]` to `open`, więc zaufanie samemu SO_ERROR dawało
    FAŁSZYWE `open`. Dla skanera portów to najgorszy możliwy błąd:
    raportuje usługę, której nie ma.

    getpeername() odpowiada na to pytanie wprost: bez połączenia rzuca
    ENOTCONN (na Windowsie WSAENOTCONN). To klasyczny, przenośny sposób
    potwierdzenia nieblokującego connect().
    """
    try:
        sock.getpeername()
    except OSError:
        return False
    return True


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
        # ile razy pod rząd socket() zawiódł, nie mając ani jednej sondy
        # w locie, która mogłaby zwolnić deskryptor
        self._fd_failures = 0
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
                    len(self._pending) + 1, self.perf, now,
                    window=host.drop_window(),
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
                # int(cwnd), a NIE cwnd + low_cwnd: przy max_parallelism = 1
                # (tak ustawiają -T0, -T1, -T2 oraz jawne --max-parallelism 1)
                # cwnd i low_cwnd są równe 1, więc stary warunek przepuszczał
                # DWIE sondy naraz — czyli dwukrotność tempa, o które prosi
                # szablon wybierany właśnie po to, żeby być cichym.
                if len(self._pending) >= int(self.group_timing.cwnd):
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
                # Podłoga 8 była błędem: gdy realna pojemność jest MNIEJSZA
                # niż 8, max_sockets zostawało na 8, len(_pending) nigdy go
                # nie dobijało, więc żadna bramka nie blokowała wysyłki
                # i pętla kręciła się bez końca na 100% CPU (ulimit -n 10
                # wystarczał, żeby skan nigdy się nie skończył).
                self.max_sockets = max(1, min(self.max_sockets, len(self._pending)))
                if self._pending:
                    # są sondy w locie — zwolnią deskryptor, warto poczekać
                    return
                self._fd_failures += 1
                if self._fd_failures >= _FD_FAILURE_LIMIT:
                    self._skip_host(
                        host,
                        "brak wolnych deskryptorów: "
                        f"{exc.strerror or exc} (zwiększ ulimit -n)",
                    )
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

        self._fd_failures = 0
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

            # Windows ma inny układ struct linger: dwa u_short, nie dwa int,
            # więc "ii" dawało 8 bajtów tam, gdzie jądro oczekuje 4 —
            # setsockopt zwracał WSAEFAULT i opcja po cichu nie była ustawiana.
            layout = "hh" if sys.platform == "win32" else "ii"
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                _struct.pack(layout, 1, 0),
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

            if code == 0 and not connection_established(sock):
                # SO_ERROR mówi "bez błędu", ale połączenia NIE MA, więc to
                # nie jest otwarty port. Ponowne czytanie SO_ERROR nic nie da:
                # jądro czyści je przy pierwszym odczycie (zmierzone — dla
                # zamkniętego portu 1. czytanie daje ECONNREFUSED, 2. już 0).
                # Nie mamy więc użytecznej odpowiedzi i NIE wymyślamy stanu:
                # port idzie normalną ścieżką retransmisji, a po wyczerpaniu
                # prób dostanie filtered/no-response.
                host.register_timeout(probe, now)
                sock.close()
                continue

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
