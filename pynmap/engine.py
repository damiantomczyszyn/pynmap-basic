"""
Szkielet silnika skanowania — odpowiednik scan_engine.h/scan_engine.cc
(klasy UltraScanInfo, HostScanStats, GroupScanStats, UltraProbe).

Tu mieszka logika wspólna dla -sT i -sS:
  * kolejka portów do przeskanowania,
  * lista sond "w powietrzu" (probes_outstanding),
  * stos retransmisji,
  * okno zatłoczenia (cwnd) i estymator RTT,
  * decyzja "czy mogę teraz wysłać kolejną sondę" (sendOK).

Konkretny sposób wysyłania i odbierania jest w scan_connect.py / scan_syn.py,
tak jak nmap rozdziela to na scan_engine_connect.cc i scan_engine_raw.cc.
"""

from __future__ import annotations

import os
import random
import sys
import time
from collections import deque
from dataclasses import dataclass, field

try:
    # Brak na Windowsie i w buildach WASM (Pyodide/Emscripten).
    # Bez tego modułu limit deskryptorów bierzemy z wartości domyślnej.
    import resource
except ImportError:  # pragma: no cover - zależne od platformy
    resource = None

from .constants import (
    DEFAULT_MAX_SOCKETS,
    MAX_EPHEMERAL_PORT,
    MIN_EPHEMERAL_PORT,
    WINDOWS_MAX_SOCKETS,
    PortState,
    Reason,
    ScanType,
)
from .ports import PortList, order_ports
from .targets import Target
from .timing import (
    ScanPerformanceVars,
    TimeoutInfo,
    TimingTemplate,
    UltraTimingVals,
)

# ---------------------------------------------------------------------------
# Opcje skanowania — odpowiednik NmapOps
# ---------------------------------------------------------------------------


@dataclass
class ScanOptions:
    """Zestaw opcji jednego uruchomienia. Odpowiednik globalnego `o` w nmapie."""

    scan_type: ScanType = ScanType.CONNECT
    ports: list[int] = field(default_factory=list)
    timing: TimingTemplate = field(default_factory=lambda: TimingTemplate(3, "normal"))
    max_retries: int | None = None
    host_timeout_s: float = 0.0
    scan_delay_s: float | None = None
    randomize_ports: bool = True
    source_port: int | None = None
    source_ip: str | None = None
    ttl: int = 64
    show_only_open: bool = False
    show_reason: bool = False
    verbose: int = 0
    debug: int = 0
    resolve_dns: bool = True
    min_parallelism: int = 0
    max_parallelism: int = 0
    seed: int | None = None

    def effective_max_retries(self) -> int:
        return self.timing.max_retries if self.max_retries is None else self.max_retries

    def effective_scan_delay_s(self) -> float:
        if self.scan_delay_s is not None:
            return self.scan_delay_s
        return self.timing.scan_delay_ms / 1000.0

    def build_perf(self) -> ScanPerformanceVars:
        perf = ScanPerformanceVars.from_template(
            self.timing,
            min_parallelism=self.min_parallelism,
            max_parallelism=self.max_parallelism,
        )
        perf.tryno_cap = self.effective_max_retries()
        return perf


# ---------------------------------------------------------------------------
# Sonda — odpowiednik UltraProbe
# ---------------------------------------------------------------------------


@dataclass
class Probe:
    """
    Jedna wysłana sonda. nmapowy UltraProbe trzyma unię danych na każdy
    typ skanu; tutaj wystarczą dwa opcjonalne pola (sock / seq+sport).
    """

    port: int
    tryno: int
    sent_at: float
    timeout_at: float
    sock: object | None = None       # tylko connect scan
    seq: int | None = None           # tylko SYN scan
    sport: int | None = None         # tylko SYN scan
    timedout: bool = False

    @property
    def key(self) -> tuple[int, int]:
        return (self.port, self.tryno)


# ---------------------------------------------------------------------------
# Statystyki hosta — odpowiednik HostScanStats
# ---------------------------------------------------------------------------


class HostScanStats:
    """
    Stan skanowania jednego hosta: co zostało, co leci, kiedy wygasa.

    Celowo trzymamy tu tę samą semantykę co nmap:
      * `ports_todo`  — porty jeszcze niewysłane (kolejka FIFO po tasowaniu),
      * `outstanding` — sondy wysłane, bez odpowiedzi,
      * `retry_stack` — porty do ponowienia (LIFO, jak w nmapie),
      * `timing`      — okno cwnd/ssthresh dla tego hosta,
      * `to`          — estymator RTT dla tego hosta.
    """

    def __init__(
        self,
        target: Target,
        opts: ScanOptions,
        perf: ScanPerformanceVars,
        now: float | None = None,
    ):
        now = time.monotonic() if now is None else now

        self.target = target
        self.opts = opts
        self.perf = perf

        ordered = order_ports(
            opts.ports,
            randomize=opts.randomize_ports,
            rng=random.Random(opts.seed) if opts.seed is not None else None,
        )
        self.scanned_ports: list[int] = list(opts.ports)
        self.ports_todo: deque[int] = deque(ordered)

        self.outstanding: dict[tuple[int, int], Probe] = {}
        self.retry_stack: list[int] = []
        self.tryno_by_port: dict[int, int] = {}

        self.timing = UltraTimingVals.init_for(perf, group=False, now=now)
        self.to = TimeoutInfo.from_template(opts.timing)

        self.portlist = PortList(
            default_state=PortState.FILTERED,
            default_reason=Reason.NORESPONSE,
        )

        self.start_time = now
        # None, a NIE 0.0: 0.0 jest poprawnym punktem na skali time.monotonic()
        # (czyli chwila bootu), wiec na swiezo wystartowanej maszynie wyrazenie
        # last_probe_sent + scan_delay wypadalo w PRZYSZLOSCI i pierwsza sonda
        # byla wstrzymywana o (scan_delay - uptime) sekund.
        self.last_probe_sent: float | None = None
        self.probes_sent = 0
        self.replies_received = 0
        self.timed_out = False
        # ustawiane przez SYN scan (adres źródłowy wybrany dla tej trasy)
        self.source_ip: str | None = None
        # powód pominięcia hosta (np. brak IPv6 w jądrze) — gdy jest
        # ustawiony, host nie trafia do raportu jako przeskanowany
        self.skip_reason: str | None = None

    # -- zapytania o stan ---------------------------------------------------

    @property
    def in_flight(self) -> int:
        return len(self.outstanding)

    def fresh_ports_left(self) -> bool:
        """Odpowiednik HostScanStats::freshPortsLeft()."""
        return bool(self.ports_todo)

    def work_left(self) -> bool:
        return bool(self.ports_todo or self.retry_stack or self.outstanding)

    def completed(self) -> bool:
        """Odpowiednik HostScanStats::completed()."""
        return not self.work_left()

    def probe_timeout_s(self) -> float:
        """
        Odpowiednik HostScanStats::probeTimeout().

        nmap bierze max(to.timeout, minimalny próg) — my dodatkowo
        przyciskamy do min/max z szablonu timingowego.
        """
        return max(self.to.timeout_s, self.opts.timing.min_rtt_timeout_ms / 1000.0)

    def host_timed_out(self, now: float) -> bool:
        limit = self.opts.host_timeout_s or (self.opts.timing.host_timeout_ms / 1000.0)
        if limit <= 0:
            return False
        return (now - self.start_time) >= limit

    def send_ok(self, now: float) -> bool:
        """
        Odpowiednik HostScanStats::sendOK() — czy wolno wysłać kolejną sondę.

        Dwa warunki: okno zatłoczenia nie jest pełne i minął scan_delay.
        """
        if self.in_flight >= int(self.timing.cwnd):
            return False

        delay = self.opts.effective_scan_delay_s()
        if delay > 0 and self.last_probe_sent is not None:
            return (now - self.last_probe_sent) >= delay

        return True

    def next_send_allowed_at(self) -> float:
        """
        Najwcześniejszy moment, w którym wolno wysłać kolejną sondę.

        Liczy się tylko --scan-delay; 0.0 znaczy "od razu". Pętla główna
        używa tego, żeby PRZESPAĆ przerwę między sondami. Bez tego, gdy nic
        nie leciało, select() dostawał timeout 0 i pętla kręciła się na
        100% CPU przez całą przerwę (przy -T0 to 300 s na sondę).
        """
        delay = self.opts.effective_scan_delay_s()
        if delay <= 0 or self.last_probe_sent is None:
            return 0.0
        return self.last_probe_sent + delay

    def next_port(self) -> int | None:
        """
        Zwraca kolejny port do zbadania.

        Priorytet jak w nmapie: najpierw retransmisje (retry_stack),
        potem świeże porty.
        """
        if self.retry_stack:
            return self.retry_stack.pop()
        if self.ports_todo:
            return self.ports_todo.popleft()
        return None

    # -- rejestracja zdarzeń ------------------------------------------------

    def register_sent(
        self, probe: Probe, now: float, group: UltraTimingVals | None = None
    ) -> None:
        self.outstanding[probe.key] = probe
        self.last_probe_sent = now
        self.probes_sent += 1
        self.timing.num_replies_expected += 1
        # Grupowe okno ma własne liczniki i też musi je dostać. Bez tego
        # num_replies_expected zostawało 0, cc_scale() zwracało 0.0, a ack()
        # mnożyło przyrost przez zero — grupowe cwnd nigdy nie rosło, więc
        # bramka oparta na nim była stałym sufitem, a nie okienkiem AIMD.
        if group is not None:
            group.num_replies_expected += 1

    def register_reply(
        self,
        probe: Probe,
        state: PortState,
        reason: Reason,
        now: float,
        reason_ttl: int | None = None,
        adjust_timing: bool = True,
    ) -> None:
        """
        Odpowiednik ultrascan_port_probe_update() — przyszła odpowiedź.

        Aktualizujemy stan portu, estymator RTT i okno zatłoczenia.
        """
        self.outstanding.pop(probe.key, None)
        self.replies_received += 1

        rtt_us = int((now - probe.sent_at) * 1_000_000)

        # nmap nie uczy się RTT z retransmisji (nie wiadomo, która wróciła)
        if adjust_timing and probe.tryno == 0:
            self.to.adjust(rtt_us)
            self.timing.ack(self.perf)
        elif adjust_timing:
            self.timing.num_replies_received += 1

        self.portlist.set_state(
            probe.port,
            state,
            reason=reason,
            reason_ttl=reason_ttl,
            rtt_us=rtt_us,
            tryno=probe.tryno,
        )

    def register_timeout(self, probe: Probe, now: float) -> bool:
        """
        Odpowiednik markProbeTimedout() + doAnyOutstandingRetransmits().

        Zwraca True, jeśli port wraca na stos retransmisji; False, jeśli
        wyczerpaliśmy próby i port zostaje oznaczony jako filtered.
        """
        self.outstanding.pop(probe.key, None)
        self.timing.drop(self.in_flight + 1, self.perf, now)

        max_retries = self.opts.effective_max_retries()
        if probe.tryno < max_retries:
            self.tryno_by_port[probe.port] = probe.tryno + 1
            self.retry_stack.append(probe.port)
            return True

        self.portlist.set_state(
            probe.port,
            PortState.FILTERED,
            reason=Reason.NORESPONSE,
            tryno=probe.tryno,
        )
        return False

    def expired_probes(self, now: float) -> list[Probe]:
        return [p for p in list(self.outstanding.values()) if p.timeout_at <= now]

    def abandon_outstanding(self) -> None:
        """Przy host-timeout porzucamy sondy bez oznaczania ich jako filtered."""
        self.outstanding.clear()
        self.ports_todo.clear()
        self.retry_stack.clear()

    def finalize(self) -> None:
        self.portlist.finalize(self.scanned_ports)


# ---------------------------------------------------------------------------
# Wynik skanu
# ---------------------------------------------------------------------------


@dataclass
class HostReport:
    target: Target
    portlist: PortList
    scanned_ports: list[int]
    elapsed_s: float
    probes_sent: int
    replies_received: int
    timed_out: bool = False
    host_up: bool = True
    skip_reason: str | None = None

    def interesting(self, only_open: bool) -> list:
        results = self.portlist.sorted_results()
        if not only_open:
            return results
        return [r for r in results if r.state in (PortState.OPEN, PortState.OPEN_FILTERED)]


@dataclass
class ScanReport:
    scan_type: ScanType
    hosts: list[HostReport] = field(default_factory=list)
    started_at: float = 0.0
    elapsed_s: float = 0.0
    command_line: str = ""
    services_source: str = "builtin"


# ---------------------------------------------------------------------------
# Pomocnicze
# ---------------------------------------------------------------------------


def select_timeout(
    hosts: list[HostScanStats], now: float, max_wait: float = 0.1
) -> float:
    """
    Jak długo wolno czekać w select()/poll() — wspólne dla -sT i -sS.

    Trzy przypadki:
      * są sondy w powietrzu  -> do najbliższego timeoutu sondy,
      * nic nie leci, ale host czeka na --scan-delay -> do końca przerwy,
      * nic nie leci i wolno wysyłać -> 0, bo pętla zaraz wyśle sondę.

    Wszystko przyciśnięte do max_wait, żeby --host-timeout pozostał
    responsywny.
    """
    soonest: float | None = None
    for host in hosts:
        for probe in host.outstanding.values():
            if soonest is None or probe.timeout_at < soonest:
                soonest = probe.timeout_at

    if soonest is not None:
        return max(0.0, min(soonest - now, max_wait))

    waiting = [host for host in hosts if host.work_left() and not host.timed_out]
    if not waiting:
        return 0.01

    earliest = min(host.next_send_allowed_at() for host in waiting)
    if earliest > now:
        return max(0.0, min(earliest - now, max_wait))

    # Zegar mówi "można wysyłać", ale to jeszcze nie znaczy, że ktokolwiek
    # faktycznie może: okno zatłoczenia też musi przepuścić. Zwrócenie tu 0.0
    # bez tego sprawdzenia zamieniało zablokowane okno w pętlę na 100% CPU
    # bez żadnego wyjścia (np. --min-parallelism -1 --max-parallelism -1
    # daje cwnd = -1, czyli send_ok() na zawsze False).
    if any(host.send_ok(now) for host in waiting):
        return 0.0
    return max_wait


def max_sockets_allowed() -> int:
    """
    Ile deskryptorów możemy bezpiecznie trzymać otwartych.

    nmap czyta getrlimit(RLIMIT_NOFILE) i zostawia zapas (MAX_SOCKETS);
    robimy to samo, bo connect scan to głównie zarządzanie deskryptorami.
    """
    if sys.platform == "win32":
        # Tam ogranicza nas nie RLIMIT_NOFILE (nie ma go), a FD_SETSIZE
        # w select(); patrz WINDOWS_MAX_SOCKETS w constants.py.
        return WINDOWS_MAX_SOCKETS

    if resource is None:
        return DEFAULT_MAX_SOCKETS

    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ValueError, OSError):
        return DEFAULT_MAX_SOCKETS

    if soft in (resource.RLIM_INFINITY, -1):
        return DEFAULT_MAX_SOCKETS

    # zapas na stdin/stdout/stderr, pliki wyjściowe i bufor bezpieczeństwa
    return max(8, min(DEFAULT_MAX_SOCKETS, soft - 32))


def pick_source_port(requested: int | None = None) -> int:
    """
    Wybiera port źródłowy dla SYN scan.

    nmap pozwala wymusić go przez --source-port (przydatne przy regułach
    firewalla przepuszczających ruch z portu 53 albo 20).
    """
    if requested:
        return requested
    span = MAX_EPHEMERAL_PORT - MIN_EPHEMERAL_PORT
    return MIN_EPHEMERAL_PORT + int.from_bytes(os.urandom(2), "big") % span


def is_root() -> bool:
    """SYN scan wymaga CAP_NET_RAW (zwykle = root)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0
