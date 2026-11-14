"""
Timing i congestion control — port algorytmów z nmap/timing.cc i timing.h.

Odwzorowane 1:1 (łącznie z przesunięciami bitowymi, żeby wyniki były
identyczne jak w C):

  TimeoutInfo        <- struct timeout_info          (timing.h)
  TimeoutInfo.adjust <- adjust_timeouts2()           (timing.cc)
  ScanPerformanceVars<- struct scan_performance_vars (timing.h / timing.cc init())
  UltraTimingVals    <- struct ultra_timing_vals     (scan_engine.h / timing.cc)

Jednostki: wszystko wewnętrznie w mikrosekundach (jak w nmapie).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .constants import (
    INITIAL_RTT_TIMEOUT_MS,
    MAX_RETRANSMISSIONS,
    MAX_RTT_TIMEOUT_MS,
    MAX_TCP_SCAN_DELAY_MS,
    MIN_RTT_TIMEOUT_MS,
)


def _box(low: float, high: float, value: float) -> float:
    """Odpowiednik box() z nmap/nbase — clamp do [low, high]."""
    if value < low:
        return low
    if value > high:
        return high
    return value


# ---------------------------------------------------------------------------
# Szablony timingowe -T0..-T5  (nmap.cc, obsługa opcji 'T')
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimingTemplate:
    """Wartości szablonów -T0..-T5 skopiowane z logiki nmap.cc."""

    level: int
    name: str
    min_rtt_timeout_ms: int = MIN_RTT_TIMEOUT_MS
    max_rtt_timeout_ms: int = MAX_RTT_TIMEOUT_MS
    initial_rtt_timeout_ms: int = INITIAL_RTT_TIMEOUT_MS
    max_retries: int = MAX_RETRANSMISSIONS
    scan_delay_ms: int = 0
    max_scan_delay_ms: int = MAX_TCP_SCAN_DELAY_MS
    max_parallelism: int = 0          # 0 = bez limitu (dynamiczny cwnd)
    host_timeout_ms: int = 0          # 0 = brak limitu


# Uwaga na T0/T1: nmap ustawia tam initial_rtt_timeout == max_rtt_timeout.
TIMING_TEMPLATES: dict[int, TimingTemplate] = {
    0: TimingTemplate(
        level=0, name="paranoid",
        max_rtt_timeout_ms=300_000, initial_rtt_timeout_ms=300_000,
        scan_delay_ms=300_000, max_parallelism=1,
    ),
    1: TimingTemplate(
        level=1, name="sneaky",
        max_rtt_timeout_ms=15_000, initial_rtt_timeout_ms=15_000,
        scan_delay_ms=15_000, max_parallelism=1,
    ),
    2: TimingTemplate(
        level=2, name="polite",
        scan_delay_ms=400, max_parallelism=1,
    ),
    3: TimingTemplate(level=3, name="normal"),
    4: TimingTemplate(
        level=4, name="aggressive",
        min_rtt_timeout_ms=100, max_rtt_timeout_ms=1_250,
        initial_rtt_timeout_ms=500, max_scan_delay_ms=10, max_retries=6,
    ),
    5: TimingTemplate(
        level=5, name="insane",
        min_rtt_timeout_ms=50, max_rtt_timeout_ms=300,
        initial_rtt_timeout_ms=250, max_scan_delay_ms=5, max_retries=2,
        host_timeout_ms=900_000,
    ),
}


# ---------------------------------------------------------------------------
# struct timeout_info + adjust_timeouts2()
# ---------------------------------------------------------------------------


@dataclass
class TimeoutInfo:
    """
    Estymator RTT w stylu Jacobsona/Karelsa, dokładnie jak w nmapie.

    W nmapie: srtt/rttvar == -1 oznacza "brak jeszcze próbki".
    timeout = srtt + 4 * rttvar, przyciśnięty do [min_rtt, max_rtt].
    """

    srtt: int = -1       # wygładzony RTT [µs]
    rttvar: int = -1     # wariancja RTT [µs]
    timeout: int = INITIAL_RTT_TIMEOUT_MS * 1000
    min_timeout: int = MIN_RTT_TIMEOUT_MS * 1000
    max_timeout: int = MAX_RTT_TIMEOUT_MS * 1000

    @classmethod
    def from_template(cls, tmpl: TimingTemplate) -> TimeoutInfo:
        return cls(
            srtt=-1,
            rttvar=-1,
            timeout=tmpl.initial_rtt_timeout_ms * 1000,
            min_timeout=tmpl.min_rtt_timeout_ms * 1000,
            max_timeout=tmpl.max_rtt_timeout_ms * 1000,
        )

    def adjust(self, rtt_us: int) -> None:
        """
        Port adjust_timeouts2() z timing.cc.

        rtt_us to zmierzona różnica (received - sent) w mikrosekundach.
        Zachowane są wszystkie sanity-checki i przesunięcia bitowe z C,
        bo Python >> na liczbach ujemnych też robi floor (jak arytmetyczne
        przesunięcie w gcc), więc wyniki się zgadzają.
        """
        delta = int(rtt_us)

        # nmap: mała ujemna delta to zwykle rozjazd libpcap vs gettimeofday
        if -50_000 < delta < 0:
            delta = 10_000
        elif delta < 0:
            return  # kompletnie bezsensowna próbka — ignorujemy

        if self.srtt == -1 and self.rttvar == -1:
            # pierwsza próbka
            self.srtt = delta
            self.rttvar = int(_box(5_000, 2_000_000, float(self.srtt)))
            self.timeout = self.srtt + (self.rttvar << 2)
        else:
            if delta >= 8_000_000:
                return  # sanity check #1 z nmapa

            rttdelta = delta - self.srtt

            # sanity check #2 — odrzucamy skoki absurdalnie większe od estymaty
            if rttdelta > 1_500_000 and rttdelta > 3 * self.srtt + 2 * self.rttvar:
                return

            self.srtt += rttdelta >> 3
            self.rttvar += (abs(rttdelta) - self.rttvar) >> 2
            self.timeout = self.srtt + (self.rttvar << 2)

        if self.rttvar > 2_300_000:
            self.rttvar = 2_000_000

        self.timeout = int(_box(self.min_timeout, self.max_timeout, float(self.timeout)))

    @property
    def timeout_s(self) -> float:
        return self.timeout / 1_000_000.0


# ---------------------------------------------------------------------------
# struct scan_performance_vars  (timing.cc: scan_performance_vars::init)
# ---------------------------------------------------------------------------


@dataclass
class ScanPerformanceVars:
    """Parametry AIMD. Wartości z scan_performance_vars::init() w timing.cc."""

    low_cwnd: int = 1
    max_cwnd: int = 300
    group_initial_cwnd: int = 10
    host_initial_cwnd: int = 10
    slow_incr: int = 1
    ca_incr: int = 1
    cc_scale_max: int = 50
    initial_ssthresh: int = 75
    group_drop_cwnd_divisor: float = 2.0
    group_drop_ssthresh_divisor: float = 1.5
    host_drop_ssthresh_divisor: float = 1.5
    # ultra_scan_performance_vars::init()
    ping_magnifier: int = 3
    pingtime_us: int = 1_250_000
    tryno_cap: int = MAX_RETRANSMISSIONS

    @classmethod
    def from_template(
        cls,
        tmpl: TimingTemplate,
        min_parallelism: int = 0,
        max_parallelism: int = 0,
    ) -> ScanPerformanceVars:
        low_cwnd = min_parallelism if min_parallelism else 1
        effective_max = max_parallelism or tmpl.max_parallelism
        max_cwnd = max(low_cwnd, effective_max if effective_max else 300)
        initial = int(_box(low_cwnd, max_cwnd, 10))

        # nmap: ca_incr rośnie przy agresywniejszym timingu
        ca_incr = 2 if tmpl.level >= 4 else 1

        # nmap: ssthresh spada łagodniej przy wyższych -T
        if tmpl.level <= 3:
            ssthresh_divisor = 3.0 / 2.0
        elif tmpl.level <= 4:
            ssthresh_divisor = 4.0 / 3.0
        else:
            ssthresh_divisor = 5.0 / 4.0

        return cls(
            low_cwnd=low_cwnd,
            max_cwnd=max_cwnd,
            group_initial_cwnd=initial,
            host_initial_cwnd=initial,
            ca_incr=ca_incr,
            group_drop_ssthresh_divisor=ssthresh_divisor,
            host_drop_ssthresh_divisor=ssthresh_divisor,
            tryno_cap=tmpl.max_retries,
        )


# ---------------------------------------------------------------------------
# struct ultra_timing_vals  (scan_engine.h + timing.cc)
# ---------------------------------------------------------------------------


@dataclass
class UltraTimingVals:
    """
    Okno zatłoczenia w stylu TCP (slow start + congestion avoidance).

    To jest serce nmapowego sterowania tempem: cwnd mówi, ile sond może być
    jednocześnie "w powietrzu". Reakcja na odpowiedź = ack(), na timeout =
    drop() / drop_group().
    """

    cwnd: float = 10.0
    ssthresh: int = 75
    num_replies_expected: int = 0
    num_replies_received: int = 0
    num_updates: int = 0
    last_drop: float = field(default_factory=lambda: 0.0)

    @classmethod
    def init_for(
        cls, perf: ScanPerformanceVars, group: bool, now: float | None = None
    ) -> UltraTimingVals:
        """Odpowiednik init_ultra_timing_vals() z scan_engine.cc."""
        cwnd = perf.group_initial_cwnd if group else perf.host_initial_cwnd
        return cls(
            cwnd=float(cwnd),
            ssthresh=perf.initial_ssthresh,
            last_drop=now if now is not None else time.monotonic(),
        )

    def cc_scale(self, perf: ScanPerformanceVars) -> float:
        """
        Port ultra_timing_vals::cc_scale().

        Skaluje wzrost cwnd przez stosunek oczekiwanych do otrzymanych
        odpowiedzi — po serii strat okno rośnie wolniej.
        """
        if self.num_replies_received <= 0:
            return 1.0
        ratio = self.num_replies_expected / self.num_replies_received
        return min(ratio, float(perf.cc_scale_max))

    def ack(self, perf: ScanPerformanceVars, scale: float = 1.0) -> None:
        """Port ultra_timing_vals::ack() — przyszła odpowiedź, rośniemy."""
        self.num_replies_received += 1
        factor = self.cc_scale(perf)

        if self.cwnd < self.ssthresh:
            # slow start
            self.cwnd += perf.slow_incr * factor * scale
            if self.cwnd > self.ssthresh:
                self.cwnd = float(self.ssthresh)
        else:
            # congestion avoidance: +1 segment na RTT
            self.cwnd += perf.ca_incr / self.cwnd * factor * scale

        if self.cwnd > perf.max_cwnd:
            self.cwnd = float(perf.max_cwnd)

    def drop(
        self, in_flight: int, perf: ScanPerformanceVars, now: float
    ) -> None:
        """Port ultra_timing_vals::drop() — timeout per-host, ostra reakcja."""
        self.cwnd = float(perf.low_cwnd)
        self.ssthresh = int(max(in_flight / perf.host_drop_ssthresh_divisor, 2))
        self.last_drop = now

    def drop_group(
        self, in_flight: int, perf: ScanPerformanceVars, now: float
    ) -> None:
        """Port ultra_timing_vals::drop_group() — łagodniejsza reakcja grupowa."""
        self.cwnd = max(float(perf.low_cwnd), self.cwnd / perf.group_drop_cwnd_divisor)
        self.ssthresh = int(max(in_flight / perf.group_drop_ssthresh_divisor, 2))
        self.last_drop = now
