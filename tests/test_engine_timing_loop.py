"""
Testy pętli głównej silnika: ile wolno czekać w select().

To jest regresja na błąd, w którym pętla kręciła się na 100% CPU zawsze,
gdy nic nie leciało w powietrzu, a wysyłkę blokował tylko --scan-delay
(czyli przy -T0, -T1, -T2 i każdym jawnym --scan-delay).
"""

import time

import pytest

from pynmap.constants import ScanType
from pynmap.engine import HostScanStats, Probe, ScanOptions, select_timeout
from pynmap.targets import Target
from pynmap.timing import TIMING_TEMPLATES


def _host(ports, now, **kwargs):
    opts = ScanOptions(
        scan_type=ScanType.CONNECT,
        ports=ports,
        timing=TIMING_TEMPLATES[3],
        randomize_ports=False,
        **kwargs,
    )
    return HostScanStats(Target(ip="192.0.2.1"), opts, opts.build_perf(), now=now)


# ---------------------------------------------------------------------------
# next_send_allowed_at()
# ---------------------------------------------------------------------------


def test_no_scan_delay_allows_immediate_send():
    now = time.monotonic()
    host = _host([80], now)
    assert host.next_send_allowed_at() == 0.0


def test_scan_delay_pushes_next_send_into_future():
    now = time.monotonic()
    host = _host([80, 443], now, scan_delay_s=2.0)
    probe = Probe(port=80, tryno=0, sent_at=now, timeout_at=now + 1.0)
    host.register_sent(probe, now)
    host.outstanding.clear()  # odpowiedź przyszła od razu

    assert host.next_send_allowed_at() == now + 2.0
    assert not host.send_ok(now)


# ---------------------------------------------------------------------------
# select_timeout()
# ---------------------------------------------------------------------------


def test_timeout_follows_soonest_probe():
    now = time.monotonic()
    host = _host([80], now)
    host.register_sent(
        Probe(port=80, tryno=0, sent_at=now, timeout_at=now + 0.03), now
    )
    # approx, bo (now + 0.03) - now nie wraca dokładnie jako 0.03:
    # błąd zależy od rzędu wielkości time.monotonic(), więc ostre `<= 0.03`
    # przechodzi lokalnie i oblewa na innej maszynie
    assert select_timeout([host], now) == pytest.approx(0.03, abs=1e-6)


def test_timeout_is_capped_for_host_timeout_responsiveness():
    now = time.monotonic()
    host = _host([80], now)
    host.register_sent(
        Probe(port=80, tryno=0, sent_at=now, timeout_at=now + 60.0), now
    )
    assert select_timeout([host], now, max_wait=0.1) == 0.1


def test_scan_delay_wait_is_slept_not_spun():
    """Rdzeń regresji: brak sond + --scan-delay musi dać dodatni timeout."""
    now = time.monotonic()
    host = _host([80, 443], now, scan_delay_s=2.0)
    host.register_sent(
        Probe(port=80, tryno=0, sent_at=now, timeout_at=now + 1.0), now
    )
    host.outstanding.clear()

    waited = select_timeout([host], now, max_wait=0.5)
    assert waited > 0.0, "timeout 0 oznacza pętlę na 100% CPU przez 2 s"
    assert waited <= 0.5


def test_paranoid_template_also_waits():
    """-T0 ma scan_delay 300 s — kiedyś palił rdzeń przez cały ten czas."""
    now = time.monotonic()
    opts = ScanOptions(ports=[80, 443], timing=TIMING_TEMPLATES[0])
    host = HostScanStats(Target(ip="192.0.2.1"), opts, opts.build_perf(), now=now)
    host.register_sent(
        Probe(port=80, tryno=0, sent_at=now, timeout_at=now + 1.0), now
    )
    host.outstanding.clear()

    assert select_timeout([host], now, max_wait=0.1) == 0.1


def test_ready_host_gets_zero_timeout():
    """Gdy wolno wysyłać, nie ma na co czekać — pętla ma iść wysłać sondę."""
    now = time.monotonic()
    host = _host([80, 443], now)
    assert select_timeout([host], now) == 0.0


def test_no_work_left_returns_small_nonzero():
    now = time.monotonic()
    host = _host([80], now)
    host.ports_todo.clear()
    assert select_timeout([host], now) == 0.01


def test_timed_out_host_is_not_waited_for():
    now = time.monotonic()
    host = _host([80, 443], now, scan_delay_s=5.0)
    host.timed_out = True
    assert select_timeout([host], now) == 0.01


# ---------------------------------------------------------------------------
# last_probe_sent: sentinel "nic nie wyslano" nie moze byc punktem na skali
# ---------------------------------------------------------------------------


def test_first_probe_is_not_delayed_by_scan_delay():
    """
    --scan-delay to przerwa MIEDZY sondami, wiec pierwsza sonda idzie od razu.

    Sentinel last_probe_sent byl kiedys 0.0, czyli poprawnym punktem na skali
    time.monotonic() (chwila bootu). Na maszynie o uptime mniejszym niz
    scan_delay wyrazenie last_probe_sent + delay wypadalo w PRZYSZLOSCI
    i pierwsza sonda byla wstrzymywana o (scan_delay - uptime) sekund:
    do 300 s przy -T0. Test odtwarza to, podajac maly `now`.
    """
    now = 2.0  # jakby maszyna wstala 2 s temu
    host = _host([80, 443], now, scan_delay_s=60.0)

    assert host.last_probe_sent is None
    assert host.next_send_allowed_at() == 0.0
    assert host.send_ok(now) is True
    assert select_timeout([host], now) == 0.0


def test_scan_delay_applies_after_the_first_probe():
    """...ale po pierwszej sondzie przerwa juz obowiazuje."""
    now = 2.0
    host = _host([80, 443], now, scan_delay_s=60.0)
    host.register_sent(
        Probe(port=80, tryno=0, sent_at=now, timeout_at=now + 1.0), now
    )
    host.outstanding.clear()

    assert host.last_probe_sent == now
    assert host.next_send_allowed_at() == now + 60.0
    assert host.send_ok(now) is False
    assert select_timeout([host], now, max_wait=0.1) == 0.1


@pytest.mark.parametrize("level", [0, 1, 2])
def test_delaying_templates_still_send_immediately_on_fresh_boot(level):
    now = 2.0
    opts = ScanOptions(ports=[80, 443], timing=TIMING_TEMPLATES[level])
    host = HostScanStats(Target(ip="192.0.2.1"), opts, opts.build_perf(), now=now)
    assert host.send_ok(now) is True, f"-T{level} wstrzymuje pierwsza sonde"
    assert select_timeout([host], now) == 0.0


# ---------------------------------------------------------------------------
# Zablokowane okno zatloczenia nie moze dawac petli na 100% CPU
# ---------------------------------------------------------------------------


def test_blocked_window_waits_instead_of_spinning():
    """
    Gdy zegar pozwala wysylac, ale okno zatloczenia nie przepuszcza zadnej
    sondy, select_timeout() NIE moze zwrocic 0.0 — to byla petla na 100% CPU
    bez zadnego wyjscia i bez jednej linii wyjscia.
    """
    now = 100.0
    host = _host([80, 443], now)
    host.timing.cwnd = 0.0  # okno zamkniete, nic nie leci

    assert host.in_flight == 0
    assert host.send_ok(now) is False
    assert host.work_left() is True
    assert select_timeout([host], now, max_wait=0.1) == 0.1


def test_open_window_still_returns_zero():
    """Kontrola: gdy wolno wysylac, timeout musi byc 0, zeby nie zwalniac skanu."""
    now = 100.0
    host = _host([80, 443], now)
    assert host.send_ok(now) is True
    assert select_timeout([host], now) == 0.0


def test_negative_parallelism_cannot_produce_dead_window():
    """ScanPerformanceVars broni sie przed cwnd <= 0 nawet wolane z API."""
    opts = ScanOptions(ports=[80], timing=TIMING_TEMPLATES[3], min_parallelism=-1)
    perf = opts.build_perf()
    assert perf.low_cwnd >= 1
    assert perf.max_cwnd >= perf.low_cwnd
