"""
Testy pętli głównej silnika: ile wolno czekać w select().

To jest regresja na błąd, w którym pętla kręciła się na 100% CPU zawsze,
gdy nic nie leciało w powietrzu, a wysyłkę blokował tylko --scan-delay
(czyli przy -T0, -T1, -T2 i każdym jawnym --scan-delay).
"""

import time

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
    assert 0.0 < select_timeout([host], now) <= 0.03


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
