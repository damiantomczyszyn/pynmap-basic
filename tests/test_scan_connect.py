"""
Testy connect scanu (-sT) — logika errno, retransmisje i test end-to-end
na prawdziwym listenerze lokalnym.
"""

import errno
import socket
import threading
import time

import pytest

from pynmap.constants import PortState, Reason, ScanType
from pynmap.engine import HostScanStats, Probe, ScanOptions
from pynmap.scan_connect import ConnectScanner, classify_connect_errno, connect_scan
from pynmap.targets import Target
from pynmap.timing import TIMING_TEMPLATES

# ---------------------------------------------------------------------------
# Mapowanie errno -> stan (tabela z handleConnectResult)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,expected_state,expected_reason",
    [
        (0, PortState.OPEN, Reason.CONACCEPT),
        (errno.EISCONN, PortState.OPEN, Reason.CONACCEPT),
        (errno.EAGAIN, PortState.OPEN, Reason.CONACCEPT),
        (errno.ECONNREFUSED, PortState.CLOSED, Reason.CONREFUSED),
        (errno.EACCES, PortState.FILTERED, Reason.ADMINPROHIBITED),
        (errno.EPERM, PortState.FILTERED, Reason.ADMINPROHIBITED),
        (errno.EHOSTUNREACH, PortState.FILTERED, Reason.HOSTUNREACH),
        (errno.ENETUNREACH, PortState.FILTERED, Reason.NETUNREACH),
        (errno.ETIMEDOUT, PortState.FILTERED, Reason.NORESPONSE),
        (errno.EHOSTDOWN, PortState.FILTERED, Reason.NORESPONSE),
        (errno.ENOPROTOOPT, PortState.FILTERED, Reason.PROTOUNREACH),
    ],
)
def test_errno_classification(code, expected_state, expected_reason):
    state, reason = classify_connect_errno(code)
    assert state is expected_state
    assert reason is expected_reason


def test_unknown_errno_is_unknown():
    state, reason = classify_connect_errno(12345)
    assert state is PortState.UNKNOWN
    assert reason is Reason.UNKNOWN


# ---------------------------------------------------------------------------
# HostScanStats — kolejkowanie, okno, retransmisje
# ---------------------------------------------------------------------------


def _stats(ports, **kwargs):
    opts = ScanOptions(
        scan_type=ScanType.CONNECT,
        ports=ports,
        timing=TIMING_TEMPLATES[3],
        randomize_ports=False,
        **kwargs,
    )
    return HostScanStats(Target(ip="10.0.0.1"), opts, opts.build_perf(), now=0.0)


def test_ports_are_queued_in_order_when_not_randomized():
    hss = _stats([22, 80, 443])
    assert [hss.next_port() for _ in range(3)] == [22, 80, 443]
    assert hss.next_port() is None


def test_retry_stack_has_priority_over_fresh_ports():
    hss = _stats([22, 80, 443])
    hss.retry_stack.append(9999)
    assert hss.next_port() == 9999   # najpierw retransmisja
    assert hss.next_port() == 22


def test_send_ok_respects_congestion_window():
    hss = _stats(list(range(1, 100)))
    hss.timing.cwnd = 3.0

    for port in (1, 2, 3):
        probe = Probe(port=port, tryno=0, sent_at=0.0, timeout_at=10.0)
        hss.register_sent(probe, 0.0)

    assert hss.in_flight == 3
    assert hss.send_ok(0.0) is False

    hss.timing.cwnd = 4.0
    assert hss.send_ok(0.0) is True


def test_send_ok_respects_scan_delay():
    hss = _stats([80], scan_delay_s=1.0)
    hss.last_probe_sent = 10.0
    assert hss.send_ok(10.5) is False
    assert hss.send_ok(11.1) is True


def test_timeout_retries_until_cap_then_marks_filtered():
    hss = _stats([80], max_retries=2)

    # próba 0 i 1 -> wracają na stos
    for tryno in (0, 1):
        probe = Probe(port=80, tryno=tryno, sent_at=0.0, timeout_at=1.0)
        hss.register_sent(probe, 0.0)
        assert hss.register_timeout(probe, now=2.0) is True
        assert hss.retry_stack == [80]
        hss.retry_stack.clear()

    # próba 2 == max_retries -> koniec, port filtered
    probe = Probe(port=80, tryno=2, sent_at=0.0, timeout_at=1.0)
    hss.register_sent(probe, 0.0)
    assert hss.register_timeout(probe, now=2.0) is False
    assert hss.portlist.get(80).state is PortState.FILTERED
    assert hss.portlist.get(80).reason is Reason.NORESPONSE


def test_timeout_collapses_congestion_window():
    hss = _stats([80])
    hss.timing.cwnd = 40.0
    probe = Probe(port=80, tryno=0, sent_at=0.0, timeout_at=1.0)
    hss.register_sent(probe, 0.0)
    hss.register_timeout(probe, now=2.0)
    assert hss.timing.cwnd == float(hss.perf.low_cwnd)


def test_reply_learns_rtt_only_on_first_try():
    hss = _stats([80, 443])

    first = Probe(port=80, tryno=0, sent_at=0.0, timeout_at=1.0)
    hss.register_sent(first, 0.0)
    hss.register_reply(first, PortState.OPEN, Reason.CONACCEPT, now=0.25)
    assert hss.to.srtt == 250_000          # nauczył się RTT

    srtt_before = hss.to.srtt
    retry = Probe(port=443, tryno=2, sent_at=0.0, timeout_at=1.0)
    hss.register_sent(retry, 0.0)
    hss.register_reply(retry, PortState.OPEN, Reason.CONACCEPT, now=0.90)
    assert hss.to.srtt == srtt_before      # retransmisja nie uczy RTT


def test_host_timeout_detection():
    hss = _stats([80], host_timeout_s=5.0)
    assert hss.host_timed_out(now=4.0) is False
    assert hss.host_timed_out(now=5.1) is True


def test_completed_when_no_work_left():
    hss = _stats([80])
    assert hss.completed() is False
    hss.next_port()
    assert hss.completed() is True


def test_finalize_fills_unanswered_ports_as_filtered():
    hss = _stats([80, 443, 8080])
    hss.portlist.set_state(80, PortState.OPEN, Reason.CONACCEPT)
    hss.finalize()
    assert hss.portlist.get(443).state is PortState.FILTERED
    assert hss.portlist.get(8080).state is PortState.FILTERED


# ---------------------------------------------------------------------------
# Test end-to-end na lokalnym listenerze
# ---------------------------------------------------------------------------


@pytest.fixture
def listener():
    """Startuje listener na losowym wolnym porcie 127.0.0.1."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(32)
    port = srv.getsockname()[1]

    stop = threading.Event()

    def accept_loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except (TimeoutError, OSError):
                continue

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    time.sleep(0.05)

    yield port

    stop.set()
    thread.join(timeout=1.0)
    srv.close()


@pytest.fixture
def closed_port():
    """Port, na którym pewnie nikt nie słucha (bindujemy i zwalniamy)."""
    tmp = socket.socket()
    tmp.bind(("127.0.0.1", 0))
    port = tmp.getsockname()[1]
    tmp.close()
    return port


def test_connect_scan_detects_open_and_closed(listener, closed_port):
    opts = ScanOptions(
        scan_type=ScanType.CONNECT,
        ports=[listener, closed_port],
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
        max_retries=1,
    )

    reports = connect_scan([Target(ip="127.0.0.1")], opts)

    assert len(reports) == 1
    report = reports[0]

    assert report.portlist.get(listener).state is PortState.OPEN
    assert report.portlist.get(closed_port).state is PortState.CLOSED
    assert report.probes_sent >= 2
    assert report.replies_received >= 2


def test_connect_scan_records_rtt(listener):
    opts = ScanOptions(
        ports=[listener],
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
    )
    report = connect_scan([Target(ip="127.0.0.1")], opts)[0]
    entry = report.portlist.get(listener)
    assert entry.rtt_us is not None
    assert entry.rtt_us >= 0


def test_connect_scan_many_ports_stays_within_socket_budget(listener):
    """Skan 300 portów nie może wyczerpać deskryptorów ani się zawiesić."""
    ports = list(range(listener, listener + 1)) + list(range(49000, 49300))
    opts = ScanOptions(
        ports=ports,
        timing=TIMING_TEMPLATES[5],
        randomize_ports=True,
        resolve_dns=False,
        max_retries=0,
        seed=1234,
    )

    start = time.monotonic()
    report = connect_scan([Target(ip="127.0.0.1")], opts)[0]
    elapsed = time.monotonic() - start

    assert len(report.portlist.results) == len(set(ports))
    assert report.portlist.get(listener).state is PortState.OPEN
    assert elapsed < 60


def test_connect_scan_multiple_hosts(listener):
    opts = ScanOptions(
        ports=[listener],
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
        max_retries=0,
    )
    targets = [Target(ip="127.0.0.1"), Target(ip="127.0.0.2")]
    reports = connect_scan(targets, opts)

    assert len(reports) == 2
    assert [r.target.ip for r in reports] == ["127.0.0.1", "127.0.0.2"]


# ---------------------------------------------------------------------------
# Błąd socket() nie może wywrócić całego skanu
# ---------------------------------------------------------------------------


def test_unsupported_address_family_skips_host_not_scan(monkeypatch):
    """
    Na maszynie z wyłączonym IPv6 socket(AF_INET6) rzuca EAFNOSUPPORT.
    Kiedyś leciał wtedy goły traceback i ginął cały skan — razem
    z celami IPv4, które dałyby się przeskanować. Wystarczyło podać
    nazwę DNS, bo getaddrinfo zwraca też adresy AAAA.
    """
    real_socket = socket.socket

    def fake_socket(family, *args, **kwargs):
        if family == socket.AF_INET6:
            raise OSError(
                errno.EAFNOSUPPORT, "Address family not supported by protocol"
            )
        return real_socket(family, *args, **kwargs)

    monkeypatch.setattr(socket, "socket", fake_socket)

    opts = ScanOptions(
        ports=[80],
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
        max_retries=0,
    )
    targets = [
        Target(ip="::1", family=socket.AF_INET6),
        Target(ip="127.0.0.1"),
    ]
    reports = connect_scan(targets, opts)

    assert len(reports) == 2
    by_ip = {r.target.ip: r for r in reports}

    skipped = by_ip["::1"]
    assert skipped.host_up is False
    assert skipped.skip_reason is not None
    assert "AF_INET6" in skipped.skip_reason

    # cel IPv4 w tym samym przebiegu musi zostać przeskanowany
    scanned = by_ip["127.0.0.1"]
    assert scanned.host_up is True
    assert scanned.portlist.get(80).state is not PortState.UNKNOWN


def test_fd_exhaustion_requeues_port_instead_of_skipping(monkeypatch):
    """EMFILE dotyczy chwili, nie hosta — port musi wrócić do kolejki."""
    real_socket = socket.socket
    calls = {"n": 0}

    def flaky_socket(family, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(errno.EMFILE, "Too many open files")
        return real_socket(family, *args, **kwargs)

    monkeypatch.setattr(socket, "socket", flaky_socket)

    opts = ScanOptions(
        ports=[80],
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
        max_retries=0,
    )
    report = connect_scan([Target(ip="127.0.0.1")], opts)[0]

    assert report.host_up is True
    assert report.skip_reason is None
    assert report.portlist.get(80).state is not PortState.UNKNOWN


# ---------------------------------------------------------------------------
# --host-timeout nie moze wymyslac stanow portow
# ---------------------------------------------------------------------------


def test_finish_host_does_not_finalize_a_timed_out_host():
    """
    Po --host-timeout raportujemy TYLKO porty, do ktorych poszla sonda.

    finalize() dopisuje kazdemu niezbadanemu portowi domyslne 'filtered',
    wiec porzucony host wygladal na w pelni przeskanowany: wyjscie tekstowe
    mowilo "Skipping host due to host timeout", ale -oG i -oJ wypisywaly
    pelna liste portow z WYMYSLONYMI stanami — i to wlasnie te formaty
    sie parsuje.

    Test celuje w sam punkt decyzyjny, bez wyscigu z zegarem: poprzednia
    wersja robila prawdziwy skan z --host-timeout 100ms i przechodzila albo
    nie, zaleznie od obciazenia maszyny.
    """
    opts = ScanOptions(
        ports=[22, 80, 443],
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
    )
    perf = opts.build_perf()
    scanner = ConnectScanner(opts, perf)
    host = HostScanStats(Target(ip="192.0.2.1"), opts, perf, now=time.monotonic())

    # jeden port zdazyl odpowiedziec, pozostale dwie sondy nigdy nie poszly
    host.portlist.set_state(22, PortState.OPEN, Reason.CONACCEPT, rtt_us=120)
    host.timed_out = True

    scanner._finish_host(host)

    assert set(host.portlist.results) == {22}, "stany portow 80/443 zostaly wymyslone"


def test_finish_host_finalizes_a_completed_host():
    """Kontrola: host dobiegniety do konca MUSI miec kazdy zamowiony port."""
    opts = ScanOptions(
        ports=[22, 80, 443],
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
    )
    perf = opts.build_perf()
    scanner = ConnectScanner(opts, perf)
    host = HostScanStats(Target(ip="192.0.2.1"), opts, perf, now=time.monotonic())
    host.portlist.set_state(22, PortState.OPEN, Reason.CONACCEPT, rtt_us=120)

    scanner._finish_host(host)

    assert set(host.portlist.results) == {22, 80, 443}
    assert host.portlist.get(80).state is PortState.FILTERED


def test_host_timeout_end_to_end_never_invents_states(listener):
    """
    Ten sam niezmiennik na prawdziwym skanie, ale sformulowany warunkowo,
    zeby nie scigac sie z zegarem: albo host sie przerwal i wtedy KAZDY
    zaraportowany port ma prawdziwy pomiar, albo dobiegl do konca i wtedy
    raport jest kompletny. Obie galezie sa poprawne, zadna nie jest flaky.
    """
    ports = list(range(1, 4001))
    opts = ScanOptions(
        ports=ports,
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
        host_timeout_s=0.1,
        max_retries=0,
    )
    report = connect_scan([Target(ip="127.0.0.1")], opts)[0]
    results = report.portlist.results

    if report.timed_out:
        assert results, "porzucony host nie zaraportowal ani jednego portu"
        assert all(r.rtt_us is not None for r in results.values())
        assert len(results) <= report.probes_sent
    else:
        assert len(results) == len(ports)
