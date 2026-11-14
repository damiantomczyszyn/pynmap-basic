"""
Testy SYN scanu (-sS).

Testy wymagające surowych socketów są pomijane bez CAP_NET_RAW, żeby
`pytest` przechodził też na zwykłym koncie użytkownika.
"""

import socket
import struct
import threading
import time

import pytest

from pynmap.constants import PortState, Reason, ScanType, TcpFlags
from pynmap.engine import ScanOptions, is_root
from pynmap.scan_syn import RawSocketError, SynScanner, syn_scan
from pynmap.targets import Target
from pynmap.tcpip import ICMP_UNREACH_FILTERED_CODES
from pynmap.timing import TIMING_TEMPLATES

requires_raw = pytest.mark.skipif(
    not is_root(), reason="SYN scan wymaga CAP_NET_RAW (uruchom jako root)"
)


# ---------------------------------------------------------------------------
# Tabela kodów ICMP
# ---------------------------------------------------------------------------


def test_icmp_filtered_codes_match_nmap():
    """
    nmap traktuje jako 'filtered' kody ICMP type 3:
    1 host, 2 protocol, 3 port, 9/10/13 administratively prohibited.
    """
    assert frozenset({1, 2, 3, 9, 10, 13}) == ICMP_UNREACH_FILTERED_CODES
    for code in (0, 4, 5, 6, 7, 8, 11, 12, 14, 15):
        assert code not in ICMP_UNREACH_FILTERED_CODES


# ---------------------------------------------------------------------------
# Logika interpretacji odpowiedzi (bez sieci)
# ---------------------------------------------------------------------------


def _opts(ports):
    return ScanOptions(
        scan_type=ScanType.SYN,
        ports=ports,
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
        max_retries=0,
    )


def _fake_tcp_reply(src_ip, dst_ip, sport, dport, flags, ack=0, ttl=64):
    """Składa pakiet IP+TCP tak, jak zobaczyłby go surowy socket."""
    from pynmap.tcpip import build_ip_header

    tcp = struct.pack(
        "!HHIIBBHHH",
        sport, dport, 0, ack, 5 << 4, int(flags), 1024, 0, 0,
    )
    ip = build_ip_header(src_ip, dst_ip, len(tcp), socket.IPPROTO_TCP, ttl=ttl)
    return ip + tcp


@requires_raw
def test_synack_marks_port_open():
    scanner = SynScanner(_opts([80]))
    scanner._open_sockets()
    try:
        from pynmap.engine import HostScanStats, Probe

        opts = _opts([80])
        host = HostScanStats(Target(ip="10.1.2.3"), opts, opts.build_perf(), now=0.0)
        probe = Probe(
            port=80, tryno=0, sent_at=0.0, timeout_at=99.0,
            seq=1000, sport=scanner.source_port,
        )
        host.register_sent(probe, 0.0)
        scanner._outstanding[("10.1.2.3", 80)] = (host, probe)

        packet = _fake_tcp_reply(
            "10.1.2.3", "10.0.0.1",
            sport=80, dport=scanner.source_port,
            flags=TcpFlags.SYN | TcpFlags.ACK, ack=1001,
        )
        scanner._handle_tcp_packet(packet, now=0.01)

        entry = host.portlist.get(80)
        assert entry.state is PortState.OPEN
        assert entry.reason is Reason.SYNACK
        assert entry.reason_ttl == 64
    finally:
        scanner._close_sockets()


@requires_raw
def test_rst_marks_port_closed():
    scanner = SynScanner(_opts([81]))
    scanner._open_sockets()
    try:
        from pynmap.engine import HostScanStats, Probe

        opts = _opts([81])
        host = HostScanStats(Target(ip="10.1.2.3"), opts, opts.build_perf(), now=0.0)
        probe = Probe(
            port=81, tryno=0, sent_at=0.0, timeout_at=99.0,
            seq=2000, sport=scanner.source_port,
        )
        host.register_sent(probe, 0.0)
        scanner._outstanding[("10.1.2.3", 81)] = (host, probe)

        packet = _fake_tcp_reply(
            "10.1.2.3", "10.0.0.1",
            sport=81, dport=scanner.source_port, flags=TcpFlags.RST,
        )
        scanner._handle_tcp_packet(packet, now=0.01)

        assert host.portlist.get(81).state is PortState.CLOSED
        assert host.portlist.get(81).reason is Reason.RESETPEER
    finally:
        scanner._close_sockets()


@requires_raw
def test_reply_to_wrong_source_port_is_ignored():
    scanner = SynScanner(_opts([80]))
    scanner._open_sockets()
    try:
        from pynmap.engine import HostScanStats, Probe

        opts = _opts([80])
        host = HostScanStats(Target(ip="10.1.2.3"), opts, opts.build_perf(), now=0.0)
        probe = Probe(
            port=80, tryno=0, sent_at=0.0, timeout_at=99.0,
            seq=1, sport=scanner.source_port,
        )
        host.register_sent(probe, 0.0)
        scanner._outstanding[("10.1.2.3", 80)] = (host, probe)

        # port docelowy != nasz port źródłowy -> pakiet nie jest nasz
        packet = _fake_tcp_reply(
            "10.1.2.3", "10.0.0.1",
            sport=80, dport=scanner.source_port + 1,
            flags=TcpFlags.SYN | TcpFlags.ACK, ack=2,
        )
        scanner._handle_tcp_packet(packet, now=0.01)

        # pakiet zignorowany => brak wpisu i sonda nadal "w powietrzu"
        assert 80 not in host.portlist.results
        assert ("10.1.2.3", 80) in scanner._outstanding
    finally:
        scanner._close_sockets()


@requires_raw
def test_bad_ack_number_is_ignored():
    """Walidacja ACK == ISN+1 chroni przed cudzym/zafałszowanym ruchem."""
    scanner = SynScanner(_opts([80]))
    scanner._open_sockets()
    try:
        from pynmap.engine import HostScanStats, Probe

        opts = _opts([80])
        host = HostScanStats(Target(ip="10.1.2.3"), opts, opts.build_perf(), now=0.0)
        probe = Probe(
            port=80, tryno=0, sent_at=0.0, timeout_at=99.0,
            seq=5000, sport=scanner.source_port,
        )
        host.register_sent(probe, 0.0)
        scanner._outstanding[("10.1.2.3", 80)] = (host, probe)

        packet = _fake_tcp_reply(
            "10.1.2.3", "10.0.0.1",
            sport=80, dport=scanner.source_port,
            flags=TcpFlags.SYN | TcpFlags.ACK, ack=99999,  # zły ACK
        )
        scanner._handle_tcp_packet(packet, now=0.01)

        # ACK nie potwierdza naszego ISN+1 => odpowiedź odrzucona
        assert 80 not in host.portlist.results
        assert ("10.1.2.3", 80) in scanner._outstanding
    finally:
        scanner._close_sockets()


# ---------------------------------------------------------------------------
# Test end-to-end
# ---------------------------------------------------------------------------


@pytest.fixture
def listener():
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
    tmp = socket.socket()
    tmp.bind(("127.0.0.1", 0))
    port = tmp.getsockname()[1]
    tmp.close()
    return port


@requires_raw
def test_syn_scan_end_to_end(listener, closed_port):
    opts = _opts([listener, closed_port])
    reports = syn_scan([Target(ip="127.0.0.1")], opts)

    assert len(reports) == 1
    report = reports[0]
    assert report.portlist.get(listener).state is PortState.OPEN
    assert report.portlist.get(closed_port).state is PortState.CLOSED


@requires_raw
def test_syn_scan_skips_ipv6_targets():
    opts = _opts([80])
    reports = syn_scan([Target(ip="::1", family=socket.AF_INET6)], opts)
    assert len(reports) == 1
    assert reports[0].host_up is False
    # powód jedzie w raporcie, a nie jest zaszyty na sztywno w output.py,
    # żeby "Skipping ..." nie kłamało przy innych przyczynach pominięcia
    assert reports[0].skip_reason is not None
    assert "-sT" in reports[0].skip_reason


def test_raw_socket_error_message_mentions_alternative():
    """Komunikat błędu musi podpowiedzieć -sT, bo to typowa pomyłka."""
    exc = RawSocketError(
        "SYN scan (-sS) wymaga uprawnień do surowych socketów (CAP_NET_RAW). "
        "Alternatywa bez roota: -sT (connect scan)."
    )
    assert "-sT" in str(exc)


# ---------------------------------------------------------------------------
# Grupowe okno zatłoczenia bramkuje wysyłkę (jak w -sT)
# ---------------------------------------------------------------------------


def test_group_cwnd_limits_probes_in_flight():
    """
    group_timing było liczone (ack/drop_group), ale nigdy nie odpytywane,
    więc w -sS tempo ograniczało tylko okno per-host. Nie wymaga raw
    socketów: podmieniamy samą wysyłkę.
    """
    from pynmap.engine import HostScanStats, Probe

    opts = ScanOptions(
        scan_type=ScanType.SYN,
        ports=list(range(1, 501)),
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
    )
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)

    now = time.monotonic()
    host = HostScanStats(Target(ip="192.0.2.1"), opts, perf, now=now)
    host.source_ip = "192.0.2.2"

    def fake_send(host_, port, when):
        probe = Probe(
            port=port, tryno=0, sent_at=when,
            timeout_at=when + 10.0, seq=1, sport=40000,
        )
        host_.register_sent(probe, when)
        scanner._outstanding[(host_.target.ip, port)] = (host_, probe)
        return True

    scanner._send_syn = fake_send
    scanner._send_new_probes([host], now)

    gate = int(scanner.group_timing.cwnd) + perf.low_cwnd
    assert len(scanner._outstanding) <= gate
    # bramka musi faktycznie przyciąć wysyłkę, a nie przepuścić 500 sond
    assert len(scanner._outstanding) < 500
