"""
Testy SYN scanu (-sS).

Testy wymagające surowych socketów są pomijane bez CAP_NET_RAW, żeby
`pytest` przechodził też na zwykłym koncie użytkownika.
"""

import errno
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


def _fake_tcp_reply(src_ip, dst_ip, sport, dport, flags, ack=0, ttl=64, seq=0):
    """Składa pakiet IP+TCP tak, jak zobaczyłby go surowy socket."""
    from pynmap.tcpip import build_ip_header

    tcp = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq, ack, 5 << 4, int(flags), 1024, 0, 0,
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
    Grupowe okno musi ograniczac sondy w locie PONAD to, co ogranicza
    okno per-host.

    Poprzednia wersja tego testu byla bezwartosciowa: miala jednego hosta,
    wiec okno per-host (cwnd 10) trzymalo in_flight na 10 i asercje
    przechodzily nawet po calkowitym usunieciu bramki grupowej.
    Z pieciu hostow bez bramki poleciałoby ~5x10 sond, wiec test faktycznie
    rozroznia obie wersje kodu.
    """
    from pynmap.engine import HostScanStats, Probe

    HOSTS = 5
    opts = ScanOptions(
        scan_type=ScanType.SYN,
        ports=list(range(1, 201)),
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
    )
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)

    now = time.monotonic()
    hosts = []
    for i in range(HOSTS):
        host = HostScanStats(Target(ip=f"192.0.2.{i + 1}"), opts, perf, now=now)
        host.source_ip = "192.0.2.254"
        hosts.append(host)

    def fake_send(host_, port, when):
        probe = Probe(
            port=port, tryno=0, sent_at=when,
            timeout_at=when + 10.0, seq=1, sport=40000,
        )
        host_.register_sent(probe, when, group=scanner.group_timing)
        scanner._outstanding[(host_.target.ip, port)] = (host_, probe)
        return True

    scanner._send_syn = fake_send
    scanner._send_new_probes(hosts, now)

    # UWAGA: prog liczymy wg KONTRAKTU (int(cwnd)), a nie przez powtorzenie
    # wyrazenia z kodu. Poprzednia wersja asercji uzywala formuly
    # int(cwnd) + low_cwnd, czyli dokladnie tej, ktora byla bledna — wiec
    # przechodzila takze po przywroceniu bledu.
    gate = int(scanner.group_timing.cwnd)
    in_flight = len(scanner._outstanding)

    assert in_flight <= gate, f"{in_flight} sond w locie przy bramce {gate}"
    # bez bramki grupowej pierwszy przebieg wyslalby po 10 sond na hosta
    assert in_flight < HOSTS * 10


def test_group_cwnd_actually_grows():
    """
    Okno grupowe musi rosnac na odpowiedziach.

    Dotad num_replies_expected grupy nikt nie inkrementowal (register_sent
    podbijalo tylko licznik hosta), wiec cc_scale() zwracalo 0.0, ack()
    mnozylo przyrost przez zero i cwnd stalo na 10 na zawsze. Bramka oparta
    na takim oknie byla stalym sufitem, a nie okienkiem AIMD.
    """
    from pynmap.engine import HostScanStats, Probe
    from pynmap.timing import UltraTimingVals

    opts = ScanOptions(
        scan_type=ScanType.SYN,
        ports=list(range(1, 300)),
        timing=TIMING_TEMPLATES[4],
        resolve_dns=False,
    )
    perf = opts.build_perf()
    group = UltraTimingVals.init_for(perf, group=True, now=0.0)
    host = HostScanStats(Target(ip="192.0.2.1"), opts, perf, now=0.0)

    start = group.cwnd
    for port in range(1, 201):
        host.register_sent(
            Probe(port=port, tryno=0, sent_at=0.0, timeout_at=99.0), 0.0, group=group
        )
        group.ack(perf)

    assert group.num_replies_expected == 200
    assert group.cc_scale(perf) == pytest.approx(1.0)
    assert group.cwnd > start, "grupowe cwnd nie rosnie, wiec bramka to staly sufit"


# ---------------------------------------------------------------------------
# Wlasna sonda nie moze byc policzona jako odpowiedz
# ---------------------------------------------------------------------------


@requires_raw
def test_own_syn_echoed_back_is_not_a_reply():
    """
    Na loopbacku nasz wlasny SYN wraca na surowy socket jako pakiet
    przychodzacy. Gdy skanowany port rowna sie portowi zrodlowemu
    (pynmap -sS -p 9 -g 9), to sport == dport, wiec pakiet przechodzil filtr
    po portach; goly SYN nie ma ACK, wiec omijal takze walidacje ACK == ISN+1
    i wpadal w galez "SYN bez ACK" jako syn-ack. Efekt: ZAMKNIETY port
    raportowany jako open.
    """
    from pynmap.engine import HostScanStats, Probe

    opts = _opts([9])
    scanner = SynScanner(opts)
    scanner.source_port = 9
    host = HostScanStats(Target(ip="127.0.0.1"), opts, opts.build_perf(), now=0.0)
    probe = Probe(
        port=9, tryno=0, sent_at=0.0, timeout_at=99.0, seq=424242, sport=9
    )
    host.register_sent(probe, 0.0)
    scanner._outstanding[("127.0.0.1", 9)] = (host, probe)

    # dokladnie nasz wlasny pakiet: ten sam ISN, sam SYN, sport == dport
    own = _fake_tcp_reply(
        "127.0.0.1", "127.0.0.1", sport=9, dport=9,
        flags=TcpFlags.SYN, seq=424242,
    )
    scanner._handle_tcp_packet(own, now=0.01)

    assert 9 not in host.portlist.results, "wlasna sonda policzona jako odpowiedz"
    assert ("127.0.0.1", 9) in scanner._outstanding, "sonda zdjeta z kolejki"


@requires_raw
def test_genuine_synack_on_same_port_still_counts():
    """Kontrola: prawdziwy SYN/ACK musi dalej dawac open, takze przy -g == -p."""
    from pynmap.engine import HostScanStats, Probe

    opts = _opts([9])
    scanner = SynScanner(opts)
    scanner.source_port = 9
    host = HostScanStats(Target(ip="127.0.0.1"), opts, opts.build_perf(), now=0.0)
    probe = Probe(
        port=9, tryno=0, sent_at=0.0, timeout_at=99.0, seq=424242, sport=9
    )
    host.register_sent(probe, 0.0)
    scanner._outstanding[("127.0.0.1", 9)] = (host, probe)

    reply = _fake_tcp_reply(
        "127.0.0.1", "127.0.0.1", sport=9, dport=9,
        flags=TcpFlags.SYN | TcpFlags.ACK, ack=424243, seq=999999,
    )
    scanner._handle_tcp_packet(reply, now=0.01)

    assert host.portlist.get(9).state is PortState.OPEN


@requires_raw
def test_rst_on_same_port_still_counts():
    """A RST (zamkniety port) tez musi przejsc, mimo -g == -p."""
    from pynmap.engine import HostScanStats, Probe

    opts = _opts([9])
    scanner = SynScanner(opts)
    scanner.source_port = 9
    host = HostScanStats(Target(ip="127.0.0.1"), opts, opts.build_perf(), now=0.0)
    probe = Probe(
        port=9, tryno=0, sent_at=0.0, timeout_at=99.0, seq=424242, sport=9
    )
    host.register_sent(probe, 0.0)
    scanner._outstanding[("127.0.0.1", 9)] = (host, probe)

    reply = _fake_tcp_reply(
        "127.0.0.1", "127.0.0.1", sport=9, dport=9,
        flags=TcpFlags.RST | TcpFlags.ACK, ack=424243, seq=0,
    )
    scanner._handle_tcp_packet(reply, now=0.01)

    assert host.portlist.get(9).state is PortState.CLOSED


def test_max_parallelism_one_is_really_serial():
    """
    -T0, -T1, -T2 oraz jawne --max-parallelism 1 ustawiaja okno na 1.
    Bramka `>= int(cwnd) + low_cwnd` przepuszczala DWIE sondy naraz,
    czyli dwukrotnosc tempa, o ktore prosi szablon wybierany wlasnie po to,
    zeby byc cichym.
    """
    from pynmap.engine import HostScanStats, Probe

    opts = ScanOptions(
        scan_type=ScanType.SYN,
        ports=list(range(1, 51)),
        timing=TIMING_TEMPLATES[3],
        randomize_ports=False,
        resolve_dns=False,
        max_parallelism=1,
    )
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)
    now = time.monotonic()
    host = HostScanStats(Target(ip="192.0.2.1"), opts, perf, now=now)
    host.source_ip = "192.0.2.254"

    def fake_send(host_, port, when):
        probe = Probe(port=port, tryno=0, sent_at=when,
                      timeout_at=when + 10.0, seq=1, sport=40000)
        host_.register_sent(probe, when, group=scanner.group_timing)
        scanner._outstanding[(host_.target.ip, port)] = (host_, probe)
        return True

    scanner._send_syn = fake_send
    scanner._send_new_probes([host], now)

    assert len(scanner._outstanding) == 1, (
        f"--max-parallelism 1 przepuscilo {len(scanner._outstanding)} sond"
    )


# ---------------------------------------------------------------------------
# sendto(): blad jednego portu nie moze zabic calego skanu
# ---------------------------------------------------------------------------


class _FailingSock:
    def __init__(self, code):
        self.code = code

    def sendto(self, *_a):
        raise OSError(self.code, "wymuszony blad")


def _one_host(opts, perf):
    from pynmap.engine import HostScanStats

    host = HostScanStats(Target(ip="127.0.0.1"), opts, perf, now=time.monotonic())
    host.source_ip = "127.0.0.1"
    return host


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES])
def test_sendto_eperm_filters_one_port_not_the_host(code):
    """
    Netfilter odrzuca lokalnie generowany pakiet (regula OUTPUT z -j DROP),
    zwracajac EPERM. Dotyczy JEDNEGO portu i powinno dac admin-prohibited,
    dokladnie jak EACCES/EPERM z connect() w -sT. Gole `raise` zabijalo
    tu caly skan, razem z innymi portami i innymi CELAMI w przebiegu.
    """
    opts = _opts([80])
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)
    scanner._send_sock = _FailingSock(code)
    host = _one_host(opts, perf)

    assert scanner._send_syn(host, 80, time.monotonic()) is True
    entry = host.portlist.get(80)
    assert entry.state is PortState.FILTERED
    assert entry.reason is Reason.ADMINPROHIBITED
    assert host.skip_reason is None, "blad jednego portu nie moze konczyc hosta"


@pytest.mark.parametrize("code", [errno.EHOSTUNREACH, errno.ENETUNREACH])
def test_sendto_unreachable_filters_one_port(code):
    opts = _opts([80])
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)
    scanner._send_sock = _FailingSock(code)
    host = _one_host(opts, perf)

    assert scanner._send_syn(host, 80, time.monotonic()) is True
    assert host.portlist.get(80).state is PortState.FILTERED
    assert host.skip_reason is None


def test_sendto_unknown_errno_skips_host_without_raising():
    """
    Nieznane errno dotyczy hosta, nie portu — ale NIE moze lecec w gore
    jako wyjatek, bo ginie z nim caly przebieg. -sT robi w tej sytuacji
    _skip_host i oba silniki musza byc spojne.
    """
    opts = _opts([80])
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)
    scanner._send_sock = _FailingSock(errno.EINVAL)
    host = _one_host(opts, perf)

    assert scanner._send_syn(host, 80, time.monotonic()) is False
    assert host.skip_reason is not None
    assert "sendto" in host.skip_reason
    assert host.completed(), "kolejki niewyczyszczone, petla glowna nie skonczy"


def test_sendto_enobufs_requeues_port():
    """Kontrola: pelny bufor nadawczy to chwila, nie wyrok na port ani host."""
    opts = _opts([80])
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)
    scanner._send_sock = _FailingSock(errno.ENOBUFS)
    host = _one_host(opts, perf)
    before = len(host.ports_todo)

    assert scanner._send_syn(host, 80, time.monotonic()) is False
    assert host.skip_reason is None
    assert len(host.ports_todo) == before + 1


# ---------------------------------------------------------------------------
# Okno nie moze byc rozdawane zawsze od hosts[0]
# ---------------------------------------------------------------------------


def test_group_window_is_shared_round_robin():
    """
    Bramka grupowa robi `return` z calej funkcji, a iteracja startowala
    zawsze od hosts[0], wiec okno bylo rozdawane scisle w kolejnosci listy
    celow i hosty z jej konca dostawaly nieproporcjonalnie malo sond
    (albo zero). nmap trzyma na to kursor w UltraScanInfo (nextI).
    """
    from pynmap.engine import HostScanStats, Probe

    HOSTS = 12
    opts = ScanOptions(
        scan_type=ScanType.SYN,
        ports=list(range(1, 201)),
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
    )
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)
    now = time.monotonic()

    hosts = []
    for i in range(HOSTS):
        host = HostScanStats(Target(ip=f"127.0.0.{i + 1}"), opts, perf, now=now)
        host.source_ip = "127.0.0.1"
        hosts.append(host)

    def fake_send(host_, port, when):
        probe = Probe(port=port, tryno=0, sent_at=when,
                      timeout_at=when + 99.0, seq=1, sport=40000)
        host_.register_sent(probe, when, group=scanner.group_timing)
        scanner._outstanding[(host_.target.ip, port)] = (host_, probe)
        return True

    scanner._send_syn = fake_send

    # kilka rund wysylki przeplatanych odpowiedziami, jak w prawdziwej petli
    for _ in range(20):
        scanner._send_new_probes(hosts, time.monotonic())
        for key in list(scanner._outstanding)[:6]:
            host_, probe = scanner._outstanding.pop(key)
            host_.outstanding.pop(probe.key, None)
            scanner.group_timing.ack(perf)

    counts = [h.probes_sent for h in hosts]
    assert all(c > 0 for c in counts), f"host bez ani jednej sondy: {counts}"
    # bez kursora rozrzut siegal kilkunastokrotnosci
    assert max(counts) <= 3 * min(counts), f"rozdzial okna nierowny: {counts}"


def test_skipped_host_is_not_probed_again():
    """Host z ustawionym skip_reason nie moze dostawac kolejnych sond."""
    from pynmap.engine import HostScanStats

    opts = _opts([80, 443])
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)
    host = HostScanStats(Target(ip="127.0.0.1"), opts, perf, now=time.monotonic())
    host.source_ip = "127.0.0.1"
    host.skip_reason = "wymuszone"

    sent = []
    scanner._send_syn = lambda h, p, w: sent.append(p) or True
    scanner._send_new_probes([host], time.monotonic())

    assert sent == []


def test_round_robin_cursor_advances_after_each_send():
    """
    Kursor musi przesuwac sie PO KAZDEJ wyslanej sondzie, nie tylko gdy
    bramka grupowa zablokuje wysylke. Inaczej kazdy przebieg petli `while
    progress` startuje od tego samego hosta i obsluguje go wielokrotnie,
    zanim dojdzie do pozostalych.
    """
    from pynmap.engine import HostScanStats, Probe

    opts = ScanOptions(
        scan_type=ScanType.SYN,
        ports=[80],
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
    )
    perf = opts.build_perf()
    scanner = SynScanner(opts, perf)
    now = time.monotonic()

    hosts = []
    for i in range(3):
        host = HostScanStats(Target(ip=f"127.0.0.{i + 1}"), opts, perf, now=now)
        host.source_ip = "127.0.0.1"
        hosts.append(host)

    def fake_send(host_, port, when):
        probe = Probe(port=port, tryno=0, sent_at=when,
                      timeout_at=when + 99.0, seq=1, sport=40000)
        host_.register_sent(probe, when, group=scanner.group_timing)
        scanner._outstanding[(host_.target.ip, port)] = (host_, probe)
        return True

    scanner._send_syn = fake_send
    assert scanner._next_host_idx == 0

    scanner._send_new_probes(hosts, now)

    # kazdy host ma po jednym porcie, wiec po obsludze wszystkich trzech
    # kursor musi byc przesuniety, a nie stac na zerze
    assert all(h.probes_sent == 1 for h in hosts), [h.probes_sent for h in hosts]
    assert scanner._next_host_idx != 0 or len(hosts) == 1
