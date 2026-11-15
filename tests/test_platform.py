"""
Testy zachowania zależnego od systemu.

Wszystkie udają platformę przez sys.platform, więc przechodzą na każdym
systemie — inaczej ścieżka windowsowa nie miałaby pokrycia w CI, które
chodzi wyłącznie na Linuksie. Dokładnie tam urwał się komunikat radzący
użytkownikowi Windowsa `sudo setcap`.
"""

import errno
import socket
import sys

import pytest

from pynmap.constants import WINDOWS_MAX_SOCKETS, PortState, Reason


@pytest.fixture
def as_platform(monkeypatch):
    """
    Udaje system na czas WYWOLANIA.

    Funkcje zalezne od platformy czytaja sys.platform w momencie wywolania,
    nie importu, wiec przeladowywanie modulu nic by nie dalo — wystarczy
    podmienic sys.platform wokol samego wywolania.
    """

    def _set(platform):
        monkeypatch.setattr(sys, "platform", platform)

    return _set


# ---------------------------------------------------------------------------
# Komunikat o surowych socketach musi pasować do systemu
# ---------------------------------------------------------------------------


def test_linux_hint_mentions_setcap(as_platform):
    from pynmap.scan_syn import _raw_socket_hint

    as_platform("linux")
    hint = _raw_socket_hint()
    assert "setcap" in hint
    assert "-sT" in hint


def test_windows_hint_does_not_tell_user_to_run_setcap(as_platform):
    """
    To jest regresja na realne zgloszenie: na Windowsie `-sS` radzilo
    `sudo setcap cap_net_raw+ep $(readlink -f $(which python3))`, czyli
    polecenie, ktorego na tym systemie nie da sie wykonac — i sugerujace,
    ze po jego wykonaniu -sS zadziala. Nie zadziala.
    """
    from pynmap.scan_syn import _raw_socket_hint

    as_platform("win32")
    hint = _raw_socket_hint()
    assert "setcap" not in hint
    assert "sudo" not in hint
    assert "Npcap" in hint
    assert "-sT" in hint


def test_macos_hint_mentions_sudo_not_setcap(as_platform):
    from pynmap.scan_syn import _raw_socket_hint

    as_platform("darwin")
    hint = _raw_socket_hint()
    assert "setcap" not in hint
    assert "sudo" in hint


def test_windows_syn_scan_refuses_before_opening_sockets(as_platform):
    """
    Na Windowsie nie probujemy nawet otwierac socketow: nawet gdy sie otworza
    (z prawami Administratora), sendto() z segmentem TCP zwroci WSAEACCES,
    bo Windows blokuje to celowo od XP SP2.
    """
    from pynmap.engine import ScanOptions
    from pynmap.scan_syn import RawSocketError, SynScanner
    from pynmap.timing import TIMING_TEMPLATES

    scanner = SynScanner(
        ScanOptions(ports=[80], timing=TIMING_TEMPLATES[3], resolve_dns=False)
    )
    as_platform("win32")
    with pytest.raises(RawSocketError) as exc:
        scanner._open_sockets()
    assert "Npcap" in str(exc.value)
    assert "-sT" in str(exc.value)


# ---------------------------------------------------------------------------
# Kody Winsock w tabeli errno connect scanu
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,state,reason",
    [
        (10061, PortState.CLOSED, Reason.CONREFUSED),      # WSAECONNREFUSED
        (10054, PortState.CLOSED, Reason.RESETPEER),       # WSAECONNRESET
        (10053, PortState.CLOSED, Reason.RESETPEER),       # WSAECONNABORTED
        (10056, PortState.OPEN, Reason.CONACCEPT),         # WSAEISCONN
        (10013, PortState.FILTERED, Reason.ADMINPROHIBITED),  # WSAEACCES
        (10065, PortState.FILTERED, Reason.HOSTUNREACH),   # WSAEHOSTUNREACH
        (10051, PortState.FILTERED, Reason.NETUNREACH),    # WSAENETUNREACH
        (10050, PortState.FILTERED, Reason.NETUNREACH),    # WSAENETDOWN
        (10060, PortState.FILTERED, Reason.NORESPONSE),    # WSAETIMEDOUT
        (10064, PortState.FILTERED, Reason.NORESPONSE),    # WSAEHOSTDOWN
    ],
)
def test_winsock_codes_are_classified(code, state, reason):
    """
    connect_ex() na Windowsie zwraca kody Winsock (10000+), a nie wartosci
    POSIX: odrzucone polaczenie to 10061, nie 111. Bez tych wpisow KAZDY
    zamkniety port wpadal w galez "nieznane errno" i byl raportowany jako
    filtered — wynik wygladajacy na poprawny, a bedacy nieprawda.
    """
    from pynmap.scan_connect import classify_connect_errno

    got_state, got_reason = classify_connect_errno(code)
    assert got_state is state
    assert got_reason is reason


def test_wsaewouldblock_is_in_progress_not_open():
    """
    WSAEWOULDBLOCK to na Windowsie normalne "connect() w toku". Gdyby trafil
    do mapy stanow jako open (tak jak linuksowy EAGAIN), KAZDY port byłby
    raportowany jako otwarty.
    """
    from pynmap.scan_connect import _IN_PROGRESS, classify_connect_errno

    assert 10035 in _IN_PROGRESS
    assert classify_connect_errno(10035)[0] is PortState.UNKNOWN


def test_posix_codes_still_classified():
    """Kontrola: dolozenie kodow Winsock nie moze ruszyc sciezki POSIX."""
    from pynmap.scan_connect import classify_connect_errno

    assert classify_connect_errno(errno.ECONNREFUSED) == (
        PortState.CLOSED,
        Reason.CONREFUSED,
    )
    assert classify_connect_errno(0) == (PortState.OPEN, Reason.CONACCEPT)


def test_winsock_and_posix_ranges_do_not_collide():
    """Kody Winsock sa 10000+, wiec nie moga przyslonic zadnej wartosci POSIX."""
    from pynmap.scan_connect import _ERRNO_MAP

    posix = {c for c in _ERRNO_MAP if c < 10000}
    winsock = {c for c in _ERRNO_MAP if c >= 10000}
    assert posix and winsock
    assert not (posix & winsock)


# ---------------------------------------------------------------------------
# Limit gniazd: na Windowsie decyduje FD_SETSIZE w select(), nie RLIMIT
# ---------------------------------------------------------------------------


def test_windows_socket_limit_respects_fd_setsize(as_platform):
    """
    selectors.DefaultSelector to na Windowsie SelectSelector, a select()
    przyjmuje najwyzej FD_SETSIZE (512) gniazd na zbior. Przy domyslnym 1024
    select() rzucal ValueError("too many file descriptors in select()").
    """
    from pynmap.engine import max_sockets_allowed

    as_platform("win32")
    assert max_sockets_allowed() == WINDOWS_MAX_SOCKETS
    assert WINDOWS_MAX_SOCKETS < 512


def test_non_windows_limit_comes_from_rlimit(as_platform):
    from pynmap.engine import max_sockets_allowed

    as_platform("linux")
    assert max_sockets_allowed() > 0


def test_so_linger_layout_is_platform_specific():
    """Windows: struct linger to dwa u_short (4 bajty), POSIX: dwa int (8)."""
    import struct

    assert struct.calcsize("hh") == 4
    assert struct.calcsize("ii") == 8


# ---------------------------------------------------------------------------
# Pomiar z prawdziwego Windowsa (Python 3.12.10) — regresje
# ---------------------------------------------------------------------------
#
# ci/platform_probe.py uruchomiony na Windowsie zwrocil:
#     connect_ex() ->            10035        (WSAEWOULDBLOCK, w toku)
#     SO_ERROR po gotowosci ->   0            dla ZAMKNIETEGO portu
#     errno.ECONNREFUSED ->      10061        (WARTOSC Winsock, nie POSIX 111)
#     SO_LINGER z "ii" ->        przyjete
#     AF_INET6 ->                OK
#
# Z tego wynikaja dwa realne bledy, oba grozniejsze niz to, co zakladalem.


def test_so_error_zero_without_connection_is_not_open():
    """
    `SO_ERROR == 0` NIE dowodzi, ze polaczenie istnieje — a `_ERRNO_MAP[0]`
    to `open`. Na Windowsie zmierzono gniazdo gotowe do zapisu z SO_ERROR 0
    dla ZAMKNIETEGO portu, wiec zaufanie samemu SO_ERROR dawalo falszywe
    `open`. Dla skanera portow to najgorszy mozliwy blad: raportuje usluge,
    ktorej nie ma.
    """
    from pynmap.scan_connect import connection_established

    sock = socket.socket()
    try:
        # gniazdo bez connect(): getpeername() musi zawiesc
        assert connection_established(sock) is False
    finally:
        sock.close()


def test_connection_established_true_for_real_connection():
    """Kontrola: prawdziwe polaczenie musi byc rozpoznane."""
    from pynmap.scan_connect import connection_established

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    cli = socket.socket()
    try:
        cli.connect(("127.0.0.1", port))
        assert connection_established(cli) is True
    finally:
        cli.close()
        srv.close()


def test_closed_socket_is_not_established():
    from pynmap.scan_connect import connection_established

    sock = socket.socket()
    sock.close()
    assert connection_established(sock) is False


def test_in_progress_codes_are_never_port_states():
    """
    Niezmiennik: kod "connect() w toku" nie moze jednoczesnie oznaczac stanu
    portu. Na Windowsie errno.EWOULDBLOCK == WSAEWOULDBLOCK == 10035, czyli
    DOKLADNIE kod "w toku", a wpis EAGAIN/EWOULDBLOCK -> open jest quirkiem
    petli lokalnej LINUKSA. Bez rozdzielenia tych dwoch rzeczy kazde
    polaczenie w trakcie zestawiania bylo na Windowsie raportowane jako
    port otwarty.
    """
    from pynmap.scan_connect import _ERRNO_MAP, _IN_PROGRESS

    winsock_in_progress = {10035, 10036, 10037}
    assert winsock_in_progress <= _IN_PROGRESS
    assert not (winsock_in_progress & set(_ERRNO_MAP)), (
        "kod Winsock 'w toku' trafil do mapy stanow portu"
    )


def test_linux_eagain_quirk_is_kept_on_linux():
    """
    Na Linuksie EAGAIN -> open to udokumentowany quirk petli lokalnej
    (docs/port-states.md, sekcja 1) i musi zostac — poprawka dla Windowsa
    nie moze go zabrac.
    """
    if sys.platform == "win32":  # pragma: no cover - CI chodzi na Linuksie
        pytest.skip("quirk dotyczy tylko Linuksa")

    from pynmap.scan_connect import classify_connect_errno

    assert classify_connect_errno(errno.EAGAIN) == (
        PortState.OPEN,
        Reason.CONACCEPT,
    )


def test_errno_aliasing_does_not_break_posix_mapping():
    """
    Python na Windowsie aliasuje socketowe nazwy POSIX na wartosci Winsock
    (errno.ECONNREFUSED == 10061). Mapa musi dawac ten sam STAN niezaleznie
    od tego, ktora wartosc ma dana nazwa na danej platformie.
    """
    from pynmap.scan_connect import classify_connect_errno

    for code in (errno.ECONNREFUSED, 10061):
        assert classify_connect_errno(code) == (
            PortState.CLOSED,
            Reason.CONREFUSED,
        ), code


def test_write_ready_socket_without_connection_is_not_reported_open():
    """
    Test MIEJSCA WYWOLANIA, nie samego helpera.

    To czwarty raz w tej sesji, kiedy poprawka siedziala w funkcji pomocniczej,
    a jej uzycie w silniku nie mialo pokrycia — i mutant "SO_ERROR brane na
    slowo" przechodzil cala suite. Tu udajemy dokladnie to, co zmierzono na
    Windowsie: gniazdo zglaszane jako gotowe do zapisu, SO_ERROR == 0,
    a polaczenia NIE MA.
    """
    import time as _time

    from pynmap.engine import HostScanStats, Probe, ScanOptions
    from pynmap.scan_connect import ConnectScanner
    from pynmap.targets import Target
    from pynmap.timing import TIMING_TEMPLATES

    class FakeSock:
        """Gniazdo jak z Windowsa: SO_ERROR 0, ale getpeername() zawodzi."""

        def __init__(self):
            self.closed = False

        def fileno(self):
            return 9999

        def getsockopt(self, *_a):
            return 0

        def getpeername(self):
            raise OSError(errno.ENOTCONN, "Transport endpoint is not connected")

        def close(self):
            self.closed = True

    class FakeKey:
        def __init__(self, sock):
            self.fileobj = sock

    class FakeSelector:
        def __init__(self, sock):
            self._sock = sock

        def select(self, _timeout):
            return [(FakeKey(self._sock), 0)]

        def unregister(self, _sock):
            pass

        def close(self):
            pass

    opts = ScanOptions(
        ports=[80],
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
        max_retries=0,
    )
    perf = opts.build_perf()
    scanner = ConnectScanner(opts, perf)
    now = _time.monotonic()
    host = HostScanStats(Target(ip="192.0.2.1"), opts, perf, now=now)

    fake = FakeSock()
    probe = Probe(port=80, tryno=0, sent_at=now, timeout_at=now + 99.0, sock=fake)
    host.register_sent(probe, now, group=scanner.group_timing)
    scanner._pending[9999] = (host, probe)
    scanner._selector = FakeSelector(fake)

    scanner._wait_for_responses([host])

    entry = host.portlist.get(80)
    assert entry.state is not PortState.OPEN, (
        "SO_ERROR == 0 bez polaczenia zaraportowane jako OPEN — falszywa usluga"
    )
    assert fake.closed is True


def test_windows_import_drops_linux_eagain_quirk():
    """
    Blok zalezny od platformy wykonuje sie przy IMPORCIE, wiec da sie go
    przetestowac przeladowaniem modulu z podmieniona platforma — w odroznieniu
    od funkcji, ktore czytaja sys.platform przy wywolaniu.

    Bez tego sprawdzenia mutant "nie zdejmuj quirku na Windowsie" przechodzil
    cala suite, bo na Linuksie ten blok w ogole sie nie wykonuje.
    """
    import importlib
    import unittest.mock as mock

    import pynmap.scan_connect as sc

    try:
        with mock.patch.object(sys, "platform", "win32"):
            win = importlib.reload(sc)
            assert errno.EAGAIN not in win._ERRNO_MAP, (
                "linuksowy quirk EAGAIN -> open zostal na Windowsie"
            )
            assert errno.EWOULDBLOCK not in win._ERRNO_MAP
            # a kody, ktore MAJA zostac, zostaja
            assert win._ERRNO_MAP[errno.ECONNREFUSED] == (
                PortState.CLOSED,
                Reason.CONREFUSED,
            )
    finally:
        importlib.reload(sc)

    # po przywroceniu quirk jest z powrotem (na Linuksie)
    if sys.platform != "win32":  # pragma: no branch
        assert errno.EAGAIN in sc._ERRNO_MAP
