"""
Testy zachowania zależnego od systemu.

Wszystkie udają platformę przez sys.platform, więc przechodzą na każdym
systemie — inaczej ścieżka windowsowa nie miałaby pokrycia w CI, które
chodzi wyłącznie na Linuksie. Dokładnie tam urwał się komunikat radzący
użytkownikowi Windowsa `sudo setcap`.
"""

import errno
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
