#!/usr/bin/env python3
"""
Diagnostyka zależna od systemu — do uruchomienia na maszynie, której nie mam.

pynmap-basic jest rozwijany i testowany na Linuksie, a CI chodzi wyłącznie
na ubuntu-latest. Kilka rzeczy różni się na Windowsie i macOS na tyle, że
decydują o POPRAWNOŚCI wyniku skanu, a nie tylko o wygodzie:

  * connect_ex() na Windowsie zwraca kody Winsock (10061), a nie POSIX (111),
    więc tabela errno -> stan portu musi znać oba zestawy,
  * select() przyjmuje tam najwyżej FD_SETSIZE gniazd na zbiór,
  * struct linger ma inny układ (dwa u_short zamiast dwóch int),
  * surowe sockety nie pozwalają wysyłać segmentów TCP (stąd brak -sS).

Uruchom:  python3 ci/platform_probe.py
i wklej wynik do zgłoszenia — nie wymaga uprawnień administratora
i nie wysyła ani jednego pakietu poza localhost.
"""

from __future__ import annotations

import errno
import os
import selectors
import socket
import struct
import sys

# uruchamiany jako `python3 ci/platform_probe.py`, wiec sys.path[0] to ci/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def line(label: str, value: object) -> None:
    print(f"  {label:<34} {value}")


def section(title: str) -> None:
    print()
    print(f"--- {title} ---")


def _probe_connect(host: str, port: int, label: str) -> None:
    """
    Pelny przebieg nieblokujacego connect(), z zapisem KAZDEGO kroku.

    Poprzednia wersja ignorowala to, czy select() w ogole sie odezwal,
    i czytala SO_ERROR bezwarunkowo — wiec "SO_ERROR 0" moglo znaczyc
    albo "polaczenie nawiazane", albo "nic sie jeszcze nie stalo".
    Te dwa przypadki trzeba rozdzielic: pierwszy to port otwarty,
    drugi nie znaczy nic.
    """
    section(f"connect() -> {label} ({host}:{port})")

    sock = socket.socket()
    sock.setblocking(False)
    code = sock.connect_ex((host, port))
    line("connect_ex()", code)

    if code != 0:
        sel = selectors.DefaultSelector()
        sel.register(sock, selectors.EVENT_WRITE)
        fired = []
        for _ in range(20):          # petla, bo jedno select() moze wrocic puste
            fired = sel.select(0.25)
            if fired:
                break
        sel.close()
        line("select() odezwal sie?", bool(fired))
        if not fired:
            line("WNIOSEK", "select() NIE zasygnalizowal gotowosci w 5 s")
            sock.close()
            return

    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    line("SO_ERROR (1. czytanie)", err)
    line("SO_ERROR (2. czytanie)", sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR))

    try:
        line("getpeername()", sock.getpeername())
        established = True
    except OSError as exc:
        line("getpeername()", f"OSError errno={exc.errno} "
                              f"winerror={getattr(exc, 'winerror', None)}: {exc.strerror}")
        established = False

    line("POLACZENIE ISTNIEJE?", established)
    if err == 0 and not established:
        print("  => TO JEST TEN PRZYPADEK: SO_ERROR mowi 0, a polaczenia NIE MA.")
        print("     Bez sprawdzenia getpeername() port bylby zaraportowany jako OPEN.")
    sock.close()


def closed_port_errno() -> None:
    """Co connect() zwraca dla portu zamknietego, a co dla otwartego."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed = probe.getsockname()[1]
    probe.close()
    _probe_connect("127.0.0.1", closed, "port ZAMKNIETY")

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        _probe_connect("127.0.0.1", srv.getsockname()[1], "port OTWARTY")
    finally:
        srv.close()

    section("wartosci stalych errno na tej platformie")
    for name in ("ECONNREFUSED", "ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH",
                 "EACCES", "EPERM", "EISCONN", "EAGAIN", "EWOULDBLOCK",
                 "EINPROGRESS", "EALREADY", "ENOTCONN"):
        line(f"errno.{name}", getattr(errno, name, "brak"))
    print("  (na Windowsie Python aliasuje te nazwy na WARTOSCI Winsock,")
    print("   np. ECONNREFUSED == 10061, a nie POSIX-owe 111)")


def scanner_sanity_check() -> None:
    """
    Najwazniejszy test: czy pynmap zgadza sie z rzeczywistoscia.

    Stawia wlasny listener i skanuje go razem z portem zamknietym. Jesli
    ktorykolwiek wiersz sie nie zgadza, wynik skanera na tej platformie jest
    nieprawdziwy — i to jest informacja, po ktora ten skrypt istnieje.
    """
    section("pynmap -sT kontra rzeczywistosc")

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]

    tmp = socket.socket()
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()

    try:
        from pynmap.engine import ScanOptions
        from pynmap.scan_connect import connect_scan
        from pynmap.targets import Target
        from pynmap.timing import TIMING_TEMPLATES

        opts = ScanOptions(
            ports=[open_port, closed_port],
            timing=TIMING_TEMPLATES[4],
            randomize_ports=False,
            resolve_dns=False,
            max_retries=1,
        )
        report = connect_scan([Target(ip="127.0.0.1")], opts)[0]
    except Exception as exc:  # noqa: BLE001 - diagnostyka nie moze sie wywalic
        line("BLAD", f"{type(exc).__name__}: {exc}")
        srv.close()
        return
    finally:
        srv.close()

    ok = True
    for port, expected in ((open_port, "open"), (closed_port, "closed")):
        entry = report.portlist.get(port)
        got = str(entry.state)
        if got != expected:
            ok = False
        line(f"{'OK ' if got == expected else 'ZLE'} port {port}",
             f"oczekiwano {expected}, dostano {got} "
             f"({entry.reason}, rtt={entry.rtt_us})")
    print("  => skaner zgadza sie z rzeczywistoscia" if ok
          else "  => SKANER KLAMIE na tej platformie")


def raw_socket_support() -> None:
    section("surowe sockety (-sS)")
    for proto, name in ((socket.IPPROTO_RAW, "IPPROTO_RAW"),
                        (socket.IPPROTO_TCP, "IPPROTO_TCP")):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
        except OSError as exc:
            line(f"SOCK_RAW/{name}", f"OSError errno={exc.errno} winerror="
                                     f"{getattr(exc, 'winerror', None)}: {exc.strerror}")
        else:
            s.close()
            line(f"SOCK_RAW/{name}", "otwarty OK")


def selector_and_limits() -> None:
    section("selektor i limity")
    line("selectors.DefaultSelector", type(selectors.DefaultSelector()).__name__)
    try:
        import resource

        line("RLIMIT_NOFILE", resource.getrlimit(resource.RLIMIT_NOFILE))
    except ImportError:
        line("RLIMIT_NOFILE", "modul resource niedostepny (Windows)")
    try:
        from pynmap.engine import max_sockets_allowed

        line("max_sockets_allowed()", max_sockets_allowed())
    except Exception as exc:  # noqa: BLE001
        line("max_sockets_allowed()", f"{type(exc).__name__}: {exc}")


def struct_layouts() -> None:
    section("układy struktur")
    line('struct.calcsize("ii")', struct.calcsize("ii"))
    line('struct.calcsize("hh")', struct.calcsize("hh"))
    s = socket.socket()
    for layout in ("ii", "hh"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(layout, 1, 0))
            line(f"SO_LINGER z {layout!r}", "przyjete")
        except OSError as exc:
            line(f"SO_LINGER z {layout!r}", f"OSError errno={exc.errno}: {exc.strerror}")
    s.close()


def ipv6_support() -> None:
    section("IPv6")
    line("socket.has_ipv6", socket.has_ipv6)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError as exc:
        line("AF_INET6", f"OSError errno={exc.errno}: {exc.strerror}")
    else:
        s.close()
        line("AF_INET6", "OK")


def main() -> int:
    print("pynmap-basic — diagnostyka platformy")
    section("system")
    line("sys.platform", sys.platform)
    line("sys.version", sys.version.split()[0])
    line("os.name", os.name)
    try:
        line("os.uname().sysname", os.uname().sysname)
    except AttributeError:
        line("os.uname()", "niedostepne (Windows)")

    closed_port_errno()
    scanner_sanity_check()
    raw_socket_support()
    selector_and_limits()
    struct_layouts()
    ipv6_support()
    print()
    print("Gotowe. Wklej całość do zgłoszenia.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
