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


def closed_port_errno() -> None:
    """Co connect() zwraca dla portu, na którym nikt nie nasłuchuje."""
    section("connect() na zamknięty port localhost")

    # port zajęty i natychmiast zwolniony => prawie pewnie nikt nie nasłuchuje
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    sock = socket.socket()
    sock.setblocking(False)
    code = sock.connect_ex(("127.0.0.1", port))
    line("connect_ex() -> ", code)
    if code in (0, errno.EINPROGRESS, getattr(errno, "EWOULDBLOCK", -1), 10035, 10036):
        # nieblokujące connect bywa „w toku” — dociągamy wynik przez SO_ERROR
        sel = selectors.DefaultSelector()
        sel.register(sock, selectors.EVENT_WRITE)
        sel.select(2.0)
        code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        sel.close()
        line("SO_ERROR po gotowości -> ", code)
    sock.close()

    line("errno.ECONNREFUSED (POSIX)", errno.ECONNREFUSED)
    line("WSAECONNREFUSED (Winsock)", 10061)
    if code == 10061:
        print("  => kody Winsock: tabela errno MUSI je znać")
    elif code == errno.ECONNREFUSED:
        print("  => kody POSIX")
    else:
        print(f"  => NIEOCZEKIWANY kod {code} — to jest ta informacja, której szukam")


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
    raw_socket_support()
    selector_and_limits()
    struct_layouts()
    ipv6_support()
    print()
    print("Gotowe. Wklej całość do zgłoszenia.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
