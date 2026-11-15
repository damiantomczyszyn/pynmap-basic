"""
Stałe odpowiadające oryginalnym definicjom nmapa.

Mapowanie na kod C/C++ nmapa:
  PortState      <- portlist.h       (PORT_OPEN, PORT_CLOSED, ...)
  Reason         <- portreasons.h    (reason_t / ER_*)
  TCP_*          <- libnetutil/netutil.h (TH_SYN, TH_ACK, ...)
  MAX_* / MIN_*  <- nmap.h           (MIN_RTT_TIMEOUT, MAX_RETRANSMISSIONS, ...)
"""

from __future__ import annotations

from enum import Enum, IntFlag

# ---------------------------------------------------------------------------
# Stany portów — odpowiednik PORT_* z portlist.h
# ---------------------------------------------------------------------------


class PortState(str, Enum):
    """Stan portu. nmap używa int-owych stałych PORT_*, my enum-a."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNKNOWN = "unknown"

    def __str__(self) -> str:  # pragma: no cover - trywialne
        return self.value


# Stany, które nmap traktuje jako "interesujące" przy --open
INTERESTING_STATES = frozenset({PortState.OPEN, PortState.OPEN_FILTERED})


# ---------------------------------------------------------------------------
# Powody (--reason) — odpowiednik reason_t / ER_* z portreasons.h
# ---------------------------------------------------------------------------


class Reason(str, Enum):
    """Dlaczego przypisaliśmy taki stan. Odpowiada ER_* w nmapie."""

    # Uwaga: nmap mapuje ER_CONACCEPT i ER_SYNACK na ten sam napis "syn-ack"
    # (portreasons.cc), dlatego oba mają tu tę samą wartość.
    CONACCEPT = "syn-ack"               # ER_CONACCEPT  - connect() się udał
    CONREFUSED = "conn-refused"         # ER_CONREFUSED - ECONNREFUSED
    SYNACK = "syn-ack"                  # ER_SYNACK     - przyszedł SYN/ACK
    RESETPEER = "reset"                 # ER_RESETPEER
    ADMINPROHIBITED = "admin-prohibited"
    HOSTUNREACH = "host-unreach"
    NETUNREACH = "net-unreach"
    PROTOUNREACH = "proto-unreach"
    PORTUNREACH = "port-unreach"
    DESTUNREACH = "dest-unreach"
    TIMEEXCEEDED = "time-exceeded"
    NORESPONSE = "no-response"
    UNKNOWN = "unknown"

    def __str__(self) -> str:  # pragma: no cover - trywialne
        return self.value


# ---------------------------------------------------------------------------
# Flagi TCP — odpowiednik TH_* z libnetutil
# ---------------------------------------------------------------------------


class TcpFlags(IntFlag):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def to_str(self) -> str:
        """Reprezentacja w stylu tcpdump, np. 'SA' dla SYN|ACK."""
        names = (
            (TcpFlags.FIN, "F"),
            (TcpFlags.SYN, "S"),
            (TcpFlags.RST, "R"),
            (TcpFlags.PSH, "P"),
            (TcpFlags.ACK, "A"),
            (TcpFlags.URG, "U"),
            (TcpFlags.ECE, "E"),
            (TcpFlags.CWR, "C"),
        )
        return "".join(ch for flag, ch in names if self & flag) or "-"


# ---------------------------------------------------------------------------
# Typy skanowania — odpowiednik stype z scan_engine.h
# ---------------------------------------------------------------------------


class ScanType(str, Enum):
    CONNECT = "connect"   # -sT  (CONNECT_SCAN)
    SYN = "syn"           # -sS  (SYN_SCAN)

    def to_label(self) -> str:
        return {
            ScanType.CONNECT: "Connect Scan",
            ScanType.SYN: "SYN Stealth Scan",
        }[self]


# ---------------------------------------------------------------------------
# Limity z nmap.h
# ---------------------------------------------------------------------------

MIN_RTT_TIMEOUT_MS = 100        # nmap.h: MIN_RTT_TIMEOUT
MAX_RTT_TIMEOUT_MS = 10_000     # nmap.h: MAX_RTT_TIMEOUT
INITIAL_RTT_TIMEOUT_MS = 1_000  # nmap.h: INITIAL_RTT_TIMEOUT
MAX_RETRANSMISSIONS = 10        # nmap.h: MAX_RETRANSMISSIONS (11 prób łącznie)
MAX_TCP_SCAN_DELAY_MS = 1_000   # nmap.h: MAX_TCP_SCAN_DELAY

# Ile deskryptorów trzymamy równolegle w connect scanie.
# nmap wylicza to z getrlimit(RLIMIT_NOFILE); my robimy to samo w engine.py.
DEFAULT_MAX_SOCKETS = 1_024

# Windows: select() przyjmuje najwyżej FD_SETSIZE (512) gniazd na zbiór,
# a selectors.DefaultSelector sprowadza się tam do SelectSelector.
# Przy 1024 select() rzucał ValueError("too many file descriptors in
# select()") w środku skanu. Zostawiamy zapas na gniazda spoza skanu.
WINDOWS_MAX_SOCKETS = 500

# Rozmiar okna w wysyłanym SYN-ie. nmap używa 1024 dla SYN scan.
SYN_PROBE_WINDOW = 1024
SYN_PROBE_MSS = 1460

MIN_EPHEMERAL_PORT = 33_000
MAX_EPHEMERAL_PORT = 61_000
