"""
pynmap-basic — nmapowy "basic scan" przepisany z C/C++ na Pythona.

Zakres: TCP connect scan (-sT) i TCP SYN scan (-sS) wraz z parsowaniem
celów/portów, estymatorem RTT i okienkiem zatłoczenia skopiowanymi
z algorytmów nmapa.

Mapa modułów na pliki źródłowe nmapa:

    pynmap/constants.py    <- portlist.h, portreasons.h, nmap.h
    pynmap/timing.py       <- timing.h, timing.cc
    pynmap/targets.py      <- Target.cc, TargetGroup.cc, targets.cc
    pynmap/ports.py        <- portlist.cc + getpts() z nmap.cc
    pynmap/services.py     <- nmap-services + gettoppts()
    pynmap/tcpip.py        <- tcpip.cc, libnetutil/
    pynmap/engine.py       <- scan_engine.h, scan_engine.cc
    pynmap/scan_connect.py <- scan_engine_connect.cc
    pynmap/scan_syn.py     <- scan_engine_raw.cc (podzbiór TCP)
    pynmap/output.py       <- output.cc, NmapOutputTable.cc
    pynmap/cli.py          <- parsowanie opcji z nmap.cc
"""

from .constants import PortState, Reason, ScanType, TcpFlags
from .engine import HostReport, ScanOptions, ScanReport
from .output import VERSION
from .ports import PortList, parse_port_spec
from .scan_connect import connect_scan
from .scan_syn import RawSocketError, syn_scan
from .services import ServiceDB
from .targets import Target, expand_specs

__version__ = VERSION

__all__ = [
    "HostReport",
    "PortList",
    "PortState",
    "RawSocketError",
    "Reason",
    "ScanOptions",
    "ScanReport",
    "ScanType",
    "ServiceDB",
    "Target",
    "TcpFlags",
    "__version__",
    "connect_scan",
    "expand_specs",
    "parse_port_spec",
    "syn_scan",
]
