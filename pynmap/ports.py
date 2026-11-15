"""
Parsowanie listy portów i przechowywanie wyników — odpowiednik
getpts() z nmap.cc oraz klasy PortList z portlist.cc.

Obsługiwane formaty -p (jak w nmapie):
  -p 80
  -p 1-1024
  -p 22,80,443
  -p -            -> 1-65535
  -p -1024        -> 1-1024
  -p 8000-        -> 8000-65535
  -p T:80,443     -> prefiks T: (my obsługujemy tylko TCP)
  -p http,https   -> nazwy usług z bazy services
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .constants import PortState, Reason


class PortSpecError(ValueError):
    """Niepoprawna specyfikacja portów."""


MIN_PORT = 1
MAX_PORT = 65535


def parse_port_spec(spec: str, service_lookup=None) -> list[int]:
    """
    Zamienia tekst z -p na posortowaną listę unikalnych portów TCP.

    service_lookup to opcjonalna funkcja nazwa -> port (patrz services.py),
    dzięki czemu '-p http,ssh' działa jak w nmapie.
    """
    if spec is None:
        raise PortSpecError("Brak specyfikacji portów")

    spec = spec.strip()
    if spec == "":
        # nmap też odrzuca puste -p; wcześniej zwracaliśmy tu cały zakres,
        # co cicho zamieniało literówkę w skan 65535 portów.
        raise PortSpecError("Pusta specyfikacja portów (-p). Użyj '-' dla 1-65535.")
    if spec == "-":
        return list(range(MIN_PORT, MAX_PORT + 1))

    ports: set[int] = set()

    # Prefiks protokołu jest w nmapie "lepki": w -p U:53,161 OBA porty są UDP,
    # a nie tylko pierwszy. Trzymanie go per-element oznaczało, że 'U:53,80'
    # cicho skanowało TCP/80 — czyli użytkownik prosił o UDP, a dostawał
    # skan TCP jednego z podanych portów.
    current_proto = "T"

    for raw in spec.split(","):
        chunk = raw.strip()
        if not chunk:
            raise PortSpecError(f"Pusty element w '{spec}'")

        # Prefiksy protokołów: T: (tcp), U: (udp), S: (sctp), P: (ip proto)
        if len(chunk) > 1 and chunk[1] == ":":
            proto = chunk[0].upper()
            if proto not in ("T", "U", "S", "P"):
                raise PortSpecError(f"Nieznany prefiks protokołu: {proto}:")
            current_proto = proto
            chunk = chunk[2:]
            if not chunk:
                continue

        if current_proto != "T":
            # pynmap-basic skanuje tylko TCP — pomijamy, jak nmap bez -sU
            continue

        if chunk.startswith("-") and chunk != "-":
            # '-1024' => 1-1024
            hi = _parse_single(chunk[1:], service_lookup)
            ports.update(range(MIN_PORT, hi + 1))
        elif chunk.endswith("-") and chunk != "-":
            # '8000-' => 8000-65535
            lo = _parse_single(chunk[:-1], service_lookup)
            ports.update(range(lo, MAX_PORT + 1))
        elif chunk == "-":
            ports.update(range(MIN_PORT, MAX_PORT + 1))
        elif "-" in chunk and _lookup(chunk, service_lookup) is not None:
            # 'http-proxy', 'https-alt', 'ms-wbt-server' — myślnik w nazwie
            # usługi trafiał w gałąź zakresu i rozbijał nazwę na pół,
            # więc nazwy, które SĄ w bazie, były nieosiągalne przez -p.
            ports.add(_lookup(chunk, service_lookup))
        elif "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            lo = _parse_single(lo_s, service_lookup)
            hi = _parse_single(hi_s, service_lookup)
            if lo > hi:
                raise PortSpecError(f"Zakres odwrócony: {chunk}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(_parse_single(chunk, service_lookup))

    if not ports:
        raise PortSpecError(f"Specyfikacja '{spec}' nie dała żadnego portu TCP")

    return sorted(ports)


def _lookup(name: str, service_lookup=None) -> int | None:
    """Nazwa usługi -> port, albo None. Nie rzuca."""
    if service_lookup is None:
        return None
    try:
        return service_lookup(name.strip())
    except Exception:  # noqa: BLE001 - baza usług nie może wywrócić parsera
        return None


def _parse_single(text: str, service_lookup=None) -> int:
    text = text.strip()
    if not text:
        raise PortSpecError("Pusty numer portu")

    if text.isdigit():
        value = int(text)
        if not MIN_PORT <= value <= MAX_PORT:
            raise PortSpecError(f"Port poza zakresem {MIN_PORT}-{MAX_PORT}: {value}")
        return value

    if service_lookup is not None:
        port = service_lookup(text)
        if port is not None:
            # Baza usług może pochodzić z pliku podanego przez użytkownika
            # (--services), więc jej zawartość jest wejściem jak każde inne.
            if not MIN_PORT <= port <= MAX_PORT:
                raise PortSpecError(
                    f"usługa '{text}' wskazuje port poza zakresem "
                    f"{MIN_PORT}-{MAX_PORT}: {port}"
                )
            return port

    raise PortSpecError(f"'{text}' nie jest numerem portu ani znaną usługą")


def order_ports(ports: list[int], randomize: bool = True, rng=None) -> list[int]:
    """
    nmap domyślnie losuje kolejność portów; -r ją wyłącza.
    Losowanie utrudnia wykrycie skanu przez proste IDS-y oparte o sekwencję.
    """
    out = list(ports)
    if randomize:
        (rng or random).shuffle(out)
    return out


# ---------------------------------------------------------------------------
# PortList — odpowiednik portlist.cc
# ---------------------------------------------------------------------------


@dataclass
class PortResult:
    """Jeden wynik: stan + powód + ile prób zużyliśmy."""

    port: int
    state: PortState = PortState.UNKNOWN
    reason: Reason = Reason.UNKNOWN
    reason_ttl: int | None = None
    service: str | None = None
    tryno: int = 0
    rtt_us: int | None = None


@dataclass
class PortList:
    """
    Wyniki dla jednego hosta.

    nmap trzyma to w tablicach indeksowanych numerem portu (szybko, ale
    65536 wpisów na host); my używamy dicta, bo skanujemy zwykle podzbiór.
    """

    results: dict[int, PortResult] = field(default_factory=dict)
    default_state: PortState = PortState.UNKNOWN
    default_reason: Reason = Reason.NORESPONSE

    def set_state(
        self,
        port: int,
        state: PortState,
        reason: Reason = Reason.UNKNOWN,
        reason_ttl: int | None = None,
        rtt_us: int | None = None,
        tryno: int = 0,
    ) -> None:
        entry = self.results.get(port)
        if entry is None:
            entry = PortResult(port=port)
            self.results[port] = entry
        entry.state = state
        entry.reason = reason
        entry.reason_ttl = reason_ttl
        entry.tryno = tryno
        if rtt_us is not None:
            entry.rtt_us = rtt_us

    def get(self, port: int) -> PortResult:
        return self.results.get(port) or PortResult(
            port=port, state=self.default_state, reason=self.default_reason
        )

    def finalize(self, scanned_ports: list[int]) -> None:
        """
        Porty bez odpowiedzi dostają stan domyślny.

        To odpowiednik set_default_port_state() z scan_engine.cc: dla SYN
        i connect scanu nmap przyjmuje 'filtered', gdy nie przyszło nic.
        """
        for port in scanned_ports:
            if port not in self.results:
                self.results[port] = PortResult(
                    port=port, state=self.default_state, reason=self.default_reason
                )

    def count_by_state(self) -> dict[PortState, int]:
        counts: dict[PortState, int] = {}
        for entry in self.results.values():
            counts[entry.state] = counts.get(entry.state, 0) + 1
        return counts

    def sorted_results(self) -> list[PortResult]:
        return [self.results[p] for p in sorted(self.results)]
