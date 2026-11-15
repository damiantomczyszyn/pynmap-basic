"""
Warstwa pośrednia między przeglądarką a pynmap.

Ładowana do Pyodide (CPython skompilowany do WebAssembly) i wołana z JS.
Każda funkcja zwraca strukturę serializowalną do JSON — żadnych obiektów
Pythona nie przekazujemy przez granicę.

Co tu NIE działa i dlaczego: przeglądarka nie daje dostępu do socketów,
więc moduły scan_connect i scan_syn nie są importowane. Uruchamiamy
wyłącznie warstwę algorytmiczną: parsowanie, estymator RTT, okno
zatłoczenia i budowanie pakietów. To jest uczciwa granica tego demo —
realny skan robi GitHub Actions i jego wynik wczytujemy jako dane.
"""

from __future__ import annotations

import ipaddress
import sys

from pynmap.ports import PortSpecError, parse_port_spec
from pynmap.services import ServiceDB
from pynmap.targets import (
    TargetSpecError,
    _looks_like_octet_spec,
    expand_spec,
)
from pynmap.tcpip import (
    build_syn_probe,
    checksum,
    parse_ip_header,
    parse_tcp_header,
)
from pynmap.timing import (
    TIMING_TEMPLATES,
    ScanPerformanceVars,
    TimeoutInfo,
    UltraTimingVals,
)

_SERVICES = ServiceDB(prefer_system=False)

MAX_LISTED = 400

# Pod Emscriptenem getaddrinfo() nie sięga do sieci, ale też nie zgłasza
# błędu — zwraca sfabrykowane adresy z 172.29.x.x. Czyli "example.com"
# rozwiązuje się na wiarygodnie wyglądającą bzdurę, co jest groźniejsze
# niż czysta porażka. Dlatego nazwy hostów odrzucamy tu wprost.
_IS_WASM = sys.platform == "emscripten"


def _needs_dns(spec: str) -> bool:
    """Czy rozwinięcie tej specyfikacji wymagałoby zapytania DNS."""
    spec = spec.strip()
    if not spec or "/" in spec or _looks_like_octet_spec(spec):
        return False
    try:
        ipaddress.ip_address(spec)
    except ValueError:
        return True
    return False


# ---------------------------------------------------------------------------
# Budowanie pakietu SYN
# ---------------------------------------------------------------------------


def build_packet(
    src: str = "192.168.1.50",
    dst: str = "192.168.1.1",
    sport: int = 44321,
    dport: int = 443,
    seq: int = 0xDEADBEEF,
    window: int = 1024,
    mss: int | None = 1460,
    ttl: int = 64,
) -> dict:
    """
    Buduje prawdziwą sondę SYN i rozkłada ją na części.

    To ten sam kod, który w CI wysyła pakiety przez mostek docker0 —
    tylko tutaj zamiast sendto() pokazujemy bajty.
    """
    try:
        packet = build_syn_probe(
            src_ip=src,
            dst_ip=dst,
            sport=int(sport),
            dport=int(dport),
            seq=int(seq),
            window=int(window),
            mss=int(mss) if mss else None,
            ttl=int(ttl),
            ip_id=0x1337,
        )
    except OSError as exc:
        return {"ok": False, "error": f"Niepoprawny adres IP: {exc}"}
    except (ValueError, TypeError) as exc:
        return {"ok": False, "error": str(exc)}

    ip = parse_ip_header(packet)
    tcp = parse_tcp_header(packet[ip.header_len:])
    options = packet[ip.header_len + 20:ip.header_len + tcp.header_len]

    # Weryfikacja sumy IP tak, jak robi to odbiorca: suma nad nagłówkiem
    # zawierającym już swoją sumę musi dać 0.
    ip_csum_ok = checksum(packet[: ip.header_len]) == 0

    fields = [
        {"group": "IP", "name": "version / IHL", "value": f"{ip.version} / {ip.ihl}",
         "offset": 0, "length": 1,
         "note": "IHL w 32-bitowych słowach, więc 5 = 20 bajtów"},
        {"group": "IP", "name": "total length", "value": str(ip.total_length),
         "offset": 2, "length": 2, "note": "nagłówek IP + segment TCP"},
        {"group": "IP", "name": "identification", "value": f"0x{ip.ip_id:04x}",
         "offset": 4, "length": 2, "note": "tu ustawione na stałe dla powtarzalności"},
        {"group": "IP", "name": "TTL", "value": str(ip.ttl),
         "offset": 8, "length": 1,
         "note": "w odpowiedzi czytamy TTL i pokazujemy przy --reason"},
        {"group": "IP", "name": "protocol", "value": f"{ip.proto} (TCP)",
         "offset": 9, "length": 1, "note": ""},
        {"group": "IP", "name": "header checksum", "value": f"0x{ip.checksum:04x}",
         "offset": 10, "length": 2,
         "note": "poprawna" if ip_csum_ok else "NIEPOPRAWNA"},
        {"group": "IP", "name": "source", "value": ip.src,
         "offset": 12, "length": 4, "note": ""},
        {"group": "IP", "name": "destination", "value": ip.dst,
         "offset": 16, "length": 4, "note": ""},
        {"group": "TCP", "name": "source port", "value": str(tcp.sport),
         "offset": 20, "length": 2,
         "note": "po nim rozpoznajemy, że odpowiedź jest nasza"},
        {"group": "TCP", "name": "destination port", "value": str(tcp.dport),
         "offset": 22, "length": 2,
         "note": f"usługa: {_SERVICES.service_name(int(dport))}"},
        {"group": "TCP", "name": "sequence number", "value": f"0x{tcp.seq:08x}",
         "offset": 24, "length": 4,
         "note": "ACK w odpowiedzi musi równać się temu +1"},
        {"group": "TCP", "name": "data offset", "value": f"{tcp.data_offset} ({tcp.header_len} B)",
         "offset": 32, "length": 1,
         "note": "6 zamiast 5, bo doszła opcja MSS" if options else "brak opcji"},
        {"group": "TCP", "name": "flags", "value": f"0x{int(tcp.flags):02x} ({tcp.flags.to_str()})",
         "offset": 33, "length": 1, "note": "sam SYN — stąd nazwa SYN scan"},
        {"group": "TCP", "name": "window", "value": str(tcp.window),
         "offset": 34, "length": 2, "note": "nmap wysyła 1024 w sondach SYN"},
        {"group": "TCP", "name": "checksum", "value": f"0x{tcp.checksum:04x}",
         "offset": 36, "length": 2,
         "note": "liczona po pseudo-nagłówku, który nie jest wysyłany"},
    ]

    if options:
        fields.append(
            {"group": "TCP", "name": "options (MSS)", "value": options.hex(" "),
             "offset": 40, "length": len(options),
             "note": "kind=2, len=4, wartość MSS"}
        )

    return {
        "ok": True,
        "hex": packet.hex(),
        "length": len(packet),
        "ip_header_len": ip.header_len,
        "tcp_header_len": tcp.header_len,
        "ip_checksum_ok": ip_csum_ok,
        "fields": fields,
    }


# ---------------------------------------------------------------------------
# Estymator RTT (Jacobson/Karels)
# ---------------------------------------------------------------------------


def rtt_trace(samples_ms: list[float], template: int = 3) -> dict:
    """
    Przepuszcza ciąg próbek RTT przez estymator i zwraca każdy krok.

    Pokazuje to, co trudno wyczytać z kodu: jak szybko srtt goni próbki
    i jak timeout reaguje na skok opóźnienia.
    """
    tmpl = TIMING_TEMPLATES.get(int(template), TIMING_TEMPLATES[3])
    to = TimeoutInfo.from_template(tmpl)

    steps = []
    for idx, sample in enumerate(samples_ms):
        try:
            sample_us = int(float(sample) * 1000)
        except (TypeError, ValueError):
            continue

        # "Odrzucona" znaczy: adjust() nie zmienil ANI estymaty, ANI timeoutu.
        # Warunek `to.srtt == -1` byl spelniony tylko dopoki estymator nie
        # przyjal jeszcze zadnej probki, wiec kazde pozniejsze odrzucenie
        # (delta < -50 ms, delta >= 8 s, sanity check #2) bylo pokazywane
        # jako probka WLICZONA do estymaty.
        before_timeout = to.timeout
        before_srtt = to.srtt
        before_rttvar = to.rttvar
        to.adjust(sample_us)
        ignored = (
            to.timeout == before_timeout
            and to.srtt == before_srtt
            and to.rttvar == before_rttvar
        )

        steps.append(
            {
                "n": idx + 1,
                "sample_ms": round(sample_us / 1000, 3),
                "srtt_ms": round(to.srtt / 1000, 3) if to.srtt >= 0 else None,
                "rttvar_ms": round(to.rttvar / 1000, 3) if to.rttvar >= 0 else None,
                "timeout_ms": round(to.timeout / 1000, 3),
                "ignored": ignored,
            }
        )

    return {
        "ok": True,
        "template": {
            "level": tmpl.level,
            "name": tmpl.name,
            "initial_ms": tmpl.initial_rtt_timeout_ms,
            "min_ms": tmpl.min_rtt_timeout_ms,
            "max_ms": tmpl.max_rtt_timeout_ms,
            "max_retries": tmpl.max_retries,
        },
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# Okno zatłoczenia (AIMD)
# ---------------------------------------------------------------------------


def cwnd_trace(events: str, template: int = 3) -> dict:
    """
    Symuluje okno zatłoczenia dla ciągu zdarzeń.

    events to napis z liter: 'a' = przyszła odpowiedź (ack),
    'd' = timeout per-host (drop), 'g' = timeout grupowy (drop_group).
    """
    tmpl = TIMING_TEMPLATES.get(int(template), TIMING_TEMPLATES[3])
    perf = ScanPerformanceVars.from_template(tmpl)
    timing = UltraTimingVals.init_for(perf, group=False, now=0.0)

    steps = [
        {
            "n": 0,
            "event": "start",
            "cwnd": round(timing.cwnd, 3),
            "ssthresh": timing.ssthresh,
            "phase": "slow start" if timing.cwnd < timing.ssthresh else "congestion avoidance",
        }
    ]

    in_flight = int(timing.cwnd)
    for idx, ch in enumerate(str(events).lower()):
        if ch not in "adg":
            continue

        phase_before = "slow start" if timing.cwnd < timing.ssthresh else "congestion avoidance"

        if ch == "a":
            timing.num_replies_expected += 1
            timing.ack(perf)
            label = "ack"
        elif ch == "d":
            in_flight = max(1, int(timing.cwnd))
            timing.drop(in_flight, perf, now=float(idx))
            label = "drop (host)"
        else:
            in_flight = max(1, int(timing.cwnd))
            timing.drop_group(in_flight, perf, now=float(idx))
            label = "drop (grupa)"

        steps.append(
            {
                "n": idx + 1,
                "event": label,
                "cwnd": round(timing.cwnd, 3),
                "ssthresh": timing.ssthresh,
                "phase": phase_before,
            }
        )

    return {
        "ok": True,
        "perf": {
            "low_cwnd": perf.low_cwnd,
            "max_cwnd": perf.max_cwnd,
            "initial_cwnd": perf.host_initial_cwnd,
            "initial_ssthresh": perf.initial_ssthresh,
            "slow_incr": perf.slow_incr,
            "ca_incr": perf.ca_incr,
            "ssthresh_divisor": round(perf.host_drop_ssthresh_divisor, 4),
            "template": f"-T{tmpl.level} ({tmpl.name})",
        },
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# Parsowanie -p i celów
# ---------------------------------------------------------------------------


def parse_ports(spec: str) -> dict:
    """Parsuje specyfikację -p. Komunikaty błędów są te same co w CLI."""
    try:
        ports = parse_port_spec(str(spec), service_lookup=_SERVICES.port_for_name)
    except PortSpecError as exc:
        return {"ok": False, "error": str(exc)}

    return {
        "ok": True,
        "count": len(ports),
        "truncated": len(ports) > MAX_LISTED,
        "ports": [
            {"port": p, "service": _SERVICES.service_name(p)}
            for p in ports[:MAX_LISTED]
        ],
    }


def parse_targets(spec: str) -> dict:
    """
    Rozwija specyfikację celów.

    DNS w przeglądarce nie działa (brak socketów), więc nazwy hostów
    zwrócą błąd — CIDR, zakresy w oktetach i literalne IP działają w pełni.
    """
    spec = str(spec)

    if _IS_WASM and _needs_dns(spec):
        return {
            "ok": False,
            "error": "Nazwy DNS nie da się tu rozwiązać: przeglądarka nie ma "
                     "socketów, a Emscripten zwraca w zamian zmyślone adresy "
                     "z 172.29.0.0/16. Podaj IP, CIDR albo zakres "
                     "(np. 10.0.1-2.1-20).",
        }

    try:
        targets = []
        for target in expand_spec(spec, resolve=False):
            targets.append(target.ip)
            if len(targets) > MAX_LISTED + 1:
                break
    except TargetSpecError as exc:
        return {"ok": False, "error": str(exc)}
    except OSError:
        return {
            "ok": False,
            "error": "Rozwiązywanie nazw DNS nie działa w przeglądarce — "
                     "podaj IP, CIDR albo zakres (np. 10.0.1-2.1-20).",
        }

    if not targets:
        return {"ok": False, "error": "Specyfikacja nie dała żadnego celu"}

    return {
        "ok": True,
        "count": len(targets),
        "truncated": len(targets) > MAX_LISTED,
        "targets": targets[:MAX_LISTED],
    }


def top_ports(count: int = 20) -> dict:
    """Lista najczęstszych portów z wbudowanej bazy."""
    n = max(1, min(int(count), _SERVICES.available_top_ports))
    return {
        "ok": True,
        "source": _SERVICES.source,
        "ports": [
            {"port": p, "service": _SERVICES.service_name(p)}
            for p in _SERVICES.top_ports(n)
        ],
    }


def environment() -> dict:
    """Co faktycznie da się tu uruchomić — pokazywane w stopce strony."""
    import sys

    probes = {}
    for name in ("socket", "selectors", "resource"):
        try:
            __import__(name)
            probes[name] = "import OK"
        except ImportError as exc:
            probes[name] = f"brak: {exc}"

    return {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "services_source": _SERVICES.source,
        "builtin_ports": _SERVICES.available_top_ports,
        "modules": probes,
    }
