"""
Interfejs wiersza poleceń — odpowiednik parsowania opcji z nmap.cc.

Flagi nazwane tak jak w nmapie, żeby dało się przełożyć polecenie 1:1:

    nmap -sS -p 1-1000 --open -T4 10.0.0.0/24
    pynmap -sS -p 1-1000 --open -T4 10.0.0.0/24
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
import time

from .constants import ScanType
from .engine import ScanOptions, ScanReport, is_root
from .output import VERSION, format_grepable, format_json, format_normal
from .ports import PortSpecError, parse_port_spec
from .scan_connect import connect_scan
from .scan_syn import RawSocketError, syn_scan
from .services import ServiceDB
from .targets import TargetSpecError, expand_specs, reverse_lookup
from .timing import TIMING_TEMPLATES

_TIME_RE = re.compile(r"^(\d+(?:\.\d+)?)(ms|s|m|h)?$", re.IGNORECASE)


def parse_time(value: str) -> float:
    """
    Parsuje czas w notacji nmapa: 500ms, 30s, 5m, 2h (goła liczba = sekundy).
    """
    match = _TIME_RE.match(value.strip())
    if not match:
        raise argparse.ArgumentTypeError(
            f"Niepoprawny czas: '{value}' (użyj np. 500ms, 30s, 5m, 2h)"
        )
    amount = float(match.group(1))
    unit = (match.group(2) or "s").lower()
    factors = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
    return amount * factors[unit]


def _positive_int(value: str) -> int:
    """
    Liczba >= 0 dla --min/--max-parallelism.

    Wartości ujemne przechodziły przez argparse i trafiały wprost do
    ScanPerformanceVars, gdzie low_cwnd i max_cwnd stawały się ujemne.
    Wtedy int(cwnd) < 0, send_ok() jest na zawsze False i skan kręcił się
    bez końca na 100% CPU, nie wypisując ani jednego portu.
    """
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"'{value}' nie jest liczbą całkowitą") from exc
    if number < 0:
        raise argparse.ArgumentTypeError(
            f"oczekiwano liczby >= 0, otrzymano {number} (0 = bez wymuszenia)"
        )
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pynmap",
        description=(
            "pynmap-basic — TCP connect scan i SYN scan przepisane z C/C++ "
            "nmapa na Pythona (projekt edukacyjny)."
        ),
        epilog=(
            "Skanuj tylko hosty, na które masz zgodę właściciela. "
            "Skanowanie obcej infrastruktury bez zgody może być nielegalne."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "targets", nargs="*", metavar="CEL",
        help="hosty: IP, nazwa DNS, CIDR (10.0.0.0/24), zakres (10.0.0.1-50)",
    )

    scan = parser.add_argument_group("typ skanowania")
    group = scan.add_mutually_exclusive_group()
    group.add_argument(
        "-sT", dest="scan_type", action="store_const", const=ScanType.CONNECT,
        help="TCP connect scan (domyślny bez roota)",
    )
    group.add_argument(
        "-sS", dest="scan_type", action="store_const", const=ScanType.SYN,
        help="TCP SYN scan / half-open (domyślny dla roota, wymaga CAP_NET_RAW)",
    )

    ports = parser.add_argument_group("wybór portów")
    ports.add_argument(
        "-p", "--ports", dest="port_spec", metavar="SPEC",
        help="np. 80 | 1-1024 | 22,80,443 | - (wszystkie) | http,ssh",
    )
    ports.add_argument(
        "--top-ports", type=int, metavar="N",
        help="N najczęściej spotykanych portów TCP",
    )
    ports.add_argument(
        "-r", dest="randomize", action="store_false", default=True,
        help="nie losuj kolejności portów",
    )
    ports.add_argument(
        "--services", metavar="PLIK",
        help="ścieżka do nmap-services (domyślnie szukane w systemie)",
    )

    disc = parser.add_argument_group("wykrywanie hostów i DNS")
    disc.add_argument(
        "-Pn", dest="skip_ping", action="store_true", default=True,
        help="pomiń wykrywanie hostów (w tej wersji zawsze włączone)",
    )
    disc.add_argument(
        "-n", dest="resolve_dns", action="store_false", default=True,
        help="nie wykonuj odwrotnego DNS",
    )
    disc.add_argument(
        "--exclude", metavar="CELE",
        help="lista celów do pominięcia (po przecinku)",
    )

    timing = parser.add_argument_group("timing i wydajność")
    timing.add_argument(
        "-T", dest="timing_level", type=int, choices=range(6), metavar="0-5",
        default=3, help="szablon timingowy: 0 paranoid ... 5 insane (domyślnie 3)",
    )
    timing.add_argument("--max-retries", type=int, metavar="N",
                        help="maks. liczba retransmisji na port")
    timing.add_argument("--host-timeout", type=parse_time, metavar="CZAS",
                        help="porzuć host po tym czasie, np. 30s, 5m")
    timing.add_argument("--scan-delay", type=parse_time, metavar="CZAS",
                        help="minimalna przerwa między sondami")
    timing.add_argument("--min-parallelism", type=_positive_int, default=0, metavar="N",
                        help="minimalna liczba sond w locie (0 = bez wymuszenia)")
    timing.add_argument("--max-parallelism", type=_positive_int, default=0, metavar="N",
                        help="maksymalna liczba sond w locie (0 = dynamicznie, wg cwnd)")
    timing.add_argument("--seed", type=int, metavar="N",
                        help="ziarno losowania kolejności portów (powtarzalne testy)")

    raw = parser.add_argument_group("parametry pakietów (dotyczą -sS)")
    raw.add_argument("-g", "--source-port", type=int, metavar="PORT",
                     help="wymuś port źródłowy")
    raw.add_argument("-S", "--source-ip", metavar="IP",
                     help="wymuś adres źródłowy")
    raw.add_argument("--ttl", type=int, default=64, metavar="N",
                     help="TTL w wysyłanych pakietach (domyślnie 64)")

    out = parser.add_argument_group("wyjście")
    out.add_argument("--open", dest="only_open", action="store_true",
                     help="pokaż tylko porty otwarte")
    out.add_argument("--reason", dest="show_reason", action="store_true",
                     help="pokaż powód przypisania stanu")
    out.add_argument("-v", dest="verbose", action="count", default=0,
                     help="więcej szczegółów (-vv dla jeszcze więcej)")
    out.add_argument("-d", dest="debug", action="count", default=0,
                     help="tryb debug")
    out.add_argument("-oN", dest="out_normal", metavar="PLIK",
                     help="zapisz wynik w formacie normalnym")
    out.add_argument("-oG", dest="out_grepable", metavar="PLIK",
                     help="zapisz wynik w formacie grepable")
    out.add_argument("-oJ", dest="out_json", metavar="PLIK",
                     help="zapisz wynik w formacie JSON")
    out.add_argument("--version", action="version",
                     version=f"pynmap-basic {VERSION}")

    return parser


DEFAULT_TOP_PORTS = 100


def resolve_ports(args, services: ServiceDB) -> list[int]:
    """
    Decyduje, które porty skanować: -p, --top-ports albo domyślne top 100.

    Rozróżnienie "nie podano" od "podano wartość fałszywą" robimy przez
    `is not None`, a nie przez samą prawdziwość. Inaczej `-p ""` i
    `--top-ports 0` wpadały w gałąź domyślną i CICHO skanowały top 100 —
    czyli literówka albo nierozwinięta zmienna środowiskowa dawały skan,
    o który nikt nie prosił, z kodem wyjścia 0. Osobny strażnik na pustą
    specyfikację jest w ports.py, ale CLI nigdy do niego nie docierał.
    """
    if args.port_spec is not None and args.top_ports is not None:
        raise SystemExit("pynmap: -p i --top-ports wykluczają się")

    if args.port_spec is not None:
        return parse_port_spec(args.port_spec, service_lookup=services.port_for_name)

    if args.top_ports is None:
        count = DEFAULT_TOP_PORTS
    elif args.top_ports <= 0:
        # nmap: "Argument to --top-ports must be greater than 0"
        raise PortSpecError("--top-ports wymaga liczby > 0")
    else:
        count = args.top_ports

    return services.top_ports(min(count, services.available_top_ports))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.targets:
        parser.print_help()
        return 0

    # Sprzeczne okno: dotychczas max było po cichu wyrzucane
    # (low_cwnd = max_cwnd = min_parallelism), czyli flaga --max-parallelism
    # nie robiła nic, mimo że użytkownik ją podał.
    if args.min_parallelism and args.max_parallelism and (
        args.min_parallelism > args.max_parallelism
    ):
        print(
            f"pynmap: --min-parallelism ({args.min_parallelism}) nie może być większe "
            f"niż --max-parallelism ({args.max_parallelism})",
            file=sys.stderr,
        )
        return 2

    services = ServiceDB(services_path=args.services)

    try:
        ports = resolve_ports(args, services)
    except (PortSpecError, ValueError) as exc:
        print(f"pynmap: {exc}", file=sys.stderr)
        return 2

    try:
        targets = expand_specs(
            args.targets,
            resolve=args.resolve_dns,
            exclude=(args.exclude or "").split(",") if args.exclude else None,
        )
    except TargetSpecError as exc:
        print(f"pynmap: {exc}", file=sys.stderr)
        return 2

    if not targets:
        print("pynmap: brak celów po zastosowaniu --exclude", file=sys.stderr)
        return 2

    # domyślny typ skanu jak w nmapie: root dostaje -sS, reszta -sT
    scan_type = args.scan_type or (ScanType.SYN if is_root() else ScanType.CONNECT)

    opts = ScanOptions(
        scan_type=scan_type,
        ports=ports,
        timing=TIMING_TEMPLATES[args.timing_level],
        max_retries=args.max_retries,
        host_timeout_s=args.host_timeout or 0.0,
        scan_delay_s=args.scan_delay,
        randomize_ports=args.randomize,
        source_port=args.source_port,
        source_ip=args.source_ip,
        ttl=args.ttl,
        show_only_open=args.only_open,
        show_reason=args.show_reason,
        verbose=args.verbose,
        debug=args.debug,
        resolve_dns=args.resolve_dns,
        min_parallelism=args.min_parallelism,
        max_parallelism=args.max_parallelism,
        seed=args.seed,
    )

    if args.resolve_dns:
        for target in targets:
            reverse_lookup(target)

    started = time.time()
    wall_start = time.monotonic()

    try:
        if scan_type is ScanType.SYN:
            hosts = syn_scan(targets, opts)
        else:
            hosts = connect_scan(targets, opts)
    except RawSocketError as exc:
        print(f"pynmap: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\npynmap: przerwano przez użytkownika", file=sys.stderr)
        return 130

    report = ScanReport(
        scan_type=scan_type,
        hosts=hosts,
        started_at=started,
        elapsed_s=time.monotonic() - wall_start,
        command_line=" ".join(shlex.quote(a) for a in (argv or sys.argv[1:])),
        services_source=services.source,
    )

    text = format_normal(
        report,
        services,
        only_open=args.only_open,
        show_reason=args.show_reason,
        verbose=args.verbose,
    )
    print(text)

    for path, formatter in (
        (args.out_normal, lambda: text),
        (args.out_grepable, lambda: format_grepable(report, services)),
        (args.out_json, lambda: format_json(report, services)),
    ):
        if not path:
            continue
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(formatter())
                handle.write("\n")
        except OSError as exc:
            print(f"pynmap: nie udało się zapisać {path}: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
