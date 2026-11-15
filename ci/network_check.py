#!/usr/bin/env python3
"""
Realny test sieciowy dla CI.

Skanuje cele podane w argumentach i weryfikuje, czy stany portów zgadzają się
z oczekiwaniami. Zwraca kod != 0, jeśli którykolwiek port wyszedł inaczej —
dzięki temu to jest test, który może oblać build, a nie demo.

W CI cele to usługi w kontenerach Dockera adresowane po IP mostka, więc
pakiety idą przez prawdziwy ARP, bridge i routing jądra, a nie skrótem
przez interfejs loopback.

Użycie:
    python3 ci/network_check.py \
        --expect-open 172.17.0.2:80 --expect-closed 172.17.0.2:9999 \
        --scan sT --scan sS --json wyniki.json --summary podsumowanie.md
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pynmap.constants import PortState, ScanType          # noqa: E402
from pynmap.engine import ScanOptions, is_root            # noqa: E402
from pynmap.scan_connect import connect_scan              # noqa: E402
from pynmap.scan_syn import RawSocketError, syn_scan      # noqa: E402
from pynmap.services import ServiceDB                     # noqa: E402
from pynmap.targets import Target                          # noqa: E402
from pynmap.timing import TIMING_TEMPLATES                 # noqa: E402

SCAN_LABELS = {"sT": ScanType.CONNECT, "sS": ScanType.SYN}


def parse_endpoint(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError(
            f"Oczekiwano formatu IP:PORT, otrzymano '{text}'"
        )
    try:
        socket.inet_aton(host)
    except OSError as exc:
        raise argparse.ArgumentTypeError(f"'{host}' nie jest adresem IPv4") from exc
    return host, int(port)


def run_scan(
    scan_label: str,
    expectations: dict[str, dict[int, PortState]],
) -> tuple[dict, list[str]]:
    """Uruchamia jeden typ skanu i zwraca (wyniki, lista błędów)."""
    scan_type = SCAN_LABELS[scan_label]
    hosts = sorted(expectations)
    ports = sorted({p for per_host in expectations.values() for p in per_host})

    opts = ScanOptions(
        scan_type=scan_type,
        ports=ports,
        timing=TIMING_TEMPLATES[4],
        randomize_ports=False,
        resolve_dns=False,
        max_retries=2,
    )
    targets = [Target(ip=ip) for ip in hosts]

    scanner = syn_scan if scan_type is ScanType.SYN else connect_scan

    started = time.monotonic()
    reports = scanner(targets, opts)
    elapsed = time.monotonic() - started

    services = ServiceDB()
    failures: list[str] = []
    rows: list[dict] = []

    for report in reports:
        expected_for_host = expectations[report.target.ip]
        for port in ports:
            entry = report.portlist.get(port)
            expected = expected_for_host.get(port)
            ok = expected is None or entry.state is expected

            if not ok:
                failures.append(
                    f"[{scan_label}] {report.target.ip}:{port} — "
                    f"oczekiwano {expected}, otrzymano {entry.state} "
                    f"(powód: {entry.reason})"
                )

            rows.append(
                {
                    "scan": scan_label,
                    "host": report.target.ip,
                    "port": port,
                    "state": entry.state.value,
                    "expected": expected.value if expected else None,
                    "reason": entry.reason.value,
                    "reason_ttl": entry.reason_ttl,
                    "rtt_us": entry.rtt_us,
                    "service": services.service_name(port),
                    "ok": ok,
                }
            )

    result = {
        "scan": scan_label,
        "elapsed_s": round(elapsed, 4),
        "hosts": len(hosts),
        "ports": len(ports),
        "probes_sent": sum(r.probes_sent for r in reports),
        "replies_received": sum(r.replies_received for r in reports),
        "rows": rows,
        "services_source": services.source,
    }
    return result, failures


def write_summary(path: str, results: list[dict], failures: list[str]) -> None:
    """Pisze podsumowanie w Markdownie — GitHub renderuje to na stronie joba."""
    lines: list[str] = ["## Realny test sieciowy", ""]

    if failures:
        lines += [f"**{len(failures)} rozbieżności wobec oczekiwań:**", ""]
        lines += [f"- {f}" for f in failures]
        lines.append("")
    else:
        lines += ["Wszystkie porty w oczekiwanych stanach.", ""]

    for result in results:
        lines += [
            f"### `-{result['scan']}`",
            "",
            f"Czas: {result['elapsed_s']} s · "
            f"sondy: {result['probes_sent']} · "
            f"odpowiedzi: {result['replies_received']}",
            "",
            "| Host | Port | Usługa | Stan | Oczekiwano | Powód | RTT |",
            "|---|---|---|---|---|---|---|",
        ]
        for row in result["rows"]:
            mark = "" if row["ok"] else " ⚠️"
            rtt = f"{row['rtt_us'] / 1000:.2f} ms" if row["rtt_us"] else "—"
            ttl = f" (ttl {row['reason_ttl']})" if row["reason_ttl"] else ""
            lines.append(
                f"| `{row['host']}` | {row['port']} | {row['service']} "
                f"| **{row['state']}**{mark} | {row['expected'] or '—'} "
                f"| {row['reason']}{ttl} | {rtt} |"
            )
        lines.append("")

    src = results[0]["services_source"] if results else "builtin"
    lines += [
        f"Baza usług: `{src}`",
        "",
        "Cele to kontenery Dockera adresowane po IP mostka, więc pakiety "
        "przechodzą przez ARP, bridge i routing jądra — nie skrótem przez "
        "loopback.",
    ]

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-open", type=parse_endpoint, action="append", default=[])
    parser.add_argument("--expect-closed", type=parse_endpoint, action="append", default=[])
    parser.add_argument("--expect-filtered", type=parse_endpoint, action="append", default=[])
    parser.add_argument("--scan", action="append", choices=sorted(SCAN_LABELS), default=[])
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--summary", dest="summary_path")
    args = parser.parse_args()

    expectations: dict[str, dict[int, PortState]] = defaultdict(dict)
    for endpoints, state in (
        (args.expect_open, PortState.OPEN),
        (args.expect_closed, PortState.CLOSED),
        (args.expect_filtered, PortState.FILTERED),
    ):
        for host, port in endpoints:
            expectations[host][port] = state

    if not expectations:
        print("network_check: nie podano żadnych oczekiwań", file=sys.stderr)
        return 2

    scans = args.scan or ["sT"]
    results: list[dict] = []
    all_failures: list[str] = []

    for label in scans:
        # Skan podany przez --scan jest ZAMOWIONY. Pominiecie go po cichu
        # oznaczalo, ze polowa testu sieciowego cicho znika, a build i tak
        # swieci na zielono — czyli test, ktory nie potrafi oblac.
        if label == "sS" and not is_root():
            msg = f"[{label}] brak CAP_NET_RAW — zamówiony skan nie wykonał się"
            print(f"network_check: {msg}", file=sys.stderr)
            all_failures.append(msg)
            continue
        print(f"network_check: uruchamiam -{label} …")
        try:
            result, failures = run_scan(label, dict(expectations))
        except RawSocketError as exc:
            msg = f"[{label}] surowe sockety niedostępne: {exc}"
            print(f"network_check: {msg}", file=sys.stderr)
            all_failures.append(msg)
            continue
        results.append(result)
        all_failures += failures

        for row in result["rows"]:
            mark = "OK " if row["ok"] else "BŁĄD"
            print(
                f"  {mark} {row['host']}:{row['port']:<6} "
                f"{row['state']:<9} (oczekiwano {row['expected']}, "
                f"powód {row['reason']})"
            )

    if not results:
        print("network_check: żaden skan się nie wykonał", file=sys.stderr)
        return 2

    if args.json_path:
        payload = {
            "generated_at": time.time(),
            "git_sha": os.environ.get("GITHUB_SHA", "")[:7],
            "git_ref": os.environ.get("GITHUB_REF_NAME", ""),
            "run_url": (
                f"{os.environ.get('GITHUB_SERVER_URL', '')}/"
                f"{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
                f"{os.environ.get('GITHUB_RUN_ID', '')}"
                if os.environ.get("GITHUB_RUN_ID")
                else ""
            ),
            "passed": not all_failures,
            "failures": all_failures,
            "scans": results,
        }
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        print(f"network_check: JSON zapisany do {args.json_path}")

    if args.summary_path:
        write_summary(args.summary_path, results, all_failures)
        print(f"network_check: podsumowanie zapisane do {args.summary_path}")

    if all_failures:
        print(f"\nnetwork_check: {len(all_failures)} rozbieżności", file=sys.stderr)
        return 1

    print("\nnetwork_check: wszystkie porty w oczekiwanych stanach")
    return 0


if __name__ == "__main__":
    sys.exit(main())
