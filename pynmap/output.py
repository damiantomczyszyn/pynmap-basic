"""
Formatowanie wyników — odpowiednik output.cc i NmapOutputTable.cc.

Trzy formaty:
  normal    (-oN)  - tabela czytelna dla człowieka, układ jak w nmapie
  grepable  (-oG)  - jedna linia na host, do przetwarzania w awk/grep
  json      (-oJ)  - własne rozszerzenie (nmap ma XML, -oX)
"""

from __future__ import annotations

import json
import time
from collections import Counter

from .constants import PortState
from .engine import HostReport, ScanReport
from .services import ServiceDB

VERSION = "0.1.0"
PROJECT_URL = "https://github.com/damiantomczyszyn/pynmap-basic"


def _fmt_latency(report: HostReport) -> str:
    rtts = [
        r.rtt_us for r in report.portlist.results.values() if r.rtt_us is not None
    ]
    if not rtts:
        return ""
    avg_s = sum(rtts) / len(rtts) / 1_000_000.0
    return f" ({avg_s:.4f}s latency)"


def _port_label(port: int) -> str:
    return f"{port}/tcp"


def format_normal(
    report: ScanReport,
    services: ServiceDB,
    only_open: bool = False,
    show_reason: bool = False,
    verbose: int = 0,
) -> str:
    lines: list[str] = []
    started = time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(report.started_at))
    lines.append(f"Starting pynmap-basic {VERSION} ( {PROJECT_URL} ) at {started}")

    hosts_up = 0

    for host in report.hosts:
        if not host.host_up:
            lines.append("")
            lines.append(
                f"Skipping {host.target.display_name} "
                f"(IPv6 nie jest wspierane w -sS; użyj -sT)"
            )
            continue

        hosts_up += 1
        lines.append("")
        lines.append(f"pynmap-basic scan report for {host.target.display_name}")
        lines.append(f"Host is up{_fmt_latency(host)}.")

        if host.timed_out:
            lines.append("Skipping host due to host timeout.")
            continue

        results = host.portlist.sorted_results()
        shown = [
            r for r in results
            if not only_open or r.state in (PortState.OPEN, PortState.OPEN_FILTERED)
        ]
        hidden = [r for r in results if r not in shown]

        # "Not shown: N closed tcp ports (conn-refused)" — jak w nmapie
        if hidden:
            by_state = Counter(r.state for r in hidden)
            parts = []
            for state, count in by_state.most_common():
                reasons = Counter(
                    r.reason for r in hidden if r.state == state
                ).most_common(1)
                reason_txt = f" ({reasons[0][0]})" if reasons else ""
                parts.append(f"{count} {state} tcp port{'s' if count != 1 else ''}{reason_txt}")
            lines.append("Not shown: " + ", ".join(parts))

        if not shown:
            lines.append("All scanned ports are filtered or closed.")
        else:
            header = f"{'PORT':<10}{'STATE':<16}{'SERVICE':<18}"
            if show_reason:
                header += "REASON"
            lines.append(header.rstrip())

            for entry in shown:
                service = entry.service or services.service_name(entry.port)
                row = (
                    f"{_port_label(entry.port):<10}"
                    f"{str(entry.state):<16}"
                    f"{service:<18}"
                )
                if show_reason:
                    ttl = f" ttl {entry.reason_ttl}" if entry.reason_ttl else ""
                    row += f"{entry.reason}{ttl}"
                lines.append(row.rstrip())

        if verbose:
            lines.append(
                f"  (sondy wysłane: {host.probes_sent}, "
                f"odpowiedzi: {host.replies_received}, "
                f"czas: {host.elapsed_s:.2f}s)"
            )

    lines.append("")
    addr_word = "address" if len(report.hosts) == 1 else "addresses"
    lines.append(
        f"pynmap-basic done: {len(report.hosts)} IP {addr_word} "
        f"({hosts_up} host{'s' if hosts_up != 1 else ''} up) scanned in "
        f"{report.elapsed_s:.2f} seconds"
    )
    return "\n".join(lines)


def format_grepable(report: ScanReport, services: ServiceDB) -> str:
    lines = [f"# pynmap-basic {VERSION} scan initiated as: {report.command_line}"]

    for host in report.hosts:
        name = host.target.hostname or host.target.reverse_dns or ""
        if not host.host_up:
            lines.append(f"Host: {host.target.ip} ({name})\tStatus: Skipped")
            continue

        entries = []
        for entry in host.portlist.sorted_results():
            service = entry.service or services.service_name(entry.port)
            # format nmapa: port/stan/proto//usługa//wersja/
            entries.append(f"{entry.port}/{entry.state}/tcp//{service}///")

        lines.append(
            f"Host: {host.target.ip} ({name})\tStatus: Up\t"
            f"Ports: {', '.join(entries)}"
        )

    lines.append(
        f"# pynmap-basic done: {len(report.hosts)} IP addresses scanned in "
        f"{report.elapsed_s:.2f} seconds"
    )
    return "\n".join(lines)


def format_json(report: ScanReport, services: ServiceDB) -> str:
    payload = {
        "tool": "pynmap-basic",
        "version": VERSION,
        "scan_type": report.scan_type.value,
        "command_line": report.command_line,
        "started_at": report.started_at,
        "elapsed_s": round(report.elapsed_s, 4),
        "services_source": report.services_source,
        "hosts": [],
    }

    for host in report.hosts:
        payload["hosts"].append(
            {
                "ip": host.target.ip,
                "hostname": host.target.hostname or host.target.reverse_dns,
                "up": host.host_up,
                "timed_out": host.timed_out,
                "elapsed_s": round(host.elapsed_s, 4),
                "probes_sent": host.probes_sent,
                "replies_received": host.replies_received,
                "ports_scanned": len(host.scanned_ports),
                "ports": [
                    {
                        "port": entry.port,
                        "protocol": "tcp",
                        "state": entry.state.value,
                        "reason": entry.reason.value,
                        "reason_ttl": entry.reason_ttl,
                        "service": entry.service or services.service_name(entry.port),
                        "rtt_us": entry.rtt_us,
                        "tryno": entry.tryno,
                    }
                    for entry in host.portlist.sorted_results()
                ],
                "summary": {
                    str(state): count
                    for state, count in host.portlist.count_by_state().items()
                },
            }
        )

    return json.dumps(payload, indent=2, ensure_ascii=False)
