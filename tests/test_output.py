"""Testy formatowania wyników (odpowiednik output.cc)."""

import json

import pytest

from pynmap.constants import PortState, Reason, ScanType
from pynmap.engine import HostReport, ScanReport
from pynmap.output import format_grepable, format_json, format_normal
from pynmap.ports import PortList
from pynmap.services import ServiceDB
from pynmap.targets import Target


@pytest.fixture
def services():
    return ServiceDB(prefer_system=False)


@pytest.fixture
def report():
    pl = PortList()
    pl.set_state(22, PortState.OPEN, Reason.SYNACK, rtt_us=1500, reason_ttl=64)
    pl.set_state(80, PortState.OPEN, Reason.SYNACK, rtt_us=1600)
    pl.set_state(443, PortState.CLOSED, Reason.CONREFUSED, rtt_us=1200)
    pl.set_state(8080, PortState.FILTERED, Reason.NORESPONSE)

    host = HostReport(
        target=Target(ip="192.0.2.10", hostname="example.test"),
        portlist=pl,
        scanned_ports=[22, 80, 443, 8080],
        elapsed_s=1.25,
        probes_sent=4,
        replies_received=3,
    )
    return ScanReport(
        scan_type=ScanType.SYN,
        hosts=[host],
        started_at=1_700_000_000.0,
        elapsed_s=1.30,
        command_line="-sS -p 22,80,443,8080 192.0.2.10",
    )


# ---------------------------------------------------------------------------
# Format normalny
# ---------------------------------------------------------------------------


def test_normal_contains_header_and_ports(report, services):
    text = format_normal(report, services)
    assert "pynmap-basic scan report for example.test (192.0.2.10)" in text
    assert "Host is up" in text
    assert "22/tcp" in text and "ssh" in text
    assert "80/tcp" in text and "http" in text
    assert "443/tcp" in text
    assert "PORT" in text and "STATE" in text and "SERVICE" in text


def test_normal_only_open_hides_others(report, services):
    text = format_normal(report, services, only_open=True)
    assert "22/tcp" in text
    assert "80/tcp" in text
    # zamknięte/filtrowane trafiają do podsumowania "Not shown"
    assert "Not shown:" in text
    lines = [ln for ln in text.splitlines() if ln.startswith(("443/tcp", "8080/tcp"))]
    assert lines == []


def test_normal_shows_reason_when_requested(report, services):
    text = format_normal(report, services, show_reason=True)
    assert "REASON" in text
    assert "syn-ack" in text
    assert "ttl 64" in text


def test_normal_hides_reason_by_default(report, services):
    text = format_normal(report, services)
    assert "REASON" not in text


def test_normal_verbose_adds_counters(report, services):
    text = format_normal(report, services, verbose=1)
    assert "sondy wysłane: 4" in text
    assert "odpowiedzi: 3" in text


def test_normal_latency_is_reported(report, services):
    text = format_normal(report, services)
    assert "latency" in text


def test_normal_footer_counts_hosts(report, services):
    text = format_normal(report, services)
    assert "1 IP address" in text
    assert "1 host up" in text


# ---------------------------------------------------------------------------
# Format grepable
# ---------------------------------------------------------------------------


def test_grepable_single_line_per_host(report, services):
    text = format_grepable(report, services)
    host_lines = [ln for ln in text.splitlines() if ln.startswith("Host:")]
    assert len(host_lines) == 1
    assert "192.0.2.10" in host_lines[0]
    assert "Status: Up" in host_lines[0]


def test_grepable_port_field_format(report, services):
    text = format_grepable(report, services)
    # format nmapa: port/stan/proto//usługa//wersja/
    assert "22/open/tcp//ssh///" in text
    assert "443/closed/tcp//https///" in text


def test_grepable_has_comment_header_and_footer(report, services):
    text = format_grepable(report, services)
    lines = text.splitlines()
    assert lines[0].startswith("# pynmap-basic")
    assert lines[-1].startswith("# pynmap-basic done")


# ---------------------------------------------------------------------------
# Format JSON
# ---------------------------------------------------------------------------


def test_json_is_valid_and_structured(report, services):
    data = json.loads(format_json(report, services))

    assert data["tool"] == "pynmap-basic"
    assert data["scan_type"] == "syn"
    assert len(data["hosts"]) == 1

    host = data["hosts"][0]
    assert host["ip"] == "192.0.2.10"
    assert host["hostname"] == "example.test"
    assert host["up"] is True
    assert host["ports_scanned"] == 4
    assert len(host["ports"]) == 4


def test_json_port_entries_have_expected_fields(report, services):
    data = json.loads(format_json(report, services))
    entry = next(p for p in data["hosts"][0]["ports"] if p["port"] == 22)

    assert entry["state"] == "open"
    assert entry["reason"] == "syn-ack"
    assert entry["protocol"] == "tcp"
    assert entry["service"] == "ssh"
    assert entry["rtt_us"] == 1500
    assert entry["reason_ttl"] == 64


def test_json_summary_counts_states(report, services):
    data = json.loads(format_json(report, services))
    summary = data["hosts"][0]["summary"]
    assert summary["open"] == 2
    assert summary["closed"] == 1
    assert summary["filtered"] == 1


def test_json_handles_skipped_host(services):
    host = HostReport(
        target=Target(ip="::1"),
        portlist=PortList(),
        scanned_ports=[],
        elapsed_s=0.0,
        probes_sent=0,
        replies_received=0,
        host_up=False,
    )
    rep = ScanReport(scan_type=ScanType.SYN, hosts=[host], started_at=0.0)
    data = json.loads(format_json(rep, services))
    assert data["hosts"][0]["up"] is False
    assert data["hosts"][0]["ports"] == []
