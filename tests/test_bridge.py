"""
Testy warstwy pośredniej dla przeglądarki (web/bridge.py).

Najważniejszy jest tu `_needs_dns`: pod Emscriptenem getaddrinfo() nie
sięga do sieci, ale też nie zgłasza błędu — zwraca sfabrykowane adresy
z 172.29.0.0/16. Bez tego guardu wpisanie nazwy hosta dawało wiarygodnie
wyglądającą bzdurę, co jest groźniejsze niż czysty błąd.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))

import bridge  # noqa: E402


# ---------------------------------------------------------------------------
# Rozpoznawanie, czy specyfikacja wymaga DNS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    ["10.0.0.1", "10.0.0.0/24", "10.0.1-2.1-5", "10.0.0.*", "192.168.1.1,5,9",
     "2001:db8::1", "::1"],
)
def test_specs_that_need_no_dns(spec):
    assert bridge._needs_dns(spec) is False


@pytest.mark.parametrize(
    "spec", ["example.com", "scanme.nmap.org", "localhost", "my-host", "a.b.c.d"]
)
def test_specs_that_need_dns(spec):
    assert bridge._needs_dns(spec) is True


def test_empty_spec_needs_no_dns():
    assert bridge._needs_dns("") is False
    assert bridge._needs_dns("   ") is False


def test_wasm_guard_rejects_hostnames(monkeypatch):
    """Pod WASM nazwa hosta musi dać jawny błąd, nie zmyślony adres."""
    monkeypatch.setattr(bridge, "_IS_WASM", True)
    result = bridge.parse_targets("example.com")

    assert result["ok"] is False
    assert "DNS" in result["error"]
    assert "172.29" in result["error"]   # komunikat tłumaczy, skąd bzdura
    assert "targets" not in result


def test_wasm_guard_allows_literals(monkeypatch):
    monkeypatch.setattr(bridge, "_IS_WASM", True)
    result = bridge.parse_targets("10.0.0.0/30")

    assert result["ok"] is True
    assert result["targets"] == ["10.0.0.1", "10.0.0.2"]


# ---------------------------------------------------------------------------
# Budowanie pakietu
# ---------------------------------------------------------------------------


def test_build_packet_shape_and_checksum():
    res = bridge.build_packet(
        src="192.168.1.50", dst="192.168.1.1",
        sport=44321, dport=443, seq=0xDEADBEEF,
    )
    assert res["ok"] is True
    assert res["length"] == 44                 # IP 20 + TCP 20 + MSS 4
    assert res["ip_header_len"] == 20
    assert res["tcp_header_len"] == 24
    assert res["ip_checksum_ok"] is True
    assert len(res["hex"]) == 88               # 44 bajty po 2 znaki


def test_build_packet_is_byte_stable():
    """
    Te same wejścia muszą dać ten sam pakiet — inaczej demo w przeglądarce
    i skan w CI nie byłyby porównywalne.
    """
    args = dict(src="10.0.0.5", dst="10.0.0.9", sport=40000, dport=80, seq=1)
    assert bridge.build_packet(**args)["hex"] == bridge.build_packet(**args)["hex"]


def test_build_packet_without_mss_is_shorter():
    res = bridge.build_packet(mss=None)
    assert res["length"] == 40
    assert res["tcp_header_len"] == 20


def test_build_packet_rejects_bad_ip():
    res = bridge.build_packet(src="nie-jest-adresem")
    assert res["ok"] is False
    assert "IP" in res["error"]


def test_build_packet_fields_reference_real_offsets():
    res = bridge.build_packet()
    for field in res["fields"]:
        assert 0 <= field["offset"] < res["length"]
        assert field["offset"] + field["length"] <= res["length"]


# ---------------------------------------------------------------------------
# Estymator RTT
# ---------------------------------------------------------------------------


def test_rtt_trace_matches_timing_module():
    res = bridge.rtt_trace([200, 240], template=3)
    first, second = res["steps"]

    assert first["srtt_ms"] == 200.0
    assert first["timeout_ms"] == 1000.0       # srtt + 4*rttvar
    assert second["srtt_ms"] == 205.0          # 200 + (40000>>3)/1000


def test_rtt_trace_ignores_absurd_sample():
    """Skok 1800 ms po stabilnych 200 ms ma zostać odrzucony sanity-checkiem."""
    res = bridge.rtt_trace([200, 240, 180, 1800], template=3)
    before, after = res["steps"][2], res["steps"][3]
    assert after["srtt_ms"] == before["srtt_ms"]
    assert after["timeout_ms"] == before["timeout_ms"]


def test_rtt_trace_reports_template():
    res = bridge.rtt_trace([100], template=5)
    assert res["template"]["level"] == 5
    assert res["template"]["max_ms"] == 300
    assert res["template"]["max_retries"] == 2


# ---------------------------------------------------------------------------
# Okno zatłoczenia
# ---------------------------------------------------------------------------


def test_cwnd_grows_then_collapses():
    res = bridge.cwnd_trace("aaaaad", template=3)
    steps = res["steps"]

    assert steps[0]["cwnd"] == 10.0
    assert steps[5]["cwnd"] == 15.0            # 5 x slow start po +1
    assert steps[6]["cwnd"] == 1.0             # drop -> low_cwnd
    assert steps[6]["ssthresh"] == 10          # max(15/1.5, 2)


def test_cwnd_group_drop_is_gentler():
    res = bridge.cwnd_trace("aaaaag", template=3)
    assert res["steps"][6]["cwnd"] == 7.5      # 15/2, nie do 1


def test_cwnd_ignores_unknown_event_letters():
    res = bridge.cwnd_trace("a?!a", template=3)
    assert len(res["steps"]) == 3              # start + 2 x ack


def test_cwnd_reports_template_params():
    res = bridge.cwnd_trace("a", template=4)
    assert res["perf"]["ca_incr"] == 2
    assert "T4" in res["perf"]["template"]


# ---------------------------------------------------------------------------
# Parsery i serializacja
# ---------------------------------------------------------------------------


def test_parse_ports_resolves_service_names():
    res = bridge.parse_ports("http,redis")
    assert res["ok"] is True
    assert [p["port"] for p in res["ports"]] == [80, 6379]


def test_parse_ports_reports_error_text():
    res = bridge.parse_ports("nieistnieje")
    assert res["ok"] is False
    assert "nieistnieje" in res["error"]


def test_parse_ports_truncates_large_results():
    res = bridge.parse_ports("-")
    assert res["count"] == 65535
    assert res["truncated"] is True
    assert len(res["ports"]) == bridge.MAX_LISTED


def test_everything_is_json_serializable():
    """Granica JS <-> Python przechodzi przez JSON, więc to musi się udać."""
    payload = {
        "packet": bridge.build_packet(),
        "rtt": bridge.rtt_trace([100, 120]),
        "cwnd": bridge.cwnd_trace("aad"),
        "ports": bridge.parse_ports("22,80"),
        "targets": bridge.parse_targets("10.0.0.0/30"),
        "top": bridge.top_ports(5),
        "env": bridge.environment(),
    }
    assert json.loads(json.dumps(payload)) == payload
