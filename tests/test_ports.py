"""Testy parsowania specyfikacji portów (odpowiednik getpts() z nmapa)."""

import pytest

from pynmap.constants import PortState, Reason
from pynmap.ports import MAX_PORT, PortList, PortSpecError, order_ports, parse_port_spec
from pynmap.services import ServiceDB


@pytest.fixture(scope="module")
def lookup():
    return ServiceDB(prefer_system=False).port_for_name


def test_single_port():
    assert parse_port_spec("80") == [80]


def test_range():
    assert parse_port_spec("20-25") == [20, 21, 22, 23, 24, 25]


def test_list():
    assert parse_port_spec("443,80,22") == [22, 80, 443]


def test_duplicates_collapse():
    assert parse_port_spec("80,80,80") == [80]


def test_open_ended_low():
    result = parse_port_spec("-1024")
    assert result[0] == 1 and result[-1] == 1024 and len(result) == 1024


def test_open_ended_high():
    result = parse_port_spec("65530-")
    assert result == [65530, 65531, 65532, 65533, 65534, 65535]


def test_all_ports():
    result = parse_port_spec("-")
    assert len(result) == MAX_PORT and result[0] == 1 and result[-1] == MAX_PORT


def test_tcp_prefix_kept_udp_dropped():
    # pynmap-basic skanuje tylko TCP, więc U: jest pomijane
    assert parse_port_spec("T:80,U:53") == [80]


def test_service_names(lookup):
    assert parse_port_spec("http,ssh", service_lookup=lookup) == [22, 80]


@pytest.mark.parametrize("bad", ["", "99999", "0", "10-5", "nieistnieje", "80,,443"])
def test_rejects_bad_specs(bad, lookup):
    with pytest.raises(PortSpecError):
        parse_port_spec(bad, service_lookup=lookup)


def test_unknown_protocol_prefix():
    with pytest.raises(PortSpecError):
        parse_port_spec("X:80")


def test_order_ports_randomize_is_permutation():
    ports = list(range(1, 101))
    shuffled = order_ports(ports, randomize=True)
    assert sorted(shuffled) == ports
    assert len(shuffled) == len(ports)


def test_order_ports_no_randomize_preserves_order():
    ports = [1, 2, 3, 4, 5]
    assert order_ports(ports, randomize=False) == ports


# ---------------------------------------------------------------------------
# PortList
# ---------------------------------------------------------------------------


def test_portlist_set_and_get():
    pl = PortList()
    pl.set_state(80, PortState.OPEN, Reason.SYNACK, rtt_us=1234)
    entry = pl.get(80)
    assert entry.state is PortState.OPEN
    assert entry.reason is Reason.SYNACK
    assert entry.rtt_us == 1234


def test_portlist_finalize_fills_default():
    pl = PortList(default_state=PortState.FILTERED, default_reason=Reason.NORESPONSE)
    pl.set_state(80, PortState.OPEN, Reason.SYNACK)
    pl.finalize([80, 443, 8080])

    assert pl.get(443).state is PortState.FILTERED
    assert pl.get(8080).reason is Reason.NORESPONSE
    assert pl.get(80).state is PortState.OPEN


def test_portlist_counts():
    pl = PortList()
    pl.set_state(80, PortState.OPEN, Reason.SYNACK)
    pl.set_state(81, PortState.OPEN, Reason.SYNACK)
    pl.set_state(82, PortState.CLOSED, Reason.CONREFUSED)
    counts = pl.count_by_state()
    assert counts[PortState.OPEN] == 2
    assert counts[PortState.CLOSED] == 1


def test_portlist_sorted():
    pl = PortList()
    for port in (443, 22, 80):
        pl.set_state(port, PortState.OPEN, Reason.SYNACK)
    assert [e.port for e in pl.sorted_results()] == [22, 80, 443]
