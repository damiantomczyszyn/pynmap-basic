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


# ---------------------------------------------------------------------------
# Prefiks protokolu jest "lepki", jak w nmapie
# ---------------------------------------------------------------------------


def test_protocol_prefix_is_sticky_across_chunks(lookup):
    """
    W nmapie -p U:53,161 oznacza, ze OBA porty sa UDP. Trzymanie prefiksu
    per-element sprawialo, ze 'U:53,80' cicho skanowalo TCP/80 — uzytkownik
    prosil o UDP, a dostawal skan TCP jednego z podanych portow.
    """
    with pytest.raises(PortSpecError):
        parse_port_spec("U:53,80", service_lookup=lookup)
    with pytest.raises(PortSpecError):
        parse_port_spec("U:53,161", service_lookup=lookup)


def test_protocol_prefix_can_switch_back_to_tcp(lookup):
    assert parse_port_spec("T:80,U:53,T:443", service_lookup=lookup) == [80, 443]
    assert parse_port_spec("T:80,U:53", service_lookup=lookup) == [80]


def test_unknown_protocol_prefix_is_rejected(lookup):
    with pytest.raises(PortSpecError):
        parse_port_spec("x:80", service_lookup=lookup)


def test_plain_ranges_are_not_mistaken_for_services(lookup):
    assert parse_port_spec("1-5", service_lookup=lookup) == [1, 2, 3, 4, 5]
    assert parse_port_spec("80-82", service_lookup=lookup) == [80, 81, 82]


# ---------------------------------------------------------------------------
# Nazwy uslug z myslnikiem
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,port",
    [("http-proxy", 8080), ("https-alt", 8443), ("ms-wbt-server", 3389)],
)
def test_hyphenated_service_names_resolve(name, port, lookup):
    """
    Myslnik w nazwie uslugi trafial w galez zakresu i rozbijal nazwe na pol
    ('http-proxy' -> blad "'proxy' nie jest numerem portu"), wiec nazwy,
    ktore SA w bazie, byly nieosiagalne przez -p.
    """
    assert parse_port_spec(name, service_lookup=lookup) == [port]


def test_service_port_outside_range_is_rejected():
    """Baza uslug moze pochodzic z pliku uzytkownika, wiec to tez wejscie."""
    with pytest.raises(PortSpecError):
        parse_port_spec("zle", service_lookup=lambda _n: 99999)
    with pytest.raises(PortSpecError):
        parse_port_spec("zle", service_lookup=lambda _n: 0)
