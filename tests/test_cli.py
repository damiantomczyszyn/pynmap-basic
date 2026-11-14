"""
Testy warstwy CLI — odpowiednik parsowania opcji z nmap.cc.

Ta warstwa nie miała dotąd żadnych testów, i właśnie dlatego przeszły
przez nią dwa przypadki, w których skaner CICHO skanował coś innego,
niż poproszono: `-p ""` oraz `--top-ports 0` wpadały w gałąź domyślną
i skanowały top 100 portów z kodem wyjścia 0.
"""

import pytest

from pynmap.cli import DEFAULT_TOP_PORTS, build_parser, parse_time, resolve_ports
from pynmap.ports import PortSpecError
from pynmap.services import ServiceDB


@pytest.fixture
def services():
    return ServiceDB(prefer_system=False)


def _args(argv):
    return build_parser().parse_args(argv)


# ---------------------------------------------------------------------------
# resolve_ports() — "nie podano" to nie to samo co "podano zero"
# ---------------------------------------------------------------------------


def test_no_port_option_uses_default_top_ports(services):
    ports = resolve_ports(_args(["127.0.0.1"]), services)
    assert len(ports) == DEFAULT_TOP_PORTS


def test_explicit_port_spec_wins(services):
    assert resolve_ports(_args(["-p", "22,80", "127.0.0.1"]), services) == [22, 80]


def test_empty_port_spec_is_an_error(services):
    """`-p ""` to literówka albo nierozwinięta zmienna, nie skan top 100."""
    with pytest.raises(PortSpecError):
        resolve_ports(_args(["-p", "", "127.0.0.1"]), services)


def test_top_ports_zero_is_an_error(services):
    with pytest.raises(PortSpecError):
        resolve_ports(_args(["--top-ports", "0", "127.0.0.1"]), services)


def test_top_ports_negative_is_an_error(services):
    with pytest.raises(PortSpecError):
        resolve_ports(_args(["--top-ports", "-5", "127.0.0.1"]), services)


def test_top_ports_positive_works(services):
    assert len(resolve_ports(_args(["--top-ports", "5", "127.0.0.1"]), services)) == 5


def test_port_spec_and_top_ports_conflict(services):
    with pytest.raises(SystemExit):
        resolve_ports(_args(["-p", "22", "--top-ports", "5", "127.0.0.1"]), services)


def test_empty_port_spec_still_conflicts_with_top_ports(services):
    """Konflikt wykrywany po `is not None`, więc pusty -p też się liczy."""
    with pytest.raises(SystemExit):
        resolve_ports(_args(["-p", "", "--top-ports", "5", "127.0.0.1"]), services)


def test_top_ports_clamped_to_database_size(services):
    ports = resolve_ports(_args(["--top-ports", "999999", "127.0.0.1"]), services)
    assert len(ports) == services.available_top_ports


# ---------------------------------------------------------------------------
# parse_time() — notacja nmapa
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("500ms", 0.5),
        ("30s", 30.0),
        ("5m", 300.0),
        ("2h", 7200.0),
        ("45", 45.0),
        ("1.5s", 1.5),
    ],
)
def test_parse_time_units(text, expected):
    assert parse_time(text) == pytest.approx(expected)


@pytest.mark.parametrize("text", ["", "abc", "10x", "-5s", "s"])
def test_parse_time_rejects_garbage(text):
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        parse_time(text)


# ---------------------------------------------------------------------------
# Domyślny typ skanu i flagi
# ---------------------------------------------------------------------------


def test_scan_type_flags_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["-sT", "-sS", "127.0.0.1"])


def test_default_timing_is_normal():
    assert _args(["127.0.0.1"]).timing_level == 3


def test_randomize_is_on_unless_dash_r():
    assert _args(["127.0.0.1"]).randomize is True
    assert _args(["-r", "127.0.0.1"]).randomize is False


# ---------------------------------------------------------------------------
# --min/--max-parallelism: wartosci, ktore zabijaly skan
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["--min-parallelism", "--max-parallelism"])
def test_negative_parallelism_is_rejected(flag):
    """
    Ujemne okno dawalo cwnd < 0, send_ok() na zawsze False i skan krecacy sie
    bez konca na 100% CPU, bez ani jednej linii wyjscia.
    """
    with pytest.raises(SystemExit):
        build_parser().parse_args([flag, "-1", "127.0.0.1"])


@pytest.mark.parametrize("flag", ["--min-parallelism", "--max-parallelism"])
def test_zero_parallelism_means_no_limit(flag):
    args = build_parser().parse_args([flag, "0", "127.0.0.1"])
    assert getattr(args, flag.lstrip("-").replace("-", "_")) == 0


@pytest.mark.parametrize("flag", ["--min-parallelism", "--max-parallelism"])
def test_non_integer_parallelism_is_rejected(flag):
    with pytest.raises(SystemExit):
        build_parser().parse_args([flag, "abc", "127.0.0.1"])


def test_min_above_max_parallelism_is_rejected():
    """Sprzeczne okno: dotad max bylo po cichu wyrzucane i flaga nic nie robila."""
    from pynmap.cli import main

    assert main(["-sT", "-p", "22", "-n", "--min-parallelism", "5",
                 "--max-parallelism", "2", "127.0.0.1"]) == 2


def test_min_below_max_parallelism_is_accepted():
    args = build_parser().parse_args(
        ["--min-parallelism", "2", "--max-parallelism", "5", "127.0.0.1"]
    )
    assert (args.min_parallelism, args.max_parallelism) == (2, 5)
