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
    """
    Bez -p skanujemy top 100 portow.

    Liczba jest tu WPISANA WPROST, a nie porownana z DEFAULT_TOP_PORTS:
    poprzednia wersja porownywala wynik z ta sama stala, ktorej uzywa kod,
    wiec przechodzila takze po zmianie stalej na 50 — czyli nie pilnowala
    niczego. Osobna asercja na sama stala dokumentuje zamiar, zeby zmiana
    domyslnej wartosci byla swiadoma, a nie przypadkowa.
    """
    ports = resolve_ports(_args(["127.0.0.1"]), services)
    assert len(ports) == 100
    assert DEFAULT_TOP_PORTS == 100


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


# ---------------------------------------------------------------------------
# Wartosci idace prosto do pol naglowka pakietu
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["0", "256", "999", "-1", "abc"])
def test_ttl_outside_header_range_is_rejected(value):
    """--ttl 999 konczylo skan niezlapanym struct.error w srodku budowy pakietu."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--ttl", value, "127.0.0.1"])


@pytest.mark.parametrize("value", ["1", "64", "255"])
def test_valid_ttl_is_accepted(value):
    assert build_parser().parse_args(["--ttl", value, "127.0.0.1"]).ttl == int(value)


@pytest.mark.parametrize("value", ["65536", "99999", "-1", "abc"])
def test_source_port_outside_range_is_rejected(value):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["-g", value, "127.0.0.1"])


@pytest.mark.parametrize("value", ["0", "53", "65535"])
def test_valid_source_port_is_accepted(value):
    args = build_parser().parse_args(["-g", value, "127.0.0.1"])
    assert args.source_port == int(value)


@pytest.mark.parametrize("value", ["nie-ip", "999.1.1.1", "example.com", ""])
def test_invalid_source_ip_is_rejected(value):
    """-S nazwa konczylo skan OSError-em z inet_aton."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["-S", value, "127.0.0.1"])


@pytest.mark.parametrize("value", ["10.0.0.1", "127.0.0.1", "::1"])
def test_valid_source_ip_is_accepted(value):
    assert build_parser().parse_args(["-S", value, "127.0.0.1"]).source_ip == value


# ---------------------------------------------------------------------------
# Pusta sciezka wyjscia nie moze gubic raportu
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["-oN", "-oG", "-oJ"])
def test_empty_output_path_is_an_error(flag):
    """
    `-oJ ""` (np. z nierozwinietej zmiennej) bylo traktowane jak brak flagi:
    skan sie wykonywal, raport przepadal, kod wyjscia 0.
    """
    from pynmap.cli import main

    assert main(["-sT", "-p", "22", "-n", flag, "", "127.0.0.1"]) == 2


@pytest.mark.parametrize("flag", ["-oN", "-oG", "-oJ"])
def test_whitespace_output_path_is_an_error(flag):
    from pynmap.cli import main

    assert main(["-sT", "-p", "22", "-n", flag, "   ", "127.0.0.1"]) == 2


def test_real_output_path_still_works(tmp_path):
    from pynmap.cli import main

    out = tmp_path / "wynik.json"
    assert main(["-sT", "-p", "22", "-n", "-oJ", str(out), "127.0.0.1"]) == 0
    assert out.exists() and out.stat().st_size > 0


# ---------------------------------------------------------------------------
# --services: jawnie podany plik nie moze byc cicho ignorowany
# ---------------------------------------------------------------------------


def test_unreadable_explicit_services_file_is_an_error():
    """
    Literowka w --services dawala --top-ports N liczone z INNEJ bazy niz
    zamowiona, bez slowa ostrzezenia.
    """
    from pynmap.cli import main

    assert main(["-sT", "--services", "/nie/ma/takiego/pliku",
                 "--top-ports", "3", "-n", "127.0.0.1"]) == 2


def test_services_file_without_tcp_entries_is_an_error(tmp_path):
    bad = tmp_path / "pusty-services"
    bad.write_text("# tylko komentarz\nfoo\t53/udp\t0.5\n", encoding="utf-8")
    from pynmap.cli import main

    assert main(["-sT", "--services", str(bad),
                 "--top-ports", "3", "-n", "127.0.0.1"]) == 2
