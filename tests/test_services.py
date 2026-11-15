"""
Testy bazy usług (odpowiednik nmap-services + gettoppts()).

Ten moduł nie miał dotąd żadnych testów, i właśnie dlatego przeszły przez
niego dwie dziury: porty z pliku zewnętrznego omijały walidację zakresu
(a potem wywracały skan OverflowError-em), a jawnie podany `--services`,
którego nie dało się odczytać, był cicho zamieniany na listę wbudowaną.
"""

import pytest

from pynmap.services import ServiceDB, ServiceDBError


def _write(tmp_path, text, name="nmap-services"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# Lista wbudowana
# ---------------------------------------------------------------------------


def test_builtin_is_used_when_nothing_is_given():
    db = ServiceDB(prefer_system=False)
    assert db.source == "builtin"
    assert db.service_name(80) == "http"
    assert db.port_for_name("ssh") == 22


def test_builtin_ports_are_all_in_range():
    db = ServiceDB(prefer_system=False)
    ports = db.top_ports(db.available_top_ports)
    assert ports == sorted(set(ports))
    assert all(1 <= p <= 65535 for p in ports)


def test_unknown_port_and_name():
    db = ServiceDB(prefer_system=False)
    assert db.service_name(64999) == "unknown"
    assert db.port_for_name("nie-ma-takiej-uslugi") is None


# ---------------------------------------------------------------------------
# Plik zewnętrzny: to jest wejście użytkownika
# ---------------------------------------------------------------------------


def test_ports_outside_range_are_skipped(tmp_path):
    """
    Port 0 i 99999 z pliku trafiały prosto do silnika, gdzie connect_ex()
    wywracał skan niezłapanym OverflowError-em w środku pętli skanowania.
    """
    path = _write(
        tmp_path,
        "zero\t0/tcp\t0.9\n"
        "huge\t99999/tcp\t0.8\n"
        "ok\t80/tcp\t0.7\n"
        "takze-ok\t443/tcp\t0.6\n",
    )
    db = ServiceDB(services_path=path)
    ports = db.top_ports(db.available_top_ports)
    assert ports == [80, 443]
    assert all(1 <= p <= 65535 for p in ports)


def test_frequencies_decide_order(tmp_path):
    path = _write(
        tmp_path,
        "rzadki\t1234/tcp\t0.001\n"
        "czesty\t80/tcp\t0.9\n"
        "sredni\t443/tcp\t0.5\n",
    )
    db = ServiceDB(services_path=path)
    # top_ports zwraca posortowane rosnąco, ale WYBIERA wg częstotliwości
    assert db.top_ports(1) == [80]
    assert db.top_ports(2) == [80, 443]


def test_udp_entries_are_ignored(tmp_path):
    path = _write(tmp_path, "dns\t53/udp\t0.9\nhttp\t80/tcp\t0.8\n")
    db = ServiceDB(services_path=path)
    assert db.top_ports(db.available_top_ports) == [80]


def test_malformed_lines_do_not_break_parsing(tmp_path):
    path = _write(
        tmp_path,
        "# komentarz\n"
        "\n"
        "bez-portu\n"
        "zly-freq\t80/tcp\tnie-liczba\n"
        "ok\t443/tcp\t0.5\n",
    )
    db = ServiceDB(services_path=path)
    assert set(db.top_ports(db.available_top_ports)) == {80, 443}


# ---------------------------------------------------------------------------
# Jawnie podany plik musi być błędem, gdy się nie udaje
# ---------------------------------------------------------------------------


def test_explicit_missing_file_raises():
    # Komunikat musi NAZWAC plik i powod — sam typ wyjatku nie odrozniał
    # "nie dalo sie odczytac" od "plik nie ma wpisow TCP", a to inne awarie.
    with pytest.raises(ServiceDBError, match="/nie/ma/takiego/pliku") as exc:
        ServiceDB(services_path="/nie/ma/takiego/pliku")
    assert "odczytać" in str(exc.value)


def test_explicit_file_without_tcp_entries_raises(tmp_path):
    path = _write(tmp_path, "# tylko komentarz\ndns\t53/udp\t0.9\n")
    with pytest.raises(ServiceDBError):
        ServiceDB(services_path=path)


def test_explicit_file_with_only_out_of_range_ports_raises(tmp_path):
    path = _write(tmp_path, "zero\t0/tcp\t0.9\nhuge\t70000/tcp\t0.8\n")
    with pytest.raises(ServiceDBError):
        ServiceDB(services_path=path)


def test_auto_discovery_failure_falls_back_quietly(monkeypatch):
    """
    Plik WYSZUKANY w systemie może nie istnieć — wtedy cicha zmiana na listę
    wbudowaną jest poprawna. Błędem jest tylko zignorowanie pliku podanego
    jawnie przez użytkownika.
    """
    monkeypatch.setattr(
        "pynmap.services.find_nmap_services", lambda: "/nie/ma/takiego/pliku"
    )
    db = ServiceDB()
    assert db.source == "builtin"


def test_top_ports_rejects_nonpositive_count():
    db = ServiceDB(prefer_system=False)
    with pytest.raises(ValueError):
        db.top_ports(0)
    with pytest.raises(ValueError):
        db.top_ports(-1)
