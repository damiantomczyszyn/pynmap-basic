"""Testy rozwijania specyfikacji celów (odpowiednik TargetGroup.cc)."""

import socket

import pytest

from pynmap.targets import TargetSpecError, expand_spec, expand_specs


def ips(spec):
    return [t.ip for t in expand_spec(spec, resolve=False)]


def test_single_ipv4():
    assert ips("192.168.1.1") == ["192.168.1.1"]


def test_cidr_24_skips_network_and_broadcast():
    result = ips("192.168.1.0/24")
    assert len(result) == 254
    assert "192.168.1.0" not in result
    assert "192.168.1.255" not in result
    assert result[0] == "192.168.1.1"


def test_cidr_32_includes_the_single_address():
    assert ips("10.0.0.5/32") == ["10.0.0.5"]


def test_cidr_31_includes_both():
    assert ips("10.0.0.0/31") == ["10.0.0.0", "10.0.0.1"]


def test_octet_range():
    assert ips("10.0.0.1-4") == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]


def test_octet_list():
    assert ips("10.0.0.1,5,9") == ["10.0.0.1", "10.0.0.5", "10.0.0.9"]


def test_multi_octet_ranges():
    result = ips("10.0.1-2.1-2")
    assert result == ["10.0.1.1", "10.0.1.2", "10.0.2.1", "10.0.2.2"]


def test_wildcard_octet():
    assert len(ips("10.0.0.*")) == 256


def test_ipv6_literal():
    targets = list(expand_spec("2001:db8::1", resolve=False))
    assert len(targets) == 1
    assert targets[0].family == socket.AF_INET6
    assert targets[0].is_ipv6


@pytest.mark.parametrize("bad", ["10.0.0.300", "10.0.0.5-1", "10.0.0.0/33", "10.0.0.a"])
def test_rejects_bad_specs(bad):
    with pytest.raises(TargetSpecError):
        list(expand_spec(bad, resolve=False))


def test_expand_specs_dedupes():
    result = expand_specs(["10.0.0.1", "10.0.0.1", "10.0.0.2"], resolve=False)
    assert [t.ip for t in result] == ["10.0.0.1", "10.0.0.2"]


def test_exclude_single_ip():
    result = expand_specs(["10.0.0.1-3"], resolve=False, exclude=["10.0.0.2"])
    assert [t.ip for t in result] == ["10.0.0.1", "10.0.0.3"]


def test_exclude_cidr():
    result = expand_specs(
        ["10.0.0.0/29"], resolve=False, exclude=["10.0.0.0/30"]
    )
    assert all(not ip.endswith((".1", ".2", ".3")) for ip in [t.ip for t in result])
    assert "10.0.0.5" in [t.ip for t in result]


def test_localhost_resolves():
    targets = list(expand_spec("localhost", resolve=False))
    assert targets
    assert any(t.ip in ("127.0.0.1", "::1") for t in targets)
    assert targets[0].hostname == "localhost"


def test_display_name_with_hostname():
    targets = list(expand_spec("localhost", resolve=False))
    name = targets[0].display_name
    assert "localhost" in name and "(" in name
