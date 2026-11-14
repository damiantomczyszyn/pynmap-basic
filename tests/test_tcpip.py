"""
Testy budowania i parsowania pakietów (odpowiednik tcpip.cc / libnetutil).

Najważniejsza własność sumy kontrolnej: policzona nad danymi, które już
zawierają poprawną sumę, musi dać 0. To ten sam test, który robi stos
sieciowy po odebraniu pakietu.
"""

import socket
import struct

from pynmap.constants import TcpFlags
from pynmap.tcpip import (
    IP_HEADER_LEN,
    build_ip_header,
    build_mss_option,
    build_syn_probe,
    build_tcp_header,
    checksum,
    get_source_address,
    parse_icmp_header,
    parse_icmp_quote,
    parse_ip_header,
    parse_tcp_header,
    random_seq,
)

# ---------------------------------------------------------------------------
# Suma kontrolna
# ---------------------------------------------------------------------------


def test_checksum_of_zeros():
    assert checksum(b"\x00\x00\x00\x00") == 0xFFFF


def test_checksum_handles_odd_length():
    # nie powinno rzucać — dopełniamy zerem
    assert 0 <= checksum(b"\x01\x02\x03") <= 0xFFFF


def test_checksum_verifies_to_zero():
    """
    Klasyczna weryfikacja: wstawiamy policzoną sumę w miejsce zer i
    liczymy ponownie — wynik musi być 0.
    """
    payload = b"\x45\x00\x00\x28\xab\xcd\x00\x00\x40\x06"
    csum = checksum(payload)
    assert checksum(payload + struct.pack("!H", csum)) == 0


# ---------------------------------------------------------------------------
# Nagłówek IP
# ---------------------------------------------------------------------------


def test_ip_header_length_and_roundtrip():
    raw = build_ip_header("10.0.0.1", "10.0.0.2", payload_len=20, ttl=64)
    assert len(raw) == IP_HEADER_LEN

    ip = parse_ip_header(raw)
    assert ip is not None
    assert ip.version == 4
    assert ip.ihl == 5
    assert ip.header_len == 20
    assert ip.src == "10.0.0.1"
    assert ip.dst == "10.0.0.2"
    assert ip.ttl == 64
    assert ip.proto == socket.IPPROTO_TCP


def test_ip_header_checksum_is_valid():
    raw = build_ip_header("192.168.0.10", "192.168.0.20", payload_len=24)
    assert checksum(raw) == 0


def test_ip_header_df_bit():
    raw = build_ip_header("10.0.0.1", "10.0.0.2", payload_len=20, df=True)
    ip = parse_ip_header(raw)
    assert ip.flags & 0b010  # DF


def test_ip_header_respects_explicit_id():
    raw = build_ip_header("10.0.0.1", "10.0.0.2", payload_len=20, ip_id=0x1234)
    assert parse_ip_header(raw).ip_id == 0x1234


def test_parse_ip_rejects_short_and_nonv4():
    assert parse_ip_header(b"\x45\x00") is None
    assert parse_ip_header(b"\x60" + b"\x00" * 19) is None  # wersja 6


# ---------------------------------------------------------------------------
# Nagłówek TCP
# ---------------------------------------------------------------------------


def test_tcp_header_roundtrip():
    raw = build_tcp_header(
        "10.0.0.1", "10.0.0.2",
        sport=40000, dport=443, seq=0xDEADBEEF,
        flags=TcpFlags.SYN, window=1024,
    )
    tcp = parse_tcp_header(raw)
    assert tcp.sport == 40000
    assert tcp.dport == 443
    assert tcp.seq == 0xDEADBEEF
    assert tcp.flags == TcpFlags.SYN
    assert tcp.window == 1024
    assert tcp.data_offset == 5
    assert tcp.header_len == 20


def test_tcp_checksum_covers_pseudo_header():
    """
    Suma TCP liczona jest po pseudo-nagłówku. Weryfikujemy tak, jak robi
    to odbiorca: pseudo-nagłówek + segment => 0.
    """
    src, dst = "10.0.0.1", "10.0.0.2"
    segment = build_tcp_header(src, dst, 40000, 80, seq=1, flags=TcpFlags.SYN)

    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src), socket.inet_aton(dst),
        0, socket.IPPROTO_TCP, len(segment),
    )
    assert checksum(pseudo + segment) == 0


def test_tcp_checksum_changes_with_addresses():
    a = build_tcp_header("10.0.0.1", "10.0.0.2", 40000, 80, seq=1)
    b = build_tcp_header("10.0.0.1", "10.0.0.3", 40000, 80, seq=1)
    assert parse_tcp_header(a).checksum != parse_tcp_header(b).checksum


def test_mss_option_layout():
    opt = build_mss_option(1460)
    assert opt == struct.pack("!BBH", 2, 4, 1460)
    assert len(opt) == 4


def test_options_bump_data_offset():
    raw = build_tcp_header(
        "10.0.0.1", "10.0.0.2", 40000, 80, seq=1,
        options=build_mss_option(1460),
    )
    tcp = parse_tcp_header(raw)
    assert tcp.data_offset == 6      # 24 bajty / 4
    assert tcp.header_len == 24
    assert len(raw) == 24


def test_options_are_padded_to_4_bytes():
    raw = build_tcp_header(
        "10.0.0.1", "10.0.0.2", 40000, 80, seq=1, options=b"\x01\x01\x01"
    )
    assert len(raw) % 4 == 0


def test_flags_to_str():
    assert (TcpFlags.SYN | TcpFlags.ACK).to_str() == "SA"
    assert TcpFlags.RST.to_str() == "R"
    assert TcpFlags(0).to_str() == "-"


# ---------------------------------------------------------------------------
# Pełna sonda SYN
# ---------------------------------------------------------------------------


def test_syn_probe_structure():
    packet = build_syn_probe(
        "10.0.0.1", "10.0.0.2", sport=40000, dport=22, seq=12345
    )
    assert len(packet) == 20 + 24  # IP + TCP z opcją MSS

    ip = parse_ip_header(packet)
    assert ip.total_length in (44, socket.htons(44))

    tcp = parse_tcp_header(packet[ip.header_len:])
    assert tcp.flags == TcpFlags.SYN
    assert tcp.dport == 22
    assert tcp.seq == 12345
    assert tcp.window == 1024


def test_syn_probe_without_mss():
    packet = build_syn_probe(
        "10.0.0.1", "10.0.0.2", sport=40000, dport=22, seq=1, mss=None
    )
    assert len(packet) == 40


# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------


def test_parse_icmp_header():
    raw = struct.pack("!BBH", 3, 3, 0) + b"\x00" * 4
    icmp = parse_icmp_header(raw)
    assert icmp.type == 3 and icmp.code == 3


def test_parse_icmp_quote_recovers_ports():
    """
    ICMP unreachable cytuje nagłówek IP + 8 bajtów danych. Z tych 8 bajtów
    odzyskujemy porty i numer sekwencyjny naszej sondy.
    """
    inner_ip = build_ip_header("10.0.0.1", "10.0.0.2", payload_len=20)
    inner_tcp_8b = struct.pack("!HHI", 40000, 22, 999)

    quote = parse_icmp_quote(inner_ip + inner_tcp_8b)
    assert quote is not None

    ip, tcp = quote
    assert ip.src == "10.0.0.1"
    assert ip.dst == "10.0.0.2"
    assert tcp.sport == 40000
    assert tcp.dport == 22
    assert tcp.seq == 999


def test_parse_icmp_quote_rejects_truncated():
    inner_ip = build_ip_header("10.0.0.1", "10.0.0.2", payload_len=20)
    assert parse_icmp_quote(inner_ip + b"\x00\x01") is None


# ---------------------------------------------------------------------------
# Pomocnicze
# ---------------------------------------------------------------------------


def test_get_source_address_for_loopback():
    assert get_source_address("127.0.0.1") == "127.0.0.1"


def test_random_seq_in_range_and_varies():
    values = {random_seq() for _ in range(50)}
    assert all(0 <= v <= 0xFFFFFFFF for v in values)
    assert len(values) > 40  # losowe, więc praktycznie bez kolizji
