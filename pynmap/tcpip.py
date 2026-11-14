"""
Budowanie i parsowanie nagłówków IPv4/TCP/ICMP — odpowiednik tcpip.cc
oraz libnetutil (build_tcp_raw(), readip_pcap(), ip_checksum()).

W nmapie to kilka tysięcy linii C z własnymi strukturami i rzutowaniem
wskaźników; w Pythonie wystarczy moduł `struct`. Różnica w objętości kodu
to jeden z głównych punktów porównania w docs/c-vs-python.md.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

from .constants import TcpFlags

IPPROTO_TCP = socket.IPPROTO_TCP
IPPROTO_ICMP = socket.IPPROTO_ICMP

IP_HEADER_LEN = 20
TCP_HEADER_LEN = 20
ICMP_HEADER_LEN = 8

# Linux oczekuje total_length w kolejności sieciowej przy IP_HDRINCL,
# klasyczne BSD (i macOS) — w kolejności hosta. Stąd ten przełącznik.
_BSD_LENGTH_QUIRK = os.uname().sysname in ("Darwin", "FreeBSD", "OpenBSD", "NetBSD") \
    if hasattr(os, "uname") else False


# ---------------------------------------------------------------------------
# Suma kontrolna (RFC 1071) — odpowiednik ip_checksum() z libnetutil
# ---------------------------------------------------------------------------


def checksum(data: bytes) -> int:
    """
    Standardowa suma kontrolna internetowa: suma 16-bitowych słów z
    zawijaniem przeniesień i dopełnieniem do jedynki.
    """
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for (word,) in struct.iter_unpack("!H", data):
        total += word

    # zwijanie przeniesień
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


# ---------------------------------------------------------------------------
# Budowanie pakietów
# ---------------------------------------------------------------------------


def build_ip_header(
    src_ip: str,
    dst_ip: str,
    payload_len: int,
    proto: int = IPPROTO_TCP,
    ttl: int = 64,
    ip_id: int | None = None,
    tos: int = 0,
    df: bool = False,
) -> bytes:
    """
    Składa 20-bajtowy nagłówek IPv4.

    Jądro przy IP_HDRINCL samo policzy sumę kontrolną IP i uzupełni adres
    źródłowy, jeśli zostawimy zera — ale liczymy ją sami, żeby kod był
    przenośny i żeby pokazać pełny obraz (nmap też liczy ją własnoręcznie).
    """
    version_ihl = (4 << 4) | (IP_HEADER_LEN // 4)
    total_length = IP_HEADER_LEN + payload_len
    if ip_id is None:
        ip_id = int.from_bytes(os.urandom(2), "big")
    frag_off = 0x4000 if df else 0  # bit DF

    length_field = socket.htons(total_length) if _BSD_LENGTH_QUIRK else total_length

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        length_field,
        ip_id,
        frag_off,
        ttl,
        proto,
        0,  # suma kontrolna - najpierw zero
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    csum = checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:]


def build_tcp_header(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int = 0,
    flags: TcpFlags | int = TcpFlags.SYN,
    window: int = 1024,
    options: bytes = b"",
    urgent: int = 0,
) -> bytes:
    """
    Składa nagłówek TCP wraz z sumą kontrolną liczoną po pseudo-nagłówku.

    Pseudo-nagłówek (src, dst, 0, proto, dł. TCP) nie jest wysyłany —
    wchodzi tylko do sumy kontrolnej. To klasyczna pułapka przy pisaniu
    raw socketów od zera.
    """
    if len(options) % 4:
        # dopełnienie opcji do wielokrotności 4 bajtów (NOP = 0x01, EOL = 0x00)
        options = options + b"\x00" * (4 - len(options) % 4)

    data_offset = (TCP_HEADER_LEN + len(options)) // 4
    offset_reserved = (data_offset << 4) | 0

    header = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_reserved,
        int(flags),
        window,
        0,  # suma kontrolna
        urgent,
    )

    segment = header + options
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        IPPROTO_TCP,
        len(segment),
    )
    csum = checksum(pseudo + segment)

    return header[:16] + struct.pack("!H", csum) + header[18:] + options


def build_mss_option(mss: int = 1460) -> bytes:
    """Opcja TCP MSS (kind=2, len=4). nmap dodaje ją do sond SYN."""
    return struct.pack("!BBH", 2, 4, mss)


def build_syn_probe(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    window: int = 1024,
    mss: int | None = 1460,
    ttl: int = 64,
    ip_id: int | None = None,
) -> bytes:
    """Gotowa sonda SYN: nagłówek IP + TCP SYN z opcją MSS."""
    options = build_mss_option(mss) if mss else b""
    tcp = build_tcp_header(
        src_ip=src_ip,
        dst_ip=dst_ip,
        sport=sport,
        dport=dport,
        seq=seq,
        flags=TcpFlags.SYN,
        window=window,
        options=options,
    )
    ip = build_ip_header(src_ip, dst_ip, len(tcp), IPPROTO_TCP, ttl=ttl, ip_id=ip_id)
    return ip + tcp


# ---------------------------------------------------------------------------
# Parsowanie pakietów
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IPHeader:
    version: int
    ihl: int
    tos: int
    total_length: int
    ip_id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    checksum: int
    src: str
    dst: str

    @property
    def header_len(self) -> int:
        return self.ihl * 4


@dataclass(frozen=True)
class TCPHeader:
    sport: int
    dport: int
    seq: int
    ack: int
    data_offset: int
    flags: TcpFlags
    window: int
    checksum: int
    urgent: int

    @property
    def header_len(self) -> int:
        return self.data_offset * 4


@dataclass(frozen=True)
class ICMPHeader:
    type: int
    code: int
    checksum: int
    rest: bytes


def parse_ip_header(data: bytes) -> IPHeader | None:
    if len(data) < IP_HEADER_LEN:
        return None

    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    if version != 4 or ihl < 5:
        return None

    (
        _vihl, tos, total_length, ip_id, flags_frag, ttl, proto, csum, src, dst
    ) = struct.unpack("!BBHHHBBH4s4s", data[:IP_HEADER_LEN])

    return IPHeader(
        version=version,
        ihl=ihl,
        tos=tos,
        total_length=total_length,
        ip_id=ip_id,
        flags=flags_frag >> 13,
        frag_offset=flags_frag & 0x1FFF,
        ttl=ttl,
        proto=proto,
        checksum=csum,
        src=socket.inet_ntoa(src),
        dst=socket.inet_ntoa(dst),
    )


def parse_tcp_header(data: bytes) -> TCPHeader | None:
    if len(data) < TCP_HEADER_LEN:
        return None

    (
        sport, dport, seq, ack, offset_reserved, flags, window, csum, urgent
    ) = struct.unpack("!HHIIBBHHH", data[:TCP_HEADER_LEN])

    return TCPHeader(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        data_offset=offset_reserved >> 4,
        flags=TcpFlags(flags),
        window=window,
        checksum=csum,
        urgent=urgent,
    )


def parse_icmp_header(data: bytes) -> ICMPHeader | None:
    if len(data) < ICMP_HEADER_LEN:
        return None
    icmp_type, code, csum = struct.unpack("!BBH", data[:4])
    return ICMPHeader(type=icmp_type, code=code, checksum=csum, rest=data[4:ICMP_HEADER_LEN])


def parse_icmp_quote(payload: bytes) -> tuple[IPHeader, TCPHeader] | None:
    """
    ICMP unreachable zawiera cytat z oryginalnego pakietu (nagłówek IP +
    pierwsze 8 bajtów danych). Wystarczy to, by dopasować odpowiedź do
    naszej sondy — nmap robi dokładnie to samo w readpacket/validate.

    Zwraca (IPHeader, TCPHeader) cytowanego pakietu albo None. Uwaga: z
    8 bajtów TCP znamy tylko porty i numer sekwencyjny, dlatego budujemy
    nagłówek z dopełnieniem zerami.
    """
    inner_ip = parse_ip_header(payload)
    if inner_ip is None:
        return None

    inner_start = inner_ip.header_len
    quoted = payload[inner_start:inner_start + 8]
    if len(quoted) < 8:
        return None

    sport, dport, seq = struct.unpack("!HHI", quoted)
    inner_tcp = TCPHeader(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=0,
        data_offset=5,
        flags=TcpFlags(0),
        window=0,
        checksum=0,
        urgent=0,
    )
    return inner_ip, inner_tcp


# ---------------------------------------------------------------------------
# Pomocnicze
# ---------------------------------------------------------------------------


def get_source_address(dst_ip: str) -> str:
    """
    Wyznacza adres źródłowy dla danego celu.

    Trik z connect() na UDP: nie wysyła żadnego pakietu, ale każe jądru
    wybrać trasę i przypisać lokalny adres. nmap robi to "porządnie",
    czytając tablicę routingu (routethrough.cc) — tu wystarczy to.
    """
    family = socket.AF_INET6 if ":" in dst_ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect((dst_ip, 9))
            return probe.getsockname()[0]
        except OSError:
            return "127.0.0.1" if family == socket.AF_INET else "::1"


def random_seq() -> int:
    """Losowy ISN. nmap używa własnego generatora z get_random_u32()."""
    return int.from_bytes(os.urandom(4), "big")


ICMP_UNREACH_FILTERED_CODES = frozenset({1, 2, 3, 9, 10, 13})
"""
Kody ICMP type 3, które nmap interpretuje jako 'filtered' przy SYN scan:
  1  host unreachable
  2  protocol unreachable
  3  port unreachable
  9  network administratively prohibited
  10 host administratively prohibited
  13 communication administratively prohibited
"""
