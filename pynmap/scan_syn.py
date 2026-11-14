"""
SYN scan (-sS) — odpowiednik scan_engine_raw.cc (podzbiór dla TCP).

Idea "half-open scan": wysyłamy SYN, czytamy odpowiedź i NIE kończymy
handshake'u. Stąd:

    SYN/ACK                     -> open      (ER_SYNACK)
    RST                         -> closed    (ER_RESETPEER)
    ICMP type 3 code 1,2,3,9,10,13 -> filtered
    ICMP type 11 (time exceeded)   -> filtered
    brak odpowiedzi po N próbach   -> filtered  (ER_NORESPONSE)

Różnice wobec nmapa:
  * nmap czyta pakiety przez libpcap z filtrem BPF; my używamy surowych
    socketów AF_INET/SOCK_RAW i filtrujemy w Pythonie. Dla skanu "basic"
    to wystarcza, ale przy dużym ruchu BPF jest nieporównywalnie tańszy,
    bo odsiewa pakiety w jądrze.
  * nmap potrafi wysyłać ramki ethernetowe (eth_send) i obsługuje ARP;
    my zostajemy na warstwie IP.

Wymaga CAP_NET_RAW (praktycznie: roota).
"""

from __future__ import annotations

import errno
import os
import selectors
import socket
import time

from .constants import SYN_PROBE_MSS, SYN_PROBE_WINDOW, PortState, Reason, ScanType, TcpFlags
from .engine import (
    HostReport,
    HostScanStats,
    Probe,
    ScanOptions,
    pick_source_port,
)
from .ports import PortList
from .targets import Target
from .tcpip import (
    ICMP_UNREACH_FILTERED_CODES,
    build_syn_probe,
    get_source_address,
    parse_icmp_header,
    parse_icmp_quote,
    parse_ip_header,
    parse_tcp_header,
    random_seq,
)
from .timing import ScanPerformanceVars, UltraTimingVals

RECV_BUFSIZE = 65535


class RawSocketError(RuntimeError):
    """Brak uprawnień lub wsparcia dla surowych socketów."""


class SynScanner:
    """
    Silnik SYN scanu.

    Trzy sockety: jeden do wysyłania (IPPROTO_RAW + IP_HDRINCL), dwa do
    odbioru (IPPROTO_TCP i IPPROTO_ICMP). Pętla główna ma ten sam kształt
    co w connect scanie: timeouty -> wysyłka -> odbiór.
    """

    def __init__(self, opts: ScanOptions, perf: ScanPerformanceVars | None = None):
        self.opts = opts
        self.perf = perf or opts.build_perf()
        self.source_port = pick_source_port(opts.source_port)
        self.group_timing = UltraTimingVals.init_for(self.perf, group=True)

        self._send_sock: socket.socket | None = None
        self._tcp_sock: socket.socket | None = None
        self._icmp_sock: socket.socket | None = None
        self._selector = selectors.DefaultSelector()

        # (ip, port) -> (HostScanStats, Probe)
        self._outstanding: dict[tuple[str, int], tuple[HostScanStats, Probe]] = {}

    # -- cykl życia ---------------------------------------------------------

    def _open_sockets(self) -> None:
        try:
            self._send_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
            )
            self._send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            self._tcp_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
            self._tcp_sock.setblocking(False)

            self._icmp_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            self._icmp_sock.setblocking(False)
        except PermissionError as exc:
            self._close_sockets()
            raise RawSocketError(
                "SYN scan (-sS) wymaga uprawnień do surowych socketów (CAP_NET_RAW). "
                "Uruchom jako root albo nadaj: "
                "sudo setcap cap_net_raw+ep $(readlink -f $(which python3)). "
                "Alternatywa bez roota: -sT (connect scan)."
            ) from exc
        except OSError as exc:
            self._close_sockets()
            if exc.errno in (errno.EPERM, errno.EACCES):
                raise RawSocketError(
                    "Brak uprawnień do surowych socketów — użyj -sT albo uruchom jako root."
                ) from exc
            raise RawSocketError(f"Nie udało się otworzyć surowych socketów: {exc}") from exc

        # powiększamy bufor odbiorczy — przy szybkim skanie łatwo go przepełnić
        for sock in (self._tcp_sock, self._icmp_sock):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
            except OSError:
                pass

        self._selector.register(self._tcp_sock, selectors.EVENT_READ, "tcp")
        self._selector.register(self._icmp_sock, selectors.EVENT_READ, "icmp")

    def _close_sockets(self) -> None:
        for sock in (self._tcp_sock, self._icmp_sock):
            if sock is None:
                continue
            try:
                self._selector.unregister(sock)
            except (KeyError, ValueError, OSError):
                pass
        for sock in (self._send_sock, self._tcp_sock, self._icmp_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._send_sock = self._tcp_sock = self._icmp_sock = None
        try:
            self._selector.close()
        except OSError:
            pass

    # -- API ----------------------------------------------------------------

    def scan(self, targets: list[Target]) -> list[HostReport]:
        ipv4_targets = [t for t in targets if not t.is_ipv6]
        skipped = [t for t in targets if t.is_ipv6]

        self._open_sockets()
        reports: list[HostReport] = []

        try:
            now = time.monotonic()
            hosts = [
                HostScanStats(t, self.opts, self.perf, now=now) for t in ipv4_targets
            ]
            for host in hosts:
                host.source_ip = self.opts.source_ip or get_source_address(
                    host.target.ip
                )

            incomplete = list(hosts)
            while incomplete:
                now = time.monotonic()

                self._handle_timeouts(incomplete, now)
                self._send_new_probes(incomplete, now)
                self._receive_replies(incomplete)

                finished = [h for h in incomplete if h.completed() or h.timed_out]
                for host in finished:
                    host.finalize()
                    reports.append(self._build_report(host))
                    incomplete.remove(host)
        finally:
            self._close_sockets()

        for target in skipped:
            # IPv6 w wersji basic obsługujemy tylko w -sT
            reports.append(
                HostReport(
                    target=target,
                    portlist=PortList(),
                    scanned_ports=[],
                    elapsed_s=0.0,
                    probes_sent=0,
                    replies_received=0,
                    host_up=False,
                )
            )

        order = {id(t): i for i, t in enumerate(targets)}
        reports.sort(key=lambda r: order.get(id(r.target), 0))
        return reports

    # -- faza 1: timeouty ---------------------------------------------------

    def _handle_timeouts(self, hosts: list[HostScanStats], now: float) -> None:
        for host in hosts:
            if host.host_timed_out(now):
                for probe in list(host.outstanding.values()):
                    self._outstanding.pop((host.target.ip, probe.port), None)
                host.abandon_outstanding()
                host.timed_out = True
                continue

            for probe in host.expired_probes(now):
                self._outstanding.pop((host.target.ip, probe.port), None)
                host.register_timeout(probe, now)
                self.group_timing.drop_group(len(self._outstanding) + 1, self.perf, now)

    # -- faza 2: wysyłanie --------------------------------------------------

    def _send_new_probes(self, hosts: list[HostScanStats], now: float) -> None:
        progress = True
        while progress:
            progress = False
            for host in hosts:
                if host.timed_out or not host.send_ok(now):
                    continue

                port = host.next_port()
                if port is None:
                    continue

                if self._send_syn(host, port, now):
                    progress = True
                now = time.monotonic()

    def _send_syn(self, host: HostScanStats, port: int, now: float) -> bool:
        tryno = host.tryno_by_port.get(port, 0)
        seq = random_seq()
        src_ip = host.source_ip or get_source_address(host.target.ip)

        packet = build_syn_probe(
            src_ip=src_ip,
            dst_ip=host.target.ip,
            sport=self.source_port,
            dport=port,
            seq=seq,
            window=SYN_PROBE_WINDOW,
            mss=SYN_PROBE_MSS,
            ttl=self.opts.ttl,
            ip_id=int.from_bytes(os.urandom(2), "big"),
        )

        try:
            self._send_sock.sendto(packet, (host.target.ip, 0))
        except OSError as exc:
            if exc.errno in (errno.ENOBUFS, errno.EAGAIN, errno.EWOULDBLOCK):
                # bufor nadawczy pełny — port wraca do kolejki
                host.ports_todo.appendleft(port)
                return False
            if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                host.portlist.set_state(
                    port, PortState.FILTERED,
                    reason=Reason.HOSTUNREACH if exc.errno == errno.EHOSTUNREACH
                    else Reason.NETUNREACH,
                )
                return True
            raise

        probe = Probe(
            port=port,
            tryno=tryno,
            sent_at=now,
            timeout_at=now + host.probe_timeout_s(),
            seq=seq,
            sport=self.source_port,
        )
        host.register_sent(probe, now)
        self._outstanding[(host.target.ip, port)] = (host, probe)
        return True

    # -- faza 3: odbiór -----------------------------------------------------

    def _receive_replies(self, hosts: list[HostScanStats]) -> None:
        timeout = self._select_timeout(hosts)
        events = self._selector.select(timeout)

        if not events and timeout == 0.0 and not self._outstanding:
            return

        for key, _mask in events:
            kind = key.data
            sock = key.fileobj
            # drenujemy socket do końca — raw socket zbiera cały ruch danego protokołu
            while True:
                try:
                    data = sock.recv(RECV_BUFSIZE)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                if not data:
                    break

                now = time.monotonic()
                if kind == "tcp":
                    self._handle_tcp_packet(data, now)
                else:
                    self._handle_icmp_packet(data, now)

    def _handle_tcp_packet(self, data: bytes, now: float) -> None:
        ip = parse_ip_header(data)
        if ip is None or ip.proto != socket.IPPROTO_TCP:
            return

        tcp = parse_tcp_header(data[ip.header_len:])
        if tcp is None:
            return

        # Odpowiedź na naszą sondę: jej port źródłowy = nasz port docelowy,
        # a port docelowy = nasz port źródłowy.
        if tcp.dport != self.source_port:
            return

        entry = self._outstanding.get((ip.src, tcp.sport))
        if entry is None:
            return

        host, probe = entry

        # Walidacja: ACK musi potwierdzać nasz ISN+1 (nmap robi to samo).
        # Surowy socket odbiera cały ruch TCP wchodzący na maszynę, więc bez
        # tego sprawdzenia cudze połączenie mogłoby zostać policzone jako
        # odpowiedź na naszą sondę.
        if (
            probe.seq is not None
            and tcp.flags & TcpFlags.ACK
            and tcp.ack != ((probe.seq + 1) & 0xFFFFFFFF)
        ):
            return

        if (tcp.flags & (TcpFlags.SYN | TcpFlags.ACK)) == (TcpFlags.SYN | TcpFlags.ACK):
            state, reason = PortState.OPEN, Reason.SYNACK
        elif tcp.flags & TcpFlags.RST:
            state, reason = PortState.CLOSED, Reason.RESETPEER
        elif tcp.flags & TcpFlags.SYN:
            # SYN bez ACK: spotykane przy skanowaniu samego siebie
            state, reason = PortState.OPEN, Reason.SYNACK
        else:
            return

        self._outstanding.pop((ip.src, tcp.sport), None)
        host.register_reply(probe, state, reason, now, reason_ttl=ip.ttl)
        self.group_timing.ack(self.perf)

        # Nie wysyłamy RST ręcznie: nasz port źródłowy nie jest zabindowany,
        # więc jądro samo odpowie RST-em i półotwarte połączenie zniknie.
        # To jest dokładnie to, na czym opiera się nmap.

    def _handle_icmp_packet(self, data: bytes, now: float) -> None:
        ip = parse_ip_header(data)
        if ip is None or ip.proto != socket.IPPROTO_ICMP:
            return

        icmp = parse_icmp_header(data[ip.header_len:])
        if icmp is None:
            return

        if icmp.type == 3:
            if icmp.code not in ICMP_UNREACH_FILTERED_CODES:
                return
            reason = {
                1: Reason.HOSTUNREACH,
                2: Reason.PROTOUNREACH,
                3: Reason.PORTUNREACH,
                9: Reason.ADMINPROHIBITED,
                10: Reason.ADMINPROHIBITED,
                13: Reason.ADMINPROHIBITED,
            }[icmp.code]
        elif icmp.type == 11:
            reason = Reason.TIMEEXCEEDED
        else:
            return

        quote = parse_icmp_quote(data[ip.header_len + 8:])
        if quote is None:
            return

        inner_ip, inner_tcp = quote
        if inner_tcp.sport != self.source_port:
            return

        entry = self._outstanding.get((inner_ip.dst, inner_tcp.dport))
        if entry is None:
            return

        host, probe = entry
        self._outstanding.pop((inner_ip.dst, inner_tcp.dport), None)
        host.register_reply(
            probe, PortState.FILTERED, reason, now, reason_ttl=ip.ttl
        )
        self.group_timing.ack(self.perf)

    def _select_timeout(self, hosts: list[HostScanStats]) -> float:
        now = time.monotonic()
        soonest = None
        for host in hosts:
            for probe in host.outstanding.values():
                if soonest is None or probe.timeout_at < soonest:
                    soonest = probe.timeout_at

        if soonest is None:
            return 0.0 if any(h.work_left() for h in hosts) else 0.01
        return max(0.0, min(soonest - now, 0.1))

    def _build_report(self, host: HostScanStats) -> HostReport:
        return HostReport(
            target=host.target,
            portlist=host.portlist,
            scanned_ports=host.scanned_ports,
            elapsed_s=time.monotonic() - host.start_time,
            probes_sent=host.probes_sent,
            replies_received=host.replies_received,
            timed_out=host.timed_out,
        )


def syn_scan(targets: list[Target], opts: ScanOptions) -> list[HostReport]:
    """Wygodny wrapper dla SYN scanu."""
    opts.scan_type = ScanType.SYN
    return SynScanner(opts).scan(targets)
