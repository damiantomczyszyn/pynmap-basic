"""
Nazwy usług i lista "top ports" — odpowiednik nmap-services + gettoppts().

UWAGA LICENCYJNA
----------------
Plik nmap-services (z częstotliwościami występowania portów) jest częścią
nmapa i objęty jego licencją — NIE jest tu kopiowany. Mamy zamiast tego:

1. własną, wbudowaną listę dobrze znanych portów (przypisania IANA +
   typowe porty aplikacyjne), uporządkowaną wg praktycznej częstotliwości;
2. opcjonalne wczytanie prawdziwego nmap-services z systemu, jeśli nmap
   jest zainstalowany — wtedy --top-ports działa 1:1 jak w nmapie.

Format nmap-services:  nazwa<TAB>port/proto<TAB>częstotliwość<TAB># komentarz
"""

from __future__ import annotations

import os
from functools import lru_cache

# Kolejność ma znaczenie: --top-ports N bierze N pierwszych.
# To autorska lista (nie dane nmapa) oparta o typowe ekspozycje usług.
_BUILTIN_TOP_TCP: tuple[tuple[int, str], ...] = (
    (80, "http"), (443, "https"), (22, "ssh"), (21, "ftp"), (25, "smtp"),
    (3389, "ms-wbt-server"), (110, "pop3"), (445, "microsoft-ds"),
    (139, "netbios-ssn"), (143, "imap"), (53, "domain"), (135, "msrpc"),
    (3306, "mysql"), (8080, "http-proxy"), (23, "telnet"), (993, "imaps"),
    (995, "pop3s"), (5432, "postgresql"), (1723, "pptp"), (111, "rpcbind"),
    (5900, "vnc"), (587, "submission"), (8443, "https-alt"), (8888, "sun-answerbook"),
    (1433, "ms-sql-s"), (6379, "redis"), (27017, "mongod"), (9200, "elasticsearch"),
    (161, "snmp"), (389, "ldap"), (636, "ldapaps"), (88, "kerberos-sec"),
    (464, "kpasswd5"), (3268, "globalcatLDAP"), (3269, "globalcatLDAPssl"),
    (5985, "wsman"), (5986, "wsmans"), (1521, "oracle"), (2049, "nfs"),
    (2375, "docker"), (2376, "docker-s"), (6443, "kubernetes-api"),
    (10250, "kubelet"), (2379, "etcd-client"), (2380, "etcd-server"),
    (5601, "kibana"), (15672, "rabbitmq-mgmt"), (5672, "amqp"),
    (9092, "kafka"), (11211, "memcached"), (1883, "mqtt"), (8883, "mqtts"),
    (502, "modbus"), (102, "iso-tsap"), (20000, "dnp3"), (44818, "EtherNetIP-2"),
    (47808, "bacnet"), (548, "afp"), (631, "ipp"), (9100, "jetdirect"),
    (515, "printer"), (69, "tftp"), (123, "ntp"), (137, "netbios-ns"),
    (138, "netbios-dgm"), (514, "shell"), (513, "login"), (512, "exec"),
    (79, "finger"), (119, "nntp"), (563, "snews"), (194, "irc"),
    (6667, "irc"), (5060, "sip"), (5061, "sips"), (1720, "h323q931"),
    (3478, "stun"), (1194, "openvpn"), (500, "isakmp"), (4500, "ipsec-nat-t"),
    (1701, "l2tp"), (51820, "wireguard"), (179, "bgp"), (520, "route"),
    (2000, "cisco-sccp"), (4786, "smart-install"), (8291, "mikrotik-winbox"),
    (8728, "mikrotik-api"), (7547, "cwmp"), (37777, "dahua-dvr"),
    (554, "rtsp"), (8554, "rtsp-alt"), (1900, "upnp"), (5353, "mdns"),
    (32400, "plex"), (8096, "jellyfin"), (9000, "cslistener"),
    (3000, "ppp"), (5000, "upnp-http"), (8000, "http-alt"), (8081, "blackice-icecap"),
    (8008, "http"), (8009, "ajp13"), (7001, "weblogic"), (4848, "appserv-http"),
    (9090, "zeus-admin"), (10000, "snet-sensor-mgmt"), (20547, "proxmox-spice"),
    (8006, "proxmox-web"), (9443, "portainer"), (1234, "hotline"),
    (4444, "krb524"), (4445, "upnotifyp"), (31337, "Elite"), (12345, "netbus"),
    (5555, "freeciv"), (7777, "cbt"), (6666, "irc"), (1337, "waste"),
    (49152, "msrpc-dyn"), (49153, "msrpc-dyn"), (49154, "msrpc-dyn"),
    (49155, "msrpc-dyn"), (49156, "msrpc-dyn"), (49157, "msrpc-dyn"),
    (1025, "NFS-or-IIS"), (1026, "LSA-or-nterm"), (1027, "IIS"),
    (1028, "unknown"), (1029, "ms-lsa"), (1110, "nfsd-status"),
    (2121, "ccproxy-ftp"), (2717, "pn-requester"), (3986, "mapper-ws_ethd"),
    (5101, "admdog"), (5190, "aol"), (5357, "wsdapi"), (5800, "vnc-http"),
    (5801, "vnc-http-1"), (6000, "X11"), (6001, "X11:1"), (6002, "X11:2"),
    (6646, "unknown"), (7070, "realserver"), (8031, "unknown"),
    (8180, "unknown"), (8192, "sophos"), (8200, "trivnet1"),
    (8300, "tmi"), (8400, "cvd"), (8500, "fmtp"), (8649, "unknown"),
    (8651, "unknown"), (8652, "unknown"), (9001, "tor-orport"),
    (9030, "tor-dirport"), (9050, "tor-socks"), (9051, "tor-control"),
    (9535, "man"), (9999, "abyss"), (16992, "amt-soap-http"),
    (16993, "amt-soap-https"), (17988, "unknown"), (30000, "ndmps"),
    (32768, "filenet-tms"), (49999, "unknown"), (55555, "unknown"),
    (1099, "rmiregistry"), (4369, "epmd"), (5984, "couchdb"),
    (7474, "neo4j"), (8086, "influxdb"), (9042, "cassandra"),
    (9160, "cassandra-thrift"), (11214, "memcached-ssl"), (26257, "cockroachdb"),
)


@lru_cache(maxsize=1)
def _builtin_tables() -> tuple[dict[int, str], dict[str, int], list[int]]:
    port_to_name: dict[int, str] = {}
    name_to_port: dict[str, int] = {}
    order: list[int] = []
    for port, name in _BUILTIN_TOP_TCP:
        order.append(port)
        port_to_name.setdefault(port, name)
        name_to_port.setdefault(name.lower(), port)
    return port_to_name, name_to_port, order


# Typowe lokalizacje nmap-services na Linuksie/macOS/Windows.
_NMAP_SERVICES_PATHS = (
    "/usr/share/nmap/nmap-services",
    "/usr/local/share/nmap/nmap-services",
    "/opt/homebrew/share/nmap/nmap-services",
    "/opt/local/share/nmap/nmap-services",
    r"C:\Program Files (x86)\Nmap\nmap-services",
    r"C:\Program Files\Nmap\nmap-services",
)


def find_nmap_services() -> str | None:
    """Zwraca ścieżkę do systemowego nmap-services albo None."""
    env = os.environ.get("PYNMAP_SERVICES")
    if env and os.path.isfile(env):
        return env
    for path in _NMAP_SERVICES_PATHS:
        if os.path.isfile(path):
            return path
    return None


@lru_cache(maxsize=4)
def _load_nmap_services(path: str) -> tuple[dict[int, str], dict[str, int], tuple[int, ...]]:
    """
    Czyta nmap-services i zwraca (port->nazwa, nazwa->port, porty wg częstotliwości).

    Parsujemy tylko wiersze TCP. Format kolumn jest stabilny od lat.
    """
    port_to_name: dict[int, str] = {}
    name_to_port: dict[str, int] = {}
    freqs: list[tuple[float, int]] = []

    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) < 2:
                fields = line.split()
                if len(fields) < 2:
                    continue
            name = fields[0].strip()
            port_proto = fields[1].strip()
            if "/" not in port_proto:
                continue
            port_s, _, proto = port_proto.partition("/")
            if proto.strip().lower() != "tcp" or not port_s.isdigit():
                continue
            port = int(port_s)

            freq = 0.0
            if len(fields) >= 3:
                try:
                    freq = float(fields[2].strip())
                except ValueError:
                    freq = 0.0

            port_to_name.setdefault(port, name)
            name_to_port.setdefault(name.lower(), port)
            freqs.append((freq, port))

    freqs.sort(key=lambda item: (-item[0], item[1]))
    return port_to_name, name_to_port, tuple(port for _freq, port in freqs)


class ServiceDB:
    """
    Baza usług. Preferuje systemowy nmap-services, w razie braku używa
    wbudowanej listy.
    """

    def __init__(self, services_path: str | None = None, prefer_system: bool = True):
        self.source = "builtin"
        self._port_to_name: dict[int, str]
        self._name_to_port: dict[str, int]
        self._ranked: list[int]

        path = services_path or (find_nmap_services() if prefer_system else None)
        if path:
            try:
                p2n, n2p, ranked = _load_nmap_services(path)
                if ranked:
                    self._port_to_name = p2n
                    self._name_to_port = n2p
                    self._ranked = list(ranked)
                    self.source = path
                    return
            except OSError:
                pass

        p2n, n2p, order = _builtin_tables()
        self._port_to_name = dict(p2n)
        self._name_to_port = dict(n2p)
        self._ranked = list(order)

    def service_name(self, port: int) -> str:
        return self._port_to_name.get(port, "unknown")

    def port_for_name(self, name: str) -> int | None:
        return self._name_to_port.get(name.strip().lower())

    def top_ports(self, count: int) -> list[int]:
        """
        Odpowiednik gettoppts() / --top-ports.

        Zwraca posortowane rosnąco numery portów (nmap też je potem
        porządkuje, a losowanie kolejności robi osobno).
        """
        if count <= 0:
            raise ValueError("--top-ports wymaga liczby > 0")
        selected = self._ranked[:count]
        if not selected:
            raise ValueError("Baza usług jest pusta")
        return sorted(set(selected))

    @property
    def available_top_ports(self) -> int:
        return len(self._ranked)
