"""
Parsowanie specyfikacji celów — odpowiednik TargetGroup.cc / targets.cc.

Obsługiwane formaty (jak w nmapie):
  192.168.1.1            - pojedynczy host
  scanme.nmap.org        - nazwa DNS
  192.168.1.0/24         - notacja CIDR
  192.168.1.1-50         - zakres w ostatnim oktecie
  10.0.0-2.1-5           - zakresy w wielu oktetach
  192.168.1.1,5,9        - lista wartości w oktecie
  2001:db8::1            - IPv6 (tylko pojedynczy adres / CIDR)

nmap trzyma to w klasie TargetGroup z osobnymi tablicami bitowymi na oktet;
tutaj generujemy leniwie przez itertools.product, co w Pythonie jest
czytelniejsze i tańsze w kodzie.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from dataclasses import dataclass, field
from itertools import product


class TargetSpecError(ValueError):
    """Niepoprawna specyfikacja celu."""


@dataclass
class Target:
    """
    Jeden cel skanowania — odpowiednik klasy Target z Target.cc.

    nmapowy Target trzyma też MAC-e, trasę, interfejs i wyniki OS detection;
    w wersji basic ograniczamy się do adresu, nazwy i powodu stanu hosta.
    """

    ip: str
    hostname: str | None = None
    family: int = socket.AF_INET
    reverse_dns: str | None = None
    _ports: dict = field(default_factory=dict, repr=False)

    @property
    def display_name(self) -> str:
        """Jak nmap pokazuje cel w nagłówku raportu."""
        label = self.hostname or self.reverse_dns
        if label and label != self.ip:
            return f"{label} ({self.ip})"
        return self.ip

    @property
    def is_ipv6(self) -> bool:
        return self.family == socket.AF_INET6


def _expand_octet(part: str, octet_index: int) -> list[int]:
    """
    Rozwija jeden oktet specyfikacji: '5', '1-20', '1,5,9', '*', '-'.

    nmap robi to w TargetGroup::parse_expr(); limit 0-255 i walidacja
    kolejności zakresu są takie same.
    """
    if part in ("*", "-", ""):
        return list(range(256))

    values: set[int] = set()
    for chunk in part.split(","):
        chunk = chunk.strip()
        if not chunk:
            raise TargetSpecError(f"Pusty element w oktecie {octet_index + 1}")

        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            lo = 0 if lo_s == "" else _parse_octet_value(lo_s, octet_index)
            hi = 255 if hi_s == "" else _parse_octet_value(hi_s, octet_index)
            if lo > hi:
                raise TargetSpecError(
                    f"Zakres odwrócony w oktecie {octet_index + 1}: {chunk}"
                )
            values.update(range(lo, hi + 1))
        else:
            values.add(_parse_octet_value(chunk, octet_index))

    return sorted(values)


def _parse_octet_value(text: str, octet_index: int) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise TargetSpecError(
            f"'{text}' nie jest liczbą (oktet {octet_index + 1})"
        ) from exc
    if not 0 <= value <= 255:
        raise TargetSpecError(f"Oktet {octet_index + 1} poza zakresem 0-255: {value}")
    return value


def _looks_like_octet_spec(spec: str) -> bool:
    """Czy to IPv4 z zakresami/listami, a nie nazwa DNS?"""
    parts = spec.split(".")
    if len(parts) != 4:
        return False
    allowed = set("0123456789-,*")
    return all(part != "" and set(part) <= allowed for part in parts)


def expand_spec(spec: str, resolve: bool = True) -> Iterator[Target]:
    """
    Zamienia jedną specyfikację w strumień celów.

    resolve=False odpowiada nmapowemu -n (bez odwrotnego DNS).
    """
    spec = spec.strip()
    if not spec:
        return

    # 1. CIDR — ipaddress robi to lepiej niż ręczne maskowanie w C
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise TargetSpecError(f"Niepoprawny CIDR: {spec} ({exc})") from exc

        family = socket.AF_INET6 if net.version == 6 else socket.AF_INET
        # nmap dla /31 i /32 skanuje też adres sieci i broadcast
        hosts = net.hosts() if net.num_addresses > 2 else net
        for addr in hosts:
            yield Target(ip=str(addr), family=family)
        return

    # 2. IPv4 z zakresami w oktetach
    if _looks_like_octet_spec(spec):
        octet_sets = [
            _expand_octet(part, idx) for idx, part in enumerate(spec.split("."))
        ]
        for combo in product(*octet_sets):
            yield Target(ip=".".join(str(o) for o in combo), family=socket.AF_INET)
        return

    # 3. Literalny adres (głównie IPv6)
    try:
        addr = ipaddress.ip_address(spec)
    except ValueError:
        pass
    else:
        family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
        yield Target(ip=str(addr), family=family)
        return

    # 4. Nazwa DNS — getaddrinfo, odpowiednik resolve() z nmapa
    try:
        infos = socket.getaddrinfo(spec, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetSpecError(
            f"Nie udało się rozwiązać nazwy '{spec}': {exc.strerror or exc}"
        ) from exc

    seen: set[tuple[int, str]] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if (family, ip) in seen:
            continue
        seen.add((family, ip))
        yield Target(ip=ip, hostname=spec, family=family)


def expand_specs(
    specs: list[str], resolve: bool = True, exclude: list[str] | None = None
) -> list[Target]:
    """
    Rozwija listę specyfikacji, usuwa duplikaty i stosuje --exclude.

    Odpowiada pętli nextTarget()/NewTargets z targets.cc, tylko że nmap
    streamuje cele grupami (determineScanGroupSize), a my materializujemy
    listę — dla skanów "basic" to w pełni wystarczy.
    """
    excluded_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    excluded_ips: set[str] = set()

    for item in exclude or []:
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            try:
                excluded_nets.append(ipaddress.ip_network(item, strict=False))
            except ValueError as exc:
                raise TargetSpecError(f"Niepoprawny --exclude: {item} ({exc})") from exc
        else:
            for target in expand_spec(item, resolve=False):
                excluded_ips.add(target.ip)

    def is_excluded(ip: str) -> bool:
        if ip in excluded_ips:
            return True
        if not excluded_nets:
            return False
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in excluded_nets)

    out: list[Target] = []
    seen: set[str] = set()
    for spec in specs:
        for target in expand_spec(spec, resolve=resolve):
            if target.ip in seen or is_excluded(target.ip):
                continue
            seen.add(target.ip)
            out.append(target)
    return out


def reverse_lookup(target: Target) -> None:
    """Uzupełnia reverse_dns. nmap robi to równolegle przez własny resolver."""
    if target.hostname:
        return
    try:
        target.reverse_dns = socket.gethostbyaddr(target.ip)[0]
    except (OSError, socket.herror):
        target.reverse_dns = None
