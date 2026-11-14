# Tablice decyzyjne: jak powstaje stan portu

Jedyne źródło prawdy dla obu skanerów. Tabele są przepisane z
`handleConnectResult()` (`scan_engine_connect.cc`) i z interpretacji
odpowiedzi w `scan_engine_raw.cc`.

---

## 1. Connect scan (`-sT`)

Źródłem informacji jest `errno` z `connect()` albo z
`getsockopt(SO_ERROR)` po tym, jak deskryptor stał się gotowy do zapisu.

| `errno` | Stan | Powód (`--reason`) | Komentarz |
|---|---|---|---|
| `0` | **open** | `syn-ack` | `connect()` się udał |
| `EISCONN` | **open** | `syn-ack` | połączenie już zestawione |
| `EAGAIN` | **open** | `syn-ack` | specyfika pętli lokalnej w Linuksie — nie błąd |
| `ECONNREFUSED` | **closed** | `conn-refused` | przyszedł `RST` |
| `EACCES` | filtered | `admin-prohibited` | lokalny firewall zablokował wyjście |
| `EPERM` | filtered | `admin-prohibited` | jak wyżej |
| `ENOPROTOOPT` | filtered | `proto-unreach` | ICMP protocol unreachable |
| `EHOSTUNREACH` | filtered | `host-unreach` | ICMP host unreachable |
| `ENETUNREACH` | filtered | `net-unreach` | ICMP network unreachable |
| `ENONET` | filtered | `dest-unreach` | brak na macOS/BSD |
| `ETIMEDOUT` | filtered | `no-response` | jądro poddało się samo |
| `EHOSTDOWN` | filtered | `no-response` | host nie odpowiada |
| brak odpowiedzi po `max_retries` | filtered | `no-response` | nasz timeout |
| cokolwiek innego | filtered | `no-response` | nmap woła tu `fatal()`; my kontynuujemy |

**Czego `-sT` nie potrafi**: rozróżnić `filtered` od `open|filtered`.
Stos TCP jądra zwraca jedną wartość `errno` i nie mamy dostępu do
surowego pakietu, więc tracimy informację o tym, *jak* połączenie
się nie udało.

**Ślad w logach**: `-sT` kończy pełny trzystopniowy handshake, więc
aplikacja po drugiej stronie zobaczy nawiązane i zamknięte połączenie.
To jest widoczne w logach serwera, w przeciwieństwie do `-sS`.

---

## 2. SYN scan (`-sS`)

Źródłem informacji jest surowy pakiet odebrany w odpowiedzi na nasz `SYN`.

### Odpowiedzi TCP

| Flagi w odpowiedzi | Stan | Powód | Komentarz |
|---|---|---|---|
| `SYN` + `ACK` | **open** | `syn-ack` | port słucha |
| `RST` | **closed** | `reset` | nic nie słucha |
| `SYN` bez `ACK` | **open** | `syn-ack` | split handshake, rzadkie |
| inne | *ignorowane* | — | nie nasza odpowiedź |

Dodatkowa walidacja przed przyjęciem odpowiedzi — pakiet jest nasz tylko
wtedy, gdy spełnia **wszystkie** warunki:

1. `ip.src` == adres skanowanego hosta
2. `tcp.dport` == nasz port źródłowy
3. `tcp.sport` == port, który sondowaliśmy
4. jeśli jest flaga `ACK`: `tcp.ack` == nasz `ISN + 1`

Punkt 4 jest istotny dla poprawności: surowy socket odbiera **cały** ruch
TCP wchodzący na maszynę, więc bez tego sprawdzenia cudze połączenie
mogłoby zostać policzone jako odpowiedź na naszą sondę. Test
`test_bad_ack_number_is_ignored` tego pilnuje.

### Odpowiedzi ICMP

| Typ | Kod | Stan | Powód |
|---|---|---|---|
| 3 | 1 — host unreachable | filtered | `host-unreach` |
| 3 | 2 — protocol unreachable | filtered | `proto-unreach` |
| 3 | 3 — port unreachable | filtered | `port-unreach` |
| 3 | 9 — network admin prohibited | filtered | `admin-prohibited` |
| 3 | 10 — host admin prohibited | filtered | `admin-prohibited` |
| 3 | 13 — communication admin prohibited | filtered | `admin-prohibited` |
| 3 | inne kody | *ignorowane* | — |
| 11 | time exceeded | filtered | `time-exceeded` |
| inne typy | — | *ignorowane* | — |

Dopasowanie odpowiedzi ICMP do sondy odbywa się przez **cytat**: pakiet
ICMP unreachable zawiera nagłówek IP oryginalnego pakietu plus jego
pierwsze 8 bajtów danych. Z tych 8 bajtów odzyskujemy `sport`, `dport`
i numer sekwencyjny (`parse_icmp_quote()` w `tcpip.py`).

### Brak odpowiedzi

Po wyczerpaniu `max_retries` port dostaje **filtered** / `no-response`.
To jest stan domyślny ustawiany przez `PortList.finalize()` — odpowiednik
`set_default_port_state()` z `scan_engine.cc`.

---

## 3. Dlaczego „filtered" to nie „zamknięte"

Rozróżnienie, które jest sedno interpretacji wyników skanu:

| Stan | Co wiemy | Co to znaczy w praktyce |
|---|---|---|
| **open** | przyszła pozytywna odpowiedź | usługa nasłuchuje |
| **closed** | przyszedł `RST` | host żyje, ale nic nie słucha na tym porcie |
| **filtered** | nie przyszło nic albo ICMP unreachable | **coś** blokuje ruch — firewall, ACL, routing |

`closed` to **informacja pozytywna**: host odpowiedział. Jeśli skan daje
1000 portów `closed` i 24 `filtered`, to te 24 są ciekawsze — ktoś je
celowo zablokował, co samo w sobie jest informacją o architekturze sieci.

Jeśli **wszystkie** porty wychodzą `filtered`, najpewniej:
- host jest za firewallem, który odrzuca ruch bez odpowiedzi (`DROP`, nie `REJECT`),
- host nie istnieje (a my działamy jak `-Pn`, więc nie sprawdzaliśmy),
- blokuje nas coś po naszej stronie (firewall lokalny, VPN, proxy).

W środowisku z proxy wyjściowym (np. kontener z egress proxy) ruch TCP
do dowolnego adresu bywa odrzucany natychmiast z `ECONNREFUSED` — wtedy
skan pokaże `closed` dla hostów, które wcale nie odpowiedziały. Warto
o tym pamiętać przy interpretacji wyników z takiego środowiska.

---

## 4. Stany, których `pynmap-basic` nie używa

nmap ma jeszcze trzy, dostępne tylko w trybach poza zakresem tego projektu:

| Stan | Skąd się bierze |
|---|---|
| `unfiltered` | tylko `-sA` (ACK scan) — wiemy, że firewall nie blokuje, ale nie wiemy, czy port jest otwarty |
| `open\|filtered` | `-sU`, `-sF`, `-sN`, `-sX` — brak odpowiedzi może znaczyć jedno albo drugie |
| `closed\|filtered` | tylko `-sI` (idle scan) |

Są zadeklarowane w `pynmap/constants.py` (`PortState`), żeby enum
odpowiadał oryginałowi, ale żaden z obecnych skanerów ich nie zwraca.
