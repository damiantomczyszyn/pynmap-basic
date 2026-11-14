# C vs Python — porównanie implementacji skanera portów

Dokument porównuje trzy implementacje tego samego algorytmu (TCP connect scan):

| Implementacja | Język | Pliki | LOC (bez komentarzy) |
|---|---|---|---|
| **nmap** (oryginał) | C++ | `scan_engine*.cc`, `timing.cc`, `tcpip.cc`, … | ~17 000 w plikach odpowiadających zakresowi, ~59 000 w całym drzewie |
| **`c_reference/connect_scan.c`** | C11 | 1 plik | 634 |
| **`pynmap/`** | Python 3.10+ | 13 modułów | 2 450 (z czego `scan_connect.py` = 285) |

Wersja C w tym repo jest napisana od zera specjalnie do porównania: ten sam
algorytm, te same stałe, ta sama tabela `errno` → stan portu, ten sam
estymator RTT i to samo okno zatłoczenia. Różni się **tylko językiem**, więc
różnice w kodzie są różnicami językowymi, a nie projektowymi.

---

## 1. Wyniki są identyczne

```
$ ./c_reference/connect_scan 127.0.0.1 2222,8080,8443,9999,7777,1234 --reason
PORT      STATE       REASON
1234/tcp  closed      conn-refused
2222/tcp  open        syn-ack
7777/tcp  closed      conn-refused
8080/tcp  open        syn-ack
8443/tcp  open        syn-ack
9999/tcp  open        syn-ack

$ python3 -m pynmap -sT -p 2222,8080,8443,9999,7777,1234 -n --reason 127.0.0.1
PORT      STATE           SERVICE           REASON
1234/tcp  closed          hotline           conn-refused
2222/tcp  open            unknown           syn-ack
7777/tcp  closed          cbt               conn-refused
8080/tcp  open            http-proxy        syn-ack
8443/tcp  open            https-alt         syn-ack
9999/tcp  open            abyss             syn-ack
```

To jest warunek wstępny całego porównania — gdyby wyniki się różniły,
porównywalibyśmy dwa różne algorytmy.

---

## 2. Wydajność

Pomiary: 1024 porty na `127.0.0.1`, wszystkie `closed`, `-T4`, bez retransmisji.
Maszyna: kontener Linux, Python 3.13.18, gcc `-O2`.

| Metryka | C | Python | Stosunek |
|---|---|---|---|
| Sam skan (pętla select) | **~8 ms** | ~18–20 ms | **~2,3×** |
| Cały proces (start → wynik) | **~12 ms** | ~90 ms | **~7×** |
| Start interpretera + importy | — | ~70 ms | — |

### Wniosek, który jest nieintuicyjny

**Pętla skanowania jest syscall-bound, nie CPU-bound.** Czas idzie na
`socket()`, `connect()`, `select()`, `getsockopt()`, `close()` — a te kosztują
tyle samo w obu językach, bo to to samo jądro. Python traci ~2,3× na obsłudze
pętli i tworzeniu obiektów, nie na I/O.

Prawdziwa przewaga C w tym zadaniu to **narzut startu**: ~70 ms na uruchomienie
interpretera i import modułów. Przy skanie jednego hosta to dominuje; przy
skanie `/16` przez 20 minut jest nieistotne.

### Kiedy różnica naprawdę boli

| Scenariusz | Co dominuje | Czy Python wystarcza |
|---|---|---|
| 1 host, 100 portów | start interpretera | tak, ale narzut widoczny |
| 1 host, 65535 portów | syscalle + pętla | tak |
| /24, top 1000 portów | sieć i timeouty | tak, z dużym zapasem |
| /16, pełny zakres, pakiety raw | przepustowość pakietów | **nie** — tu C/pcap wygrywa jakościowo |
| Skan z rate 10k+ pakietów/s | koszt na pakiet | **nie** — `masscan`/nmap z pcap |

Dlatego nmap jest w C++: nie dla skanu jednego hosta, ale dla skanów, gdzie
koszt na pakiet decyduje o tym, czy skan trwa godzinę czy tydzień.

---

## 3. Różnice w konstrukcjach języka

### 3.1 Tabela `errno` → stan portu

Ta sama logika, dwie zupełnie różne objętości.

**C** — musi być funkcja ze `switch`, bo C nie ma literałów map:

```c
static void classify_errno(int code, port_state_t *state, reason_t *reason)
{
    switch (code) {
    case 0:
    case EISCONN:
        *state = PORT_OPEN;      *reason = ER_CONACCEPT;       break;
    case ECONNREFUSED:
        *state = PORT_CLOSED;    *reason = ER_CONREFUSED;      break;
    case EACCES:
    case EPERM:
        *state = PORT_FILTERED;  *reason = ER_ADMINPROHIBITED; break;
    /* ... 6 kolejnych przypadków ... */
    default:
        *state = PORT_UNKNOWN;   *reason = ER_UNKNOWN;         break;
    }
}
```

Zwrot przez wskaźniki, bo C nie zwraca krotek. 25 linii.

**Python** — dane zamiast kodu:

```python
_ERRNO_MAP: dict[int, tuple[PortState, Reason]] = {
    0:                  (PortState.OPEN,     Reason.CONACCEPT),
    errno.EISCONN:      (PortState.OPEN,     Reason.CONACCEPT),
    errno.ECONNREFUSED: (PortState.CLOSED,   Reason.CONREFUSED),
    errno.EACCES:       (PortState.FILTERED, Reason.ADMINPROHIBITED),
    errno.EPERM:        (PortState.FILTERED, Reason.ADMINPROHIBITED),
    # ...
}

def classify_connect_errno(code: int) -> tuple[PortState, Reason]:
    return _ERRNO_MAP.get(code, (PortState.UNKNOWN, Reason.UNKNOWN))
```

12 linii i tabela jest danymi — da się ją wypisać, przetestować parametrycznie
(`@pytest.mark.parametrize`) albo wygenerować. W C `switch` jest kodem i nie da
się go iterować.

**Ale**: `switch` w C kompiluje się do tablicy skoków — zero alokacji, zero
hashowania. Python robi lookup w słowniku i tworzy krotkę. Przy milionach
wywołań to mierzalne.

### 3.2 Zarządzanie pamięcią

To największa różnica w kodzie.

**C** — każda alokacja ma parę:

```c
sc.ports       = calloc(MAX_PORTS, sizeof(int));
sc.retry_stack = calloc(MAX_PORTS, sizeof(int));
sc.tryno       = calloc(MAX_PORTS + 1, sizeof(int));
if (sc.ports == NULL || sc.retry_stack == NULL || sc.tryno == NULL) {
    perror("calloc");
    free(sc.ports); free(sc.retry_stack); free(sc.tryno);   /* cleanup */
    return 1;
}
/* ... 200 linii dalej ... */
free(sc.probes);
free(sc.results);
free(sc.tryno);
free(sc.retry_stack);
free(sc.ports);
```

Zauważ wzorzec: **każda ścieżka błędu musi zwolnić to, co już zaalokowano.**
W `connect_scan.c` jest 5 takich bloków cleanup. To klasyczne źródło wycieków
— w tym pliku jest ich 0 (sprawdzone ASAN-em), ale utrzymanie tego stanu przy
rozwoju kodu wymaga dyscypliny.

**Python** — alokacja nie istnieje jako pojęcie:

```python
self.ports_todo: deque[int] = deque(ordered)
self.outstanding: dict[tuple[int, int], Probe] = {}
self.retry_stack: list[int] = []
self.tryno_by_port: dict[int, int] = {}
```

Brak `free`, brak ścieżek cleanup, brak sprawdzania `NULL`. Zamiast tego:
GC działa niedeterministycznie, zużycie pamięci jest ~10–30× wyższe na obiekt,
a `__del__` nie jest gwarantowany.

**Istotny wyjątek — deskryptory plików.** GC nie pomaga: socket trzeba zamknąć
jawnie, bo limit `RLIMIT_NOFILE` wyczerpie się, zanim GC zdecyduje się zebrać
obiekty. Dlatego w `scan_connect.py` jest pełna obsługa zamykania, jak w C:

```python
def _close_probe_socket(self, probe: Probe) -> None:
    sock = probe.sock
    if sock is None:
        return
    try:
        fd = sock.fileno()
    except OSError:
        fd = -1
    if fd >= 0:
        self._pending.pop(fd, None)
    self._safe_unregister(sock)
    try:
        sock.close()
    except OSError:
        pass
    probe.sock = None
```

Lekcja: **GC zarządza pamięcią, nie zasobami systemowymi.** Przy skanerze
portów to właśnie zasoby systemowe są wąskim gardłem.

### 3.3 Multipleksowanie I/O

**C** — `fd_set` to tablica bitów o stałym rozmiarze (`FD_SETSIZE`, zwykle 1024):

```c
fd_set wfds;
int maxfd = -1;

FD_ZERO(&wfds);
for (int i = 0; i < sc->probe_capacity; i++) {
    struct probe *p = &sc->probes[i];
    if (!p->active || p->fd < 0)
        continue;
    FD_SET(p->fd, &wfds);
    if (p->fd > maxfd)
        maxfd = p->fd;
}
ready = select(maxfd + 1, NULL, &wfds, NULL, &tv);
```

Trzeba ręcznie śledzić `maxfd`, przebudowywać `fd_set` przy każdej iteracji
(bo `select()` go modyfikuje) i pamiętać o limicie `FD_SETSIZE` — przekroczenie
to **undefined behavior**, nie błąd.

**Python** — `selectors` wybiera najlepszy mechanizm (epoll na Linuksie,
kqueue na BSD) i trzyma rejestrację między wywołaniami:

```python
self._selector.register(sock, selectors.EVENT_WRITE)
# ...
events = self._selector.select(timeout)
for key, _mask in events:
    sock = key.fileobj
```

Brak `maxfd`, brak przebudowy, brak limitu 1024, i automatycznie dostajemy
epoll (O(1)) zamiast select (O(n)). To przypadek, w którym **Python jest
jakościowo lepszy**, nie tylko krótszy — nmap musiał to rozwiązać ręcznie
(i rozwiązał, w `nsock`).

### 3.4 Budowanie pakietów (SYN scan)

**C/nmap** — rzutowanie wskaźników na struktury:

```c
struct tcp_hdr {
    uint16_t th_sport, th_dport;
    uint32_t th_seq, th_ack;
    uint8_t  th_off_x2, th_flags;
    uint16_t th_win, th_sum, th_urp;
};
/* ... */
struct tcp_hdr *tcp = (struct tcp_hdr *)(packet + ip_len);
tcp->th_sport = htons(sport);
```

Szybkie (zero kopii), ale: trzeba pilnować `__attribute__((packed))`,
wyrównania, kolejności bajtów przy każdym polu i endianness na każdej
platformie. Pomyłka = pakiet, który wygląda poprawnie, ale nie działa.

**Python** — `struct` deklaruje format raz:

```python
header = struct.pack(
    "!HHIIBBHHH",
    sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
    offset_reserved, int(flags), window, 0, urgent,
)
```

`!` wymusza network byte order dla wszystkich pól naraz — cała klasa błędów
endianness znika. Koszt: kopia bufora przy każdym pakiecie.

Cały `tcpip.py` (budowanie + parsowanie IP/TCP/ICMP, sumy kontrolne) to
283 linie. Odpowiednik w nmapie — `tcpip.cc` (1597 linii) plus `libnetutil/`.

### 3.5 Suma kontrolna

Ten sam algorytm (RFC 1071), ale widać różnicę w podejściu do iteracji.

**C** — jawna arytmetyka wskaźników:

```c
unsigned long sum = 0;
const uint16_t *w = (const uint16_t *)data;
while (len > 1) { sum += *w++; len -= 2; }
if (len == 1) sum += *(const uint8_t *)w;
while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
return (uint16_t)(~sum);
```

**Python** — iterator zamiast wskaźnika:

```python
if len(data) % 2:
    data += b"\x00"

total = 0
for (word,) in struct.iter_unpack("!H", data):
    total += word

while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)

return (~total) & 0xFFFF
```

Python wygrywa na czytelności (`iter_unpack` załatwia endianness), C na
szybkości (~50–100× przy dużych buforach). Przy pakietach 44-bajtowych
różnica jest nieistotna; przy sumowaniu megabajtów — decydująca.

Uwaga na `& 0xFFFF` na końcu: Python ma liczby nieograniczone, więc `~total`
daje liczbę ujemną, a nie 16-bitowe dopełnienie. W C typ pilnuje tego sam.
To jedna z nielicznych rzeczy, w których brak typów w Pythonie **dodaje**
pracy.

### 3.6 Przesunięcia bitowe na liczbach ujemnych

W estymatorze RTT nmap używa `>>` do dzielenia:

```c
to->srtt   += rttdelta >> 3;                        /* / 8 */
to->rttvar += (ABS(rttdelta) - to->rttvar) >> 2;    /* / 4 */
to->timeout = to->srtt + (to->rttvar << 2);         /* * 4 */
```

W Pythonie przepisałem to **dosłownie**, nie na `// 8`:

```python
self.srtt += rttdelta >> 3
self.rttvar += (abs(rttdelta) - self.rttvar) >> 2
self.timeout = self.srtt + (self.rttvar << 2)
```

Dlaczego to działa: `rttdelta` bywa ujemne (gdy RTT spada), a gcc na typach
ze znakiem robi przesunięcie arytmetyczne — czyli dzielenie z zaokrągleniem
**w dół**. Python `>>` też zaokrągla w dół. Gdybym napisał `int(rttdelta / 8)`,
Python zaokrągliłby **w stronę zera** i wyniki rozjechałyby się z C dla
ujemnych delt. Test `test_subsequent_sample_formula` to pilnuje.

To typowa pułapka przy przepisywaniu C na Python: operatory wyglądają tak samo,
ale semantyka dzielenia liczb ujemnych jest inna.

### 3.7 Obsługa błędów

**C** — kod powrotu + `errno`, sprawdzany ręcznie przy każdym wywołaniu:

```c
flags = fcntl(fd, F_GETFL, 0);
if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    perror("fcntl");
    close(fd);          /* nie zapomnij! */
    return false;
}
```

Łatwo zignorować błąd (kompilator nie zmusza do sprawdzenia) i łatwo wyciec
zasobem na ścieżce błędu.

**Python** — wyjątki, więc błąd nie da się przeoczyć, ale trzeba zdecydować,
co z nim zrobić:

```python
try:
    sock = socket.socket(family, socket.SOCK_STREAM)
except OSError as exc:
    if exc.errno in (errno.EMFILE, errno.ENFILE):
        host.ports_todo.appendleft(port)      # port wraca do kolejki
        self.max_sockets = max(8, len(self._pending))
        return
    raise
```

Zauważ: obsługujemy konkretny przypadek (wyczerpane deskryptory) i **re-raise**
resztę. To wzorzec, którego w C nie ma — tam każdy błąd trzeba obsłużyć na
miejscu albo przekazać ręcznie w górę.

### 3.8 Struktury danych

| Zadanie | C | Python |
|---|---|---|
| kolejka portów | `int *ports` + indeks | `deque[int]` |
| stos retransmisji | `int *stack` + licznik | `list[int]` |
| sondy w locie | tablica + flaga `active` | `dict[tuple, Probe]` |
| wyniki | tablica + liniowe szukanie | `dict[int, PortResult]` |
| licznik prób na port | `int tryno[65536]` (256 KB!) | `dict[int, int]` |

Ostatni wiersz jest pouczający. W C najprościej zaalokować tablicę
indeksowaną numerem portu — 65536 `int`-ów = 256 KB, nawet gdy skanujemy
10 portów. nmap robi dokładnie to w `portlist.cc`, bo dostęp O(1) jest wart
pamięci. W Pythonie `dict` zużywa pamięć proporcjonalną do liczby
skanowanych portów, ale każdy wpis kosztuje ~100 bajtów zamiast 4.

Przy 10 portach Python wygrywa (1 KB vs 256 KB), przy 65535 — C wygrywa
(256 KB vs ~6 MB).

### 3.9 Wypisywanie wyników — pułapka, w którą wpadłem

Pierwsza wersja raportu w C wyglądała tak:

```c
for (int port = 1; port <= 65535; port++)
    for (int i = 0; i < sc.port_count; i++)
        if (sc.results[i].port == port) { /* wypisz */ }
```

Przy 1024 portach to **67 mln iteracji** — raport trwał dłużej niż skan
(34 ms zamiast 12 ms). Napisałem to tak, bo w C nie ma `sorted(dict)` i
„przeleć po wszystkich portach” wydawało się najprostsze.

Naprawa: `qsort()` + jedna pętla, czyli O(n log n). Czas całego procesu spadł
z 34 ms do 12 ms — **naprawa raportu dała większy zysk niż cokolwiek w samym
skanie.**

W Pythonie ten błąd jest trudniejszy do popełnienia, bo `sorted(self.results)`
jest krótsze niż podwójna pętla:

```python
def sorted_results(self) -> list[PortResult]:
    return [self.results[p] for p in sorted(self.results)]
```

Morał: w C „najprostsze rozwiązanie" i „wydajne rozwiązanie" często się
rozchodzą, bo brak struktur danych w bibliotece standardowej popycha
w stronę pętli po tablicach.

---

## 4. Czego wersja w Pythonie nie ma

Uczciwe porównanie wymaga wymienienia, co odpuściłem:

| Funkcja nmapa | Dlaczego nie ma |
|---|---|
| libpcap + filtry BPF | Filtrujemy w Pythonie; BPF odsiewa pakiety w jądrze, co przy dużym ruchu jest nieporównywalnie tańsze |
| Wysyłanie ramek ethernetowych, ARP | Zostajemy na warstwie IP |
| Host discovery (`-sn`, ping probes) | Zawsze działamy jak `-Pn` |
| Service/version detection (`-sV`) | Osobny, duży podsystem (`service_scan.cc`, 2892 linie) |
| OS fingerprinting (`-O`) | `FPEngine.cc` + `osscan2.cc` ≈ 7500 linii |
| NSE (skrypty Lua) | Cały embedded interpreter Lua |
| UDP, FIN/NULL/Xmas, ACK, idle scan | Tylko `-sT` i `-sS` |
| Rate limiting, `--min-rate`/`--max-rate` | Mamy tylko cwnd i `--scan-delay` |
| IPv6 w SYN scan | `-sS` tylko IPv4; `-sT` obsługuje oba |
| Windows | Surowe sockety na Windows wymagają innego podejścia (Npcap) |
| XML output (`-oX`) | Mamy JSON zamiast |

Innymi słowy: `pynmap-basic` to **podzbiór dwóch z dwunastu trybów skanowania**
nmapa, bez żadnego z systemów detekcji. Te ~2450 linii Pythona odpowiada
funkcjonalnie może 3–5% nmapa.

---

## 5. Wnioski praktyczne

**Co Python robi lepiej**

1. `selectors` zamiast ręcznego `select()` — dostajemy epoll za darmo,
   bez limitu `FD_SETSIZE` i bez śledzenia `maxfd`.
2. `struct.pack("!...")` — endianness deklaratywnie, zamiast `htons()`
   przy każdym polu.
3. Brak ścieżek cleanup pamięci — 5 bloków `free()` w C znika.
4. `ipaddress` — parsowanie CIDR i zakresów w jednej linii zamiast
   ręcznego maskowania.
5. Tabele jako dane (`dict`) zamiast `switch` — testowalne parametrycznie.
6. Struktury danych z biblioteki standardowej popychają w stronę
   rozwiązań o właściwej złożoności.

**Co C robi lepiej**

1. ~2,3× szybsza pętla skanowania, ~7× szybszy cały proces (głównie start).
2. Przewidywalne, małe zużycie pamięci — kilkadziesiąt KB vs kilka MB.
3. Deterministyczne zwalnianie zasobów (`free`/`close` tam, gdzie je napisano).
4. Dostęp do pcap/BPF, surowych ramek i API jądra bez warstw pośrednich.
5. `switch` → tablica skoków, zero alokacji w gorącej ścieżce.
6. Typy pilnują szerokości pól (16-bit wrap w sumie kontrolnej „sam się robi").

**Kiedy który język**

- Skaner do nauki, prototyp, narzędzie wewnętrzne, integracja z pipeline'em
  → Python. Różnica 2,3× nie ma znaczenia, a kod jest 3–4× krótszy.
- Narzędzie, które ma wysyłać dziesiątki tysięcy pakietów na sekundę przez
  lata, na wszystkich platformach → C/C++. Dokładnie dlatego nmap jest w C++.

**Dla kogoś, kto przechodzi z C# na niskopoziomową sieciówkę**: wersja
w Pythonie jest dobrym miejscem na zrozumienie *algorytmu* (cwnd, estymator
RTT, mapowanie errno), bo nie zasłaniają go szczegóły pamięci i endianness.
Potem warto przeczytać `c_reference/connect_scan.c`, żeby zobaczyć, ile pracy
dokłada C — a dopiero na końcu `scan_engine.cc` nmapa, żeby zobaczyć, ile
dokłada produkcyjna jakość.
