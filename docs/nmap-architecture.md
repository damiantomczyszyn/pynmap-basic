# Jak wygląda kod nmapa — architektura basic scan

Analiza drzewa źródeł nmapa w wersji **7.993SVN** (commit `68739db`,
2026-11-12, `github.com/nmap/nmap`).

Celem jest zrozumienie, którędy przebiega ścieżka wykonania dla
`nmap -sT` i `nmap -sS`, bo to właśnie ten fragment odtwarza `pynmap-basic`.

---

## 1. Skala projektu

| Zakres | Linie |
|---|---|
| Główny katalog (105 plików `.cc` / `.h`) | ~59 300 |
| Pliki istotne dla basic scan (13 plików, tabela niżej) | ~17 000 |
| Wbudowane biblioteki (`libpcap`, `libdnet-stripped`, `liblua`, `libssh2`, `libpcre`, `libz`, `liblinear`, `libnetutil`) | dodatkowo dziesiątki tysięcy |

nmap wozi własne, odchudzone kopie bibliotek (`libdnet-stripped`,
`libpcap`), żeby zachować kontrolę nad zachowaniem na wszystkich
platformach. To jedna z przyczyn rozmiaru drzewa.

## 2. Pliki istotne dla basic scan

| Plik | Linie | Rola | Odpowiednik w `pynmap` |
|---|---|---|---|
| `nmap.cc` | 2 902 | `main()`, parsowanie ~150 opcji, `getpts()` | `cli.py`, `ports.py` |
| `scan_engine.cc` | 2 844 | `ultra_scan()` — wspólny silnik wszystkich skanów | `engine.py` |
| `scan_engine.h` | 696 | `UltraScanInfo`, `HostScanStats`, `UltraProbe`, `GroupScanStats` | `engine.py` |
| `scan_engine_connect.cc` | 664 | connect scan (`-sT`) | `scan_connect.py` |
| `scan_engine_raw.cc` | 2 201 | skany na surowych pakietach (`-sS`, `-sU`, `-sA`, …) | `scan_syn.py` (tylko TCP SYN) |
| `timing.cc` | 796 | estymator RTT, okno zatłoczenia, `RateMeter` | `timing.py` |
| `timing.h` | 254 | `timeout_info`, `scan_performance_vars`, `ultra_timing_vals` | `timing.py` |
| `tcpip.cc` | 1 597 | budowanie i odbiór pakietów, pcap | `tcpip.py` |
| `portlist.cc` | 967 | przechowywanie stanów portów | `ports.py` |
| `targets.cc` | 622 | strumieniowanie celów, grupowanie | `targets.py` |
| `TargetGroup.cc` | 204 | parsowanie `10.0.0-2.1-5`, CIDR | `targets.py` |
| `Target.cc` | 555 | jeden cel: adresy, MAC, trasa, wyniki | `targets.py` |
| `output.cc` | 2 699 | formaty normal / grepable / XML | `output.py` |

**Obserwacja**: `scan_engine_connect.cc` ma tylko 664 linie, bo cała logika
tempa, retransmisji i kolejkowania siedzi we wspólnym `scan_engine.cc`.
Odtworzyłem ten sam podział: `scan_connect.py` (285 linii) zajmuje się
socketami, a `engine.py` (287) trzyma stan skanu.

---

## 3. Ścieżka wykonania

```
main()                                  nmap.cc
 └─ nmap_main()                         nmap.cc
     ├─ parsowanie opcji (getopt_long)
     ├─ getpts()                        → lista portów (struct scan_lists)
     ├─ TargetGroup / nextTarget()      → grupy celów
     └─ ultra_scan(targets, ports, SYN_SCAN | CONNECT_SCAN)
         │                              scan_engine.cc:2735
         ├─ UltraScanInfo::Init()        → alokacja HostScanStats na host
         ├─ set_default_port_state()     → stan domyślny (filtered dla -sS/-sT)
         ├─ begin_sniffer()              → tylko skany raw: pcap + filtr BPF
         │
         └─ while (!incompleteHostsEmpty())      ← PĘTLA GŁÓWNA
             ├─ doAnyOutstandingRetransmits()    → timeouty i retransmisje
             ├─ doAnyRetryStackRetransmits()
             ├─ doAnyNewProbes()                 → wysyłka, jeśli sendOK()
             ├─ waitForResponses()
             │   ├─ do_one_select_round()        scan_engine_connect.cc:526  (-sT)
             │   └─ get_pcap_result()            scan_engine_raw.cc          (-sS)
             └─ removeCompletedHosts()
```

`pynmap-basic` zachowuje dokładnie tę kolejność faz — zobacz
`ConnectScanner.scan()` w `scan_connect.py` i `SynScanner.scan()`
w `scan_syn.py`:

```python
while incomplete:
    now = time.monotonic()
    self._handle_timeouts(incomplete, now)   # doAnyOutstandingRetransmits
    self._send_new_probes(incomplete, now)   # doAnyNewProbes
    self._wait_for_responses(incomplete)     # waitForResponses
    # ... removeCompletedHosts
```

---

## 4. Kluczowe struktury danych

### `UltraScanInfo` (`scan_engine.h:533`)

Kontekst całego skanu: lista hostów niedokończonych, wskaźnik na pcap,
`GroupScanStats`, typ skanu, zegar. Jeden obiekt na wywołanie `ultra_scan()`.

### `HostScanStats` (`scan_engine.h:336`)

Stan skanowania jednego hosta — najważniejsza struktura w silniku:

- `probes_outstanding` — lista `UltraProbe*` wysłanych bez odpowiedzi
- `retry_stack` — porty do ponowienia (LIFO)
- `timing` — `ultra_timing_vals` tego hosta (cwnd, ssthresh)
- `to` — `timeout_info` tego hosta (srtt, rttvar, timeout)
- `sendOK()` — czy wolno wysłać kolejną sondę
- `allowedTryno()` — ile retransmisji jeszcze wolno
- `freshPortsLeft()` / `completed()`

### `UltraProbe` (`scan_engine.h:153`)

Jedna sonda. Zawiera unię `IPExtraProbeData` z wariantami dla TCP, UDP,
SCTP i ICMP — bo w C++ trzeba zadeklarować wszystkie możliwe kształty
z góry. W Pythonie `Probe` ma po prostu opcjonalne pola (`sock` dla
connect scanu, `seq`/`sport` dla SYN scanu).

### `ConnectScanInfo` (`scan_engine.h:235`)

Specyficzne dla `-sT`: zarządza `fd_set`-ami i śledzi `maxValidSD`
(najwyższy aktywny deskryptor), bo `select()` tego wymaga. W Pythonie
ta klasa **nie ma odpowiednika** — `selectors` załatwia to samo.

---

## 5. Sterowanie tempem

To najbardziej pouczająca część nmapa: **sterowanie tempem skanu jest
skopiowane z kontroli przepływu TCP**.

### Estymator RTT — `adjust_timeouts2()` (`timing.cc:99`)

Algorytm Jacobsona/Karelsa, ten sam co w stosie TCP (RFC 6298):

```
pierwsza próbka:
    srtt    = delta
    rttvar  = box(5 ms, 2 s, srtt)
    timeout = srtt + 4 * rttvar

kolejne próbki:
    rttdelta = delta - srtt
    srtt    += rttdelta / 8
    rttvar  += (|rttdelta| - rttvar) / 4
    timeout  = srtt + 4 * rttvar
```

Plus sanity-checki: próbki ≥ 8 s są odrzucane, małe ujemne delty
(rozjazd `libpcap` vs `gettimeofday()`) zamieniane na 10 ms, `rttvar`
powyżej 2,3 s ścinane do 2,0 s, a `timeout` przyciskany do
`[MIN_RTT_TIMEOUT, MAX_RTT_TIMEOUT]` = `[100 ms, 10 s]`.

### Okno zatłoczenia — `ultra_timing_vals` (`timing.cc:211–264`)

```
ack()  (przyszła odpowiedź):
    jeśli cwnd < ssthresh:  cwnd += slow_incr * cc_scale      ← slow start
    w przeciwnym razie:     cwnd += ca_incr / cwnd * cc_scale ← congestion avoidance

drop()  (timeout, per-host):
    cwnd     = low_cwnd                      ← kolaps do 1, jak RTO w TCP
    ssthresh = max(in_flight / 1.5, 2)

drop_group()  (timeout, grupowo — łagodniej):
    cwnd     = max(low_cwnd, cwnd / 2)
    ssthresh = max(in_flight / 1.5, 2)
```

`cc_scale()` to sprytny dodatek nmapa, którego nie ma w TCP:

```
cc_scale = min(num_replies_expected / num_replies_received, 50)
```

Im więcej sond zostało bez odpowiedzi, tym **wolniej** rośnie okno —
hamuje odbudowę tempa w sieci, która właśnie gubi pakiety.

### Stałe — `scan_performance_vars::init()` (`timing.cc:267`)

| Parametr | Wartość | Znaczenie |
|---|---|---|
| `low_cwnd` | 1 | minimalne okno |
| `max_cwnd` | 300 | maksimum sond w locie |
| `group_initial_cwnd` | 10 | okno startowe |
| `initial_ssthresh` | 75 | próg slow start → congestion avoidance |
| `slow_incr` | 1 | przyrost w slow start |
| `ca_incr` | 1 (`-T0..3`) / 2 (`-T4..5`) | przyrost w congestion avoidance |
| `cc_scale_max` | 50 | limit skalowania |
| `group_drop_cwnd_divisor` | 2.0 | dzielnik przy stracie (grupowo) |
| `ssthresh_divisor` | 1.5 (`≤T3`) / 1.333 (`T4`) / 1.25 (`T5`) | dzielnik ssthresh |
| `MAX_RETRANSMISSIONS` | 10 | czyli 11 sond na port maksymalnie |

### Szablony `-T0..-T5` (`nmap.cc:1376–1412`)

| Szablon | `scan_delay` | `initial_rtt` | `max_rtt` | `max_retries` | `max_parallelism` |
|---|---|---|---|---|---|
| `-T0` paranoid | 5 min | 5 min | 5 min | 10 | 1 |
| `-T1` sneaky | 15 s | 15 s | 15 s | 10 | 1 |
| `-T2` polite | 400 ms | 1 s | 10 s | 10 | 1 |
| `-T3` normal | 0 | 1 s | 10 s | 10 | dynamiczne |
| `-T4` aggressive | 0 | 500 ms | 1250 ms | 6 | dynamiczne |
| `-T5` insane | 0 | 250 ms | 300 ms | 2 | dynamiczne |

`-T0`, `-T1` i `-T2` wymuszają `max_parallelism = 1`, czyli skan
szeregowy — stąd ich „cichość”. `-T5` dodatkowo ustawia
`host_timeout = 15 min`.

Wszystkie te wartości są odwzorowane w `pynmap/timing.py`
(`TIMING_TEMPLATES`) i sprawdzane testami w `tests/test_timing.py`.

---

## 6. Ciekawostki z kodu

**Zaciemniona linia w parsowaniu `-T`** (`nmap.cc:1377`):

```c
p=optarg+1;*p=*p>'5'?*p:*(p-1)!=*p?'\0':*(p-1)='\0'==(*p-'1')?(error("%s",(char*)(k+8)),'5'):*p;
```

To żart autorów — obsługa `-T` zapisana celowo nieczytelnie. Nie ma
odpowiednika w `pynmap` (u mnie to zwykły `choices=range(6)` w `argparse`).

**`EAGAIN` oznacza port otwarty.** W `handleConnectResult()`
`EAGAIN` z `SO_ERROR` jest mapowane na `PORT_OPEN`. To obejście
specyfiki pętli lokalnej w Linuksie — wygląda na błąd, a jest
celowym workaroundem. Przepisałem to razem z komentarzem, bo bez
niego skan `localhost` dawałby fałszywe wyniki.

**`ENETDOWN` / `ENETRESET` / `ECONNABORTED` = `fatal()`.** nmap
przerywa cały skan, uznając, że sieć padła i dalsze wyniki byłyby
bezwartościowe. `pynmap-basic` jest tu łagodniejszy: traktuje nieznane
`errno` jak brak odpowiedzi i kontynuuje — wolę skończyć skan
z jednym portem oznaczonym `filtered` niż stracić całość.

**Nie wysyłamy RST ręcznie.** Przy SYN scanie port źródłowy nie jest
zabindowany, więc gdy przyjdzie `SYN/ACK`, jądro samo odpowiada `RST`
i półotwarte połączenie znika. nmap opiera się na tym samym
zachowaniu — to nie przeoczenie, a świadoma decyzja.

---

## 7. Co przeczytać, w jakiej kolejności

Jeśli chcesz wejść w oryginalne źródła:

1. **`scan_engine.h`** (696 linii) — same deklaracje. Przeczytaj
   `HostScanStats` i `UltraProbe`; bez nich reszta jest nieczytelna.
2. **`timing.h` + `timing.cc:99–300`** — estymator RTT i cwnd.
   Najbardziej samodzielny i najlepiej skomentowany fragment nmapa.
3. **`scan_engine_connect.cc`** (664 linie) — najprostszy backend.
   Zacznij od `handleConnectResult()` i `do_one_select_round()`.
4. **`scan_engine.cc:2735`** (`ultra_scan`) — pętla główna. Czytaj
   od końca pliku.
5. **`scan_engine_raw.cc:1700–2100`** — interpretacja odpowiedzi
   TCP i ICMP w SYN scanie.

Dopiero potem `output.cc`, `service_scan.cc` i `FPEngine.cc` — ale to
już osobne podsystemy, nie silnik skanowania.

---

## Źródła

- Drzewo źródeł nmapa: `https://github.com/nmap/nmap` (7.993SVN, commit `68739db`)
- Dokumentacja timingu: `https://nmap.org/book/man-performance.html`
- Opis technik skanowania: `https://nmap.org/book/man-port-scanning-techniques.html`
- RFC 6298 — algorytm RTO w TCP (Jacobson/Karels)
- RFC 5681 — kontrola przepływu TCP (slow start, congestion avoidance)
- RFC 1071 — suma kontrolna internetowa
