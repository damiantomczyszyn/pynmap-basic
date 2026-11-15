# pynmap-basic

Nmapowy **basic scan** przepisany z C/C++ na Pythona — projekt edukacyjny
z porównaniem obu implementacji.

Zakres: **TCP connect scan (`-sT`)** i **TCP SYN scan (`-sS`)**, wraz
z parsowaniem celów i portów, estymatorem RTT i oknem zatłoczenia
odwzorowanymi z algorytmów nmapa (7.993SVN).

```
$ python3 -m pynmap -sS -p 22,443,2222,8080,8443,9999 -n --reason 127.0.0.1
Starting pynmap-basic 0.1.0 ( https://github.com/damiantomczyszyn/pynmap-basic ) at 2026-11-14 07:56 CET

pynmap-basic scan report for 127.0.0.1
Host is up (0.0003s latency).
PORT      STATE           SERVICE           REASON
22/tcp    closed          ssh               reset ttl 64
443/tcp   closed          https             reset ttl 64
2222/tcp  open            unknown           syn-ack ttl 64
8080/tcp  open            http-proxy        syn-ack ttl 64
8443/tcp  open            https-alt         syn-ack ttl 64
9999/tcp  open            abyss             syn-ack ttl 64

pynmap-basic done: 1 IP address (1 host up) scanned in 0.00 seconds
```

---

## Wypróbuj bez instalacji

Trzy drogi, wszystkie darmowe, żadna nie wymaga klonowania repo:

| Gdzie | Co dostajesz | Czego nie dostajesz |
|---|---|---|
| **[Demo w przeglądarce](https://damiantomczyszyn.github.io/pynmap-basic/)** | Estymator RTT, okno zatłoczenia i budowanie pakietów SYN, policzone przez ten sam kod przez Pyodide. Plus wynik ostatniego realnego skanu z CI. | Skanowania — przeglądarka nie ma socketów. |
| **Codespaces** (`Code → Codespaces`) | Pełny skaner z `-sS` w terminalu w przeglądarce. Kontener ma `NET_RAW`, zbudowaną wersję C i nmapa do porównań. | Nic — to zwykły Linux. 120 core-godzin/mies. na koncie Free. |
| **[GitHub Actions](https://github.com/damiantomczyszyn/pynmap-basic/actions)** | Realny skan nginxa i redisa w kontenerach, po IP mostka `docker0`. | Interaktywności — odpala się na push. |

Dlaczego taki podział, a nie jeden hosting: skanera portów nie da się
uruchomić na darmowym PaaS-ie. Brakuje `CAP_NET_RAW`, a skanowanie
z infrastruktury dostawcy łamie regulamin. Szczegóły i mapa darmowych
tierów: [`docs/darmowy-hosting.md`](docs/darmowy-hosting.md).

### Co weryfikuje CI

Na każdy push: `ruff`, `pytest` na Pythonie 3.10 i 3.13, testy jako root
(włączają przypadki `-sS` na surowych socketach), build wersji C pod
`-Wall -Wextra -Wpedantic` z zerową tolerancją na ostrzeżenia, przebieg pod
AddressSanitizerem, a potem **realny test sieciowy**: nginx i redis stawiane
w kontenerach i skanowane po IP mostka — czyli przez prawdziwy ARP, bridge
i routing jądra, nie skrótem przez loopback. Build pada, jeśli
którykolwiek port wyjdzie w innym stanie niż oczekiwany.

---

## ⚠️ Zanim uruchomisz

**Skanuj wyłącznie hosty, których jesteś właścicielem albo na które masz
pisemną zgodę właściciela.** Skanowanie obcej infrastruktury bez zgody
może naruszać art. 267 k.k. (nieuprawniony dostęp do informacji) i
regulaminy dostawców. Do nauki użyj własnego homelabu,
`scanme.nmap.org` (host udostępniony przez autorów nmapa właśnie do tego
celu, z limitem kilku skanów dziennie) albo celowo podatnych maszyn
w izolowanej sieci.

To narzędzie edukacyjne. Do pracy używaj nmapa — jest szybszy,
przetestowany na milionach hostów i ma wszystkie tryby, których tu nie ma.

---

## Instalacja

Nie ma zależności poza biblioteką standardową Pythona (3.10+).

```bash
git clone https://github.com/damiantomczyszyn/pynmap-basic.git
cd pynmap-basic

# uruchomienie bez instalacji
python3 -m pynmap --help

# albo instalacja w trybie edytowalnym
pip install -e .
pynmap --help
```

### SYN scan bez roota

`-sS` wymaga `CAP_NET_RAW`. Zamiast `sudo` dla całego skanu:

```bash
sudo setcap cap_net_raw+ep "$(readlink -f "$(which python3)")"
```

Uwaga: to nadaje uprawnienie **całemu interpreterowi**, więc każdy skrypt
Pythona na tej maszynie będzie mógł otwierać surowe sockety. Na maszynie
współdzielonej lepiej użyć `sudo` albo osobnego venv-a z własnym binarium.

Bez tych uprawnień `-sT` działa normalnie i nie wymaga niczego.

### Windows i macOS

| | `-sT` | `-sS` |
|---|---|---|
| Linux | działa | wymaga `CAP_NET_RAW` |
| macOS | działa | wymaga `sudo` |
| Windows | działa | **niedostępny** — patrz niżej |

Na Windowsie `-sS` nie jest i nie będzie wspierany bez Npcapa: system
blokuje wysyłanie segmentów TCP przez surowe sockety od XP SP2 i nie zmienia
tego uruchomienie jako Administrator. `pynmap -sS` mówi to wprost, zamiast
podsuwać linuksowe `setcap`.

Jeśli coś zachowuje się inaczej niż tutaj opisane, pomaga wynik:

```bash
python3 ci/platform_probe.py
```

Skrypt wypisuje kody błędów `connect()`, wsparcie surowych socketów, typ
selektora i układ `struct linger` na danym systemie. Nie wymaga uprawnień
i nie wysyła pakietów poza `localhost`.

---

## Użycie

Flagi nazwane jak w nmapie, więc polecenia przekładają się 1:1:

```bash
# connect scan, konkretne porty
python3 -m pynmap -sT -p 22,80,443 192.168.1.10

# SYN scan, pierwsze 1000 portów, tylko otwarte, agresywny timing
sudo python3 -m pynmap -sS -p 1-1000 --open -T4 192.168.1.0/24

# top 100 portów z powodem przypisania stanu
python3 -m pynmap --top-ports 100 --reason 192.168.1.10

# pełny zakres, bez losowania kolejności, zapis do JSON
python3 -m pynmap -sT -p - -r -oJ wynik.json 192.168.1.10

# zakresy w oktetach i wykluczenia
python3 -m pynmap -sT -p 445 10.0.1-3.1-50 --exclude 10.0.2.15

# wymuszony port źródłowy (obejście reguł firewalla typu "allow from :53")
sudo python3 -m pynmap -sS -g 53 -p 1-100 192.168.1.10
```

### Najważniejsze opcje

| Opcja | Znaczenie |
|---|---|
| `-sT` / `-sS` | connect scan / SYN scan (domyślnie: `-sS` dla roota, `-sT` inaczej) |
| `-p SPEC` | `80`, `1-1024`, `22,80,443`, `-` (wszystkie), `http,ssh` |
| `--top-ports N` | N najczęstszych portów TCP |
| `-T0..-T5` | szablon timingowy (0 paranoid … 5 insane, domyślnie 3) |
| `--open` | pokaż tylko porty otwarte |
| `--reason` | pokaż, dlaczego przypisano dany stan |
| `-v` | nie zwijaj stanów w wyjściu (pokaż każdy port osobno) |
| `-r` | nie losuj kolejności portów |
| `-n` | bez odwrotnego DNS |
| `--max-retries N` | limit retransmisji |
| `--host-timeout CZAS` | np. `30s`, `5m` |
| `--scan-delay CZAS` | minimalna przerwa między sondami |
| `-g PORT` / `-S IP` | wymuszony port / adres źródłowy (`-sS`) |
| `--services PLIK` | własna baza `nmap-services` (błąd, jeśli nieczytelna) |
| `-oN` / `-oG` / `-oJ` | zapis: normal / grepable / JSON |

Pełna lista: `python3 -m pynmap --help`.

### Baza usług

Domyślnie używana jest wbudowana lista dobrze znanych portów. Jeśli masz
zainstalowanego nmapa, `pynmap` automatycznie wczyta jego `nmap-services`
— wtedy `--top-ports` daje **dokładnie** te same porty co nmap. Można też
wskazać plik ręcznie:

```bash
python3 -m pynmap --services /usr/share/nmap/nmap-services --top-ports 1000 cel
# albo przez zmienną środowiskową
PYNMAP_SERVICES=/usr/share/nmap/nmap-services python3 -m pynmap --top-ports 1000 cel
```

Plik `nmap-services` **nie jest** częścią tego repozytorium — jest objęty
licencją nmapa.

---

## Struktura projektu

```
pynmap/
  constants.py     stany portów, powody, flagi TCP, limity   <- portlist.h, portreasons.h, nmap.h
  timing.py        estymator RTT + okno zatłoczenia (AIMD)    <- timing.h, timing.cc
  targets.py       parsowanie celów: CIDR, zakresy, DNS       <- Target.cc, TargetGroup.cc
  ports.py         parsowanie -p + przechowywanie wyników     <- portlist.cc, getpts()
  services.py      nazwy usług, --top-ports                   <- nmap-services, gettoppts()
  tcpip.py         budowanie/parsowanie IP, TCP, ICMP         <- tcpip.cc, libnetutil/
  engine.py        wspólny silnik: kolejki, cwnd, retransmisje <- scan_engine.cc/.h
  scan_connect.py  connect scan przez selectors               <- scan_engine_connect.cc
  scan_syn.py      SYN scan na surowych socketach             <- scan_engine_raw.cc
  output.py        formaty normal / grepable / JSON           <- output.cc
  cli.py           parsowanie opcji                            <- nmap.cc

c_reference/
  connect_scan.c   ten sam algorytm w C11 — do porównania
  Makefile         make | make debug | make asan

docs/
  nmap-architecture.md   jak zbudowany jest kod nmapa, ścieżka wykonania
  c-vs-python.md         porównanie: wydajność, konstrukcje, wnioski
  port-states.md         tablice decyzyjne errno/flagi -> stan portu
  rozszerzenia.md        plan dojścia do nmapa: tryby, fazy, koszty

tests/                   319 testów (pytest)
```

---

## Porównanie z C

Repo zawiera **drugą implementację tego samego algorytmu w C11**
(`c_reference/connect_scan.c`) — napisaną od zera, nie skopiowaną z nmapa.
Te same stałe, ta sama tabela `errno`, ten sam estymator RTT, to samo okno
zatłoczenia. Różni się tylko językiem, więc wyniki są identyczne:

```bash
make -C c_reference
./c_reference/connect_scan 127.0.0.1 22,80,443 --reason
python3 -m pynmap -sT -p 22,80,443 -n --reason 127.0.0.1
```

Pomiary (1024 porty na `127.0.0.1`, `-T4`):

| Metryka | C | Python | Stosunek |
|---|---|---|---|
| Sam skan | ~8 ms | ~18–20 ms | ~2,3× |
| Cały proces | ~12 ms | ~90 ms | ~7× |
| LOC (bez komentarzy) | 634 | 285 (`scan_connect.py`) + moduły wspólne | — |

Wniosek, który był dla mnie najciekawszy: **pętla skanowania jest
syscall-bound, nie CPU-bound** — czas idzie na `socket()`/`connect()`/
`select()`, a te kosztują tyle samo w obu językach. Prawdziwa przewaga C
to narzut startu (~70 ms interpretera) i zużycie pamięci, a nie szybkość
samej pętli.

Szczegóły, przykłady kodu i wnioski: [`docs/c-vs-python.md`](docs/c-vs-python.md).

---

## Testy

```bash
pip install pytest
python3 -m pytest tests/ -v
```

319 testów. Pokrywają m.in.:

- zgodność estymatora RTT z wzorami z `timing.cc` (łącznie z zachowaniem
  przesunięć bitowych na liczbach ujemnych),
- parametry AIMD: slow start, congestion avoidance, `drop` vs `drop_group`,
  limit `cc_scale`,
- wartości szablonów `-T0..-T5`,
- parsowanie `-p` i specyfikacji celów wraz z przypadkami błędnymi,
- poprawność sum kontrolnych IP i TCP (weryfikacja „suma nad danymi
  z sumą = 0"),
- pełną tabelę `errno` → stan portu,
- retransmisje: ponawianie do limitu, potem `filtered`,
- skan end-to-end na prawdziwym listenerze lokalnym,
- zwijanie stanów w wyjściu (`Not shown:`) wraz z regresją wydajnościową,
- czekanie na `--scan-delay` bez kręcenia się na 100% CPU — w helperze
  **oraz** w obu silnikach, bo testowanie mutacyjne pokazało, że sama
  delegacja nie miała pokrycia,
- pominięcie hosta, gdy `socket()` zawiedzie (np. wyłączony IPv6),
- warstwę CLI: `-p ""`, `--top-ports 0` i ujemne `--min/--max-parallelism`
  muszą być błędem, a nie cichym skanem domyślnych 100 portów albo pętlą
  bez wyjścia,
- że `--host-timeout` nie dopisuje wymyślonych stanów portom, do których
  nie poszła żadna sonda,
- że grupowe okno zatłoczenia faktycznie rośnie, a nie stoi na wartości
  początkowej,
- że prefiks protokołu w `-p` jest „lepki" (`U:53,80` to dwa porty UDP, jak
  w nmapie, a nie skan TCP/80),
- że własna sonda SYN wrócona po loopbacku nie jest liczona jako odpowiedź
  (`-g 9 -p 9` na zamkniętym porcie nie może dać `open`),
- że trwały brak deskryptorów kończy hosta, a nie zapętla skan,
- że wartości idące do pól nagłówka (`--ttl`, `-g`, `-S`) są walidowane,
  zamiast kończyć skan tracebackiem.

Testy SYN scanu wymagające `CAP_NET_RAW` są automatycznie pomijane bez
uprawnień, więc `pytest` przechodzi też na zwykłym koncie.

---

## Czego tu nie ma

`pynmap-basic` to podzbiór dwóch z dwunastu trybów skanowania nmapa, bez
żadnego z systemów detekcji. Brakuje:

- libpcap i filtrów BPF (filtrujemy w Pythonie — wolniej przy dużym ruchu)
- host discovery (`-sn`), czyli zawsze działamy jak `-Pn`
- detekcji usług i wersji (`-sV`) oraz OS fingerprintingu (`-O`)
- NSE (skryptów Lua)
- UDP, ACK, FIN/NULL/Xmas, idle scan
- IPv6 w SYN scanie (`-sT` obsługuje oba)
- rate limitingu (`--min-rate` / `--max-rate`)
- wysyłania ramek ethernetowych i ARP
- `-sS` na Windowsie — system blokuje wysyłanie segmentów TCP przez surowe
  sockety od XP SP2, niezależnie od praw administratora, więc byłby potrzebny
  Npcap (tak jak w nmapie). `-sT` na Windowsie działa.
- wyjścia XML (`-oX`) — mamy JSON

Pełna lista z uzasadnieniem: [`docs/c-vs-python.md`](docs/c-vs-python.md#4-czego-wersja-w-pythonie-nie-ma).

Co z tego i w jakiej kolejności ma dojść — razem z kosztem każdego kroku
i tym, co odblokowuje — opisuje [`docs/rozszerzenia.md`](docs/rozszerzenia.md).

---

## Licencja

Kod w tym repozytorium: **MIT** (patrz [`LICENSE`](LICENSE)).

Napisany od zera. Z nmapa pochodzą **algorytmy i stałe** (estymator RTT,
parametry AIMD, tabele `errno` i ICMP → stan portu), odtworzone na
podstawie analizy publicznie dostępnych źródeł i udokumentowane
odwołaniami do plików i linii. Żaden kod źródłowy nmapa nie został
skopiowany, podobnie jak żaden z jego plików danych (`nmap-services`).

nmap jest objęty własną licencją (NPSL) — zobacz
[nmap.org/npsl](https://nmap.org/npsl/).

## Źródła

- `https://github.com/nmap/nmap` — źródła nmapa (7.993SVN, commit `68739db`)
- `https://nmap.org/book/man-port-scanning-techniques.html` — techniki skanowania
- `https://nmap.org/book/man-performance.html` — timing i wydajność
- RFC 6298 — algorytm RTO w TCP (Jacobson/Karels)
- RFC 5681 — slow start i congestion avoidance
- RFC 1071 — suma kontrolna internetowa
