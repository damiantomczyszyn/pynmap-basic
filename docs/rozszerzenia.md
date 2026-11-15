# Plan rozszerzeń — od `basic scan` do nmapa

Stan na listopad 2026. `pynmap-basic` ma dziś **2 z 12** trybów skanowania
nmapa (`-sT`, `-sS`) i **żadnego** z systemów detekcji. Ten dokument opisuje,
co trzeba dołożyć, w jakiej kolejności i co w Pythonie wychodzi łatwiej, a co
trudniej niż w C++.

Kolejność nie jest przypadkowa: najpierw rzeczy, które **odblokowują wiele
kolejnych** (warstwa przechwytywania pakietów), potem te o najlepszym stosunku
wartości do kosztu (host discovery, pozostałe skany flagowe), a na końcu duże
podsystemy (`-sV`, `-O`, NSE).

Oznaczenia: **[S]** mały (dzień–dwa), **[M]** średni (tydzień), **[L]** duży
(tygodnie), **[XL]** osobny projekt.

---

## Faza 0. Fundament: przechwytywanie i wysyłanie pakietów

Bez tego kroku każdy kolejny tryb skanowania będzie obchodził te same
ograniczenia, co dziś `-sS`.

### 0.1 Filtry BPF w jądrze zamiast filtrowania w Pythonie **[M]**

Dziś `scan_syn.py` otwiera `SOCK_RAW`/`IPPROTO_TCP` i odrzuca obce pakiety
**w Pythonie**. Przy skanowaniu hosta, który ma ruch produkcyjny, każdy pakiet
TCP maszyny przechodzi przez interpreter.

W nmapie robi to libpcap z filtrem BPF. W Pythonie **nie trzeba libpcapa** —
Linux pozwala podpiąć program BPF wprost pod socket:

```python
# struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }
# struct sock_fprog  { unsigned short len; struct sock_filter *filter; }
SO_ATTACH_FILTER = 26
prog = b"".join(struct.pack("HBBI", code, jt, jf, k) for code, jt, jf, k in bpf)
fprog = struct.pack("HxxP", len(bpf), ctypes.addressof(buf))
sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
```

Bajtkod da się wygenerować samemu (filtr „tcp and dst port N" to kilkanaście
instrukcji) albo wyciągnąć raz z `tcpdump -ddd`. Zysk: odsiewanie w jądrze,
bez zależności zewnętrznych, i rozdział `/proc/net`-owej rzeczywistości od
logiki skanera.

Alternatywa: `ctypes.CDLL("libpcap.so.0.8")` i `pcap_compile`/`pcap_setfilter`
— mniej kodu, ale wraca zależność systemowa, którą projekt dotąd omijał.

> Odpowiednik w nmapie: `libnetutil/netutil.cc`, `set_pcap_filter()` w `tcpip.cc`.

### 0.2 Warstwa ethernetowa i ARP **[M]**

`AF_PACKET`/`SOCK_RAW` pozwala wysyłać całe ramki. Potrzebne do:

- `-PR` (ARP ping) — w sieci lokalnej **najszybsza i najpewniejsza** metoda
  wykrywania hostów; nmap używa jej automatycznie dla celów w tej samej sieci,
- obejścia sytuacji, w której jądro nie ma wpisu ARP i samo gubi pierwszy pakiet,
- przyszłego `--spoof-mac`.

> Odpowiednik: `libnetutil/eth_*`, `Target::NextHopMACAddress()`.

### 0.3 Prawdziwa tablica routingu **[S]**

`tcpip.get_source_address()` używa triku z `connect()` na UDP. Działa, ale nie
powie, **którym interfejsem** pójdzie pakiet ani jaki jest następny skok — a to
potrzebne do ARP i do `-S`/`-e`.

Do zrobienia: czytanie `/proc/net/route` i `/proc/net/ipv6_route`, a docelowo
`AF_NETLINK` + `RTM_GETROUTE` (czysty `socket` + `struct`, bez zależności).

Przy okazji: flaga `-e <iface>` z nmapa.

> Odpowiednik: `routethrough.cc`, `getinterfaces()`.

### 0.4 IPv6 w skanach surowych **[M]**

`IP_HDRINCL` nie istnieje dla IPv6. Dwie drogi: złożyć nagłówek IPv6 samemu
i wysłać przez `AF_PACKET` (wymaga 0.2), albo zostawić budowanie nagłówka
jądru i ustawiać pola przez `IPV6_*` sockopts. Dochodzi suma kontrolna TCP
z 40-bajtowym pseudo-nagłówkiem IPv6 i nagłówki rozszerzeń.

To domyka obietnicę z README: dziś `-sS` odrzuca cele IPv6.

---

## Faza 1. Wykrywanie hostów (`-sn` i rodzina `-P*`) **[L]**

Dziś skaner zachowuje się **zawsze** jak `nmap -Pn`. Przy skanowaniu `/24`
oznacza to pełny zestaw sond do 254 adresów, z których większość nie istnieje.
To największa pojedyncza strata wydajności w projekcie.

Do zrobienia:

| Flaga | Sonda | Stan portu / hosta |
|---|---|---|
| `-sn` | tylko wykrywanie, bez skanowania portów | — |
| `-PE` | ICMP echo request | odpowiedź → up |
| `-PP` | ICMP timestamp | omija filtry blokujące tylko echo |
| `-PM` | ICMP address mask | rzadkie, ale w starych stosach działa |
| `-PS<ports>` | TCP SYN | SYN/ACK albo RST → up |
| `-PA<ports>` | TCP ACK | RST → up; przechodzi przez proste reguły |
| `-PU<ports>` | UDP | ICMP port unreachable → up |
| `-PR` | ARP | tylko sieć lokalna, wymaga 0.2 |
| `-PO<proto>` | IP protocol ping | — |
| `-PY` | SCTP INIT | niski priorytet |

Architektonicznie: `engine.py` jest już napisany wokół „kolejka sond →
cwnd → retransmisje", więc wykrywanie hostów to **ten sam silnik z inną
jednostką pracy** (host zamiast portu). Warto wydzielić `ProbeQueue`
generyczny po typie celu, zamiast kopiować pętlę po raz trzeci.

Domyślny zestaw nmapa dla roota: `-PE -PS443 -PA80 -PP`. Warto odtworzyć
dokładnie, bo to jedna z rzeczy, które decydują o tym, czy wyniki zgadzają się
z nmapem na tym samym celu.

> Odpowiednik: `ping_scan()` w `scan_engine.cc`, `massping()`.

---

## Faza 2. Pozostałe skany TCP **[M razem]**

Po Fazie 0 to w większości **tabela decyzyjna plus inne flagi w pakiecie** —
silnik jest ten sam co w `-sS`.

| Tryb | Wysyłamy | Odpowiedź → stan |
|---|---|---|
| `-sA` ACK | ACK | RST → `unfiltered`; brak → `filtered` |
| `-sW` Window | ACK | RST z `window > 0` → `open`, `window == 0` → `closed` |
| `-sF` FIN | FIN | brak → `open\|filtered`; RST → `closed` |
| `-sN` NULL | brak flag | jak wyżej |
| `-sX` Xmas | FIN+PSH+URG | jak wyżej |
| `-sM` Maimon | FIN+ACK | brak → `open\|filtered` (BSD-owy bug) |
| `--scanflags` | dowolna kombinacja | użytkownik interpretuje sam |

`-sW` jest ciekawy dydaktycznie: pokazuje, że „zamknięty" i „otwarty" można
rozróżnić po polu, które z definicji nic o tym nie mówi — i że to zależy od
implementacji stosu, nie od standardu.

`-sI` (idle scan) **[L]** stoi osobno: wymaga klasyfikacji sekwencji IP ID
hosta-zombie (`ipid_sequence()` w nmapie), wykrycia, czy jest przewidywalna,
i trzyfazowej logiki sondowania. Najtrudniejszy tryb nmapa i jednocześnie
najlepszy materiał na artykuł.

`-sO` (IP protocol scan) **[S]** — przy okazji, bo tabela ICMP jest już w kodzie.

---

## Faza 3. Skanowanie UDP (`-sU`) **[L]**

Najczęściej proszony brakujący tryb i jednocześnie najbardziej podstępny.

Logika stanów:

- odpowiedź UDP → `open`
- ICMP type 3 code 3 (port unreachable) → `closed`
- ICMP type 3 code 1,2,9,10,13 → `filtered`
- brak odpowiedzi po retransmisjach → `open|filtered`

Trzy rzeczy, które sprawiają, że to nie jest „`-sS` z innym protokołem":

1. **Limitowanie ICMP w jądrze.** Linux domyślnie wysyła ~1 port unreachable
   na sekundę (`net.ipv4.icmp_ratelimit`). Bez detekcji tego skan UDP 1000
   portów trwa kwadranse i kłamie. Nmap ma na to osobny mechanizm
   (`--defeat-icmp-ratelimit`) i dynamiczne zwalnianie.
2. **Payloady.** Pusty datagram UDP na port 53 albo 161 zwykle nic nie
   zwróci. Nmap ma `nmap-payloads` z sondami dla DNS, SNMP, NetBIOS, NTP,
   RPC, IKE, DHCP… Trzeba napisać własny zestaw (plik nmapa, jak
   `nmap-services`, jest objęty NPSL i nie wolno go redystrybuować).
3. **`open|filtered` jest stanem normalnym**, nie wyjątkiem. Wyjście musi to
   jasno pokazywać, inaczej wyniki są mylące.

To też naturalny punkt wejścia dla tematów IoT: SNMP (161), mDNS (5353),
CoAP (5683), DHCP (67) — to wszystko UDP i to właśnie tam mieszka sprzęt.

---

## Faza 4. Detekcja usług i wersji (`-sV`) **[XL]**

Tu projekt przestaje być „skanerem portów", a zaczyna być narzędziem, którego
się faktycznie używa. Port 8080 `open` to informacja; `nginx 1.24.0` to
odpowiedź na pytanie.

Mechanizm nmapa:

1. połącz się z portem, **nic nie wysyłaj**, czekaj do 5 s na banner
   (NULL probe — łapie SSH, SMTP, FTP, POP3 za darmo),
2. jeśli nic, wysyłaj kolejne sondy z `nmap-service-probes` w kolejności
   `rarity` ≤ `--version-intensity` (domyślnie 7),
3. dopasuj odpowiedź do regexpów `match`/`softmatch`,
4. `softmatch` zawęża dalsze sondy do jednej usługi,
5. `ports`/`sslports` decydują, które sondy mają sens na danym porcie,
6. `fallback` pozwala dziedziczyć dopasowania między sondami.

Format `nmap-service-probes` jest tekstowy i dobrze udokumentowany, ale sam
plik jest na NPSL — więc albo czytamy systemowy (jak dziś `nmap-services`),
albo budujemy własny, mniejszy zestaw dla kilkudziesięciu najczęstszych usług.
Drugie jest lepsze dydaktycznie: pisanie sygnatur uczy więcej niż ich
parsowanie.

W Pythonie **łatwiej niż w C++**: moduł `re` zastępuje własny silnik regexpów
nmapa, a `ssl` daje `--version-all` na HTTPS w kilku linijkach
(`ssl.create_default_context()` + `check_hostname=False`).

Flagi do dołożenia: `-sV`, `--version-intensity 0-9`, `--version-light`,
`--version-all`, `--version-trace`, `--allports`.

> Odpowiednik: `service_scan.cc`, `nmap-service-probes`.

---

## Faza 5. Rozpoznawanie systemu (`-O`) **[XL]**

Druga generacja fingerprintingu nmapa to 16 sond i ~30 wyliczanych cech:

- `SEQ` — GCD numerów sekwencyjnych, `SP` (zmienność), `ISR` (tempo),
  przewidywalność IP ID (`TI`/`CI`/`II`), timestamp (`TS`),
- `OPS`/`WIN` — kolejność opcji TCP i rozmiary okna dla 6 sond,
- `ECN`, `T1`–`T7` — reakcje na nietypowe kombinacje flag,
- `U1` — ICMP port unreachable na zamknięty port UDP,
- `IE` — dwa ICMP echo z różnymi parametrami.

Potem dopasowanie do `nmap-os-db` z wagami per-cecha i wyliczeniem procentu
zgodności.

Dobra wiadomość: `tcpip.py` już umie budować dowolne nagłówki, a `struct`
sprawia, że sondy T1–T7 to po kilka linijek. Zła: baza `nmap-os-db` ma
~2600 odcisków i jest na NPSL. Realistyczny zakres to **wyliczanie cech
i pokazywanie ich użytkownikowi** plus dopasowanie do systemowej bazy, jeśli
nmap jest zainstalowany — czyli dokładnie model, który projekt już stosuje
dla `nmap-services`.

Pośredni, tani krok **[S]**: `--osscan-guess` na podstawie samego TTL
i rozmiaru okna (64/5840 → Linux, 128/8192 → Windows, 255 → sieciówka).
Niedokładne, ale pokazuje mechanizm i działa bez bazy.

---

## Faza 6. Skrypty — odpowiednik NSE **[L]**

**To miejsce, w którym Python wygrywa z C++ i gdzie teza projektu się
obronie najlepiej.** Nmap musi wbudować interpreter Lua (`nse_main.cc`,
`nse_nsock.cc`, ~6000 linii kodu klejącego). My mamy interpreter z pudełka.

Minimalne NSE po pythonowemu:

```python
# scripts/http_title.py
CATEGORIES = ["default", "discovery", "safe"]
PORTRULE = {"ports": [80, 443, 8080], "states": ["open"]}

def action(host, port, ctx):
    body = ctx.http_get(host.ip, port.port, "/")
    if (m := re.search(rb"<title>(.*?)</title>", body, re.I | re.S)):
        return {"title": m.group(1).decode(errors="replace").strip()}
    return None
```

Do zrobienia: `--script <nazwy|kategorie>`, `--script-args`, `--script-help`,
`-sC` (= `--script=default`), kategorie nmapa (`auth`, `broadcast`, `brute`,
`default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`,
`malware`, `safe`, `version`, `vuln`) i wyjście skryptów w `-oN`/`-oX`/`-oJ`.

Dwie rzeczy do przemyślenia na starcie, nie potem:

- **Izolacja.** Skrypt to dowolny kod Pythona. Minimum: osobny proces
  (`multiprocessing`), limit czasu, brak dostępu do sieci poza celem.
  Uczciwie udokumentować, że to nie sandbox.
- **Kategorie `intrusive`/`dos`/`exploit` nie powinny być domyślne** — nmap
  tego pilnuje i jest to decyzja projektowa, nie kosmetyka.

Naturalne pierwsze skrypty pod zainteresowania projektu: `mqtt-info` (1883),
`modbus-discover` (502), `snmp-info` (161), `upnp-info` (1900),
`esp32-ota-detect` (3232), `home-assistant-detect` (8123),
`ssl-cert`, `ssh-hostkey`, `http-headers`.

---

## Faza 7. Wyjście i ergonomia **[M razem]**

| Element | Uwagi |
|---|---|
| `-oX` XML | nmapowy DTD; odblokowuje cały ekosystem (Metasploit, Faraday, `ndiff`) |
| `-oA <baza>` | zapis wszystkich formatów naraz |
| `--append-output` | dopisywanie zamiast nadpisywania |
| `--resume <plik>` | wznowienie przerwanego skanu; wymaga zapisu stanu kolejek |
| `--stats-every 10s` | okresowe podsumowanie |
| status po klawiszu | nmap pokazuje postęp po naciśnięciu dowolnego klawisza |
| `About X% done; ETC:` | estymacja z liczby ukończonych sond — mamy już liczniki |
| `--packet-trace` | log każdego pakietu; bardzo pomaga przy debugowaniu `-sS` |
| `-vv`, `-dd` | poziomy, które dziś są parsowane, ale nic nie zmieniają |
| `--noninteractive` | — |

`-oX` warto zrobić wcześnie: `ndiff` z nmapa potrafi porównać dwa pliki XML,
co daje **gotowy test różnicowy** względem prawdziwego nmapa.

---

## Faza 8. Wydajność i sterowanie tempem **[M]**

- `--min-rate` / `--max-rate` — token bucket; dziś tempo wynika wyłącznie
  z cwnd, więc nie da się powiedzieć „nie więcej niż 100 pakietów/s",
  a to jest wymóg w wielu regulaminach i zleceniach.
- `--min-hostgroup` / `--max-hostgroup` — nmap skanuje hosty **grupami**
  (`determineScanGroupSize()`); `targets.py` materializuje dziś całą listę,
  więc `-p -` na `/16` to 65 536 obiektów `Target` i porażka pamięciowa.
  Przejście na generator + grupowanie to jedna zmiana, która to naprawia.
- `--defeat-rst-ratelimit` — Linux limituje też RST-y.
- `PortList` jako `array`/`bytearray` zamiast `dict` dla dużych zakresów:
  65 536 `PortResult`-ów na host to ~20 MB; `bytearray` stanów + słownik
  tylko dla portów „interesujących" schodzi do kilobajtów.
- Batching syscalli: `sendmmsg`/`recvmmsg` przez `ctypes`. Projekt sam
  ustalił, że pętla jest syscall-bound — to jest dźwignia, która tu działa,
  w odróżnieniu od mikrooptymalizacji w Pythonie.

---

## Faza 9. Unikanie detekcji **[M]**

Potrzebne do zgodności z nmapem i do testowania własnych IDS-ów — czyli
realnie przydatne po stronie obrony, bo pozwala sprawdzić, czy reguły łapią
coś więcej niż skan domyślny.

`-f` / `--mtu` (fragmentacja), `-D <decoys>` (sondy z podstawionych adresów
obok prawdziwej), `--spoof-mac`, `--data-length`, `--ip-options`,
`--badsum` (pakiety z błędną sumą — odpowiada tylko sprzęt pośredniczący,
więc wykrywa firewalle), `--ttl` (już jest), `--randomize-hosts`.

Każda z tych flag powinna mieć w dokumentacji opis **jak to wygląda
z perspektywy obrońcy** — to jest ta część, która ma wartość szkoleniową.

---

## Faza 10. Przenośność **[M]**

- **Windows**: surowe sockety są tam mocno ograniczone; nmap używa Npcap.
  Droga: `ctypes` + `wpcap.dll` (API zgodne z libpcap). `-sT` działa już dziś.
- **macOS/BSD**: `_BSD_LENGTH_QUIRK` w `tcpip.py` jest, ale nieprzetestowane
  w CI. `runs-on: macos-latest` jest darmowe dla repozytoriów publicznych.
- **Android/Termux**: `-sT` działa bez roota, więc to realny cel.

---

## Ulepszenia inżynierskie (niezależne od funkcji)

Rzeczy, które nie dodają trybów, ale zmieniają to, ile można kodowi zaufać.

### Testy

- **Testy różnicowe względem nmapa.** Jeśli `nmap` jest w systemie, CI
  skanuje ten sam cel oboma narzędziami i porównuje stany portów. To
  najmocniejsza możliwa gwarancja zgodności — mocniejsza niż jakikolwiek
  test jednostkowy — a infrastruktura (kontenery w CI) już jest.
- **Fuzzing parserów.** `parse_ip_header`, `parse_tcp_header`,
  `parse_icmp_quote` czytają bajty **kontrolowane przez cel skanowania**.
  To jedyne miejsce w projekcie, gdzie wejście jest wrogie. `atheris`
  albo własna pętla z `os.urandom` + mutacje, w CI.
- **Testy własnościowe** (`hypothesis`) dla `parse_port_spec`,
  `expand_spec` i sum kontrolnych: „suma nad danymi z sumą = 0" to już
  własność, ale jest sprawdzana na kilku przykładach, nie na generowanych.
- **Benchmark w CI z progiem.** Błąd O(n²) w formatowaniu (2 m 38 s przy
  `-p -`) nie został złapany przez 164 testy, bo żaden nie mierzył czasu
  na dużym wejściu. Jeden test z progiem wystarczy.
- **Testowanie mutacyjne.** Najtańszy sposób odpowiedzenia na pytanie „czy
  ten test w ogóle coś chroni". Procedura: wycofaj poprawkę w kopii repo,
  uruchom jej test, sprawdź, czy czerwieni. Warto to zautomatyzować
  (`mutmut`, `cosmic-ray`) choćby dla `pynmap/`.

  Opłaciło się natychmiast — przy dwóch przeglądach wyłapało **pięć**
  bezwartościowych testów, których zielona suita nie odróżniała od
  działających:

  | Test | Dlaczego nic nie chronił |
  |---|---|
  | bramka grupowego cwnd | przy jednym hoście limit wymuszało okno per-host |
  | próg bramki | asercja powtarzała **błędną** formułę z kodu (`cwnd + low_cwnd`) |
  | domyślna liczba portów | porównanie stałej z samą sobą |
  | wyczerpanie deskryptorów | `state is not UNKNOWN` jest zawsze prawdą (domyślny stan to `filtered`) |
  | nieczytelny `--services` | sprawdzał tylko typ wyjątku, nie który plik zawiódł |

  Wniosek praktyczny: asercja nie może powtarzać wyrażenia z kodu
  produkcyjnego — musi wyrażać **kontrakt**, inaczej mutant przechodzi.

### Jakość kodu

- **`mypy --strict`.** Adnotacje są w całym kodzie, ale nikt ich nie
  weryfikuje. W projekcie, który ma uczyć, typ jest częścią dokumentacji.
- **Wiele sond na port.** `scan_syn.py` trzyma w `_outstanding` **jedną**
  sondę na `(ip, port)`. Po retransmisji spóźniona odpowiedź na starszą
  sondę nie przejdzie walidacji `ACK == ISN+1` (bo ISN jest już nowy)
  i zostanie wyrzucona — czyli płacimy kolejną retransmisją za odpowiedź,
  którą mieliśmy. Nmap trzyma listę `probes_outstanding` i dopasowuje do
  wszystkich prób.
- **Opóźnienie hosta ≠ średnia z portów.** `_fmt_latency()` liczy średnią
  RTT ze wszystkich portów; nmap podaje RTT z fazy wykrywania hosta.
  Po Fazie 1 warto to poprawić — teraz przy `-p -` liczba jest zdominowana
  przez porty zamknięte.
- **Okno grupowe a sondy rozstrzygnięte natychmiast.** W `-sT` sondy,
  które `connect()` rozstrzyga od razu (localhost, RST), nie wchodzą do
  `_pending`, więc nie podlegają bramce grupowego cwnd. Na szybkich celach
  okno grupowe praktycznie nie ogranicza niczego. (Osobna sprawa — sam
  wzrost okna — została już naprawiona: `register_sent()` podbija teraz
  `num_replies_expected` grupy, bez czego `cc_scale()` zwracało 0.0
  i grupowe `cwnd` stało na wartości początkowej na zawsze.)
- ~~**`--host-timeout` a stan portów.**~~ Naprawione: porzucony host nie
  przechodzi już przez `finalize()`, więc `-oG`/`-oJ` pokazują tylko porty,
  do których faktycznie poszła sonda. W JSON-ie doszło pole
  `ports_requested` obok `ports_scanned`, żeby dało się odróżnić „zamówiono"
  od „zmierzono".
- **Weryfikacja stałych timingowych.** Dzielniki `ssthresh` w
  `ScanPerformanceVars.from_template()` (1.5 / 4÷3 / 5÷4) warto zestawić
  linijka w linijkę ze `scan_performance_vars::init()` w `timing.cc`
  i dopisać odwołanie do numeru linii, jak w pozostałych stałych.

### Dane

- **Własny plik częstotliwości portów.** Dziś `--top-ports` powyżej ~190
  wyczerpuje wbudowaną listę, a nmapowy `nmap-services` jest na NPSL.
  Własny plik, zbudowany z publicznych danych (rejestr IANA + statystyki
  z własnych skanów homelabu), odblokowuje `--top-ports 1000` bez nmapa
  i pozwala zmienić domyślne 100 na nmapowe 1000.

---

## Podsumowanie: co kiedy

| Priorytet | Element | Koszt | Co odblokowuje |
|---|---|---|---|
| 1 | Filtry BPF (0.1) | M | poprawność i tempo wszystkich skanów surowych |
| 2 | Host discovery `-sn`/`-P*` (Faza 1) | L | sensowne skany sieci, nie tylko hostów |
| 3 | `-oX` XML (Faza 7) | S | `ndiff` jako test różnicowy, integracje |
| 4 | Skany flagowe `-sA -sW -sF -sN -sX -sM` (Faza 2) | M | 6 trybów za cenę jednego |
| 5 | Grupowanie hostów + rate limiting (Faza 8) | M | skany `/16`, zgodność z regulaminami |
| 6 | `-sU` (Faza 3) | L | UDP, czyli większość IoT |
| 7 | `-sV` (Faza 4) | XL | narzędzie, którego się używa, nie tylko czyta |
| 8 | Skrypty (Faza 6) | L | teza projektu: tu Python bije C++ |
| 9 | `-O` (Faza 5) | XL | — |
| 10 | Unikanie detekcji (Faza 9) | M | testowanie własnych IDS-ów |

Realistycznie: pozycje 1–5 to wersja **0.2**, która zachowuje się jak nmap na
typowym `nmap -sS -p- 10.0.0.0/24`. Pozycje 6–8 to wersja **0.3**, po której
narzędzie da się postawić obok nmapa w pracy, a nie tylko w notatkach.

Co zostaje poza zakresem na zawsze: `-sI` w produkcyjnej jakości, pełna baza
`nmap-os-db`, SCTP, wszystko, co wymaga redystrybucji plików danych nmapa.
