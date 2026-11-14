# Darmowy hosting i workflow „piszę → push → działa w chmurze”

Stan zweryfikowany w listopadzie 2026. Darmowe tiery zmieniają się szybko
i większość poradników w sieci jest nieaktualna — daty i źródła na końcu.

---

## 1. Dlaczego ten projekt nie da się uhostować jako działający skaner

Trzy niezależne przeszkody, każda wystarczająca:

| Przeszkoda | Szczegół |
|---|---|
| Brak uprawnień | `-sS` potrzebuje `CAP_NET_RAW`. Żaden darmowy PaaS ani serverless go nie daje — kontenery lecą bez tej capability. |
| Regulamin | Skanowanie portów z infrastruktury dostawcy to klasyczny wektor nadużyć. Vercel, Netlify, Render, Fly i spółka zabraniają tego wprost. Konsekwencją jest ban konta, nie ostrzeżenie. |
| Model hostingu | GitHub Pages serwuje pliki statyczne. Nie ma tam żadnego backendu, więc nie ma gdzie uruchomić Pythona. |

Dlatego ten projekt dzieli się na trzy warstwy, każda w miejscu, które
faktycznie potrafi ją uruchomić:

```
   co                          gdzie                      dlaczego tam
   ────────────────────────────────────────────────────────────────────────
   pisanie i build             Claude Code / Codespaces    shell, root, gcc
   realny skan sieciowy        GitHub Actions              root + CAP_NET_RAW
   publiczne demo algorytmów   GitHub Pages + Pyodide      zero serwera
   interaktywny skaner         Codespaces                  terminal w przeglądarce
```

---

## 2. Co zostało realnie darmowe

### Zmiany, które wywróciły stare rekomendacje

- **Fly.io** — nie ma już darmowego tieru dla nowych kont. Trial to 2 godziny
  czasu maszyny albo 7 dni, co skończy się pierwsze; potem wymagana karta.
- **Railway** — free tier zniknął w 2023. Dziś: jednorazowe $5 kredytu na
  30 dni, potem $1/miesiąc, co nie utrzyma nic sensownego.
- **Koyeb** — od lutego 2026 wymaga karty z blokadą autoryzacyjną $29.
- **Heroku** — darmowego tieru nie ma od 2022.

### Co działa bez karty

| Platforma | Co dostajesz | Haczyk |
|---|---|---|
| **GitHub Actions** | Na repo **publicznym minuty bez limitu**. Root, Docker, `CAP_NET_RAW`. | Nie jest serwerem — joby są efemeryczne i odpalane zdarzeniem. |
| **GitHub Pages** | Statyczny hosting, bez limitu czasu, własna domena. | Tylko pliki. Żadnego kodu po stronie serwera. |
| **GitHub Codespaces** | 120 core-godzin/mies. + 15 GB (konto Free); 180 h + 20 GB (Pro). Pełny Linux z terminalem w przeglądarce. | Core-godziny, nie godziny: na maszynie 2-rdzeniowej to ~60 h, na 4-rdzeniowej ~30 h. |
| **Render** | 512 MB, 750 h/mies. (jedna usługa non-stop), Docker, Postgres na 30 dni. | Usypia po 15 min bezczynności i budzi się ~minutę. Od 23.04.2026 tylko 5 GB transferu. |

Render jest w praktyce **jedynym sensownym always-free PaaS-em bez karty**,
jaki został.

---

## 3. Co możesz pisać i od razu hostować za darmo

### Bez serwera, na GitHub Pages

Wszystko, co kompiluje się do plików statycznych:

- **Blazor WebAssembly** — przy Twoim stacku C# to najmocniejsza i najbardziej
  pomijana opcja. Prawdziwy .NET chodzi w przeglądarce, hostuje się jako pliki
  statyczne, nie usypia, nie wymaga karty, nie ma limitu czasu.
- **Python przez Pyodide** — dokładnie to, co robi `web/` w tym repo.
- SPA w czymkolwiek (React, Svelte, vanilla), generatory statyczne, WASM z Rusta czy C.

Granica jest jedna i twarda: **brak socketów, brak dostępu do systemu plików
hosta, brak sekretów**. Wszystko, co wymaga klucza API, musi iść przez proxy,
bo w kodzie frontendu klucz jest publiczny.

### Z serwerem, na Renderze (Docker)

- REST API — FastAPI, Flask, ASP.NET Core minimal API
- Dashboardy i CRUD
- Boty Discord/Telegram, odbiorniki webhooków
- Scheduled joby (albo lepiej: cron w GitHub Actions, bo nie usypia)
- Wszystko, co robi **wychodzące** HTTP

Czego nie da się tam uruchomić: raw sockety, craftowanie pakietów, skanowanie,
stałe IP wychodzące, cokolwiek wymagającego bycia online 24/7 bez przerw.

### Tylko w Actions / Codespaces

- Skanery i narzędzia sieciowe (ten projekt)
- Cokolwiek wymagającego roota albo `CAP_NET_ADMIN`
- Ciężkie buildy i testy integracyjne z Dockerem

---

## 4. Co trzeba zmienić w kodzie, żeby lokalna apka ruszyła w chmurze

Prawie nigdy architektura. Prawie zawsze te pięć rzeczy:

**1. Bind na `0.0.0.0` i port ze zmiennej środowiskowej.** Zdecydowanie
najczęstszy powód „u mnie działa, na hostingu nie" — dostawca wstrzykuje
`$PORT` i routuje tylko tam.

```python
# źle: nasłuch tylko na pętli lokalnej, na sztywnym porcie
uvicorn.run(app, host="127.0.0.1", port=8000)

# dobrze
import os
uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
```

```csharp
// ASP.NET Core — to samo
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
```

**2. Konfiguracja ze zmiennych środowiskowych, nie z pliku.** Kontener nie ma
Twojego `appsettings.Development.json` ani `.env`.

**3. Logi na stdout.** Nie do pliku — plik zniknie przy restarcie i nikt go nie
przeczyta. Dostawca zbiera stdout.

**4. Zero stanu na dysku.** Kontener jest efemeryczny: pliki, SQLite i sesje
w pamięci giną przy każdym redeployu i przy wybudzeniu z uśpienia. Stan idzie
do bazy albo do obiektowego storage.

**5. Healthcheck i `Dockerfile`.** Endpoint `/health` zwracający 200 pozwala
platformie stwierdzić, że proces wstał.

---

## 5. Terminal w chmurze — trzy różne odpowiedzi

Pytanie „jak mieć ten sam terminal co lokalnie, ale w chmurze" ma trzy
rozłączne odpowiedzi i warto wiedzieć, której się szuka.

### a) Codespaces — wchodzisz z przeglądarki i masz VS Code z terminalem

To jest odpowiedź dla tego projektu. W repo jest `.devcontainer/devcontainer.json`,
więc wystarczy **Code → Codespaces → Create codespace**. Dostajesz kontener
z `NET_RAW`, zbudowaną wersją C, zainstalowanym nmapem do porównań i gotowym
`pytest`. `-sS` działa.

Limit: 120 core-godzin/miesiąc na koncie Free, czyli ~60 h na maszynie
2-rdzeniowej. Zatrzymany codespace nie zużywa czasu CPU, ale zużywa storage —
warto kasować nieużywane.

### b) Shell do działającego kontenera na PaaS

Zależnie od dostawcy i planu; na darmowych tierach zwykle niedostępny.
Przydatny do debugowania produkcji, nie do pracy.

### c) Własny web terminal w aplikacji

`xterm.js` w przeglądarce + WebSocket + PTY po stronie serwera (`pty` w Pythonie,
`Pty.Net` w .NET). Technicznie ~100 linii.

**Nie publikuj tego.** Publiczny web terminal to dosłownie zdalne wykonywanie
kodu jako usługa. Bez autentykacji, sandboxa i limitów zasobów to zaproszenie
do przejęcia konta i infrastruktury. Jeśli naprawdę potrzebujesz tego wzorca,
potrzebujesz też: autentykacji przed otwarciem WebSocketa, osobnego kontenera
na sesję, limitów CPU/RAM/czasu, odebranych capability i braku dostępu do
sieci wewnętrznej.

---

## 6. Workflow, który z tego wychodzi

```
  ty: "dorób ACK scan"
        │
        ▼
  Claude Code (chmura)  ── pisze, buduje, uruchamia 164 testy
        │
        │  git push
        ▼
  GitHub ──┬─→ Actions: ruff, pytest na 3.10 i 3.13, build C z -Wall,
           │            ASAN, potem realny skan nginxa i redisa
           │            w kontenerach przez mostek docker0
           │                    │
           │                    │  wynik jako JSON
           │                    ▼
           └─→ Pages: demo algorytmów w przeglądarce + ten wynik
        │
        ▼
  ty: otwierasz URL albo Codespaces i sprawdzasz
```

Koszt: zero. Repo jest publiczne, więc minuty Actions są nielimitowane,
a Pages nie ma limitu czasu.

Co ważne: Pages deployuje się **tylko wtedy, gdy testy przeszły**
(`needs: [test, network]` plus warunek na `needs.test.result`), więc
publiczna strona zawsze odpowiada commitowi, który przeszedł CI.

---

## Źródła

Stan darmowych tierów zmienia się na tyle szybko, że warto sprawdzać daty:

- flaviocopes.com/hosting-free-tiers — przegląd tierów, weryfikowany wrzesień 2026
- snapdeploy.dev/blog/free-cloud-deployment-platforms-2026-comparison — weryfikowany 26.09.2026
- xcloud.host/best-free-docker-hosting — listopad 2026
- docs.github.com/en/billing/concepts/product-billing/github-codespaces — limity Codespaces
- docs.github.com/en/get-started/learning-about-github/githubs-plans — limity Actions i Pages
