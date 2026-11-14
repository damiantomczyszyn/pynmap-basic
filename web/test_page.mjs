/* Test strony end-to-end.
 *
 * Wczytuje prawdziwy index.html do jsdom-a, wykonuje prawdziwe modules.js
 * i app.js, i podstawia prawdziwe Pyodide z node. Jedyne, czego brakuje,
 * to silnik renderujący — więc weryfikujemy logikę i strukturę DOM-u:
 * czy strona bootuje, czy hex dump ma właściwą liczbę bajtów w każdym
 * regionie, czy zmiana portu przelicza sumę kontrolną, czy wykresy mają
 * właściwą liczbę serii i czy wynik skanu z CI się renderuje.
 *
 * Uruchomienie:
 *   python3 web/build_site.py _preview [--scan wynik.json]
 *   cd web && npm ci && PYNMAP_SITE=../_preview node test_page.mjs
 */
import { JSDOM, VirtualConsole } from "jsdom";
import { loadPyodide } from "pyodide";
import { readFileSync } from "node:fs";

const SITE = process.env.PYNMAP_SITE || "_preview";
const html = readFileSync(`${SITE}/index.html`, "utf8")
  // pyodide.js z CDN zastąpimy wstrzykniętym loadPyodide z node
  .replace(/<script src="https:\/\/cdn\.jsdelivr\.net[^>]*><\/script>/, "");

const vc = new VirtualConsole();
const logs = [];
vc.on("jsdomError", (e) => logs.push(["jsdomError", e.message]));
vc.on("error", (...a) => logs.push(["error", a.join(" ")]));
vc.on("warn", (...a) => logs.push(["warn", a.join(" ")]));

const dom = new JSDOM(html, {
  runScripts: "outside-only",
  pretendToBeVisual: true,
  virtualConsole: vc,
  url: "https://example.test/",
});
const { window } = dom;

// fetch dla data/latest-scan.json
window.fetch = async (url) => {
  const path = String(url).replace(/^https?:\/\/[^/]+\//, "");
  try {
    const body = readFileSync(`${SITE}/${path}`, "utf8");
    return { ok: true, status: 200, text: async () => body, json: async () => JSON.parse(body) };
  } catch {
    return { ok: false, status: 404, text: async () => "", json: async () => ({}) };
  }
};

// prawdziwe Pyodide z node
window.loadPyodide = async () => await loadPyodide();

// modules.js + app.js w kontekscie okna
window.eval(readFileSync(`${SITE}/modules.js`, "utf8"));
window.eval(readFileSync(`${SITE}/app.js`, "utf8"));

// app.js czeka na DOMContentLoaded; jsdom go juz wystrzelil, wiec odpalamy recznie
window.document.dispatchEvent(new window.Event("DOMContentLoaded"));

// czekamy na boot (Pyodide + rendery)
const deadline = Date.now() + 180000;
while (Date.now() < deadline) {
  if (window.document.getElementById("app") &&
      !window.document.getElementById("app").hidden) break;
  await new Promise((r) => setTimeout(r, 500));
}
await new Promise((r) => setTimeout(r, 2500));

const $ = (id) => window.document.getElementById(id);
const fail = [];
const ok = (cond, msg) => { console.log(`  ${cond ? "OK  " : "BLAD"} ${msg}`); if (!cond) fail.push(msg); };

console.log("\n=== boot ===");
ok($("boot").hidden === true, "panel ladowania ukryty");
ok($("app").hidden === false, "aplikacja odslonieta");
ok($("env").textContent.includes("Python"), `naglowek env: "${$("env").textContent.trim().slice(0,70)}"`);

console.log("\n=== hex dump pakietu ===");
const rows = $("p-hex").querySelectorAll(".hexrow");
ok(rows.length === 3, `wierszy hex: ${rows.length} (44 bajty / 16 = 3)`);
const bytes = $("p-hex").querySelectorAll("[data-off]");
ok(bytes.length === 44, `bajtow z data-off: ${bytes.length}`);
ok($("p-hex").querySelectorAll(".b-ip").length === 20, `bajtow IP: ${$("p-hex").querySelectorAll(".b-ip").length}`);
ok($("p-hex").querySelectorAll(".b-tcp").length === 20, `bajtow TCP: ${$("p-hex").querySelectorAll(".b-tcp").length}`);
ok($("p-hex").querySelectorAll(".b-opt").length === 4, `bajtow opcji: ${$("p-hex").querySelectorAll(".b-opt").length}`);
ok($("p-fields").querySelectorAll("tr").length === 16, `wierszy tabeli pol: ${$("p-fields").querySelectorAll("tr").length}`);
ok($("p-meta").textContent.includes("weryfikuje"), `meta: "${$("p-meta").textContent}"`);
ok($("p-err").hidden, "brak komunikatu bledu");

console.log("\n=== zmiana portu przelicza sume kontrolna ===");
const sumBefore = [...$("p-fields").querySelectorAll("tr")].find(r => r.textContent.includes("checksum") && r.textContent.includes("TCP"))?.textContent;
$("p-dport").value = "6379";
$("p-dport").dispatchEvent(new window.Event("input", { bubbles: true }));
await new Promise((r) => setTimeout(r, 800));
const sumAfter = [...$("p-fields").querySelectorAll("tr")].find(r => r.textContent.includes("checksum") && r.textContent.includes("TCP"))?.textContent;
ok(sumBefore !== sumAfter, `suma TCP sie zmienila (443 -> 6379)`);
ok($("p-fields").textContent.includes("redis"), "usluga rozpoznana jako redis");

console.log("\n=== bledne IP pokazuje blad ===");
$("p-src").value = "nie-jest-ip";
$("p-src").dispatchEvent(new window.Event("input", { bubbles: true }));
await new Promise((r) => setTimeout(r, 800));
ok(!$("p-err").hidden, `blad widoczny: "${$("p-err").textContent.slice(0,50)}"`);

console.log("\n=== wykres RTT ===");
const rsvg = $("r-chart").querySelector("svg");
ok(!!rsvg, "SVG wykresu RTT istnieje");
ok(rsvg && rsvg.querySelectorAll("path").length === 4, `serii na wykresie: ${rsvg?.querySelectorAll("path").length}`);
ok($("r-steps").querySelectorAll("tr").length === 10, `wierszy tabeli RTT: ${$("r-steps").querySelectorAll("tr").length}`);
ok($("r-meta").textContent.includes("Odrzuconych") || $("r-meta").textContent.includes("timeout"), `meta RTT: "${$("r-meta").textContent.slice(0,90)}"`);

console.log("\n=== wykres cwnd ===");
const csvg = $("c-chart").querySelector("svg");
ok(!!csvg, "SVG wykresu cwnd istnieje");
ok(csvg && csvg.querySelectorAll("path").length === 2, `serii: ${csvg?.querySelectorAll("path").length}`);
const cRows = [...$("c-steps").querySelectorAll("tr")];
ok(cRows.length > 40, `wierszy cwnd: ${cRows.length}`);
ok(cRows.some(r => r.textContent.includes("drop")), "widoczne zdarzenie drop");

console.log("\n=== parsery ===");
ok($("pp-out").textContent.includes("portow") || $("pp-out").textContent.includes("portów"), `porty: "${$("pp-out").textContent.slice(0,40)}"`);
ok($("tt-out").textContent.includes("10.0.1.1"), "cele rozwiniete");

// Sekcja wyników skanu ma dwa prawidłowe stany: z danymi (gdy build_site
// dostał --scan) i bez nich (gdy strona budowana jest samodzielnie, np.
// w jobie testowym). Oba są user-facing, więc testujemy ten, który zachodzi.
const hasScanData = (() => {
  try { readFileSync(`${SITE}/data/latest-scan.json`, "utf8"); return true; }
  catch { return false; }
})();

console.log(`\n=== wyniki skanu z CI (dane ${hasScanData ? "obecne" : "nieobecne"}) ===`);
const ciText = $("ci-out").textContent;

if (hasScanData) {
  const scan = JSON.parse(readFileSync(`${SITE}/data/latest-scan.json`, "utf8"));
  const hosts = [...new Set(scan.scans.flatMap((s) => s.rows.map((r) => r.host)))];
  const openCount = scan.scans.flatMap((s) => s.rows).filter((r) => r.state === "open").length;

  for (const host of hosts) {
    ok(ciText.includes(host), `IP celu ${host} obecne`);
  }
  ok($("ci-out").querySelectorAll("table").length === scan.scans.length,
     `tabel skanu: ${$("ci-out").querySelectorAll("table").length} (oczekiwano ${scan.scans.length})`);
  ok($("ci-out").querySelectorAll(".state-open").length === openCount,
     `portow open: ${$("ci-out").querySelectorAll(".state-open").length} (oczekiwano ${openCount})`);
} else {
  ok($("ci-out").querySelectorAll("table").length === 0, "brak tabel, zgodnie z brakiem danych");
  ok(/Brak zapisanego wyniku|Actions/.test(ciText),
     `komunikat zastępczy obecny: "${ciText.trim().slice(0, 60)}"`);
  ok(!!$("ci-out").querySelector('a[href*="actions"]'), "odnosnik do Actions obecny");
}

console.log("\n=== bledy konsoli ===");
const real = logs.filter(([k, m]) => k !== "warn" && !String(m).includes("Could not parse CSS"));
if (real.length) { real.slice(0,5).forEach(([k,m]) => console.log(`  ${k}: ${String(m).slice(0,160)}`)); }
ok(real.length === 0, `powaznych bledow: ${real.length}`);

console.log(`\n${fail.length === 0 ? "WSZYSTKO PRZESZLO" : "NIEPOWODZENIA: " + fail.length}`);
process.exit(fail.length ? 1 : 0);
