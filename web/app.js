/* pynmap-basic — playground.
 *
 * Ładuje CPythona skompilowanego do WebAssembly (Pyodide), wrzuca do jego
 * wirtualnego systemu plików moduły pynmap i woła warstwę pośrednią
 * z web/bridge.py.
 *
 * Granica JS <-> Python jest celowo wąska: przekazujemy tylko JSON-a
 * (pyCall niżej), więc nie ma zarządzania proxy ani wyciekających uchwytów.
 *
 * Czego tu nie ma: skanowania. Przeglądarka nie daje socketów, więc moduły
 * scan_connect i scan_syn nie są ładowane.
 */

"use strict";

const PKG_MODULES = ["constants", "timing", "ports", "services", "targets", "tcpip"];
const PY_ROOT = "/lib";

const COL = {
  srtt: "#27408F",
  rttvar: "#1B6B40",
  timeout: "#94392B",
  sample: "#878DA0",
  cwnd: "#27408F",
  ssthresh: "#94392B",
  grid: "#DCDFE7",
  axis: "#878DA0",
};

let pyodide = null;

/* ------------------------------------------------------------------ */
/* Pomocnicze DOM                                                      */
/* ------------------------------------------------------------------ */

const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (v !== null && v !== undefined) node.setAttribute(k, String(v));
  }
  for (const child of [].concat(children)) {
    if (child == null) continue;
    node.append(child);
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function bootStep(n, state) {
  const node = $(`boot-${n}`);
  if (node) node.dataset.done = state;
}

/* ------------------------------------------------------------------ */
/* Most do Pythona                                                     */
/* ------------------------------------------------------------------ */

/** Woła bridge.<name>(**kwargs) i zwraca sparsowany JSON. */
function pyCall(name, kwargs = {}) {
  pyodide.globals.set("_pn_arg", JSON.stringify(kwargs));
  const out = pyodide.runPython(
    `json.dumps(bridge.${name}(**json.loads(_pn_arg)))`
  );
  return JSON.parse(out);
}

async function boot() {
  try {
    pyodide = await loadPyodide({
      indexURL: "https://cdn.jsdelivr.net/pyodide/v0.29.5/full/",
    });
    bootStep(1, "1");
  } catch (err) {
    bootStep(1, "err");
    fatal("Nie udało się pobrać Pyodide", err);
    return;
  }

  try {
    const sources = await Promise.all(
      [...PKG_MODULES.map((m) => `pynmap/${m}.py`), "bridge.py"].map(
        async (path) => {
          const res = await fetch(path, { cache: "no-cache" });
          if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
          return [path, await res.text()];
        }
      )
    );

    pyodide.FS.mkdirTree(`${PY_ROOT}/pynmap`);
    for (const [path, src] of sources) {
      pyodide.FS.writeFile(`${PY_ROOT}/${path}`, src);
    }
    // Pakietowy __init__ celowo pusty: prawdziwy importuje scan_connect
    // i scan_syn, które wymagają socketów.
    pyodide.FS.writeFile(`${PY_ROOT}/pynmap/__init__.py`, "");
    bootStep(2, "1");
  } catch (err) {
    bootStep(2, "err");
    fatal("Nie udało się wczytać modułów pynmap", err);
    return;
  }

  try {
    pyodide.runPython(`
import sys, json
sys.path.insert(0, "${PY_ROOT}")
import bridge
`);
    bootStep(3, "1");
  } catch (err) {
    bootStep(3, "err");
    fatal("Import warstwy algorytmicznej nie przeszedł", err);
    return;
  }

  showEnvironment();
  wireUp();

  $("boot").hidden = true;
  $("app").hidden = false;
}

function fatal(message, err) {
  console.error(message, err);
  const box = $("boot");
  box.append(
    el("div", { class: "err", style: "margin-top:0.8rem" },
      `${message}: ${err && err.message ? err.message : err}`)
  );
}

function showEnvironment() {
  const env = pyCall("environment");
  const node = $("env");
  clear(node);
  node.append(
    el("span", {}, [el("b", { text: `Python ${env.python}` }), ` / ${env.platform}`]),
    el("span", { text: `baza usług: ${env.services_source} (${env.builtin_ports} portów)` }),
    el("span", { text: `socket: ${env.modules.socket.startsWith("import") ? "importuje się, ale bez sieci" : env.modules.socket}` })
  );
}

/* ------------------------------------------------------------------ */
/* Wykres liniowy (SVG)                                                */
/* ------------------------------------------------------------------ */

function lineChart(series, opts = {}) {
  const W = 560, H = 240;
  const m = { t: 12, r: 12, b: 28, l: 52 };
  const iw = W - m.l - m.r;
  const ih = H - m.t - m.b;

  const all = series.flatMap((s) => s.points);
  if (!all.length) return el("svg", { viewBox: `0 0 ${W} ${H}` });

  const xs = all.map((p) => p.x);
  const ys = all.map((p) => p.y);
  const x0 = Math.min(...xs), x1 = Math.max(...xs) || 1;
  const y1 = Math.max(...ys, opts.yMin || 0) * 1.08 || 1;

  const sx = (x) => m.l + (x1 === x0 ? iw / 2 : ((x - x0) / (x1 - x0)) * iw);
  const sy = (y) => m.t + ih - (y / y1) * ih;

  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", opts.label || "wykres");

  const add = (tag, attrs) => {
    const n = document.createElementNS(svgNS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
    svg.append(n);
    return n;
  };

  // siatka + opisy osi Y
  const ticks = 4;
  for (let i = 0; i <= ticks; i++) {
    const v = (y1 / ticks) * i;
    const y = sy(v);
    add("line", { x1: m.l, y1: y, x2: W - m.r, y2: y, stroke: COL.grid, "stroke-width": 1 });
    const t = add("text", {
      x: m.l - 7, y: y + 3.5, "text-anchor": "end",
      fill: COL.axis, "font-size": 10, "font-family": "IBM Plex Mono, monospace",
    });
    t.textContent = v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v.toFixed(v < 10 ? 1 : 0);
  }

  // etykieta osi X
  const xl = add("text", {
    x: m.l + iw / 2, y: H - 6, "text-anchor": "middle",
    fill: COL.axis, "font-size": 10, "font-family": "IBM Plex Mono, monospace",
  });
  xl.textContent = opts.xLabel || "";

  for (const s of series) {
    if (!s.points.length) continue;
    const d = s.points.map((p, i) => `${i ? "L" : "M"}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(" ");
    add("path", {
      d, fill: "none", stroke: s.color,
      "stroke-width": s.width || 1.8,
      "stroke-dasharray": s.dashed ? "4 3" : "none",
      "stroke-linejoin": "round",
    });
    if (s.dots) {
      for (const p of s.points) {
        add("circle", { cx: sx(p.x), cy: sy(p.y), r: 2.1, fill: s.color });
      }
    }
  }

  return svg;
}

/* ------------------------------------------------------------------ */
/* Sekcja: pakiet SYN                                                  */
/* ------------------------------------------------------------------ */

function regionClass(offset, ipLen, tcpLen) {
  if (offset < ipLen) return "b-ip";
  if (offset < ipLen + 20) return "b-tcp";
  if (offset < ipLen + tcpLen) return "b-opt";
  return "";
}

function renderPacket() {
  const args = {
    src: $("p-src").value.trim(),
    dst: $("p-dst").value.trim(),
    sport: Number($("p-sport").value) || 1,
    dport: Number($("p-dport").value) || 1,
    window: Number($("p-window").value) || 0,
    ttl: Number($("p-ttl").value) || 64,
    mss: $("p-mss").checked ? 1460 : null,
  };

  let res;
  try {
    res = pyCall("build_packet", args);
  } catch (err) {
    res = { ok: false, error: String(err).split("\n").slice(-3).join(" ") };
  }

  const errBox = $("p-err");
  if (!res.ok) {
    errBox.textContent = res.error;
    errBox.hidden = false;
    return;
  }
  errBox.hidden = true;

  // hex dump
  const bytes = res.hex.match(/../g).map((h) => parseInt(h, 16));
  const hexBox = $("p-hex");
  clear(hexBox);

  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const row = el("div", { class: "hexrow" });
    row.append(el("span", {
      class: "hexrow__off",
      text: off.toString(16).padStart(4, "0"),
    }));

    const bytesSpan = el("span", { class: "hexrow__bytes" });
    chunk.forEach((b, i) => {
      const abs = off + i;
      bytesSpan.append(el("i", {
        class: regionClass(abs, res.ip_header_len, res.tcp_header_len),
        "data-off": abs,
        text: b.toString(16).padStart(2, "0"),
      }));
      bytesSpan.append(document.createTextNode(i === 7 ? "  " : " "));
    });
    row.append(bytesSpan);

    row.append(el("span", {
      class: "hexrow__ascii",
      text: chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "·")).join(""),
    }));
    hexBox.append(row);
  }

  $("p-meta").textContent =
    `${res.length} B — IP ${res.ip_header_len} B + TCP ${res.tcp_header_len} B` +
    ` · suma IP: ${res.ip_checksum_ok ? "weryfikuje się do zera" : "BŁĄD"}`;

  // tabela pól, z podświetlaniem bajtów
  const tbody = $("p-fields");
  clear(tbody);

  for (const f of res.fields) {
    const tr = el("tr", { class: f.group === "IP" ? "g-ip" : "g-tcp" }, [
      el("td", {}, [
        el("span", { class: "meta", text: `${f.group} ` }),
        document.createTextNode(f.name),
      ]),
      el("td", { class: "t-mono", text: f.value }),
      el("td", { class: "note", text: f.note || "" }),
    ]);

    const highlight = (on) => {
      for (let i = f.offset; i < f.offset + f.length; i++) {
        const b = hexBox.querySelector(`[data-off="${i}"]`);
        if (b) b.classList.toggle("b-hi", on);
      }
    };
    tr.addEventListener("mouseenter", () => highlight(true));
    tr.addEventListener("mouseleave", () => highlight(false));
    tr.addEventListener("focusin", () => highlight(true));
    tr.addEventListener("focusout", () => highlight(false));
    tr.tabIndex = 0;

    tbody.append(tr);
  }
}

/* ------------------------------------------------------------------ */
/* Sekcja: estymator RTT                                               */
/* ------------------------------------------------------------------ */

function renderRtt() {
  const samples = $("r-samples").value
    .split(",")
    .map((s) => parseFloat(s.trim()))
    .filter((n) => Number.isFinite(n) && n > -1000);

  if (!samples.length) return;

  const res = pyCall("rtt_trace", {
    samples_ms: samples,
    template: Number($("r-template").value),
  });

  const steps = res.steps;
  const chart = lineChart(
    [
      { name: "próbka", color: COL.sample, points: steps.map((s) => ({ x: s.n, y: s.sample_ms })), dashed: true, width: 1.2, dots: true },
      { name: "srtt", color: COL.srtt, points: steps.filter((s) => s.srtt_ms != null).map((s) => ({ x: s.n, y: s.srtt_ms })) },
      { name: "rttvar", color: COL.rttvar, points: steps.filter((s) => s.rttvar_ms != null).map((s) => ({ x: s.n, y: s.rttvar_ms })) },
      { name: "timeout", color: COL.timeout, points: steps.map((s) => ({ x: s.n, y: s.timeout_ms })), width: 2.2 },
    ],
    { xLabel: "numer próbki", label: "Przebieg estymatora RTT w milisekundach" }
  );

  const box = $("r-chart");
  clear(box);
  box.append(chart);

  const t = res.template;
  const last = steps[steps.length - 1];
  const ignored = steps.filter((s) => s.ignored).length;
  $("r-meta").textContent =
    `-T${t.level} (${t.name}): start ${t.initial_ms} ms, zakres ${t.min_ms}–${t.max_ms} ms, ` +
    `${t.max_retries} retransmisji. Końcowy timeout: ${last.timeout_ms} ms.` +
    (ignored ? ` Odrzuconych próbek: ${ignored}.` : "");

  const tbody = $("r-steps");
  clear(tbody);
  for (const s of steps) {
    tbody.append(el("tr", {}, [
      el("td", { class: "num", text: s.n }),
      el("td", { class: "num", text: s.sample_ms }),
      el("td", { class: "num", text: s.srtt_ms ?? "—" }),
      el("td", { class: "num", text: s.rttvar_ms ?? "—" }),
      el("td", { class: "num", text: s.timeout_ms }),
    ]));
  }
}

/* ------------------------------------------------------------------ */
/* Sekcja: okno zatłoczenia                                            */
/* ------------------------------------------------------------------ */

function renderCwnd() {
  const res = pyCall("cwnd_trace", {
    events: $("c-events").value,
    template: Number($("c-template").value),
  });

  const steps = res.steps;
  const chart = lineChart(
    [
      { name: "ssthresh", color: COL.ssthresh, points: steps.map((s) => ({ x: s.n, y: s.ssthresh })), dashed: true, width: 1.4 },
      { name: "cwnd", color: COL.cwnd, points: steps.map((s) => ({ x: s.n, y: s.cwnd })), width: 2.2 },
    ],
    { xLabel: "zdarzenie", label: "Przebieg okna zatłoczenia" }
  );

  const box = $("c-chart");
  clear(box);
  box.append(chart);

  const p = res.perf;
  const peak = Math.max(...steps.map((s) => s.cwnd));
  $("c-meta").textContent =
    `${p.template}: start cwnd ${p.initial_cwnd}, ssthresh ${p.initial_ssthresh}, ` +
    `ca_incr ${p.ca_incr}, dzielnik ssthresh ${p.ssthresh_divisor}, max ${p.max_cwnd}. ` +
    `Szczyt w tym przebiegu: ${peak.toFixed(1)}.`;

  const tbody = $("c-steps");
  clear(tbody);
  for (const s of steps) {
    tbody.append(el("tr", {}, [
      el("td", { class: "num", text: s.n }),
      el("td", { text: s.event }),
      el("td", { class: "num", text: s.cwnd.toFixed(2) }),
      el("td", { class: "num", text: s.ssthresh }),
      el("td", { class: "note", text: s.phase }),
    ]));
  }
}

/* ------------------------------------------------------------------ */
/* Sekcja: parsery                                                     */
/* ------------------------------------------------------------------ */

function renderPorts() {
  const res = pyCall("parse_ports", { spec: $("pp-spec").value });
  const box = $("pp-out");
  clear(box);

  if (!res.ok) {
    box.append(el("div", { class: "err", text: res.error }));
    return;
  }

  box.append(el("p", {
    class: "meta",
    text: `${res.count} portów${res.truncated ? ` (pokazuję pierwsze ${res.ports.length})` : ""}`,
  }));

  const table = el("table", {}, [
    el("thead", {}, el("tr", {}, [
      el("th", { text: "port" }), el("th", { text: "usługa" }),
    ])),
  ]);
  const tbody = el("tbody");
  for (const p of res.ports) {
    tbody.append(el("tr", {}, [
      el("td", { class: "num", text: p.port }),
      el("td", { class: "t-mono", text: p.service }),
    ]));
  }
  table.append(tbody);
  box.append(el("div", { class: "scroll-y" }, table));
}

function renderTargets() {
  const res = pyCall("parse_targets", { spec: $("tt-spec").value });
  const box = $("tt-out");
  clear(box);

  if (!res.ok) {
    box.append(el("div", { class: "err", text: res.error }));
    return;
  }

  box.append(el("p", {
    class: "meta",
    text: `${res.count} celów${res.truncated ? ` (pokazuję pierwsze ${res.targets.length})` : ""}`,
  }));
  box.append(el("div", { class: "scroll-y hexdump" },
    el("div", { text: res.targets.join("\n"), style: "white-space:pre" })));
}

/* ------------------------------------------------------------------ */
/* Sekcja: wyniki realnego skanu z CI                                  */
/* ------------------------------------------------------------------ */

async function renderCi() {
  const box = $("ci-out");
  let data;

  try {
    const res = await fetch("data/latest-scan.json", { cache: "no-cache" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data = await res.json();
  } catch (err) {
    clear(box);
    box.append(el("p", { class: "meta" }, [
      "Brak zapisanego wyniku skanu. Pojawi się tutaj po pierwszym przebiegu ",
      el("a", {
        href: "https://github.com/damiantomczyszyn/pynmap-basic/actions",
        text: "GitHub Actions",
      }),
      ".",
    ]));
    console.info("latest-scan.json niedostępny:", err.message);
    return;
  }

  clear(box);

  const when = data.generated_at
    ? new Date(data.generated_at * 1000).toLocaleString("pl-PL")
    : "nieznana data";

  const head = el("p", { class: "meta" }, [
    `commit ${data.git_sha || "?"} · ${when} · `,
    data.passed ? "wszystkie porty zgodne z oczekiwaniami" : "wystąpiły rozbieżności",
  ]);
  if (data.run_url) {
    head.append(" · ", el("a", { href: data.run_url, text: "przebieg w Actions" }));
  }
  box.append(head);

  for (const scan of data.scans || []) {
    box.append(el("h3", {
      class: "t-mono",
      style: "margin:1.2rem 0 0.4rem;font-size:1rem;font-weight:600",
      text: `-${scan.scan} · ${scan.elapsed_s} s · ${scan.probes_sent} sond, ${scan.replies_received} odpowiedzi`,
    }));

    const table = el("table", {}, [
      el("thead", {}, el("tr", {}, [
        el("th", { text: "host" }), el("th", { text: "port" }),
        el("th", { text: "usługa" }), el("th", { text: "stan" }),
        el("th", { text: "powód" }), el("th", { text: "RTT" }),
      ])),
    ]);
    const tbody = el("tbody");
    for (const r of scan.rows || []) {
      tbody.append(el("tr", {}, [
        el("td", { class: "t-mono", text: r.host }),
        el("td", { class: "num", text: r.port }),
        el("td", { class: "t-mono", text: r.service }),
        el("td", { class: `t-mono state-${r.state}`, text: r.state }),
        el("td", { class: "note", text: r.reason + (r.reason_ttl ? ` ttl ${r.reason_ttl}` : "") }),
        el("td", { class: "num", text: r.rtt_us ? `${(r.rtt_us / 1000).toFixed(2)} ms` : "—" }),
      ]));
    }
    table.append(tbody);
    box.append(table);
  }
}

/* ------------------------------------------------------------------ */
/* Podłączenie zdarzeń                                                 */
/* ------------------------------------------------------------------ */

function debounce(fn, ms) {
  let t;
  return (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
}

function wireUp() {
  const packetInputs = ["p-src", "p-dst", "p-sport", "p-dport", "p-window", "p-ttl", "p-mss"];
  const repaint = debounce(renderPacket, 120);
  for (const id of packetInputs) {
    $(id).addEventListener("input", repaint);
    $(id).addEventListener("change", repaint);
  }

  $("r-run").addEventListener("click", renderRtt);
  $("r-template").addEventListener("change", renderRtt);
  $("r-samples").addEventListener("input", debounce(renderRtt, 250));
  $("r-spike").addEventListener("click", () => {
    const field = $("r-samples");
    field.value = `${field.value.trim().replace(/,$/, "")}, 1800, 215, 210`;
    renderRtt();
  });

  $("c-run").addEventListener("click", renderCwnd);
  $("c-template").addEventListener("change", renderCwnd);
  $("c-events").addEventListener("input", debounce(renderCwnd, 250));
  $("c-drop").addEventListener("click", () => {
    const field = $("c-events");
    field.value = `${field.value.trim()}daaaaaaaaaa`;
    renderCwnd();
  });

  $("pp-spec").addEventListener("input", debounce(renderPorts, 200));
  $("tt-spec").addEventListener("input", debounce(renderTargets, 200));

  renderPacket();
  renderRtt();
  renderCwnd();
  renderPorts();
  renderTargets();
  renderCi();
}

window.addEventListener("DOMContentLoaded", boot);
