#!/usr/bin/env python3
"""
Składa katalog strony do publikacji.

Źródła Pythona nie są kopiowane jako pliki .py, a wstrzykiwane do
`modules.js` jako napisy. Trzy powody:

  * niektóre hostingi statyczne nie serwują .py w ogóle,
  * jedno żądanie zamiast ośmiu,
  * strona działa też z file:// (fetch na file:// blokuje CORS).

Do przeglądarki trafia wyłącznie warstwa algorytmiczna. Moduły
scan_connect i scan_syn wymagają socketów, których tam nie ma, więc
celowo ich tu nie ma — razem z pakietowym __init__.py, który je importuje.

Użycie: python3 web/build_site.py site/ [--scan wynik.json]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BROWSER_SAFE_MODULES = (
    "constants",
    "timing",
    "ports",
    "services",
    "targets",
    "tcpip",
)

STATIC_FILES = ("index.html", "app.js")


def build(out_dir: Path, scan_json: Path | None = None) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. statyczne pliki strony
    for name in STATIC_FILES:
        src = ROOT / "web" / name
        if not src.is_file():
            print(f"build_site: brak {src}", file=sys.stderr)
            return 1
        shutil.copy2(src, out_dir / name)

    # 2. źródła Pythona jako modules.js
    sources: dict[str, str] = {}
    for module in BROWSER_SAFE_MODULES:
        path = ROOT / "pynmap" / f"{module}.py"
        if not path.is_file():
            print(f"build_site: brak modułu {path}", file=sys.stderr)
            return 1
        sources[f"pynmap/{module}.py"] = path.read_text(encoding="utf-8")

    bridge = ROOT / "web" / "bridge.py"
    if not bridge.is_file():
        print(f"build_site: brak {bridge}", file=sys.stderr)
        return 1
    sources["bridge.py"] = bridge.read_text(encoding="utf-8")

    # Pakietowy __init__ celowo pusty — prawdziwy importuje scan_connect
    # i scan_syn, które w przeglądarce nie mają jak działać.
    sources["pynmap/__init__.py"] = ""

    banner = (
        "/* Wygenerowane przez web/build_site.py — nie edytuj ręcznie.\n"
        " * Źródła Pythona wstrzyknięte jako napisy, żeby strona działała\n"
        " * też tam, gdzie hosting nie serwuje plików .py.\n"
        " */\n"
    )
    (out_dir / "modules.js").write_text(
        f"{banner}window.PYNMAP_SOURCES = {json.dumps(sources, ensure_ascii=False, indent=0)};\n",
        encoding="utf-8",
    )

    # 3. opcjonalny wynik realnego skanu z CI
    data_dir = out_dir / "data"
    data_dir.mkdir(exist_ok=True)
    if scan_json and scan_json.is_file():
        shutil.copy2(scan_json, data_dir / "latest-scan.json")
        print(f"build_site: dołączony wynik skanu z {scan_json}")
    else:
        print("build_site: bez wyniku skanu — strona pokaże odnośnik do Actions")

    # 4. Pages domyślnie przepuszcza treść przez Jekylla
    (out_dir / ".nojekyll").touch()

    total = sum(len(s) for s in sources.values())
    print(f"build_site: {len(sources)} modułów, {total / 1024:.1f} KB źródeł Pythona")
    for path in sorted(p for p in out_dir.rglob("*") if p.is_file()):
        print(f"  {path.relative_to(out_dir)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path, help="katalog wyjściowy")
    parser.add_argument("--scan", type=Path, help="JSON z wynikiem skanu z CI")
    args = parser.parse_args()
    return build(args.out, args.scan)


if __name__ == "__main__":
    sys.exit(main())
