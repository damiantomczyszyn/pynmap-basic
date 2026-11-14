"""
Konfiguracja pytest.

web/bridge.py nie jest częścią pakietu pynmap (ładuje go przeglądarka przez
Pyodide), więc dokładamy katalog web/ do sys.path tutaj. Dzięki temu testy
mogą importować `bridge` normalnie, na górze pliku, bez sys.path.insert
w środku modułu.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

for path in (ROOT, ROOT / "web"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
