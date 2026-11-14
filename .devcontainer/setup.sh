#!/usr/bin/env bash
# Przygotowanie środowiska w Codespaces / dev containerze.
set -euo pipefail

echo "==> Instalacja zależności deweloperskich"
pip install --upgrade pip
pip install -e ".[dev]"

echo "==> Narzędzia systemowe (nmap dla porównań, build-essential dla wersji C)"
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential nmap >/dev/null

echo "==> Build wersji C"
make -C c_reference clean >/dev/null 2>&1 || true
make -C c_reference

echo "==> Czy raw sockety są dostępne?"
if python3 -c "
import socket, sys
try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP).close()
except PermissionError:
    sys.exit(1)
" 2>/dev/null; then
    RAW="dostępne jako obecny użytkownik"
elif sudo python3 -c "
import socket, sys
try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP).close()
except PermissionError:
    sys.exit(1)
" 2>/dev/null; then
    RAW="dostępne przez sudo (uruchamiaj -sS z sudo)"
else
    RAW="NIEDOSTĘPNE — działa tylko -sT"
fi

cat <<INFO

======================================================================
 pynmap-basic — środowisko gotowe
======================================================================

 Raw sockety: $RAW
 nmap systemowy: $(nmap --version 2>/dev/null | head -1 || echo "brak")

 Szybki start:

   python3 -m pytest tests/ -q          # 133 testy
   python3 -m pynmap --help

   # skan loopbacku (bezpieczny, zawsze dozwolony)
   python3 -m pynmap -sT -p 1-1024 --open 127.0.0.1
   sudo python3 -m pynmap -sS -p 1-1024 --open 127.0.0.1

   # realny test sieciowy na kontenerze, przez mostek docker0
   docker run -d --name cel nginx:alpine
   IP=\$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cel)
   sudo python3 -m pynmap -sS -p 22,80,443,6379 --reason "\$IP"

   # porównanie z oryginałem i z wersją C
   nmap -sT -p 22,80,443 127.0.0.1
   ./c_reference/connect_scan 127.0.0.1 22,80,443 --reason

 Skanuj tylko to, co Twoje albo na co masz zgodę.

======================================================================
INFO
