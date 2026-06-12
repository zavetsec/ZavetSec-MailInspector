#!/usr/bin/env bash
# ZavetSec-MailInspector build helper
# Usage: build/build.sh [pyz|exe|clean]
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="ZavetSec-MailInspector.py"
NAME="ZavetSec-MailInspector"

build_pyz() {
  echo "[*] Building portable .pyz (zipapp, AV-friendly)..."
  rm -rf build/deps && mkdir -p build/deps
  pip install --target build/deps extract-msg oletools requests py7zr -q
  cp "$SRC" build/deps/__main__.py
  python3 -m zipapp build/deps -p "/usr/bin/env python3" -o "${NAME}.pyz"
  echo "[+] Done: ${NAME}.pyz"
  echo "    Run: python ${NAME}.pyz message.eml -o report.html"
}

build_exe() {
  echo "[*] Building single-file .exe (PyInstaller)..."
  echo "    NOTE: unsigned exe is often flagged by AV/EDR — allowlist by SHA-256."
  pip install pyinstaller extract-msg oletools requests py7zr -q
  pyinstaller --onefile --name "$NAME" \
    --hidden-import oletools.olevba --hidden-import extract_msg \
    --collect-submodules oletools --collect-submodules extract_msg \
    "$SRC"
  echo "[+] Done: dist/${NAME}"
}

case "${1:-pyz}" in
  pyz) build_pyz ;;
  exe) build_exe ;;
  clean) rm -rf build/deps dist *.spec *.pyz *.exe; echo "[+] Cleaned." ;;
  *) echo "Usage: $0 [pyz|exe|clean]"; exit 1 ;;
esac
