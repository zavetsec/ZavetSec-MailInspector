#!/usr/bin/env bash
# ZavetSec-MailInspector — хелпер сборки
# Использование: build/build.sh [pyz|exe|clean]
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="ZavetSec-MailInspector.py"
NAME="ZavetSec-MailInspector"

build_pyz() {
  echo "[*] Сборка портативного .pyz (zipapp, дружелюбный к AV)..."
  rm -rf build/deps && mkdir -p build/deps
  pip install --target build/deps extract-msg oletools requests py7zr opencv-python-headless pymupdf -q
  cp "$SRC" build/deps/__main__.py
  python3 -m zipapp build/deps -p "/usr/bin/env python3" -o "${NAME}.pyz"
  echo "[+] Готово: ${NAME}.pyz"
  echo "    Запуск: python ${NAME}.pyz message.eml -o report.html"
}

build_exe() {
  echo "[*] Сборка однофайлового .exe (PyInstaller)..."
  echo "    ПРИМЕЧАНИЕ: неподписанный exe часто флагается AV/EDR — allowlist по SHA-256."
  pip install pyinstaller extract-msg oletools requests py7zr opencv-python-headless pymupdf -q
  pyinstaller --onefile --name "$NAME" \
    --hidden-import oletools.olevba --hidden-import extract_msg \
    --collect-submodules oletools --collect-submodules extract_msg \
    "$SRC"
  echo "[+] Готово: dist/${NAME}"
}

case "${1:-pyz}" in
  pyz) build_pyz ;;
  exe) build_exe ;;
  clean) rm -rf build/deps dist *.spec *.pyz *.exe; echo "[+] Очищено." ;;
  *) echo "Usage: $0 [pyz|exe|clean]"; exit 1 ;;
esac
