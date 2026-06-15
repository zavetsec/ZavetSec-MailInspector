# ZavetSec-MailInspector — хелпер сборки для Windows
# Использование: build\build.ps1 [-Target pyz|exe|clean]
param([ValidateSet('pyz','exe','clean')][string]$Target = 'exe')

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$Src  = 'ZavetSec-MailInspector.py'
$Name = 'ZavetSec-MailInspector'

switch ($Target) {
  'pyz' {
    Write-Host '[*] Сборка портативного .pyz (zipapp, дружелюбный к AV)...'
    Remove-Item -Recurse -Force build\deps -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force build\deps | Out-Null
    pip install --target build\deps extract-msg oletools requests py7zr opencv-python-headless pymupdf -q
    Copy-Item $Src build\deps\__main__.py -Force
    python -m zipapp build\deps -p 'python' -o "$Name.pyz"
    Write-Host "[+] Готово: $Name.pyz"
  }
  'exe' {
    Write-Host '[*] Сборка однофайлового .exe (PyInstaller)...'
    Write-Host '    ПРИМЕЧАНИЕ: неподписанный exe часто флагается AV/EDR — allowlist по SHA-256.'
    pip install pyinstaller extract-msg oletools requests py7zr opencv-python-headless pymupdf -q
    pyinstaller --onefile --name $Name `
      --hidden-import oletools.olevba --hidden-import extract_msg `
      --collect-submodules oletools --collect-submodules extract_msg `
      $Src
    $exe = "dist\$Name.exe"
    Write-Host "[+] Готово: $exe"
    if (Test-Path $exe) {
      $h = (Get-FileHash $exe -Algorithm SHA256).Hash
      Write-Host "    SHA-256: $h"
      Write-Host '    -> добавьте этот хэш в allowlist EDR перед развёртыванием.'
    }
  }
  'clean' {
    Remove-Item -Recurse -Force build\deps,dist,*.spec,*.pyz,*.exe -ErrorAction SilentlyContinue
    Write-Host '[+] Очищено.'
  }
}
