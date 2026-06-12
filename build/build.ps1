# ZavetSec-MailInspector Windows build helper
# Usage: build\build.ps1 [-Target pyz|exe|clean]
param([ValidateSet('pyz','exe','clean')][string]$Target = 'exe')

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$Src  = 'ZavetSec-MailInspector.py'
$Name = 'ZavetSec-MailInspector'

switch ($Target) {
  'pyz' {
    Write-Host '[*] Building portable .pyz (zipapp, AV-friendly)...'
    Remove-Item -Recurse -Force build\deps -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force build\deps | Out-Null
    pip install --target build\deps extract-msg oletools requests py7zr -q
    Copy-Item $Src build\deps\__main__.py -Force
    python -m zipapp build\deps -p 'python' -o "$Name.pyz"
    Write-Host "[+] Done: $Name.pyz"
  }
  'exe' {
    Write-Host '[*] Building single-file .exe (PyInstaller)...'
    Write-Host '    NOTE: unsigned exe is often flagged by AV/EDR — allowlist by SHA-256.'
    pip install pyinstaller extract-msg oletools requests py7zr -q
    pyinstaller --onefile --name $Name `
      --hidden-import oletools.olevba --hidden-import extract_msg `
      --collect-submodules oletools --collect-submodules extract_msg `
      $Src
    $exe = "dist\$Name.exe"
    Write-Host "[+] Done: $exe"
    if (Test-Path $exe) {
      $h = (Get-FileHash $exe -Algorithm SHA256).Hash
      Write-Host "    SHA-256: $h"
      Write-Host '    -> add this hash to your EDR allowlist before deploying.'
    }
  }
  'clean' {
    Remove-Item -Recurse -Force build\deps,dist,*.spec,*.pyz,*.exe -ErrorAction SilentlyContinue
    Write-Host '[+] Cleaned.'
  }
}
