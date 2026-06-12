# Building standalone artifacts

The canonical, recommended distribution is the **`.py` script** (auditable,
runs everywhere `.eml` analysis needs only the stdlib). The helpers here build
portable artifacts for analysts who don't have Python.

## `.pyz` — portable, AV-friendly (recommended)

A native Python zipapp: a single portable file that is **not** heuristically flagged by antivirus the way a packed `.exe` is. Bundling `oletools` makes it ~30 MB; for a near-stdlib build, omit the optional deps.

```bash
build/build.sh pyz          # Linux/macOS
build\build.ps1 -Target pyz # Windows
# run: python ZavetSec-MailInspector.pyz message.eml -o report.html
```

Requires Python on the target host.

## `.exe` — no Python required (internal use)

```bash
build/build.sh exe          # Linux (cross-build not supported; build on Windows for Windows)
build\build.ps1             # Windows -> dist\ZavetSec-MailInspector.exe
```

> An unsigned single-file PyInstaller binary unpacks an interpreter at runtime,
> which AV/EDR heuristics frequently flag (false positive). Recommended handling:
> **allowlist the build by SHA-256** in your endpoint policy rather than shipping
> it publicly. `build.ps1` prints the SHA-256 after a successful build.

`--collect-submodules` for `oletools` and `extract_msg` is required — both load
modules dynamically, and onefile builds fail at runtime without it.
