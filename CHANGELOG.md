# Changelog

All notable changes to ZavetSec-MailInspector are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [1.2] — 2026-06-12

### Added
- **Recursive archive analysis** — nested archive contents are extracted and
  re-scanned with the full detector pass (true type, dangerous/double extension,
  exec-as-document, entropy, macros, nested protection). Nested file hashes are
  added to the IOC list and shown as a path tree in the report.
  - ZIP / TAR / GZIP extracted **in memory** (stdlib); 7z / RAR via optional
    `py7zr` / `rarfile`. OOXML documents are not treated as containers.
- **Zip-bomb / resource guards** — depth (3), file-count (500), per-file (64 MB)
  and total (256 MB) budgets, plus a compression-ratio check. A suspected
  decompression bomb is reported and extraction is halted, not detonated.
  In-memory extraction also avoids path-traversal (zip-slip).
- Report attachment table now shows nested files as an indented path tree.

### Optional dependencies
- `py7zr` — recurse into 7-Zip archives.
- `rarfile` — recurse into RAR archives (also improves RAR encryption detection).

## [1.1] — 2026-06-12

### Added
- **Context-aware attachment entropy** (Shannon, bits/byte). High entropy is only
  flagged where it is *unexpected*: packed/obfuscated executables and "document"
  types that are really opaque blobs. Inherently high-entropy formats
  (ZIP/OOXML/PNG/JPEG/PDF/archives) do not raise false positives.
- **Password-protected archive detection** for ZIP (incl. WinZip-AES), RAR4,
  RAR5 (header encryption) and 7-Zip (AES coder), with graceful best-effort
  handling and zero false positives on OOXML.
- **Body-password correlation** — an encrypted archive whose password appears in
  the e-mail body is escalated to HIGH (classic AV/sandbox-evasion malspam).
- Entropy and protection surfaced in the HTML report table and JSON output.

### Optional dependency
- `rarfile` — improves RAR coverage (RAR4 detection works without it).

## [1.0] — 2026-06-12

### Added
- Initial public release.
- `.eml` (RFC822) and `.msg` (Outlook) parsing.
- Authentication analysis: SPF / DKIM / DMARC, `Received` chain, originating IP.
- Sender spoofing: From/Return-Path/Reply-To mismatch, display-name foreign address,
  brand impersonation, Message-ID domain mismatch.
- URL analysis: link spoofing, IP-literal hosts, `user:pass@` obfuscation,
  punycode/IDN and mixed-script homoglyphs, shorteners, suspicious TLDs,
  brand-in-subdomain, dangerous URI schemes.
- Body analysis: bilingual (EN/RU) social-engineering scoring, tracking pixels,
  hidden text, in-body HTML forms.
- Attachment analysis: MD5/SHA-1/SHA-256, magic-byte true-type vs extension,
  dangerous & double extensions, VBA macro detection (oletools), archive flagging.
- Optional online threat-intel (MalwareBazaar + ThreatFox) behind `--online`.
- Self-contained HTML report (zero external references), JSON output, colored console.
- Risk scoring with per-category diminishing returns; verdict thresholds.
- Directory recursion; exit codes reflecting worst verdict.
