# Changelog

All notable changes to ZavetSec-MailInspector are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

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
