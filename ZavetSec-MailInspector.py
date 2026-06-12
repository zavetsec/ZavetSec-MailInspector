#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 ZavetSec-MailInspector  v1.0
 Phishing & malware triage for .eml / .msg e-mail files
--------------------------------------------------------------------------------
 Defensive DFIR / SOC tool. Parses raw e-mail (RFC822 .eml and Outlook .msg),
 analyzes authentication (SPF/DKIM/DMARC), sender spoofing, URLs, body social
 engineering, and attachments (true file type, dangerous extensions, Office
 macros, hashes). Extracts IOCs, scores risk and renders a self-contained
 HTML report. Optional offline-by-default threat-intel enrichment.

 Online enrichment (MalwareBazaar / ThreatFox) is OFF unless --online is passed.
 No external resources are referenced by the HTML report (air-gap / OPSEC safe).
================================================================================
"""

import argparse
import base64
import datetime
import email
import email.policy
import email.utils
import hashlib
import html as html_lib
import json
import os
import re
import sys
import unicodedata
from collections import defaultdict
from email.parser import BytesParser

# --------------------------------------------------------------------------- #
#  Optional dependencies (graceful degradation)
# --------------------------------------------------------------------------- #
try:
    import extract_msg  # type: ignore
    HAVE_EXTRACT_MSG = True
except Exception:
    HAVE_EXTRACT_MSG = False

try:
    from oletools.olevba import VBA_Parser  # type: ignore
    HAVE_OLEVBA = True
except Exception:
    HAVE_OLEVBA = False

try:
    import requests  # type: ignore
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

VERSION = "1.0"

# --------------------------------------------------------------------------- #
#  Severity model
# --------------------------------------------------------------------------- #
SEV_INFO, SEV_LOW, SEV_MED, SEV_HIGH, SEV_CRIT = "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
SEV_WEIGHT = {SEV_INFO: 0, SEV_LOW: 5, SEV_MED: 15, SEV_HIGH: 30, SEV_CRIT: 55}
SEV_ORDER = {SEV_INFO: 0, SEV_LOW: 1, SEV_MED: 2, SEV_HIGH: 3, SEV_CRIT: 4}

# --------------------------------------------------------------------------- #
#  Knowledge bases
# --------------------------------------------------------------------------- #
DANGEROUS_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf",
    "wsh", "ps1", "psm1", "msi", "msp", "hta", "cpl", "jar", "lnk", "reg", "inf",
    "scf", "gadget", "application", "msc", "ws", "vb", "vbscript", "sct", "shb",
    "iso", "img", "vhd", "vhdx", "udf", "cab", "ace", "appx", "appref-ms", "url",
    "settingcontent-ms", "library-ms", "diagcab", "py", "pyc", "sh", "elf", "apk",
    "xll", "wll", "ppam", "xlam", "docm", "xlsm", "pptm", "dotm", "xltm", "potm",
    "one", "onepkg", "chm", "mht", "mhtml", "svg",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "ppam", "xls", "doc", "ppt"}
ARCHIVE_EXT = {"zip", "rar", "7z", "tar", "gz", "bz2", "iso", "img", "cab", "ace", "udf"}

# Magic bytes -> (label, treat_as_executable_family)
MAGIC = [
    (b"MZ", "PE/DOS executable (EXE/DLL)", True),
    (b"\x7fELF", "ELF executable", True),
    (b"\xfe\xed\xfa\xce", "Mach-O executable", True),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64 executable", True),
    (b"\xca\xfe\xba\xbe", "Mach-O FAT / Java class", True),
    (b"%PDF", "PDF document", False),
    (b"PK\x03\x04", "ZIP / OOXML / JAR / APK", False),
    (b"PK\x05\x06", "ZIP (empty)", False),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (legacy Office / MSI / MSG)", False),
    (b"{\\rtf", "RTF document", False),
    (b"Rar!\x1a\x07", "RAR archive", False),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", False),
    (b"\x1f\x8b", "GZIP archive", False),
    (b"BZh", "BZIP2 archive", False),
    (b"MSCF", "Microsoft Cabinet (CAB)", False),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows Shortcut (LNK)", True),
    (b"ITSF", "Compiled HTML Help (CHM)", False),
    (b"\x4c\x00\x00\x00", "Windows Shortcut (LNK?)", True),
    (b"<!DOCTYPE", "HTML document", False),
    (b"<html", "HTML document", False),
    (b"<?xml", "XML / SVG document", False),
]

EXT_FOR_MAGIC = {
    "PE/DOS executable (EXE/DLL)": {"exe", "dll", "scr", "com", "cpl", "ocx", "sys", "drv"},
    "ELF executable": {"elf", "so", "bin", "o"},
    "PDF document": {"pdf"},
    "ZIP / OOXML / JAR / APK": {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm",
                               "jar", "apk", "odt", "ods", "odp", "epub", "vsdx", "kmz",
                               "dotx", "xltx", "potx", "thmx", "xlam", "ppam"},
    "OLE2 (legacy Office / MSI / MSG)": {"doc", "xls", "ppt", "msi", "msg", "dot", "xla",
                                         "pps", "vsd", "db", "mdb"},
    "RTF document": {"rtf", "doc"},
    "RAR archive": {"rar"},
    "7-Zip archive": {"7z"},
    "GZIP archive": {"gz", "tgz", "gzip"},
    "Microsoft Cabinet (CAB)": {"cab"},
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "bl.ink",
    "clck.ru", "vk.cc", "u.to", "qps.ru", "to.click", "lnkd.in", "surl.li",
}

# Cheap / heavily-abused TLDs (heuristic, weighted low to avoid over-flagging)
SUSPICIOUS_TLD = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "link", "country", "kim", "science", "party", "gdn", "review", "stream",
    "loan", "download", "racing", "win", "bid", "date", "men", "rest", "fit",
    "cam", "monster", "icu", "cyou", "sbs", "lol", "quest", "autos", "su",
}

# Brand keywords for display-name / lookalike impersonation (EN + RU/CIS)
BRANDS = [
    "microsoft", "office365", "office 365", "outlook", "onedrive", "sharepoint",
    "windows", "azure", "google", "gmail", "apple", "icloud", "amazon", "aws",
    "paypal", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
    "dropbox", "docusign", "adobe", "fedex", "dhl", "ups", "usps", "ebay",
    "binance", "coinbase", "metamask", "telegram", "github", "gitlab",
    "sberbank", "sber", "tinkoff", "alfabank", "alfa", "vtb", "gosuslugi",
    "yandex", "mail.ru", "kaspi", "halyk", "wildberries", "ozon", "cdek",
    "pochta", "nalog", "fns", "mvd", "rosreestr", "kaspersky",
]

SE_KEYWORDS = [
    # English
    "urgent", "immediately", "verify your account", "verify your identity",
    "confirm your account", "suspended", "suspension", "unusual activity",
    "unusual sign-in", "security alert", "password expire", "reset your password",
    "update your payment", "billing problem", "invoice attached", "click here",
    "act now", "limited time", "final notice", "your account will be",
    "unauthorized", "locked", "validate", "re-activate", "reactivate",
    "wire transfer", "gift card", "bitcoin", "cryptocurrency", "payment failed",
    "confirm payment", "you have won", "claim your", "tax refund", "refund",
    "voicemail", "fax", "shared a document", "view document", "secure message",
    # Russian / CIS
    "срочно", "немедленно", "подтвердите", "подтвердить", "ваш аккаунт",
    "учётная запись", "учетная запись", "заблокирован", "блокировка",
    "подозрительн", "вход в аккаунт", "сменить пароль", "сбросить пароль",
    "обновите данные", "проблема с оплатой", "счёт во вложении", "счет на оплату",
    "нажмите здесь", "перейдите по ссылке", "ограниченное время", "последнее уведомление",
    "несанкционированн", "верифик", "подтверждение оплаты", "вы выиграли",
    "получите", "возврат налога", "налоговая", "штраф", "задолженность",
    "перевод средств", "криптовалют", "биткоин", "госуслуги", "выплата",
]

# Confusable-script detection: which scripts a codepoint belongs to
def _char_scripts(s):
    scripts = set()
    for ch in s:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            if "CYRILLIC" in name:
                scripts.add("Cyrillic")
            elif "GREEK" in name:
                scripts.add("Greek")
            elif "LATIN" in name:
                scripts.add("Latin")
            elif "ARMENIAN" in name:
                scripts.add("Armenian")
            else:
                scripts.add("Other")
    return scripts


# --------------------------------------------------------------------------- #
#  Result container
# --------------------------------------------------------------------------- #
class Finding:
    __slots__ = ("category", "severity", "title", "detail")

    def __init__(self, category, severity, title, detail=""):
        self.category = category
        self.severity = severity
        self.title = title
        self.detail = detail

    def as_dict(self):
        return {"category": self.category, "severity": self.severity,
                "title": self.title, "detail": self.detail}


class MailReport:
    def __init__(self, path):
        self.path = path
        self.filename = os.path.basename(path)
        self.kind = ""            # eml / msg
        self.headers = {}         # selected header fields
        self.from_addr = ""
        self.from_name = ""
        self.return_path = ""
        self.reply_to = ""
        self.to = ""
        self.subject = ""
        self.date = ""
        self.message_id = ""
        self.auth = {"spf": "", "dkim": "", "dmarc": ""}
        self.hops = []
        self.findings = []
        self.urls = []           # list of dicts: text, href, host
        self.attachments = []    # list of dicts
        self.iocs = {"domains": set(), "ips": set(), "urls": set(),
                     "emails": set(), "hashes": set()}
        self.score = 0
        self.verdict = "CLEAN"
        self.error = ""

    def add(self, category, severity, title, detail=""):
        self.findings.append(Finding(category, severity, title, detail))


# --------------------------------------------------------------------------- #
#  Parsing
# --------------------------------------------------------------------------- #
def parse_eml(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=email.policy.default).parse(fh)
    return msg


def _decode_header(value):
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def load_email(path, rep):
    ext = path.lower().rsplit(".", 1)[-1] if "." in path else ""
    if ext == "msg":
        rep.kind = "msg"
        if not HAVE_EXTRACT_MSG:
            rep.error = ("Файл .msg требует библиотеки 'extract-msg' "
                         "(pip install extract-msg). Анализ невозможен.")
            return None
        return _load_msg(path, rep)
    rep.kind = "eml"
    msg = parse_eml(path)
    _extract_common_from_eml(msg, rep)
    return msg


def _extract_common_from_eml(msg, rep):
    raw_from = _decode_header(msg.get("From"))
    name, addr = email.utils.parseaddr(raw_from)
    rep.from_name = name
    rep.from_addr = addr.lower()
    rep.return_path = email.utils.parseaddr(_decode_header(msg.get("Return-Path")))[1].lower()
    rep.reply_to = email.utils.parseaddr(_decode_header(msg.get("Reply-To")))[1].lower()
    rep.to = _decode_header(msg.get("To"))
    rep.subject = _decode_header(msg.get("Subject"))
    rep.date = _decode_header(msg.get("Date"))
    rep.message_id = _decode_header(msg.get("Message-ID"))
    rep.headers = {
        "X-Mailer": _decode_header(msg.get("X-Mailer")),
        "X-Originating-IP": _decode_header(msg.get("X-Originating-IP")),
        "User-Agent": _decode_header(msg.get("User-Agent")),
        "Content-Type": _decode_header(msg.get("Content-Type")),
    }
    # Authentication-Results
    authres = " ; ".join(
        _decode_header(v) for v in msg.get_all("Authentication-Results", [])
    )
    authres += " " + _decode_header(msg.get("Received-SPF") or "")
    rep.auth = _parse_auth(authres)
    # Received hops
    for r in msg.get_all("Received", []):
        rep.hops.append(_decode_header(r).replace("\n", " ").strip())
    rep.hops.reverse()  # origin first


def _parse_auth(authres):
    out = {"spf": "", "dkim": "", "dmarc": ""}
    low = authres.lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"=([a-z]+)", low)
        if m:
            out[mech] = m.group(1)
    return out


def _load_msg(path, rep):
    """Wrap extract_msg output to behave enough like an email.Message for the
    rest of the pipeline; returns a lightweight shim object."""
    m = extract_msg.Message(path)
    rep.from_name, rep.from_addr = email.utils.parseaddr(m.sender or "")
    rep.from_addr = rep.from_addr.lower()
    rep.to = m.to or ""
    rep.subject = m.subject or ""
    rep.date = str(m.date or "")
    rep.message_id = getattr(m, "messageId", "") or ""
    # transport headers carry SPF/DKIM/Received for received mail
    th = ""
    try:
        th = m.header.as_string() if m.header else ""
    except Exception:
        th = ""
    if th:
        rep.auth = _parse_auth(th)
        rt = re.search(r"Return-Path:\s*<?([^>\r\n]+)>?", th, re.I)
        if rt:
            rep.return_path = rt.group(1).strip().lower()
        for line in re.findall(r"^Received:.*(?:\r?\n[ \t].*)*", th, re.M | re.I):
            rep.hops.append(re.sub(r"\s+", " ", line).strip())
        rep.hops.reverse()
    rep.reply_to = ""  # extract_msg exposes reply-to inconsistently; skip
    rep.headers = {"Content-Type": "msg/outlook"}

    bodies = {"plain": m.body or "", "html": m.htmlBody or ""}
    if isinstance(bodies["html"], bytes):
        bodies["html"] = bodies["html"].decode("utf-8", "replace")

    atts = []
    for att in m.attachments:
        try:
            data = att.data
            if not isinstance(data, (bytes, bytearray)):
                # nested msg attachment
                data = b""
            fname = att.longFilename or att.shortFilename or "attachment.bin"
        except Exception:
            data, fname = b"", "attachment.bin"
        atts.append((fname, bytes(data) if data else b""))
    # stash for analyzer
    rep._msg_bodies = bodies
    rep._msg_atts = atts
    return m


# --------------------------------------------------------------------------- #
#  Body / URL extraction
# --------------------------------------------------------------------------- #
URL_RE = re.compile(r"""(?xi)\b((?:https?://|www\.)[^\s<>"'\]\)}]+)""")
HREF_RE = re.compile(r"""(?is)<a\b[^>]*?href\s*=\s*["']?([^"'>\s]+)[^>]*>(.*?)</a>""")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _strip_tags(s):
    return re.sub(r"<[^>]+>", " ", s)


def _host_of(url):
    u = url.strip()
    u = re.sub(r"^[a-z]+://", "", u, flags=re.I)
    u = u.split("/")[0].split("?")[0]
    if "@" in u:
        u = u.split("@")[-1]
    u = u.split(":")[0]
    return u.lower().strip(".")


def _registrable_tail(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def get_bodies(msg, rep):
    if rep.kind == "msg":
        return rep._msg_bodies.get("plain", ""), rep._msg_bodies.get("html", "")
    plain, html = "", ""
    if msg.is_multipart() or msg.get_content_maintype() == "text":
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                continue
            if ctype == "text/plain":
                try:
                    plain += part.get_content()
                except Exception:
                    pass
            elif ctype == "text/html":
                try:
                    html += part.get_content()
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_content()
            if msg.get_content_type() == "text/html":
                html = payload
            else:
                plain = str(payload)
        except Exception:
            pass
    return plain, html


def analyze_body(plain, html, rep):
    urls = []
    seen = set()

    # anchors from HTML: text vs href mismatch
    for href, anchor_html in HREF_RE.findall(html or ""):
        href = href.strip()
        if href.lower().startswith(("mailto:", "tel:", "#")):
            continue
        anchor_text = _strip_tags(anchor_html).strip()
        host = _host_of(href)
        urls.append({"text": anchor_text, "href": href, "host": host})
        seen.add(href)

    # bare URLs from text + html
    for blob in (plain or "", _strip_tags(html or "")):
        for m in URL_RE.findall(blob):
            u = m.rstrip(".,);]")
            if u not in seen:
                seen.add(u)
                urls.append({"text": "", "href": u, "host": _host_of(u)})

    rep.urls = urls

    # ---- URL-level findings ----
    from_dom = rep.from_addr.split("@")[-1] if "@" in rep.from_addr else ""
    for u in urls:
        href, host, text = u["href"], u["host"], u["text"]
        if not host:
            continue
        rep.iocs["urls"].add(href)
        rep.iocs["domains"].add(host)

        tail = host.rsplit(".", 1)[-1] if "." in host else ""

        # IP-literal URL
        if IP_RE.fullmatch(host):
            rep.add("URL", SEV_HIGH, "Ссылка ведёт на IP-адрес, а не на домен",
                    f"{href}")
            rep.iocs["ips"].add(host)

        # user:pass@ obfuscation
        if "@" in href.split("//", 1)[-1].split("/", 1)[0]:
            rep.add("URL", SEV_HIGH, "В URL присутствует символ '@' (сокрытие реального хоста)",
                    f"{href}")

        # punycode / IDN
        if "xn--" in host:
            rep.add("URL", SEV_HIGH, "Punycode/IDN-домен (возможен homograph-фишинг)",
                    f"{host}  ({href})")

        # mixed-script confusable
        scr = _char_scripts(host.replace(".", ""))
        if "Latin" in scr and ("Cyrillic" in scr or "Greek" in scr):
            rep.add("URL", SEV_HIGH, "Домен смешивает алфавиты (Latin + Cyrillic/Greek) — homoglyph",
                    f"{host}  ({href})")

        # shortener
        if _registrable_tail(host) in URL_SHORTENERS:
            rep.add("URL", SEV_MED, "Сокращатель ссылок (реальная цель скрыта)",
                    f"{href}")

        # suspicious TLD
        if tail in SUSPICIOUS_TLD:
            rep.add("URL", SEV_LOW, f"Подозрительный/дешёвый TLD .{tail}", f"{host}")

        # display vs href mismatch
        if text:
            t_host = _host_of(text) if ("." in text and " " not in text.strip()) else ""
            if t_host and t_host != host and not host.endswith("." + t_host) and not t_host.endswith("." + host):
                rep.add("URL", SEV_HIGH,
                        "Текст ссылки не совпадает с реальным адресом (link spoofing)",
                        f"показано: {text}  →  ведёт на: {href}")

        # excessive subdomains / brand in subdomain
        labels = host.split(".")
        if len(labels) >= 5:
            rep.add("URL", SEV_LOW, "Много поддоменов (обфускация хоста)", f"{host}")
        for b in BRANDS:
            bclean = b.replace(" ", "")
            if bclean in host.replace(".", "") and bclean not in _registrable_tail(host).replace(".", ""):
                rep.add("URL", SEV_MED, f"Бренд «{b}» в поддомене, но не в основном домене",
                        f"{host}")
                break

        # data: / javascript: URIs
        if href.lower().startswith(("data:", "javascript:", "vbscript:")):
            rep.add("URL", SEV_HIGH, "Опасная схема URI (data:/javascript:/vbscript:)",
                    f"{href[:120]}")

    # tracking pixels & hidden links
    if re.search(r'<img[^>]+(?:width|height)\s*=\s*["\']?[01]\b', html or "", re.I):
        rep.add("BODY", SEV_LOW, "Трекинг-пиксель (1x1 изображение)",
                "письмо отслеживает факт открытия")
    if re.search(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0", html or "", re.I):
        rep.add("BODY", SEV_LOW, "Скрытый текст в HTML (обход анти-спам фильтров)", "")
    if re.search(r"<form\b", html or "", re.I):
        rep.add("BODY", SEV_MED, "В письме есть HTML-форма (сбор данных прямо в письме)", "")

    # social engineering keywords
    corpus = ((plain or "") + " " + _strip_tags(html or "") + " " + rep.subject).lower()
    hits = sorted({kw for kw in SE_KEYWORDS if kw in corpus})
    if hits:
        sev = SEV_MED if len(hits) >= 3 else SEV_LOW
        sample = ", ".join(hits[:8])
        rep.add("BODY", sev, f"Триггеры социальной инженерии ({len(hits)})", sample)

    # IOC harvest from corpus
    for ip in IP_RE.findall(corpus):
        rep.iocs["ips"].add(ip)
    for em in EMAIL_RE.findall((plain or "") + " " + _strip_tags(html or "")):
        rep.iocs["emails"].add(em.lower())


# --------------------------------------------------------------------------- #
#  Header / sender analysis
# --------------------------------------------------------------------------- #
def analyze_headers(rep):
    fa = rep.from_addr
    from_dom = fa.split("@")[-1] if "@" in fa else ""
    if fa:
        rep.iocs["emails"].add(fa)
        if from_dom:
            rep.iocs["domains"].add(from_dom)

    # auth results
    spf, dkim, dmarc = rep.auth["spf"], rep.auth["dkim"], rep.auth["dmarc"]
    if spf in ("fail", "softfail"):
        rep.add("AUTH", SEV_HIGH if spf == "fail" else SEV_MED,
                f"SPF = {spf}", "адрес отправителя не авторизован в SPF домена")
    if dkim == "fail":
        rep.add("AUTH", SEV_MED, "DKIM = fail", "подпись DKIM не прошла проверку")
    if dmarc in ("fail",):
        rep.add("AUTH", SEV_HIGH, "DMARC = fail",
                "письмо не прошло политику DMARC отправляющего домена")
    if not any([spf, dkim, dmarc]):
        rep.add("AUTH", SEV_INFO, "Нет заголовков аутентификации",
                "SPF/DKIM/DMARC не обнаружены (или .msg без транспортных заголовков)")

    # Return-Path / From mismatch
    if rep.return_path and from_dom:
        rp_dom = rep.return_path.split("@")[-1]
        if rp_dom and rp_dom != from_dom and not rp_dom.endswith("." + from_dom) \
                and not from_dom.endswith("." + rp_dom):
            rep.add("HEADER", SEV_MED, "Return-Path не совпадает с From",
                    f"From: {from_dom}   Return-Path: {rp_dom}")

    # Reply-To / From mismatch
    if rep.reply_to and from_dom:
        rt_dom = rep.reply_to.split("@")[-1]
        if rt_dom and rt_dom != from_dom:
            rep.add("HEADER", SEV_MED, "Reply-To указывает на другой домен",
                    f"From: {fa}   Reply-To: {rep.reply_to}")

    # Display-name spoofing: name contains an email/domain different from real
    name = rep.from_name or ""
    name_emails = EMAIL_RE.findall(name)
    for ne in name_emails:
        if ne.lower() != fa:
            rep.add("HEADER", SEV_HIGH, "Display-name содержит чужой e-mail",
                    f"имя: «{name}»   реальный адрес: {fa}")
            break
    # brand in display name but not in domain
    low_name = name.lower()
    for b in BRANDS:
        if b in low_name and from_dom and b.replace(" ", "") not in from_dom.replace(".", ""):
            rep.add("HEADER", SEV_MED, f"Имя отправителя имитирует бренд «{b}»",
                    f"имя: «{name}»   домен: {from_dom}")
            break

    # Message-ID domain vs From domain
    if rep.message_id and from_dom:
        mid = re.search(r"@([^>]+)>?", rep.message_id)
        if mid:
            mid_dom = mid.group(1).strip(">").lower()
            base_from = _registrable_tail(from_dom)
            base_mid = _registrable_tail(mid_dom)
            if base_mid and base_from and base_mid != base_from:
                rep.add("HEADER", SEV_LOW, "Домен Message-ID не совпадает с From",
                        f"From: {from_dom}   Message-ID: {mid_dom}")

    # subject encoding / unicode tricks
    if rep.subject and _char_scripts(rep.subject) >= {"Latin", "Cyrillic"}:
        # only flag if it looks like an ASCII-word built from cyrillic chars is unlikely;
        # keep it INFO to avoid noise on legit bilingual subjects
        pass

    # originating IP
    xoip = rep.headers.get("X-Originating-IP", "")
    for ip in IP_RE.findall(xoip):
        rep.iocs["ips"].add(ip)


# --------------------------------------------------------------------------- #
#  Attachment analysis
# --------------------------------------------------------------------------- #
def _iter_attachments(msg, rep):
    if rep.kind == "msg":
        for fname, data in rep._msg_atts:
            yield fname, data
        return
    for part in msg.walk():
        disp = (part.get("Content-Disposition") or "").lower()
        ctype = part.get_content_type()
        is_att = "attachment" in disp or ("inline" in disp and part.get_filename())
        if not is_att and not part.get_filename():
            continue
        if ctype.startswith("multipart"):
            continue
        fname = part.get_filename() or "attachment.bin"
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        yield fname, data


def _detect_magic(data):
    head = data[:64]
    for sig, label, is_exec in MAGIC:
        if head.startswith(sig):
            return label, is_exec
    # OOXML disambiguation handled by caller; LNK ambiguous
    return "", False


def _scan_macros(data, fname):
    if not HAVE_OLEVBA:
        return None
    try:
        vp = VBA_Parser(filename=fname, data=data)
        if not vp.detect_vba_macros():
            vp.close()
            return {"has_macros": False, "autoexec": [], "suspicious": []}
        autoexec, suspicious = [], []
        for kw_type, keyword, desc in vp.analyze_macros():
            if kw_type == "AutoExec":
                autoexec.append(keyword)
            elif kw_type in ("Suspicious", "IOC"):
                suspicious.append(f"{keyword}: {desc}")
        vp.close()
        return {"has_macros": True, "autoexec": autoexec,
                "suspicious": suspicious[:25]}
    except Exception as e:
        return {"has_macros": None, "error": str(e)}


def analyze_attachments(msg, rep, save_dir=None):
    for fname, data in _iter_attachments(msg, rep):
        if not data:
            continue
        ext = fname.lower().rsplit(".", 1)[-1] if "." in fname else ""
        info = {
            "name": fname,
            "ext": ext,
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "magic": "",
            "ext_mismatch": False,
            "macros": None,
            "ti": None,
        }
        rep.iocs["hashes"].add(info["sha256"])

        label, is_exec = _detect_magic(data)
        info["magic"] = label or "unknown"

        # dangerous extension
        if ext in DANGEROUS_EXT:
            sev = SEV_HIGH if ext in {"exe", "scr", "com", "pif", "js", "vbs",
                                      "hta", "jar", "lnk", "iso", "img", "wsf",
                                      "bat", "cmd", "ps1", "msi", "cpl"} else SEV_MED
            rep.add("ATTACH", sev, f"Опасное вложение .{ext}", f"{fname}")

        # double extension
        parts = fname.lower().split(".")
        if len(parts) >= 3 and parts[-1] in DANGEROUS_EXT and parts[-2] in {
            "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt",
            "zip", "rtf", "html", "htm", "csv"
        }:
            rep.add("ATTACH", SEV_HIGH, "Двойное расширение файла",
                    f"{fname}  (маскируется под .{parts[-2]})")

        # extension vs magic mismatch
        if label and label in EXT_FOR_MAGIC:
            allowed = EXT_FOR_MAGIC[label]
            if ext and ext not in allowed:
                info["ext_mismatch"] = True
                sev = SEV_HIGH if is_exec else SEV_MED
                rep.add("ATTACH", sev, "Тип файла не соответствует расширению",
                        f"{fname}: расширение .{ext}, реально → {label}")
        if label and is_exec and ext not in {"exe", "dll", "scr", "com", "elf",
                                             "so", "lnk", "cpl", "ocx", "sys"}:
            rep.add("ATTACH", SEV_CRIT, "Исполняемый файл под видом документа",
                    f"{fname}: содержимое = {label}")

        # archive notice
        if ext in ARCHIVE_EXT:
            rep.add("ATTACH", SEV_LOW, f"Архив-вложение (.{ext})",
                    f"{fname} — содержимое требует ручной/песочничной проверки")

        # macro analysis
        if ext in MACRO_EXT or label in ("OLE2 (legacy Office / MSI / MSG)",
                                         "ZIP / OOXML / JAR / APK"):
            mac = _scan_macros(data, fname)
            info["macros"] = mac
            if mac and mac.get("has_macros"):
                detail = ""
                if mac.get("autoexec"):
                    detail += "auto-exec: " + ", ".join(mac["autoexec"][:6])
                sev = SEV_HIGH if mac.get("autoexec") else SEV_MED
                if mac.get("suspicious"):
                    sev = SEV_HIGH
                    detail += ("; " if detail else "") + \
                              " | ".join(s.split(":")[0] for s in mac["suspicious"][:6])
                rep.add("ATTACH", sev, f"Office-вложение содержит VBA-макросы: {fname}",
                        detail or "обнаружены макросы")

        if save_dir:
            try:
                os.makedirs(save_dir, exist_ok=True)
                safe = re.sub(r"[^\w.\-]", "_", fname)[:120] or "att.bin"
                out = os.path.join(save_dir, f"{info['sha256'][:12]}_{safe}")
                with open(out, "wb") as fh:
                    fh.write(data)
                info["saved"] = out
            except Exception:
                pass

        rep.attachments.append(info)


# --------------------------------------------------------------------------- #
#  Optional threat-intel enrichment (offline by default)
# --------------------------------------------------------------------------- #
def enrich_online(rep, timeout=12):
    if not HAVE_REQUESTS:
        rep.add("INTEL", SEV_INFO, "Онлайн-обогащение пропущено",
                "библиотека 'requests' не установлена")
        return
    for att in rep.attachments:
        h = att["sha256"]
        verdict = None
        # MalwareBazaar
        try:
            r = requests.post("https://mb-api.abuse.ch/api/v1/",
                              data={"query": "get_info", "hash": h}, timeout=timeout)
            j = r.json()
            if j.get("query_status") == "ok" and j.get("data"):
                d = j["data"][0]
                verdict = f"MalwareBazaar: {d.get('signature') or 'known sample'} " \
                          f"({d.get('file_type')})"
        except Exception:
            pass
        # ThreatFox
        try:
            r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                              json={"query": "search_hash", "hash": h}, timeout=timeout)
            j = r.json()
            if j.get("query_status") == "ok" and j.get("data"):
                d = j["data"][0]
                verdict = (verdict + " | " if verdict else "") + \
                          f"ThreatFox: {d.get('malware_printable') or d.get('threat_type')}"
        except Exception:
            pass
        att["ti"] = verdict
        if verdict:
            rep.add("INTEL", SEV_CRIT, f"Хэш известен threat-intel: {att['name']}",
                    f"{h}  →  {verdict}")


# --------------------------------------------------------------------------- #
#  Scoring
# --------------------------------------------------------------------------- #
def score_report(rep):
    score = 0
    cap_per_cat = defaultdict(int)
    for f in rep.findings:
        w = SEV_WEIGHT[f.severity]
        # diminishing returns per category to avoid runaway scores
        cap_per_cat[f.category] += 1
        if cap_per_cat[f.category] > 4:
            w = max(1, w // 3)
        score += w
    score = min(score, 100)
    rep.score = score
    if score >= 70:
        rep.verdict = "MALICIOUS"
    elif score >= 40:
        rep.verdict = "LIKELY MALICIOUS"
    elif score >= 18:
        rep.verdict = "SUSPICIOUS"
    else:
        rep.verdict = "CLEAN"
    return score


# --------------------------------------------------------------------------- #
#  Console output
# --------------------------------------------------------------------------- #
C = {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "b": "\033[34m",
     "c": "\033[36m", "m": "\033[35m", "w": "\033[37m", "bold": "\033[1m",
     "dim": "\033[2m", "x": "\033[0m"}
VERDICT_COLOR = {"CLEAN": "g", "SUSPICIOUS": "y", "LIKELY MALICIOUS": "m", "MALICIOUS": "r"}
SEV_COLOR = {SEV_INFO: "dim", SEV_LOW: "c", SEV_MED: "y", SEV_HIGH: "m", SEV_CRIT: "r"}


def print_console(rep, no_color=False):
    def col(s, c):
        return s if no_color else f"{C.get(c,'')}{s}{C['x']}"
    print()
    print(col("┌" + "─" * 70, "g"))
    print(col(f"│ ZavetSec-MailInspector  v{VERSION}", "g"))
    print(col(f"│ {rep.filename}  [{rep.kind.upper()}]", "w"))
    print(col("└" + "─" * 70, "g"))
    if rep.error:
        print(col("  [ERROR] " + rep.error, "r"))
        return
    print(f"  From      : {rep.from_name}  <{rep.from_addr}>")
    print(f"  Subject   : {rep.subject[:80]}")
    print(f"  Date      : {rep.date}")
    print(f"  Auth      : SPF={rep.auth['spf'] or '-'}  "
          f"DKIM={rep.auth['dkim'] or '-'}  DMARC={rep.auth['dmarc'] or '-'}")
    print(f"  URLs      : {len(rep.urls)}   Attachments: {len(rep.attachments)}")
    vc = VERDICT_COLOR[rep.verdict]
    print()
    print("  " + col(f"VERDICT: {rep.verdict}  (score {rep.score}/100)", vc))
    print()
    order = sorted(rep.findings, key=lambda f: -SEV_ORDER[f.severity])
    if not order:
        print(col("  Подозрительных индикаторов не обнаружено.", "g"))
    for f in order:
        tag = f"[{f.severity}]".ljust(10)
        print("  " + col(tag, SEV_COLOR[f.severity]) + f"{f.category}: {f.title}")
        if f.detail:
            print(col(f"             {f.detail[:110]}", "dim"))
    print()


# --------------------------------------------------------------------------- #
#  HTML report  (ZavetSec design standard, fully self-contained, no external refs)
# --------------------------------------------------------------------------- #
HTML_CSS = """
:root{
  --bg:#0a0d10; --bg2:#0d1117; --panel:#10161d; --line:#1c2530;
  --green:#00ff88; --green-dim:#0a3; --txt:#c7d0d9; --muted:#6b7785;
  --crit:#ff2e4d; --high:#ff6b35; --med:#ffcc00; --low:#36c5ff; --info:#5a6776;
  --mono:'JetBrains Mono','Cascadia Code','Fira Code',Consolas,monospace;
  --disp:'Rajdhani','Segoe UI',sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:var(--mono);
  font-size:14px;line-height:1.55;position:relative;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,rgba(0,255,136,.025) 0,rgba(0,255,136,.025) 1px,transparent 1px,transparent 3px)}
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;
  background:radial-gradient(900px 500px at 75% -10%,rgba(0,255,136,.10),transparent 60%),
             radial-gradient(700px 500px at 10% 110%,rgba(0,255,136,.05),transparent 60%)}
.wrap{max-width:1180px;margin:0 auto;padding:34px 26px 80px}
header.hd{border:1px solid var(--line);background:linear-gradient(180deg,#0e151c,#0a0f14);
  border-radius:10px;padding:22px 26px;position:relative;overflow:hidden}
header.hd::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--green)}
.brand{font-family:var(--disp);letter-spacing:3px;color:var(--green);font-weight:700;
  font-size:13px;text-transform:uppercase}
.brand .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);
  margin-right:9px;box-shadow:0 0 10px var(--green);animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
h1{font-family:var(--disp);font-weight:700;font-size:30px;margin:8px 0 2px;color:#eef3f7;letter-spacing:.5px}
.sub{color:var(--muted);font-size:12px}
.verdict{margin:24px 0;border-radius:10px;padding:20px 24px;border:1px solid;
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:14px}
.verdict .v{font-family:var(--disp);font-size:34px;font-weight:700;letter-spacing:1px}
.verdict .meter{flex:1;min-width:220px;height:14px;border-radius:8px;background:#0a0f14;
  overflow:hidden;border:1px solid var(--line)}
.verdict .fill{height:100%;border-radius:8px}
.v-clean{border-color:#0a5;background:rgba(0,255,136,.06)} .v-clean .v{color:var(--green)} .v-clean .fill{background:var(--green)}
.v-susp{border-color:#a90;background:rgba(255,204,0,.06)} .v-susp .v{color:var(--med)} .v-susp .fill{background:var(--med)}
.v-likely{border-color:#a40;background:rgba(255,107,53,.07)} .v-likely .v{color:var(--high)} .v-likely .fill{background:var(--high)}
.v-mal{border-color:#a02;background:rgba(255,46,77,.08)} .v-mal .v{color:var(--crit)} .v-mal .fill{background:var(--crit)}
section{margin-top:30px}
h2{font-family:var(--disp);font-size:19px;letter-spacing:1px;color:#dfe7ee;
  border-bottom:1px solid var(--line);padding-bottom:8px;display:flex;align-items:center;gap:10px}
h2 .num{color:var(--green);font-size:13px;border:1px solid var(--green-dim);
  border-radius:5px;padding:1px 8px;background:rgba(0,255,136,.05)}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--green);font-family:var(--disp);letter-spacing:.5px;text-transform:uppercase;font-size:12px;
  background:rgba(0,255,136,.03)}
tr:hover td{background:rgba(255,255,255,.015)}
.kv td:first-child{color:var(--muted);width:190px;white-space:nowrap}
.badge{display:inline-block;font-family:var(--disp);font-weight:700;font-size:11px;letter-spacing:.5px;
  padding:2px 9px;border-radius:4px;border:1px solid}
.b-CRITICAL{color:var(--crit);border-color:var(--crit);background:rgba(255,46,77,.08)}
.b-HIGH{color:var(--high);border-color:var(--high);background:rgba(255,107,53,.08)}
.b-MEDIUM{color:var(--med);border-color:var(--med);background:rgba(255,204,0,.08)}
.b-LOW{color:var(--low);border-color:var(--low);background:rgba(54,197,255,.08)}
.b-INFO{color:var(--info);border-color:var(--info);background:rgba(90,103,118,.08)}
.alert{border:1px solid;border-left-width:4px;border-radius:8px;padding:12px 16px;margin:10px 0;background:var(--panel)}
.a-crit{border-color:var(--crit);background:rgba(255,46,77,.05)}
.a-high{border-color:var(--high);background:rgba(255,107,53,.05)}
.a-med{border-color:var(--med);background:rgba(255,204,0,.05)}
.a-low{border-color:var(--low);background:rgba(54,197,255,.05)}
.a-info{border-color:var(--info);background:rgba(90,103,118,.05)}
.alert .t{font-family:var(--disp);font-weight:700;letter-spacing:.4px;font-size:15px}
.alert .d{color:var(--muted);font-size:12.5px;margin-top:3px;word-break:break-word}
.alert .cat{color:var(--green);font-size:11px;letter-spacing:1px}
code,.mono{font-family:var(--mono);background:#0a0f14;border:1px solid var(--line);
  border-radius:4px;padding:1px 6px;color:#9fb3c8;word-break:break-all}
.ioc{background:#0a0f14;border:1px solid var(--line);border-radius:6px;padding:12px 14px;
  font-size:12.5px;color:#9fb3c8;white-space:pre-wrap;word-break:break-all;max-height:240px;overflow:auto}
.muted{color:var(--muted)}
.foot{margin-top:50px;text-align:center;color:var(--muted);font-size:11px;letter-spacing:1px}
.foot .green{color:var(--green)}
.hash{font-size:11px}
"""

VERDICT_CLASS = {"CLEAN": "v-clean", "SUSPICIOUS": "v-susp",
                 "LIKELY MALICIOUS": "v-likely", "MALICIOUS": "v-mal"}
ALERT_CLASS = {SEV_CRIT: "a-crit", SEV_HIGH: "a-high", SEV_MED: "a-med",
               SEV_LOW: "a-low", SEV_INFO: "a-info"}


def _esc(s):
    return html_lib.escape(str(s), quote=True)


def build_html(rep):
    e = _esc
    vclass = VERDICT_CLASS[rep.verdict]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    parts = []
    parts.append(f"""<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MailInspector — {e(rep.filename)}</title><style>{HTML_CSS}</style></head>
<body><div class="wrap">
<header class="hd">
  <div class="brand"><span class="dot"></span>ZavetSec // Mail Threat Inspector</div>
  <h1>Анализ почтового сообщения</h1>
  <div class="sub">{e(rep.filename)} · формат {e(rep.kind.upper())} · сгенерировано {now} · v{VERSION}</div>
</header>""")

    if rep.error:
        parts.append(f'<div class="alert a-crit"><div class="t">Ошибка</div>'
                     f'<div class="d">{e(rep.error)}</div></div>')
        parts.append("</div></body></html>")
        return "".join(parts)

    # verdict banner
    parts.append(f"""<div class="verdict {vclass}">
  <div><div class="v">{e(rep.verdict)}</div>
  <div class="muted">риск-скор {rep.score}/100</div></div>
  <div class="meter"><div class="fill" style="width:{rep.score}%"></div></div>
</div>""")

    # summary table
    parts.append(f"""<section><h2><span class="num">01</span> Сводка письма</h2>
<table class="kv"><tbody>
<tr><td>Отправитель</td><td>{e(rep.from_name)} &lt;<code>{e(rep.from_addr)}</code>&gt;</td></tr>
<tr><td>Кому</td><td>{e(rep.to)}</td></tr>
<tr><td>Тема</td><td>{e(rep.subject)}</td></tr>
<tr><td>Дата</td><td>{e(rep.date)}</td></tr>
<tr><td>Return-Path</td><td><code>{e(rep.return_path) or '—'}</code></td></tr>
<tr><td>Reply-To</td><td><code>{e(rep.reply_to) or '—'}</code></td></tr>
<tr><td>Message-ID</td><td><code>{e(rep.message_id) or '—'}</code></td></tr>
<tr><td>Аутентификация</td><td>SPF=<code>{e(rep.auth['spf'] or '-')}</code>
  DKIM=<code>{e(rep.auth['dkim'] or '-')}</code> DMARC=<code>{e(rep.auth['dmarc'] or '-')}</code></td></tr>
<tr><td>Ссылок / вложений</td><td>{len(rep.urls)} / {len(rep.attachments)}</td></tr>
</tbody></table></section>""")

    # findings
    order = sorted(rep.findings, key=lambda f: -SEV_ORDER[f.severity])
    parts.append(f'<section><h2><span class="num">02</span> Индикаторы ({len(order)})</h2>')
    if not order:
        parts.append('<div class="alert a-info"><div class="t">Чисто</div>'
                     '<div class="d">Подозрительных индикаторов не обнаружено.</div></div>')
    for f in order:
        parts.append(f"""<div class="alert {ALERT_CLASS[f.severity]}">
  <span class="badge b-{f.severity}">{f.severity}</span>
  <span class="cat"> {e(f.category)}</span>
  <div class="t">{e(f.title)}</div>
  {'<div class="d">'+e(f.detail)+'</div>' if f.detail else ''}
</div>""")
    parts.append("</section>")

    # URLs
    if rep.urls:
        rows = ""
        for u in rep.urls[:200]:
            rows += (f"<tr><td>{e(u['text'][:60]) or '<span class=muted>—</span>'}</td>"
                     f"<td><code>{e(u['host'])}</code></td>"
                     f"<td><code style='font-size:11px'>{e(u['href'][:140])}</code></td></tr>")
        parts.append(f"""<section><h2><span class="num">03</span> Ссылки ({len(rep.urls)})</h2>
<table><thead><tr><th>Текст</th><th>Хост</th><th>URL</th></tr></thead><tbody>{rows}</tbody></table></section>""")

    # attachments
    if rep.attachments:
        rows = ""
        for a in rep.attachments:
            mac = ""
            if a.get("macros") and a["macros"].get("has_macros"):
                mac = "VBA"
                if a["macros"].get("autoexec"):
                    mac += "+auto"
            ti = a.get("ti") or ""
            rows += (f"<tr><td><code>{e(a['name'])}</code></td>"
                     f"<td>{a['size']:,}</td>"
                     f"<td>{e(a['magic'])}</td>"
                     f"<td>{'⚠ '+mac if mac else '—'}</td>"
                     f"<td class='hash'><code class='hash'>{e(a['sha256'])}</code>"
                     f"{'<br><span class=muted>'+e(ti)+'</span>' if ti else ''}</td></tr>")
        parts.append(f"""<section><h2><span class="num">04</span> Вложения ({len(rep.attachments)})</h2>
<table><thead><tr><th>Имя</th><th>Байт</th><th>Реальный тип</th><th>Макросы</th><th>SHA-256 / TI</th></tr></thead>
<tbody>{rows}</tbody></table></section>""")

    # IOCs
    def ioc_block(title, items):
        if not items:
            return ""
        body = "\n".join(sorted(items))
        return f'<h2 style="font-size:14px;border:none;margin:14px 0 6px;color:var(--green)">{title} ({len(items)})</h2><div class="ioc">{e(body)}</div>'

    iocs_html = (ioc_block("Домены", rep.iocs["domains"]) +
                 ioc_block("IP-адреса", rep.iocs["ips"]) +
                 ioc_block("URL", rep.iocs["urls"]) +
                 ioc_block("E-mail", rep.iocs["emails"]) +
                 ioc_block("Хэши (SHA-256)", rep.iocs["hashes"]))
    if iocs_html:
        parts.append(f'<section><h2><span class="num">05</span> IOC для блокировки / hunting</h2>{iocs_html}</section>')

    # delivery path
    if rep.hops:
        hops = "\n".join(f"{i+1}. {h[:200]}" for i, h in enumerate(rep.hops))
        parts.append(f'<section><h2><span class="num">06</span> Маршрут доставки (Received)</h2>'
                     f'<div class="ioc">{e(hops)}</div></section>')

    parts.append(f'<div class="foot"><span class="green">ZavetSec</span> · MailInspector v{VERSION} · '
                 f'оборонительный DFIR-инструмент · самодостаточный отчёт без внешних ресурсов</div>')
    parts.append("</div></body></html>")
    return "".join(parts)


# --------------------------------------------------------------------------- #
#  JSON
# --------------------------------------------------------------------------- #
def build_json(rep):
    return {
        "tool": "ZavetSec-MailInspector", "version": VERSION,
        "file": rep.filename, "kind": rep.kind,
        "verdict": rep.verdict, "score": rep.score, "error": rep.error,
        "from_name": rep.from_name, "from_addr": rep.from_addr,
        "return_path": rep.return_path, "reply_to": rep.reply_to,
        "to": rep.to, "subject": rep.subject, "date": rep.date,
        "message_id": rep.message_id, "auth": rep.auth,
        "findings": [f.as_dict() for f in rep.findings],
        "urls": rep.urls,
        "attachments": [{k: v for k, v in a.items() if k != "macros"} |
                        {"macros": a.get("macros")} for a in rep.attachments],
        "iocs": {k: sorted(v) for k, v in rep.iocs.items()},
        "delivery_path": rep.hops,
    }


# --------------------------------------------------------------------------- #
#  Driver
# --------------------------------------------------------------------------- #
def process_file(path, args):
    rep = MailReport(path)
    try:
        msg = load_email(path, rep)
        if rep.error:
            score_report(rep)
            return rep
        analyze_headers(rep)
        plain, html = get_bodies(msg, rep)
        analyze_body(plain, html, rep)
        analyze_attachments(msg, rep, save_dir=args.dump)
        if args.online:
            enrich_online(rep)
    except Exception as ex:
        rep.error = f"Сбой анализа: {ex}"
    score_report(rep)
    return rep


def gather_inputs(target):
    if os.path.isdir(target):
        out = []
        for root, _, files in os.walk(target):
            for fn in files:
                if fn.lower().endswith((".eml", ".msg")):
                    out.append(os.path.join(root, fn))
        return sorted(out)
    return [target]


def main():
    ap = argparse.ArgumentParser(
        prog="ZavetSec-MailInspector",
        description="Phishing & malware triage for .eml / .msg files (ZavetSec).")
    ap.add_argument("target", help="файл .eml/.msg или каталог для рекурсивного обхода")
    ap.add_argument("-o", "--html", metavar="PATH",
                    help="путь для HTML-отчёта (для каталога — это каталог отчётов)")
    ap.add_argument("-j", "--json", metavar="PATH",
                    help="сохранить результат(ы) в JSON")
    ap.add_argument("--dump", metavar="DIR",
                    help="извлечь вложения в указанный каталог (имя = sha256_имя)")
    ap.add_argument("--online", action="store_true",
                    help="включить онлайн threat-intel (MalwareBazaar/ThreatFox) — "
                         "отправляет ХЭШИ вложений во внешние сервисы. По умолчанию OFF.")
    ap.add_argument("--no-color", action="store_true", help="без ANSI-цвета в консоли")
    ap.add_argument("--quiet", action="store_true", help="не печатать подробности в консоль")
    args = ap.parse_args()

    if not os.path.exists(args.target):
        print(f"[!] Путь не найден: {args.target}", file=sys.stderr)
        sys.exit(2)

    inputs = gather_inputs(args.target)
    if not inputs:
        print("[!] Не найдено .eml/.msg файлов.", file=sys.stderr)
        sys.exit(1)

    is_dir = os.path.isdir(args.target)
    all_json = []
    worst = 0
    for path in inputs:
        rep = process_file(path, args)
        if not args.quiet:
            print_console(rep, no_color=args.no_color)
        worst = max(worst, rep.score)

        if args.html:
            html_doc = build_html(rep)
            if is_dir:
                os.makedirs(args.html, exist_ok=True)
                base = re.sub(r"[^\w.\-]", "_", rep.filename)
                hp = os.path.join(args.html, base + ".report.html")
            else:
                hp = args.html
            with open(hp, "w", encoding="utf-8") as fh:
                fh.write(html_doc)
            if not args.quiet:
                print(f"  [+] HTML-отчёт: {hp}")
        all_json.append(build_json(rep))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(all_json if is_dir else all_json[0], fh,
                      ensure_ascii=False, indent=2)
        if not args.quiet:
            print(f"  [+] JSON: {args.json}")

    # exit code reflects worst verdict (useful for pipelines/automation)
    sys.exit(0 if worst < 18 else (1 if worst < 70 else 2))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Прервано.", file=sys.stderr)
        sys.exit(130)
