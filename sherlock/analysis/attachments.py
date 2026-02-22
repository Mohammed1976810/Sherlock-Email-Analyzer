"""Attachment analysis — single-pass YARA + structural + PDF/Office in one function.

Key change from original: no separate _yara_scan_email(), _yara_scan() duplication.
One _yara_scan() function with a shared string extractor. PDF analysis uses
pikepdf with cache. Office analysis via oletools.
"""
from __future__ import annotations
import hashlib, io, re, threading, logging, os, zipfile, html, tempfile, contextlib
from typing import List, Dict, Optional
from ..models import AttachmentResult
from ..utils import shannon_entropy, defang
from ..constants import (
    MAX_FILE_SIZE, CONTENT_TYPES_SEARCH, MAX_ZIP_EXTRACT,
    PDF_CRITICAL_TAGS, PDF_CONTEXT_TAGS, PDF_META_NS,
    PAT_URL, PAT_PDF_URI, PAT_PDF_URL,
)

log = logging.getLogger("sherlock.attachments")

# Optional deps
YARA_OK = OLETOOLS_OK = PIKEPDF_OK = PDFMINER_OK = False
try:
    import yara; YARA_OK = True
except ImportError: pass
try:
    from oletools.olevba import VBA_Parser
    from oletools.oleid import OleID
    from oletools.mraptor import MacroRaptor
    OLETOOLS_OK = True
except ImportError: pass
try:
    import pikepdf; PIKEPDF_OK = True
except ImportError: pass
try:
    from pdfminer.high_level import extract_text as pdfminer_extract
    PDFMINER_OK = True
except ImportError: pass

# ── YARA Engine ───────────────────────────────────────────────────────────────
_yara_rules = None
_yara_lock = threading.Lock()
_yara_cofense_loaded = False
_yara_last_error = ""
_yara_found_path = ""

YARA_SRC = r"""
rule VBA_Macro_Dropper {
  meta: description = "VBA download+autoexec dropper" severity = "CRITICAL" category = "macro"
  strings:
    $d1 = "URLDownloadToFile" nocase  $d2 = "XMLHTTP" nocase  $d3 = "WinHttpRequest" nocase
    $e1 = "AutoOpen" nocase  $e2 = "Document_Open" nocase  $e3 = "Workbook_Open" nocase
    $s = "WScript.Shell" nocase
  condition: ($d1 or $d2 or $d3) and ($e1 or $e2 or $e3 or $s)
}
rule VBA_Obfuscated {
  meta: description = "Obfuscated VBA (multi-primitive)" severity = "HIGH" category = "macro"
  strings: $a="Chr(" nocase $b="StrReverse(" nocase $c="Environ(" nocase $d="CallByName(" nocase $e="Execute(" nocase $f="Asc(" nocase
  condition: 4 of them
}
rule PDF_JS_Exploit {
  meta: description = "PDF JavaScript exploit chain" severity = "HIGH" category = "pdf"
  strings: $j1="/JavaScript" $j2="/JS" $ev="eval(" nocase $un="unescape(" nocase $oa="/OpenAction"
  condition: $oa and ($j1 or $j2) and ($ev or $un)
}
rule PDF_Launch {
  meta: description = "PDF /Launch action" severity = "CRITICAL" category = "pdf"
  strings: $launch="/Launch" $action="/Action" $win="/Win" $unix="/Unix" $mac="/Mac"
  condition: $launch and $action and (1 of ($win,$unix,$mac))
}
rule EXE_Magic {
  meta: description = "Executable magic bytes" severity = "CRITICAL" category = "executable"
  strings: $mz={4D 5A} $pe={50 45 00 00} $elf={7F 45 4C 46}
  condition: ($mz at 0) or ($elf at 0) or $pe
}
rule Archive_Sig {
  meta: description = "Archive magic bytes" severity = "MEDIUM" category = "archive"
  strings: $zip={50 4B 03 04} $rar={52 61 72 21 1A 07} $sz={37 7A BC AF 27 1C}
  condition: any of them
}
rule Phishing_Form {
  meta: description = "HTML credential harvesting form" severity = "HIGH" category = "phishing"
  strings: $form="<form" nocase $vfy="verify your account" nocase $sus="account suspended" nocase $act="immediate action" nocase $sub="confirm your identity" nocase $exp="account will expire" nocase
  condition: $form and (3 of ($vfy,$sus,$act,$sub,$exp))
}
rule Macro_Registry {
  meta: description = "VBA registry run-key persistence" severity = "HIGH" category = "macro"
  strings: $rw="RegWrite" nocase $hk="HKEY_" nocase $rk="CurrentVersion\\Run" nocase
  condition: $rw and ($hk or $rk)
}
rule PS_In_Macro {
  meta: description = "PowerShell evasion in macro" severity = "CRITICAL" category = "macro"
  strings: $ps="PowerShell" nocase $enc="-EncodedCommand" nocase $byp="-ExecutionPolicy Bypass" nocase $hid="-WindowStyle Hidden" nocase $dl="DownloadString" nocase
  condition: $ps and (2 of ($enc,$byp,$hid,$dl))
}
"""

_BUILTIN_RULE_COUNT = YARA_SRC.count('\nrule ') + (1 if YARA_SRC.startswith('rule ') else 0)

_ENRICHMENT_RULES = frozenset({
    'CY_Sender_is_NOREPLY', 'CY_URL_Redirect', 'PM_SPF_Pass',
    'CY_Mailer_Not_Office_Outlook', 'CY_Mobile_Phone_Text_To_Email',
    'PM_Labs_Potential_Malware_Reply_Chain', 'PM_pdf_document', 'PM_zip_file',
    'PM_xlsx_file', 'PM_docx_file', 'PM_pptx_file', 'PM_office_magic_bytes',
    'PM_word_document', 'PM_excel_document', 'PM_powerpoint_document', 'PM_rtf_file',
    'CY_PDF_With_Links',
})
_ENRICHMENT_PREFIXES = ('CY_CofenseLabs_ServiceID_', 'PM_TNR_')
_ATTACHMENT_ONLY_RULES = frozenset({
    'EXE_Magic', 'Archive_Sig', 'PDF_Launch', 'PDF_JS_Exploit',
    'VBA_Macro_Dropper', 'VBA_Obfuscated', 'PS_In_Macro', 'Macro_Registry',
})


def _is_enrichment(rule_name: str) -> bool:
    return rule_name in _ENRICHMENT_RULES or any(rule_name.startswith(p) for p in _ENRICHMENT_PREFIXES)


def _cofense_severity(rule_name: str, meta: dict) -> str:
    if 'severity' in meta:
        return meta['severity'].upper()
    if _is_enrichment(rule_name):
        return 'INFO'
    if rule_name.startswith('PM_'):
        return 'HIGH'
    if rule_name.startswith(('CY_PDC_Phish_', 'CY_Phish_')):
        return 'HIGH'
    if rule_name.startswith('CY_FMR_'):
        return 'LOW'
    if rule_name.startswith('CY_'):
        return 'MEDIUM'
    return 'MEDIUM'


def get_yara():
    """Compile and cache YARA rules. Thread-safe with pre-lock fast path."""
    global _yara_rules, _yara_cofense_loaded
    if not YARA_OK:
        return None
    if _yara_rules is not None and _yara_cofense_loaded:
        return _yara_rules
    with _yara_lock:
        global _yara_last_error, _yara_found_path
        if _yara_rules is not None and _yara_cofense_loaded:
            return _yara_rules
        # Try external rules
        ext = _find_external_yara()
        if ext:
            _yara_found_path = ext
            try:
                with open(ext, 'r', encoding='utf-8', errors='ignore') as f:
                    src = f.read()
                compiled = yara.compile(sources={'builtin': YARA_SRC, 'cofense': src})
                _yara_rules = compiled
                _yara_cofense_loaded = True
                _yara_last_error = ""
                return _yara_rules
            except Exception as e:
                _yara_last_error = str(e)
        # Built-in fallback
        if _yara_rules is None:
            try:
                _yara_rules = yara.compile(source=YARA_SRC)
            except Exception as e:
                log.error(f"YARA built-in compile failed: {e}")
        return _yara_rules


def _find_external_yara() -> str:
    import sys
    candidates = []
    env = os.environ.get('SHERLOCK_YARA_RULES', '').strip()
    if env:
        candidates.append(env)
    try:
        candidates.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'triage_rules.yar'))
    except Exception: pass
    try:
        candidates.append(os.path.join(os.getcwd(), 'triage_rules.yar'))
    except Exception: pass
    candidates.append(os.path.join(os.path.expanduser('~'), '.sherlock', 'triage_rules.yar'))
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return ""


def _extract_match_strings(hit) -> List[str]:
    """Shared YARA match string extraction — was duplicated in _yara_scan and _yara_scan_email."""
    ms = []
    try:
        for sm in hit.strings:
            try:
                for inst in sm.instances:
                    try:
                        ms.append(inst.matched_data.decode('utf-8', 'replace')[:60])
                    except Exception: pass
            except AttributeError:
                if isinstance(sm, tuple) and len(sm) >= 3:
                    try: ms.append(sm[2].decode('utf-8', 'replace')[:60])
                    except Exception: pass
    except Exception: pass
    return list(set(ms))[:5]


def yara_scan(data: bytes, fname: str = "", exclude_attachment_only: bool = False) -> List[Dict]:
    """Unified YARA scan for both attachments and email body."""
    rules = get_yara()
    if not rules or not data:
        return []
    data = data[:10 * 1024 * 1024]
    matches = []
    try:
        for hit in rules.match(data=data)[:200]:
            if exclude_attachment_only and hit.rule in _ATTACHMENT_ONLY_RULES:
                continue
            matches.append({
                'rule': hit.rule,
                'severity': _cofense_severity(hit.rule, hit.meta),
                'desc': hit.meta.get('description', hit.rule.replace('_', ' ')),
                'cat': hit.meta.get('category', ''),
                'tlp': hit.meta.get('tlp', ''),
                'enrichment': _is_enrichment(hit.rule),
                'strings': _extract_match_strings(hit),
            })
    except Exception as e:
        log.error(f"YARA scan: {e}")
    return matches


# ── PDF Security ──────────────────────────────────────────────────────────────
_PIKEPDF_CACHE: dict = {}
_PIKEPDF_LOCK = threading.Lock()


def _pikepdf_scan(data: bytes) -> Optional[dict]:
    """Security scan of PDF via pikepdf. Cached by content hash."""
    if not PIKEPDF_OK or len(data) > 15 * 1024 * 1024:
        return None
    cache_key = hashlib.md5(data, usedforsecurity=False).hexdigest()
    with _PIKEPDF_LOCK:
        if cache_key in _PIKEPDF_CACHE:
            return _PIKEPDF_CACHE[cache_key]

    result = [None]
    def _scan():
        try:
            pdf = pikepdf.open(io.BytesIO(data))
            tags, uris, js = set(), set(), []
            def _walk(obj, depth=0):
                if depth > 12: return
                try:
                    if isinstance(obj, pikepdf.Dictionary):
                        for key in obj.keys():
                            tags.add(str(key))
                            try:
                                v = str(obj[key])
                                if v in ("/JavaScript","/JS","/Launch","/EmbeddedFile","/RichMedia","/XFA"):
                                    tags.add(v)
                            except Exception: pass
                            if str(key) == "/URI":
                                try:
                                    u = str(obj[key])
                                    if u.startswith(("http","ftp","//")):
                                        uris.add(u)
                                except Exception: pass
                            if str(key) == "/JS":
                                try:
                                    js_val = str(obj[key])
                                    if len(js_val) > 5:
                                        js.append(js_val[:100])
                                        tags.add("/JavaScript")
                                except Exception: pass
                            try: _walk(obj[key], depth+1)
                            except Exception: pass
                    elif isinstance(obj, (pikepdf.Array, list)):
                        for item in obj:
                            try: _walk(item, depth+1)
                            except Exception: pass
                except Exception: pass
            for obj in pdf.objects:
                try: _walk(obj)
                except Exception: pass
            try: _walk(pdf.Root)
            except Exception: pass
            dangerous = [t for t in tags if t in PDF_CRITICAL_TAGS]
            context = [t for t in tags if t in PDF_CONTEXT_TAGS]
            clean_uris = [u for u in list(uris)[:100]
                          if not any(ns in u.lower() for ns in PDF_META_NS) and len(u) >= 8]
            result[0] = {
                'dangerous_tags': dangerous, 'context_tags': context,
                'js_snippets': js[:5], 'uris': clean_uris,
                'has_xfa': '/XFA' in tags,
                'is_encrypted': pdf.is_encrypted,
                'object_count': len(pdf.objects),
            }
            pdf.close()
        except Exception:
            pass

    from ..constants import PDFMINER_TIMEOUT
    t = threading.Thread(target=_scan, daemon=True)
    t.start()
    t.join(timeout=PDFMINER_TIMEOUT)
    with _PIKEPDF_LOCK:
        _PIKEPDF_CACHE[cache_key] = result[0]
    return result[0]


def _pdf_uris(data: bytes) -> List[str]:
    uris = set()
    ps = _pikepdf_scan(data)
    if ps and ps['uris']:
        uris.update(ps['uris'])
    if PDFMINER_OK and len(uris) < 10:
        try:
            from ..constants import PDFMINER_TIMEOUT
            result = [None]
            def _ex():
                try: result[0] = pdfminer_extract(io.BytesIO(data))
                except Exception: pass
            t = threading.Thread(target=_ex, daemon=True)
            t.start()
            t.join(timeout=PDFMINER_TIMEOUT)
            if result[0]:
                for url in PAT_URL.findall(result[0]):
                    uris.add(url)
        except Exception: pass
    # Raw fallback
    scan = data[:5*1024*1024]
    for m in PAT_PDF_URI.finditer(scan):
        try:
            raw = m.group(1).decode('latin-1', 'ignore').strip().replace('\x00','')
            if raw.startswith(('http','ftp')):
                uris.add(raw)
        except Exception: pass
    return [u for u in list(uris)[:100]
            if not any(ns in u.lower() for ns in PDF_META_NS) and len(u) >= 8]


def _office_uris(data: bytes) -> List[str]:
    uris = set()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                if n.endswith('.rels'):
                    info = z.getinfo(n)
                    if info.file_size > MAX_ZIP_EXTRACT:
                        continue
                    content = z.read(n).decode('utf-8', 'ignore')
                    for link in re.findall(r'Target=["\'](https?:[^"\']+)["\']', content, re.I):
                        if 'schemas.openxmlformats' not in link and 'schemas.microsoft' not in link:
                            uris.add(html.unescape(link))
    except Exception: pass
    return list(uris)[:100]


@contextlib.contextmanager
def _tmp_file(data, suffix=''):
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    p = f.name
    try:
        f.write(data)
        f.close()
        yield p
    except Exception:
        try: f.close()
        except Exception: pass
        raise
    finally:
        if os.path.exists(p):
            try: os.unlink(p)
            except Exception: pass


def analyze_attachment(data: bytes, filename: str) -> AttachmentResult:
    """Single-pass attachment analysis: hash → MalwareBazaar → YARA → structural → type-specific."""
    r = AttachmentResult(filename=filename)
    if not data:
        r.verdict = "Empty file"
        return r
    if len(data) > MAX_FILE_SIZE:
        r.verdict = f"Skipped — exceeds {MAX_FILE_SIZE//1024//1024}MB"
        r.risk_score = 5
        return r

    r.md5 = hashlib.md5(data).hexdigest()
    r.sha256 = hashlib.sha256(data).hexdigest()

    # MalwareBazaar
    from ..intel.malwarebazaar import check_malwarebazaar
    found, family, _ = check_malwarebazaar(data, filename)
    if found:
        r.mb_found, r.mb_family, r.risk_score = True, family, 100
        r.details.append(f"MALWARE BAZAAR: {family}")

    # YARA (single call)
    hits = yara_scan(data, filename)
    is_valid_office = (data[:4] == b'PK\x03\x04' and b'[Content_Types].xml' in data[:CONTENT_TYPES_SEARCH])
    is_valid_pdf = data[:5] == b'%PDF-'
    is_ole = data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
    fl = filename.lower()

    # Structural FP suppression (dict-based instead of 4 separate frozensets)
    _FP_GUARDS = {
        'Archive_Sig': is_valid_office or fl.endswith(('.zip','.rar','.7z','.gz','.tar')),
        'PM_zip_file': is_valid_office, 'PM_xlsx_file': is_valid_office,
        'PM_docx_file': is_valid_office, 'PM_pptx_file': is_valid_office,
        'PM_office_magic_bytes': is_ole, 'PM_word_document': is_ole,
        'PM_excel_document': is_ole, 'PM_powerpoint_document': is_ole,
        'PM_pdf_document': is_valid_pdf, 'CY_PDF_With_Links': is_valid_pdf,
        'PM_rtf_file': data[:5] == b'{\\rtf',
    }

    for m in hits:
        rule = m['rule']
        if _FP_GUARDS.get(rule, False):
            # Archive_Sig on non-archive, non-office = disguised archive
            if rule == 'Archive_Sig' and not is_valid_office and not fl.endswith(('.zip','.rar','.7z')):
                m['severity'] = 'HIGH'
                m['desc'] = f"DISGUISED ARCHIVE: '{filename}'"
                r.yara_matches.append(m)
                r.risk_score = max(r.risk_score, 50)
            continue
        r.yara_matches.append(m)

    scoring_hits = [m for m in r.yara_matches if not m.get('enrichment')]
    if scoring_hits:
        _SEV = {'CRITICAL': 80, 'HIGH': 50, 'MEDIUM': 25}
        r.risk_score = max(r.risk_score, min(100, sum(_SEV.get(m['severity'], 10) for m in scoring_hits)))

    # Type-specific analysis
    if is_valid_pdf:
        r.file_type = "PDF"
        ps = _pikepdf_scan(data)
        if ps:
            if ps['dangerous_tags']:
                r.has_macros = True
                _TAG_SCORES = {'/Launch': 88, '/JavaScript': 72, '/JS': 72, '/EmbeddedFile': 65, '/RichMedia': 55}
                for tag in ps['dangerous_tags']:
                    r.risk_score = max(r.risk_score, _TAG_SCORES.get(tag, 50))
                    r.details.append(f"PDF tag: {tag}")
            if ps['js_snippets']:
                r.has_macros = True
                r.risk_score = max(r.risk_score, 70)
            if ps['has_xfa']:
                r.risk_score = max(r.risk_score, 50)
                r.details.append("XFA form detected")
        else:
            # Raw fallback
            if b'/Launch' in data:
                r.has_macros = True; r.risk_score = max(r.risk_score, 85)
            if b'/JavaScript' in data or b'/JS' in data:
                r.has_macros = True; r.risk_score = max(r.risk_score, 70)

        r.embedded_uris = _pdf_uris(data)
        r.verdict = "SUSPICIOUS" if (r.yara_matches or r.has_macros) else "SAFE"
        return r

    if is_ole or is_valid_office:
        r.file_type = "Office"
        r.embedded_uris.extend(_office_uris(data))
        if OLETOOLS_OK:
            vba = None
            try:
                with _tmp_file(data, '.doc') as tmp:
                    vba = VBA_Parser(tmp)
                    if vba.detect_vba_macros():
                        r.has_macros = True
                        code = "\n".join(c for _, _, _, c in vba.extract_macros() if c)
                        try:
                            mr = MacroRaptor(code)
                            mr.scan()
                            if mr.suspicious:
                                r.risk_score += 60
                                r.verdict = "SUSPICIOUS (MacroRaptor)"
                                r.details.append("MacroRaptor: SUSPICIOUS")
                            else:
                                r.verdict = "SAFE — benign macros" if r.risk_score < 50 else "REVIEW"
                        except Exception:
                            r.verdict = "HAS MACROS (raptor failed)"
                        ent = shannon_entropy(code)
                        if ent > 5.5:
                            r.risk_score += 15; r.details.append(f"High macro entropy ({ent:.1f})")
                        if YARA_OK:
                            for m in yara_scan(code.encode('utf-8', 'ignore'), f"{filename}_vba"):
                                if m not in r.yara_matches:
                                    r.yara_matches.append(m)
                    else:
                        r.verdict = "SAFE — no macros"
            except Exception as e:
                r.verdict = f"Error: {str(e)[:40]}"
            finally:
                if vba:
                    try: vba.close()
                    except Exception: pass
        return r

    if data[:4] == b'PK\x03\x04' and not is_valid_office:
        r.file_type = "Archive"
        r.embedded_uris.extend(_office_uris(data))
        r.verdict = "Archive file" if not r.yara_matches else f"SUSPICIOUS — {r.yara_matches[0]['rule']}"
        return r

    if r.yara_matches:
        r.file_type = "Binary"
        r.verdict = f"SUSPICIOUS — YARA: {r.yara_matches[0]['rule']}"
    return r


def _check_archive_risks(att_parts: list) -> list:
    """Structural risk checks on collected attachment parts (double-ext, dangerous ext, MIME mismatch, password archive).

    Replaces the original get_attachment_risks() which did its own msg.walk().
    Now operates on already-collected (data, filename) tuples.
    """
    from ..constants import DOUBLE_EXT_PATS, DANGEROUS_EXTS, CONTAINER_EXTS, VALID_MIMES
    risks = []
    for data, fname in att_parts:
        fl = fname.lower()
        for pat, desc in DOUBLE_EXT_PATS:
            if pat.search(fl):
                risks.append({'file': fname, 'type': 'double_ext',
                              'desc': f"Double ext: {desc}", 'severity': 'CRITICAL'})
                break
        ext = '.' + fl.rsplit('.', 1)[-1] if '.' in fl else ''
        if ext in DANGEROUS_EXTS:
            risks.append({'file': fname, 'type': 'dangerous_ext',
                          'desc': f"Dangerous: {ext}", 'severity': 'CRITICAL'})
        if ext in CONTAINER_EXTS:
            if _check_archive_password(data, fl):
                risks.append({'file': fname, 'type': 'password_archive',
                              'desc': f"Password-protected archive: {fname}",
                              'severity': 'HIGH'})
    return risks


def _check_archive_password(payload: bytes, filename: str) -> bool:
    """Detect password-protected archives (ZIP, RAR, 7z). Metadata-only, never decompresses."""
    ext = ('.' + filename.rsplit('.', 1)[-1]).lower() if '.' in filename else ''
    if len(payload) > 50 * 1024 * 1024:
        return False
    if ext == '.zip':
        try:
            with zipfile.ZipFile(io.BytesIO(payload), 'r') as zf:
                first = zf.infolist()[0] if zf.infolist() else None
                return bool(first and first.flag_bits & 0x0001)
        except Exception:
            return False
    if ext == '.rar':
        try:
            if payload[:7] == b'Rar!\x1a\x07\x01':
                return bool(payload[10] & 0x01) if len(payload) > 10 else False
            elif payload[:6] == b'Rar!\x1a\x07':
                return bool(payload[11] & 0x04) if len(payload) > 11 else False
        except Exception:
            pass
    if ext == '.7z':
        try:
            if payload[:6] == b'7z\xbc\xaf\x27\x1c':
                return b'\x06' in payload[6:min(len(payload), 128)]
        except Exception:
            pass
    return False
