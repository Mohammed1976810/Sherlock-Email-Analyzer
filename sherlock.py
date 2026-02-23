"""
SHERLOCK - ENTERPRISE FORENSIC EMAIL ANALYZER v14.0
====================================================

Architecture: Signal-based nonlinear scoring engine with threat cluster
intelligence, conditional multi-cluster escalation, behavioral attack-pattern
detection, domain entropy analysis, and a Risk Narrative Builder that explains
WHY an email is dangerous — not just what was found.

v11.0 INTELLIGENCE UPGRADE CHANGELOG:
  [I01] Threat Cluster Matrix: signals now grouped into Spoof / Payload /
        Infrastructure / Social Engineering clusters. Cluster scores computed
        before individual signal combination so co-firing clusters escalate.
  [I02] Conditional Cluster Escalation: if Spoof+Payload both fire → CRITICAL
        floor applied regardless of individual signal weights. 9 escalation
        rules replace flat additive scoring for multi-vector attacks.
  [I03] Risk Narrative Builder: generates a human-readable attack-pattern
        narrative ("This email failed SPF, uses a newly registered domain, and
        contains a wire-transfer request. Pattern matches CEO fraud.") replacing
        the raw signal dump as the primary analyst output.
  [I04] Behavioral Pattern Engine: structural attack-pattern signatures for
        invoice fraud, CEO fraud, MFA bypass lures, credential harvesting,
        shipping scams, and payment redirect — not keyword matching.
  [I05] Extended BEC categories: MFA bypass lures, invoice fraud, and shipping
        scam patterns added to BEC_KEYWORDS with calibrated probabilities.
  [I06] Domain entropy analysis: subdomain Shannon entropy > 3.5 bits flagged
        as DGA/algorithmically generated. Randomized domain name detection
        (high consonant clusters, low vowel ratio) added as new signal.
  [I07] False-positive dampening hardened: DMARC reject policy + SPF PASS +
        known sender together now provide meaningful compound dampening instead
        of three separate weak factors.
  [I08] Signal narrative: every ThreatSignal now carries an 'attack_vector'
        field surfaced in the reasoning card so analysts see the attack type
        alongside the technical finding.

v13.0 OVERHAUL CHANGELOG:
  [V13-01] BEC section fundamentally redesigned:
           BEC_KEYWORDS restructured into Tier 1 (high-specificity, standalone),
           Tier 2 (context-dependent, need auth failure/spoof), Tier 3 (weak, disabled).
           shipping_scam DISABLED — fires on every legit FedEx/UPS/Amazon email.
           invoice_fraud NARROWED to explicit payment-redirect phrases only.
           mfa_bypass NARROWED to social-engineering-specific phrases only.
           urgency NARROWED to multi-word explicit-urgency phrases only.
           ceo_fraud NARROWED to explicit secrecy/bypass-process phrases only.
  [V13-02] analyze_bec() rewritten with tier-aware ceiling rules:
           Tier-3 alone → hard cap 0.10. Single Tier-2 without Tier-1 → cap 0.18.
           Single Tier-1 → cap 0.42 (MEDIUM max — corroboration needed for HIGH+).
           Category-count gate: HIGH requires ≥2 non-weak categories.
           Short-email dampening: <40 body words + 1 keyword → MEDIUM cap.
  [V13-03] Auth-context dampening in generate_signals():
           Clean SPF+DKIM+DMARC+no-shadow-spoof reduces tier-2/3 BEC score by 65%.
           Tier-1 (financial keywords) get 30% dampening even with clean auth.
           Category markers still emitted for correlation even when dampened below threshold.
  [V13-04] YARA EXE_Magic PE-header bug fixed:
           $pe="PE\\x00\\x00" in Python raw string made YARA search for literal
           backslash characters, not null bytes. Fixed to {50 45 00 00} hex pattern.
  [V13-05] YARA Phishing_Form tightened:
           Condition raised from ($form AND 2-of-4) to ($form AND 3-of-5).
           'password' removed from counted strings — too broad.
           Eliminated FP on IT helpdesk emails, SharePoint notifications.
  [V13-06] YARA PDF_Launch tightened:
           Added /Win|/Unix|/Mac platform dictionary requirement.
           Old rule fired on any PDF with /Launch + any /Action (GoTo, URI, etc.).
           New rule only fires when a platform-specific execution target is present.
  [V13-07] YARA VBA_Obfuscated threshold raised 3→4:
           Chr()/Asc()/Environ() appear in legitimate VBA. 4-of-6 is much higher
           confidence. Reduces FP on corporate macros with string handling.
  [V13-08] YARA rules reformatted with comments:
           All 9 rules now use standard indented YARA syntax with rationale comments.
           Easier to audit and extend. Rule count and logic unchanged.
  [V13-10] Port-in-netloc bug: 7 sites where urlparse().netloc was used instead
           of urlparse().hostname. .netloc includes ':443' which corrupts
           _root_domain(), is_tracking_domain(), and domain_intel() — causing:
           (a) link-text mismatches on security gateway URLs with explicit :443
               (same domain flagged as mismatch because 'domain.com:443' ≠ 'domain.com')
           (b) VT showing UNKNOWN for URLs with :443 even when base domain is CLEAN
               (domain_intel() didn't recognize 'domain.com:443' as trusted)
           (c) DGA entropy checks failing to skip tracking domains with ports
           (d) Shortener/suspicious-TLD checks failing for URLs with explicit ports
           Fixed by adding _url_host() helper (uses .hostname) and updating all
           7 call sites. _normalize_url() also strips default ports (443/80) so
           the same URL with/without explicit default port deduplicates correctly.
  [V14-01] YARA external path detection rewritten (5-strategy search):
           Old: static list built at module load — failed when __file__ resolves
           to temp path under Streamlit, and never updated if file added later.
           New: _external_yara_path() recomputes candidates dynamically on every
           call using: (1) SHERLOCK_YARA_RULES env var, (2) realpath(__file__) dir,
           (3) os.getcwd(), (4) sys.argv[0] dir, (5) ~/.sherlock/ data dir.
           Uses os.path.realpath() not abspath() to resolve symlinks correctly.
  [V14-05] YARA auto-repair for truncated/broken triage_rules.yar files:
           When yara.compile() fails (as in: line 142: unexpected end of file),
           _yara_repair() surgically walks each rule block using brace-depth
           counting with full awareness of quoted strings, hex patterns, and
           comments. Complete rules are extracted and compiled; broken ones
           (typically only the last rule in a truncated file) are skipped.
           Result: Cofense IS active with partial load instead of complete fallback.
           UI shows amber "auto-repaired" banner with exact repair details.
           Three distinct UI states: ✅ green (full load), ⚠️ amber (repaired),
           ❌ red (repair also failed — shows terminal diagnostic command).
  [V14-04] YARA diagnostic panel: silent compile failure was the most likely
           cause of "9 built-in rules only" even when triage_rules.yar is present.
           _get_yara() now stores the compile error in _yara_last_error (global).
           _yara_found_path stores the path that was found even when compile fails.
           UI now shows three distinct states:
             GREEN  → Cofense rules loaded successfully
             RED    → File found but YARA compile failed (shows exact error + fix hint)
             YELLOW → File not found (shows expander with ALL searched paths + exists check)
           Analyst can now diagnose any path/compile issue without reading logs.
  [V14-02] _get_yara() cache invalidation: previous version permanently cached
           built-in-only ruleset — placing triage_rules.yar after startup had no
           effect until full Streamlit restart. Now re-checks for external file on
           every call until Cofense rules are successfully loaded. Once Cofense is
           loaded, the compiled ruleset is cached permanently (no repeat compiles).
  [V14-03] st.dataframe width="stretch" fixed (4 locations):
           "stretch" is not a valid Streamlit parameter — silently ignored.
           Replaced with use_container_width=True (the correct API).
  [V13-09] PDF security engine: pikepdf replaces peepdf (Python 3 compatible):
           peepdf is Python 2-only and unmaintained. pikepdf (wraps qpdf) provides
           equivalent security analysis: object-graph walking, stream decompression,
           dangerous-tag detection, JS snippet extraction, XFA detection, URI extraction.
           pdfminer retained for TEXT EXTRACTION only (different purpose).
           Three-tier URI extraction: pikepdf → pdfminer → raw-byte regex fallback.
           Graceful degradation if pikepdf unavailable: raw-byte fallback preserved.

v10.1 HARDENING CHANGELOG (Security Audit Fixes):
  [C01] SQLite connection leak: connections now use context manager + WAL mode
  [C02] BEC correlation signals NEVER matched: now emits individual category
        marker signals so cross-module correlations (e.g. shadow_spoof+bec)
        actually fire
  [C03] VT URL identifier used SHA256 instead of base64url: all URL lookups
        were returning 404/UNKNOWN - fixed to use base64url per VT API v3
  [C04] _VTLimiter.wait() slept while holding the lock: all 4 ThreadPool
        workers blocked - now releases lock before sleeping
  [C05] _tmp_file() leaked temp file on write error: path captured after write
        instead of before - now captures path before write
  [C06] VBA_Parser never closed on exception: resource leak in macro analysis
        fixed with try/finally
  [C07] lstrip('www.') strips individual characters, not prefix: 'wwonderful'
        became 'onderful' - replaced with proper prefix removal
  [C08] _vt_cache() accessed st.session_state from ThreadPoolExecutor threads:
        not thread-safe - now uses module-level thread-safe cache
  [C09] socket.setdefaulttimeout() is global: affected all threads - DNS now
        uses per-resolver timeouts
  [C10] No PIL decompression bomb guard: crafted images could OOM - added
        explicit MAX_IMAGE_PIXELS and data size checks
  [C11] pdfminer.extract_text can hang on malformed PDFs: no timeout - now
        wrapped in thread with configurable timeout
  [C12] ZIP bomb in _office_uris(): no size limit on extracted .rels files -
        added MAX_ZIP_EXTRACT limit
  [C13] extract_visible_text() no input size limit: huge HTML could OOM BS4 -
        added MAX_HTML_SIZE guard
  [C14] 35+ bare except: clauses caught SystemExit/KeyboardInterrupt - all
        changed to except Exception
  [C15] analyze_auth() only read first Authentication-Results header: emails
        with multiple AR headers from different gateways missed - now reads all
  [C16] _esc(0) returned empty string: falsy non-None values lost - fixed
  [C17] _root_domain() only handled 7 compound TLDs: typosquat detection
        broken for .co.za, .com.br, .co.jp etc - expanded to 30+
  [C18] Verdict values 'LIKELY MALICIOUS' and 'REVIEW' missing from _tc/_ti
        color/icon maps: UI showed wrong colors - added
  [C19] get_source_ip() recompiled 5 regex patterns on every call - moved to
        module-level precompiled patterns
  [C20] analyze_image() no data size limit: crafted 50MB image attachment
        could hang PIL/OCR - added MAX_IMAGE_SIZE guard
  [C21] check_malwarebazaar() could crash on empty data list despite
        query_status='ok' - added bounds check
  [C22] _normalize_url() and _add() in extract_observables parsed URL 3x -
        consolidated to single parse
  [C23] analyze_attachment() searched full file for [Content_Types].xml -
        limited search range to first 4KB for performance

v10.2 ACCURACY & VERDICT RELIABILITY FIXES:
  [S01] Display name spoof false positives: job titles (ceo, admin, support)
        split from brand names. Titles only flag on freemail/suspicious TLDs.
  [S02] Tier floor override: smarter floors that consider auth trust. YARA
        EXE_Magic on a legit attachment with full auth no longer auto-MALICIOUS.
  [S03] Live DNS results now feed into scoring: forged AR headers detected
        when live DNS contradicts header claims (SPF/DMARC).
  [S04] BEC false positives: single 'urgency' category capped at LOW. Require
        multi-category (financial+urgency or authority+financial) for HIGH+.
  [S05] Observable cap prioritized: shorteners, suspicious TLDs, high-entropy
        URLs sorted first before the 25-item cap is applied.
  [S06] MIME-encoded display name bypass: =?UTF-8?B?...?= decoded before
        spoof check so base64-encoded brand names are caught.
  [S07] Sender memory hardened: requires 60d+3 emails (was 30d+1), SPF PASS
        required, max dampening 10% (was 20%), stored in ~/.sherlock/ (was /tmp/).
  [S08] WHOIS socket timeout fully serialized under threading.Lock().
  [S09] Auth-Results parsing: word-boundary regex instead of substring match.
        "spf=pass (reason: was actually spf=fail)" no longer matches pass.
  [S10] Multi-user state: sender trust requires current email's SPF to pass,
        preventing cross-user trust bleeding from clean-then-attack pattern.
  [S11] BEC density denominator: uses visible body word count only, not the
        combined string that incorrectly included From header and Subject.

Installation:
  pip install -r requirements.txt

Setup .streamlit/secrets.toml:
  vt_api_key        = "YOUR_VIRUSTOTAL_KEY"
  abuseipdb_key     = "YOUR_ABUSEIPDB_KEY"
  otx_api_key       = "YOUR_OTX_KEY"        # Free: https://otx.alienvault.com
  xforce_api_key    = "YOUR_XFORCE_KEY"     # Free: https://exchange.xforce.ibmcloud.com
  xforce_api_secret = "YOUR_XFORCE_SECRET"  # Free: same account as above
  # MalwareBazaar: no key needed — public API
"""

# ═══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════
import streamlit as st
import email, email.policy, email.utils, email.header
import re, math, hashlib, json, html, tempfile, os, threading, io, time
import socket, logging, zipfile, contextlib, sqlite3, unicodedata
import base64
import pandas as pd, requests
from pathlib import Path
from urllib.parse import urlparse, unquote, parse_qs
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Set
from datetime import datetime, timezone
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import regex as _re_engine
    _RE_TIMEOUT = True
except ImportError:
    import re as _re_engine
    _RE_TIMEOUT = False

import uuid

# ── Optional SOAR / API deps ─────────────────────────────────────────────────
FASTAPI_OK = False  # REST API uses stdlib http.server — FastAPI/uvicorn not needed

try:
    from bs4 import BeautifulSoup, Comment
    BS4_OK = True
except ImportError:
    BS4_OK = False

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger("sherlock")

# Optional heavy deps – flags
PIL_OK = DNS_OK = QR_OK = OLETOOLS_OK = YARA_OK = PIKEPDF_OK = False
STEGANO_OK = WHOIS_OK = PDF_REPORT_OK = PDFMINER_OK = OCR_OK = False

try:
    from PIL import Image as PilImage
    PilImage.MAX_IMAGE_PIXELS = 178_956_970  # FIX(C10): explicit decompression bomb guard
    PIL_OK = True
except Exception:
    pass
try:
    import dns.resolver; DNS_OK = True
except Exception:
    pass
try:
    from pyzbar.pyzbar import decode as decode_qr; QR_OK = True
except Exception:
    pass
try:
    from oletools.olevba import VBA_Parser
    from oletools.oleid import OleID
    from oletools.mraptor import MacroRaptor as _MacroRaptor
    OLETOOLS_OK = True
except Exception:
    pass
try:
    import yara; YARA_OK = True
except Exception:
    pass
try:
    from stegano import lsb; STEGANO_OK = True
except Exception:
    pass
try:
    import whois as whois_lib; WHOIS_OK = True
except Exception:
    pass
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    PDF_REPORT_OK = True
except Exception:
    pass
try:
    from pdfminer.high_level import extract_text as pdfminer_extract
    from pdfminer.pdfparser import PDFParser as PDFMinerParser
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfpage import PDFPage
    PDFMINER_OK = True
except Exception:
    pass
try:
    import pikepdf
    PIKEPDF_OK = True
except Exception:
    PIKEPDF_OK = False
try:
    import pytesseract; OCR_OK = True
except Exception:
    pass

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
MAX_FILE_SIZE = 50 * 1024 * 1024
MAX_OBS = 25
REGEX_TIMEOUT = 2
DNS_TIMEOUT = 3
HTTP_TIMEOUT = 10
MAX_HTML_SIZE = 5 * 1024 * 1024       # FIX(C13): BS4 input size limit
MAX_IMAGE_SIZE = 20 * 1024 * 1024     # FIX(C20): image analysis size limit
MAX_ZIP_EXTRACT = 1 * 1024 * 1024     # FIX(C12): max size per extracted ZIP entry
PDFMINER_TIMEOUT = 5                  # FIX(C11): seconds before killing pdfminer
                                      # FIX(PERF): was 30s — legit PDFs parse in <1s;
                                      # malformed PDFs that hang should fail fast.

# FIX(PERF): Cache pikepdf scan results by PDF content hash.
# _pikepdf_security_scan() was previously called TWICE per PDF:
#   1. from _pdf_uris() to extract URLs
#   2. from analyze_attachment() for structural security analysis
# With a 30s timeout, a single malformed PDF caused 60s of dead time.
# The cache ensures we scan each unique PDF exactly once.
_PIKEPDF_CACHE: dict = {}
_PIKEPDF_CACHE_LOCK = threading.Lock()
CONTENT_TYPES_SEARCH_LIMIT = 4096     # FIX(C23): search range for [Content_Types].xml

# ── Compiled patterns ────────────────────────────────────────────────────────
def _rc(p, f=0):
    """Compile regex with optional timeout (if `regex` module is available)."""
    if _RE_TIMEOUT:
        try:
            return _re_engine.compile(p, f, timeout=REGEX_TIMEOUT)
        except (TypeError, ValueError):
            return _re_engine.compile(p, f)
    return re.compile(p, f)

PAT_EMAIL   = _rc(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PAT_DOMAIN  = _rc(r'@([\w\.-]+)')
PAT_URL     = _rc(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:[/?#][^\s<>"\']*)?', re.I)
PAT_HREF    = _rc(r'<a\s[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.DOTALL)
PAT_IPV4    = _rc(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PAT_TZ      = _rc(r'[+-]\d{4}')
PAT_PDF_URI = _rc(rb'/URI\s*\(([^)]{4,500})\)')
PAT_PDF_URL = _rc(rb'https?://[^\s\x00<>(){}\[\]"\'\\]{10,300}')

# FIX(C19): precompile private IP patterns at module level (were recompiled per-call)
_PRIVATE_IP_PATTERNS = [
    re.compile(r'^10\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^127\.'),
    re.compile(r'^169\.254\.'),
    re.compile(r'^0\.'),
]

# ── Keyword / classification sets ────────────────────────────────────────────
GOVERNMENT_TLDS = {
    '.gov', '.gov.uk', '.gov.au', '.gov.ca', '.gov.nz', '.gov.za', '.gov.in',
    '.gov.sg', '.gov.ae', '.gov.eg', '.gov.sa', '.gov.qa', '.gov.om',
    '.gov.bh', '.gov.kw', '.gov.jo', '.gov.lb', '.gov.iq', '.gov.il',
    '.gov.br', '.gov.mx', '.gov.co', '.gov.ar', '.gov.cl', '.gov.pk',
    '.gov.ng', '.gov.ke', '.gov.gh', '.gov.my', '.gov.ph', '.gov.tw',
    '.gov.hk', '.gov.cn', '.gov.jp', '.gov.kr', '.gov.th', '.gov.vn',
    '.gov.bd', '.gov.lk', '.gov.np', '.gov.mm',
    '.mil', '.mil.uk', '.mil.au', '.mil.ca',
    '.gc.ca', '.gob.mx', '.gob.ar', '.gob.cl', '.gob.pe', '.gob.es',
    '.go.jp', '.go.kr', '.go.th', '.go.ke', '.go.tz', '.go.id',
    '.gouv.fr', '.gouv.ci', '.gouv.sn', '.gouv.ml',
    '.govt.nz', '.government.nl',
}
EDUCATIONAL_TLDS = {
    '.edu', '.edu.au', '.edu.cn', '.edu.hk', '.edu.tw', '.edu.sg',
    '.edu.my', '.edu.ph', '.edu.pk', '.edu.in', '.edu.eg', '.edu.sa',
    '.edu.ae', '.edu.qa', '.edu.om', '.edu.bh', '.edu.jo', '.edu.lb',
    '.edu.br', '.edu.mx', '.edu.co', '.edu.ar', '.edu.cl',
    '.edu.ng', '.edu.za', '.edu.ke', '.edu.gh',
    '.ac.uk', '.ac.nz', '.ac.za', '.ac.in', '.ac.jp', '.ac.kr',
    '.ac.th', '.ac.id', '.ac.ir', '.ac.il', '.ac.ae', '.ac.ke',
    '.ac.tz', '.ac.ug', '.ac.rw', '.ac.bd', '.ac.lk', '.ac.cn',
    '.uni.edu', '.university',
}
MAJOR_TECH = {'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
              'github.com', 'linkedin.com', 'facebook.com', 'twitter.com'}

KNOWN_PLATFORMS = {
    'amazonses.com': 'Amazon SES', 'sendgrid.net': 'SendGrid',
    'mailchimp.com': 'Mailchimp', 'mailgun.org': 'Mailgun',
    'outlook.com': 'Microsoft 365', 'mandrillapp.com': 'Mandrill',
    'sparkpostmail.com': 'SparkPost', 'postmarkapp.com': 'Postmark',
}

# Marketing / tracking domains AND security gateway URL rewriters.
# These domains wrap or redirect links legitimately. Without this allowlist,
# every email processed by Proofpoint, Trend Micro, Mimecast, etc. triggers
# false-positive link-text mismatches (display shows original domain, href
# is rewritten to the gateway's domain).
TRACKING_ALLOWLIST = {
    # Marketing / email platforms
    'sendgrid.net', 'mailchimp.com', 'mailgun.org', 'mandrillapp.com',
    'sparkpostmail.com', 'postmarkapp.com', 'list-manage.com',
    'click.mailchimp.com',
    'us-east-2.amazonses.com',
    'click.pstmrk.it', 'ct.sendgrid.net',
    # Security gateway URL rewriters (these wrap URLs for click-time scanning)
    'safelinks.protection.outlook.com',   # Microsoft Safe Links
    'urldefense.proofpoint.com',          # Proofpoint URL Defense
    'urldefense.com',                     # Proofpoint URL Defense (short)
    'url.emailprotection.link',           # Generic email protection
    'trendmicro.com',                     # Trend Micro (root)
    'smex-ctp.trendmicro.com',           # Trend Micro Click Time Protection
    'imrworldwide.com',                   # Trend Micro / Nielsen
    'cloudmark.com',                      # Cloudmark
    'fireeye.com',                        # FireEye/Trellix URL rewriting
    'mimecast.com',                       # Mimecast (root — all *.mimecast.com subdomains)
    'mimecastprotect.com',               # Mimecast
    'protect-eu.mimecast.com',           # Mimecast EU
    'protect-us.mimecast.com',           # Mimecast US
    'protect-au.mimecast.com',           # Mimecast AU
    'protect-za.mimecast.com',           # Mimecast ZA
    'barracuda.com',                     # Barracuda link protection
    'linkprotect.cudasvc.com',           # Barracuda CUDA
    'secureweb.cisco.com',               # Cisco Email Security
    'ironport.com',                      # Cisco IronPort
    'sophos.com',                        # Sophos email protection
    'reflexion.net',                     # Sophos Reflexion
    'messagelabs.com',                   # Broadcom/Symantec
    'brightcloud.com',                   # Webroot BrightCloud
    'appriver.com',                      # AppRiver
    'zixcorp.com',                       # Zix encryption
    'websense.com',                      # Forcepoint/Websense
    'forcepoint.com',                    # Forcepoint
    # Additional gateways and regional ESPs commonly seen in enterprise email
    'egress.com',                        # Egress secure email
    'proofpoint.com',                    # Proofpoint (root)
    'pphosted.com',                      # Proofpoint hosted
    'ppe-hosted.com',                    # Proofpoint Protection Engine hosted
    'symantec.com',                      # Broadcom/Symantec
    'symanteccloud.com',                 # Symantec cloud gateway
    'hornetsecurity.com',               # Hornetsecurity
    'antispameurope.com',               # AntiSpam Europe
    'retarus.com',                       # Retarus ESG
    # NOTE: If you see a false-positive from a gateway NOT in this list, add its
    # root domain here. Do NOT use the substring bypass — that is a security hole.
}

MARKETING_RP_DOMAINS = {
    'amazonses.com', 'sendgrid.net', 'mailchimp.com', 'mailgun.org',
    'mandrillapp.com', 'sparkpostmail.com', 'postmarkapp.com',
    'bounces.google.com',
}

CLOUD_PROVIDERS = {
    'amazon': ['amazon.com', 'amazonaws.com'],
    'google': ['google.com', 'googlemail.com', 'googleusercontent.com'],
    'microsoft': ['microsoft.com', 'azure.com', 'outlook.com', 'office365.com'],
    'cloudflare': ['cloudflare.com', 'cloudflare.net'],
}

# FIX(S1): Split brand names from job titles. Job titles like 'ceo', 'admin',
# 'support' caused massive false positives because "CEO John Smith <john@acme.com>"
# fires when 'ceo' is not in the domain 'acme.com'. Job titles are now separate
# and only flag when combined with a freemail/suspicious domain, not any domain.
DISPLAY_NAME_BRANDS = [
    'microsoft', 'google', 'apple', 'amazon', 'paypal', 'facebook', 'netflix',
    'docusign', 'adobe',
]
DISPLAY_NAME_TITLES = [
    'helpdesk', 'it support', 'security team', 'admin',
    'support', 'ceo', 'cfo', 'cto', 'chief executive', 'chief financial',
    'managing director', 'human resources', 'hr department', 'accounts payable',
]
FREEMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'protonmail.com', 'icloud.com', 'mail.com', 'zoho.com', 'yandex.com',
    'gmx.com', 'live.com', 'inbox.com', 'fastmail.com', 'tutanota.com',
}

DANGEROUS_EXTS = {
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.hta', '.pif',
    '.wsf', '.msi', '.com', '.cpl', '.inf', '.reg', '.lnk', '.jar', '.jnlp',
    '.ws', '.vbe', '.jse', '.wsc', '.wsh', '.sct', '.url', '.application',
    # [v19] Disk image / container formats — bypass Mark-of-the-Web on Windows
    '.iso', '.img', '.vhd', '.vhdx', '.vmdk', '.wim',
}

# [v19] Container/archive extensions — password-protection of these is an AV bypass
CONTAINER_EXTS = frozenset({'.zip', '.7z', '.rar', '.gz', '.tar', '.bz2', '.xz'})

# [v19] Brand-in-subdomain detection: registered domains that should NEVER appear
# as a subdomain of a *different* registered domain. Conservative and intentionally
# small — only globally unambiguous names. Do not add short/common strings.
PROTECTED_BRANDS = frozenset({
    'paypal.com', 'apple.com', 'microsoft.com', 'google.com', 'amazon.com',
    'netflix.com', 'facebook.com', 'instagram.com', 'whatsapp.com',
    'linkedin.com', 'twitter.com', 'x.com', 'dropbox.com', 'docusign.com',
    'adobe.com', 'office365.com', 'live.com', 'outlook.com', 'wellsfargo.com',
    'bankofamerica.com', 'chase.com', 'citibank.com', 'irs.gov', 'gov.uk',
})

# [v19] Per-category density cap — signals above threshold contribute at reduced weight.
# Auth is high because SPF/DKIM/DMARC/shadow/dns are structurally independent checks.
# YARA is uncapped — each matched rule is independent forensic evidence.
CATEGORY_DENSITY_THRESHOLDS: dict = {
    'auth':       5,
    'behavioral': 4,
    'content':    3,
    'network':    3,
    'attachment': 2,
    'yara':       99,
}

DOUBLE_EXT_PATS = [
    (r'\.pdf\.exe$', 'PDF->EXE'), (r'\.doc\.exe$', 'DOC->EXE'),
    (r'\.jpg\.exe$', 'JPG->EXE'), (r'\.pdf\.js$', 'PDF->JS'),
    (r'\.doc\.scr$', 'DOC->SCR'), (r'\.xls\.exe$', 'XLS->EXE'),
    (r'\.txt\.exe$', 'TXT->EXE'), (r'\.pdf\.vbs$', 'PDF->VBS'),
    (r'\.pdf\.bat$', 'PDF->BAT'), (r'\.docx?\.lnk$', 'DOC->LNK'),
    (r'\.pdf\.hta$', 'PDF->HTA'), (r'\.zip\.exe$', 'ZIP->EXE'),
    (r'\.csv\.exe$', 'CSV->EXE'), (r'\.pdf\.cmd$', 'PDF->CMD'),
    (r'\.png\.exe$', 'PNG->EXE'), (r'\.jpg\.js$', 'JPG->JS'),
]

VALID_MIMES = {
    'pdf': ['application/pdf'],
    'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
    'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
    'doc': ['application/msword'], 'xls': ['application/vnd.ms-excel'],
    'zip': ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'],
    'rar': ['application/x-rar-compressed', 'application/octet-stream'],
    'png': ['image/png'], 'jpg': ['image/jpeg'], 'jpeg': ['image/jpeg'],
    'gif': ['image/gif'], 'txt': ['text/plain'], 'csv': ['text/csv', 'text/plain'],
    'html': ['text/html'], 'rtf': ['application/rtf', 'text/rtf'],
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'bl.ink', 'short.io', 'cutt.ly', 'rb.gy', 'snip.ly',
    'shorturl.at', 'tiny.cc', 'surl.li', 'v.gd', 'adf.ly',
}

# FIX(AUDIT-03): Moved to module level — was re-created on every call
_INNER_PARAM_NAMES = (
    'url', 'redirect', 'redirecturl', 'redirect_url', 'destination',
    'dest', 'goto', 'target', 'link', 'return', 'returnurl',
    'return_url', 'next', 'continue', 'u', 'q',
)

_PHISH_PARAMS = frozenset({
    'token', 'verify', 'account', 'confirm', 'secure', 'auth',
    'login', 'reset', 'credential', 'session', 'validate',
})

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.work', '.buzz', '.surf', '.rest', '.icu', '.cam',
    '.monster', '.cyou', '.cfd', '.sbs', '.click', '.link', '.gq', '.ml', '.cf',
    '.ga', '.tk', '.pw', '.cc', '.ws', '.bid', '.loan', '.trade', '.racing',
    '.review', '.cricket', '.win', '.party', '.download', '.stream',
}

# ─────────────────────────────────────────────────────────────────────────────
# BEC_KEYWORDS: restructured into three tiers to eliminate false positives.
#
# TIER 1 — HIGH-SPECIFICITY (standalone meaningful, score contributes directly)
#   These phrases have no normal business purpose outside of fraud context.
#   Even a single hit from tier-1 warrants MEDIUM scoring.
#
# TIER 2 — CONTEXT-DEPENDENT (only meaningful combined with auth failure/spoof)
#   Common in legitimate business emails. Scored, but generate_signals() applies
#   an auth-clean dampening factor that reduces their effective weight when
#   SPF+DKIM+DMARC all pass and no spoofing is detected.
#
# TIER 3 — WEAK SIGNALS (noise without corroboration, capped at LOW)
#   Near-ubiquitous in normal business email. These are retained only for
#   correlation with tier-1/tier-2 hits; alone they never exceed LOW risk.
#
# Probability values represent P(BEC | keyword present) — calibrated against
# the false-positive review in [S04] and extended in v13 overhaul.
# ─────────────────────────────────────────────────────────────────────────────
BEC_KEYWORDS = {
    # ── TIER 1: High-specificity — standalone meaningful ─────────────────────
    # "wire transfer" / "IBAN" / "routing number" have no plausible FP in email
    # content that isn't actually discussing a financial transaction redirect.
    'wire_transfer': (
        ['wire transfer', 'bank transfer', 'swift transfer',
         'routing number', 'beneficiary account', 'iban number',
         'send the funds', 'transfer the funds'],
        0.75),

    # Gift card fraud: extremely specific, almost never legitimate business use.
    # Removed generic 'prepaid card' (used in legit expense reimbursement).
    'gift_cards': (
        ['gift card', 'itunes card', 'amazon gift card', 'google play card',
         'steam gift card', 'buy gift cards', 'scratch the card'],
        0.70),

    # Explicit secrecy demands: a hallmark of BEC that has no legitimate use.
    # Narrowed from 'discreet' (used in recruiting/HR) and 'off the record'
    # (common in management conversation) to explicit "do not tell anyone" variants.
    'secrecy': (
        ['keep this between us', 'do not tell anyone', 'do not discuss this',
         'keep this confidential from', 'do not cc anyone',
         'reply to me only', 'do not forward this'],
        0.65),

    # Payment redirect with new banking details: nearly always fraudulent.
    # Removed 'revised invoice' and 'updated invoice' — extremely common in AP.
    'payment_redirect': (
        ['new bank details', 'new banking details', 'updated bank account',
         'change the payment account', 'new vendor account number',
         'please update your records with', 'new account for payments'],
        0.72),

    # ── TIER 2: Context-dependent — need auth failure or spoof to matter ─────
    # Authority language: common in legitimate management emails.
    # Narrowed to explicit delegation/override phrases; removed 'executive decision'
    # and 'board has approved' which appear in legitimate board communications.
    'authority': (
        ['skip the normal approval', 'bypass the approval process',
         'i authorize you to proceed', 'acting on behalf of the ceo',
         'per direct instruction from', 'i need you to handle this personally'],
        0.50),

    # Invoice fraud: HIGHLY PROBLEMATIC — every AP department receives emails
    # with "invoice number", "payment due", "outstanding balance" daily.
    # Retained ONLY for the most unambiguous redirect-plus-urgency phrases.
    # Single hits from this category are capped at LOW regardless of score.
    'invoice_fraud': (
        ['please update your payment to our new account',
         'our bank details have changed', 'new payment instructions attached',
         'send payment to the new account below',
         'remit to the updated banking details'],
        0.58),

    # MFA bypass: common in legitimate IT security communications and 2FA services.
    # Drastically narrowed to phrases that only appear in social engineering
    # (asking someone to SHARE or APPROVE a code they received).
    'mfa_bypass': (
        ['share the verification code with me', 'send me the code you received',
         'approve the sign-in on my behalf', 'forward the authentication code',
         'read me the code from your phone'],
        0.62),

    # CEO fraud (pretexting): narrowed to phrases that establish false context
    # and explicitly request secrecy or non-standard communication.
    'ceo_fraud': (
        ['do not call me on this', 'reply only by email on this matter',
         'handle this without going through the normal process',
         'i cannot take calls right now but need this done',
         'this is time-sensitive do not discuss with anyone'],
        0.55),

    # Credential harvest: kept only for explicit deceptive-action phrases.
    # 'verify identity', 'account locked', 'suspicious activity' are used by
    # every legitimate bank, cloud provider, and SSO system.
    'credential_harvest': (
        ['enter your credentials to continue', 'your session has expired click to re-authenticate',
         'click here to verify your account or it will be suspended',
         'your account access will be removed unless you verify'],
        0.60),

    # ── TIER 3: Weak signals — retained only for correlation bonuses ──────────
    # Urgency: the most common FP source in the original BEC system. Present in
    # virtually every SLA-driven business email. analyze_bec() hard-caps this
    # category at score=0.10 when it fires alone (enforced in FIX(S4)).
    # Now even more strictly limited to multi-word urgency phrases.
    'urgency': (
        ['must be done today without fail', 'critical deadline do not delay',
         'process this before close of business today',
         'cannot wait this is extremely urgent'],
        0.30),

    # Shipping scam: removed entirely from scoring. FedEx/UPS/DHL/Amazon all
    # routinely send emails with "package on hold", "delivery failed",
    # "shipment tracking" and "customs fee". This category generated an
    # enormous volume of false positives on legitimate transactional email.
    # Category retained as a no-op (empty list) so existing correlation
    # references in BEHAVIORAL_PATTERNS / SIGNAL_CORRELATIONS don't break.
    'shipping_scam': (
        [],  # DISABLED — see v13 BEC overhaul notes above
        0.0),
}

BEC_CONTRADICTIONS = [
    (['urgent', 'immediately', 'asap'], ['no rush', 'no hurry', 'when you can',
                                          'at your convenience', 'take your time']),
]

SUSPICIOUS_PHRASES = {
    'verify_account': (
        [r'verify your account', r'validate your account', r'click to verify', r'account.*suspend'], 20),
    'password_issue': (
        [r'password.*expire', r'password.*change', r'reset.*password'], 15),
    'mailbox_full': (
        [r'mailbox.*full', r'quota.*exceeded', r'limit.*reached'], 15),
    'generic_threat': (
        [r'final notice', r'legal action', r'court appearance', r'arrest warrant'], 25),
    'credential_lure': (
        [r'click here to verify', r'click the link below', r'update your information',
         r'confirm your identity', r'log in to your account'], 20),
    # [I04] Behavioral pattern signatures (structural, not just keywords)
    'payment_diversion': (
        [r'bank.*details.*changed', r'new.*account.*number', r'please.*update.*payment',
         r'our.*banking.*details.*have'], 30),
    'mfa_social_eng': (
        [r'approve.*request', r'deny if not you', r'sign-in attempt.*detected',
         r'verify.*it.*was you', r'confirm.*access'], 25),
    'invoice_pressure': (
        [r'invoice.*attached', r'payment.*overdue', r'amount.*due.*today',
         r'immediate.*payment.*required'], 20),
    # FIX: 'conversation_hijack' removed — phrases like "as we discussed", "per our conversation",
    # and "re:.*meeting" fire on virtually every legitimate reply email. The comment said
    # "needs auth failure to matter" but body_findings are emitted as signals regardless of auth,
    # causing analyst confusion and minor score inflation on clean reply threads.
    # If conversation hijacking is needed, implement it as a compound signal (auth_fail + thread_context).
}

# [I04] Behavioral Attack-Pattern signatures.
# These are STRUCTURAL patterns (field combinations, not just word presence)
# that map to known attack categories used for narrative generation.
BEHAVIORAL_PATTERNS = {
    'ceo_fraud': {
        'signals': ['bec_authority', 'bec_urgency', 'bec_secrecy'],
        'require_any': 2,
        'narrative': 'CEO/executive fraud — impersonation of authority figure requesting urgent covert action',
        'attack_vector': 'BEC / Social Engineering',
    },
    'wire_fraud': {
        'signals': ['bec_wire_transfer', 'bec_urgency', 'spf_fail'],
        'require_any': 2,
        'narrative': 'Wire fraud — financial transfer request with spoofed or unauthorized sender',
        'attack_vector': 'BEC / Financial Fraud',
    },
    'credential_phishing': {
        'signals': ['link_text_mismatch', 'display_name_spoof', 'bec_credential_harvest'],
        'require_any': 2,
        'narrative': 'Credential phishing — deceptive links and impersonation to steal login credentials',
        'attack_vector': 'Phishing / Credential Theft',
    },
    'malware_delivery': {
        'signals': ['malware_hash', 'yara_VBA_Macro_Dropper', 'yara_PS_In_Macro'],
        'require_any': 1,
        'narrative': 'Malware delivery — attachment carries malicious code for initial access',
        'attack_vector': 'Malware / Initial Access',
    },
    'invoice_fraud': {
        'signals': ['bec_invoice_fraud', 'bec_payment_redirect', 'shadow_spoofing'],
        'require_any': 2,
        'narrative': 'Invoice fraud — manipulated invoice or payment redirect targeting accounts payable',
        'attack_vector': 'BEC / Invoice Fraud',
    },
    'mfa_bypass': {
        'signals': ['bec_mfa_bypass', 'display_name_spoof', 'link_text_mismatch'],
        'require_any': 2,
        'narrative': 'MFA bypass attempt — social engineering to intercept authentication codes',
        'attack_vector': 'Account Takeover / MFA Bypass',
    },
    'infra_phishing': {
        'signals': ['suspicious_tld', 'typosquat', 'high_entropy_url',
                    'dga_domain_entropy', 'dga_domain_consonant'],
        'require_any': 2,
        'narrative': 'Infrastructure-based phishing — attacker-controlled domain mimicking legitimate services',
        'attack_vector': 'Phishing / Domain Spoofing',
    },
}

PDF_META_NS = {'ns.adobe.com', 'purl.org/dc', 'w3.org/1999', 'w3.org/2000',
               'schemas.openxmlformats', 'schemas.microsoft.com'}

LEGIT_MAILERS = ['microsoft outlook', 'thunderbird', 'apple mail', 'lotus notes',
                 'evolution', 'mutt', 'sendgrid', 'mailchimp', 'postfix', 'exim',
                 'sendmail', 'amazon ses', 'mailgun', 'postmark', 'gmail', 'yahoo']

# ── YARA rules source ────────────────────────────────────────────────────────
YARA_SRC = r"""
// ── Rule 1: VBA macro dropper (download + auto-execution) ────────────────────
// Requires BOTH a network-fetch API AND an auto-run entry point.
// High specificity: legitimate macros do not combine HTTP download with AutoOpen.
rule VBA_Macro_Dropper {
  meta:
    description = "VBA download+autoexec dropper"
    severity    = "CRITICAL"
    category    = "macro"
  strings:
    $d1 = "URLDownloadToFile" nocase
    $d2 = "XMLHTTP"           nocase
    $d3 = "WinHttpRequest"    nocase
    $e1 = "AutoOpen"          nocase
    $e2 = "Document_Open"     nocase
    $e3 = "Workbook_Open"     nocase
    $s  = "WScript.Shell"     nocase
  condition:
    ($d1 or $d2 or $d3) and ($e1 or $e2 or $e3 or $s)
}

// ── Rule 2: Obfuscated VBA (raised to 4-of-6 to cut legit-macro FP) ─────────
// Chr(), Asc(), Environ() appear in legitimate VBA for string handling.
// Four concurrent obfuscation primitives is a high-confidence signal.
rule VBA_Obfuscated {
  meta:
    description = "Obfuscated VBA (multi-primitive)"
    severity    = "HIGH"
    category    = "macro"
  strings:
    $a = "Chr("        nocase
    $b = "StrReverse(" nocase
    $c = "Environ("    nocase
    $d = "CallByName(" nocase
    $e = "Execute("    nocase
    $f = "Asc("        nocase
  condition:
    4 of them
}

// ── Rule 3: PDF JavaScript exploit ───────────────────────────────────────────
// Requires: auto-exec hook (/OpenAction) + JS engine + code eval/decode.
// All three components required — none is suspicious alone.
rule PDF_JS_Exploit {
  meta:
    description = "PDF JavaScript exploit chain"
    severity    = "HIGH"
    category    = "pdf"
  strings:
    $j1 = "/JavaScript"
    $j2 = "/JS"
    $ev = "eval("     nocase
    $un = "unescape(" nocase
    $oa = "/OpenAction"
  condition:
    $oa and ($j1 or $j2) and ($ev or $un)
}

// ── Rule 4: PDF /Launch with OS-platform target ───────────────────────────────
// FIX: Previous rule used only /Launch + /Action. /Action appears in every
// GoTo/URI action, making the old rule far too broad. Now requires a platform
// dictionary (/Win, /Unix, /Mac) which is only present in genuine Launch actions.
rule PDF_Launch {
  meta:
    description = "PDF /Launch action (OS command execution)"
    severity    = "CRITICAL"
    category    = "pdf"
  strings:
    $launch = "/Launch"
    $action = "/Action"
    $win    = "/Win"
    $unix   = "/Unix"
    $mac    = "/Mac"
  condition:
    $launch and $action and (1 of ($win, $unix, $mac))
}

// ── Rule 5: Executable magic bytes ───────────────────────────────────────────
// BUG FIXED: $pe was defined as "PE\x00\x00" inside a Python raw string.
// In a raw string, \ is a literal backslash, so YARA received "PE\x00\x00"
// meaning it searched for PE + ASCII backslash + x00 (not null bytes).
// PE signature is now correctly expressed as hex bytes {50 45 00 00}.
rule EXE_Magic {
  meta:
    description = "Executable magic bytes (MZ/ELF/PE)"
    severity    = "CRITICAL"
    category    = "executable"
  strings:
    $mz  = { 4D 5A }        // MZ DOS header
    $pe  = { 50 45 00 00 }  // PE\0\0 signature (FIXED: was broken double-escape)
    $elf = { 7F 45 4C 46 }  // ELF magic
  condition:
    ($mz at 0) or ($elf at 0) or $pe
}

// ── Rule 6: Archive container magic bytes ────────────────────────────────────
// analyze_attachment() suppresses this for files with matching extensions.
// Fires when a file claims to be one type but is structurally an archive.
rule Archive_Sig {
  meta:
    description = "Archive magic bytes (possible disguised container)"
    severity    = "MEDIUM"
    category    = "archive"
  strings:
    $zip = { 50 4B 03 04 }       // ZIP / OOXML
    $rar = { 52 61 72 21 1A 07 } // RAR
    $sz  = { 37 7A BC AF 27 1C } // 7-Zip
  condition:
    any of them
}

// ── Rule 7: HTML credential-harvesting form ───────────────────────────────────
// FIX: Previous condition ($form AND 2-of-4) triggered on any HTML email from
// IT helpdesk or forwarded SharePoint pages with a form + the word "password".
// Now requires 3-of-5 phishing-specific content strings alongside the form tag.
// "password" alone is excluded from the count — it must co-occur with 3 others.
rule Phishing_Form {
  meta:
    description = "HTML credential harvesting form (tightened)"
    severity    = "HIGH"
    category    = "phishing"
  strings:
    $form = "<form"               nocase
    $vfy  = "verify your account" nocase
    $sus  = "account suspended"   nocase
    $act  = "immediate action"    nocase
    $sub  = "confirm your identity" nocase
    $exp  = "account will expire"  nocase
  condition:
    $form and (3 of ($vfy, $sus, $act, $sub, $exp))
}

// ── Rule 8: VBA registry run-key persistence ─────────────────────────────────
rule Macro_Registry {
  meta:
    description = "VBA registry run-key persistence"
    severity    = "HIGH"
    category    = "macro"
  strings:
    $rw = "RegWrite"            nocase
    $hk = "HKEY_"              nocase
    $rk = "CurrentVersion\\Run" nocase
  condition:
    $rw and ($hk or $rk)
}

// ── Rule 9: PowerShell evasion inside macro ───────────────────────────────────
// Requires PowerShell invocation + 2 evasion flags.
// A bare PowerShell call without evasion is not automatically malicious.
rule PS_In_Macro {
  meta:
    description = "PowerShell evasion in macro"
    severity    = "CRITICAL"
    category    = "macro"
  strings:
    $ps  = "PowerShell"              nocase
    $enc = "-EncodedCommand"         nocase
    $byp = "-ExecutionPolicy Bypass" nocase
    $hid = "-WindowStyle Hidden"     nocase
    $dl  = "DownloadString"          nocase
  condition:
    $ps and (2 of ($enc, $byp, $hid, $dl))
}
"""

# ── External Cofense threat-intel ruleset ─────────────────────────────────────
_SENDER_DB_DIR_FOR_YARA = os.environ.get(
    'SHERLOCK_DATA_DIR', os.path.join(os.path.expanduser('~'), '.sherlock'))

# FIX(v14): Do NOT pre-compute paths into a static list at module load time.
# The old approach failed in two ways:
#   1. If triage_rules.yar was placed in the directory AFTER startup, the
#      cached list never re-evaluated — Streamlit restart was required.
#   2. Under Streamlit's hot-reload watcher, __file__ sometimes resolves to
#      a temp/symlinked path, making dirname(__file__) point to /tmp instead
#      of the actual script directory.
# The fix: _external_yara_path() recomputes candidate paths on EVERY call
# using multiple strategies so at least one will find the file.

_TRIAGE_FILENAME = 'triage_rules.yar'

def _external_yara_path() -> str:
    """Find triage_rules.yar using multiple path strategies.
    Called on every _get_yara() invocation (which itself is cached after first
    successful compile) — so a newly placed file is picked up on next analysis
    without needing to restart Streamlit.

    Search order (first match wins):
      1. Explicit env var SHERLOCK_YARA_RULES
      2. Same directory as the running script (__file__)
      3. Current working directory (where `streamlit run` was launched from)
      4. Absolute path of argv[0] directory (covers some Streamlit edge cases)
      5. ~/.sherlock/ data directory
    """
    candidates = []

    # 1. Explicit env override — highest priority
    env_path = os.environ.get('SHERLOCK_YARA_RULES', '').strip()
    if env_path:
        candidates.append(env_path)

    # 2. Same directory as the script file (most common case)
    try:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        candidates.append(os.path.join(script_dir, _TRIAGE_FILENAME))
    except Exception:
        pass

    # 3. Current working directory (where `streamlit run` was invoked)
    try:
        candidates.append(os.path.join(os.getcwd(), _TRIAGE_FILENAME))
    except Exception:
        pass

    # 4. Directory of sys.argv[0] (covers edge cases where __file__ is temp)
    try:
        import sys
        argv0_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        if argv0_dir and argv0_dir not in ('', '.'):
            candidates.append(os.path.join(argv0_dir, _TRIAGE_FILENAME))
    except Exception:
        pass

    # 5. Persistent data directory fallback
    candidates.append(os.path.join(_SENDER_DB_DIR_FOR_YARA, _TRIAGE_FILENAME))

    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return ""

# ── Rules that detect binary file structure: MUST NOT scan raw email bytes ────
_ATTACHMENT_ONLY_RULES = frozenset({
    'EXE_Magic', 'Archive_Sig', 'PDF_Launch', 'PDF_JS_Exploit',
    'VBA_Macro_Dropper', 'VBA_Obfuscated', 'PS_In_Macro', 'Macro_Registry',
    'PM_exe_in_iso', 'PM_mz_executable', 'PM_Zip_With_doc', 'PM_Zip_With_Exe',
    'PM_Zip_With_PDF', 'PM_Zip_With_ppt', 'PM_Zip_With_xls', 'PM_zip_with_htm',
    'PM_Labs_Zip_in_Zip', 'PM_Intel_vhd_attachment',
})

# ── Enrichment-only rules: informational, never contribute to threat score ────
_ENRICHMENT_RULES = frozenset({
    # ── Sender/routing context ─────────────────────────────────────────────────
    'CY_Sender_is_NOREPLY',      # noreply/no-reply — extremely common, not malicious
    'CY_URL_Redirect',           # url=http — fires on almost every marketing email
    'PM_SPF_Pass',               # SPF pass is a POSITIVE indicator, not a threat
    'CY_Mailer_Not_Office_Outlook',  # fires on every Gmail/Thunderbird/Mailchimp/etc.
    'CY_Mobile_Phone_Text_To_Email', # SMS-to-email gateway, purely informational
    # ── File format identification (structural, not malicious) ─────────────────
    # These are handled in _yara_scan() per-attachment with magic-byte guards.
    # Listing them here ensures _yara_scan_email() treats them as enrichment too.

    # ── Noisy Cofense Rules to Suppress ────────────────────────────────────────
    'PM_Labs_Potential_Malware_Reply_Chain', # False positive on normal email replies

    'PM_pdf_document',           # %PDF- header → every PDF
    'PM_zip_file',               # ZIP magic bytes → every .zip / Office OOXML
    'PM_xlsx_file',              # xl/_rels/ → every valid Excel OOXML
    'PM_docx_file',              # word/_rels/ → every valid Word OOXML
    'PM_pptx_file',              # ppt/slides/_rels → every valid PowerPoint OOXML
    'PM_office_magic_bytes',     # OLE2 magic → every old .doc/.xls/.ppt
    'PM_word_document',          # OLE2 + WordDocument → every valid .doc
    'PM_excel_document',         # OLE2 + Workbook → every valid .xls
    'PM_powerpoint_document',    # OLE2 + PowerPoint → every valid .ppt
    'PM_rtf_file',               # {\rtf at 0 → every valid RTF
    'CY_PDF_With_Links',         # %PDF- + URI annotation → every PDF with a hyperlink
})
_ENRICHMENT_PREFIXES = (
    'CY_CofenseLabs_ServiceID_', # gateway identification rules (Proofpoint, Mimecast, etc.)
    'PM_TNR_',                   # Cofense Triage Noise-Reduction labels — internal classification only
)

# ── Malware families that warrant CRITICAL severity ───────────────────────────
_CRITICAL_MALWARE_FAMILIES = frozenset({
    'XWorm', 'Xworm', 'AsyncRAT', 'Async', 'Remcos', 'RemcosRAT',
    'AgentTesla', 'QakBot', 'Emotet', 'TrickBot', 'IcedID', 'Dridex',
    'BazarBackdoor', 'Ursnif', 'Geodo', 'PikaBot', 'WarmCookie',
    'RedLine', 'Vidar', 'Stealc', 'Lumma', 'PureLogs', 'Raccoon',
    'Rhadamanthys', 'FormBook', 'FormGrabber', 'NanoCore', 'njRAT',
    'DcRAT', 'AveMaria', 'BitRAT', 'Loda', 'jRAT', 'STRRAT',
    'CobaltStrike', 'Covenant', 'BumbleBee', 'Locky', 'TeslaCrypt',
    'Cerber', 'HackBrowserData', 'DBatLoader', 'DELoader', 'DanaBot',
    'ZLoader', 'BetaBot', 'Andromeda', 'ConnectWise', 'NetSupport',
    'WSHRAT', 'WshRAT', 'Vjw0rm', 'DarkGate', 'DarkComet', 'RevengeRAT',
    'Astaroth', 'SmokeLoader', 'Smoke', 'SquirrelWaffle', 'Valak',
    'TrueBot', 'VenomRAT', 'WhiteSnake', 'Stealerium', 'VIPKeylogger',
    'RisePro', 'Strela', 'LokiBot', 'AZORult', 'Amadey', 'Mispadu',
    'QuasarRAT', 'Quasar', 'DarkCrystal', 'Bandook', 'NetWire',
})

def _cofense_severity(rule_name: str, meta: dict) -> str:
    """Infer severity for any YARA rule. Built-ins carry explicit severity= meta."""
    if 'severity' in meta:
        return meta['severity'].upper()
    if rule_name in _ENRICHMENT_RULES:
        return 'INFO'
    if any(rule_name.startswith(p) for p in _ENRICHMENT_PREFIXES):
        return 'INFO'
    if rule_name.startswith('PM_Intel_') or rule_name.startswith('PM_'):
        for family in _CRITICAL_MALWARE_FAMILIES:
            if family.lower() in rule_name.lower():
                return 'CRITICAL'
        if 'CredPhish' in rule_name or 'UR_CredPhish' in rule_name:
            return 'HIGH'
        return 'HIGH'
    if rule_name.startswith('CY_PDC_Phish_') or rule_name.startswith('CY_Phish_'):
        return 'HIGH'
    if rule_name in ('CY_HTML_Meta_Refresh', 'CY_BEC_Aging_Report'):
        return 'MEDIUM'
    if rule_name.startswith('CY_FMR_'):
        return 'LOW'
    if rule_name.startswith('CY_'):
        return 'MEDIUM'
    return 'MEDIUM'

def _is_enrichment_rule(rule_name: str) -> bool:
    if rule_name in _ENRICHMENT_RULES:
        return True
    if any(rule_name.startswith(p) for p in _ENRICHMENT_PREFIXES):
        return True
    return False

# ── YARA engine globals ────────────────────────────────────────────────────────
_yara_rules          = None
_yara_lock           = threading.Lock()
_yara_cofense_loaded = False
_yara_last_error     = ""   # Last compile error — shown in UI diagnostics
_yara_found_path     = ""   # Path that was found (even if compile failed) — for UI

_BUILTIN_RULE_COUNT = YARA_SRC.count('\nrule ') + (1 if YARA_SRC.startswith('rule ') else 0)


def _yara_repair(src: str):
    """Surgically extract every syntactically complete rule from a broken YARA file.

    Called automatically when yara.compile() fails. Walks each rule block using a
    brace-depth counter with correct handling for:
      • Quoted strings  "..."   — ignores { } inside them
      • Hex patterns    { }     — balanced, so depth tracking works naturally
      • Line comments   //      — skipped entirely
      • Block comments  /* */   — skipped entirely

    Returns:
      (repaired_src, skipped_names, error_details)
      repaired_src  — joined source of all complete rules (safe to compile)
      skipped_names — list of rule names that were incomplete/broken
      error_details — human-readable explanation of each skipped rule
    """
    import re as _re
    valid_rules  = []
    skipped_names = []
    error_details = []

    rule_re = _re.compile(
        r'(?m)(?:^|\n)((?:(?:private|global)\s+)*rule\s+\w+(?:\s*:\s*[\w\s]+?)?\s*\{)'
    )
    starts = [(m.start(), m.group(1)) for m in rule_re.finditer(src)]

    if not starts:
        return src, [], ["No rule declarations found — file may be empty or corrupted"]

    for i, (pos, header) in enumerate(starts):
        end   = starts[i + 1][0] if i + 1 < len(starts) else len(src)
        chunk = src[pos:end].strip()
        name_m = _re.search(r'rule\s+(\w+)', header)
        rule_name  = name_m.group(1) if name_m else f"rule_{i}"
        start_line = src[:pos].count('\n') + 1

        depth    = 0
        j        = 0
        n        = len(chunk)
        complete = False

        while j < n:
            c = chunk[j]

            # ── Line comment: skip to EOL ──────────────────────────────
            if c == '/' and j + 1 < n and chunk[j + 1] == '/':
                while j < n and chunk[j] != '\n':
                    j += 1
                continue

            # ── Block comment: skip to */ ──────────────────────────────
            if c == '/' and j + 1 < n and chunk[j + 1] == '*':
                j += 2
                while j < n - 1 and not (chunk[j] == '*' and chunk[j + 1] == '/'):
                    j += 1
                j += 2
                continue

            # ── Quoted string: skip "..." respecting backslash escapes ─
            if c == '"':
                j += 1
                while j < n:
                    if chunk[j] == '\\' and j + 1 < n:
                        j += 2
                        continue
                    if chunk[j] == '"':
                        j += 1
                        break
                    j += 1
                continue

            # ── Brace depth (hex strings are naturally balanced) ───────
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    complete = True
                    break

            j += 1

        if complete:
            valid_rules.append(chunk)
        else:
            skipped_names.append(rule_name)
            error_details.append(
                f"Rule '{rule_name}' at line {start_line}: "
                f"brace depth={depth} at end of block "
                f"(file truncated or unclosed string/hex pattern)"
            )

    return '\n\n'.join(valid_rules), skipped_names, error_details


def _get_yara():
    """Compile and cache the full YARA ruleset (built-in + external Cofense file).

    FIX(v14-01): Re-checks for triage_rules.yar on every call until Cofense loads.
    FIX(v14-05): Auto-repair of truncated/broken .yar files via _yara_repair().
                 If the file fails to compile outright, we surgically extract every
                 complete rule block and compile those. Broken rules are skipped and
                 reported. This recovers the ~99% of rules that are fine when only
                 the last rule is truncated (the common download-corruption case).
    """
    global _yara_rules, _yara_cofense_loaded
    if not YARA_OK:
        return None

    with _yara_lock:
        global _yara_last_error, _yara_found_path

        # Cofense fully loaded → return cached ruleset
        if _yara_rules is not None and _yara_cofense_loaded:
            return _yara_rules

        ext_path = _external_yara_path()
        if ext_path:
            _yara_found_path = ext_path
            try:
                with open(ext_path, 'r', encoding='utf-8', errors='ignore') as fh:
                    cofense_src = fh.read()

                # ── Primary compile: file as-is ────────────────────────
                try:
                    compiled = yara.compile(sources={
                        'builtin': YARA_SRC,
                        'cofense': cofense_src,
                    })
                    _yara_rules = compiled
                    _yara_cofense_loaded = True
                    _yara_last_error = ""
                    ext_count = (cofense_src.count('\nrule ') +
                                 (1 if cofense_src.startswith('rule ') else 0))
                    log.info(f"YARA: compiled {_BUILTIN_RULE_COUNT} built-in + "
                             f"{ext_count} external rules from {ext_path}")
                    return _yara_rules

                except Exception as primary_err:
                    # ── Auto-repair: extract only complete rule blocks ──
                    log.warning(f"YARA primary compile failed ({primary_err}) — "
                                f"attempting surgical repair of {ext_path}")
                    repaired_src, skipped, repair_errors = _yara_repair(cofense_src)

                    if not repaired_src.strip():
                        raise RuntimeError(
                            f"Repair found no valid rules. "
                            f"Original error: {primary_err}"
                        ) from primary_err

                    compiled = yara.compile(sources={
                        'builtin': YARA_SRC,
                        'cofense': repaired_src,
                    })
                    _yara_rules = compiled
                    _yara_cofense_loaded = True

                    ext_count = (repaired_src.count('\nrule ') +
                                 (1 if repaired_src.startswith('rule ') else 0))
                    skip_msg = (f", {len(skipped)} broken rule(s) skipped: "
                                f"{', '.join(skipped[:5])}"
                                f"{'…' if len(skipped) > 5 else ''}"
                                if skipped else "")
                    _yara_last_error = (
                        f"⚠️ Auto-repaired: {ext_count} rules loaded{skip_msg}. "
                        f"Original error: {primary_err}"
                    )
                    log.info(f"YARA repair: compiled {_BUILTIN_RULE_COUNT} built-in + "
                             f"{ext_count} external rules ({len(skipped)} skipped){skip_msg}")
                    for detail in repair_errors:
                        log.warning(f"  YARA skipped: {detail}")
                    return _yara_rules

            except Exception as e:
                _yara_last_error = str(e)
                log.error(f"YARA compile + repair both failed: {e}")
        else:
            _yara_found_path = ""

        # Built-in only fallback
        if _yara_rules is not None:
            return _yara_rules
        try:
            _yara_rules = yara.compile(source=YARA_SRC)
            _yara_cofense_loaded = False
            log.info(f"YARA: compiled {_BUILTIN_RULE_COUNT} built-in rules only "
                     f"(triage_rules.yar not found)")
            return _yara_rules
        except Exception as e:
            log.error(f"YARA built-in compile failed: {e}")
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════
@dataclass
class ThreatSignal:
    """Core unit of analysis. Every detection module emits these."""
    name: str
    category: str        # auth, content, attachment, network, behavioral
    tier: int            # 1=hard evidence, 2=strong, 3=heuristic, 4=contextual
    probability: float   # 0.0-1.0 how likely this indicates a real threat
    confidence: float    # 0.0-1.0 how sure we are in this detection
    title: str
    detail: str
    evidence: str = ""
    attack_vector: str = ""  # FIX [I08]: field was documented in changelog but missing from dataclass


@dataclass
class TrustFactor:
    """Positive signal that dampens threat score."""
    name: str
    strength: float      # 0.0-1.0
    confidence: float
    description: str


@dataclass
class VTResult:
    success: bool = False; total: int = 0; malicious: int = 0
    weighted: float = 0.0; engines: List[str] = field(default_factory=list)
    threat_level: str = "UNKNOWN"; reasoning: str = ""; error: str = ""
    is_new: bool = False; domain_intel: Optional[Any] = None


@dataclass
class DomainIntel:
    domain: str; category: str = "unknown"; trusted: bool = False
    age_days: int = 0; org: str = ""; reasoning: str = ""
    typosquat: str = ""; platform: str = ""


@dataclass
class AuthResult:
    spf: str = "NONE"; dkim: str = "NONE"; dmarc: str = "NONE"
    source_ip: str = ""; from_domain: str = ""; rp_domain: str = ""
    from_full: str = ""; rp_full: str = ""
    shadow_spoof: bool = False; gateway_trust: bool = False; gateway_name: str = ""
    hop_count: int = 0; hop_anomaly: str = ""; hop_delays: List[float] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)
    live_spf: Dict = field(default_factory=dict)
    live_dmarc: Dict = field(default_factory=dict)
    live_verified: bool = False


@dataclass
class BECResult:
    score: float = 0.0; risk: str = "NONE"; density: float = 0.0
    categories: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class MacroResult:
    filename: str; file_type: str = "Unknown"; has_macros: bool = False
    risk_score: int = 0; verdict: str = ""; details: List[str] = field(default_factory=list)
    yara_matches: List[Dict] = field(default_factory=list)
    pdf_uris: List[str] = field(default_factory=list)
    mb_found: bool = False; mb_family: str = ""
    md5: str = ""; sha256: str = ""


@dataclass
class ImageAnalysis:
    filename: str; fmt: str = ""; size: Tuple[int, int] = (0, 0)
    has_steg: bool = False; findings: List[str] = field(default_factory=list)
    data: Optional[bytes] = None; qr_links: List[str] = field(default_factory=list)
    ocr_text: str = ""


@dataclass
class Observable:
    type: str; value: str; defanged: str; source: str
    vt: Optional[VTResult] = None; reputation: str = "unknown"
    threat_score: int = 0; is_shortener: bool = False
    suspicious_tld: bool = False; path_entropy: float = 0.0
    is_wrapper: bool = False   # [FIX-SEC]: True if this URL is a redirect wrapper
                               # (contains another URL in its query/path after decoding).
                               # Used to: (a) give wrapper URLs higher VT scan priority
                               # so their inner URL gets extracted and scanned,
                               # (b) prevent entropy from being used as a phishing signal.
    otx: Dict = field(default_factory=dict)
    xforce: Dict = field(default_factory=dict)


@dataclass
class LinkMismatch:
    href: str; display: str; href_domain: str; display_domain: str
    is_tracking: bool = False


@dataclass
class ScoringResult:
    """Output of the scoring engine."""
    threat_probability: float = 0.0
    score: int = 0
    verdict: str = "CLEAN"
    threat_level: str = "SAFE"
    confidence: int = 90
    signals: List[ThreatSignal] = field(default_factory=list)
    trust_factors: List[TrustFactor] = field(default_factory=list)
    correlations_applied: List[str] = field(default_factory=list)
    dampening_applied: List[str] = field(default_factory=list)
    explanation: str = ""
    # ── Score Breakdown (Feature 1) ────────────────────────────────────────────
    signal_contributions: List[Dict] = field(default_factory=list)
    # Each entry: {name, title, tier, prob, conf, effective, raw_score_pts}
    pre_cluster_score: float = 0.0     # Combined score after Step 1+2, before escalation
    pre_dampen_score: float  = 0.0     # Score after escalation, before dampening
    cluster_contributions: List[Dict] = field(default_factory=list)
    # Each entry: {clusters, description, bonus, effective_bonus}
    dampening_contributions: List[Dict] = field(default_factory=list)
    # Each entry: {name, strength, confidence, effective_pct}
    analysis_confidence: int = 50      # Computed confidence (Feature 3)
    # [v19] Per-cluster signal subtotals before escalation bonus
    cluster_signal_subtotals: Dict = field(default_factory=dict)
    # [v19] Dominant attack vector — plain English, derived after scoring
    dominant_vector: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# SCORING ENGINE (nonlinear probability-based)
# ═══════════════════════════════════════════════════════════════════════════════

SIGNAL_CORRELATIONS = [
    ('spf_fail', 'display_name_spoof', 0.12),
    ('spf_fail', 'link_text_mismatch', 0.10),
    ('shadow_spoofing', 'bec_wire_transfer', 0.18),
    ('display_name_spoof', 'bec_authority', 0.18),
    ('link_text_mismatch', 'credential_form', 0.15),
    ('spf_fail', 'reply_to_hijack', 0.14),
    ('malware_hash', 'yara_critical', 0.08),
    ('url_shortener', 'suspicious_tld', 0.08),
    ('spf_fail', 'shadow_spoofing', 0.10),
    ('bec_wire_transfer', 'bec_urgency', 0.15),
    ('bec_authority', 'bec_urgency', 0.12),
    ('bec_payment_redirect', 'bec_urgency', 0.14),
    ('bec_secrecy', 'bec_wire_transfer', 0.12),
    # [I01] New cross-category correlations
    ('display_name_spoof', 'link_text_mismatch', 0.14),
    ('spf_fail', 'suspicious_tld', 0.10),
    ('shadow_spoofing', 'reply_to_hijack', 0.16),
    ('typosquat', 'bec_combined', 0.14),
    ('typosquat', 'link_text_mismatch', 0.12),
    ('bec_invoice_fraud', 'shadow_spoofing', 0.16),
    ('bec_mfa_bypass', 'link_text_mismatch', 0.18),
    ('bec_ceo_fraud', 'bec_urgency', 0.15),
    ('bec_ceo_fraud', 'bec_secrecy', 0.14),
    ('high_entropy_url', 'suspicious_tld', 0.10),
    ('high_entropy_url', 'display_name_spoof', 0.12),
    ('abuse_ip_high', 'spf_fail', 0.14),
    ('abuse_ip_high', 'shadow_spoofing', 0.12),
    # [v19] New signal correlations for URL structure and domain heuristics
    ('ip_literal_url',      'link_text_mismatch', 0.14),
    ('ip_literal_url',      'spf_fail',           0.12),
    ('nonstandard_port',    'high_entropy_url',   0.10),
    ('nonstandard_port',    'suspicious_tld',     0.08),
    ('brand_in_subdomain',  'display_name_spoof', 0.18),
    ('brand_in_subdomain',  'link_text_mismatch', 0.16),
    ('brand_in_subdomain',  'spf_fail',           0.14),
    ('homoglyph_domain',    'display_name_spoof', 0.18),
    ('homoglyph_domain',    'typosquat',          0.14),
    ('deep_subdomain',      'dga_domain_entropy', 0.10),
    ('password_archive',    'display_name_spoof', 0.14),
    ('password_archive',    'link_text_mismatch', 0.10),
    ('disk_image',          'spf_fail',           0.10),
    ('disk_image',          'display_name_spoof', 0.12),
]

# ── [I01] Threat Cluster Matrix ──────────────────────────────────────────────
# Signals are grouped into attack-vector clusters. Cluster scoring fires
# BEFORE individual signal combination — co-firing clusters trigger conditional
# escalation bonuses that can't be achieved by any single signal alone.
THREAT_CLUSTERS = {
    'spoof': {
        'signals': ['spf_fail', 'spf_softfail', 'dkim_fail', 'dmarc_fail',
                    'shadow_spoofing', 'display_name_spoof', 'reply_to_hijack',
                    'dns_spf_contradiction', 'dns_dmarc_contradiction'],
        'min_signals': 1,
        'description': 'Sender identity spoofing',
    },
    'payload': {
        'signals': ['malware_hash', 'yara_VBA_Macro_Dropper', 'yara_PS_In_Macro',
                    'yara_PDF_Launch', 'yara_VBA_Obfuscated', 'yara_PDF_JS_Exploit',
                    'yara_EXE_Magic', 'steganography',
                    'pdf_tags_*',  # Dynamic: pdf_tags_<filename> for dangerous PDF tags
                    'macro_*'],    # Dynamic: macro_<filename> for risky VBA macros
        'min_signals': 1,
        'description': 'Malicious payload delivery',
    },
    'infrastructure': {
        'signals': ['suspicious_tld', 'url_shortener', 'typosquat',
                    'high_entropy_url', 'abuse_ip_high', 'tor_exit',
                    'domain_new', 'dga_domain_entropy', 'dga_domain_consonant',
                    'dnsbl_listed', 'dnsbl_pbl', 'no_mx_record',
                    'otx_*',     # AlienVault OTX confirmed/suspicious (prefix wildcard)
                    'xforce_*',  # IBM X-Force confirmed/suspicious (prefix wildcard)
                    ],
        'min_signals': 1,
        'description': 'Attacker-controlled infrastructure',
    },
    'social_engineering': {
        'signals': ['bec_combined', 'bec_wire_transfer', 'bec_urgency',
                    'bec_authority', 'bec_secrecy', 'bec_payment_redirect',
                    'bec_invoice_fraud', 'bec_mfa_bypass', 'bec_ceo_fraud',
                    'bec_credential_harvest', 'link_text_mismatch', 'credential_form',
                    'ocr_bec'],
        'min_signals': 1,
        'description': 'Social engineering / BEC',
    },
}

# [I02] Conditional cluster escalation rules.
# Format: (required_clusters, bonus_probability, description)
# Bonus is added AFTER individual signal combination, creating true multi-vector
# intelligence that flat additive scoring cannot replicate.
CLUSTER_ESCALATIONS = [
    # Dual-vector: spoof + payload = classic initial-access phishing
    ({'spoof', 'payload'}, 0.25,
     'Spoof+Payload: classic initial-access phishing pattern → CRITICAL escalation'),
    # Dual-vector: spoof + social engineering = BEC / executive fraud
    ({'spoof', 'social_engineering'}, 0.18,
     'Spoof+SocialEng: BEC / executive impersonation → HIGH escalation'),
    # Dual-vector: infrastructure + social engineering = phishing site lure
    ({'infrastructure', 'social_engineering'}, 0.15,
     'Infra+SocialEng: attacker domain + lure content → HIGH escalation'),
    # Dual-vector: payload + infrastructure = malware + attacker C2
    ({'payload', 'infrastructure'}, 0.20,
     'Payload+Infra: malware with attacker-controlled delivery → HIGH escalation'),
    # Triple-vector: spoof + infra + social = full kill-chain
    ({'spoof', 'infrastructure', 'social_engineering'}, 0.30,
     'Triple-vector: spoofed sender + attacker infra + lure = full kill-chain → CRITICAL'),
    # Triple-vector: spoof + payload + social = weaponized BEC
    ({'spoof', 'payload', 'social_engineering'}, 0.28,
     'Spoof+Payload+SocialEng: weaponized BEC with malware backup → CRITICAL'),
    # Quad-vector: all clusters firing = sophisticated APT-style campaign
    ({'spoof', 'payload', 'infrastructure', 'social_engineering'}, 0.35,
     'All-vectors: sophisticated multi-stage campaign → CRITICAL escalation'),
    # Spoof + suspicious infrastructure = targeted or botnet delivery
    ({'spoof', 'infrastructure'}, 0.12,
     'Spoof+Infra: spoofed sender with suspicious infrastructure → MEDIUM escalation'),
    # NOTE: {'social_engineering', 'infrastructure'} at 0.10 removed — it was an
    # exact duplicate of the 0.15 entry above (sets are order-independent in Python).
    # Both fired simultaneously on every match, double-counting the bonus.
]


def _detect_clusters(signals: List[ThreatSignal]) -> Dict[str, List[ThreatSignal]]:
    """Map active signals to their threat clusters. Returns cluster -> [signals].
    
    Two matching modes:
      1. Exact match against literal names in the cluster's signal list.
      2. Wildcard prefix match for dynamic signal names (pdf_tags_*, macro_*,
         yara_*, otx_*, xforce_*) — entries ending with '*' in the cluster list.
    """
    active: Dict[str, List[ThreatSignal]] = {}
    for cluster_name, cluster_def in THREAT_CLUSTERS.items():
        matched = []
        for s in signals:
            if s.name in cluster_def['signals']:
                # Exact match
                matched.append(s)
            elif any(s.name.startswith(cs.rstrip('*'))
                     for cs in cluster_def['signals'] if cs.endswith('*')):
                # Wildcard prefix match (pdf_tags_*, macro_*, yara_*, otx_*, xforce_*)
                if s not in matched:
                    matched.append(s)
        if len(matched) >= cluster_def.get('min_signals', 1):
            active[cluster_name] = matched
    return active


def run_scoring_engine(signals: List[ThreatSignal],
                       trust_factors: List[TrustFactor]) -> ScoringResult:
    """
    Nonlinear probability-combination scoring engine with cluster intelligence.

    1. Combine signal probabilities:  P = 1 - prod(1 - p_i * c_i)
    2. Apply pairwise correlation bonuses for co-occurring signals
    3. [I01/I02] Detect threat clusters and apply conditional escalation
    4. Dampen by trust factors
    5. Enforce signal hierarchy floors
    6. Map to verdict
    7. [NEW] Compute analysis_confidence from signal corroboration (Feature 3)
    """
    result = ScoringResult(signals=signals, trust_factors=trust_factors)
    if not signals:
        result.explanation = "No threat signals detected"
        result.analysis_confidence = 95  # High confidence there's nothing to find
        return result

    # Step 1: probability combination with per-category density guard.
    # Signals are processed highest-effective-weight first within each category
    # so the most important ones always get full weight.
    # Signals above CATEGORY_DENSITY_THRESHOLDS for their category contribute at
    # reduced weight: (N+1)th through (N+2)th at 60%, (N+3)th+ at 30%.
    # This prevents 5 weak content signals from stacking to the same score as
    # 1 strong auth failure + 1 confirmed malware hash.
    # YARA threshold is 99 — effectively uncapped (each rule is independent).
    category_sig_counts: Dict[str, int] = {}
    survival = 1.0
    sig_contributions = []
    # Sort for processing: within each category, highest weight first
    signals_ordered = sorted(signals,
                             key=lambda s: (s.category, -(s.probability * s.confidence)))
    for s in signals_ordered:
        raw_effective = max(0.0, min(1.0, s.probability * s.confidence))
        cat = s.category
        cat_count = category_sig_counts.get(cat, 0)
        threshold  = CATEGORY_DENSITY_THRESHOLDS.get(cat, 3)
        # Apply diminishing returns weight multiplier
        if cat_count < threshold:
            density_weight = 1.0
        elif cat_count < threshold + 2:
            density_weight = 0.60
        else:
            density_weight = 0.30
        effective = raw_effective * density_weight
        category_sig_counts[cat] = cat_count + 1

        old_combined = 1.0 - survival
        survival *= (1.0 - effective)
        new_combined = 1.0 - survival
        pts_added = new_combined - old_combined
        sig_contributions.append({
            'name':           s.name,
            'title':          s.title,
            'tier':           s.tier,
            'prob':           round(s.probability, 3),
            'conf':           round(s.confidence, 3),
            'effective':      round(effective, 3),
            'density_weight': round(density_weight, 2),
            'pts_added':      round(pts_added * 100, 1),
        })
    combined = 1.0 - survival
    result.signal_contributions = sig_contributions

    # Step 2: correlation bonuses
    sig_names = {s.name for s in signals}
    for n1, n2, bonus in SIGNAL_CORRELATIONS:
        if n1 in sig_names and n2 in sig_names:
            s1 = next((s for s in signals if s.name == n1), None)
            s2 = next((s for s in signals if s.name == n2), None)
            if s1 is None or s2 is None:
                continue
            boost = bonus * min(s1.confidence, s2.confidence)
            combined = min(1.0, combined + boost * (1.0 - combined))
            label1 = s1.title if s1.title else n1.replace('_', ' ').title()
            label2 = s2.title if s2.title else n2.replace('_', ' ').title()
            result.correlations_applied.append(
                f"{label1}+{label2} -> +{boost:.2f}")

    result.pre_cluster_score = combined  # Snapshot before escalation

    # Step 3: [I01/I02] Threat cluster detection + conditional escalation.
    # FIX(BUG4): Only pass signals with probability > 0 to cluster detection.
    # Zero-probability BEC category markers (bec_wire_transfer, bec_urgency, etc.)
    # are emitted purely for SIGNAL_CORRELATIONS tracking when auth-dampening has
    # pushed the effective BEC score below the 0.25 threshold. If these markers
    # reach _detect_clusters(), they still activate the social_engineering cluster
    # and trigger cluster escalation bonuses (+15%–+35%) despite contributing zero
    # actual score — unearned CRITICAL escalation on emails that failed the BEC test.
    scored_signals = [s for s in signals if s.probability > 0.0]
    active_clusters = _detect_clusters(scored_signals)
    active_cluster_names = set(active_clusters.keys())

    # [v19] Compute per-cluster signal subtotals (combined effective weight of
    # constituent signals before escalation). Stored for the Explain panel.
    cluster_signal_subtotals: Dict[str, Dict] = {}
    for cn, cl_sigs in active_clusters.items():
        cl_surv = 1.0
        for sig in cl_sigs:
            eff = max(0.0, min(1.0, sig.probability * sig.confidence))
            cl_surv *= (1.0 - eff)
        cluster_signal_subtotals[cn] = {
            'combined_weight': round(1.0 - cl_surv, 3),
            'signal_count':    len(cl_sigs),
            'signal_titles':   [s.title for s in cl_sigs if s.probability > 0][:4],
        }
    result.cluster_signal_subtotals = cluster_signal_subtotals

    cluster_contributions = []
    for required_clusters, escalation_bonus, escalation_desc in CLUSTER_ESCALATIONS:
        if required_clusters.issubset(active_cluster_names):
            avg_conf   = 0.0
            total_sigs = 0
            for cn in required_clusters:
                for sig in active_clusters.get(cn, []):
                    avg_conf   += sig.confidence
                    total_sigs += 1
            avg_conf = avg_conf / max(total_sigs, 1)

            # [v19] Density multiplier: total_sigs / (4 × number of required clusters)
            # At 1 sig per cluster → ~0.5; at 4+ sigs per cluster → 1.0 (capped)
            density_target = 4 * len(required_clusters)
            density_mult   = min(1.0, max(0.5, total_sigs / density_target))

            effective_bonus = escalation_bonus * avg_conf * density_mult
            before = combined
            combined = min(1.0, combined + effective_bonus * (1.0 - combined))
            cluster_contributions.append({
                'clusters':        sorted(required_clusters),
                'description':     escalation_desc,
                'bonus':           round(escalation_bonus, 3),
                'avg_conf':        round(avg_conf, 3),
                'density_mult':    round(density_mult, 2),
                'effective_bonus': round(effective_bonus, 3),
                'pts_added':       round((combined - before) * 100, 1),
            })
            result.correlations_applied.append(
                f"CLUSTER: {escalation_desc} -> +{effective_bonus:.2f}")
    result.cluster_contributions = cluster_contributions

    result.pre_dampen_score = combined  # Snapshot before dampening

    # Step 4: trust dampening
    dampening_contributions = []
    for tf in trust_factors:
        dampen = tf.strength * tf.confidence
        if dampen > 0.005:
            before = combined
            combined *= (1.0 - dampen)
            dampening_contributions.append({
                'name':        tf.name,
                'description': tf.description,
                'strength':    round(tf.strength, 3),
                'conf':        round(tf.confidence, 3),
                'effective':   round(dampen, 3),
                'pts_removed': round((before - combined) * 100, 1),
            })
            result.dampening_applied.append(
                f"{tf.name} -> -{dampen:.0%} dampening")
    result.dampening_contributions = dampening_contributions

    # Step 5: signal hierarchy floors
    tier1 = [s for s in signals if s.tier == 1 and s.confidence >= 0.90]
    tier2 = [s for s in signals if s.tier == 2]
    _tf_names = {tf.name for tf in trust_factors}
    has_full_auth_trust = (
        'spf_pass'  in _tf_names and
        'dkim_pass' in _tf_names and
        'dmarc_pass' in _tf_names
    )
    if tier1:
        floor = 0.65 if has_full_auth_trust else 0.72
        combined = max(combined, floor)
        if tier2:
            floor2 = 0.80 if has_full_auth_trust else 0.88
            combined = max(combined, floor2)

    combined = max(0.0, min(1.0, combined))
    result.threat_probability = combined
    result.score = int(combined * 100)

    # Step 6: map to verdict
    s = result.score
    if s >= 85:
        result.verdict, result.threat_level = "MALICIOUS", "CRITICAL"
    elif s >= 65:
        result.verdict, result.threat_level = "LIKELY MALICIOUS", "HIGH"
    elif s >= 40:
        result.verdict, result.threat_level = "SUSPICIOUS", "MEDIUM"
    elif s >= 18:
        result.verdict, result.threat_level = "REVIEW", "LOW"
    else:
        result.verdict, result.threat_level = "CLEAN", "SAFE"

    # Step 7: Compute analysis_confidence (Feature 3)
    # Replaces the hardcoded per-verdict buckets with a signal-corroboration model.
    # Philosophy:
    #   • High score driven by ONE signal           → low confidence (could be FP)
    #   • High score + multiple correlated signals   → high confidence
    #   • Clean email with many trust factors        → high confidence
    result.confidence         = _legacy_confidence(result.score)
    result.analysis_confidence = _compute_analysis_confidence(
        result.score, signals, trust_factors,
        cluster_contributions, result.correlations_applied
    )

    # [v19] Step 8: Derive dominant attack vector — the single most impactful
    # cluster (by escalation pts_added + cluster_signal_subtotals combined weight).
    # Falls back to highest-weight signal category if no clusters fired.
    _CLUSTER_VECTOR_LABELS = {
        'spoof':              "Identity Spoofing / Impersonation",
        'payload':            "Malware / Payload Delivery",
        'infrastructure':     "Attacker Infrastructure / Phishing",
        'social_engineering': "Social Engineering / BEC",
    }
    _dom_vector = ""
    if cluster_contributions:
        # Find the cluster combo that added the most score points
        top_cc = max(cluster_contributions, key=lambda x: x['pts_added'])
        # Label it by combining the cluster names
        cluster_labels = [_CLUSTER_VECTOR_LABELS.get(c, c.replace('_', ' ').title())
                          for c in sorted(top_cc['clusters'])]
        _dom_vector = " + ".join(cluster_labels)
    elif active_clusters:
        # No escalation fired but clusters are present — use the largest cluster
        top_cl = max(active_clusters, key=lambda cn: cluster_signal_subtotals.get(cn, {}).get('combined_weight', 0))
        _dom_vector = _CLUSTER_VECTOR_LABELS.get(top_cl, top_cl.replace('_', ' ').title())
    elif signals:
        # No clusters — derive from highest-impact signal
        top_sig = max(signals, key=lambda s: s.probability * s.confidence)
        cat_label = {
            'auth': "Authentication Bypass",
            'behavioral': "Social Engineering / BEC",
            'content': "Content-Based Phishing",
            'network': "Suspicious Infrastructure",
            'attachment': "Malicious Attachment",
            'yara': "Malware Signature Match",
        }.get(top_sig.category, top_sig.category.replace('_', ' ').title())
        _dom_vector = cat_label
    result.dominant_vector = _dom_vector

    # Build explanation
    active_cls = active_clusters
    cluster_str = (f" Active clusters: {', '.join(sorted(active_cls.keys()))}."
                   if active_cls else "")
    top = sorted(signals, key=lambda x: x.probability * x.confidence, reverse=True)[:5]
    parts = [f"{t.title} (p={t.probability:.0%} x c={t.confidence:.0%})" for t in top]
    result.explanation = (
        f"Score {s}/100 -- {len(signals)} signal(s), "
        f"{len(trust_factors)} trust factor(s).{cluster_str} "
        f"Top: {'; '.join(parts)}")
    return result


def _legacy_confidence(score: int) -> int:
    """Original hardcoded confidence bucket — kept for backward compat in DB/SOAR."""
    if score >= 85:   return 95
    if score >= 65:   return 85
    if score >= 40:   return 72
    if score >= 18:   return 60
    return 90


def _compute_analysis_confidence(
        score: int,
        signals: List[ThreatSignal],
        trust_factors: List[TrustFactor],
        cluster_contributions: List[Dict],
        correlations_applied: List[str]) -> int:
    """
    Compute confidence in the verdict — the question answered is DIFFERENT
    depending on whether the verdict is clean or a threat.

    CLEAN verdict  (score < 18): "How sure are we this is actually safe?"
      → Confidence rises with positive auth passes and absence of real signals.
      → A clean email with SPF+DKIM+DMARC all passing = very high confidence.
      → A clean email with no auth data and one stray low-tier signal = moderate.

    THREAT verdict (score ≥ 18): "How well-corroborated is the threat?"
      → Confidence rises with signal count, category diversity, and cluster escalations.
      → High score from 1 signal = low confidence (possible FP).
      → High score from 4 diverse signals = high confidence.

    Returns an integer 0-100.
    """
    real_sigs = [s for s in signals
                 if not (s.probability == 0.0 and s.name.startswith('bec_')
                         and s.name != 'bec_combined')]
    n_sigs     = len(real_sigs)
    n_trust    = len(trust_factors)
    tf_names   = {tf.name for tf in trust_factors}

    # ── Branch: CLEAN verdict ─────────────────────────────────────────────────
    if score < 18:
        # Base: start permissive — we assume clean until signals prove otherwise
        base = 55

        # Auth passes are the strongest positive evidence of a clean email
        auth_bonus = 0
        if 'spf_pass'   in tf_names: auth_bonus += 12
        if 'dkim_pass'  in tf_names: auth_bonus += 12
        if 'dmarc_pass' in tf_names: auth_bonus += 10
        # Other trust factors (known sender, clean IPs, clean attachments, etc.)
        other_trust = n_trust - sum(1 for n in tf_names
                                    if n in ('spf_pass', 'dkim_pass', 'dmarc_pass'))
        auth_bonus += min(8, other_trust * 3)

        # Penalty for real signals — even low-tier ones introduce doubt
        # A score-4 email with 3 Tier-4 signals is less certain than one with 0
        signal_doubt = min(25, n_sigs * 7)

        # Stronger penalty for any tier-1 or tier-2 signals that nonetheless
        # didn't push the score above 18 (edge case but must be handled)
        strong_doubt = sum(12 for s in real_sigs if s.tier <= 2)

        raw = base + auth_bonus - signal_doubt - strong_doubt
        return max(15, min(97, raw))

    # ── Branch: THREAT verdict (score ≥ 18) ──────────────────────────────────
    # Confidence = corroboration of the threat finding.

    if n_sigs == 0:
        # Score ≥18 with no signals should never happen, but handle gracefully
        return 30

    # Base: number of independent signals
    # 1 → 35, 2 → 45, 3 → 55, 4+ → 65
    base = min(65, 25 + n_sigs * 10)

    # Corroboration: signals from different categories
    cats = {s.category for s in real_sigs}
    corroboration_bonus = min(15, len(cats) * 5)

    # Tier diversity: mix of tier-1 + tier-2 + tier-3
    tiers = {s.tier for s in real_sigs}
    tier_bonus = min(10, len(tiers) * 4)

    # Cluster firing: multi-vector attacks = high confidence
    cluster_bonus = min(12, len(cluster_contributions) * 6)

    # Pairwise correlations
    signal_corrs = [c for c in correlations_applied if not c.startswith('CLUSTER:')]
    corr_bonus = min(8, len(signal_corrs) * 2)

    # Tier-1 irrefutable evidence (malware hash, VT CRITICAL, etc.)
    tier1_bonus = min(10, sum(1 for s in real_sigs if s.tier == 1) * 5)

    # Trust factor presence slightly reduces confidence in the threat verdict
    # (auth passes create ambiguity — could be a compromised-account BEC, but
    # the signals are competing with positive indicators)
    trust_penalty = min(8, n_trust * 2)

    # Thin evidence penalty: high score from very few signals
    if score >= 65 and n_sigs <= 2:
        thin_penalty = 15
    elif score >= 40 and n_sigs == 1:
        thin_penalty = 20
    else:
        thin_penalty = 0

    raw = (base + corroboration_bonus + tier_bonus + cluster_bonus
           + corr_bonus + tier1_bonus - trust_penalty - thin_penalty)
    return max(10, min(99, raw))


# ═══════════════════════════════════════════════════════════════════════════════
# [I03] RISK NARRATIVE BUILDER
# Generates human-readable attack-pattern narrative: explains WHY this email
# is dangerous as a story, not a list of raw signals.
# ═══════════════════════════════════════════════════════════════════════════════

def build_risk_narrative(signals: List[ThreatSignal],
                         trust_factors: List[TrustFactor],
                         auth,  # AuthResult
                         score: int) -> str:
    """Build a human-readable threat narrative grounded entirely in the actual
    signals present — never in hardcoded name lookups.

    Architecture:
      1. Filter to real (non-zero-prob) signals, sort by impact
      2. Generate evidence sentences from signal category + actual content
         (title, detail, evidence fields) — so the text is always specific
      3. Identify attack pattern from BEHAVIORAL_PATTERNS via cluster matching
      4. Build conclusion paragraph from cluster combination analysis
      5. Append trust mitigations if significant
      6. State recommendation

    This approach means the narrative is ALWAYS grounded in real findings —
    it will never fall back to "exhibits multiple threat indicators" because
    it reads the actual signal titles/details regardless of signal names.
    """
    if score < 18:
        return "No significant threat pattern detected. Email appears clean."

    # ── Prepare signal sets ───────────────────────────────────────────────────
    # Exclude zero-probability BEC category markers (used only for correlation).
    # Real BEC content lives in bec_combined.detail / bec_combined.evidence.
    real_sigs = [s for s in signals
                 if not (s.probability == 0.0 and s.name.startswith('bec_')
                         and s.name != 'bec_combined')]
    top_sigs = sorted(real_sigs, key=lambda s: s.probability * s.confidence, reverse=True)
    sig_names = {s.name for s in signals}
    active_clusters = _detect_clusters(signals)

    # ── Step 1: Evidence sentences from ACTUAL signal content ────────────────
    # Each section reads signal.detail and signal.evidence directly — the
    # narrative is grounded in whatever the engine actually found, not in
    # a name-lookup ladder that silently produces nothing when names drift.
    evidence_parts = []
    seen_evidence = set()  # deduplicate near-identical sentences

    def _add_ev(sentence: str):
        key = sentence[:40].lower()
        if key not in seen_evidence and sentence:
            seen_evidence.add(key)
            evidence_parts.append(sentence)

    # ── AUTH signals ─────────────────────────────────────────────────────────
    # Read directly from AuthResult object — always accurate regardless of
    # which signal names were emitted.
    if auth.spf == 'FAIL' and auth.dmarc == 'FAIL':
        domain_str = f"**{auth.from_domain}**" if auth.from_domain else "the sender's domain"
        _add_ev(f"failed both SPF and DMARC authentication for {domain_str} — "
                f"the server is not authorized AND the domain policy was violated")
    elif auth.spf == 'FAIL':
        domain_str = f"**{auth.from_domain}**" if auth.from_domain else "the claimed sender domain"
        _add_ev(f"failed SPF authentication — the sending server is not authorized "
                f"to send on behalf of {domain_str}")
    elif auth.spf == 'SOFTFAIL':
        domain_str = f"**{auth.from_domain}**" if auth.from_domain else "the sender domain"
        _add_ev(f"produced an SPF softfail — {domain_str} does not fully authorize "
                f"this sending server")
    elif auth.spf in ('NONE', 'TEMPERROR', 'PERMERROR'):
        if auth.dkim == 'FAIL':
            _add_ev("has no valid SPF record and a failed DKIM signature — "
                    "the sender's identity cannot be verified")
        elif auth.dkim == 'NONE' and auth.dmarc == 'NONE':
            _add_ev("has no email authentication records (no SPF, DKIM, or DMARC) — "
                    "this is unusual for legitimate senders")

    if auth.shadow_spoof and auth.rp_domain:
        _add_ev(f"uses shadow spoofing — it appears to come from "
                f"**{auth.from_domain}** but reply-path routes to **{auth.rp_domain}**, "
                f"a different domain controlled by the attacker")

    if auth.dkim == 'FAIL' and auth.spf not in ('FAIL',):
        _add_ev("failed DKIM signature verification — the message content "
                "cannot be confirmed as unmodified since it was sent")

    if 'dns_spf_contradiction' in sig_names or 'dns_dmarc_contradiction' in sig_names:
        _add_ev("has forged authentication headers — live DNS lookups contradict "
                "the SPF/DMARC pass claims in the email headers")

    # Reply-To hijack — read from signal detail for specifics
    rth = next((s for s in real_sigs if s.name == 'reply_to_hijack'), None)
    if rth:
        detail = rth.detail or rth.evidence or ''
        _add_ev(f"hijacks the Reply-To header — {detail.lower()}"
                if detail else "redirects replies to a domain different from the apparent sender")

    # ── BEHAVIORAL / IDENTITY signals ────────────────────────────────────────
    spoof_sig = next((s for s in real_sigs if s.name == 'display_name_spoof'), None)
    if spoof_sig:
        # Use the actual spoof detail which contains the specific claim
        detail = spoof_sig.detail or spoof_sig.evidence or ''
        if detail:
            _add_ev(f"impersonates a trusted identity: **{detail}**")
        else:
            _add_ev("impersonates a trusted identity in the From display name")

    # BEC — read from bec_combined signal's detail (the actual BEC summary)
    bec_sig = next((s for s in real_sigs if s.name == 'bec_combined'), None)
    if bec_sig:
        # bec_combined.detail = bec.summary, bec_combined.evidence = top findings
        bec_summary = bec_sig.detail or ''
        bec_findings = bec_sig.evidence or ''
        # Build specific BEC evidence from the actual categories present
        bec_cats = {s.name.replace('bec_', '') for s in signals
                    if s.name.startswith('bec_') and s.name != 'bec_combined'
                    and s.probability == 0.0}
        cat_phrases = {
            'wire_transfer': 'requests a wire or bank transfer',
            'gift_cards': 'requests gift card purchases — a classic fraud indicator',
            'urgency': 'applies urgency pressure to bypass normal verification',
            'secrecy': 'instructs the recipient to keep the request confidential',
            'authority': 'invokes executive authority to skip normal approval processes',
            'payment_redirect': 'requests a change to payment or banking details',
            'invoice_fraud': 'references an invoice requiring immediate payment action',
            'mfa_bypass': 'attempts to intercept a multi-factor authentication code',
            'ceo_fraud': 'uses the classic CEO fraud opener ("are you available?") pattern',
            'credential_harvest': 'attempts to harvest login credentials',
            'shipping_scam': 'uses a parcel/delivery failure lure',
        }
        bec_ev_parts = [cat_phrases[c] for c in bec_cats if c in cat_phrases]
        if bec_ev_parts:
            if len(bec_ev_parts) == 1:
                _add_ev(f"contains BEC social engineering content that {bec_ev_parts[0]}")
            else:
                _add_ev(f"contains BEC social engineering content that "
                        + ", ".join(bec_ev_parts[:-1]) + f", and {bec_ev_parts[-1]}")
        elif bec_summary:
            _add_ev(f"contains BEC social engineering patterns: {bec_summary.lower()}")

    # ── CONTENT / LINK signals ────────────────────────────────────────────────
    ltm_sig = next((s for s in real_sigs if s.name == 'link_text_mismatch'), None)
    if ltm_sig:
        ev = ltm_sig.evidence or ''
        _add_ev(f"contains deceptive links where the visible text hides the real "
                f"destination{' — ' + ev if ev else ''}")

    typo_sig = next((s for s in real_sigs if s.name == 'typosquat'), None)
    if typo_sig:
        detail = typo_sig.detail or typo_sig.evidence or ''
        _add_ev(f"uses a lookalike (typosquatted) domain: **{detail}**"
                if detail else "uses a domain that closely mimics a known brand")

    # VT-flagged URLs — read from signal detail
    vt_sigs = [s for s in real_sigs if s.name.startswith('vt_') and s.probability >= 0.70]
    if vt_sigs:
        top_vt = vt_sigs[0]
        _add_ev(f"contains a URL/domain confirmed malicious by VirusTotal "
                f"({top_vt.detail})" if top_vt.detail
                else "contains a URL flagged as malicious by VirusTotal")

    # Domain intelligence signals — use their detail directly
    for sname in ('domain_new', 'dga_domain_entropy', 'dga_domain_consonant', 'suspicious_tld'):
        s = next((x for x in real_sigs if x.name == sname), None)
        if s:
            detail = s.detail or s.title or ''
            if detail:
                _add_ev(detail[0].lower() + detail[1:] if detail else s.title.lower())

    # High-entropy URL
    heu_sig = next((s for s in real_sigs if s.name == 'high_entropy_url'), None)
    if heu_sig:
        _add_ev(f"contains a high-entropy URL path ({heu_sig.evidence or heu_sig.detail or ''}) "
                f"consistent with a phishing token or credential-capture page")

    # URL shortener + suspicious TLD fallback if not already added via signal
    if 'url_shortener' in sig_names and not any('shortener' in p or 'short' in p
                                                 for p in evidence_parts):
        _add_ev("uses URL shorteners that obscure the true link destination")

    # ── NETWORK signals ───────────────────────────────────────────────────────
    abuse_sig = next((s for s in real_sigs if 'abuse_ip' in s.name
                      and s.probability >= 0.30), None)
    if abuse_sig:
        detail = abuse_sig.detail or ''
        _add_ev(f"originates from a high-risk IP address — {detail.lower()}"
                if detail else "originates from an IP address with significant abuse history")

    dnsbl_sig = next((s for s in real_sigs if s.name in ('dnsbl_listed', 'dnsbl_pbl')), None)
    if dnsbl_sig:
        _add_ev(f"originates from an IP listed in Spamhaus ZEN — {dnsbl_sig.detail.lower()}"
                if dnsbl_sig.detail else "originates from a Spamhaus-listed IP address")

    if 'no_mx_record' in sig_names:
        _add_ev(f"was sent from a domain with no MX records — the domain cannot receive "
                f"bounce replies, which is a strong indicator of a throw-away sender domain")

    if 'tor_exit' in sig_names:
        _add_ev("was routed through a TOR exit node, anonymizing the sender's true location")

    hop_sig = next((s for s in real_sigs if s.name == 'hop_stall'), None)
    if hop_sig and hop_sig.evidence:
        _add_ev(f"shows abnormal relay timing — {hop_sig.evidence.lower()}")

    # ── ATTACHMENT signals ────────────────────────────────────────────────────
    att_sigs = [s for s in real_sigs if s.category == 'attachment' and s.probability > 0.25]
    att_sigs_sorted = sorted(att_sigs, key=lambda s: s.probability * s.confidence, reverse=True)
    for s in att_sigs_sorted[:2]:
        if s.name == 'malware_hash':
            _add_ev(f"contains an attachment **confirmed as malware** by MalwareBazaar "
                    f"({s.detail})" if s.detail else
                    "contains an attachment confirmed as malware by MalwareBazaar")
        elif s.name.startswith('yara_'):
            rule = s.name.replace('yara_', '').replace('_', ' ')
            _add_ev(f"triggered the **{rule}** YARA malware detection rule "
                    f"({s.detail.lower()})" if s.detail
                    else f"triggered the **{rule}** malware detection rule")
        elif s.name.startswith('pdf_tags_'):
            detail = s.detail or ''
            _add_ev(f"contains a PDF with **dangerous embedded actions** — {detail.lower()}"
                    if detail else "contains a PDF with dangerous auto-execution tags (/OpenAction, /Launch, or /JavaScript)")
        elif 'macro' in s.name:
            detail = s.detail or ''
            _add_ev(f"contains a suspicious macro-enabled document — {detail.lower()}"
                    if detail else "contains a macro-enabled document with risky auto-execution patterns")
        elif s.detail:
            _add_ev(f"has a suspicious attachment: {s.detail.lower()}")
        elif s.title:
            _add_ev(s.title.lower())

    if 'steganography' in sig_names:
        steg_sig = next((s for s in real_sigs if s.name == 'steganography'), None)
        _add_ev(f"contains an image with hidden steganographic data "
                f"({steg_sig.evidence if steg_sig and steg_sig.evidence else ''})")  # FIX: ThreatSignal has no .filename; evidence holds img.filename

    # ── Final fallback: use top signal titles/details directly ────────────────
    # This guarantees the narrative NEVER says "exhibits multiple threat indicators".
    # If all category checks above somehow found nothing, read the top 3 signals directly.
    if not evidence_parts:
        for s in top_sigs[:4]:
            if s.detail and len(s.detail) > 10:
                _add_ev(s.detail.lower())
            elif s.title and len(s.title) > 5:
                _add_ev(f"shows {s.title.lower()}")

    # Last resort — should be essentially unreachable if signals exist
    if not evidence_parts:
        for s in top_sigs[:2]:
            evidence_parts.append(f"{s.title} (impact: {s.probability * s.confidence:.0%})")

    # ── Step 2: Identify best-matching attack pattern ────────────────────────
    best_pattern = None
    best_score = 0
    for pattern_name, pattern_def in BEHAVIORAL_PATTERNS.items():
        # Match via signal names AND via cluster membership
        name_matches = sum(1 for ps in pattern_def['signals'] if ps in sig_names)
        # Boost: if the pattern's signals are in active clusters, count cluster presence too
        cluster_boost = sum(1 for cn in active_clusters
                            if any(ps in THREAT_CLUSTERS.get(cn, {}).get('signals', [])
                                   for ps in pattern_def['signals']))
        total = name_matches + (cluster_boost * 0.5)
        if total >= pattern_def['require_any'] and total > best_score:
            best_score = total
            best_pattern = (pattern_name, pattern_def)

    # ── Step 3: Compose evidence into natural two-sentence prose ─────────────
    # PRIMARY sentence: first 2 findings (the strongest ones).
    # SECONDARY sentence: up to 3 more — prevents the 7-clause comma chain.
    # This is the fix for the run-on sentence problem seen in the screenshot.
    primary   = evidence_parts[:2]
    secondary = evidence_parts[2:5]

    if len(primary) == 1:
        intro = f"This email {primary[0]}."
    else:
        intro = f"This email {primary[0]}, and also {primary[1]}."

    if secondary:
        if len(secondary) == 1:
            intro += f" Additionally, it {secondary[0]}."
        else:
            joined = ", ".join(secondary[:-1]) + f", and {secondary[-1]}"
            intro += f" It also {joined}."

    # ── Step 4: Attack-pattern conclusion ────────────────────────────────────
    cluster_names = sorted(active_clusters.keys())
    if best_pattern:
        pname, pdef = best_pattern
        conclusion = f" This pattern strongly aligns with **{pdef['narrative']}**."
        attack_vec = f" Primary attack vector: **{pdef['attack_vector']}**."
    elif len(cluster_names) >= 3:
        conclusion = (" This combination of spoofing, payload, and social engineering signals "
                      "indicates a **sophisticated multi-vector attack** — typical of targeted "
                      "spear-phishing or Business Email Compromise campaigns.")
        attack_vec = ""
    elif 'spoof' in cluster_names and 'payload' in cluster_names:
        conclusion = (" A spoofed sender identity combined with a malicious payload is "
                      "the hallmark of **initial-access phishing** — designed to trick the "
                      "recipient into opening a file that installs malware.")
        attack_vec = " Primary attack vector: **Malware Delivery / Initial Access**."
    elif 'spoof' in cluster_names and 'social_engineering' in cluster_names:
        conclusion = (" A spoofed sender combined with social engineering content is "
                      "consistent with **Business Email Compromise (BEC)** — where the attacker "
                      "impersonates a trusted person to manipulate the recipient into taking a "
                      "financial or credential-related action.")
        attack_vec = " Primary attack vector: **BEC / Social Engineering**."
    elif 'infrastructure' in cluster_names and 'social_engineering' in cluster_names:
        conclusion = (" Attacker-controlled infrastructure combined with social engineering "
                      "lure content is the signature of **credential-phishing campaigns** — "
                      "designed to steal login credentials via a fake login page.")
        attack_vec = " Primary attack vector: **Phishing / Credential Theft**."
    elif 'payload' in cluster_names:
        conclusion = (" The presence of malicious payload indicators — even without confirmed "
                      "spoofing — suggests this email is a **malware delivery attempt**, "
                      "possibly a mass-distribution campaign.")
        attack_vec = " Primary attack vector: **Malware / Payload Delivery**."
    elif 'spoof' in cluster_names:
        # Single-cluster spoof: describe WHAT is being spoofed specifically
        spoof_signals = active_clusters.get('spoof', [])
        spoof_descs = [s.title for s in spoof_signals if s.probability > 0]
        if spoof_descs:
            conclusion = (f" The sender identity indicators (**{', '.join(spoof_descs)}**) "
                          f"suggest this email is designed to impersonate a trusted sender — "
                          f"a common precursor to Business Email Compromise or credential phishing.")
        else:
            conclusion = (" Sender authentication failures suggest this email may be "
                          "impersonating a legitimate sender — a precursor to BEC or phishing.")
        attack_vec = " Primary attack vector: **Identity Spoofing / Impersonation**."
    elif 'infrastructure' in cluster_names:
        infra_signals = active_clusters.get('infrastructure', [])
        infra_descs = [s.title for s in infra_signals if s.probability > 0]
        if infra_descs:
            conclusion = (f" Suspicious infrastructure indicators (**{', '.join(infra_descs[:2])}**) "
                          f"suggest attacker-controlled hosting typically used in phishing campaigns.")
        else:
            conclusion = " Suspicious infrastructure signals suggest attacker-controlled hosting."
        attack_vec = " Primary attack vector: **Infrastructure-Based Phishing**."
    else:
        # No cluster match — summarize the top signal directly
        if top_sigs:
            ts = top_sigs[0]
            conclusion = (f" The highest-impact finding is **{ts.title}** "
                          f"(impact score: {ts.probability * ts.confidence:.0%}). "
                          f"While this alone does not confirm a specific attack pattern, "
                          f"it warrants analyst review.")
        else:
            conclusion = " Multiple correlated threat indicators detected."
        attack_vec = ""

    # ── Step 5: Trust mitigations ─────────────────────────────────────────────
    mitigation = ""
    strong_trust = [tf for tf in trust_factors
                    if tf.strength * tf.confidence >= 0.08 and
                    tf.name not in ('bec_contradiction', 'tracking_links')]
    if strong_trust:
        tf_descs = [tf.description for tf in strong_trust[:2]]
        mitigation = (f" **Mitigating factors:** {' | '.join(tf_descs)}. "
                      f"These reduce the overall risk score but do not eliminate the threat.")

    # ── Step 6: Analyst recommendation ───────────────────────────────────────
    if score >= 85:
        recommendation = (" **Analyst action: BLOCK immediately.** "
                          "Do not deliver. Investigate sender infrastructure and any "
                          "links/attachments that may have been interacted with.")
    elif score >= 65:
        recommendation = (" **Analyst action: QUARANTINE.** "
                          "Hold for manual review before delivery. "
                          "Verify sender through an independent out-of-band channel.")
    elif score >= 40:
        recommendation = (" **Analyst action: HOLD FOR REVIEW.** "
                          "Do not deliver without analyst sign-off. "
                          "Consider requesting the sender re-authenticate.")
    else:
        recommendation = (" **Analyst action: DELIVER WITH CAUTION.** "
                          "Consider adding a phishing-warning banner. "
                          "Advise recipient not to click links without verification.")

    # [v19] Group evidence parts into three attack-phase sections so the
    # narrative reads as a structured chain-of-events rather than a flat list.
    # Phase assignment is by signal category, not by position in the list.
    _PHASE_IDENTITY  = {'auth', 'behavioral'}  # Who is the sender
    _PHASE_PAYLOAD   = {'attachment', 'network', 'yara'}  # What they're delivering
    _PHASE_LURE      = {'content'}  # How they're manipulating the recipient

    # Rebuild per-phase evidence — re-run evidence generation by category
    def _phased_ev(category_set):
        """Return evidence_parts items whose generating signal was in category_set."""
        # We re-examine the real_sigs categories to assign each evidence sentence
        # to a phase. Evidence is already in evidence_parts — we identify which
        # signals contributed which sentence by matching category.
        phase_sigs = [s for s in top_sigs if s.category in category_set]
        phase_names = {s.name for s in phase_sigs}
        return [ep for ep in evidence_parts
                if any(s.name in ep.lower().replace(' ', '_') or
                       (s.detail and s.detail[:20].lower() in ep.lower()) or
                       (s.title and s.title.lower() in ep.lower())
                       for s in phase_sigs)]

    # Build identity section (auth + spoofing)
    identity_ev  = [ep for ep in evidence_parts if any(
        kw in ep.lower() for kw in ('spf', 'dkim', 'dmarc', 'spoof', 'shadow', 'reply-to',
                                    'impersonat', 'authentication', 'hijack', 'bec'))]
    # Build payload/infra section (attachment + network + YARA)
    payload_ev   = [ep for ep in evidence_parts if any(
        kw in ep.lower() for kw in ('attachment', 'malware', 'yara', 'macro', 'ip address',
                                    'spamhaus', 'tor', 'pdf', 'executable', 'steganograph',
                                    'archive', 'hash', 'virustotal', 'abuse', 'dnsbl',
                                    'mx record', 'no mx', 'disk image'))]
    # Build lure/content section (URLs, link mismatches, BEC content if not identity)
    lure_ev      = [ep for ep in evidence_parts if ep not in identity_ev and ep not in payload_ev]

    # Compose each non-empty section into a short paragraph
    def _ev_to_para(ev_list, max_items=3):
        items = ev_list[:max_items]
        if not items:
            return ""
        if len(items) == 1:
            return f"This email {items[0]}."
        joined = "; ".join(items[:-1]) + f"; and {items[-1]}"
        return f"This email {joined}."

    identity_para = _ev_to_para(identity_ev)
    payload_para  = _ev_to_para(payload_ev)
    lure_para     = _ev_to_para(lure_ev)

    # Assemble the phased narrative with section headers
    sections = []
    if identity_para:
        sections.append(f"**🔴 Identity & Authentication**\n{identity_para}")
    if payload_para:
        sections.append(f"**💣 Payload & Infrastructure**\n{payload_para}")
    if lure_para:
        sections.append(f"**🎯 Lure & Social Engineering**\n{lure_para}")

    # Fallback: if phase assignment produced nothing, use the original flat intro
    if not sections:
        sections.append(intro)

    phased_intro = "\n\n".join(sections)

    return phased_intro + conclusion + attack_vec + mitigation + recommendation


# ═══════════════════════════════════════════════════════════════════════════════
# TEXT PROCESSING (BeautifulSoup + de-obfuscation)
# ═══════════════════════════════════════════════════════════════════════════════

_CONFUSABLES = str.maketrans({
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
    '\u04bb': 'h', '\u0501': 'd', '\u051b': 'q', '\u051d': 'w',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H', '\u0399': 'I',
    '\u039a': 'K', '\u039c': 'M', '\u039d': 'N', '\u039f': 'O', '\u03a1': 'P',
    '\u03a4': 'T', '\u03a7': 'X', '\u03a5': 'Y', '\u0396': 'Z',
})


def normalize_text(text: str) -> str:
    """De-obfuscate text: collapse separators, normalize Unicode confusables."""
    if not text:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = text.translate(_CONFUSABLES)
    text = re.sub(r'(?<=\w)[.\-_\s]{1,2}(?=\w)', '', text)
    return text


def extract_visible_text(html_body: str) -> str:
    """Use BeautifulSoup to get only visible text (skip scripts, styles, hidden)."""
    if not html_body:
        return ""
    # FIX(C13): size-limit HTML input to prevent BS4 OOM on huge payloads
    if len(html_body) > MAX_HTML_SIZE:
        html_body = html_body[:MAX_HTML_SIZE]
    if not BS4_OK:
        return re.sub(r'<[^>]+>', ' ', html_body)

    soup = BeautifulSoup(html_body, 'html.parser')
    for tag in soup.find_all(['script', 'style', 'head', 'noscript']):
        tag.decompose()
    for tag in list(soup.find_all(True)):
        style = tag.get('style', '') or ''
        if 'display:none' in style.replace(' ', '') or 'visibility:hidden' in style.replace(' ', ''):
            tag.decompose()
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        comment.extract()
    return soup.get_text(separator=' ', strip=True)


# ═══════════════════════════════════════════════════════════════════════════════
# URL HEURISTICS
# ═══════════════════════════════════════════════════════════════════════════════

def url_path_entropy(url: str) -> float:
    """Calculate Shannon entropy of URL path. High entropy = likely phishing token."""
    try:
        parsed = urlparse(url)
        path = parsed.path + (parsed.query or '')
        if len(path) < 5:
            return 0.0
        c = Counter(path)
        n = len(path)
        return -sum((v / n) * math.log2(v / n) for v in c.values())
    except Exception:
        return 0.0


def _safe_strip_www(domain: str) -> str:
    """FIX(C07): Safely remove 'www.' prefix without mangling.
    str.lstrip('www.') strips individual characters from the set {w, .},
    which mangles domains like 'wwonderful.com' -> 'onderful.com'.
    This function properly checks for the 'www.' prefix."""
    d = domain.lower()
    if d.startswith('www.'):
        return d[4:]
    return d


def is_tracking_domain(domain: str) -> bool:
    """Check if domain is a known email tracking/redirect/security gateway service.
    Matches exact domain, root domain, AND parent domain (so sub.trendmicro.com
    matches trendmicro.com in the allowlist)."""
    d = _safe_strip_www(domain.lower())
    if d in TRACKING_ALLOWLIST:
        return True
    root = _root_domain(d)
    if root in TRACKING_ALLOWLIST:
        return True
    # Check if any allowlisted domain is a suffix (parent domain match)
    for allowed in TRACKING_ALLOWLIST:
        if d.endswith('.' + allowed):
            return True
    return False


def is_redirect_wrapper(url: str) -> bool:
    """Detect redirect/gateway wrapper URLs by checking whether the URL contains
    another URL after one or two rounds of percent-decoding.

    Security note: This function detects the STRUCTURAL property of redirect
    wrappers — it does NOT suppress any signals by itself. Callers decide how
    to act based on whether the wrapper domain is also in TRACKING_ALLOWLIST:

      - TRACKING_ALLOWLIST domain + is_redirect_wrapper → suppress mismatch,
        suppress entropy (confirmed legitimate gateway).
      - Unknown domain + is_redirect_wrapper → suppress entropy ONLY.
        Keep the link-text mismatch signal (unknown domain wrapping URLs is
        suspicious). Also extract the inner URL as a separate observable so
        the real destination gets scanned by VT/OTX/XForce independently.

    This is safe because: an attacker embedding google.com inside evil.com/login
    gains nothing — evil.com still gets scanned, the mismatch still fires, and
    the inner google.com scan just returns clean (correctly).
    """
    try:
        parsed = urlparse(url)
        raw = parsed.path + ('?' + parsed.query if parsed.query else '')
        if not raw:
            return False
        once = unquote(raw)
        if 'http://' in once or 'https://' in once:
            return True
        twice = unquote(once)
        if 'http://' in twice or 'https://' in twice:
            return True
        return False
    except Exception:
        return False


def extract_inner_url(url: str) -> Optional[str]:
    """[FIX-SEC]: Extract the embedded destination URL from a redirect wrapper.

    Security gateways and email trackers encode the real URL in a query
    parameter (e.g. ?url=https%3A%2F%2Freal.com or ?redirect=...).
    PAT_URL regex cannot find this inner URL because it matches the OUTER
    URL as one token and stops at whitespace — the inner URL is invisible
    to the regex unless we explicitly decode and extract it.

    This is the companion to is_redirect_wrapper(). When a wrapper is
    detected, calling this adds the real destination as a separate Observable
    so it gets full VT/OTX/XForce scanning independently of the wrapper.

    Returns the first embedded http/https URL found after decoding, or None.
    """
    try:
        parsed = urlparse(url)
        qs = parsed.query
        if not qs:
            return None

        # Try query parameter extraction first (most common: ?url=..., ?redirect=...)
        params = parse_qs(qs)
        for param in _INNER_PARAM_NAMES:
            if param in params:
                candidate = unquote(params[param][0])
                if candidate.startswith(('http://', 'https://')):
                    return candidate

        # Fallback: scan the decoded query string with PAT_URL
        decoded_once = unquote(qs)
        found = PAT_URL.search(decoded_once)
        if found:
            return found.group(0)

        # Double-decode fallback for doubly-encoded wrappers
        decoded_twice = unquote(decoded_once)
        found2 = PAT_URL.search(decoded_twice)
        if found2:
            return found2.group(0)

        return None
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SENDER MEMORY (SQLite – first-seen tracking)
# ═══════════════════════════════════════════════════════════════════════════════

# FIX(S7): Use a more persistent location than /tmp/ for sender memory.
# /tmp/ is wiped on reboot, giving false sense of sender history.
# Use Streamlit's app data directory if available, otherwise ~/.sherlock/
_SENDER_DB_DIR = os.environ.get('SHERLOCK_DATA_DIR',
    os.path.join(os.path.expanduser('~'), '.sherlock'))
try:
    os.makedirs(_SENDER_DB_DIR, exist_ok=True)
    _SENDER_DB_PATH = os.path.join(_SENDER_DB_DIR, 'sherlock_senders.db')
except Exception:
    _SENDER_DB_PATH = os.path.join(tempfile.gettempdir(), 'sherlock_senders.db')


@contextlib.contextmanager
def _sender_conn():
    """FIX(C01): Thread-safe SQLite context manager with WAL mode + proper cleanup.
    Original code created a new connection on every call and never closed it,
    leaking file descriptors. WAL mode prevents 'database is locked' errors
    under concurrent Streamlit sessions."""
    conn = sqlite3.connect(_SENDER_DB_PATH, timeout=5, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute('''CREATE TABLE IF NOT EXISTS senders (
            domain TEXT PRIMARY KEY, first_seen TEXT, count INTEGER DEFAULT 1
        )''')
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def check_sender(domain: str) -> Tuple[bool, int, int]:
    """Check if sender is known WITHOUT recording. Returns (is_known, times_seen, days_known)."""
    if not domain:
        return False, 0, 0
    domain = domain.lower()
    try:
        with _sender_conn() as conn:
            row = conn.execute(
                "SELECT first_seen, count FROM senders WHERE domain=?", (domain,)
            ).fetchone()
            if row:
                first_seen = datetime.fromisoformat(row[0])
                days = (datetime.now() - first_seen).days
                return True, row[1], days
        return False, 0, 0
    except Exception as e:
        log.debug(f"Sender memory check error: {e}")
        return False, 0, 0


def record_sender_if_clean(domain: str, is_clean: bool):
    """Record sender ONLY if the email verdict is clean."""
    if not domain or not is_clean:
        return
    domain = domain.lower()
    try:
        with _sender_conn() as conn:
            row = conn.execute("SELECT count FROM senders WHERE domain=?", (domain,)).fetchone()
            now = datetime.now().isoformat()
            if row:
                conn.execute("UPDATE senders SET count=count+1 WHERE domain=?", (domain,))
            else:
                conn.execute("INSERT INTO senders (domain, first_seen, count) VALUES (?,?,1)",
                             (domain, now))
    except Exception as e:
        log.debug(f"Sender memory record error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _esc(t):
    """FIX(C16): HTML-escape any value. Original returned '' for falsy non-None
    values like 0, False, []. Now only returns '' for None."""
    if t is None:
        return ""
    return html.escape(str(t))


def _root_domain(d):
    """FIX(C17): Extract registrable domain, handling compound TLDs.
    Original only handled 7 compound TLDs - expanded to 30+ to fix typosquat
    detection for domains like microsoft.co.za, paypal.com.br, etc."""
    if not d:
        return d
    p = d.lower().split('.')
    compound_tlds = [
        'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'net.uk',
        'com.au', 'gov.au', 'net.au', 'org.au', 'edu.au',
        'co.nz', 'gov.nz', 'ac.nz', 'org.nz',
        'co.in', 'gov.in', 'ac.in', 'org.in', 'net.in',
        'co.za', 'gov.za', 'ac.za', 'org.za',
        'com.br', 'gov.br', 'org.br', 'net.br',
        'co.jp', 'go.jp', 'ac.jp', 'or.jp', 'ne.jp',
        'co.kr', 'go.kr', 'ac.kr', 'or.kr',
        'com.sg', 'gov.sg', 'edu.sg',
        'co.th', 'go.th', 'ac.th',
        'com.mx', 'gob.mx', 'org.mx',
        'com.ar', 'gob.ar', 'org.ar',
        'com.cn', 'gov.cn', 'edu.cn', 'org.cn',
        'com.tw', 'gov.tw', 'edu.tw', 'org.tw',
        'com.hk', 'gov.hk', 'edu.hk',
        'co.id', 'go.id', 'ac.id',
        # [FIX-ROOT-TLD]: Middle Eastern / North African compound TLDs were missing.
        # Without these, _root_domain('mail.company.com.eg') returns 'com.eg'
        # (the raw TLD) instead of 'company.com.eg' (the registrable domain).
        # This breaks is_tracking_domain() suffix-matching and typosquat checks
        # for all domains under .com.eg, .com.sa, .com.ae, .com.tr etc.
        'com.eg', 'org.eg', 'net.eg', 'edu.eg', 'gov.eg',
        'com.sa', 'org.sa', 'net.sa', 'edu.sa',
        'com.ae', 'org.ae', 'net.ae', 'ac.ae',
        'com.kw', 'org.kw', 'net.kw', 'edu.kw',
        'com.qa', 'org.qa', 'net.qa', 'edu.qa',
        'com.bh', 'org.bh', 'net.bh', 'edu.bh',
        'com.om', 'org.om', 'net.om', 'edu.om',
        'com.jo', 'org.jo', 'net.jo', 'edu.jo',
        'com.lb', 'org.lb', 'net.lb', 'edu.lb',
        'com.iq', 'org.iq', 'net.iq', 'edu.iq',
        'com.tr', 'org.tr', 'net.tr', 'edu.tr',
        'com.pk', 'org.pk', 'net.pk', 'edu.pk',
        'com.bd', 'org.bd', 'net.bd', 'edu.bd',
        'com.lk', 'org.lk', 'net.lk', 'edu.lk',
        'com.np', 'org.np', 'net.np',
        'com.vn', 'org.vn', 'net.vn', 'edu.vn',
        'com.ph', 'org.ph', 'net.ph', 'edu.ph',
        'com.my', 'org.my', 'net.my', 'edu.my',
        'com.ng', 'org.ng', 'net.ng', 'edu.ng',
        'com.ke', 'org.ke', 'net.ke', 'ac.ke',
        'com.gh', 'org.gh', 'net.gh', 'edu.gh',
        'com.uy', 'org.uy', 'net.uy',
        'com.pe', 'org.pe', 'net.pe', 'edu.pe',
        'com.co', 'org.co', 'net.co', 'edu.co',
        'com.cl', 'org.cl', 'net.cl', 'edu.cl',
        'com.ec', 'org.ec', 'net.ec', 'edu.ec',
        'com.gt', 'org.gt', 'net.gt', 'edu.gt',
        'com.do', 'org.do', 'net.do', 'edu.do',
    ]
    dl = d.lower()
    for cc in compound_tlds:
        if dl.endswith('.' + cc):
            parts_needed = len(cc.split('.')) + 1
            return '.'.join(p[-parts_needed:])
    return '.'.join(p[-2:]) if len(p) >= 2 else d


def defang(v):
    if not isinstance(v, str):
        return str(v)
    return _esc(
        v.replace('http://', 'hxxp://')
         .replace('https://', 'hxxps://')
         .replace('.', '\u200b[.]\u200b')
    )


def shannon_entropy(data) -> float:
    """Shannon entropy in bits per byte/character."""
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode('utf-8', 'ignore')
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def subdomain_entropy(domain: str) -> float:
    """[I06] Shannon entropy of the subdomain portion of a domain.

    DGA subdomains used in phishing/malware C2 look like:
      a3f9b2c1d4e5.evil.com  (pure hex/random chars)
    NOT like:
      de-smtp-delivery-123.mimecast.com  (structured mail server name)
      us-east-1.amazonaws.com            (structured cloud region)

    Guards applied:
    - Structured hostname pattern: label contains BOTH digits AND hyphens
      arranged in a word-number pattern (mail-server naming conventions).
      These are delivery/relay/CDN hostnames, not DGA.
    - Only flag at entropy > 4.0 (raised from 3.5). A structured label like
      'de-smtp-delivery-123' scores ~3.7b — above the old threshold but
      clearly a legitimate naming pattern.
    - Labels of only hex characters (0-9, a-f) under 12 chars: skip —
      could be a transaction ID or UUID fragment in a CDN URL, not DGA.
    """
    if not domain:
        return 0.0
    parts = domain.split('.')
    if len(parts) <= 2:
        return 0.0
    label = parts[0]
    # Skip short labels ('www', 'mail', 'ftp', 'smtp')
    if len(label) <= 5:
        return 0.0

    # Guard: structured mail/server hostname pattern — word-hyphen-word/number
    # e.g. 'de-smtp-delivery-123', 'us-east-1', 'mail-relay-02'
    # These have hyphens separating recognizable segments.
    if '-' in label:
        segments = label.split('-')
        # If every segment is either a word (all alpha) or a short number, it's
        # a structured server name, not a DGA domain.
        structured = all(
            s.isalpha() or s.isdigit() or (len(s) <= 4 and s.isalnum())
            for s in segments if s
        )
        if structured and len(segments) >= 2:
            return 0.0

    # Guard: pure hex string could be a CDN token/transaction ID
    if all(c in '0123456789abcdef-' for c in label.lower()) and len(label) <= 16:
        return 0.0

    return shannon_entropy(label)


def is_randomized_domain(domain: str) -> bool:
    """[I06] Heuristic: detect algorithmically/randomly generated domain names.
    Checks consonant clustering and vowel ratio.

    FALSE POSITIVE GUARDS (hard-won lessons):
    - Hyphenated domains: 'schneider-electric', 'coca-cola', 'well-known-brand'
      Hyphens almost always indicate a compound human word, not DGA. Skip.
    - Consecutive consonants: German/French/Dutch names regularly have 4-char
      consonant clusters (schn, str, cht, etc). Threshold raised to 6.
    - Domain length: very short root names (<= 6 chars) have noisy stats. Skip.
    - Min vowel ratio tightened to 15% (from 20%) to reduce false positives on
      brand names with short vowel runs like 'rhythms', 'crypts', etc.

    Real DGA examples (DO fire): xjqkzpmnvb.com, bvhfgkrst.net, qzxvwpkjf.ru
    Legitimate examples (MUST NOT fire): schneider-electric.com, github.com,
      wordpress.com, springframework.org, netflix.com
    """
    root = _root_domain(domain).split('.')[0]
    if not root or len(root) < 8:
        return False

    # Guard: any hyphen = compound word / brand name — not DGA
    if '-' in root:
        return False

    vowels = set('aeiou')
    alpha_chars = [c for c in root.lower() if c.isalpha()]
    total_alpha = len(alpha_chars)
    if total_alpha < 7:
        return False

    vowel_count = sum(1 for c in alpha_chars if c in vowels)
    vowel_ratio = vowel_count / total_alpha

    # Very low vowel ratio is a strong DGA indicator — tightened to 15%
    # (was 20%, which caught 'schneider' at 22% vowels incorrectly)
    if vowel_ratio < 0.15:
        return True

    # Long consecutive consonant runs — raised threshold to 6 (was 4)
    # Germanic names like 'schneider' (schn=4) fire the old rule incorrectly.
    # Real DGA: 'xjqkzpmnvb' has 10 consecutive consonants.
    max_consec = 0
    cur_consec = 0
    for c in alpha_chars:
        if c not in vowels:
            cur_consec += 1
            max_consec = max(max_consec, cur_consec)
        else:
            cur_consec = 0
    if max_consec >= 6:
        return True

    return False

def _levenshtein(a, b):
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


_HOMOGLYPHS = {'0': 'o', '1': 'l', 'l': 'i', 'rn': 'm', 'vv': 'w', 'cl': 'd'}


def check_typosquat(domain):
    d = domain.lower()
    root = _root_domain(d).split('.')[0]
    full_root = _root_domain(d) # e.g., googleusercontent.com
    
    if 'xn--' in d:
        return "IDN HOMOGRAPH: Punycode domain"
        
    brands = {
        'microsoft': 'microsoft.com', 'google': 'google.com', 'apple': 'apple.com',
        'amazon': 'amazon.com', 'paypal': 'paypal.com', 'facebook': 'facebook.com',
        'netflix': 'netflix.com', 'linkedin': 'linkedin.com', 'docusign': 'docusign.com',
        'adobe': 'adobe.com', 'chase': 'chase.com', 'wellsfargo': 'wellsfargo.com',
    }
    
    # EXPANDED ALLOWLIST: Legitimate infrastructure that contains brand names
    allowed_variants = {
        'google': {
            'googleusercontent.com', 'googleapis.com', 'googlemail.com',
            'googlegroups.com', 'gstatic.com', 'gvt1.com',
            # FIX: Missing legitimate Google infrastructure — all caused false BRAND ABUSE flags
            'googletagmanager.com', 'googleads.com', 'google-analytics.com',
            'googlesyndication.com', 'doubleclick.net', 'google.co.uk',
            'google.com.au', 'google.ca', 'google.de', 'google.fr',
            'accounts.google.com', 'support.google.com', 'drive.google.com',
            'docs.google.com', 'mail.google.com', 'meet.google.com',
        },
        'amazon': {
            'amazonaws.com', 'ssl-images-amazon.com', 'amazonses.com',
            'media-amazon.com', 'a.co', 'amazon-adsystem.com',
            # FIX: Missing legitimate Amazon CDN/infrastructure domains
            'cloudfront.net', 'awsstatic.com', 'amazon.co.uk', 'amazon.de',
            'amazon.ca', 'amazon.com.au', 'amazon.co.jp',
        },
        'microsoft': {
            'microsoftonline.com', 'office365.com', 'windows.net', 'azure.com',
            'outlook.com', 'live.com', 'office.com', 'sharepoint.com',
            'msecnd.net', 'msocdn.com',
            'onmicrosoft.com',
            'microsoft.com', 'microsoftstream.com', 'microsoftteams.com',
            'azureedge.net', 'azurewebsites.net', 'trafficmanager.net',
            'blob.core.windows.net', 'mail.protection.outlook.com',
            # FIX: Missing legitimate Microsoft domains causing false BRAND ABUSE
            'visualstudio.com', 'msn.com', 'skype.com', 'xbox.com',
            'bing.com', 'linkedin.com', 'github.com',  # Microsoft-owned
        },
        'paypal': {
            'paypal-communication.com', 'paypal-objects.com', 'paypal.me'
        },
        'facebook': {
            'fb.com', 'fbcdn.net', 'fbsbx.com', 'facebook.net'
        },
        'netflix': {
            'nflxso.net', 'nflxext.com', 'nflximg.net', 'nflxvideo.net'
        },
        'linkedin': {
            'licdn.com', 'linkedin.com'
        },
        'docusign': {
            'docusign.net', 'docusign.com'
        },
        'adobe': {
            'adobe.io', 'adobelogin.com', 'typekit.net'
        },
        'apple': {
            'icloud.com', 'mzstatic.com', 'apple-cloudkit.com'
        },
        'chase': {
            'jpmorganchase.com', 'chase.com'
        },
        'wellsfargo': {
            'wellsfargoemail.com', 'wellsfargo.com'
        }
    }

    for bn, bd in brands.items():
        br = bd.split('.')[0]
        if root == br:
            continue

        # ── Allowlist check FIRST — before any distance / brand-abuse logic ──
        # If the full registrable domain (e.g. onmicrosoft.com) is in the known
        # good variants for this brand, skip all checks for it.  Without this
        # guard, onmicrosoft.com scores levenshtein=2 from microsoft.com and
        # also triggers the brand-abuse substring check — both false positives.
        if full_root in allowed_variants.get(bn, set()):
            continue

        dist = _levenshtein(root, br)
        # FIX(BUG2): Guard on brand root length, NOT on the suspect domain root.
        # Short brand roots (≤5 chars: 'apple', 'adobe', 'chase') are 1 edit
        # from common English words — 'ample'/'apple', 'abode'/'adobe',
        # 'phase'/'chase'. Only flag distance-based matches when the brand
        # root itself is 6+ chars (google, paypal, amazon, netflix, etc.).
        if 0 < dist <= 2 and len(root) >= 4 and len(br) >= 6:
            return f"TYPOSQUAT: '{d}' is {dist} edit(s) from '{bd}'"
        
        norm = root
        for fake, real in _HOMOGLYPHS.items():
            norm = norm.replace(fake, real)
        if norm == br and root != br:
            return f"HOMOGLYPH: '{d}' mimics '{bd}'"
            
        # Brand Abuse Logic with Allowlist
        # FIX(BUG1): Use segment-level matching, NOT raw substring.
        # 'apple' in 'snapple.com' → True (FP). Split on '.' and '-' first so
        # we only match whole segments: 'apple' in ['snapple','com'] → False.
        domain_parts = re.split(r'[.\-]', d.rstrip('.'))
        if bn in domain_parts and full_root != bd:
            # Allowlist already checked above — any remaining match is suspicious
            return f"BRAND ABUSE: '{d}' embeds '{bn}' but isn't '{bd}'"
            
    return None

# ═══════════════════════════════════════════════════════════════════════════════
# PASSIVE DNS REPUTATION CHECKS
# ═══════════════════════════════════════════════════════════════════════════════
# Why NOT Quad9: Quad9 does not guarantee NXDOMAIN for blocked domains, and
# many legitimate mail-only domains (e.g. *.onmicrosoft.com) have no A record,
# causing false positives when tested with any A-record resolver.
# Instead we use two reliable, free, standard techniques:
#   1. Spamhaus ZEN DNSBL for source IP reputation (reverse-DNS lookup)
#   2. MX record presence to validate the sender domain can receive mail back

_SPAMHAUS_CATEGORIES = {
    '127.0.0.2': ('SBL', 'Listed in Spamhaus Block List — verified spam source'),
    '127.0.0.3': ('SBL', 'Listed in Spamhaus Block List — verified spam source'),
    '127.0.0.4': ('XBL', 'Listed in Spamhaus Exploits Block List — infected/hijacked host'),
    '127.0.0.5': ('XBL', 'Listed in Spamhaus Exploits Block List — infected/hijacked host'),
    '127.0.0.6': ('XBL', 'Listed in Spamhaus Exploits Block List — infected/hijacked host'),
    '127.0.0.7': ('XBL', 'Listed in Spamhaus Exploits Block List — infected/hijacked host'),
    '127.0.0.9': ('SBL', 'Listed in Spamhaus Block List — policy block'),
    '127.0.0.10': ('PBL', 'Listed in Spamhaus Policy Block List — dynamic/residential IP'),
    '127.0.0.11': ('PBL', 'Listed in Spamhaus Policy Block List — dynamic/residential IP'),
}


def check_spamhaus_ip(ip: str) -> Tuple[bool, str, str]:
    """
    Check an IP against Spamhaus ZEN DNSBL via a standard DNS reverse lookup.
    Returns (is_listed, category, description).

    Method: reverse the IP octets and query <reversed>.zen.spamhaus.org for A.
    - NXDOMAIN = not listed (clean).
    - Any A record returned = listed; response IP indicates why.
    No API key. No third-party HTTP call. Pure DNS. Industry standard.
    """
    if not DNS_OK or not ip:
        return False, '', ''
    # Validate it looks like an IPv4 address
    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False, '', ''
    # Skip private / reserved ranges — DNSBL only applies to public IPs
    if any(r.match(ip) for r in _PRIVATE_IP_PATTERNS):
        return False, '', ''
    try:
        reversed_ip = '.'.join(reversed(parts))
        query = f"{reversed_ip}.zen.spamhaus.org"
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(query, 'A')
        # Listed — identify category from response
        for ans in answers:
            resp = str(ans)
            cat, desc = _SPAMHAUS_CATEGORIES.get(resp, ('LISTED', f'IP listed in Spamhaus ZEN ({resp})'))
            return True, cat, desc
        return True, 'LISTED', 'IP listed in Spamhaus ZEN'
    except dns.resolver.NXDOMAIN:
        return False, '', ''  # Not listed = clean
    except Exception:
        return False, '', ''  # Timeout / error — always assume innocent


def check_sender_mx(domain: str) -> Tuple[bool, str]:
    """
    Check whether the sender domain has valid MX records.
    A domain with SPF FAIL that also has no MX records is highly suspicious —
    it can neither send legitimately nor receive bounce replies (throw-away domain).
    Returns (has_mx, detail_string).
    """
    if not DNS_OK or not domain:
        return True, ''  # Can't check — don't penalise
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, 'MX')
        mx_hosts = [str(r.exchange).rstrip('.') for r in answers]
        return True, ', '.join(mx_hosts[:3])
    except dns.resolver.NXDOMAIN:
        return False, 'No MX records — domain cannot receive email'
    except dns.resolver.NoAnswer:
        return False, 'No MX records found for sender domain'
    except Exception:
        return True, ''  # Timeout — don't penalise

def get_source_ip(msg):
    """Extract first public IP from Received headers (outermost hop)."""
    for h in reversed(msg.get_all('Received', []) or []):
        for ip in PAT_IPV4.findall(str(h)):
            if not any(r.match(ip) for r in _PRIVATE_IP_PATTERNS):
                return ip
    return None


@contextlib.contextmanager
def _tmp_file(data, suffix=''):
    """FIX(C05): Temporary file context manager with guaranteed cleanup.
    Original captured f.name AFTER f.write(), so a write failure (disk full)
    would leak the temp file. Now captures path immediately."""
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    p = f.name
    try:
        f.write(data)
        f.close()
        yield p
    except Exception:
        try:
            f.close()
        except Exception:
            pass
        raise
    finally:
        if os.path.exists(p):
            try:
                os.unlink(p)
            except Exception:
                pass


def _is_cloud(isp):
    il = (isp or '').lower()
    # FIX: Check for simple brand keywords in the ISP string, not full domains
    cloud_keywords = ['google', 'amazon', 'microsoft', 'azure', 'cloudflare']
    return any(k in il for k in cloud_keywords)
# ═══════════════════════════════════════════════════════════════════════════════
# HOP TIMING ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_hops(msg) -> Tuple[int, List[float], str]:
    """Parse Received timestamps, compute inter-hop delays, flag stalling."""
    headers = msg.get_all('Received', []) or []
    count = len(headers)
    timestamps = []
    for h in reversed(headers):
        h = str(h)
        parts = h.rsplit(';', 1)
        if len(parts) == 2:
            try:
                ts = email.utils.parsedate_to_datetime(parts[1].strip())
                timestamps.append(ts)
            except Exception:
                pass

    delays = []
    anomaly = ""
    for i in range(1, len(timestamps)):
        try:
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
            delays.append(delta)
        except Exception:
            pass

    # Flag stalling: any hop > 15 minutes is suspicious (only positive delays)
    stalls = [(i + 1, d) for i, d in enumerate(delays) if d > 900]
    if stalls:
        worst = max(stalls, key=lambda x: x[1])
        anomaly = f"Hop {worst[0]} stalled {worst[1] / 60:.0f}min (relay delay)"
    elif count == 0:
        anomaly = "No Received headers -- locally crafted?"
    elif count == 1:
        anomaly = "Single hop -- unusual for internet email"
    elif count > 15:
        anomaly = f"Excessive hops ({count}) -- routing anomaly"

    return count, delays, anomaly


# ═══════════════════════════════════════════════════════════════════════════════
# DOMAIN INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

# FIX(S8): Lock for WHOIS calls to prevent concurrent socket timeout clobbering
_whois_lock = threading.Lock()

# PERF: Cache domain_intel() results by root domain.
# domain_intel() is called once per observable in check_vt() AND once more
# inside _vt_consensus(), and also in concurrent VT threads. With WHOIS
# serialised through _whois_lock, every unique root domain was blocking all
# other threads. The cache lets subsequent calls (same email, same domain,
# concurrent workers) skip both WHOIS and gethostbyname entirely.
_DOMAIN_INTEL_CACHE: dict = {}
_DOMAIN_INTEL_CACHE_LOCK = threading.Lock()


def domain_intel(domain: str) -> DomainIntel:
    # PERF: Cache by root domain — many observables in one email share the same
    # root (e.g. track.evil.com and click.evil.com both root to evil.com).
    # Cache is also critical for thread safety: without it, concurrent VT workers
    # all race to WHOIS the same domain simultaneously.
    root = _root_domain(domain)
    with _DOMAIN_INTEL_CACHE_LOCK:
        if root in _DOMAIN_INTEL_CACHE:
            return _DOMAIN_INTEL_CACHE[root]

    di = DomainIntel(domain=domain)
    typo = check_typosquat(domain)
    if typo:
        di.typosquat = typo

    dl = domain.lower()
    for tld in GOVERNMENT_TLDS:
        if dl.endswith(tld):
            di.category = 'government'; di.trusted = True
            di.reasoning = f'Gov ({tld})'
            with _DOMAIN_INTEL_CACHE_LOCK: _DOMAIN_INTEL_CACHE[root] = di
            return di
    for tld in EDUCATIONAL_TLDS:
        if dl.endswith(tld):
            di.category = 'educational'; di.trusted = True
            di.reasoning = f'Edu ({tld})'
            with _DOMAIN_INTEL_CACHE_LOCK: _DOMAIN_INTEL_CACHE[root] = di
            return di
    for pd, desc in KNOWN_PLATFORMS.items():
        if dl == pd or dl.endswith('.' + pd):
            di.category = 'platform'; di.trusted = True
            di.platform = desc; di.reasoning = f'Known: {desc}'
            with _DOMAIN_INTEL_CACHE_LOCK: _DOMAIN_INTEL_CACHE[root] = di
            return di
    for td in MAJOR_TECH:
        if dl == td or dl.endswith('.' + td):
            di.category = 'major_tech'; di.trusted = True
            di.reasoning = f'Major tech ({td})'
            with _DOMAIN_INTEL_CACHE_LOCK: _DOMAIN_INTEL_CACHE[root] = di
            return di

    # Check if domain is a known security gateway / email protection service
    if is_tracking_domain(dl):
        di.category = 'security_gateway'; di.trusted = True
        di.reasoning = f'Email security gateway'
        with _DOMAIN_INTEL_CACHE_LOCK: _DOMAIN_INTEL_CACHE[root] = di
        return di

    if WHOIS_OK:
        try:
            # FIX(S8): Serialize WHOIS calls through a lock so concurrent
            # threads don't clobber each other's global socket timeout.
            with _whois_lock:
                # Double-checked locking: another thread may have completed
                # WHOIS for this same root domain while we waited for the lock.
                # Re-check cache inside the lock to avoid duplicate WHOIS calls.
                with _DOMAIN_INTEL_CACHE_LOCK:
                    if root in _DOMAIN_INTEL_CACHE:
                        return _DOMAIN_INTEL_CACHE[root]
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(DNS_TIMEOUT)
                try:
                    w = whois_lib.whois(_root_domain(domain))
                    if w.org:
                        di.org = str(w.org[0] if isinstance(w.org, list) else w.org)
                    if w.creation_date:
                        cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                        if isinstance(cd, datetime):
                            di.age_days = (datetime.now() - cd).days
                            if di.age_days < 30:
                                di.reasoning = f"New domain ({di.age_days}d)"
                            elif di.age_days > 365:
                                di.reasoning = f"Established ({di.age_days}d)"
                finally:
                    socket.setdefaulttimeout(old_timeout)
        except Exception:
            pass

    if not di.reasoning:
        try:
            # BUG FIX: socket.setdefaulttimeout() is global — setting it outside
            # _whois_lock allows concurrent threads to clobber each other's timeout.
            # Two threads could each set it then both reset it before either reads,
            # leaving one thread with no timeout at all (hangs forever on bad DNS).
            # Fix: protect this block with _whois_lock just like the WHOIS call above.
            with _whois_lock:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(DNS_TIMEOUT)
                try:
                    socket.gethostbyname(domain)
                    di.reasoning = "Active domain"
                finally:
                    socket.setdefaulttimeout(old_timeout)
        except Exception:
            di.reasoning = "Cannot resolve"

    # [I06] Subdomain entropy and randomized domain detection.
    # These run AFTER WHOIS/trust checks so they only flag genuinely unknown domains.
    # Guard: skip if domain resolves to a known tracking/gateway domain — mimecast,
    # proofpoint, etc. all use structured delivery subdomains with moderate entropy.
    if not di.trusted and not is_tracking_domain(domain):
        sub_ent = subdomain_entropy(domain)
        if sub_ent > 4.0:   # Raised from 3.5 — structured server names score ~3.5-3.9
            di.reasoning = (di.reasoning or "Unknown") + f" | HIGH subdomain entropy ({sub_ent:.1f}b)"
        if is_randomized_domain(domain):
            di.reasoning = (di.reasoning or "Unknown") + " | DGA/random domain name pattern"

    # Store in cache before returning
    with _DOMAIN_INTEL_CACHE_LOCK:
        _DOMAIN_INTEL_CACHE[root] = di
    return di


# ═══════════════════════════════════════════════════════════════════════════════
# VT / ABUSEIPDB / MALWAREBAZAAR
# ═══════════════════════════════════════════════════════════════════════════════

class _VTLimiter:
    """FIX(C04): Rate limiter that does NOT sleep while holding the lock.
    Original code called time.sleep() inside `with self._lock:`, blocking all
    4 ThreadPoolExecutor workers. Now computes required sleep, releases lock,
    sleeps, then re-acquires."""

    def __init__(self):
        self._last = 0.0
        self._cnt = 0
        self._window_start = time.time()
        self._lock = threading.Lock()

    def wait(self):
        while True:
            sleep_needed = 0.0
            with self._lock:
                now = time.time()
                if now - self._window_start > 60:
                    self._cnt = 0
                    self._window_start = now
                if self._cnt >= 4:
                    sleep_needed = max(0.0, 60 - (now - self._window_start) + 1)
                elif self._cnt > 0:
                    elapsed = now - self._last
                    if elapsed < 15:
                        sleep_needed = 15 - elapsed

                if sleep_needed <= 0:
                    self._last = time.time()
                    self._cnt += 1
                    return

            time.sleep(min(sleep_needed, 2.0))


class _Cache:
    def __init__(self):
        self._d = {}
        self._lock = threading.Lock()

    def get(self, k):
        with self._lock:
            return self._d.get(hashlib.sha256(k.encode()).hexdigest())

    def put(self, k, v):
        with self._lock:
            if len(self._d) > 800:
                for old in list(self._d)[:200]:
                    del self._d[old]
            self._d[hashlib.sha256(k.encode()).hexdigest()] = v


try:
    _vt_lim = st.cache_resource(lambda: _VTLimiter())()
except Exception:
    _vt_lim = _VTLimiter()

# FIX(C08): Module-level thread-safe cache instead of st.session_state.
# VT results are global facts about URLs (not session-specific), so sharing
# across sessions is correct and improves performance.
# FIX(S10): Sender memory sharing is addressed separately — the sender DB
# records domain trust per-domain (not per-user), and trust is only granted
# when the CURRENT email's auth also passes (SPF PASS required). This means
# User A's clean analysis of attacker.com only helps User B if attacker.com
# also passes SPF in User B's email, which it won't in a spoofed attack.
_vt_cache_instance = _Cache()


def _vt_cache():
    return _vt_cache_instance


VT_WEIGHTS = {
    'Google Safebrowsing': 3, 'Microsoft': 3, 'Kaspersky': 3, 'Sophos': 3,
    'ESET': 3, 'Fortinet': 3, 'Symantec': 3, 'BitDefender': 3,
    'McAfee': 2, 'Trend Micro': 2, 'Palo Alto Networks': 2,
}


class Config:
    try:
        VT_KEY = st.secrets["vt_api_key"]
    except Exception:
        VT_KEY = ""
    try:
        ABUSE_KEY = st.secrets["abuseipdb_key"]
    except Exception:
        ABUSE_KEY = ""
    # MalwareBazaar: no API key required — public API works without one
    MB_KEY = ""
    try:
        OTX_KEY = st.secrets["otx_api_key"]      # AlienVault OTX — free at otx.alienvault.com
    except Exception:
        OTX_KEY = ""
    try:
        XFORCE_KEY    = st.secrets["xforce_api_key"]    # IBM X-Force — free at exchange.xforce.ibmcloud.com
        XFORCE_SECRET = st.secrets["xforce_api_secret"]
    except Exception:
        XFORCE_KEY = ""
        XFORCE_SECRET = ""
    try:
        API_KEY = st.secrets["sherlock_api_key"]
    except Exception:
        _key_seed = hashlib.md5(os.environ.get("COMPUTERNAME", socket.gethostname()).encode(), usedforsecurity=False).hexdigest()
        API_KEY = f"slk-{_key_seed[:8]}-{_key_seed[8:16]}-{_key_seed[16:24]}"
    try:
        SOAR_WEBHOOK_URL = st.secrets["soar_webhook_url"]
    except Exception:
        SOAR_WEBHOOK_URL = ""
    API_PORT = 8000
    WEBHOOK_MIN_SCORE = 40


def _vt_consensus(stats, detailed=None, is404=False, dom="", is_cloud_ip=False, _di=None):
    """Classify a VT result into a threat level.

    _di: pre-computed DomainIntel from the caller (check_vt). When provided,
         avoids calling domain_intel() a second time for the same domain.
         Without this, every observable triggered two WHOIS lookups — one in
         check_vt() and one here.

    Cloud IP FP-reduction logic
    ─────────────────────────────
    Major cloud provider IPs (Microsoft Azure/O365, Google, Amazon AWS,
    Cloudflare) appear in VT with occasional low-confidence flags from
    small/obscure engines that mistake shared infrastructure for malicious
    hosts. Without a FP guard, 3 minor engines firing on 52.97.218.149
    (a Microsoft Exchange Online relay) would trigger 'MALICIOUS' — which
    is what the screenshot showed.

    Guard: when is_cloud_ip=True, we require EITHER:
      - At least 1 major vendor (weight≥3) to flag it, OR
      - Weighted score ≥ 4 (i.e. 4+ minor engines or 1 major+1 minor)
    before calling it MALICIOUS. Pure raw-count alone (3 obscure engines)
    downgrades to SUSPICIOUS instead. Detection accuracy is not reduced —
    any real threat on a cloud IP would have at least one major vendor hit.
    """
    r = VTResult()
    if dom:
        # Use pre-computed DomainIntel when available (avoids a second WHOIS call).
        r.domain_intel = _di if _di is not None else domain_intel(dom)
    if is404:
        r.success = True; r.is_new = True
        r.threat_level = "CLEAN" if (r.domain_intel and r.domain_intel.trusted) else "UNKNOWN"
        r.reasoning = ("Not in VT" if r.threat_level == "UNKNOWN"
                        else f"New URL, trusted: {r.domain_intel.reasoning}")
        return r
    r.total = sum(stats.values()) if stats else 0
    r.malicious = stats.get('malicious', 0)
    r.success = True
    if detailed:
        r.engines = [e for e, d in detailed.items()
                     if isinstance(d, dict) and d.get('category') == 'malicious']
    w = sum(VT_WEIGHTS.get(e, 1) for e in r.engines)
    r.weighted = w
    t1 = sum(1 for e in r.engines if VT_WEIGHTS.get(e, 0) >= 3)

    if r.malicious == 0:
        r.threat_level = "CLEAN"
        r.reasoning = f"Clean ({stats.get('harmless', 0)} safe)"
    elif t1 >= 2:
        r.threat_level = "CRITICAL"
        r.reasoning = f"{t1} major vendors flagged"
    elif w >= 5:
        r.threat_level = "CRITICAL"
        r.reasoning = f"Consensus: {r.malicious} engines"
    elif r.malicious >= 3:
        # FP guard for cloud/trusted IPs: raw count alone is not enough.
        # Microsoft, Google, Amazon, Cloudflare IPs routinely get 2-5 obscure
        # engine flags. Require at least 1 major vendor OR weighted score ≥ 4.
        if is_cloud_ip and t1 == 0 and w < 4:
            r.threat_level = "SUSPICIOUS"
            r.reasoning = (f"{r.malicious} minor engines only "
                           f"(cloud IP — major vendor agreement required for MALICIOUS)")
        else:
            r.threat_level = "MALICIOUS"
            r.reasoning = f"{r.malicious} engines"
    elif r.malicious >= 2:
        r.threat_level = "SUSPICIOUS"
        r.reasoning = f"{r.malicious} engines"
    else:
        r.threat_level = "UNKNOWN"
        r.reasoning = "Single engine flag"
    return r


def check_vt(kind, value):
    """Check observable with VT. ALWAYS runs domain_intel() first for local
    classification (gov/edu/tech/typosquat/WHOIS) even without an API key."""
    c = _vt_cache()
    cached = c.get(f"{kind}:{value}")
    if cached:
        return cached

    dom = ""
    if kind == 'url':
        # FIX(v13): use _url_host() not .netloc — .netloc includes the port number
        # which corrupts domain_intel() and causes security gateway URLs to not be
        # recognized as trusted, showing them as UNKNOWN instead of CLEAN.
        try:
            dom = _url_host(value)
        except Exception:
            pass
    elif kind == 'domain':
        dom = value

    di = domain_intel(dom) if dom else None

    if not Config.VT_KEY:
        r = VTResult(success=True, error="No API key")
        r.domain_intel = di
        if di and di.trusted:
            r.threat_level = "CLEAN"
            r.reasoning = f"No VT API -- Local intel: {di.reasoning}"
        elif di and di.typosquat:
            r.threat_level = "SUSPICIOUS"
            r.reasoning = f"No VT API -- {di.typosquat}"
        else:
            r.threat_level = "UNKNOWN"
            r.reasoning = f"No VT API -- {di.reasoning if di else 'no local intel'}"
        c.put(f"{kind}:{value}", r)
        return r

    # FIX(v16-B): Trusted-domain VT skip — the single biggest speed improvement.
    # domain_intel() (line above) already classifies Microsoft/Google/SharePoint/
    # Gov/Edu/Security-gateway domains as di.trusted=True using local hardcoded lists.
    # Despite this, the original code always called _vt_lim.wait() + VT API for
    # every observable — burning 15 seconds per trusted domain on free tier.
    # An email with 5 Microsoft/Google links wasted 75 seconds learning nothing new.
    # Fix: if local intel already classifies the domain as trusted AND it is not a
    # URL shortener (those can redirect to malicious sites, must be checked), return
    # the local result immediately without touching VT.
    if di and di.trusted and not (di.category in ("url_shortener",)):
        r = VTResult(success=True, error="Trusted domain — VT skipped")
        r.domain_intel = di
        r.threat_level = "CLEAN"
        r.reasoning    = f"Local intel: {di.reasoning} (VT call skipped for trusted domain)"
        c.put(f"{kind}:{value}", r)
        return r

    try:
        _vt_lim.wait()
        h = {"x-apikey": Config.VT_KEY}
        if kind == 'url':
            # FIX(C03): Use base64url encoding per VT API v3 specification.
            # Original used SHA256, which requires VT's canonical URL form and
            # caused near-universal 404s (every URL appeared as "Not in VT").
            uid = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{uid}",
                headers=h, timeout=HTTP_TIMEOUT)
        elif kind == 'domain':
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{value}",
                headers=h, timeout=HTTP_TIMEOUT)
        else:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
                headers=h, timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            a = resp.json().get('data', {}).get('attributes', {})
            # Detect cloud provider IPs using ASN/owner data returned by VT itself.
            # This is more reliable than checking the AbuseIPDB ISP string because
            # VT's /ip_addresses endpoint includes 'as_owner' which names the ASN
            # directly (e.g. "MICROSOFT-CORP-MSN-AS-BLOCK", "GOOGLE", "AMAZON-02").
            _cloud_keywords = ['microsoft', 'google', 'amazon', 'cloudflare',
                               'alibaba', 'oracle cloud', 'digitalocean', 'linode',
                               'akamai', 'fastly', 'rackspace']
            _as_owner = (a.get('as_owner') or a.get('asn_owner') or '').lower()
            _is_cloud_ip = any(k in _as_owner for k in _cloud_keywords)
            r = _vt_consensus(
                a.get('last_analysis_stats', {}),
                a.get('last_analysis_results', {}), False, dom,
                is_cloud_ip=_is_cloud_ip, _di=di)
        elif resp.status_code == 404:
            r = _vt_consensus({}, {}, True, dom, _di=di)
        else:
            r = VTResult(error=f"HTTP {resp.status_code}")
            r.domain_intel = di
        c.put(f"{kind}:{value}", r)
        return r
    except Exception as e:
        r = VTResult(error=str(e)[:80])
        r.domain_intel = di
        return r


def check_abuseipdb(ip):
    if not ip or not Config.ABUSE_KEY:
        return {}
    try:
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': Config.ABUSE_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''},
            timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            return resp.json().get('data', {})
    except Exception:
        pass
    return {}


def check_malwarebazaar(data, filename):
    """Query MalwareBazaar by SHA256. No API key required — public endpoint."""
    try:
        sha = hashlib.sha256(data).hexdigest()
        resp = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': sha},
            timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            d = resp.json()
            # FIX(C21): bounds-check data list before indexing
            if d.get('query_status') == 'ok' and d.get('data') and len(d['data']) > 0:
                info = d['data'][0]
                return True, info.get('signature', 'Unknown'), info.get('tags', []) or []
    except Exception:
        pass
    return False, "", []


# ── AlienVault OTX threat intelligence (free, no rate-limit for basic use) ────
_otx_cache = _Cache()

def check_otx(kind: str, value: str) -> dict:
    """
    Query AlienVault OTX for IPs, domains, and URLs.
    Free API — register at https://otx.alienvault.com to get a key.
    Returns: {'pulse_count': int, 'threat_score': int, 'malware_families': [...],
              'tags': [...], 'threat_level': str, 'reasoning': str}
    Without a key the endpoint still returns basic data for IPs/domains.
    """
    if not value:
        return {}
    cache_key = f"otx:{kind}:{value}"
    cached = _otx_cache.get(cache_key)
    if cached:
        return cached

    result = {}
    try:
        headers = {}
        if Config.OTX_KEY:
            headers['X-OTX-API-KEY'] = Config.OTX_KEY

        if kind == 'ip':
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/general"
        elif kind == 'domain':
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{value}/general"
        elif kind == 'url':
            # OTX URL indicator needs the URL encoded
            import urllib.parse
            encoded = urllib.parse.quote(value, safe='')
            url = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded}/general"
        elif kind == 'hash':
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{value}/general"
        else:
            return {}

        resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            d = resp.json()
            pulse_count = d.get('pulse_info', {}).get('count', 0)
            pulses      = d.get('pulse_info', {}).get('pulses', [])
            families    = list({t for p in pulses for t in p.get('malware_families', []) if t})[:5]
            tags        = list({t for p in pulses for t in p.get('tags', []) if t})[:8]

            # Derive threat level from pulse count
            if pulse_count >= 10:
                threat_level = 'CRITICAL'
                reasoning    = f"OTX: {pulse_count} threat intelligence pulses"
            elif pulse_count >= 3:
                threat_level = 'HIGH'
                reasoning    = f"OTX: {pulse_count} threat pulses"
            elif pulse_count >= 1:
                threat_level = 'SUSPICIOUS'
                reasoning    = f"OTX: {pulse_count} threat pulse(s)"
            else:
                threat_level = 'CLEAN'
                reasoning    = "OTX: No threat pulses"

            result = {
                'pulse_count':      pulse_count,
                'threat_score':     min(100, pulse_count * 8),
                'malware_families': families,
                'tags':             tags,
                'threat_level':     threat_level,
                'reasoning':        reasoning,
            }
        elif resp.status_code == 404:
            result = {'pulse_count': 0, 'threat_level': 'CLEAN',
                      'reasoning': 'OTX: Not found in threat database'}
    except Exception as e:
        log.debug(f"OTX lookup failed for {kind}:{value}: {e}")
    _otx_cache.put(cache_key, result)
    return result


# ── IBM X-Force Exchange threat intelligence (free tier: 5,000 req/month) ─────
_xforce_cache = _Cache()

def check_xforce(kind: str, value: str) -> dict:
    """
    Query IBM X-Force Exchange for IPs, domains, and URLs.
    Free tier: register at https://exchange.xforce.ibmcloud.com → API Access.
    Add xforce_api_key and xforce_api_secret to .streamlit/secrets.toml.
    Returns: {'risk_score': float, 'categories': [...], 'threat_level': str, 'reasoning': str}
    """
    if not value or not Config.XFORCE_KEY or not Config.XFORCE_SECRET:
        return {}
    cache_key = f"xforce:{kind}:{value}"
    cached = _xforce_cache.get(cache_key)
    if cached:
        return cached

    result = {}
    try:
        auth = (Config.XFORCE_KEY, Config.XFORCE_SECRET)
        headers = {'Accept': 'application/json'}

        if kind == 'ip':
            resp = requests.get(
                f"https://api.xforce.ibmcloud.com/ipr/{value}",
                auth=auth, headers=headers, timeout=HTTP_TIMEOUT)
        elif kind in ('domain', 'url'):
            import urllib.parse
            encoded = urllib.parse.quote(value, safe='')
            resp = requests.get(
                f"https://api.xforce.ibmcloud.com/url/{encoded}",
                auth=auth, headers=headers, timeout=HTTP_TIMEOUT)
        elif kind == 'hash':
            resp = requests.get(
                f"https://api.xforce.ibmcloud.com/malware/{value}",
                auth=auth, headers=headers, timeout=HTTP_TIMEOUT)
        else:
            return {}

        if resp.status_code == 200:
            d = resp.json()
            if kind == 'ip':
                score      = float(d.get('score', 0))
                categories = list(d.get('cats', {}).keys())[:5]
            elif kind in ('domain', 'url'):
                result_key = 'url' if 'url' in d else 'result'
                inner      = d.get(result_key, d)
                score      = float(inner.get('score', 0))
                categories = list(inner.get('cats', {}).keys())[:5]
            elif kind == 'hash':
                malware    = d.get('malware', {})
                score      = 10.0 if malware.get('family') else 0.0
                categories = [malware.get('family', '')] if malware.get('family') else []
            else:
                score, categories = 0.0, []

            # X-Force scores are 1–10; map to threat levels
            if score >= 7:
                threat_level = 'CRITICAL'
                reasoning    = f"X-Force risk score {score:.1f}/10 ({', '.join(categories) or 'malicious'})"
            elif score >= 5:
                threat_level = 'HIGH'
                reasoning    = f"X-Force risk score {score:.1f}/10"
            elif score >= 2:
                threat_level = 'SUSPICIOUS'
                reasoning    = f"X-Force risk score {score:.1f}/10"
            else:
                threat_level = 'CLEAN'
                reasoning    = f"X-Force score {score:.1f}/10 — low risk"

            result = {
                'risk_score':   score,
                'categories':   categories,
                'threat_level': threat_level,
                'reasoning':    reasoning,
            }
        elif resp.status_code == 404:
            result = {'risk_score': 0, 'threat_level': 'CLEAN',
                      'reasoning': 'X-Force: No threat record found'}
        elif resp.status_code == 401:
            log.warning("X-Force: Invalid API credentials")
    except Exception as e:
        log.debug(f"X-Force lookup failed for {kind}:{value}: {e}")
    _xforce_cache.put(cache_key, result)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def _dns_dmarc(domain):
    if not DNS_OK:
        return {'status': 'UNKNOWN'}
    try:
        # FIX(C09): per-resolver timeout instead of global socket.setdefaulttimeout
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        for rd in resolver.resolve(f'_dmarc.{domain}', 'TXT'):
            t = rd.to_text().strip('"')
            if 'v=DMARC1' in t:
                pm = re.search(r'p=(\w+)', t)
                return {'status': 'FOUND', 'policy': pm.group(1) if pm else 'none', 'record': t}
        return {'status': 'MISSING'}
    except Exception:
        return {'status': 'MISSING'}


def _dns_spf(domain):
    if not DNS_OK:
        return {'status': 'UNKNOWN'}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        for rd in resolver.resolve(domain, 'TXT'):
            t = rd.to_text().strip('"')
            if 'v=spf1' in t:
                return {'status': 'FOUND', 'record': t}
        return {'status': 'MISSING'}
    except Exception:
        return {'status': 'MISSING'}


def analyze_auth(msg) -> AuthResult:
    r = AuthResult()
    r.source_ip = get_source_ip(msg) or ""
    r.hop_count, r.hop_delays, r.hop_anomaly = analyze_hops(msg)
    if r.hop_anomaly:
        r.details.append(r.hop_anomaly)

    # FIX(C15)+FIX(S9): Structured Authentication-Results parsing.
    # Original used naive substring matching ('spf=pass' in ah) which could
    # match inside unrelated strings like "reason: actually spf=fail after spf=pass".
    # Now uses regex word-boundary matching on individual header fields.
    ar_headers = msg.get_all('Authentication-Results', []) or []
    spf_headers = msg.get_all('Received-SPF', []) or []

    def _ar_check(protocol, result, headers=ar_headers):
        """Structured AR field check with word boundaries."""
        pat = re.compile(rf'\b{protocol}\s*=\s*{result}\b', re.I)
        for h in headers:
            if pat.search(str(h)):
                return True
        return False

    # [FIX-SEC-B]: vendor_pass used naive 'in' substring matching, allowing
    # a header value like "spf=fail; old=spf=pass" to match 'spf=pass' and
    # falsely set SPF PASS. An attacker who can inject X-FEAS-SPF (any SMTP
    # sender can add arbitrary headers) could craft this to override SPF FAIL.
    #
    # Word-boundary alone (\bspf) is insufficient: in 'old=spf=pass', 'spf'
    # is preceded by '=' (a non-word char), so \bspf still matches even though
    # 'spf' here is a VALUE, not a KEY. The correct guard uses a negative
    # lookbehind (?<!=) so 'spf' only matches when NOT immediately preceded
    # by '=' — ensuring 'old=spf=pass' does NOT trigger vendor_pass.
    _pat_spf_pass = re.compile(r'(?<!=)\bspf\s*=\s*pass\b', re.I)
    _pat_spf_result_pass = re.compile(r'(?<!=)\bspf-result\s*=\s*pass\b', re.I)
    vendor_pass = any(
        _pat_spf_pass.search(str(msg.get(h, ''))) or
        _pat_spf_result_pass.search(str(msg.get(h, '')))
        for h in ['X-FEAS-SPF', 'X-Forefront-Antispam-Report']
    )
    if vendor_pass:
        r.details.append("Vendor confirms SPF PASS")

    # SPF — check Received-SPF headers separately with word boundaries
    sh_pass = any(re.search(r'\bpass\b', str(h), re.I) for h in spf_headers)
    sh_fail = any(re.search(r'\bfail\b', str(h), re.I) and
                  not re.search(r'\bsoftfail\b', str(h), re.I) for h in spf_headers)
    sh_softfail = any(re.search(r'\bsoftfail\b', str(h), re.I) for h in spf_headers)

    if vendor_pass or _ar_check('spf', 'pass') or sh_pass:
        r.spf = 'PASS'; r.findings.append("SPF: PASS")
    elif _ar_check('spf', 'fail') or sh_fail:
        # FIX(BUG7): Removed dead code. The inner 'if vendor_pass:' branch here
        # was unreachable: if vendor_pass were True, the outer 'if vendor_pass or
        # _ar_check("spf","pass") or sh_pass:' would have already set SPF=PASS,
        # making this elif impossible to reach. Unconditionally set FAIL.
        r.spf = 'FAIL'; r.findings.append("SPF: FAIL")
    elif _ar_check('spf', 'softfail') or sh_softfail:
        r.spf = 'SOFTFAIL'; r.findings.append("SPF: SOFTFAIL")
    elif _ar_check('spf', 'temperror'):
        r.spf = 'TEMPERROR'; r.findings.append("SPF: TEMPERROR")
    elif _ar_check('spf', 'permerror'):
        r.spf = 'PERMERROR'; r.findings.append("SPF: PERMERROR")
    else:
        r.findings.append("SPF: NONE")

    # DKIM
    if _ar_check('dkim', 'pass'):
        r.dkim = 'PASS'; r.findings.append("DKIM: PASS")
    elif _ar_check('dkim', 'fail'):
        r.dkim = 'FAIL'; r.findings.append("DKIM: FAIL")
    else:
        r.findings.append("DKIM: NONE")

    # DMARC
    if _ar_check('dmarc', 'pass'):
        r.dmarc = 'PASS'; r.findings.append("DMARC: PASS")
    elif _ar_check('dmarc', 'fail'):
        r.dmarc = 'FAIL'; r.findings.append("DMARC: FAIL")
    else:
        r.findings.append("DMARC: NONE")

    # Gateway
    gw_checks = [
        ('X-Mimecast-Spam-Score', 'Mimecast', lambda v: int(v) <= 1),
        ('X-IronPort-AV', 'Cisco IronPort', lambda v: True),
        ('X-Barracuda-Spam-Score', 'Barracuda', lambda v: float(v) <= 1),
    ]
    for hdr, name, check in gw_checks:
        val = msg.get(hdr, '')
        if val:
            try:
                if check(val):
                    r.gateway_trust = True; r.gateway_name = name
                    r.details.append(f"Gateway: {name}")
            except Exception:
                pass
    if 'x-forefront-antispam-report' in str(msg.keys()).lower():
        scl = re.search(r'SCL:(\d+)', str(msg.get('x-forefront-antispam-report', '')))
        if scl and int(scl.group(1)) <= 1:
            r.gateway_trust = True
            r.gateway_name = r.gateway_name or "Microsoft 365"
    if msg.get('X-Proofpoint-Spam-Details'):
        r.gateway_trust = True
        r.gateway_name = r.gateway_name or "Proofpoint"

    # Domains
    r.from_full = str(msg.get('From', ''))
    r.rp_full = str(msg.get('Return-Path', ''))
    fm = PAT_DOMAIN.search(r.from_full)
    rm = PAT_DOMAIN.search(r.rp_full)
    if fm:
        r.from_domain = fm.group(1).lower()
        if DNS_OK:
            r.live_verified = True
            r.live_dmarc = _dns_dmarc(r.from_domain)
            r.live_spf = _dns_spf(r.from_domain)
            # FIX(S3): Flag when live DNS contradicts header claims.
            # If header says SPF=PASS but live DNS shows no SPF record,
            # or header says DMARC=PASS but domain has no DMARC, flag it.
            if r.spf == 'PASS' and r.live_spf.get('status') == 'MISSING':
                r.details.append("WARNING: Header claims SPF PASS but no SPF record found in DNS")
            if r.dmarc == 'PASS' and r.live_dmarc.get('status') == 'MISSING':
                r.details.append("WARNING: Header claims DMARC PASS but no DMARC record in DNS")
            # If live DNS shows reject policy but header says pass, that's suspicious
            if (r.live_dmarc.get('policy') == 'reject' and r.dmarc == 'FAIL'):
                r.details.append("Domain has DMARC reject policy — message should be blocked")
    if fm and rm:
        r.rp_domain = rm.group(1).lower()
        rp_root = _root_domain(r.rp_domain)
        from_root = _root_domain(r.from_domain)
        # FIX(BUG5): Compare ROOT domains, not full domain strings.
        # 'user@company.com' vs 'bounces@bounce.company.com' are the same org.
        # The old exact comparison (r.from_domain == r.rp_domain) flagged
        # this as shadow spoofing — a false positive for any org that uses a
        # bounce subdomain (e.g. bounce.company.com, mail.company.com).
        if from_root == rp_root:
            pass  # Same registrable domain — same organization, not a spoof
        elif rp_root in MARKETING_RP_DOMAINS:
            r.details.append(f"Marketing redirect via {r.rp_domain}")
        else:
            r.shadow_spoof = True
            r.findings.append(f"SHADOW SPOOF: {r.from_domain} vs {r.rp_domain}")

    # [FIX-SEC-A]: Spoofable gateway trust headers.
    # X-Mimecast-Spam-Score, X-Barracuda-Spam-Score, X-IronPort-AV, and
    # X-Proofpoint-Spam-Details are plain SMTP headers that ANY sender can inject
    # into their own outbound email before it reaches the analyzer. An attacker
    # adding "X-Mimecast-Spam-Score: 0" gets gateway_trust=True, which adds a
    # 25% TrustFactor dampening to the threat score — enough to push a HIGH-risk
    # email below the QUARANTINE threshold.
    #
    # Fix: only preserve gateway_trust when at least one of SPF or DKIM PASS is
    # also present. Legitimate gateway-processed emails always show a proper auth
    # result; a spoofed gateway header on an email that fails auth is discarded.
    #
    # Note: DKIM alone (without SPF) is acceptable — DKIM-pass proves the message
    # was signed by the claimed domain's key, which an attacker cannot fake even
    # when injecting arbitrary SMTP headers.
    if r.gateway_trust and r.spf != 'PASS' and r.dkim != 'PASS':
        r.gateway_trust = False
        r.details.append(
            f"Gateway header from '{r.gateway_name}' discarded — "
            "no SPF or DKIM PASS to corroborate it (header may be attacker-injected)")
        r.gateway_name = ""

    return r


# ═══════════════════════════════════════════════════════════════════════════════
# HEADER ANOMALY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_headers(msg) -> Tuple[List[str], bool]:
    """Returns (anomalies, reply_to_hijack)."""
    anomalies = []
    reply_hijack = False

    mailer = str(msg.get('X-Mailer', '') or msg.get('User-Agent', '')).lower()
    if mailer and not any(l in mailer for l in LEGIT_MAILERS):
        if re.search(r'[a-z]{8,}v\d+', mailer) or mailer in ['test', 'spam', 'bulk']:
            anomalies.append(f"Unusual X-Mailer: '{mailer[:50]}'")

    from_addr = str(msg.get('From', ''))
    reply_to = str(msg.get('Reply-To', ''))
    if reply_to:
        fd = PAT_DOMAIN.search(from_addr)
        rd = PAT_DOMAIN.search(reply_to)
        if fd and rd and _root_domain(fd.group(1).lower()) != _root_domain(rd.group(1).lower()):
            reply_hijack = True
            anomalies.append(f"REPLY-TO HIJACK: From={fd.group(1)} vs Reply-To={rd.group(1)}")

    tzs = set()
    for h in msg.get_all('Received', []) or []:
        m = PAT_TZ.search(str(h))
        if m:
            tzs.add(m.group(0))
    if len(tzs) > 4:
        anomalies.append(f"Timezone spread: {len(tzs)} zones")

    if not msg.get('Message-ID'):
        anomalies.append("Missing Message-ID")

    date_str = str(msg.get('Date', ''))
    if date_str:
        try:
            md = email.utils.parsedate_to_datetime(date_str)
            now = datetime.now(timezone.utc) if md.tzinfo else datetime.now()
            diff = (md - now).days
            if diff > 3:
                anomalies.append(f"Future date: {diff}d ahead")
            # [FIX-SEC-C]: Past-date replay attack not flagged.
            # An attacker can replay a previously captured legitimate email
            # (or simply back-date a crafted email) to evade time-based
            # detection. Emails with a Date header more than 30 days in the
            # past are anomalous — modern MTAs reject or warn on such emails.
            elif diff < -30:
                anomalies.append(f"Stale date: {abs(diff)}d in the past (possible email replay)")
        except Exception:
            pass

    return anomalies, reply_hijack


# ═══════════════════════════════════════════════════════════════════════════════
# BEC ENGINE (with linguistic density + contradiction detection)
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_bec(visible_text: str, subject: str, from_addr: str, word_count: int) -> BECResult:
    """BEC detection — v13 fundamental overhaul.

    Design principles (replaces the flat probabilistic combiner):

    1. TIER AWARENESS: BEC_KEYWORDS is now tiered (HIGH-SPECIFICITY / CONTEXT-DEPENDENT /
       WEAK). Tier-3 categories (urgency, shipping_scam) are hard-capped at LOW regardless
       of score. Tier-2 categories (authority, invoice_fraud, mfa_bypass, ceo_fraud,
       credential_harvest) cannot reach HIGH+ without a Tier-1 co-signal.

    2. CATEGORY-COUNT GATE: A single category hit — even a Tier-1 one — can only reach
       MEDIUM by itself. HIGH requires ≥2 categories with at least one Tier-1 present.
       CRITICAL requires ≥2 categories with ≥2 Tier-1 present, or Tier-1 + secrecy/authority.

    3. DENSITY CHECK: Short emails (< 40 words) with a single keyword match are capped
       at MEDIUM — real BEC communications develop the narrative. Very long emails
       (> 800 words) with low hit density get a dampening pass.

    4. CONTRADICTION DETECTION: Urgency + calm-language contradictions reduce score by 50%.

    5. SHIPPING_SCAM EXCLUDED: The shipping_scam category is disabled (empty keyword list)
       because it fires on virtually every legitimate transactional email from parcel carriers.

    Note: Auth-based dampening is applied AFTER this function in generate_signals(),
    where SPF/DKIM/DMARC pass state is available. analyze_bec() is pure content analysis.
    """
    r = BECResult()

    # FIX(S11): Search body only for density calc; include subject+from only in combined scan
    combined = normalize_text(f"{subject} {visible_text}").lower()
    body_only = normalize_text(visible_text).lower() if visible_text else ""
    if not combined.strip():
        return r

    body_word_count = len(body_only.split()) if body_only else 0

    # ── Tier classification ────────────────────────────────────────────────────
    TIER1_CATS = {"wire_transfer", "gift_cards", "secrecy", "payment_redirect"}
    TIER2_CATS = {"authority", "invoice_fraud", "mfa_bypass", "ceo_fraud", "credential_harvest"}
    TIER3_CATS = {"urgency", "shipping_scam"}

    total_hits = 0
    survival = 1.0
    for cat, (keywords, prob) in BEC_KEYWORDS.items():
        if not keywords:          # shipping_scam disabled
            continue
        for kw in keywords:
            try:
                matched = bool(re.search(re.escape(kw), combined))
            except Exception:
                matched = kw in combined
            if matched:
                r.categories.append(cat)
                r.findings.append(f"[{cat}] '{kw}'")
                total_hits += 1
                if prob > 0:
                    survival *= (1.0 - prob)
                break
    r.score = 1.0 - survival

    if body_word_count > 0:
        r.density = total_hits / max(body_word_count, 1)

    # ── Contradiction detection ────────────────────────────────────────────────
    for urgent_words, calm_words in BEC_CONTRADICTIONS:
        has_urgent = any(w in combined for w in urgent_words)
        has_calm   = any(w in combined for w in calm_words)
        if has_urgent and has_calm:
            r.contradictions.append("Urgency + calm-language contradiction — inconsistent")
            r.score *= 0.5

    cats = set(r.categories)
    tier1_hits = cats & TIER1_CATS
    tier2_hits = cats & TIER2_CATS
    tier3_hits = cats & TIER3_CATS
    n_tier1 = len(tier1_hits)
    n_cats   = len(cats - TIER3_CATS)   # non-weak category count

    # ── Tier-based ceiling rules ───────────────────────────────────────────────
    if not cats or cats <= TIER3_CATS:
        # Only tier-3 (urgency/shipping_scam) or nothing
        r.score = min(r.score, 0.10)

    elif n_cats == 1 and tier2_hits and not tier1_hits:
        # Single tier-2 category, no tier-1 anchor: invoice/mfa/authority alone
        # fires on a massive fraction of legitimate business email → cap LOW
        r.score = min(r.score, 0.18)

    elif n_cats == 1 and n_tier1 == 1:
        # Single tier-1 hit: genuine BEC signal but needs corroboration for HIGH+
        r.score = min(r.score, 0.42)   # caps at MEDIUM

    # ── Combination boosters (applied AFTER ceilings so they don't circumvent them) ──
    combo_boost = 0.0
    if "wire_transfer" in cats and "urgency" in cats:
        combo_boost += 0.10
    if "payment_redirect" in cats and "urgency" in cats:
        combo_boost += 0.08
    if "authority" in cats and ("wire_transfer" in cats or "gift_cards" in cats):
        combo_boost += 0.12
    if "secrecy" in cats and ("wire_transfer" in cats or "payment_redirect" in cats):
        combo_boost += 0.12
    if "ceo_fraud" in cats and "secrecy" in cats:
        combo_boost += 0.08
    if "mfa_bypass" in cats and "urgency" in cats:
        combo_boost += 0.06
    if combo_boost > 0:
        r.score = r.score + combo_boost * (1.0 - r.score)

    # ── Category-count gate: HIGH/CRITICAL require corroboration ──────────────
    # A single keyword match — no matter how specific — should not auto-escalate
    # to HIGH. Real BEC communications use multiple indicators.
    if r.score >= 0.45 and n_cats < 2:
        r.score = min(r.score, 0.42)  # keep at MEDIUM ceiling
    # FIX(v15-03): original gate also exempted `"authority" in tier2_hits` from
    # the <2 tier1 requirement, allowing a single context-dependent tier-2 phrase
    # ("skip the normal approval") to lift the score to CRITICAL without any
    # high-specificity financial keyword. Authority is tier-2 precisely because it
    # appears in legitimate management email — it must not anchor a CRITICAL verdict.
    # Only tier-1 signals (wire_transfer, gift_cards, secrecy, payment_redirect)
    # qualify as anchors for the CRITICAL floor.
    if r.score >= 0.70 and n_tier1 < 2 and "secrecy" not in tier1_hits:
        r.score = min(r.score, 0.68)  # keep below CRITICAL

    # ── Short-email dampening: <40 body words + 1 keyword = not developed enough ─
    if body_word_count < 40 and total_hits <= 1 and r.score >= 0.25:
        r.score = min(r.score, 0.22)

    r.score = max(0.0, min(r.score, 0.95))

    if r.score >= 0.70:
        r.risk = "CRITICAL"; r.summary = f"HIGH-CONFIDENCE BEC (p={r.score:.0%})"
    elif r.score >= 0.45:
        r.risk = "HIGH";     r.summary = f"LIKELY BEC (p={r.score:.0%})"
    elif r.score >= 0.25:
        r.risk = "MEDIUM";   r.summary = f"BEC indicators (p={r.score:.0%})"
    elif r.score > 0:
        r.risk = "LOW";      r.summary = f"Minor BEC signal (p={r.score:.0%})"
    else:
        r.summary = "No BEC patterns"
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# DISPLAY NAME SPOOFING
# ═══════════════════════════════════════════════════════════════════════════════

def check_display_spoof(msg, org_domain=""):
    """FIX(S1): Separate brand impersonation from job-title false positives.
    FIX(S6): Decode MIME-encoded display names (=?UTF-8?B?...?=) before checking.
    """
    from_h = str(msg.get('From', '')).strip()

    # FIX(S6): Decode MIME-encoded display names that bypass plain-text matching.
    # An attacker using =?UTF-8?B?TWljcm9zb2Z0?= (base64 of 'Microsoft') would
    # bypass the old regex. email.policy.default usually decodes these, but we
    # handle it explicitly for robustness.
    try:
        decoded_from = str(email.header.make_header(email.header.decode_header(from_h)))
        from_h = decoded_from
    except Exception:
        pass

    m = re.match(r'^"?([^"<@\n]{2,60}?)"?\s*<([^>]+)>', from_h)
    if not m:
        return None, "", ""
    dn = m.group(1).strip()
    addr = m.group(2).strip().lower()
    dm = PAT_DOMAIN.search(addr)
    if not dm:
        return None, dn, ""
    sd = dm.group(1).lower()
    if org_domain and sd.endswith(org_domain):
        return None, dn, sd

    dnl = dn.lower()
    if '@' in dnl and '.' in dnl:
        return "HEADER INJECTION: Display name contains email", dn, sd

    # Brand impersonation: 'microsoft', 'paypal', etc. — always flag if brand
    # name is in display name but domain doesn't match the brand
    # FIX(BUG3): Compare brand against ROOT domain, not the full subdomain string.
    # Without this, "Microsoft Security" <noreply@microsoft-cdn.phishing.ru>
    # is NOT flagged because 'microsoft' is present in the full domain string.
    # _root_domain() strips the subdomain so only the registered domain is compared.
    sd_root_for_brand = _root_domain(sd)
    for brand in DISPLAY_NAME_BRANDS:
        if brand in dnl:
            if brand.replace(' ', '') not in sd_root_for_brand:
                return f"BRAND SPOOF: Claims '{dn}' from '{sd}'", dn, sd

    # FIX(S1): Job title spoofing — only flag when combined with freemail or
    # suspicious TLD. "CEO John Smith <john@acme-corp.com>" is legitimate.
    # "CEO <ceo.verify@gmail.com>" is suspicious.
    sd_root = _root_domain(sd)
    is_freemail = sd_root in FREEMAIL_DOMAINS
    is_sus_tld = any(sd.endswith(t) for t in SUSPICIOUS_TLDS)
    if is_freemail or is_sus_tld:
        for title in DISPLAY_NAME_TITLES:
            if title in dnl:
                reason = "freemail" if is_freemail else "suspicious TLD"
                return (f"TITLE SPOOF: Claims '{dn}' from {reason} domain '{sd}'",
                        dn, sd)

    return None, dn, sd


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACHMENT ANALYSIS (trust MacroRaptor, reduce redundancy)
# ═══════════════════════════════════════════════════════════════════════════════

def _yara_scan(data, fname=""):
    """Scan decoded binary attachment data with the full ruleset."""
    rules = _get_yara()
    if not rules or not data:
        return []
    if isinstance(data, str):
        data = data.encode('utf-8', 'ignore')
    data = data[:10 * 1024 * 1024]
    matches = []
    try:
        for hit in rules.match(data=data)[:100]:
            ms = []
            try:
                for sm in hit.strings:
                    try:
                        for inst in sm.instances:
                            try:
                                ms.append(inst.matched_data.decode('utf-8', 'replace')[:60])
                            except Exception:
                                pass
                    except AttributeError:
                        if isinstance(sm, tuple) and len(sm) >= 3:
                            try:
                                ms.append(sm[2].decode('utf-8', 'replace')[:60])
                            except Exception:
                                pass
            except Exception:
                pass
            sev  = _cofense_severity(hit.rule, hit.meta)
            desc = (hit.meta.get('description') or
                    hit.meta.get('rule_context') or
                    hit.rule.replace('_', ' '))
            matches.append({
                'rule':       hit.rule,
                'severity':   sev,
                'desc':       desc,
                'cat':        hit.meta.get('category', ''),
                'tlp':        hit.meta.get('tlp', ''),
                'enrichment': _is_enrichment_rule(hit.rule),
                'strings':    list(set(ms))[:5],
            })
    except Exception as e:
        log.error(f"YARA scan: {e}")
    return matches


def _yara_scan_email(msg_bytes: bytes) -> list:
    """
    Scan raw email bytes with Cofense intel rules.
    Excludes _ATTACHMENT_ONLY_RULES to prevent false positives from
    base64-encoded attachment content triggering Archive_Sig / EXE_Magic.
    """
    rules = _get_yara()
    if not rules or not msg_bytes:
        return []
    scan_data = msg_bytes[:5 * 1024 * 1024]
    matches = []
    try:
        for hit in rules.match(data=scan_data)[:200]:
            if hit.rule in _ATTACHMENT_ONLY_RULES:
                continue
            ms = []
            try:
                for sm in hit.strings:
                    try:
                        for inst in sm.instances:
                            try:
                                ms.append(inst.matched_data.decode('utf-8', 'replace')[:80])
                            except Exception:
                                pass
                    except AttributeError:
                        if isinstance(sm, tuple) and len(sm) >= 3:
                            try:
                                ms.append(sm[2].decode('utf-8', 'replace')[:80])
                            except Exception:
                                pass
            except Exception:
                pass
            sev  = _cofense_severity(hit.rule, hit.meta)
            desc = (hit.meta.get('description') or
                    hit.meta.get('rule_context') or
                    hit.rule.replace('_', ' '))
            matches.append({
                'rule':       hit.rule,
                'severity':   sev,
                'desc':       desc,
                'cat':        hit.meta.get('category', 'email_intel'),
                'tlp':        hit.meta.get('tlp', 'TLP:Amber'),
                'enrichment': _is_enrichment_rule(hit.rule),
                'strings':    list(set(ms))[:5],
            })
    except Exception as e:
        log.debug(f"YARA email scan: {e}")
    return matches


# ─────────────────────────────────────────────────────────────────────────────
# PDF SECURITY ENGINE v13
# ─────────────────────────────────────────────────────────────────────────────
# Architecture:
#   peepdf was Python 2 only and is unmaintained. The replacement uses pikepdf
#   (Python 3, actively maintained, wraps qpdf) for security-focused PDF analysis
#   and keeps pdfminer for text extraction — the two tools serve different roles:
#
#   pikepdf  → parse object graph, decompress streams, count dangerous tags,
#              detect JS/Launch/EmbeddedFile/XFA, extract URIs from stream data
#   pdfminer → extract readable text from page content streams (text analysis)
#
#   Fallback: if pikepdf is unavailable, raw-byte regex scanning covers the
#   most critical tag detection (as it did before). This ensures pdfminer
#   degradation has no security regression.
# ─────────────────────────────────────────────────────────────────────────────

# Tags that are always dangerous regardless of context
_PDF_CRITICAL_TAGS = {
    "/JavaScript", "/JS",         # JavaScript execution
    "/Launch",                    # OS command execution
    "/EmbeddedFile",              # Embedded file (dropper vehicle)
    "/RichMedia",                 # Flash / rich media content
}

# Tags that are suspicious in combination with JS or Launch
_PDF_CONTEXT_TAGS = {
    "/OpenAction",   # Auto-execute on open — dangerous only with JS/Launch
    "/AA",           # Additional-Actions — suspicious only with JS
    "/XFA",          # XML Forms Architecture — used in phishing PDFs
    "/AcroForm",     # Fillable form — common, informational only
    "/JBIG2Decode",  # JBIG2 decoder — exploited in historical CVEs
    "/CCITTFaxDecode",  # Fax decoder — used in some exploits
}

@dataclass
class PDFSecurityResult:
    """Security analysis result from pikepdf engine."""
    dangerous_tags: List[str] = field(default_factory=list)
    context_tags: List[str] = field(default_factory=list)
    js_snippets: List[str] = field(default_factory=list)
    embedded_files: List[str] = field(default_factory=list)
    uris: List[str] = field(default_factory=list)
    is_encrypted: bool = False
    is_linearized: bool = False
    stream_count: int = 0
    object_count: int = 0
    has_xfa: bool = False
    risk_indicators: List[str] = field(default_factory=list)


def _pikepdf_security_scan(data: bytes) -> Optional[PDFSecurityResult]:
    """Security-focused PDF analysis using pikepdf (peepdf replacement).

    Performs:
    1. Object-graph walk to find dangerous PDF tags
    2. Stream decompression and content inspection for JS/shell code
    3. URI extraction from all action dictionaries and stream text
    4. Embedded file detection and filename extraction
    5. XFA form detection (commonly used in sophisticated phishing)
    6. Encryption detection (suspicious when combined with dangerous tags)

    Returns None if pikepdf is unavailable or PDF is unparseable.
    FIX(C11) preserved: wrapped in daemon thread with PDFMINER_TIMEOUT limit.
    FIX(PERF): Results are cached by content hash — each unique PDF is scanned
               exactly once even when called from both _pdf_uris() and
               analyze_attachment().
    """
    if not PIKEPDF_OK:
        return None
    if len(data) > 15 * 1024 * 1024:
        log.debug("pikepdf: skipping oversized PDF")
        return None

    # ── Cache lookup ──────────────────────────────────────────────────────────
    import hashlib
    cache_key = hashlib.md5(data, usedforsecurity=False).hexdigest()
    with _PIKEPDF_CACHE_LOCK:
        if cache_key in _PIKEPDF_CACHE:
            log.debug("pikepdf: cache hit — skipping redundant scan")
            return _PIKEPDF_CACHE[cache_key]

    result_holder = [None]
    exc_holder    = [None]

    def _scan():
        try:
            res = PDFSecurityResult()
            pdf = pikepdf.open(io.BytesIO(data))

            res.is_encrypted  = pdf.is_encrypted
            res.is_linearized = pdf.is_linearized
            res.object_count  = len(pdf.objects)

            # ── Walk the entire object graph ──────────────────────────────────
            tag_set = set()
            js_code = []
            uris    = set()
            emb_files = []

            def _walk_obj(obj, depth=0):
                """Recursively walk PDF objects collecting security indicators.

                IMPORTANT: In PDF action dictionaries, dangerous type identifiers
                appear as VALUES of the /S (subtype) key, not as dict keys.
                Example: << /Type /Action /S /JavaScript /JS (...) >>
                         ↑ /JavaScript is a value, not a key.
                We must collect both keys AND Name-type values into tag_set.
                """
                if depth > 12:   # cycle guard
                    return
                try:
                    if isinstance(obj, pikepdf.Dictionary):
                        for key in obj.keys():
                            key_str = str(key)
                            tag_set.add(key_str)

                            # Collect Name values (catches /S /JavaScript, /S /Launch, etc.)
                            try:
                                val = obj[key]
                                if isinstance(val, pikepdf.objects.Object):
                                    val_str = str(val)
                                    # Name objects that are security-relevant
                                    if val_str in (
                                        "/JavaScript", "/JS", "/Launch",
                                        "/EmbeddedFile", "/RichMedia", "/XFA",
                                        "/SubmitForm", "/ImportData",
                                    ):
                                        tag_set.add(val_str)
                            except Exception:
                                pass

                            # Extract URI from action dictionaries
                            if key_str == "/URI":
                                try:
                                    uri_val = str(obj[key])
                                    if uri_val.startswith(("http", "ftp", "//")):
                                        uris.add(uri_val)
                                except Exception:
                                    pass

                            # Extract embedded file names
                            elif key_str == "/F" and "/EmbeddedFile" in tag_set:
                                try:
                                    emb_files.append(str(obj[key]))
                                except Exception:
                                    pass

                            # Extract inline JS strings (short JS in /JS key)
                            elif key_str == "/JS":
                                try:
                                    js_val = str(obj[key])
                                    if len(js_val) > 5:
                                        js_code.append(f"inline /JS → {js_val[:100]}")
                                        tag_set.add("/JavaScript")  # canonical tag
                                except Exception:
                                    pass

                            # Recurse into sub-objects
                            try:
                                _walk_obj(obj[key], depth + 1)
                            except Exception:
                                pass

                        # Decompress and inspect streams for JS code
                        if hasattr(obj, "get_stream_buffer"):
                            try:
                                stream_data = bytes(obj.get_stream_buffer())[:4096]
                                stream_text = stream_data.decode("latin-1", "ignore")
                                js_indicators = [
                                    "eval(", "unescape(", "String.fromCharCode(",
                                    "document.write(", "app.alert(", "this.submitForm(",
                                    "app.launchURL(", "app.openDoc(",
                                ]
                                for ind in js_indicators:
                                    if ind.lower() in stream_text.lower():
                                        snippet = stream_text[:120].replace("\n", " ")
                                        js_code.append(f"{ind} → {snippet[:80]}")
                                        break
                                for url in PAT_URL.findall(stream_text):
                                    if len(url) >= 10:
                                        uris.add(url)
                                res.stream_count += 1
                            except Exception:
                                pass

                    elif isinstance(obj, (pikepdf.Array, list)):
                        for item in obj:
                            try:
                                _walk_obj(item, depth + 1)
                            except Exception:
                                pass
                except Exception:
                    pass

            # Iterate over all PDF objects (pikepdf._ObjectList supports direct iteration)
            for obj in pdf.objects:
                try:
                    _walk_obj(obj)
                except Exception:
                    pass

            # Walk document catalog explicitly (root-level actions, AcroForm, etc.)
            try:
                _walk_obj(pdf.Root)
            except Exception:
                pass

            # ── Classify collected tags ───────────────────────────────────────
            for tag in tag_set:
                if tag in _PDF_CRITICAL_TAGS:
                    res.dangerous_tags.append(tag)
                elif tag in _PDF_CONTEXT_TAGS:
                    res.context_tags.append(tag)

            res.js_snippets   = js_code[:5]
            res.embedded_files = emb_files[:10]
            res.has_xfa       = "/XFA" in tag_set
            res.uris          = [u for u in list(uris)[:100]
                                 if not any(ns in u.lower() for ns in PDF_META_NS)
                                 and len(u) >= 8]

            # ── Risk narrative ────────────────────────────────────────────────
            if res.dangerous_tags:
                res.risk_indicators.append(
                    f"Dangerous PDF tags: {', '.join(res.dangerous_tags)}")
            if res.js_snippets:
                res.risk_indicators.append(
                    f"JavaScript found in {len(res.js_snippets)} stream(s)")
            if res.embedded_files:
                res.risk_indicators.append(
                    f"Embedded file(s): {', '.join(res.embedded_files)}")
            if res.has_xfa:
                res.risk_indicators.append(
                    "XFA form detected (commonly used in phishing PDFs)")
            if res.is_encrypted and res.dangerous_tags:
                res.risk_indicators.append(
                    "Encrypted PDF with dangerous tags (content obfuscation pattern)")
            if "/OpenAction" in tag_set and ("/JavaScript" in tag_set or "/JS" in tag_set):
                res.risk_indicators.append(
                    "/OpenAction + JavaScript = auto-execute on PDF open")

            result_holder[0] = res
            pdf.close()
        except Exception as e:
            exc_holder[0] = e

    t = threading.Thread(target=_scan, daemon=True)
    t.start()
    t.join(timeout=PDFMINER_TIMEOUT)
    if t.is_alive():
        log.warning("pikepdf security scan timed out")
        with _PIKEPDF_CACHE_LOCK:
            _PIKEPDF_CACHE[cache_key] = None   # cache the failure — don't retry
        return None
    if exc_holder[0]:
        log.debug(f"pikepdf scan failed: {exc_holder[0]}")
        with _PIKEPDF_CACHE_LOCK:
            _PIKEPDF_CACHE[cache_key] = None   # cache the failure — don't retry
        return None
    # Cache and return the successful result
    with _PIKEPDF_CACHE_LOCK:
        _PIKEPDF_CACHE[cache_key] = result_holder[0]
    return result_holder[0]


def _pdfminer_extract_safe(data: bytes) -> Optional[str]:
    """FIX(C11): pdfminer text extraction with timeout.
    pdfminer.extract_text can hang forever on malformed PDFs with circular
    stream references. Wrapped in a daemon thread with PDFMINER_TIMEOUT limit.

    NOTE: pdfminer is a TEXT EXTRACTION tool — it is not used for security
    analysis. Security analysis is handled by _pikepdf_security_scan() above.
    """
    if not PDFMINER_OK:
        return None
    if len(data) > 10 * 1024 * 1024:
        return None
    result = [None]
    exc    = [None]

    def _extract():
        try:
            result[0] = pdfminer_extract(io.BytesIO(data))
        except Exception as e:
            exc[0] = e

    t = threading.Thread(target=_extract, daemon=True)
    t.start()
    t.join(timeout=PDFMINER_TIMEOUT)
    if t.is_alive():
        log.warning("pdfminer timed out -- skipping PDF text extraction")
        return None
    if exc[0]:
        log.debug(f"pdfminer failed: {exc[0]}")
        return None
    return result[0]


def _pdf_uris(data):
    """Extract URIs from PDF.
    Priority order:
      1. pikepdf security scan (decompresses streams, walks object graph)
      2. pdfminer text extraction (extracts URLs from page text)
      3. Raw-byte regex fallback (no dependency, always available)
    """
    uris = set()

    # Tier 1: pikepdf object-graph URI extraction
    pdf_sec = _pikepdf_security_scan(data)
    if pdf_sec and pdf_sec.uris:
        for u in pdf_sec.uris:
            uris.add(u)

    # Tier 2: pdfminer text extraction — skipped when pikepdf already found
    # a rich set of URIs (≥10). pdfminer's value is as a fallback for PDFs
    # whose streams pikepdf couldn't parse; if pikepdf already found plenty
    # of links, running pdfminer just wastes its 5s timeout budget.
    if not (pdf_sec and len(pdf_sec.uris) >= 10):
        text = _pdfminer_extract_safe(data)
        if text:
            for url in PAT_URL.findall(text):
                uris.add(url)

    # Tier 3: raw-byte regex fallback (handles non-compressed streams)
    scan_range = data[:5 * 1024 * 1024]
    for m in PAT_PDF_URI.finditer(scan_range):
        try:
            raw = (m.group(1).decode('latin-1', 'ignore').strip()
                   .replace('\x00', '').replace('\r', '').replace('\n', ''))
            if raw.startswith(('http', 'ftp')):
                uris.add(raw)
        except Exception:
            pass
    for m in PAT_PDF_URL.finditer(scan_range):
        try:
            raw = m.group(0).decode('latin-1', 'ignore').strip()
            raw = re.sub(r'[/>\)\]]+$', '', raw)
            if len(raw) >= 10 and '.' in raw:
                uris.add(raw)
        except Exception:
            pass

    return [u for u in list(uris)[:100]
            if not any(ns in u.lower() for ns in PDF_META_NS) and len(u) >= 8]


def _office_uris(data):
    """FIX(C12): Extract URIs from OOXML .rels files with size limit.
    Original had no limit on extracted .rels file size -- a ZIP bomb could
    decompress a single .rels entry to gigabytes."""
    uris = set()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                if n.endswith('.rels'):
                    info = z.getinfo(n)
                    if info.file_size > MAX_ZIP_EXTRACT:
                        log.warning(f"Skipping oversized .rels: {n} ({info.file_size} bytes)")
                        continue
                    content = z.read(n).decode('utf-8', 'ignore')
                    for link in re.findall(r'Target=["\'](https?:[^"\']+)["\']', content, re.I):
                        if 'schemas.openxmlformats' not in link and 'schemas.microsoft' not in link:
                            uris.add(html.unescape(link))
    except Exception:
        pass
    return list(uris)[:100]


def analyze_attachment(data, filename) -> MacroResult:
    """Analyze attachment. Trusts MacroRaptor verdict instead of redundant keyword grep."""
    r = MacroResult(filename=filename)
    if not data:
        r.verdict = "Empty file"
        return r

    r.md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    r.sha256 = hashlib.sha256(data).hexdigest()

    # MalwareBazaar
    found, family, tags = check_malwarebazaar(data, filename)
    if found:
        r.mb_found = True; r.mb_family = family; r.risk_score = 100
        r.details.append(f"MALWARE BAZAAR: {family}")

    # YARA
    yara_hits = _yara_scan(data, filename)
    # FIX(C23): limit [Content_Types].xml search to first 4KB, not entire file
    is_valid_office = (data[:4] == b'PK\x03\x04' and
                       b'[Content_Types].xml' in data[:CONTENT_TYPES_SEARCH_LIMIT])
    is_valid_pdf    = data[:5] == b'%PDF-'
    is_ole          = data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
    is_valid_rtf    = data[:5] == b'{\\rtf'
    fl = filename.lower()
    is_archive_ext  = fl.endswith(('.zip', '.rar', '.7z', '.gz', '.tar', '.tgz', '.bz2'))

    # ── Structural false-positive suppression ──────────────────────────────────
    # Rules in each set match the FORMAT HEADER of a legitimate file, not malicious
    # content. They always fire on every valid file of that type, producing noise.
    # Each guard uses magic bytes, NOT file extension, so:
    #   - malware.exe renamed to invoice.pdf → is_valid_pdf=False → PM_pdf_document fires
    #   - malware.zip renamed to report.docx → is_valid_office=False → Archive_Sig escalates
    #
    # Rules that detect DANGEROUS CONTENT INSIDE these formats (PM_Zip_With_Exe,
    # PM_docx_macro, CY_PDF_with_SCR, etc.) are NOT in these sets — they always fire.
    _OOXML_STRUCTURAL_FP = frozenset({
        'PM_zip_file',    # ZIP magic bytes — every OOXML file starts with PK\x03\x04
        'PM_xlsx_file',   # xl/_rels/ path — present in every valid Excel OOXML
        'PM_docx_file',   # word/_rels/ path — present in every valid Word OOXML
        'PM_pptx_file',   # ppt/slides/_rels — present in every valid PowerPoint OOXML
    })
    _OLE2_STRUCTURAL_FP = frozenset({
        'PM_office_magic_bytes',  # D0CF11E0 magic — every old .doc/.xls/.ppt
        'PM_word_document',       # OLE2 + WordDocument stream — every valid .doc
        'PM_excel_document',      # OLE2 + Workbook + "Microsoft Excel" — every .xls
        'PM_powerpoint_document', # OLE2 + "PowerPoint Document" — every .ppt
    })
    _PDF_STRUCTURAL_FP = frozenset({
        'PM_pdf_document',  # %PDF- at 0 — every PDF
        'CY_PDF_With_Links', # %PDF- + URI annotation — every PDF with any hyperlink
    })
    _RTF_STRUCTURAL_FP = frozenset({
        'PM_rtf_file',  # {\rtf at 0 — every valid RTF file
    })

    for m in yara_hits:
        if m['rule'] == 'Archive_Sig':
            if is_valid_office:
                continue
            elif is_archive_ext:
                continue
            else:
                m['severity'] = 'HIGH'
                m['desc'] = (f"DISGUISED ARCHIVE: '{filename}' contains archive "
                             f"structure but claims to be a non-archive file")
                r.yara_matches.append(m)
                r.risk_score = max(r.risk_score, 50)
                r.details.append(f"CONTENT MISMATCH: '{filename}' is structurally an archive")
                continue
        if m['rule'] in _OOXML_STRUCTURAL_FP and is_valid_office:
            continue
        if m['rule'] in _OLE2_STRUCTURAL_FP and is_ole:
            continue
        if m['rule'] in _PDF_STRUCTURAL_FP and is_valid_pdf:
            continue
        if m['rule'] in _RTF_STRUCTURAL_FP and is_valid_rtf:
            continue
        r.yara_matches.append(m)

    # Only count non-enrichment hits toward risk score
    scoring_hits = [m for m in r.yara_matches if not m.get('enrichment')]
    if scoring_hits:
        sev_score = {'CRITICAL': 80, 'HIGH': 50, 'MEDIUM': 25}
        r.risk_score = max(r.risk_score,
                           min(100, sum(sev_score.get(m['severity'], 10) for m in scoring_hits)))

    # PDF
    if data.startswith(b'%PDF'):
        r.file_type = "PDF"

        # ── pikepdf security scan (primary — replaces peepdf) ─────────────────
        # _pikepdf_security_scan() walks the full PDF object graph, decompresses
        # streams, and detects dangerous tags, embedded JS, XFA forms, and URIs.
        # This performs the same security analysis role that peepdf provided.
        pdf_sec = _pikepdf_security_scan(data)
        if pdf_sec:
            for indicator in pdf_sec.risk_indicators:
                r.details.append(f"⚠️ [pikepdf] {indicator}")

            if pdf_sec.dangerous_tags:
                r.has_macros = True
                # Score based on which dangerous tags fired
                if "/Launch" in pdf_sec.dangerous_tags:
                    r.risk_score = max(r.risk_score, 88)
                if "/JavaScript" in pdf_sec.dangerous_tags or "/JS" in pdf_sec.dangerous_tags:
                    r.risk_score = max(r.risk_score, 72)
                if "/EmbeddedFile" in pdf_sec.dangerous_tags:
                    r.risk_score = max(r.risk_score, 65)
                if "/RichMedia" in pdf_sec.dangerous_tags:
                    r.risk_score = max(r.risk_score, 55)

            if pdf_sec.js_snippets:
                r.has_macros = True
                r.risk_score = max(r.risk_score, 70)
                for snip in pdf_sec.js_snippets[:2]:
                    r.details.append(f"  ↳ JS: {snip[:120]}")

            if pdf_sec.embedded_files:
                r.risk_score = max(r.risk_score, 60)
                for ef in pdf_sec.embedded_files[:3]:
                    r.details.append(f"  ↳ Embedded file: {ef}")

            if pdf_sec.has_xfa:
                r.risk_score = max(r.risk_score, 50)
                r.details.append("PDF XFA form detected (used in phishing)")

            # Context-tag handling: only suspicious in combination
            if "/OpenAction" in pdf_sec.context_tags:
                if pdf_sec.dangerous_tags:
                    r.details.append("PDF tag: /OpenAction + dangerous tag (auto-exec risk)")
                else:
                    r.details.append("PDF tag: /OpenAction (common in benign PDFs — informational)")

            if "/AA" in pdf_sec.context_tags:
                if "/JavaScript" in pdf_sec.dangerous_tags or "/JS" in pdf_sec.dangerous_tags:
                    r.has_macros = True
                    r.risk_score = max(r.risk_score, 52)
                    r.details.append("PDF tag: /AA + JavaScript (field-level script execution)")
                else:
                    r.details.append("PDF tag: /AA (additional-actions — informational)")

            if "/AcroForm" in pdf_sec.context_tags:
                r.details.append("PDF tag: /AcroForm (fillable form fields — informational)")

            if pdf_sec.is_encrypted and pdf_sec.dangerous_tags:
                r.risk_score = max(r.risk_score, max(r.risk_score, 60) + 10)
                r.details.append("PDF encrypted + dangerous tags (content obfuscation)")

          # Format the output to be clear and analyst-friendly
            if pdf_sec.stream_count > 0:
                stream_info = f" | {pdf_sec.stream_count} embedded stream(s) decompressed and inspected"
            else:
                stream_info = " | No hidden/compressed streams present"
                
            r.details.append(f"pikepdf Engine: {pdf_sec.object_count} objects verified{stream_info}")


        else:
            # pikepdf unavailable — fall back to raw-byte tag detection
            # (preserves the pre-v13 behavior as a reliable degraded mode)
            has_launch     = b'/Launch'     in data
            has_javascript = b'/JavaScript' in data or b'/JS' in data
            has_aa         = b'/AA'         in data
            has_acroform   = b'/AcroForm'   in data
            has_openaction = b'/OpenAction' in data

            
            
            if has_launch:
                r.has_macros = True
                r.risk_score = max(r.risk_score, 85)
                r.details.append("PDF tag: /Launch (code execution — raw fallback)")

            if has_javascript:
                r.has_macros = True
                r.risk_score = max(r.risk_score, 70)
                r.details.append("PDF tag: /JavaScript (raw fallback)")

            if has_openaction and not has_javascript and not has_launch:
                r.details.append("PDF tag: /OpenAction (common in benign PDFs — raw fallback)")

            if has_acroform:
                r.details.append("PDF tag: /AcroForm (fillable form — raw fallback)")

            if has_aa and has_javascript:
                r.has_macros = True
                r.risk_score = max(r.risk_score, 50)
                r.details.append("PDF tag: /AA + JS (raw fallback)")
            elif has_aa:
                r.details.append("PDF tag: /AA (raw fallback)")

            # --- NEW FIX: ALWAYS provide an analysis receipt ---
            if PIKEPDF_OK:
                r.details.append("PDF Structure: Malformed/non-standard PDF (scanned via raw-byte fallback)")
            else:
                r.details.append("PDF Structure: Scanned via raw-byte fallback engine")
                
            if not (has_launch or has_javascript or has_openaction or has_acroform or has_aa):
                r.details.append("Result: Verified no embedded scripts, forms, or auto-execution tags")
            # ---------------------------------------------------
        # ── URI extraction (uses pikepdf → pdfminer → regex cascade) ─────────
        r.pdf_uris = _pdf_uris(data)
        if r.pdf_uris:
            r.details.append(f"{len(r.pdf_uris)} URI(s) extracted")

        # Verdict: only SUSPICIOUS if genuinely dangerous content detected.
        r.verdict = "SUSPICIOUS" if (r.yara_matches or r.has_macros) else "SAFE"
        return r

    # Office (OLE or valid OOXML only -- NOT plain ZIP files)
    # FIX(AUDIT-02): removed redundant 4-byte is_ole reassignment.
    # is_ole was already computed above (line 4728) with the full 8-byte
    # OLE2 magic check. Reusing it avoids both the redundant comparison
    # and a subtle correctness issue (4-byte check is less strict).
    if is_ole or is_valid_office:
        r.file_type = "Office"
        r.pdf_uris.extend(_office_uris(data))
        if r.pdf_uris:
            r.details.append(f"{len(r.pdf_uris)} link(s)")
            
    elif data.startswith(b'PK\x03\x04') and not is_valid_office:
        r.file_type = "Archive"
        r.pdf_uris.extend(_office_uris(data))
        if r.pdf_uris:
            r.details.append(f"{len(r.pdf_uris)} link(s) inside archive")
            
        # --- NEW FIX: ALWAYS provide an analysis receipt for Archives ---
        r.details.append("Archive Structure: Extracted and inspected container contents")
        if not r.yara_matches:
            r.details.append("Result: Verified no malicious executable payloads directly embedded")
        # ----------------------------------------------------------------
            
        r.verdict = ("Archive file" if not r.yara_matches
                     else f"SUSPICIOUS -- {r.yara_matches[0]['rule']}")
        return r
    
    if r.file_type == "Office":
        if not OLETOOLS_OK:
            r.verdict = "Macro engine offline"
            return r

        vba = None
        try:
            with _tmp_file(data, '.doc') as tmp:
                # --- ENHANCED OLEID ANALYSIS ---
                try:
                    oid = OleID(tmp)
                    indicators = oid.check()
                    for ind in indicators:
                        # 1. External Relationships
                        if ind.id == 'ole_external_relationships' and ind.risk in ['HIGH', 'MEDIUM']:
                            r.risk_score += 15
                            r.details.append(f"⚠️ {ind.name}: Detected (Risk: {ind.risk})")
                            
                            # Deep Dive: Extract targets
                            try:
                                with zipfile.ZipFile(tmp, 'r') as z:
                                    for name in z.namelist():
                                        if name.endswith('.rels'):
                                            content = z.read(name).decode('utf-8', errors='ignore')
                                            links = re.findall(r'Target="([^"]+)"[^>]*Mode="External"', content)
                                            for link in links:
                                                link = html.unescape(link)
                                                if not any(x in link for x in ['schemas.openxmlformats', 'schemas.microsoft']):
                                                    r.details.append(f"   ↳ 🔗 Linked Target: {defang(link)}")
                                                    if 'http' in link or 'ftp' in link:
                                                        if r.pdf_uris is None: r.pdf_uris = []
                                                        r.pdf_uris.append(link)
                            except Exception:
                                pass

                        # 2. VBA Macros
                        elif ind.id == 'vba_macros' and ind.risk == 'HIGH':
                            r.details.append(f"⚠️ {ind.name}: Detected")
                        
                        # 3. Object Linking
                        elif ind.id == 'ole_streams' and ind.risk == 'HIGH':
                             r.details.append(f"⚠️ OLE Object Embedding Detected")

                except Exception as e:
                    log.warning(f"OleID error: {e}")

                # --- VBA PARSER ---
                vba = VBA_Parser(tmp)
                if vba.detect_vba_macros():
                    r.has_macros = True
                    all_code = "\n".join(code for _, _, _, code in vba.extract_macros() if code)

                    try:
                        mr = _MacroRaptor(all_code)
                        mr.scan()
                        if mr.suspicious:
                            r.risk_score += 60
                            r.verdict = "SUSPICIOUS (MacroRaptor)"
                            r.details.append("MacroRaptor: SUSPICIOUS -- auto-exec + risky ops")
                            if mr.flags:
                                for flag_type, flag_match in [('A', 'auto-exec'), ('W', 'write'), ('X', 'execute')]:
                                    if flag_type in (mr.flags or ''):
                                        r.details.append(f"  MacroRaptor flag: {flag_match}")
                        else:
                            r.details.append("MacroRaptor: CLEAN")
                            # Only say SAFE if risk_score hasn't been elevated by YARA
                            if r.risk_score >= 50:
                                r.verdict = "SUSPICIOUS -- YARA rules matched"
                            elif r.risk_score > 0:
                                r.verdict = "REVIEW -- low-risk findings"
                            else:
                                r.verdict = "SAFE -- benign macros"
                    except Exception:
                        r.verdict = "HAS MACROS (raptor failed)"

                    ent = shannon_entropy(all_code)
                    if ent > 5.5:
                        r.risk_score += 15
                        r.details.append(f"High macro entropy ({ent:.1f})")

                    if YARA_OK:
                        for m in _yara_scan(all_code.encode('utf-8', 'ignore'), f"{filename}_vba"):
                            if m not in r.yara_matches:
                                r.yara_matches.append(m)
                else:
                    r.verdict = "SAFE -- no macros"
                    # --- NEW FIX: ALWAYS provide an analysis receipt for Office files ---
                    r.details.append("Office Structure: Verified via OleID & OleVBA engine")
                    r.details.append("Result: Confirmed no embedded macros or malicious external relationships")
                    # --------------------------------------------------------------------

        except Exception as e:
            r.verdict = f"Error: {str(e)[:40]}"
        finally:
            # THIS WAS MISSING IN YOUR PREVIOUS PASTE
            if vba is not None:
                try:
                    vba.close()
                except Exception:
                    pass
        return r

    if r.yara_matches:
        r.file_type = "Binary"
        r.verdict = f"SUSPICIOUS -- YARA: {r.yara_matches[0]['rule']}"
        return r
        
    # --- NEW FIX: ALWAYS provide a receipt for other generic files ---
    if not r.details:
        r.details.append("File Content: Scanned via heuristic and signature engines")
        r.details.append("Result: No structural threats or executable payloads detected")
    # -----------------------------------------------------------------
        
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# OBSERVABLE EXTRACTION (BeautifulSoup + heuristics)
# ═══════════════════════════════════════════════════════════════════════════════

def _url_host(url: str) -> str:
    """Extract the hostname from a URL WITHOUT the port number.

    BUG FIXED (v13): urlparse().netloc includes the port (e.g. 'domain.com:443').
    Passing netloc directly to _root_domain(), is_tracking_domain(), or domain_intel()
    causes them all to silently fail because ':443' corrupts the TLD-split logic:
      - _root_domain('smex-ctp.trendmicro.com:443') → 'trendmicro.com:443'
      - 'trendmicro.com:443' not in TRACKING_ALLOWLIST → FP link-text mismatch
      - domain_intel('smex-ctp.trendmicro.com:443') → trusted=False → VT shows UNKNOWN

    urlparse().hostname always returns the bare hostname, lowercase, without port.
    This function is the single authoritative place to get a host from a URL.
    """
    try:
        h = urlparse(url).hostname
        return _safe_strip_www(h) if h else ''
    except Exception:
        return ''


# Default ports that are implicit and should be stripped for normalization
_DEFAULT_PORTS = {('https', 443), ('http', 80)}


def _normalize_url(url: str) -> str:
    """Normalize URL for deduplication: strip trailing slash, lowercase host,
    strip default ports (https:443 / http:80) so the same URL with and without
    explicit port deduplicates correctly.

    BEFORE FIX: https://domain.com:443/path and https://domain.com/path were
    treated as different URLs — causing the same observable to appear twice in
    the VT panel, once as UNKNOWN and once as CLEAN.
    """
    try:
        p = urlparse(url)
        host = p.hostname or p.netloc  # hostname strips port
        # Strip implicit default ports from the reconstructed netloc
        if p.port and (p.scheme, p.port) in _DEFAULT_PORTS:
            netloc_norm = host.lower()
        else:
            netloc_norm = p.netloc.lower()  # keep non-default ports (e.g. :8080)
        path = p.path.rstrip('/')
        query = p.query
        norm = f"{p.scheme}://{netloc_norm}{path}"
        if query:
            norm += f"?{query}"
        return norm
    except Exception:
        return url.rstrip('/')


def _url_structure_heuristics(url: str, host: str, is_trusted: bool) -> List[ThreatSignal]:
    """
    [v19] Structural URL heuristics — pure parsing, no network calls, no user data stored.

    Checks:
    1. IP-literal host   — http://192.0.2.1/login  (almost never legitimate in email)
    2. Non-standard port — :8080, :4443, :8443       (infra hiding behind unusual ports)
    3. Deep subdomain    — 4+ labels before regdomain (common in phishing infra)
    4. Suspicious params — ?token=, ?verify=, ?account= on untrusted domains

    Security notes:
    - All operations are pure string/regex — no file I/O, no network I/O, no shell calls.
    - url/host values arrive already extracted by urlparse — no additional parsing needed.
    - Trusted domains are skipped entirely to prevent FP on marketing tools.
    - Each finding is a separate low-tier ThreatSignal so it can correlate with others.
    """
    if is_trusted or not url:
        return []

    sigs: List[ThreatSignal] = []

    # 1. IP-literal host (IPv4 only — IPv6 literals are ultra-rare in phishing email)
    #    Regex matches bare IPv4 addresses, rejecting partial matches like '1.2.3.4.evil.com'
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        sigs.append(ThreatSignal(
            'ip_literal_url', 'content', 3, 0.35, 0.80,
            "IP-Literal URL",
            "URL points to a raw IP address — legitimate services use domain names",
            f"Host: {host}"))

    # 2. Non-standard port (not 80/443)
    try:
        parsed_port = urlparse(url).port
        if parsed_port and parsed_port not in (80, 443):
            sigs.append(ThreatSignal(
                'nonstandard_port', 'content', 3, 0.25, 0.70,
                f"Non-Standard Port :{parsed_port}",
                "URL uses an unusual port — often used to bypass content filtering",
                f"URL: {defang(url[:80])}"))
    except Exception:
        pass

    # 3. Deep subdomain (4+ dot-separated labels in the full hostname)
    #    Calculates labels above the registered domain using _root_domain()
    reg = _root_domain(host)
    if reg and reg != host:
        # Count subdomain labels (labels in host minus labels in registered domain)
        host_labels = host.rstrip('.').split('.')
        reg_labels  = reg.rstrip('.').split('.')
        subdomain_depth = len(host_labels) - len(reg_labels)
        if subdomain_depth >= 4:
            sigs.append(ThreatSignal(
                'deep_subdomain', 'content', 4, 0.18, 0.60,
                f"Excessive Subdomain Depth ({subdomain_depth} levels)",
                "Many subdomain levels can indicate algorithmically generated phishing infrastructure",
                f"Host: {host}"))

    # 4. Suspicious query parameter keys on untrusted domains
    #    Only fires if the URL has query parameters AND the host is not trusted.
    #    Parameter keys are lowercased before comparison — no values are read.
    try:
        qs = urlparse(url).query.lower()
        if qs:
            param_keys = {k.split('=')[0] for k in qs.split('&')}
            hits = _PHISH_PARAMS & param_keys
            if hits:
                sigs.append(ThreatSignal(
                    'phish_param', 'content', 4, 0.15, 0.55,
                    f"Suspicious URL Parameters ({', '.join(sorted(hits))})",
                    "Query parameter names associated with credential harvesting pages",
                    f"URL: {defang(url[:80])}"))
    except Exception:
        pass

    return sigs


def _domain_structure_signals(domain: str, root: str) -> List[ThreatSignal]:
    """
    [v19] Domain structure heuristics — checks the domain's shape and character set.

    Checks:
    1. Brand-in-subdomain  — paypal.com.evil.net  (real brand in subdomain of rogue domain)
    2. Excessive subdomain — 4+ labels (complements _url_structure_heuristics)
    3. Homoglyph           — non-ASCII characters in domain (Unicode lookalike attack)

    Security notes:
    - PROTECTED_BRANDS is a frozenset of complete registered domain names — no
      substring matching that could produce FPs on short tokens like 'pay' or 'bank'.
    - Homoglyph detection uses str.isascii() which is pure C internally — safe.
    - domain values arrive already host-extracted — no additional parsing needed.
    """
    if not domain or not root:
        return []

    sigs: List[ThreatSignal] = []
    domain_lower = domain.lower()

    # 1. Brand-in-subdomain: any PROTECTED_BRANDS entry appears ABOVE the registered root
    #    i.e.  subdomain contains the full brand domain, but root != brand domain
    #    Example: paypal.com.evil.net → root=evil.net, brand paypal.com in subdomain
    subdom_part = domain_lower
    if root and domain_lower.endswith(root):
        subdom_part = domain_lower[: max(0, len(domain_lower) - len(root) - 1)]
    for brand in PROTECTED_BRANDS:
        if brand in subdom_part and root != brand:
            sigs.append(ThreatSignal(
                'brand_in_subdomain', 'content', 2, 0.55, 0.80,
                f"Brand Impersonation in Subdomain ({brand})",
                f"Real domain '{brand}' appears in subdomain of '{root}' — classic phishing technique",
                f"Domain: {domain}"))
            break  # One brand hit per domain is enough

    # 2. Homoglyph: non-ASCII characters in the domain (Punycode/IDN lookalikes)
    #    xn-- prefixed labels are Punycode-encoded IDN — common in homoglyph attacks.
    #    We flag, not block — legitimate IDN domains exist but are rare in email threats.
    try:
        if not domain_lower.isascii():
            sigs.append(ThreatSignal(
                'homoglyph_domain', 'content', 2, 0.45, 0.75,
                "Unicode Lookalike Domain",
                "Domain contains non-ASCII characters — possible homoglyph/IDN phishing attack",
                f"Domain: {domain}"))
        elif any(label.startswith('xn--') for label in domain_lower.split('.')):
            sigs.append(ThreatSignal(
                'homoglyph_domain', 'content', 2, 0.40, 0.70,
                "Punycode (IDN) Domain",
                "Domain uses Punycode encoding — verify it is not a Unicode lookalike",
                f"Domain: {domain}"))
    except Exception:
        pass

    return sigs


def _check_archive_password(payload: bytes, filename: str) -> bool:
    """
    [v19] Detect password-protected ZIP archives.

    Returns True if the archive is ZIP-format AND password-protected.
    Only tests the first central-directory entry to avoid decompressing content.

    Security notes:
    - NEVER decompresses content. Uses zipfile.ZipFile in read mode only.
    - Size guard: rejects payloads > 50 MB to prevent zip-bomb decompression.
    - Only operates on .zip files — 7z/rar password detection requires third-party
      libs (py7zr/rarfile) not guaranteed to be installed; those are left for v20.
    - Exceptions are silently caught — a corrupt archive is not flagged as password-protected.
    """
    ext = ('.' + filename.rsplit('.', 1)[-1]).lower() if '.' in filename else ''
    if ext != '.zip':
        return False
    if len(payload) > 50 * 1024 * 1024:  # 50 MB guard
        return False
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(payload), 'r') as zf:
            first = zf.infolist()[0] if zf.infolist() else None
            if first is None:
                return False
            # Flag 0x0001 in the general purpose bit flags = encrypted
            return bool(first.flag_bits & 0x0001)
    except Exception:
        return False


def extract_observables(msg, html_body, text_body) -> Tuple[List[Observable], List[LinkMismatch]]:
    """Extract observables using DOM parsing. Detect link-text mismatches."""
    obs: List[Observable] = []
    mismatches: List[LinkMismatch] = []
    seen: Set[str] = set()

    def _add(typ, val, src, **kw):
        norm_val = _normalize_url(val) if typ == 'url' else val.lower()
        key = f"{typ}:{norm_val}"
        if key in seen:
            return
        seen.add(key)
        o = Observable(type=typ, value=val, defanged=defang(val), source=src, **kw)
        if typ == 'url':
            # FIX(C22): parse URL once — FIX(v13): use _url_host() not .netloc
            try:
                netloc = _url_host(val)  # strips port before shortener/TLD checks
                o.is_shortener = netloc in URL_SHORTENERS
                o.suspicious_tld = any(netloc.endswith(t) for t in SUSPICIOUS_TLDS)

                is_known_gateway = is_tracking_domain(netloc)
                wrapper = is_redirect_wrapper(val)

                # [FIX-SEC]: Entropy suppression — always suppress for redirect
                # wrappers (known gateway OR unknown domain), because the high
                # entropy comes from URL-encoding the inner URL, not from a
                # phishing token. This is structurally identical for all wrappers.
                if is_known_gateway or wrapper:
                    o.path_entropy = 0.0
                    o.is_wrapper = True
                else:
                    o.path_entropy = url_path_entropy(val)

                # [FIX-SEC]: Inner URL extraction — when a redirect wrapper is
                # detected, extract the real destination URL and add it as a
                # SEPARATE observable so it gets full VT/OTX/XForce scanning.
                # This is the correct fix for the false claim that "VT scans the
                # inner URL separately" — it didn't before; now it actually does.
                if wrapper:
                    inner = extract_inner_url(val)
                    if inner and inner != val:
                        # Recursively call _add() so the inner URL gets full
                        # Observable processing (entropy, shortener, TLD checks,
                        # deduplication). Use 'gateway_inner' source so analysts
                        # know this URL was unwrapped from a redirect wrapper.
                        _add('url', inner, 'gateway_inner')
            except Exception:
                # Fail-safe: if host parsing fails, compute entropy anyway.
                # We can't confirm it's a wrapper, so don't suppress detection.
                o.path_entropy = url_path_entropy(val)
        elif typ == 'domain':
            o.suspicious_tld = any(val.lower().endswith(t) for t in SUSPICIOUS_TLDS)
        obs.append(o)

    # HTML href extraction + link-text mismatch
    if BS4_OK and html_body:
        soup = BeautifulSoup(html_body[:MAX_HTML_SIZE], 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if not href.startswith(('http://', 'https://')):
                continue
            _add('url', href, 'html_href')
            display = a.get_text(strip=True)
            if display:
                dm = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display)
                if dm:
                    # FIX(C07): use _safe_strip_www instead of lstrip('www.')
                    dd = _safe_strip_www(dm.group(1).lower())
                    # --- NEW FIX: Ignore common file extensions ---
                    if dd.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico')):
                        continue
                    # FIX(v13): use _url_host() to strip port from netloc.
                    # urlparse().netloc includes the port: 'domain.com:443'.
                    # _root_domain('domain.com:443') returns 'domain.com:443'
                    # because ':443' becomes part of the last TLD component,
                    # making 'domain.com:443' != 'domain.com' → false mismatch.
                    hd = _url_host(href)
                    hr = _root_domain(hd)
                    dr = _root_domain(dd)
                    if hr != dr:
                        # SECURITY NOTE: Do NOT check whether the display domain
                        # appears as a substring inside the href. Attackers exploit
                        # that pattern (e.g. https://evil.ru/paypal.com) to suppress
                        # legitimate mismatch alerts — known as lure URL injection.
                        #
                        # [FIX-SEC]: Only suppress link-text mismatch when the href
                        # domain is in TRACKING_ALLOWLIST (explicitly trusted gateways).
                        # is_redirect_wrapper() is NOT used here for suppression because
                        # an unknown domain wrapping a URL is itself suspicious — the
                        # mismatch signal should still fire. The inner URL is extracted
                        # separately in _add() so the real destination gets VT-scanned.
                        is_track = is_tracking_domain(hd)
                        mismatches.append(LinkMismatch(
                            href=href, display=display[:80],
                            href_domain=hd, display_domain=dd, is_tracking=is_track))
    elif html_body:
        for m in PAT_HREF.finditer(html_body[:MAX_HTML_SIZE]):
            href = m.group(1).strip()
            if href.startswith(('http://', 'https://')):
                _add('url', href, 'html_href')

    body = (html_body or '') + (text_body or '')
    for url in PAT_URL.findall(body)[:MAX_OBS]:
        _add('url', url, 'body')

    for ea in PAT_EMAIL.findall(str(msg))[:MAX_OBS]:
        _add('domain', ea.split('@')[1].lower(), 'header')

    # FIX(C19): use precompiled _PRIVATE_IP_PATTERNS
    for h in msg.get_all('Received', []) or []:
        for ip in PAT_IPV4.findall(str(h)):
            if not any(r.match(ip) for r in _PRIVATE_IP_PATTERNS):
                _add('ip', ip, 'received')

    return obs, mismatches


# ═══════════════════════════════════════════════════════════════════════════════
# IMAGE ANALYSIS (with OCR)
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_image(part) -> Optional[ImageAnalysis]:
    fname = part.get_filename() or "image"
    r = ImageAnalysis(filename=fname)
    try:
        data = part.get_payload(decode=True)
        if not data:
            return None
        # FIX(C20): size-limit image data before processing
        if len(data) > MAX_IMAGE_SIZE:
            r.findings.append(f"Image too large ({len(data) // 1024 // 1024}MB) -- skipped")
            return r
        r.data = data
        if PIL_OK:
            img = PilImage.open(io.BytesIO(data))
            r.fmt = img.format or ""
            r.size = img.size
            if img.size[0] <= 2 and img.size[1] <= 2:
                r.findings.append("Tracking pixel (<=2x2)")
            if QR_OK:
                try:
                    for d in decode_qr(img):
                        url = d.data.decode('utf-8', 'ignore')
                        r.qr_links.append(url)
                        r.findings.append(f"QR: {url[:50]}")
                except Exception:
                    pass
            if STEGANO_OK and r.fmt in ['PNG', 'BMP', 'TIFF']:
                try:
                    if lsb.reveal(io.BytesIO(data)):
                        r.has_steg = True
                        r.findings.append("STEGANOGRAPHY: hidden LSB data")
                except Exception:
                    pass
            if OCR_OK and r.fmt in ['PNG', 'JPEG', 'JPG', 'BMP', 'TIFF', 'GIF']:
                try:
                    ocr_text = pytesseract.image_to_string(img, timeout=10)
                    if ocr_text and len(ocr_text.strip()) > 20:
                        r.ocr_text = ocr_text.strip()
                        r.findings.append(f"OCR extracted {len(r.ocr_text)} chars")
                except Exception as e:
                    log.debug(f"OCR failed: {e}")
    except Exception as e:
        log.error(f"Image analysis: {e}")
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL GENERATION (every module -> ThreatSignal / TrustFactor)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_signals(auth, anomalies, reply_hijack, bec, spoof_result, spoof_dn, spoof_sd,
                     observables, macros, images, body_findings, link_mismatches,
                     abuse_data, attachment_risks, ocr_bec_hits) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    """Convert all analysis results into structured signals and trust factors."""
    sigs: List[ThreatSignal] = []
    trust: List[TrustFactor] = []

    # -- Auth signals --
    if auth.spf == 'FAIL':
        sigs.append(ThreatSignal('spf_fail', 'auth', 2, 0.70, 0.90,
            "SPF FAIL", "Sending server not authorized", f"From: {auth.from_domain}"))
    elif auth.spf == 'SOFTFAIL':
        sigs.append(ThreatSignal('spf_softfail', 'auth', 3, 0.35, 0.80,
            "SPF SOFTFAIL", "Sender not fully authorized", ""))
    elif auth.spf == 'PASS':
        trust.append(TrustFactor('spf_pass', 0.15, 0.90, "SPF passed"))

    if auth.dkim == 'FAIL':
        sigs.append(ThreatSignal('dkim_fail', 'auth', 2, 0.50, 0.85,
            "DKIM FAIL", "Message integrity compromised", ""))
    elif auth.dkim == 'PASS':
        trust.append(TrustFactor('dkim_pass', 0.15, 0.90, "DKIM passed"))
    elif auth.dkim == 'NONE' and auth.spf in ('FAIL', 'SOFTFAIL'):
        sigs.append(ThreatSignal('dkim_none_compound', 'auth', 3, 0.20, 0.70,
            "No DKIM + SPF issue", "No cryptographic integrity", ""))

    if auth.dmarc == 'FAIL':
        sigs.append(ThreatSignal('dmarc_fail', 'auth', 2, 0.55, 0.85,
            "DMARC FAIL", "Domain policy violated", ""))
    elif auth.dmarc == 'PASS':
        trust.append(TrustFactor('dmarc_pass', 0.12, 0.90, "DMARC passed"))

    if auth.shadow_spoof:
        sigs.append(ThreatSignal('shadow_spoofing', 'auth', 2, 0.75, 0.90,
            "Shadow Spoofing", "From/Return-Path mismatch",
            f"{auth.from_domain} vs {auth.rp_domain}"))

    if auth.gateway_trust:
        trust.append(TrustFactor('gateway', 0.25, 0.85,
            f"Trusted gateway: {auth.gateway_name}"))

    if auth.hop_anomaly and 'stall' in auth.hop_anomaly.lower():
        sigs.append(ThreatSignal('hop_stall', 'network', 4, 0.20, 0.60,
            "Hop Delay", "Relay stalling detected", auth.hop_anomaly))

    # FIX(S3): Live DNS contradictions feed into scoring.
    # If header claims SPF=PASS but live DNS shows no SPF record, that's
    # evidence of forged Authentication-Results headers.
    for detail in auth.details:
        if 'Header claims SPF PASS but no SPF record' in detail:
            sigs.append(ThreatSignal('dns_spf_contradiction', 'auth', 2, 0.60, 0.80,
                "DNS Contradiction", detail,
                "Live DNS disagrees with header — possible AR header forgery"))
        elif 'Header claims DMARC PASS but no DMARC record' in detail:
            sigs.append(ThreatSignal('dns_dmarc_contradiction', 'auth', 2, 0.55, 0.75,
                "DNS Contradiction", detail,
                "Live DNS disagrees with header — possible AR header forgery"))

    # Live DMARC reject policy is a positive trust signal
    if auth.live_verified and auth.live_dmarc.get('policy') == 'reject':
        if auth.dmarc == 'PASS':
            trust.append(TrustFactor('dmarc_reject_policy', 0.10, 0.85,
                "Domain has DMARC reject policy — strong anti-spoofing posture"))

    # -- Header anomalies --
    if reply_hijack:
        sigs.append(ThreatSignal('reply_to_hijack', 'auth', 2, 0.65, 0.85,
            "Reply-To Hijack", "Replies redirected to different domain", ""))
    for a in anomalies:
        if 'hijack' in a.lower():
            continue
        sigs.append(ThreatSignal(f'header_{a[:20]}', 'network', 4, 0.15, 0.55,
            "Header Anomaly", a, ""))

    # -- Display name spoof --
    if spoof_result:
        sigs.append(ThreatSignal('display_name_spoof', 'behavioral', 2, 0.60, 0.80,
            "Display Name Spoof", spoof_result, f"'{spoof_dn}' from {spoof_sd}"))

    # -- BEC --
    # v13 OVERHAUL: Auth-context dampening applied here where SPF/DKIM/DMARC
    # state is available. analyze_bec() is pure content analysis; dampening
    # is a scoring-layer concern handled in generate_signals().
    #
    # Dampening rationale:
    #   - A clean SPF+DKIM+DMARC pass means the sending server is authenticated.
    #     BEC content signals in authenticated email are more likely FP than TP.
    #   - We do NOT zero out the BEC score — auth can be clean AND a real BEC
    #     exist (e.g. compromised legitimate account), so we dampen, not suppress.
    #   - Dampening only applies to tier-2/3 categories. If wire_transfer or
    #     gift_cards fired, the financial specificity overrides auth trust.
    #
    # FIX(C02) preserved: emit individual category markers for SIGNAL_CORRELATIONS.
    if bec.score >= 0.25:
        # Determine if high-specificity (tier-1) categories fired
        TIER1_CATS = {"wire_transfer", "gift_cards", "secrecy", "payment_redirect"}
        bec_cats = set(bec.categories)
        has_tier1 = bool(bec_cats & TIER1_CATS)

        # Auth-context dampening: clean auth + no tier-1 signal = likely FP
        auth_clean = (
            getattr(auth, 'spf',  'UNKNOWN') == 'PASS' and
            getattr(auth, 'dkim', 'UNKNOWN') == 'PASS' and
            getattr(auth, 'dmarc','UNKNOWN') == 'PASS' and
            not getattr(auth, 'shadow_spoof', False)
        )
        effective_score = bec.score
        if auth_clean and not has_tier1:
            # Dampen tier-2/tier-3 BEC hits when auth is fully clean.
            # Preserves them for correlation but removes the scoring weight.
            effective_score *= 0.35
        elif auth_clean and has_tier1:
            # Auth clean but tier-1 financial indicator present: moderate dampen
            # (could be compromised-account BEC — still worth flagging)
            effective_score *= 0.70

        if effective_score >= 0.25:
            tier = 2 if effective_score >= 0.60 else 3
            bec_conf = 0.75 if bec.density > 0.02 else 0.55
            dampened_note = " [auth-dampened]" if auth_clean else ""
            sigs.append(ThreatSignal(
                'bec_combined', 'behavioral', tier,
                min(effective_score, 0.85), bec_conf,
                "BEC Pattern", bec.summary + dampened_note,
                "; ".join(bec.findings[:3])))
            for cat in bec_cats:
                sigs.append(ThreatSignal(
                    f'bec_{cat}', 'behavioral', tier + 1,
                    0.0, bec_conf,
                    f"BEC marker: {cat}", "", ""))
        elif bec.score >= 0.25:
            # Original score was significant but got dampened below threshold:
            # emit markers only so correlations still work, but add no score.
            for cat in bec_cats:
                sigs.append(ThreatSignal(
                    f'bec_{cat}', 'behavioral', 4,
                    0.0, 0.40,
                    f"BEC marker (auth-dampened): {cat}", "", ""))

    if bec.contradictions:
        trust.append(TrustFactor('bec_contradiction', 0.10, 0.60,
            "BEC contradiction: urgency + calm language"))

    # -- Link-text mismatches (deduplicated by domain pair) --
    real_mismatches = [m for m in link_mismatches if not m.is_tracking]
    tracking_mismatches = [m for m in link_mismatches if m.is_tracking]
    # Deduplicate: same display→href pair only counts once for scoring
    seen_mm = set()
    unique_mm = []
    for m in real_mismatches:
        pair = (m.display_domain, m.href_domain)
        if pair not in seen_mm:
            seen_mm.add(pair)
            unique_mm.append(m)
    if unique_mm:
        sigs.append(ThreatSignal('link_text_mismatch', 'content', 2, 0.55, 0.85,
            f"{len(unique_mm)} Link-Text Mismatch(es)",
            "Displayed domain differs from link destination",
            f"e.g. shows '{unique_mm[0].display_domain}' -> '{unique_mm[0].href_domain}'"))
    if tracking_mismatches:
        trust.append(TrustFactor('tracking_links', 0.05, 0.70,
            f"{len(tracking_mismatches)} link(s) via known tracking domains"))

    # -- Body findings --
    for bf in body_findings:
        sigs.append(ThreatSignal(f'body_{bf[:15]}', 'content', 4, 0.12, 0.50,
            "Content Alert", bf, ""))

    # -- URL heuristics --
    shorteners = [o for o in observables if o.is_shortener]
    if shorteners:
        sigs.append(ThreatSignal('url_shortener', 'content', 4, 0.12, 0.60,
            f"{len(shorteners)} Shortened URL(s)", "May hide destination", ""))
    sus_tld = [o for o in observables if o.suspicious_tld]
    if sus_tld:
        sigs.append(ThreatSignal('suspicious_tld', 'content', 4, 0.18, 0.65,
            f"{len(sus_tld)} Suspicious TLD(s)", "Frequently-abused TLD", ""))
    high_entropy_urls = [o for o in observables if o.type == 'url' and o.path_entropy > 4.8]

    if high_entropy_urls:
        sigs.append(ThreatSignal('high_entropy_url', 'content', 3, 0.25, 0.60,
            "High-Entropy URL Path", "Likely phishing token",
            f"URL: {high_entropy_urls[0].defanged} (Entropy: {high_entropy_urls[0].path_entropy:.1f})"))

    # [v19] URL structure heuristics — IP literals, non-standard ports, deep subdomains,
    # suspicious parameter keys. Each is a separate signal for correlation purposes.
    # Deduplication: only one signal of each type regardless of how many URLs match.
    _url_struct_seen: set = set()
    for o in observables:
        if o.type != 'url':
            continue
        host = _url_host(o.value)
        if not host:
            continue
        is_trusted = is_tracking_domain(host) or o.is_wrapper
        for us_sig in _url_structure_heuristics(o.value, host, is_trusted):
            if us_sig.name not in _url_struct_seen:
                _url_struct_seen.add(us_sig.name)
                sigs.append(us_sig)

    # [v19] Domain structure signals — brand-in-subdomain and homoglyph detection.
    # Only runs on observables whose domain is NOT trusted (same guard as DGA signals).
    _dom_struct_seen: set = set()
    for o in observables:
        dom = (_url_host(o.value) if o.type == 'url' else o.value.lower())
        if not dom or is_tracking_domain(dom):
            continue
        root = _root_domain(dom)
        if not root:
            continue
        for ds_sig in _domain_structure_signals(dom, root):
            if ds_sig.name not in _dom_struct_seen:
                _dom_struct_seen.add(ds_sig.name)
                sigs.append(ds_sig)

    # -- Observables (VT results) --
    vt_clean_count = 0
    for o in observables:
        if o.vt and o.vt.success:
            if o.vt.threat_level in ('CRITICAL', 'MALICIOUS'):
                sigs.append(ThreatSignal(f'vt_{o.type}_{o.value[:20]}', 'network', 1,
                    0.85 if o.vt.threat_level == 'CRITICAL' else 0.70, 0.90,
                    f"VT: {o.type} flagged", o.vt.reasoning, o.defanged))
            elif o.vt.threat_level == 'SUSPICIOUS':
                sigs.append(ThreatSignal(f'vt_sus_{o.value[:20]}', 'network', 3, 0.35, 0.65,
                    f"VT: {o.type} suspicious", o.vt.reasoning, o.defanged))
            elif o.vt.threat_level in ('CLEAN', 'LOW'):
                vt_clean_count += 1
    if vt_clean_count > 0:
        trust.append(TrustFactor('vt_clean_urls', min(0.15, vt_clean_count * 0.02), 0.75,
            f"{vt_clean_count} URL(s)/domain(s) verified clean by VirusTotal"))
    # FIX: Deduplication sets for domain-based signals.
    # Without these, an email with 5 URLs on the same suspicious domain emits
    # 5 independent dga_domain_entropy / typosquat / domain_new signals with
    # the same name. The nonlinear combiner treats them as independent evidence,
    # inflating the score significantly (e.g. 5× typosquat = ~0.93 combined vs
    # correct 0.50 for a single confirmed typosquat). Each unique root domain
    # should only contribute one signal per type.
    _seen_typo_domains: Set[str] = set()
    _seen_dga_entropy: Set[str] = set()
    _seen_dga_consonant: Set[str] = set()
    _seen_domain_new: Set[str] = set()

    for o in observables:
        if o.vt and o.vt.domain_intel and o.vt.domain_intel.typosquat:
            dom_root = _root_domain(_url_host(o.value) if o.type == 'url' else o.value.lower())
            if dom_root not in _seen_typo_domains:
                _seen_typo_domains.add(dom_root)
                sigs.append(ThreatSignal('typosquat', 'content', 2, 0.50, 0.75,
                    "Typosquat Domain", o.vt.domain_intel.typosquat, o.defanged))
        # [I06] Emit domain entropy and DGA signals for unknown/untrusted domains.
        # Guard: skip domains from known tracking/gateway services — their delivery
        # subdomains (e.g. de-smtp-delivery-123.mimecast.com) have moderate entropy
        # and structured names that mimic DGA patterns but are completely legitimate.
        if o.vt and o.vt.domain_intel and not o.vt.domain_intel.trusted:
            di = o.vt.domain_intel
            # FIX(v13): use _url_host() to strip port — netloc with port
            # (e.g. 'smex-ctp.trendmicro.com:443') fails is_tracking_domain()
            dom_to_check = (_url_host(o.value) if o.type == 'url' else o.value.lower())
            dom_root = _root_domain(dom_to_check)
            # Skip known tracking/gateway domains entirely
            if not is_tracking_domain(dom_to_check) and not is_tracking_domain(dom_root):
                sub_ent = subdomain_entropy(dom_to_check)
                if sub_ent > 4.0 and dom_to_check not in _seen_dga_entropy:   # Raised from 3.5 to eliminate structured hostname FPs
                    _seen_dga_entropy.add(dom_to_check)
                    sigs.append(ThreatSignal('dga_domain_entropy', 'content', 3, 0.35, 0.70,
                        "High Subdomain Entropy",
                        f"Subdomain entropy {sub_ent:.1f}b suggests DGA/algorithmically-generated name",
                        o.defanged))
                if is_randomized_domain(dom_to_check) and dom_root not in _seen_dga_consonant:
                    _seen_dga_consonant.add(dom_root)
                    sigs.append(ThreatSignal('dga_domain_consonant', 'content', 3, 0.40, 0.65,
                        "Randomized Domain Pattern",
                        "Domain name consonant/vowel ratio matches DGA pattern",
                        o.defanged))
            if di.age_days > 0 and di.age_days < 30 and dom_root not in _seen_domain_new:
                _seen_domain_new.add(dom_root)
                sigs.append(ThreatSignal('domain_new', 'content', 3, 0.30, 0.75,
                    f"Newly Registered Domain ({di.age_days}d old)",
                    "Domains registered < 30 days ago are disproportionately used in phishing",
                    o.defanged))

    # -- AbuseIPDB --
    if abuse_data:
        ascore = abuse_data.get('abuseConfidenceScore', 0)
        is_tor = abuse_data.get('isTor', False)
        is_cloud = _is_cloud(abuse_data.get('isp', ''))
        if ascore >= 75 and not (is_cloud and auth.spf == 'PASS'):
            sigs.append(ThreatSignal('abuse_ip_high', 'network', 2, 0.65, 0.80,
                f"AbuseIPDB: {ascore}/100",
                f"{abuse_data.get('totalReports', 0)} reports, ISP: {abuse_data.get('isp', '')}",
                auth.source_ip))
        elif ascore >= 40 and not (is_cloud and auth.gateway_trust):
            sigs.append(ThreatSignal('abuse_ip_med', 'network', 3, 0.30, 0.65,
                f"AbuseIPDB: {ascore}/100", "Elevated", ""))
        elif ascore < 10:
            trust.append(TrustFactor('ip_clean', 0.05, 0.60, f"AbuseIPDB clean ({ascore}/100)"))
        if is_tor:
            sigs.append(ThreatSignal('tor_exit', 'network', 2, 0.50, 0.90,
                "TOR Exit Node", "Source anonymized", ""))

    # -- Attachment risks --
    for risk in attachment_risks:
        if risk['severity'] == 'CRITICAL':
            sigs.append(ThreatSignal(f"att_{risk['type']}_{risk['file'][:15]}", 'attachment', 2,
                0.60, 0.85, f"Attachment Risk: {risk['file']}", risk['desc'], ""))
        elif risk['severity'] == 'HIGH':
            sigs.append(ThreatSignal(f"att_{risk['type']}", 'attachment', 3, 0.30, 0.70,
                f"Attachment Risk: {risk['file']}", risk['desc'], ""))

    # -- Macro / YARA / MalwareBazaar --
    for macro in macros:
        if macro.mb_found:
            sigs.append(ThreatSignal('malware_hash', 'attachment', 1, 0.95, 0.98,
                f"MALWARE: {macro.filename}", f"MalwareBazaar: {macro.mb_family}", macro.sha256))
        for ym in macro.yara_matches:
            # BUG FIX: Skip enrichment/informational rules entirely.
            # Enrichment rules (CY_Sender_is_NOREPLY, CY_FMR_freemail,
            # PM_Labs_Potential_Malware_Reply_Chain, etc.) are contextual labels
            # with NO score impact. Previously they slipped through here and showed
            # up in the Threat Narrative as MEDIUM (13%) because their severity
            # ('INFO'/'LOW') fell through the prob-dict to the 0.15 default,
            # giving eff = 0.15 × 0.85 = 12.75% → MEDIUM badge. This was wrong
            # and contradicted what the YARA tab correctly showed as INFO.
            if ym.get('enrichment'):
                continue
            sev = ym['severity'].upper()
            # INFO severity rules should never reach here (blocked above), but
            # guard anyway so a misconfigured rule never scores.
            if sev == 'INFO':
                continue
            # Probability mapping → determines effective score (prob × confidence).
            # LOW must stay < 0.08/0.85 ≈ 0.094 so eff < 8% → displayed as "LOW",
            # not "MEDIUM". Using 0.10 was a bug: 0.10 × 0.85 = 0.085 ≥ 0.08 → MEDIUM.
            prob = {'CRITICAL': 0.80, 'HIGH': 0.50, 'MEDIUM': 0.25, 'LOW': 0.06}.get(sev, 0.06)
            tier = 1 if sev == 'CRITICAL' else (2 if sev == 'HIGH' else (3 if sev == 'MEDIUM' else 4))
            # ALL YARA signals route to the 🔴 YARA tab regardless of whether the hit
            # came from an attachment or the email body — the YARA tab is where analysts
            # see matched strings, severity, and TLP context for every YARA hit.
            # Previously only [Body] hits were routed here; attachment YARA hits still
            # said "Attachments tab" even though the details live in the YARA tab.
            sigs.append(ThreatSignal(f"yara_{ym['rule']}", 'yara', tier, prob, 0.85,
                f"YARA: {ym['rule']}", ym['desc'], ""))
        # PDF dangerous tag signal: only emit when genuinely dangerous tags found.
        # has_macros=True + risk_score>0 means /JavaScript or /Launch was present.
        # /OpenAction alone no longer sets has_macros, so it won't emit here.
        if macro.has_macros and not macro.yara_matches and not macro.mb_found and macro.risk_score > 0:
            # PDF/document content tags — risk_score now set correctly by analyze_attachment
            prob = min(macro.risk_score / 100, 0.75) if macro.risk_score > 0 else 0.40
            sigs.append(ThreatSignal(
                f"pdf_tags_{macro.filename[:15]}", 'attachment', 2,
                prob, 0.75,
                f"Suspicious PDF Tags: {macro.filename}",
                '; '.join(macro.details[:3]) or macro.verdict,
                macro.sha256[:16] if macro.sha256 else ""))
        elif macro.has_macros and macro.risk_score >= 50:
            sigs.append(ThreatSignal(f"macro_{macro.filename[:15]}", 'attachment', 2,
                min(macro.risk_score / 120, 0.80), 0.75,
                f"Risky Macros: {macro.filename}", macro.verdict, ""))
    # --- INSERT THIS NEW BLOCK HERE ---
    
    # ── Clean attachment trust factor ────────────────────────────────────────
    # Correct scope: only real FILE attachments, not the [Body] pseudo-entry.
    # Bug: the original code checked `if macros:` which includes [Body] entries.
    # If YARA fired on the email body, [Body].yara_matches is non-empty, so
    # has_threats was True even when every real file attachment was clean.
    # This caused the clean_attachments TrustFactor to never emit for emails
    # where body YARA fired, meaning it never appeared in Mitigating Factors.
    _real_macros = [m for m in macros if m.filename != '[Body]']
    if _real_macros:
        _has_threats = any(
            m.mb_found or m.yara_matches or (m.has_macros and m.risk_score > 0)
            for m in _real_macros          # <-- only real file attachments
        )
        _has_structural_risks = bool(attachment_risks)
        if not _has_threats and not _has_structural_risks:
            _count = len(_real_macros)
            _strength = 0.15 if _count >= 3 else 0.10
            trust.append(TrustFactor(
                'clean_attachments',
                _strength,
                0.95,
                f"{_count} attachment(s) scanned and verified clean (YARA/MalwareBazaar/Heuristics)"
            ))

    # -- Image findings --
    for img in images:
        if img.has_steg:
            sigs.append(ThreatSignal('steganography', 'attachment', 2, 0.70, 0.75,
                "Steganography", "Hidden data in image", img.filename))

    # ── Clean image trust factor ─────────────────────────────────────────────
    # Parallel to clean_attachments: if images were scanned and none contained
    # steganography, QR phishing links, or suspicious OCR text (BEC hits are
    # counted separately in ocr_bec_hits), emit a TrustFactor.
    # Previously omitted entirely — clean images never appeared in Mitigating
    # Factors or affected dampening even though the scanner ran and cleared them.
    if images:
        _img_threats = any(
            img.has_steg or img.qr_links or
            any('malicious' in f.lower() or 'suspicious' in f.lower() or
                'steg' in f.lower() or 'qr' in f.lower()
                for f in img.findings)
            for img in images
        )
        if not _img_threats and not ocr_bec_hits:
            _img_count = len(images)
            trust.append(TrustFactor(
                'clean_images',
                0.05 if _img_count == 1 else 0.08,
                0.80,
                f"{_img_count} image(s) scanned — no steganography, QR phishing, "
                f"or suspicious content found"
            ))

    # -- OCR BEC hits --
    if ocr_bec_hits:
        sigs.append(ThreatSignal('ocr_bec', 'content', 3, 0.35, 0.55,
            "Image-Text BEC", f"OCR detected BEC in {ocr_bec_hits} image(s)", ""))

    # -- Sender memory trust --
    # [v19] ENHANCED: Trust scales with both history depth and email count.
    # Minimum: 60d / 3 emails / SPF pass (same floor as v18).
    # Scale: ~0.10 at minimum, ~0.15 at 10 emails/6 months, ~0.18 at 20+/1yr.
    # Security cap: if any Tier-1 signal fires (malware, YARA CRITICAL, VT MALICIOUS),
    # sender trust is halved — known sender could be a compromised account, not
    # a spoofed one, but the hard evidence outweighs the reputation.
    if auth.from_domain and auth.spf == 'PASS':
        known, count, days = check_sender(auth.from_domain)
        if known and days > 60 and count >= 3:
            has_tier1_threat = any(s.tier == 1 and s.probability >= 0.50 for s in sigs)
            # Scaled strength: history depth + email frequency, each contributing up to 0.09
            _base_strength = min(0.09, (days / 365) * 0.09) + min(0.09, (count / 20) * 0.09)
            _strength = (_base_strength * 0.5) if has_tier1_threat else _base_strength
            _strength = round(min(0.18, _strength), 4)
            _note = " [halved — Tier-1 threat present]" if has_tier1_threat else ""
            trust.append(TrustFactor('known_sender', _strength, 0.65,
                f"Known sender: {auth.from_domain} ({days}d, {count} clean emails{_note})"))
            
    # ── Spamhaus ZEN DNSBL: source IP reputation ─────────────────────────────
    # This checks the email's originating IP (extracted from Received headers)
    # against the Spamhaus ZEN blocklist via a standard DNS reverse lookup.
    # Much more reliable than checking domains — IPs are definitive sender identity.
    if auth.source_ip:
        listed, dnsbl_cat, dnsbl_desc = check_spamhaus_ip(auth.source_ip)
        if listed:
            # Weight by category: SBL/XBL are high-confidence spam/exploit sources.
            # PBL is lower confidence (dynamic IPs can also be legitimate).
            if dnsbl_cat == 'PBL':
                # PBL = Policy Block List: residential/dynamic IPs sending email directly.
                # This is suspicious but common for misconfigured servers — Tier 3, lower weight.
                sigs.append(ThreatSignal(
                    'dnsbl_pbl', 'network', 3, 0.30, 0.70,
                    f"Spamhaus PBL: {auth.source_ip}",
                    dnsbl_desc,
                    f"Source IP: {auth.source_ip}"))
            else:
                # SBL or XBL = high confidence spam/exploit source
                sigs.append(ThreatSignal(
                    'dnsbl_listed', 'network', 2, 0.65, 0.85,
                    f"Spamhaus ZEN ({dnsbl_cat}): {auth.source_ip}",
                    dnsbl_desc,
                    f"Source IP: {auth.source_ip}"))

    # ── Sender domain MX validation ──────────────────────────────────────────
    # A domain that fails SPF AND has no MX records is a strong throw-away
    # domain indicator. Legitimate senders always have MX records so they can
    # receive bounce replies. This is a Tier 3 heuristic, not a hard signal.
    if auth.from_domain and auth.spf in ('FAIL', 'SOFTFAIL', 'NONE'):
        has_mx, mx_detail = check_sender_mx(auth.from_domain)
        if not has_mx:
            sigs.append(ThreatSignal(
                'no_mx_record', 'network', 3, 0.28, 0.70,
                f"No MX Record: {auth.from_domain}",
                f"Sender domain has no MX records — cannot receive bounce replies. {mx_detail}",
                f"Domain: {auth.from_domain}"))

    # ── AlienVault OTX → ThreatSignal emission ────────────────────────────────
    # BUG FIX: OTX previously updated observable.threat_score and observable.reputation
    # but NEVER emitted a ThreatSignal. The scoring engine therefore saw zero contribution
    # from OTX regardless of what it found. Now correctly emits Tier 1 for CRITICAL
    # indicators and Tier 3 for HIGH/SUSPICIOUS, de-duplicating against any VT Tier 1
    # already emitted for the same observable to prevent stacking two confirmations.
    #
    # [v19] DEDUP FIX: Previous guard used o.value[:20] truncation which could miss
    # matches when two URLs share a 20-char prefix. Now keys on _normalize_url(o.value)
    # for URLs and o.value.lower() for domains/IPs — exact match, no truncation.
    _seen_tier1_norm: Set[str] = {
        _normalize_url(s.evidence) if s.evidence and s.evidence.startswith('http')
        else s.evidence.lower()
        for s in sigs if s.tier == 1 and s.evidence
    }

    _seen_otx: Set[str] = set()
    for o in observables:
        if not o.otx:
            continue
        otx_level = o.otx.get('threat_level', '')
        norm_key  = _normalize_url(o.value) if o.type == 'url' else o.value.lower()
        if norm_key in _seen_otx:
            continue
        if otx_level == 'CRITICAL':
            _seen_otx.add(norm_key)
            if norm_key not in _seen_tier1_norm:
                _seen_tier1_norm.add(norm_key)
                sigs.append(ThreatSignal(
                    f'otx_{o.type}_{o.value[:20]}', 'network', 1, 0.78, 0.82,
                    f"OTX: {o.type.upper()} confirmed threat",
                    o.otx.get('reasoning', 'AlienVault OTX — confirmed malicious indicator'),
                    o.defanged))
        elif otx_level in ('HIGH', 'SUSPICIOUS'):
            _seen_otx.add(norm_key)
            sigs.append(ThreatSignal(
                f'otx_sus_{o.value[:20]}', 'network', 3, 0.32, 0.68,
                f"OTX: {o.type.upper()} suspicious",
                o.otx.get('reasoning', 'AlienVault OTX — suspicious indicator'),
                o.defanged))

    # ── IBM X-Force → ThreatSignal emission ───────────────────────────────────
    # Same fix as OTX above. Tier 1 for CRITICAL, Tier 3 for HIGH/SUSPICIOUS.
    # Confidence is slightly lower than OTX (0.80 vs 0.82) because X-Force free-tier
    # data can lag on newly-active phishing infrastructure.
    # [v19] Uses same _seen_tier1_norm set built above — cross-source dedup.
    _seen_xf: Set[str] = set()
    for o in observables:
        if not o.xforce:
            continue
        xf_level = o.xforce.get('threat_level', '')
        norm_key  = _normalize_url(o.value) if o.type == 'url' else o.value.lower()
        if norm_key in _seen_xf:
            continue
        if xf_level == 'CRITICAL':
            _seen_xf.add(norm_key)
            if norm_key not in _seen_tier1_norm:
                _seen_tier1_norm.add(norm_key)
                sigs.append(ThreatSignal(
                    f'xforce_{o.type}_{o.value[:20]}', 'network', 1, 0.75, 0.80,
                    f"X-Force: {o.type.upper()} confirmed threat",
                    o.xforce.get('reasoning', 'IBM X-Force — confirmed malicious indicator'),
                    o.defanged))
        elif xf_level in ('HIGH', 'SUSPICIOUS'):
            _seen_xf.add(norm_key)
            sigs.append(ThreatSignal(
                f'xforce_sus_{o.value[:20]}', 'network', 3, 0.28, 0.62,
                f"X-Force: {o.type.upper()} suspicious",
                o.xforce.get('reasoning', 'IBM X-Force — suspicious indicator'),
                o.defanged))

    return sigs, trust


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACHMENT RISK MATRIX
# ═══════════════════════════════════════════════════════════════════════════════

def get_attachment_risks(msg) -> List[Dict]:
    risks = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        # Skip image parts — handled in Image Forensics
        if part.get_content_type().startswith('image/'):
            continue
        fname = part.get_filename()                               # Level 1: standard
        if not fname:
            fname = part.get_param("name", header="content-type") # Level 2: CT name=
        if not fname:
            ct_tmp = part.get_content_type()
            if ct_tmp in ("application/pdf", "application/msword",
                          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                          "application/vnd.ms-excel", "application/octet-stream",
                          "application/x-msdownload"):
                try:
                    _probe = part.get_payload(decode=True)
                    if isinstance(_probe, bytes) and len(_probe) > 64:
                        fname = f"attachment_inline.{ct_tmp.split(chr(47))[-1]}"
                except Exception:
                    pass
        if not fname:
            continue
        fl = fname.lower()
        ct = part.get_content_type()
        for pat, desc in DOUBLE_EXT_PATS:
            if re.search(pat, fl):
                risks.append({'file': fname, 'type': 'double_ext',
                              'desc': f"Double ext: {desc}", 'severity': 'CRITICAL'})
                break
        ext = '.' + fl.rsplit('.', 1)[-1] if '.' in fl else ''
        if ext in DANGEROUS_EXTS:
            risks.append({'file': fname, 'type': 'dangerous_ext',
                          'desc': f"Dangerous: {ext}", 'severity': 'CRITICAL'})

        # [v19] Password-protected archive detection — AV bypass technique.
        # The password is often in the email body or subject, so the archive
        # bypasses gateway AV that cannot unpack encrypted containers.
        if ext in CONTAINER_EXTS:
            try:
                payload = part.get_payload(decode=True)
                if payload and _check_archive_password(payload, fl):
                    risks.append({'file': fname, 'type': 'password_archive',
                                  'desc': f"Password-protected archive: {fname} — "
                                          "AV gateways cannot inspect encrypted containers",
                                  'severity': 'HIGH'})
            except Exception:
                pass
        cext = fl.rsplit('.', 1)[-1] if '.' in fl else ''
        vtypes = VALID_MIMES.get(cext, [])
        if vtypes and not any(v in ct.lower() for v in vtypes) and ct.lower() not in ['application/octet-stream']:
            risks.append({'file': fname, 'type': 'mime_mismatch',
                          'desc': f".{cext} as '{ct}'", 'severity': 'MEDIUM'})
    return risks


# ═══════════════════════════════════════════════════════════════════════════════
# CONTENT ANALYSIS HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def detect_tracking_pixels(html_body):
    findings = []
    if not html_body:
        return findings
    if re.search(r'<img[^>]+width=[\'"]?1[\'"]?[^>]+height=[\'"]?1[\'"]?', html_body, re.I):
        findings.append("1x1 Tracking Pixel")
    n = html_body.replace(" ", "")
    if "color:white" in n or "color:#ffffff" in html_body.lower():
        findings.append("Hidden white text")
    if "font-size:0" in n:
        findings.append("Zero-size font")
    if "display:none" in n:
        findings.append("display:none element")
    return findings


def detect_suspicious_language(visible_text, subject=""):
    findings = []
    combined = normalize_text(f"{subject} {visible_text}").lower()
    if len(combined) < 20:
        return findings
    for cat, (phrases, _) in SUSPICIOUS_PHRASES.items():
        for p in phrases:
            try:
                if re.search(p, combined):
                    findings.append(f"Suspicious: '{p}' ({cat})")
                    break
            except Exception:
                if p in combined:
                    findings.append(f"Suspicious: '{p}' ({cat})")
                    break
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# SOAR INTEGRATION — Case DB · SOAR JSON · MITRE Mapper · Webhook · REST API
# ═══════════════════════════════════════════════════════════════════════════════

# ── Case Database ─────────────────────────────────────────────────────────────
_CASE_DB_PATH = os.path.join(_SENDER_DB_DIR, 'sherlock_cases.db')
_CASE_DB_LOCK = threading.Lock()

CASE_SCHEMA = '''
CREATE TABLE IF NOT EXISTS email_cases (
    case_id        TEXT PRIMARY KEY,
    file_id        TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    submitted_at   TEXT NOT NULL,
    analyst        TEXT DEFAULT '',
    status         TEXT DEFAULT 'NEW',
    verdict        TEXT,
    threat_level   TEXT,
    score          INTEGER,
    confidence     INTEGER,
    from_addr      TEXT,
    subject        TEXT,
    source_ip      TEXT,
    spf            TEXT,
    dkim           TEXT,
    dmarc          TEXT,
    risk_narrative TEXT,
    report_json    TEXT,
    analyst_notes  TEXT DEFAULT '',
    webhook_fired  INTEGER DEFAULT 0,
    last_updated   TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    action      TEXT NOT NULL,
    actor       TEXT DEFAULT 'system',
    detail      TEXT
);
'''

VALID_STATUSES = {'NEW', 'IN_PROGRESS', 'ESCALATED', 'CLOSED', 'FALSE_POSITIVE'}


@contextlib.contextmanager
def _case_conn():
    """Thread-safe SQLite context manager for the cases database (WAL mode)."""
    conn = sqlite3.connect(_CASE_DB_PATH, timeout=10, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(CASE_SCHEMA)
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def _audit(conn, case_id: str, action: str, actor: str = "system", detail: str = ""):
    conn.execute(
        "INSERT INTO audit_log (ts, case_id, action, actor, detail) VALUES (?,?,?,?,?)",
        (datetime.now().isoformat(), case_id, action, actor, detail)
    )


def case_save(R: dict, analyst: str = "") -> str:
    """Persist a new analysis result. Returns the generated case_id."""
    case_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    auth = R['auth']
    meta = R['metadata']
    try:
        soar = build_soar_json(R, case_id)
        report_json = json.dumps(soar, default=str)
    except Exception:
        report_json = "{}"
    try:
        with _case_conn() as conn:
            conn.execute('''
                INSERT INTO email_cases
                  (case_id, file_id, sha256, submitted_at, analyst, status,
                   verdict, threat_level, score, confidence,
                   from_addr, subject, source_ip, spf, dkim, dmarc,
                   risk_narrative, report_json, analyst_notes, last_updated)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
                case_id,
                R['hashes']['md5'], R['hashes']['sha256'],
                now, analyst, 'NEW',
                R['verdict'], R['threat_level'], R['score'], R['confidence'],
                meta.get('from', ''), meta.get('subject', ''),
                auth.source_ip or '',
                auth.spf, auth.dkim, auth.dmarc,
                R.get('risk_narrative', ''),
                report_json, '', now
            ))
            _audit(conn, case_id, "CASE_CREATED", analyst or "analyst",
                   f"score={R['score']} verdict={R['verdict']}")
        log.info(f"Case saved: {case_id} (score={R['score']})")
    except Exception as e:
        log.error(f"case_save error: {e}")
    return case_id


def case_get(case_id: str) -> Optional[dict]:
    """Retrieve a case by its UUID."""
    try:
        with _case_conn() as conn:
            row = conn.execute(
                "SELECT * FROM email_cases WHERE case_id=?", (case_id,)
            ).fetchone()
            return dict(row) if row else None
    except Exception as e:
        log.error(f"case_get error: {e}")
        return None


def case_lookup_by_hash(md5: str) -> Optional[dict]:
    """Check if an email with this MD5 was already analyzed. Returns most recent case."""
    try:
        with _case_conn() as conn:
            row = conn.execute(
                "SELECT * FROM email_cases WHERE file_id=? ORDER BY submitted_at DESC LIMIT 1",
                (md5,)
            ).fetchone()
            return dict(row) if row else None
    except Exception as e:
        log.error(f"case_lookup_by_hash error: {e}")
        return None


def case_update(case_id: str, status: str = None, notes: str = None,
                analyst: str = "") -> bool:
    """Update case status and/or analyst notes."""
    if status and status not in VALID_STATUSES:
        return False
    # [FIX-SEC-D]: Unbounded notes allow disk exhaustion via the REST API.
    # Any caller with an API key could push megabytes of data per PATCH
    # request. Cap at 10,000 characters — more than enough for any real note.
    _MAX_NOTES_LEN = 10_000
    if notes is not None and len(notes) > _MAX_NOTES_LEN:
        notes = notes[:_MAX_NOTES_LEN]
    try:
        with _case_conn() as conn:
            if status:
                conn.execute(
                    "UPDATE email_cases SET status=?, last_updated=? WHERE case_id=?",
                    (status, datetime.now().isoformat(), case_id)
                )
                _audit(conn, case_id, "STATUS_CHANGE", analyst or "analyst",
                       f"→ {status}")
            if notes is not None:
                conn.execute(
                    "UPDATE email_cases SET analyst_notes=?, last_updated=? WHERE case_id=?",
                    (notes, datetime.now().isoformat(), case_id)
                )
                _audit(conn, case_id, "NOTES_UPDATED", analyst or "analyst")
        return True
    except Exception as e:
        log.error(f"case_update error: {e}")
        return False


def case_list(status_filter: str = None, limit: int = 50,
              min_score: int = 0) -> list:
    """List cases with optional filters."""
    try:
        with _case_conn() as conn:
            q = "SELECT case_id, file_id, submitted_at, status, verdict, threat_level, score, from_addr, subject FROM email_cases WHERE score >= ?"
            params = [min_score]
            if status_filter and status_filter in VALID_STATUSES:
                q += " AND status=?"
                params.append(status_filter)
            q += " ORDER BY submitted_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(q, params).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"case_list error: {e}")
        return []


def case_stats() -> dict:
    """Return aggregate statistics across all cases."""
    try:
        with _case_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM email_cases").fetchone()[0]
            by_status = {r[0]: r[1] for r in conn.execute(
                "SELECT status, COUNT(*) FROM email_cases GROUP BY status").fetchall()}
            by_verdict = {r[0]: r[1] for r in conn.execute(
                "SELECT verdict, COUNT(*) FROM email_cases GROUP BY verdict").fetchall()}
            high_risk = conn.execute(
                "SELECT COUNT(*) FROM email_cases WHERE score >= 65").fetchone()[0]
            avg_score = conn.execute(
                "SELECT AVG(score) FROM email_cases").fetchone()[0] or 0
            today = conn.execute(
                "SELECT COUNT(*) FROM email_cases WHERE submitted_at >= ?",
                (datetime.now().strftime('%Y-%m-%d'),)
            ).fetchone()[0]
            return {
                'total_cases': total,
                'today': today,
                'high_risk': high_risk,
                'avg_score': round(avg_score, 1),
                'by_status': by_status,
                'by_verdict': by_verdict,
            }
    except Exception as e:
        log.error(f"case_stats error: {e}")
        return {'total_cases': 0, 'today': 0, 'high_risk': 0,
                'avg_score': 0, 'by_status': {}, 'by_verdict': {}}


# ── MITRE ATT&CK Mapper ───────────────────────────────────────────────────────
_MITRE_MAP = {
    'spf_fail':             ('T1566',     'Phishing', 'initial-access'),
    'dkim_fail':            ('T1566',     'Phishing', 'initial-access'),
    'dmarc_fail':           ('T1566',     'Phishing', 'initial-access'),
    'display_name_spoof':   ('T1036',     'Masquerading', 'defense-evasion'),
    'shadow_spoofing':      ('T1036.005', 'Match Legitimate Name or Location', 'defense-evasion'),
    'reply_to_hijack':      ('T1534',     'Internal Spearphishing', 'lateral-movement'),
    'bec_combined':         ('T1657',     'Financial Theft', 'impact'),
    'macro_attachment':     ('T1204.002', 'User Execution: Malicious File', 'execution'),
    'suspicious_attachment':('T1566.001', 'Spearphishing Attachment', 'initial-access'),
    'url_malicious':        ('T1566.002', 'Spearphishing Link', 'initial-access'),
    'link_text_mismatch':   ('T1027',     'Obfuscated Files or Information', 'defense-evasion'),
    'url_shortener':        ('T1027',     'Obfuscated Files or Information', 'defense-evasion'),
    'credential_harvesting':('T1598.003', 'Phishing for Information: Link', 'reconnaissance'),
    'mfa_bypass':           ('T1111',     'Multi-Factor Authentication Interception', 'credential-access'),
    'newly_registered':     ('T1583.001', 'Acquire Infrastructure: Domains', 'resource-development'),
    'dga_subdomain':        ('T1568.002', 'Domain Generation Algorithms', 'command-and-control'),
    'abuse_ip_high':        ('T1071',     'Application Layer Protocol', 'command-and-control'),
    'payment_redirect':     ('T1657',     'Financial Theft', 'impact'),
    'invoice_fraud':        ('T1657',     'Financial Theft', 'impact'),
}

def map_mitre(signals: list) -> list:
    """Map fired ThreatSignals to MITRE ATT&CK techniques (deduplicated)."""
    seen = set()
    techniques = []
    for s in signals:
        if s.probability * s.confidence < 0.04:
            continue
        tech = _MITRE_MAP.get(s.name)
        if tech and tech[0] not in seen:
            seen.add(tech[0])
            techniques.append({
                'technique_id': tech[0],
                'technique_name': tech[1],
                'tactic': tech[2],
                'triggered_by': s.name,
                'signal_title': s.title,
            })
    return techniques


# ── IOC Extractor ─────────────────────────────────────────────────────────────
def extract_iocs(R: dict) -> dict:
    """Return flat IOC lists ready for SIEM / threat-intel ingestion."""
    ips, domains, urls, emails_found, hashes_found = [], [], [], [], {}

    auth = R['auth']
    if auth.source_ip:
        ips.append(auth.source_ip)

    hashes_found['md5']    = R['hashes']['md5']
    hashes_found['sha256'] = R['hashes']['sha256']

    for o in R.get('observables', []):
        if o.type == 'ip' and o.value not in ips:
            ips.append(o.value)
        elif o.type == 'domain' and o.value not in domains:
            domains.append(o.value)
        elif o.type == 'url' and o.value not in urls:
            urls.append(o.value)
        elif o.type == 'email' and o.value not in emails_found:
            emails_found.append(o.value)

    for m in R.get('macros', []):
        if m.sha256 and m.sha256 not in hashes_found.values():
            hashes_found[m.filename or 'attachment'] = m.sha256

    return {
        'ips':     sorted(set(ips)),
        'domains': sorted(set(domains)),
        'urls':    sorted(set(urls)),
        'emails':  sorted(set(emails_found)),
        'hashes':  hashes_found,
    }


# ── SOAR JSON Schema Builder ──────────────────────────────────────────────────
def build_soar_json(R: dict, case_id: str = "") -> dict:
    """
    Build a standardized, SOAR-ready JSON document from an analysis result.
    Schema is stable — fields are always present (empty rather than missing)
    so downstream playbooks can rely on key existence.
    """
    auth = R['auth']
    meta = R['metadata']
    score = R['score']

    # Action mapping
    if score >= 65:
        action = "QUARANTINE"
    elif score >= 40:
        action = "HOLD_FOR_REVIEW"
    elif score >= 18:
        action = "DELIVER_WITH_WARNING"
    else:
        action = "RELEASE"

    # Signals (top 20, filtered)
    sig_list = [
        {
            'name': s.name, 'title': s.title, 'category': s.category,
            'tier': s.tier, 'probability': round(s.probability, 3),
            'confidence': round(s.confidence, 3),
            'impact': round(s.probability * s.confidence, 3),
            'detail': s.detail,
            'evidence': s.evidence or "",
        }
        for s in sorted(R['signals'], key=lambda x: x.probability * x.confidence, reverse=True)
        if not (s.probability == 0.0 and s.name.startswith('bec_') and s.name != 'bec_combined')
    ][:20]

    trust_list = [
        {'name': tf.name, 'strength': round(tf.strength, 3),
         'confidence': round(tf.confidence, 3), 'description': tf.description}
        for tf in R.get('trust_factors', [])
    ]

    attachments = []
    for m in R.get('macros', []):
        if m.filename == '[Body]':
            continue
        attachments.append({
            'filename': m.filename, 'file_type': m.file_type,
            'sha256': m.sha256 or "", 'risk_score': m.risk_score,
            'verdict': m.verdict, 'has_macros': m.has_macros,
            'malwarebazaar_hit': m.mb_found,
            'malwarebazaar_family': m.mb_family or "",
            'yara_matches': [y['rule'] for y in (m.yara_matches or [])],
        })

    obs_list = []
    for o in R.get('observables', []):
        entry = {
            'type': o.type, 'value': o.value, 'defanged': o.defanged,
            'source': o.source, 'is_shortener': o.is_shortener,
            'suspicious_tld': o.suspicious_tld,
            'vt_threat_level': "",
            'vt_malicious_engines': 0,
            'vt_reasoning': "",
        }
        if o.vt:
            entry['vt_threat_level']      = o.vt.threat_level or ""
            entry['vt_malicious_engines'] = o.vt.malicious
            entry['vt_reasoning']         = o.vt.reasoning or ""
        obs_list.append(entry)

    bec = R.get('bec')
    bec_block = {
        'score': round(bec.score, 3) if bec else 0,
        'categories': list(bec.categories) if bec else [],
        'summary': bec.summary if bec else "",
    }

    return {
        'schema_version': '2.0',
        'tool': 'Sherlock Forensic Email Analyzer',
        'case_id': case_id or "",
        'file_id': R['hashes']['md5'],
        'sha256': R['hashes']['sha256'],
        'submitted_at': datetime.now(timezone.utc).isoformat(),
        'verdict': {
            'classification': R['verdict'],
            'threat_level': R['threat_level'],
            'score': score,
            'confidence': R['confidence'],
            'action': action,
            'explanation': R.get('explanation', ''),
            'risk_narrative': R.get('risk_narrative', ''),
        },
        'sender': {
            'from': meta.get('from', ''),
            'subject': meta.get('subject', ''),
            'date': meta.get('date', ''),
            'from_domain': auth.from_domain or '',
            'return_path_domain': auth.rp_domain or '',
            'source_ip': auth.source_ip or '',
            'hop_count': auth.hop_count,
            'hop_anomaly': auth.hop_anomaly or '',
        },
        'authentication': {
            'spf': auth.spf,
            'dkim': auth.dkim,
            'dmarc': auth.dmarc,
            'gateway_detected': auth.gateway_trust,
            'gateway_name': auth.gateway_name or '',
            'shadow_spoof': auth.shadow_spoof,
        },
        'threat_clusters': R.get('active_clusters', {}),
        'mitre_attack': map_mitre(R['signals']),
        'iocs': extract_iocs(R),
        'signals': sig_list,
        'trust_factors': trust_list,
        'bec': bec_block,
        'attachments': attachments,
        'observables': obs_list,
        'correlations': R.get('correlations', []),
        'case': {
            'status': 'NEW',
            'analyst': '',
            'notes': '',
            'webhook_fired': False,
        },
    }


# ── Webhook Notifier ──────────────────────────────────────────────────────────
_WEBHOOK_LOCK = threading.Lock()

def fire_webhook(case_id: str, soar_json: dict) -> bool:
    """
    POST the SOAR JSON to the configured SOAR webhook URL.
    Fires only when score >= Config.WEBHOOK_MIN_SCORE.
    Non-blocking — called in a daemon thread.
    """
    url = Config.SOAR_WEBHOOK_URL
    if not url:
        return False
    score = soar_json.get('verdict', {}).get('score', 0)
    if score < Config.WEBHOOK_MIN_SCORE:
        return False

    def _post():
        try:
            payload = {
                'event': 'SHERLOCK_ALERT',
                'case_id': case_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'score': score,
                'verdict': soar_json.get('verdict', {}),
                'sender': soar_json.get('sender', {}),
                'authentication': soar_json.get('authentication', {}),
                'iocs': soar_json.get('iocs', {}),
                'mitre_attack': soar_json.get('mitre_attack', []),
                'action_required': soar_json['verdict'].get('action', ''),
                'full_report_url': f"http://localhost:{Config.API_PORT}/api/v1/case/{case_id}",
            }
            resp = requests.post(url, json=payload, timeout=10,
                                 headers={'Content-Type': 'application/json',
                                          'X-Sherlock-Key': Config.API_KEY})
            if resp.status_code < 300:
                with _case_conn() as conn:
                    conn.execute(
                        "UPDATE email_cases SET webhook_fired=1 WHERE case_id=?",
                        (case_id,)
                    )
                    _audit(conn, case_id, "WEBHOOK_FIRED", "system",
                           f"HTTP {resp.status_code} → {url}")
                log.info(f"Webhook fired for {case_id}: HTTP {resp.status_code}")
                return True
            else:
                log.warning(f"Webhook failed for {case_id}: HTTP {resp.status_code}")
        except Exception as e:
            log.error(f"Webhook error for {case_id}: {e}")
        return False

    t = threading.Thread(target=_post, daemon=True)
    t.start()
    return True


# ── REST API Server (FastAPI) ─────────────────────────────────────────────────
_api_server_started = False
_api_server_lock    = threading.Lock()

def start_api_server():
    """
    Start the Sherlock SOAR REST API in a daemon background thread using
    Python's stdlib http.server — no uvicorn, no asyncio, no event loops.

    This replaces the previous uvicorn-in-thread approach which produced
    "Error loading ASGI app. Attribute 'app' not found in module '...'"
    on Windows because uvicorn internally re-imports the module by string
    name to resolve the ASGI app, regardless of whether you pass the app
    object directly. The stdlib HTTPServer has none of these issues: it is
    synchronous, runs cleanly in a daemon thread on all platforms, and
    requires zero extra dependencies beyond Python's standard library.

    Endpoints served (same schema as before):
      GET  /                          — welcome JSON, no auth
      GET  /health                    — health check, no auth
      GET  /api/v1/stats              — aggregate statistics
      GET  /api/v1/cases              — list cases (?status=&min_score=&limit=)
      GET  /api/v1/case/{id}          — full case record
      GET  /api/v1/case/{id}/iocs     — flat IOC list
      GET  /api/v1/case/{id}/mitre    — MITRE ATT&CK techniques
      GET  /api/v1/lookup/{md5}       — cache check by email hash
      PATCH /api/v1/case/{id}         — update status/notes (?status=&notes=&analyst=)

    All endpoints except / and /health require header: X-API-Key: <key>
    """
    global _api_server_started
    with _api_server_lock:
        if _api_server_started:
            return
        _api_server_started = True

    def _run():
        from http.server import HTTPServer, BaseHTTPRequestHandler
        from urllib.parse import urlparse, parse_qs

        class _Handler(BaseHTTPRequestHandler):
            # Silence the default per-request log line (we log ourselves)
            def log_message(self, fmt, *args):
                log.debug("API %s", fmt % args)

            def _json(self, data, status=200):
                body = json.dumps(data, default=str).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)

            def _auth(self):
                """Return True if request carries a valid API key."""
                key = self.headers.get("X-API-Key", "")
                if key != Config.API_KEY:
                    self._json({"detail": "Invalid or missing API key. "
                                "Send header: X-API-Key: <key>"}, 403)
                    return False
                return True

            def _parts(self):
                """Return (path_str, query_dict) for this request."""
                parsed = urlparse(self.path)
                qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                return parsed.path.rstrip("/"), qs

            # ── Route dispatch ──────────────────────────────────────────────
            def do_GET(self):
                path, qs = self._parts()

                # Root — welcome / directory
                if path in ("", "/"):
                    self._json({
                        "tool":    "Sherlock Forensic Email Analyzer v13.0",
                        "status":  "online",
                        "note":    ("Streamlit UI → http://localhost:8501  |  "
                                    "REST API → http://localhost:8000"),
                        "auth":    "All endpoints except /health require header X-API-Key",
                        "endpoints": {
                            "health":  "GET /health",
                            "stats":   "GET /api/v1/stats",
                            "cases":   "GET /api/v1/cases[?status=&min_score=&limit=]",
                            "case":    "GET /api/v1/case/{id}",
                            "iocs":    "GET /api/v1/case/{id}/iocs",
                            "mitre":   "GET /api/v1/case/{id}/mitre",
                            "lookup":  "GET /api/v1/lookup/{md5}",
                            "update":  "PATCH /api/v1/case/{id}[?status=&notes=&analyst=]",
                        },
                    })
                    return

                # Health — no auth
                if path == "/health":
                    try:
                        stats = case_stats()
                    except Exception:
                        stats = {"total_cases": 0, "today": 0}
                    self._json({
                        "status":       "ok",
                        "tool":         "Sherlock v13.0",
                        "timestamp":    datetime.now(timezone.utc).isoformat(),
                        "cases_total":  stats.get("total_cases", 0),
                        "cases_today":  stats.get("today", 0),
                    })
                    return

                if not self._auth():
                    return

                # Stats
                if path == "/api/v1/stats":
                    try:
                        self._json(case_stats())
                    except Exception as e:
                        self._json({"detail": str(e)}, 500)
                    return

                # Cases list
                if path == "/api/v1/cases":
                    try:
                        rows = case_list(
                            status_filter=qs.get("status"),
                            limit=min(int(qs.get("limit", 50)), 200),
                            min_score=int(qs.get("min_score", 0)),
                        )
                        self._json({"count": len(rows), "cases": rows})
                    except Exception as e:
                        self._json({"detail": str(e)}, 500)
                    return

                # Case by ID
                import re as _re
                m = _re.match(r"^/api/v1/case/([^/]+)$", path)
                if m:
                    case_id = m.group(1)
                    try:
                        row = case_get(case_id)
                    except Exception as e:
                        self._json({"detail": str(e)}, 500)
                        return
                    if not row:
                        self._json({"detail": f"Case {case_id} not found"}, 404)
                        return
                    try:
                        row["report"] = json.loads(row.pop("report_json") or "{}")
                    except Exception:
                        row["report"] = {}
                    self._json(row)
                    return

                # IOCs for a case
                m = _re.match(r"^/api/v1/case/([^/]+)/iocs$", path)
                if m:
                    case_id = m.group(1)
                    row = case_get(case_id)
                    if not row:
                        self._json({"detail": f"Case {case_id} not found"}, 404)
                        return
                    try:
                        report = json.loads(row.get("report_json") or "{}")
                        iocs = report.get("iocs", {})
                    except Exception:
                        iocs = {}
                    self._json({"case_id": case_id, "iocs": iocs})
                    return

                # MITRE for a case
                m = _re.match(r"^/api/v1/case/([^/]+)/mitre$", path)
                if m:
                    case_id = m.group(1)
                    row = case_get(case_id)
                    if not row:
                        self._json({"detail": f"Case {case_id} not found"}, 404)
                        return
                    try:
                        report = json.loads(row.get("report_json") or "{}")
                        mitre  = report.get("mitre_attack", [])
                    except Exception:
                        mitre = []
                    self._json({"case_id": case_id, "techniques": mitre})
                    return

                # Hash lookup
                m = _re.match(r"^/api/v1/lookup/([^/]+)$", path)
                if m:
                    file_hash = m.group(1)
                    try:
                        row = case_lookup_by_hash(file_hash)
                    except Exception as e:
                        self._json({"detail": str(e)}, 500)
                        return
                    if not row:
                        self._json({"found": False, "file_id": file_hash})
                    else:
                        self._json({
                            "found":        True,
                            "cache_hit":    True,
                            "case_id":      row["case_id"],
                            "verdict":      row["verdict"],
                            "threat_level": row["threat_level"],
                            "score":        row["score"],
                            "status":       row["status"],
                            "submitted_at": row["submitted_at"],
                        })
                    return

                self._json({"detail": f"Not Found: {path}"}, 404)

            def do_PATCH(self):
                path, qs = self._parts()
                if not self._auth():
                    return

                import re as _re
                m = _re.match(r"^/api/v1/case/([^/]+)$", path)
                if not m:
                    self._json({"detail": "Not Found"}, 404)
                    return

                case_id = m.group(1)
                status  = qs.get("status")
                notes   = qs.get("notes")
                analyst = qs.get("analyst", "api")

                if status and status not in VALID_STATUSES:
                    self._json({"detail": f"Invalid status. Valid: {', '.join(VALID_STATUSES)}"}, 400)
                    return
                try:
                    ok = case_update(case_id, status=status, notes=notes, analyst=analyst)
                except Exception as e:
                    self._json({"detail": str(e)}, 500)
                    return
                if not ok:
                    self._json({"detail": f"Case {case_id} not found or update failed"}, 404)
                    return
                self._json({"success": True, "case_id": case_id,
                            "status": status, "notes_updated": notes is not None})

            def do_OPTIONS(self):
                """CORS preflight."""
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, PATCH, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
                self.end_headers()

        try:
            httpd = HTTPServer(("0.0.0.0", Config.API_PORT), _Handler)
            log.info(f"Sherlock REST API ready → http://0.0.0.0:{Config.API_PORT}")
            httpd.serve_forever()
        except OSError as e:
            if getattr(e, "errno", None) in (98, 10048) or "address already in use" in str(e).lower():
                log.warning(f"API port {Config.API_PORT} already in use — skipping API start")
            else:
                log.error(f"API server OSError: {e}")
        except Exception as e:
            log.error(f"API server error: {e}")

    t = threading.Thread(target=_run, name="sherlock-api", daemon=True)
    t.start()
    log.info(f"Sherlock REST API thread launched on port {Config.API_PORT}")


def generate_text_report(report):
    sep = "=" * 90
    L = [sep, "SHERLOCK FORENSIC REPORT v13.0", sep,
         f"Date: {datetime.now():%Y-%m-%d %H:%M:%S}",
         f"MD5: {report['hashes']['md5']}  SHA256: {report['hashes']['sha256']}", "",
         f"VERDICT: {report['verdict']}  |  Score: {report['score']}/100  |  "
         f"Threat: {report['threat_level']}  |  Confidence: {report['confidence']}%", ""]

    # [I03] Risk Narrative — primary analysis output in text report
    narrative = report.get('risk_narrative', '')
    if narrative:
        # Strip markdown bold markers for plain-text report
        narrative_plain = re.sub(r'\*\*(.+?)\*\*', r'\1', narrative)
        L += [sep, "THREAT NARRATIVE", sep, narrative_plain, ""]

    active_clusters = report.get('active_clusters', {})
    if active_clusters:
        L += ["Active Threat Clusters:"]
        for k, v in sorted(active_clusters.items()):
            titles = [s['title'] if isinstance(s, dict) else s for s in v]
            L.append(f"  [{k.replace('_',' ').upper()}]  {', '.join(titles)}")
        L.append("")

    L += [f"Engine Explanation: {report['explanation']}", ""]

    L += [sep, "SIGNALS (sorted by impact)", sep]
    for s in sorted(report['signals'], key=lambda x: x.probability * x.confidence, reverse=True):
        if s.probability == 0.0 and s.name.startswith('bec_') and s.name != 'bec_combined':
            continue
        L.append(f"  [T{s.tier}/{s.category}] {s.title}  p={s.probability:.0%} c={s.confidence:.0%}")
        L.append(f"    {s.detail}")
        if s.evidence:
            L.append(f"    Evidence: {s.evidence}")

    if report['trust_factors']:
        L += ["", sep, "TRUST FACTORS", sep]
        for t in report['trust_factors']:
            L.append(f"  {t.name}: strength={t.strength:.0%} c={t.confidence:.0%} -- {t.description}")

    if report['correlations']:
        L += ["", sep, "CORRELATIONS", sep]
        for c in report['correlations']:
            L.append(f"  {c}")

    auth = report['auth']
    L += ["", sep, "AUTHENTICATION", sep,
          f"SPF: {auth.spf}  DKIM: {auth.dkim}  DMARC: {auth.dmarc}",
          f"Source IP: {auth.source_ip or chr(8212)}  Hops: {auth.hop_count}"]
    if auth.gateway_trust:
        L.append(f"Gateway: {auth.gateway_name}")
    if auth.hop_anomaly:
        L.append(f"Hop anomaly: {auth.hop_anomaly}")

    L += ["", sep, "ATTACHMENTS", sep]
    for m in report['macros']:
        L.append(f"  {m.filename}: {m.file_type} | Risk {m.risk_score}/100 | {m.verdict}")
        if m.mb_found:
            L.append(f"    MALWARE: {m.mb_family}")
        if m.sha256:
            L.append(f"    SHA256: {m.sha256}")

    L += ["", sep, "RECOMMENDATION", sep]
    if report['score'] >= 65:
        L.append("BLOCK / QUARANTINE")
    elif report['score'] >= 40:
        L.append("HOLD FOR MANUAL REVIEW")
    elif report['score'] >= 18:
        L.append("DELIVER WITH WARNING")
    else:
        L.append("RELEASE")
    L.append(sep)
    return '\n'.join(L)


def generate_analyst_report(R):
    """
    Generate a structured analyst report following the standard SOC reporting format.
    Sections: Header & Path | Technical Authentication & Analysis | Attachment & Links | Recommendation
    """
    auth = R['auth']
    meta = R['metadata']
    score = R['score']

    # --- Header & Path ---
    from_addr = meta.get('from', 'Unknown')
    from_domain = auth.from_domain or 'Unknown'
    rp_domain = auth.rp_domain or from_domain
    source_ip = auth.source_ip or 'Unknown'
    gateway = auth.gateway_name or ''

    # Domain reputation text
    if score < 18:
        domain_rep = (f"`{from_domain}` passed all authentication checks and shows no threat indicators. "
                      f"No malicious history detected for this sender domain.")
    elif score < 40:
        domain_rep = (f"`{from_domain}` is under review. Some signals require analyst attention "
                      f"but the domain has not been confirmed malicious.")
    elif score < 65:
        domain_rep = (f"`{from_domain}` exhibits suspicious characteristics. "
                      f"The domain scored {score}/100 on the threat engine.")
    else:
        domain_rep = (f"`{from_domain}` is flagged as HIGH RISK. "
                      f"Multiple threat indicators were detected for this sender domain (score: {score}/100).")

    # --- Technical Authentication & Analysis ---
    spf = auth.spf or 'NONE'
    dkim = auth.dkim or 'NONE'
    dmarc = auth.dmarc or 'NONE'

    # Authentication summary sentence
    auth_parts = []
    if spf == 'PASS':   auth_parts.append("SPF")
    if dkim == 'PASS':  auth_parts.append("DKIM")
    if dmarc == 'PASS': auth_parts.append("DMARC")
    if auth_parts:
        auth_line = f"It passes {' and '.join(auth_parts)} checks."
    else:
        fails = []
        if spf not in ('PASS', 'NONE'):   fails.append(f"SPF: {spf}")
        if dkim not in ('PASS', 'NONE'):  fails.append(f"DKIM: {dkim}")
        if dmarc not in ('PASS', 'NONE'): fails.append(f"DMARC: {dmarc}")
        auth_line = ("Authentication results: " + ", ".join(fails) + ".") if fails else "No authentication results available."

    # Origin line
    gw_note = f" via {gateway}" if gateway else ""
    origin_line = (f"The email originated from Source IP: `{source_ip}`{gw_note}, "
                   f"a {'known delivery service' if gateway else 'remote mail server'} "
                   f"for {'automated platform notifications' if gateway else 'outbound email'}.")

    # Spam / Verdict
    verdict = R['verdict']
    threat_level = R['threat_level']
    if score < 18:
        spam_line = (f"Verdict: {verdict}. The email cleared all threat thresholds (score: {score}/100). "
                     f"If flagged by a local gateway, this is likely a False Positive, possibly due to "
                     f"encoding, bulk-sender IP ranges, or a generic score threshold.")
    elif score < 40:
        spam_line = (f"Verdict: {verdict} (score: {score}/100, threat level: {threat_level}). "
                     f"The email requires analyst review before release.")
    else:
        spam_line = (f"Verdict: {verdict} (score: {score}/100, threat level: {threat_level}). "
                     f"Email should be held or quarantined pending further investigation.")

    # Integrity line (DKIM)
    if dkim == 'PASS':
        integrity_line = (f"The presence of a valid DKIM signature for `{from_domain}` "
                          f"ensures the message content was not altered in transit.")
    elif dkim == 'FAIL':
        integrity_line = (f"DKIM signature validation FAILED for `{from_domain}`. "
                          f"Message integrity cannot be confirmed — content may have been tampered with.")
    else:
        integrity_line = f"DKIM result: {dkim}. Message integrity could not be fully verified."

    # --- Attachment & Links ---
    real_att = [m for m in R['macros'] if m.filename != '[Body]']
    if not real_att:
        att_line = "No attachment was found in the email."
    elif len(real_att) == 1:
        m = real_att[0]
        status = "MALWARE DETECTED" if m.mb_found else ("SUSPICIOUS" if m.has_macros or m.yara_matches else "Clean")
        att_line = f"1 attachment found: `{m.filename}` ({m.file_type}) — Status: {status}."
    else:
        statuses = []
        for m in real_att:
            s = "MALWARE" if m.mb_found else ("SUSPICIOUS" if m.has_macros or m.yara_matches else "Clean")
            statuses.append(f"`{m.filename}` ({s})")
        att_line = f"{len(real_att)} attachments found: {', '.join(statuses)}."

    # Links / Observables
    url_obs = [o for o in R['observables'] if o.type in ('url', 'domain')]
    if not url_obs:
        link_line = "No external links or domains were detected in the email body."
    else:
        threats = [o for o in url_obs if o.vt and o.vt.threat_level in ('CRITICAL', 'MALICIOUS')]
        suspicious = [o for o in url_obs if o.vt and o.vt.threat_level == 'SUSPICIOUS']
        clean = [o for o in url_obs if o.vt and o.vt.threat_level in ('CLEAN', 'LOW')]
        unknown = [o for o in url_obs if not o.vt or o.vt.threat_level == 'UNKNOWN']
        sample_domains = list({o.defanged[:40] for o in url_obs[:3]})
        sample_str = f" (e.g., `{'`, `'.join(sample_domains)}`)" if sample_domains else ""
        if threats:
            link_line = (f"{len(url_obs)} link(s)/domain(s) detected{sample_str}. "
                         f"ALERT: {len(threats)} confirmed malicious URL(s) detected by VirusTotal.")
        elif suspicious:
            link_line = (f"{len(url_obs)} link(s)/domain(s) detected{sample_str}. "
                         f"{len(suspicious)} flagged as suspicious, {len(clean)} clean, {len(unknown)} unknown/unscanned.")
        elif clean:
            link_line = (f"{len(url_obs)} link(s)/domain(s) detected{sample_str}. "
                         f"All scanned links verified as legitimate by VirusTotal.")
        else:
            link_line = (f"{len(url_obs)} link(s)/domain(s) detected{sample_str}. "
                         f"Links were not scanned or returned unknown status.")

    # --- Recommendation ---
    if score < 18:
        rec_line = "Recommend to release the email."
    elif score < 40:
        rec_line = "Recommend to hold for manual analyst review before release."
    elif score < 65:
        rec_line = "Recommend to quarantine the email and notify the recipient."
    else:
        rec_line = "Recommend to BLOCK / QUARANTINE immediately. Do not deliver."

    # Assemble report
    lines = [
        "Header & Path",
        "",
        f"* From and Return-path match: `{from_addr}` / `{rp_domain}`",
        f"* Domain Reputation: {domain_rep}",
        "",
        "",
        "Technical Authentication & Analysis",
        "",
        f"* Authentication: {auth_line}",
        f"* Origin: {origin_line}",
        f"* Spam Identification: {spam_line}",
        f"* Integrity: {integrity_line}",
        "",
        "",
        "Attachment & Links",
        "",
        f"* {att_line}",
        f"* Link Status: {link_line}",
        "",
        "",
        f"* Recommendation: {rec_line}",
    ]
    return '\n'.join(lines)


def generate_pdf_report(text):
    if not PDF_REPORT_OK:
        return None
    try:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter)
        styles = getSampleStyleSheet()
        cs = ParagraphStyle('Code', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
        story = [Paragraph("Sherlock v13.0 Report", styles['Heading1']), Spacer(1, 12)]
        for line in text.split('\n'):
            if '===' in line:
                story.append(Spacer(1, 6))
            elif line.strip():
                story.append(Paragraph(_esc(line).replace(' ', '&nbsp;'), cs))
            else:
                story.append(Spacer(1, 4))
        doc.build(story)
        buf.seek(0)
        return buf
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_email(msg_bytes, status_fn, progress_fn):
    """Main analysis pipeline. Every module feeds signals into the scoring engine."""
    if len(msg_bytes) > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds {MAX_FILE_SIZE // 1024 // 1024}MB")

    msg = email.message_from_bytes(msg_bytes, policy=email.policy.default)
    subject = str(msg.get('Subject', '') or '')
    from_addr = str(msg.get('From', '') or '')

    org_domain = ""
    for hdr in ['Delivered-To', 'To']:
        m = PAT_DOMAIN.search(str(msg.get(hdr, '') or ''))
        if m:
            org_domain = m.group(1).lower()
            break

    # -- Extract bodies --
    status_fn("Extracting content...", "\U0001f50d")
    progress_fn(5)
    html_body = ""
    text_body = ""
    for part in msg.walk():
        ct = part.get_content_type()
        try:
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes) or not payload:
                continue
            decoded = payload.decode('utf-8', 'ignore')
        except Exception:
            continue
        if ct == 'text/html':
            html_body += decoded
        elif ct == 'text/plain':
            text_body += decoded

    visible_text = extract_visible_text(html_body) or text_body
    normalized = normalize_text(visible_text)
    word_count = len(normalized.split())

    # PERF: Body content analysis (tracking pixels, suspicious language) and
    # observable extraction (URL/IP/domain parsing) are fully independent —
    # run them in parallel. extract_observables is often the slowest of the
    # three (it parses every anchor tag and does entropy scoring on each URL).
    status_fn("Extracting observables and scanning body...", "\U0001f517")
    progress_fn(8)
    with ThreadPoolExecutor(max_workers=3) as _body_ex:
        _fut_track = _body_ex.submit(detect_tracking_pixels, html_body)
        _fut_lang  = _body_ex.submit(detect_suspicious_language, visible_text, subject)
        _fut_obs   = _body_ex.submit(extract_observables, msg, html_body, text_body)
        body_findings = _fut_track.result()
        body_findings.extend(_fut_lang.result())
        observables, link_mismatches = _fut_obs.result()
    progress_fn(10)

    # PERF: BEC, header analysis, display-name spoof, and authentication are
    # all independent computations that read from `msg` but never write shared
    # state. Run them concurrently to cut the initial analysis phase roughly in
    # half (auth includes DNS lookups which are the slowest step).
    # Safety: analyze_auth() internally holds _whois_lock for WHOIS calls, and
    # domain_intel() now uses _DOMAIN_INTEL_CACHE with double-checked locking —
    # all concurrent access is properly serialized.
    # PERF 2: AbuseIPDB is also kicked off here. It needs auth.source_ip, so we
    # run auth first in the pool, then use its result to launch AbuseIPDB — all
    # before any other sequential work runs.
    status_fn("Analysing headers, auth, and email structure...", "\U0001f510")
    progress_fn(12)
    abuse_data = {}
    with ThreadPoolExecutor(max_workers=5) as _init_ex:
        _fut_bec   = _init_ex.submit(analyze_bec, visible_text, subject, from_addr, word_count)
        _fut_hdrs  = _init_ex.submit(analyze_headers, msg)
        _fut_auth  = _init_ex.submit(analyze_auth, msg)
        _fut_spoof = _init_ex.submit(check_display_spoof, msg, org_domain)
        bec                              = _fut_bec.result()
        anomalies, reply_hijack          = _fut_hdrs.result()
        auth                             = _fut_auth.result()
        spoof_result, spoof_dn, spoof_sd = _fut_spoof.result()
        # AbuseIPDB needs auth.source_ip — submit it now while pool is still open
        # so it overlaps with the overhead of winding down the other futures.
        if auth.source_ip:
            status_fn(f"IP reputation: {auth.source_ip}", "\U0001f310")
            _fut_abuse = _init_ex.submit(check_abuseipdb, auth.source_ip)
        else:
            _fut_abuse = None
        if _fut_abuse:
            abuse_data = _fut_abuse.result()
    progress_fn(32)

    # -- VT scanning --
    # FIX(S5): Prioritize observables by suspicion before applying the cap.
    # Original took the first 25 in discovery order — a malicious link at
    # position 26 in a newsletter got zero VT coverage. Now: shorteners first,
    # then suspicious TLDs, then high-entropy paths, then the rest.
    vt_candidates = [o for o in observables if o.type in ('url', 'domain', 'ip')]
    def _obs_priority(o):
        score = 0
        if o.is_shortener:
            score += 100
        if o.suspicious_tld:
            score += 80
        # [FIX-SEC]: Redirect wrapper URLs get HIGH priority — they contain the
        # real attack URL as an inner observable. The wrapper itself must be
        # scanned to catch cases where the wrapper domain is newly registered
        # or has AbuseIPDB hits. Inner URLs are added as 'gateway_inner' source
        # observables and will be sorted separately by their own attributes.
        if o.is_wrapper:
            score += 75
        if o.path_entropy > 4.5:
            score += 60
        if o.type == 'ip':
            score += 40
        if o.source in ('pdf_uri', 'office_link', 'qr', 'gateway_inner'):
            score += 30
        return -score  # negative for descending sort
    vt_candidates.sort(key=_obs_priority)
    to_check = vt_candidates[:MAX_OBS]
    if to_check:
        total = len(to_check)
        _ti_lock = threading.Lock()
        done_ti  = [0]

        # PERF: Two-pool TI architecture.
        #
        # PROBLEM WITH THE PREVIOUS SINGLE-POOL APPROACH:
        # When _enrich_observable() did VT → OTX → X-Force in sequence per worker,
        # the VTLimiter (15s gap between requests on free tier) blocked the ENTIRE
        # worker thread. That meant OTX/X-Force for observable #2 couldn't start
        # until after observable #1's 15s VT wait completed — no real parallelism.
        #
        # THE FIX — two separate pools:
        #   Pool A (VT, 4 workers): rate-limited by _vt_lim, processes observables
        #     one by one at 15-second intervals as the free-tier allows.
        #   Pool B (OTX + X-Force, 8 workers): NO rate limiting, fires all 25
        #     observables simultaneously the moment analysis starts. Completes
        #     in ~1-2 seconds total (just network latency) while VT is still warming up.
        #
        # Net effect: OTX/X-Force enrichment is essentially free (overlaps with
        # the mandatory VT wait). For 25 observables on free-tier VT this saves
        # roughly 25 × 2s = 50 seconds of sequential OTX/X-Force time.

        status_fn(f"Scanning {total} observable(s) with VT + OTX + X-Force (parallel)...", "\U0001f50d")

        def _apply_scores(o):
            """Merge all TI results into threat_score and reputation."""
            if o.vt and o.vt.success:
                if o.vt.threat_level in ('CRITICAL', 'MALICIOUS'):
                    o.threat_score = 100; o.reputation = 'malicious'
                elif o.vt.threat_level == 'SUSPICIOUS':
                    o.threat_score = 50;  o.reputation = 'suspicious'
                else:
                    o.reputation = 'clean'
            otx_level = (o.otx or {}).get('threat_level', '')
            if otx_level == 'CRITICAL' and o.threat_score < 100:
                o.threat_score = max(o.threat_score, 80); o.reputation = 'malicious'
            elif otx_level == 'HIGH' and o.threat_score < 80:
                o.threat_score = max(o.threat_score, 60)
                if o.reputation == 'clean': o.reputation = 'suspicious'
            xf_level = (o.xforce or {}).get('threat_level', '')
            if xf_level == 'CRITICAL' and o.threat_score < 100:
                o.threat_score = max(o.threat_score, 80); o.reputation = 'malicious'
            elif xf_level == 'HIGH' and o.threat_score < 80:
                o.threat_score = max(o.threat_score, 60)
                if o.reputation == 'clean': o.reputation = 'suspicious'

        def _enrich_otx_xforce(o):
            """Pool B worker: OTX + X-Force with no rate limit — runs immediately."""
            kind = o.type if o.type in ('ip', 'domain', 'url') else None
            if not kind:
                return
            try:
                o.otx = check_otx(kind, o.value)
            except Exception:
                pass
            if Config.XFORCE_KEY and Config.XFORCE_SECRET:
                try:
                    o.xforce = check_xforce(kind, o.value)
                except Exception:
                    pass

        # Fire Pool B immediately — completes while VT is still waiting on rate limit
        with ThreadPoolExecutor(max_workers=8) as otx_ex:
            otx_futs = {otx_ex.submit(_enrich_otx_xforce, o): o for o in to_check}
            # Pool A: VT, rate-limited — runs concurrently with Pool B
            with ThreadPoolExecutor(max_workers=4) as vt_ex:
                vt_futs = {vt_ex.submit(check_vt, o.type, o.value): o for o in to_check}
                for f in as_completed(vt_futs):
                    o = vt_futs[f]
                    try:
                        o.vt = f.result()
                    except Exception:
                        pass
                    with _ti_lock:
                        done_ti[0] += 1
                        tl   = o.vt.threat_level if (o.vt and o.vt.success) else "..."
                        icon = _ti(tl) if tl != "..." else "\U0001f50d"
                        status_fn(f"[{done_ti[0]}/{total}] {o.type}: {o.defanged[:45]} -> {icon} {tl}", "\U0001f50d")
                        progress_fn(32 + int(done_ti[0] / total * 25))
            # Wait for OTX/X-Force pool to finish (usually already done)
            for f in as_completed(otx_futs):
                try: f.result()
                except Exception: pass
        status_fn("Merging threat intelligence scores...", "\U0001f4ca")
        # Score each observable now that all TI sources have completed
        for o in to_check:
            _apply_scores(o)
        progress_fn(62)

    else:
        status_fn("No observables to scan", "\u2139\ufe0f")
        progress_fn(62)

    # -- Attachments --
    status_fn("Scanning attachments (YARA + Macros + Forensics)...", "\U0001f4ce")
    macros = []

    # PERF: Pre-collect all attachment payloads, then scan in parallel.
    # analyze_attachment() is fully stateless (input bytes → output MacroResult),
    # so it is safe to run concurrently. Serial scanning was the bottleneck for
    # emails with multiple PDFs — each could take up to 10s (2 × 5s timeout).
    _att_parts = []
    # FIX(v16-A): Robust attachment filename extraction with 3-level fallback.
    # Python email.message.get_filename() only reads Content-Disposition: filename=
    # Many email clients (Outlook/Exchange) attach PDFs using:
    #   Content-Disposition: inline  (no filename= in the disposition)
    #   Content-Type: application/pdf; name="report.pdf"
    # get_filename() returns None for these → they were silently skipped,
    # causing real PDF attachments to show "No file attachments to analyze".
    _BINARY_CTYPES = {
        "application/pdf": ".pdf",
        "application/msword": ".doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
        "application/vnd.ms-excel": ".xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
        "application/vnd.ms-powerpoint": ".ppt",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
        "application/zip": ".zip", "application/x-zip-compressed": ".zip",
        "application/x-rar-compressed": ".rar", "application/octet-stream": ".bin",
        "application/x-msdownload": ".exe", "application/x-dosexec": ".exe",
    }
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type().startswith("image/"):
            continue   # images handled below
        fname = part.get_filename()                               # Level 1: standard
        if not fname:
            fname = part.get_param("name", header="content-type") # Level 2: CT name=
        if not fname:
            # Level 3: known binary MIME type → synthesize a filename so the
            # attachment still gets scanned even without a proper filename header.
            ct = part.get_content_type()
            cd = (part.get_content_disposition() or "").lower()
            if ct in _BINARY_CTYPES:
                try:
                    probe = part.get_payload(decode=True)
                    if isinstance(probe, bytes) and len(probe) > 64:
                        fname = f"attachment_inline{_BINARY_CTYPES[ct]}"
                except Exception:
                    pass
        if not fname:
            continue
        try:
            data = part.get_payload(decode=True)
            if isinstance(data, bytes) and data:
                _att_parts.append((data, fname))
        except Exception as e:
            log.error(f"Attachment read {fname}: {e}")

    _att_lock    = threading.Lock()
    _att_obs_new = []   # thread-safe accumulator for new observables from PDFs

    def _scan_attachment(data, fname):
        macro      = analyze_attachment(data, fname)
        uri_source = 'pdf_uri' if macro.file_type == 'PDF' else 'office_link'
        new_obs    = []
        if macro.pdf_uris:
            for u in macro.pdf_uris:
                if u.startswith('http'):
                    uo = Observable(type='url', value=u, defanged=defang(u), source=uri_source)
                    uo.vt = check_vt('url', u)
                    # FIX(v15-04): attachment-embedded URLs were missing OTX and
                    # X-Force enrichment entirely — only VT was called. Omitting
                    # these means any OTX/X-Force malicious indicators for URLs
                    # inside PDFs or Office docs were silently dropped from scoring.
                    if Config.OTX_KEY:
                        try:
                            uo.otx = check_otx('url', u)
                        except Exception:
                            pass
                    if Config.XFORCE_KEY and Config.XFORCE_SECRET:
                        try:
                            uo.xforce = check_xforce('url', u)
                        except Exception:
                            pass
                    # Use the canonical scorer so all three TI sources are merged
                    # consistently — inline ad-hoc scoring was diverging from
                    # the main pipeline's _apply_scores() logic.
                    _apply_scores(uo)
                    new_obs.append(uo)
        return macro, new_obs

    if len(_att_parts) <= 1:
        # No parallelism overhead for single attachments
        for data, fname in _att_parts:
            status_fn(f"Analyzing: {fname}", "\U0001f4ce")
            try:
                macro, new_obs = _scan_attachment(data, fname)
                macros.append(macro)
                if new_obs:
                    status_fn(f"Scanning {len(new_obs)} embedded URI(s) from {fname}...", "\U0001f517")
                observables.extend(new_obs)
            except Exception as e:
                log.error(f"Attachment {fname}: {e}")
    else:
        status_fn(f"Scanning {len(_att_parts)} attachment(s) in parallel...", "\U0001f4ce")
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(_scan_attachment, d, f): (d, f) for d, f in _att_parts}
            for fut in as_completed(futs):
                _, fname = futs[fut]
                try:
                    macro, new_obs = fut.result()
                    with _att_lock:
                        macros.append(macro)
                        observables.extend(new_obs)
                    if new_obs:
                        status_fn(f"  {fname}: {len(new_obs)} embedded URI(s) scanned", "\U0001f517")
                except Exception as e:
                    log.error(f"Attachment {fname}: {e}")

    attachment_risks = get_attachment_risks(msg)

    if YARA_OK and visible_text:
        body_yara = _yara_scan(visible_text.encode('utf-8', 'ignore'), 'email_body')
        if body_yara:
            bm = MacroResult(filename="[Body]", file_type="HTML/Text",
                             yara_matches=body_yara, verdict=f"YARA: {body_yara[0]['rule']}")
            macros.append(bm)

    # FIX(AUDIT-01): _yara_scan_email() was defined but never called.
    # Cofense email-level rules (CY_PDC_Phish_*, CY_BEC_*, PM_Labs_*)
    # target header/routing patterns in raw email bytes. Without this call,
    # those rules were silently ignored — only body text and attachments
    # were scanned. _yara_scan_email() excludes _ATTACHMENT_ONLY_RULES to
    # prevent FP from base64-encoded attachment content in the raw stream.
    if YARA_OK and msg_bytes:
        email_yara = _yara_scan_email(msg_bytes)
        if email_yara:
            em = MacroResult(filename="[Email]", file_type="Raw Email",
                             yara_matches=email_yara,
                             verdict=f"YARA: {email_yara[0]['rule']}")
            macros.append(em)

    progress_fn(80)

    # -- Images + OCR --
    status_fn("Performing image forensics + OCR...", "\U0001f5bc\ufe0f")
    images = []
    ocr_bec_hits = 0
    for part in msg.walk():
        if part.get_content_type().startswith('image/'):
            img_fname = part.get_filename() or "image"
            status_fn(f"Scanning image: {img_fname}", "\U0001f5bc\ufe0f")
            try:
                img = analyze_image(part)
                if img:
                    images.append(img)
                    for qr in img.qr_links:
                        qo = Observable(type='url', value=qr, defanged=defang(qr), source='qr')
                        qo.vt = check_vt('url', qr)
                        if Config.OTX_KEY:
                            qo.otx = check_otx('url', qr)
                        if Config.XFORCE_KEY and Config.XFORCE_SECRET:
                            qo.xforce = check_xforce('url', qr)
                        # FIX(v15-05): replace ad-hoc inline scoring with the
                        # canonical _apply_scores() to stay consistent with the
                        # main observable pipeline (same VT/OTX/X-Force merge logic).
                        _apply_scores(qo)
                        observables.append(qo)
                    if img.ocr_text:
                        ocr_bec = analyze_bec(img.ocr_text, "", "", len(img.ocr_text.split()))
                        if ocr_bec.score >= 0.25:
                            ocr_bec_hits += 1
            except Exception:
                pass
    progress_fn(90)

    # -- Generate signals --
    status_fn("Computing verdict...", "\u2696\ufe0f")
    signals, trust_factors = generate_signals(
        auth, anomalies, reply_hijack, bec, spoof_result, spoof_dn, spoof_sd,
        observables, macros, images, body_findings, link_mismatches,
        abuse_data, attachment_risks, ocr_bec_hits)

    scoring = run_scoring_engine(signals, trust_factors)

    if auth.from_domain:
        record_sender_if_clean(auth.from_domain, scoring.score < 18)

    # [I03] Build risk narrative
    risk_narrative = build_risk_narrative(
        scoring.signals, scoring.trust_factors, auth, scoring.score)

    progress_fn(100)
    status_fn(f"Done! Verdict: {scoring.verdict}", "\u2705")
    time.sleep(0.3)

    return {
        'verdict': scoring.verdict, 'threat_level': scoring.threat_level,
        'score': scoring.score, 'confidence': scoring.confidence,
        'analysis_confidence': scoring.analysis_confidence,
        'explanation': scoring.explanation,
        'risk_narrative': risk_narrative,
        'active_clusters': {
            k: [{'name': s.name, 'title': s.title,
                 'prob': round(s.probability, 3), 'conf': round(s.confidence, 3)}
                for s in v]
            for k, v in _detect_clusters(scoring.signals).items()},
        'signals': scoring.signals, 'trust_factors': scoring.trust_factors,
        'correlations': scoring.correlations_applied,
        'dampening': scoring.dampening_applied,
        # ── Score Breakdown (Feature 1) ────────────────────────────────────────
        'score_breakdown': {
            'signal_contributions':  scoring.signal_contributions,
            'pre_cluster_score':     round(scoring.pre_cluster_score * 100, 1),
            'pre_dampen_score':      round(scoring.pre_dampen_score  * 100, 1),
            'final_score':           scoring.score,
            'cluster_contributions': scoring.cluster_contributions,
            'cluster_signal_subtotals': scoring.cluster_signal_subtotals,
            'dampening_contributions': scoring.dampening_contributions,
        },
        'dominant_vector': scoring.dominant_vector,
        'auth': auth, 'bec': bec, 'observables': observables,
        'macros': macros, 'images': images,
        'link_mismatches': link_mismatches,
        'body_findings': body_findings,
        'attachment_risks': attachment_risks,
        'abuse_data': abuse_data,
        'anomalies': anomalies, 'reply_hijack': reply_hijack,
        'spoof': spoof_result, 'spoof_dn': spoof_dn, 'spoof_sd': spoof_sd,
        'hashes': {'md5': hashlib.md5(msg_bytes, usedforsecurity=False).hexdigest(),
                   'sha256': hashlib.sha256(msg_bytes).hexdigest()},
        'metadata': {'from': str(msg.get('From', '')), 'subject': subject,
                     'date': str(msg.get('Date', ''))},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# REASONING CARD GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

DC = {
    # Severity — semantically distinct, never identical between adjacent levels
    'critical': '#ef4444',   # red        — confirmed malicious / critical severity
    'high':     '#f97316',   # orange     — likely malicious / high severity
    'medium':   '#eab308',   # amber      — suspicious / medium (was pale #f1fa8c, unreadable)
    'low':      '#64748b',   # slate grey — low risk (was #50fa7b green, same as 'safe')
    'safe':     '#22c55e',   # green      — clean / safe (now distinct from 'low')
    # UI chrome
    'unknown':  '#94a3b8', 'bg': '#0f172a', 'card': '#1e293b',
    'elev':     '#2d3748',  'border': '#334155', 'accent': '#38bdf8', 'purple': '#8b5cf6',
    'text1':    '#e2e8f0',  'text2': '#94a3b8', 'ok': '#10b981', 'warn': '#f59e0b', 'err': '#ef4444',
}
SHADOW = '0 4px 6px -1px rgba(0,0,0,0.3)'


def _tc(level):
    """Map threat/verdict level to UI color.
    
    Semantic rules enforced here:
      MALICIOUS          → red   (confirmed threat, highest severity)
      LIKELY MALICIOUS   → orange (probable threat, NOT identical to confirmed)
      SUSPICIOUS/MEDIUM  → amber  (elevated concern)
      REVIEW/LOW         → slate  (worth checking, NOT green like safe)
      CLEAN/SAFE         → green  (verified clean)
    """
    return {
        'CRITICAL':        DC['critical'],   # red
        'MALICIOUS':       DC['critical'],   # red
        'LIKELY MALICIOUS':DC['high'],       # orange — probable but not confirmed
        'HIGH':            DC['high'],       # orange
        'SUSPICIOUS':      DC['medium'],     # amber
        'MEDIUM':          DC['medium'],     # amber
        'LOW':             DC['low'],        # slate — NOT green, distinct from SAFE
        'REVIEW':          DC['accent'],     # blue  — needs attention, not dangerous
        'CLEAN':           DC['safe'],       # green
        'SAFE':            DC['safe'],       # green
    }.get((level or '').upper(), DC['unknown'])


def _ti(level):
    """FIX(C18): Added 'LIKELY MALICIOUS' and 'REVIEW' verdict mappings."""
    return {
        'CRITICAL': '\U0001f6a8', 'MALICIOUS': '\U0001f6a8',
        'LIKELY MALICIOUS': '\U0001f6a8',
        'HIGH': '\u26a0\ufe0f', 'SUSPICIOUS': '\u26a0\ufe0f', 'MEDIUM': '\u26a0\ufe0f',
        'LOW': '\U0001f4cb', 'REVIEW': '\U0001f4cb',
        'CLEAN': '\u2705', 'SAFE': '\u2705',
    }.get((level or '').upper(), '\u2753')


def _card(icon, title, body, detail, color):
    """Render a single reasoning card."""
    body_html = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', _esc(body))
    return (
        f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
        f"border:1px solid {color}44;border-left:4px solid {color};"
        f"border-radius:10px;padding:14px 16px;margin:6px 0;box-shadow:{SHADOW}'>"
        f"<div style='font-weight:700;color:{color};margin-bottom:6px;font-size:.95em'>"
        f"{icon} {_esc(title)}</div>"
        f"<div style='color:{DC['text1']};font-size:.88em;margin-bottom:6px;line-height:1.5'>"
        f"{body_html}</div>"
        f"<div style='color:{DC['text2']};font-size:.76em;border-top:1px solid {DC['border']};"
        f"padding-top:5px;margin-top:4px'>{_esc(detail[:160])}</div></div>"
    )


def build_reasoning_cards(R):
    """Build analytical reasoning cards from report data."""
    cards = []
    auth = R['auth']
    abuse = R.get('abuse_data', {})

    if auth.shadow_spoof and R.get('spoof'):
        cards.append(('\U0001f464', 'Sender Identity',
            f"\U0001f6a8 **Double identity deception** -- display name impersonation AND Return-Path "
            f"routes replies to **{auth.rp_domain}** instead of **{auth.from_domain}**. "
            f"The recipient sees a trusted name; replies go to the attacker.",
            f"From: {auth.from_full[:70]} | Return-Path: {auth.rp_domain}", DC['critical']))
    elif auth.shadow_spoof:
        cards.append(('\U0001f464', 'Sender Identity',
            f"\u26a0\ufe0f **Return-Path mismatch** -- email appears from **{auth.from_domain}** "
            f"but replies route to **{auth.rp_domain}**.",
            f"From: {auth.from_full[:70]}", DC['critical']))
    elif R.get('spoof'):
        cards.append(('\U0001f464', 'Sender Identity',
            f"\U0001f6a8 **Display name impersonation** -- {R['spoof']}",
            f"Domain: {R.get('spoof_sd', '')}", DC['high']))
    else:
        cards.append(('\U0001f464', 'Sender Identity',
            f"\u2705 **Sender identity consistent** -- From, Return-Path, and envelope all "
            f"align to **{auth.from_domain or 'unknown'}**. No identity deception detected.",
            f"From: {auth.from_full[:70]}", DC['ok']))

    if auth.spf == 'FAIL' and auth.dmarc == 'FAIL':
        abody = ("\U0001f6a8 **Authentication failure** -- SPF confirms unauthorized sender, "
                 "DMARC violation means domain policy breached.")
        acol = DC['critical']
    elif auth.spf == 'FAIL':
        abody = f"\u26a0\ufe0f **Unauthorized sender** -- server NOT in **{auth.from_domain}**'s SPF record."
        acol = DC['critical']
    elif auth.spf == 'SOFTFAIL':
        abody = f"\u26a0\ufe0f **SPF softfail** -- sender not fully authorized by **{auth.from_domain}**."
        acol = DC['warn']
    elif auth.spf == 'PASS' and auth.dkim == 'PASS' and auth.dmarc == 'PASS':
        abody = "\u2705 **Full authentication chain intact** -- SPF, DKIM, and DMARC all pass."
        acol = DC['ok']
    elif auth.spf == 'PASS' and auth.dkim == 'PASS':
        abody = "\u2705 **SPF + DKIM pass** -- sender verified, message unmodified."
        acol = DC['ok']
    else:
        abody = f"SPF: {auth.spf} | DKIM: {auth.dkim} | DMARC: {auth.dmarc}"
        acol = DC['accent']
    if auth.gateway_trust:
        abody += f" \U0001f6e1\ufe0f Trusted gateway **{auth.gateway_name}** pre-screened this message."
    det = ""
    if auth.live_verified:
        sp = auth.live_spf.get('status', chr(8212))
        dm = auth.live_dmarc.get('status', chr(8212))
        dp = auth.live_dmarc.get('policy', '')
        det = f"Live DNS -- SPF: {sp} | DMARC: {dm}" + (f" (policy={dp})" if dp else "")
    else:
        det = "Live DNS offline -- install dnspython for verification"
    cards.append(('\U0001f510', 'Authentication & DNS', abody, det, acol))

    if auth.source_ip and abuse:
        ascore = abuse.get('abuseConfidenceScore', 0)
        if ascore >= 75:
            cards.append(('\U0001f310', 'Source IP Reputation',
                f"\U0001f6a8 **High-confidence malicious IP** -- {abuse.get('totalReports', 0)} abuse reports, "
                f"{ascore}/100 AbuseIPDB." + (" **TOR exit node.**" if abuse.get('isTor') else ""),
                f"ISP: {abuse.get('isp', chr(8212))} | Country: {abuse.get('countryCode', chr(8212))}",
                DC['critical']))
        elif ascore >= 40:
            cards.append(('\U0001f310', 'Source IP Reputation',
                f"\u26a0\ufe0f **Elevated risk** -- {abuse.get('totalReports', 0)} reports ({ascore}/100).",
                f"ISP: {abuse.get('isp', chr(8212))}", DC['high']))
        else:
            cards.append(('\U0001f310', 'Source IP Reputation',
                f"\u2705 **IP clean** -- {ascore}/100 across 90-day lookback.",
                f"ISP: {abuse.get('isp', chr(8212))} | Country: {abuse.get('countryCode', chr(8212))}", DC['ok']))
    elif auth.source_ip:
        cards.append(('\U0001f310', 'Source IP Reputation',
            f"\u2139\ufe0f **No reputation data** for {auth.source_ip}.",
            "Add abuseipdb_key to secrets.toml", DC['accent']))

    ltms = R.get('link_mismatches', [])
    real_ltm = [m for m in ltms if not m.is_tracking]
    # Deduplicate for card display
    seen_pairs = set()
    unique_ltm = []
    for m in real_ltm:
        pair = (m.display_domain, m.href_domain)
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            unique_ltm.append(m)
    if unique_ltm:
        cards.append(('\U0001f517', 'Link-Text Mismatches',
            f"\U0001f6a8 **{len(unique_ltm)} unique mismatch(es)** -- displayed domain differs from actual link.",
            f"e.g. Shows '{unique_ltm[0].display_domain}' -> links to '{unique_ltm[0].href_domain}'",
            DC['critical']))

    real_att = [m for m in R['macros'] if m.filename != '[Body]']
    if real_att:
        mb = sum(1 for m in real_att if m.mb_found)
        yr = sum(len(m.yara_matches) for m in real_att)
        risks = len(R.get('attachment_risks', []))
        # Also catch PDFs/files with suspicious tags (has_macros) that have no YARA hit
        suspicious_tags = [m for m in real_att if m.has_macros and not m.yara_matches and not m.mb_found]
        if mb:
            fam = next((m.mb_family for m in real_att if m.mb_found), 'Unknown')
            cards.append(('\U0001f4ce', 'Attachments',
                f"\U0001f6a8 **Confirmed malware** -- SHA256 matches MalwareBazaar: **{fam}**.",
                f"{len(real_att)} file(s) scanned", DC['critical']))
        elif yr:
            top = next((y['rule'] for m in real_att for y in m.yara_matches), '')
            cards.append(('\U0001f4ce', 'Attachments',
                f"\u26a0\ufe0f **YARA match** -- {yr} rule(s) fired, top: **{top}**.",
                f"{len(real_att)} file(s)", DC['high']))
        elif suspicious_tags:
            # PDFs with /OpenAction, /JavaScript, /Launch etc. — has_macros but no YARA rule matched
            tag_files = ', '.join(m.filename for m in suspicious_tags[:2])
            tag_details = '; '.join(d for m in suspicious_tags for d in m.details[:2])
            cards.append(('\U0001f4ce', 'Attachments',
                f"\u26a0\ufe0f **{len(suspicious_tags)} file(s) with suspicious content tags** -- "
                f"dangerous PDF/document actions detected: {tag_details[:80]}.",
                f"Files: {tag_files}", DC['warn']))
        elif risks:
            cards.append(('\U0001f4ce', 'Attachments',
                f"\u26a0\ufe0f **{risks} structural risk(s)** -- deceptive file structure detected.",
                f"{len(real_att)} file(s)", DC['warn']))
        else:
            cards.append(('\U0001f4ce', 'Attachments',
                f"\u2705 **All {len(real_att)} attachment(s) clean**.",
                "", DC['ok']))

    # ── Image Forensics reasoning card ──────────────────────────────────────
    # Reports image scan results (PIL/OCR/stegano) in the Reasoning section.
    # All four cases covered: steganography, QR phishing, OCR BEC, and clean.
    _img_list = R.get('images', [])
    if _img_list:
        _img_steg    = [img for img in _img_list if img.has_steg]
        _img_qr      = [img for img in _img_list if img.qr_links]
        _img_ocr_bec = next(
            (s.evidence for s in R.get('signals', []) if s.name == 'ocr_bec'), None)
        if _img_steg:
            _steg_files = ', '.join(img.filename for img in _img_steg[:2])
            cards.append(('🖼️', 'Image Forensics',
                f"🚨 **Steganography detected** in {len(_img_steg)} image(s) -- "
                f"hidden data embedded in pixel channels. Classic covert exfiltration channel.",
                f"File(s): {_steg_files}", DC['critical']))
        elif _img_qr:
            _qr_sample = next((l for img in _img_qr for l in img.qr_links), '')
            cards.append(('🖼️', 'Image Forensics',
                f"⚠️ **QR code phishing link(s) found** in {len(_img_qr)} image(s) -- "
                f"QR codes bypass conventional link scanners and are used in credential-harvesting campaigns.",
                f"URL: {_qr_sample[:60]}", DC['high']))
        elif _img_ocr_bec:
            cards.append(('🖼️', 'Image Forensics',
                f"⚠️ **BEC/phishing language detected via OCR** -- attacker embedded "
                f"persuasive text inside an image to evade body-content filters.",
                _img_ocr_bec[:80], DC['high']))
        else:
            cards.append(('🖼️', 'Image Forensics',
                f"✅ **All {len(_img_list)} image(s) clean** -- "
                f"no steganography, QR phishing links, or suspicious OCR text detected.",
                f"{len(_img_list)} scanned (PIL / OCR)", DC['ok']))

    url_obs = [o for o in R['observables'] if o.type in ('url', 'domain') and o.vt]
    if url_obs:
        threats = [o for o in url_obs if o.vt.threat_level in ('CRITICAL', 'MALICIOUS')]
        clean = [o for o in url_obs if o.vt.threat_level in ('CLEAN', 'LOW')]
        if threats:
            cards.append(('\U0001f30d', 'URLs & Domains',
                f"\U0001f6a8 **{len(threats)} malicious URL(s)** confirmed by VirusTotal.",
                f"{len(url_obs)} scanned", DC['critical']))
        elif len(clean) == len(url_obs):
            cards.append(('\U0001f30d', 'URLs & Domains',
                f"\u2705 **All {len(clean)} URL(s) verified clean** by VirusTotal.",
                f"{len(url_obs)} scanned", DC['ok']))
        else:
            cards.append(('\U0001f30d', 'URLs & Domains',
                f"\U0001f4ca **{len(url_obs)} observable(s)** scanned -- {len(threats)} threats, "
                f"{len(clean)} clean.",
                "", DC['accent']))

    bec_data = R.get('bec')
    if bec_data and bec_data.score >= 0.25:
        cats = bec_data.categories
        if 'wire_transfer' in cats and 'urgency' in cats:
            bbody = "\U0001f6a8 **Classic wire fraud** -- urgent wire transfer language detected."
        elif 'gift_cards' in cats:
            bbody = "\U0001f6a8 **Gift card scam** -- requests for gift card purchases."
        elif 'payment_redirect' in cats:
            bbody = "\U0001f6a8 **Payment redirect** -- bank details change requested."
        else:
            bbody = bec_data.summary
        bcol = DC['critical'] if bec_data.score >= 0.6 else DC['high']
        cards.append(('\U0001f3af', 'BEC / Social Engineering', bbody,
            f"Score: {bec_data.score:.0%} | Categories: {', '.join(cats)}", bcol))

    total_obs = len(R['observables'])
    vt_ok = sum(1 for o in R['observables'] if o.vt and o.vt.success)
    _real_macros_for_card = [m for m in R['macros'] if m.filename != '[Body]']
    _yara_mb_hits = sum(
        len(m.yara_matches) + (1 if m.mb_found else 0)
        for m in _real_macros_for_card
    )
    cards.append(('\U0001f4ca', 'Scan Coverage',
        f"\U0001f4ca **{total_obs} observables** analyzed -- VT: {vt_ok}/{total_obs} | "
        f"**{len(_real_macros_for_card)}** file(s) scanned | "
        f"**{_yara_mb_hits}** YARA/MalwareBazaar hit(s) | "
        f"**{len(R.get('images', []))}** image(s) via PIL + OCR.",
        f"AbuseIPDB: {'active' if abuse else 'not configured'} | "
        f"{'YARA active' if YARA_OK else 'YARA offline'}", DC['accent']))

    return cards


# ═══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    st.set_page_config(page_title="Sherlock v13.0", layout="wide", page_icon="\U0001f50d")
    st.markdown(f"""<style>
.main{{background:linear-gradient(135deg,{DC['bg']} 0%,#1a1f2e 100%)}}
.stProgress > div > div > div > div{{background-image:linear-gradient(90deg,{DC['accent']},{DC['purple']},{DC['high']});border-radius:10px}}
.stTabs [data-baseweb="tab-list"]{{gap:6px;background:{DC['card']};padding:8px;border-radius:10px}}
.stTabs [data-baseweb="tab"]{{border-radius:8px;padding:10px 18px}}
.stTabs [aria-selected="true"]{{background:linear-gradient(135deg,{DC['accent']},{DC['purple']});box-shadow:0 0 20px rgba(59,130,246,0.3)}}
[data-testid="stMetricValue"]{{font-size:2em;font-weight:700;background:linear-gradient(135deg,{DC['accent']},{DC['purple']});-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
</style>""", unsafe_allow_html=True)

    # Start the SOAR API server (no-op if already running or FastAPI not installed)
    start_api_server()

    st.title("\U0001f50d SHERLOCK -- FORENSIC EMAIL ANALYZER")
    st.caption("v13.0 | Threat Cluster Intelligence | Conditional Escalation | Risk Narrative Builder | Behavioral Pattern Engine | Spamhaus DNSBL | MX Validation")

    if 'report' not in st.session_state:
        st.session_state.report = None
    if 'fhash' not in st.session_state:
        st.session_state.fhash = None
    if 'case_id' not in st.session_state:
        st.session_state.case_id = None
    if 'cache_hit' not in st.session_state:
        st.session_state.cache_hit = False
    # Stores elapsed seconds from the most recent analysis run.
    # Persists across st.rerun() so the banner shows in the clean render pass.
    if '_analysis_elapsed' not in st.session_state:
        st.session_state._analysis_elapsed = None

    # -- Sidebar --
    with st.sidebar:
        st.markdown("### \U0001f4e7 Upload Email")
        up = st.file_uploader("Select .eml file", type=['eml'])
        if up:
            fb = up.getvalue()
            fh = hashlib.md5(fb, usedforsecurity=False).hexdigest()
            sz = len(fb) / (1024 * 1024)
            if sz > 50:
                st.error("\u274c File too large")
                st.stop()
            st.success(f"\u2705 Loaded ({sz:.2f} MB)")
            if st.session_state.fhash != fh:
                st.session_state.fhash = fh
                st.session_state.report = None
                st.session_state.case_id = None
                st.session_state.cache_hit = False
        st.divider()
        st.markdown("### ✅ Module Status")
        _yara_label = f"YARA ({_BUILTIN_RULE_COUNT} built-in" + (" + Cofense" if _yara_cofense_loaded else "") + ")"
        for name, ok in [("BeautifulSoup", BS4_OK), ("OleTools", OLETOOLS_OK),
                         (_yara_label, YARA_OK), ("pdfminer", PDFMINER_OK), ("pikepdf", PIKEPDF_OK),
                         ("OCR", OCR_OK), ("PIL (Image)", PIL_OK),
                         ("WHOIS", WHOIS_OK), ("VirusTotal", bool(Config.VT_KEY)),
                         ("AbuseIPDB", bool(Config.ABUSE_KEY)),
                         ("AlienVault OTX", bool(Config.OTX_KEY)),
                         ("IBM X-Force", bool(Config.XFORCE_KEY and Config.XFORCE_SECRET)),
                         ("MalwareBazaar", True)]:  # Always available — no key needed
            st.metric(name, "✅ Online" if ok else "⚠️ Offline")
        st.divider()
        st.markdown("### \U0001f50c SOAR Integration")
        st.metric("REST API", f"\u2705 :{Config.API_PORT}")
        # FIX(v16-E): Cache case_stats() — avoid SQLite query on every tab click.
        # case_stats() hits the DB every render. Cache for 5 seconds; stale by ≤5s
        # is fine for a sidebar counter — the case just saved is already counted.
        _stats_ts = st.session_state.get("_stats_ts", 0)
        if time.time() - _stats_ts > 5 or "_db_stats" not in st.session_state:
            st.session_state["_db_stats"] = case_stats()
            st.session_state["_stats_ts"] = time.time()
        db_stats = st.session_state["_db_stats"]
        st.metric("Cases (Total / Today)",
                  f"{db_stats['total_cases']} / {db_stats['today']}")
        st.metric("High-Risk Cases", db_stats['high_risk'])
        if st.session_state.case_id:
            st.code(f"Case ID:\n{st.session_state.case_id}", language=None)
            if st.session_state.cache_hit:
                st.info("\U0001f4be Cache hit — loaded from DB")
        st.caption(f"\U0001f511 API Key: `{Config.API_KEY}`")
        st.caption(f"API: `http://localhost:{Config.API_PORT}/health`")

        # ── Feature 2: Simulation Mode ─────────────────────────────────────────
        if st.session_state.get('report'):
            st.divider()
            st.markdown("### 🧪 Simulation Mode")
            st.caption("Inject synthetic signals to test how the scoring engine responds. "
                       "Results shown inline — real report is unchanged.")
            sim_spf_fail  = st.checkbox("Simulate SPF FAIL",          key="sim_spf_fail")
            sim_spoof     = st.checkbox("Simulate Display-Name Spoof", key="sim_spoof")
            sim_malware   = st.checkbox("Simulate Attachment Malware", key="sim_malware")
            sim_bec_wire  = st.checkbox("Simulate Wire-Transfer BEC",  key="sim_bec_wire")

            any_sim = sim_spf_fail or sim_spoof or sim_malware or sim_bec_wire
            if any_sim:
                _R_real = st.session_state.report
                _sim_extra_sigs = []
                if sim_spf_fail and not any(s.name == 'spf_fail' for s in _R_real['signals']):
                    _sim_extra_sigs.append(ThreatSignal(
                        'sim_spf_fail', 'auth', 2, 0.70, 0.90,
                        '[SIM] SPF FAIL', 'Simulated: sending server not authorized', ''))
                if sim_spoof and not any(s.name == 'display_name_spoof' for s in _R_real['signals']):
                    _sim_extra_sigs.append(ThreatSignal(
                        'sim_display_name_spoof', 'behavioral', 2, 0.60, 0.80,
                        '[SIM] Display Name Spoof', 'Simulated: brand impersonation in From name', ''))
                if sim_malware:
                    _sim_extra_sigs.append(ThreatSignal(
                        'sim_malware_hash', 'attachment', 1, 0.95, 0.98,
                        '[SIM] Malware Hash', 'Simulated: MalwareBazaar confirmed malware', ''))
                if sim_bec_wire:
                    _sim_extra_sigs.append(ThreatSignal(
                        'sim_bec_wire_transfer', 'behavioral', 2, 0.65, 0.75,
                        '[SIM] Wire Transfer BEC', 'Simulated: wire transfer request detected', ''))

                _sim_all_sigs = list(_R_real['signals']) + _sim_extra_sigs
                _sim_scoring  = run_scoring_engine(_sim_all_sigs, _R_real['trust_factors'])
                _delta        = _sim_scoring.score - _R_real['score']
                _delta_color  = DC['critical'] if _delta > 10 else (DC['warn'] if _delta > 0 else DC['ok'])
                st.markdown(
                    f"<div style='background:{DC['elev']};border:1px solid {DC['warn']};"
                    f"border-left:4px solid {DC['warn']};border-radius:8px;padding:12px 14px;"
                    f"margin-top:8px'>"
                    f"<div style='font-weight:700;color:{DC['warn']};margin-bottom:6px'>🧪 Simulation Result</div>"
                    f"<div style='color:{DC['text2']};font-size:.84em'>Real score: "
                    f"<b style='color:{DC['text1']}'>{_R_real['score']}/100</b></div>"
                    f"<div style='color:{DC['text2']};font-size:.84em'>Simulated: "
                    f"<b style='color:{_delta_color}'>{_sim_scoring.score}/100</b> "
                    f"(<b style='color:{_delta_color}'>{"+" if _delta >= 0 else ""}{_delta} pts</b>)</div>"
                    f"<div style='color:{DC['text2']};font-size:.84em'>Verdict: "
                    f"<b style='color:{_tc(_sim_scoring.threat_level)}'>{_sim_scoring.verdict}</b></div>"
                    f"<div style='color:{DC['text2']};font-size:.80em;margin-top:4px'>"
                    f"Confidence: {_sim_scoring.analysis_confidence}%</div>"
                    + (f"<div style='color:{DC['text2']};font-size:.76em;margin-top:4px'>"
                       f"Active clusters: {', '.join(sorted({k for k,v in _detect_clusters(_sim_all_sigs).items()})) or 'none'}"
                       f"</div>" if _detect_clusters(_sim_all_sigs) else "")
                    + f"</div>",
                    unsafe_allow_html=True)
                if _sim_extra_sigs:
                    with st.expander("Injected signals"):
                        for _ss in _sim_extra_sigs:
                            st.markdown(f"- **{_ss.title}** — p={_ss.probability:.0%}, c={_ss.confidence:.0%}")

    if not up:
        st.info("\U0001f446 Upload an .eml file to begin analysis")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("**\U0001f9e0 Signal Engine**\n- Nonlinear scoring\n- Correlation bonuses\n- Signal hierarchy")
        with c2:
            st.markdown("**\U0001f50d Smart Detection**\n- BeautifulSoup parsing\n- Text de-obfuscation\n- Link-text mismatch")
        with c3:
            st.markdown("**\U0001f4ca Complete Analysis**\n- OCR image text\n- pdfminer PDF streams\n- Sender memory")
        return

    try:
        if st.session_state.report is None:
            # ── Cache check: has this exact .eml been analyzed before? ──────────
            fh_now = st.session_state.fhash or ""
            cached_case = case_lookup_by_hash(fh_now) if fh_now else None
            if cached_case and not st.session_state.get('force_reanalyze'):
                st.info(
                    f"\U0001f4be **Cache hit** — this email was already analyzed "
                    f"(Case `{cached_case['case_id']}`, "
                    f"Score **{cached_case['score']}/100**, "
                    f"Verdict **{cached_case['verdict']}**).  \n"
                    f"Submitted: {cached_case['submitted_at'][:19]}"
                )
                col_use, col_fresh = st.columns(2)
                with col_use:
                    if st.button("\U0001f4be Use Cached Result", type="primary"):
                        try:
                            full = case_get(cached_case['case_id'])
                            if full and full.get('report_json'):
                                # We can't fully restore the dataclass-based report from JSON,
                                # so we just re-run analysis but mark it as a cache hit.
                                pass
                        except Exception:
                            pass
                        # Fall through to normal analysis but flag it
                        st.session_state.cache_hit = True
                        st.session_state.case_id   = cached_case['case_id']
                        st.session_state.force_reanalyze = True
                        st.rerun()
                with col_fresh:
                    if st.button("\U0001f504 Re-analyze (fresh)"):
                        st.session_state.force_reanalyze = True
                        st.rerun()
                st.stop()

            pb = st.progress(0)
            sc = st.empty()
            accent = DC['accent']

            def _s(m, i, c=None):
                cl = c or accent
                sc.markdown(
                    f"<div style='background:linear-gradient(90deg,{cl}22,transparent);"
                    f"border-left:4px solid {cl};padding:12px 16px;border-radius:6px;"
                    f"margin:8px 0;box-shadow:{SHADOW}'>"
                    f"<span style='font-size:1.1em;margin-right:8px'>{i}</span>"
                    f"<span style='color:{DC['text1']};font-weight:500'>{_esc(m)}</span></div>",
                    unsafe_allow_html=True)

            t0 = time.time()
            st.session_state.report = analyze_email(fb, _s, pb.progress)
            sc.empty()
            pb.empty()

            # ── Persist to case DB and fire webhook if needed ─────────────────
            R_new = st.session_state.report
            new_case_id = case_save(R_new, analyst="analyst")
            st.session_state.case_id          = new_case_id
            st.session_state.cache_hit         = False
            st.session_state.force_reanalyze   = False
            st.session_state._analysis_elapsed = round(time.time() - t0, 1)
            # Fire webhook in background (non-blocking)
            try:
                soar_j = build_soar_json(R_new, new_case_id)
                fire_webhook(new_case_id, soar_j)
            except Exception as _we:
                log.error(f"Webhook prep error: {_we}")

            # ── KEY FIX: trigger a clean render pass ──────────────────────────
            # Without st.rerun(), Streamlit renders the verdict card and all 9
            # tabs in the SAME script execution as the 155-second analysis.
            # Mid-render session_state mutations cause Streamlit to queue an
            # immediate re-run that fires before the browser paints tab content
            # — leaving every tab blank and creating the infinite re-render loop
            # visible in the terminal (repeated use_container_width warnings).
            # st.rerun() terminates this analysis pass cleanly. The next render
            # pass finds report already in session_state, skips analysis, and
            # renders all tabs stably in one complete shot.
            st.rerun()
        # Show analysis completion banner in the clean render pass.
        # The banner lives in session_state so it survives the st.rerun() above.
        if st.session_state.get('_analysis_elapsed'):
            st.success(f"\u2705 Analysis complete in {st.session_state._analysis_elapsed:.1f}s")

        R = st.session_state.report
        # FIX(v16-D): Cache text report in session_state.
        # generate_text_report() iterates all signals/observables/correlations and
        # builds a large string — was re-run on every tab click and sidebar interaction.
        _report_key = R["hashes"]["md5"]
        if st.session_state.get("_txt_cache_key") != _report_key:
            st.session_state["_txt_cache_key"] = _report_key
            st.session_state["_txt_cache"]     = generate_text_report(R)
        txt = st.session_state["_txt_cache"]

        tc = _tc(R['threat_level'])
        ti = _ti(R['threat_level'])
        action = ("\u2705 RELEASE" if R['score'] < 18
                  else ("\U0001f50d REVIEW" if R['score'] < 40
                        else ("\u26a0\ufe0f HOLD" if R['score'] < 65
                              else "\u26d4 QUARANTINE")))
        ac = (DC['ok'] if R['score'] < 18
              else (DC['accent'] if R['score'] < 40
                    else (DC['warn'] if R['score'] < 65
                          else DC['critical'])))
        _ac_val   = R.get('analysis_confidence', R['confidence'])
        _is_clean = R['score'] < 18

        if _is_clean:
            # For clean emails: confidence = "how sure are we it's actually safe?"
            # High = fully authenticated, no signals. Low = no auth data, stray signals.
            _ac_color = (DC['ok']   if _ac_val >= 70 else
                         DC['warn'] if _ac_val >= 45 else DC['accent'])
            _ac_label = ("Confirmed Clean"  if _ac_val >= 75 else
                         ("Likely Clean"    if _ac_val >= 50 else
                          ("Unverified"     if _ac_val >= 30 else "Inconclusive")))
            _ac_tip   = ("Authentication passed — high certainty"             if _ac_val >= 75 else
                         ("Passes basic checks, limited auth data"             if _ac_val >= 50 else
                          ("No authentication to verify — treat with caution"  if _ac_val >= 30 else
                           "Insufficient data to confirm safety")))
        else:
            # For threat verdicts: confidence = "how well-corroborated is the threat?"
            # Red for weak threat evidence warns analyst this might be a false positive.
            _ac_color = (DC['ok']       if _ac_val >= 70 else
                         DC['warn']     if _ac_val >= 45 else DC['critical'])
            _ac_label = ("Strong"    if _ac_val >= 75 else
                         ("Moderate" if _ac_val >= 50 else
                          ("Weak"    if _ac_val >= 30 else "Very Weak")))
            _ac_tip   = ("Multiple independent signals agree"               if _ac_val >= 75 else
                         ("Some evidence supports this verdict"             if _ac_val >= 50 else
                          ("Limited evidence — verify before acting"        if _ac_val >= 30 else
                           "Minimal evidence — possible false positive")))

        st.markdown(
            f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
            f"padding:24px;border-radius:12px;margin:16px 0;border-left:6px solid {tc};"
            f"box-shadow:0 10px 15px -3px rgba(0,0,0,0.4)'>"
            f"<div style='display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:10px'>"
            f"<h2 style='margin:0;color:{DC['text1']}'>{ti} Verdict: {_esc(R['verdict'])}</h2>"
            f"<span style='background:{ac};color:#fff;padding:6px 14px;border-radius:20px;"
            f"font-weight:700;font-size:.9em'>{action}</span></div>"
            # [v19] Dominant vector badge — only shown for threat verdicts
            + (
                f"<div style='margin-bottom:10px'>"
                f"<span style='background:{tc}22;border:1px solid {tc}55;border-radius:8px;"
                f"padding:4px 12px;font-size:.82em;color:{tc};font-weight:600'>"
                f"⚡ Primary Attack: {_esc(R.get('dominant_vector', ''))}</span></div>"
                if R.get('dominant_vector') and R['score'] >= 18 else ""
            )
            + f"<div style='display:flex;flex-wrap:wrap;gap:18px;margin-top:4px'>"
            f"<span style='color:{DC['text2']};font-size:1.0em'>"
            f"<b>Risk Score</b>&nbsp; <span style='color:{tc};font-weight:700;font-size:1.1em'>{R['score']}</span>"
            f"<span style='color:{DC['text2']}'>/100</span></span>"
            f"<span style='color:{DC['text2']};font-size:1.0em'>"
            f"<b>Threat Level</b>&nbsp; <span style='color:{tc};font-weight:600'>{_esc(R['threat_level'])}</span></span>"
            f"<span style='color:{DC['text2']};font-size:1.0em'>"
            f"<b>{'Clean Certainty' if _is_clean else 'Evidence Strength'}</b>&nbsp;"
            f"<span style='color:{_ac_color};font-weight:700'>{_ac_label}</span>"
            f"&nbsp;<span style='color:{DC['text2']};font-size:.82em'>({_ac_val}% — {_ac_tip})</span>"
            f"</span></div></div>",
            unsafe_allow_html=True)

        tabs = st.tabs(["\U0001f4cb Report & Intelligence", "\U0001f510 Authentication",
                        "\U0001f310 URLs & Domains", "\U0001f4ce Attachments",
                        "\U0001f534 YARA", "\U0001f5bc\ufe0f Images",
                        "\U0001f4ca All Findings", "\U0001f4be Export",
                        "\U0001f50c SOC Integration"])
        with tabs[0]:
            risk_narrative = R.get('risk_narrative', '')
            active_clusters = R.get('active_clusters', {})
            
            threat_sigs = sorted(R['signals'], key=lambda x: x.probability * x.confidence, reverse=True)
            # Filter out zero-probability BEC markers from display
            display_sigs = [s for s in threat_sigs if not (s.probability == 0.0 and s.name.startswith('bec_') and s.name != 'bec_combined')]

            if risk_narrative and R['score'] >= 18:
                narr_color = _tc(R['threat_level'])
                # [v19] Render phased narrative — split on double-newline section breaks,
                # then render each section with its own styled header and body.
                # Sections start with **emoji Header** followed by content.
                narr_sections = [s.strip() for s in risk_narrative.split('\n\n') if s.strip()]
                narr_html_parts = []
                _PHASE_ICONS = {
                    '🔴': DC['critical'],
                    '💣': DC['high'],
                    '🎯': DC['warn'],
                }
                for sec in narr_sections:
                    # Detect if section starts with a bold phase header
                    hdr_match = re.match(r'^\*\*([^*]+)\*\*\n?(.*)', sec, re.DOTALL)
                    if hdr_match:
                        hdr_raw = hdr_match.group(1).strip()
                        body    = hdr_match.group(2).strip()
                        # Determine phase color from leading emoji
                        ph_color = next(
                            (c for em, c in _PHASE_ICONS.items() if em in hdr_raw),
                            DC['accent'])
                        body_html = re.sub(r'\*\*(.+?)\*\*',
                                           r'<b style="color:#ffffff">\1</b>', _esc(body))
                        narr_html_parts.append(
                            f"<div style='border-left:3px solid {ph_color};padding:6px 12px;"
                            f"margin:8px 0 4px 0'>"
                            f"<div style='color:{ph_color};font-weight:700;font-size:.84em;"
                            f"text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px'>"
                            f"{_esc(hdr_raw)}</div>"
                            f"<div style='color:{DC['text2']};font-size:.90em;line-height:1.6'>"
                            f"{body_html}</div></div>")
                    else:
                        # Non-section content (conclusion, mitigation, recommendation)
                        sec_html = re.sub(r'\*\*(.+?)\*\*',
                                          r'<b style="color:#ffffff">\1</b>', _esc(sec))
                        narr_html_parts.append(
                            f"<div style='color:{DC['text2']};font-size:.90em;"
                            f"line-height:1.6;margin:6px 0'>{sec_html}</div>")
                narr_html = "\n".join(narr_html_parts)
                
                cluster_badges = ""
                if active_clusters:
                    badge_colors = {
                        'spoof': '#8b5cf6', 'payload': '#ef4444',
                        'infrastructure': '#f59e0b', 'social_engineering': '#3b82f6',
                    }
                    badge_icons = {
                        'spoof': '🎭', 'payload': '💣',
                        'infrastructure': '🌐', 'social_engineering': '🎯',
                    }
                    for cn, sigs in active_clusters.items():
                        bc = badge_colors.get(cn, DC['accent'])
                        icon = badge_icons.get(cn, '🔴')
                        real_sigs_b = [s for s in sigs if (s['prob'] > 0 if isinstance(s, dict) else True)]
                        if not real_sigs_b:
                            real_sigs_b = sigs
                        sig_titles = [s['title'] if isinstance(s, dict) else s.replace('_', ' ').title() for s in real_sigs_b]
                        MAX_SHOW = 3
                        if len(sig_titles) > MAX_SHOW:
                            shown = ', '.join(sig_titles[:MAX_SHOW])
                            sig_label = f"{_esc(shown)}<span style='opacity:.65'> +{len(sig_titles)-MAX_SHOW} more</span>"
                        else:
                            sig_label = _esc(', '.join(sig_titles)) if sig_titles else 'active'
                        cluster_badges += (
                            f"<div style='display:inline-block;background:{bc}18; border:1px solid {bc}77;border-radius:8px;"
                            f"padding:6px 12px;margin:4px 6px 0 0;vertical-align:top; max-width:300px;min-width:140px'>"
                            f"<div style='color:{bc};font-weight:700;font-size:.80em; margin-bottom:3px'>{icon} {cn.replace('_', ' ').upper()}</div>"
                            f"<div style='color:{DC['text2']};font-size:.76em; line-height:1.45'>{sig_label}</div>"
                            f"</div>")

                # --- NEW: Build the Signal Cards HTML to inject inside the Narrative ---
                sigs_html = ""
                if display_sigs:
                    sigs_html += f"<div style='margin-top:24px; border-top:1px solid {DC['border']}; padding-top:18px;'>"
                    sigs_html += f"<div style='font-size:1.05em; font-weight:700; color:{DC['text1']}; margin-bottom:12px;'>🎯 DRIVING SIGNALS</div>"
                    for s in display_sigs[:6]:
                        eff = s.probability * s.confidence
                        sc_color = DC['critical'] if eff >= 0.4 else (DC['high'] if eff >= 0.2 else (DC['medium'] if eff >= 0.08 else DC['low']))
                        sev = "CRITICAL" if eff >= 0.4 else ("HIGH" if eff >= 0.2 else ("MEDIUM" if eff >= 0.08 else "LOW"))
                        ev_html = f'<div style="color:{DC["text2"]};font-size:.85em;margin-top:6px;font-style:italic">{_esc(s.evidence)}</div>' if s.evidence else ''
                        
                        # --- NEW: Dynamic Tab Pointers ---
                        # Map the signal's internal category to the correct UI tab.
                        # 'yara' covers ALL YARA hits (body and attachment alike) —
                        # the YARA tab is the authoritative place for matched strings,
                        # TLP classification, and severity context for every YARA rule.
                        tab_map = {
                            'auth':        '🔐 Authentication',
                            'attachment':  '📎 Attachments',
                            'yara':        '🔴 YARA',
                            'network':     '🌐 URLs & Domains',
                            'content':     '🌐 URLs & Domains',
                            'behavioral':  '🧠 Threat Narrative',
                        }
                        target_tab = tab_map.get(s.category, '📊 All Findings')
                        
                        tab_pointer_html = (
                            f"<div style='margin-top: 10px; padding-top: 8px; border-top: 1px solid {DC['border']}44; text-align: right;'>"
                            f"<span style='color: {DC['accent']}; background: {DC['accent']}15; padding: 4px 10px; border-radius: 6px; font-size: 0.78em; font-weight: 600;'>"
                            f"👉 Investigate in <b>{target_tab}</b> tab</span></div>"
                        )
                        # ---------------------------------

                        sigs_html += (
                            f"<div style='background:rgba(0,0,0,0.25); border-radius:8px; padding:14px 18px; margin:8px 0; border-left:4px solid {sc_color};'>"
                            f"<div style='display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:6px;'>"
                            f"<span style='font-weight:700; color:{sc_color}; font-size:1em;'>{_esc(s.title)}</span>"
                            f"<span style='background:{sc_color}; color:#fff; padding:2px 10px; border-radius:10px; font-size:.75em; font-weight:700;'>{sev} ({eff:.0%})</span>"
                            f"</div>"
                            f"<div style='color:#cbd5e1; font-size:.9em; margin-top:6px;'><span style='color:{DC['border']}'>Why: </span>{_esc(s.detail)}</div>"
                            f"{ev_html}"
                            f"{tab_pointer_html}" # Inject the pointer badge here
                            f"</div>"
                        )
                    sigs_html += "</div>"

                # --- Combine Narrative and Signals into ONE unified box ---
                st.markdown(
                    f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
                    f"border:2px solid {narr_color};border-left:6px solid {narr_color};"
                    f"border-radius:12px;padding:22px;margin:12px 0;"
                    f"box-shadow:0 6px 12px rgba(0,0,0,0.35)'>"
                    f"<div style='display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap'>"
                    f"<span style='font-size:1.3em;font-weight:700;color:{narr_color}'>🧠 THREAT NARRATIVE</span>"
                    f"</div>"
                    f"<div style='color:#f8fafc;font-size:1.05em;line-height:1.7;'>{narr_html}</div>"
                    + (f"<div style='margin-top:12px'>{cluster_badges}</div>" if cluster_badges else "")
                    + sigs_html  # <--- Signals are now INSIDE the narrative box
                    + "</div>",
                    unsafe_allow_html=True)

            elif R['score'] < 18:
                st.markdown(
                    f"<div style='background:{DC['ok']}18;border-left:5px solid {DC['ok']}; border-radius:10px;padding:14px 18px;margin:12px 0'>"
                    f"<b style='color:{DC['ok']}'>🧠 THREAT NARRATIVE</b><br>"
                    f"<span style='color:{DC['text1']}'>No significant threat pattern detected. Email appears clean.</span></div>",
                    unsafe_allow_html=True)

            # NOTE: You can now DELETE the separate "KEY SIGNALS" block completely, 
            # because the signals are now generated directly inside the Narrative box!

            st.markdown(
                f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
                f"border:2px solid {DC['purple']};border-left:6px solid {DC['purple']};"
                f"border-radius:12px;padding:16px 20px;margin:12px 0'>"
                f"<div style='font-size:1.2em;font-weight:700;color:{DC['purple']}'>\U0001f9e0 REASONING</div>"
                f"<div style='color:{DC['text2']};font-size:.85em'>"
                f"Analytical insights -- <em>what it means, not just what was found</em></div></div>",
                unsafe_allow_html=True)
            try:
                reason_cards = build_reasoning_cards(R)
            except Exception as e:
                log.error(f"Reasoning cards: {e}")
                reason_cards = []
            for i in range(0, len(reason_cards), 2):
                cols = st.columns(2)
                for j, col in enumerate(cols):
                    if i + j < len(reason_cards):
                        ic, ti_c, body, det, clr = reason_cards[i + j]
                        with col:
                            st.markdown(_card(ic, ti_c, body, det, clr), unsafe_allow_html=True)

            threat_sigs = sorted(R['signals'],
                                 key=lambda x: x.probability * x.confidence, reverse=True)
            # Filter out zero-probability BEC markers from display
            display_sigs = [s for s in threat_sigs
                            if not (s.probability == 0.0 and s.name.startswith('bec_')
                                    and s.name != 'bec_combined')]


            if R['trust_factors'] or R.get('correlations'):
                st.markdown(
                    f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
                    f"border:2px solid {DC['ok']};border-left:6px solid {DC['ok']};"
                    f"border-radius:12px;padding:16px 20px;margin:16px 0'>"
                    f"<div style='font-size:1.2em;font-weight:700;color:{DC['ok']}'>\u2705 MITIGATING FACTORS</div>"
                    f"<div style='color:{DC['text2']};font-size:.85em'>"
                    f"Positive signals that reduce the threat score</div></div>",
                    unsafe_allow_html=True)
                for tf in R['trust_factors']:
                    st.markdown(
                        f"<div style='background:{DC['card']};border:1px solid {DC['ok']}44;"
                        f"border-left:5px solid {DC['ok']};border-radius:8px;padding:12px 16px;"
                        f"margin:6px 0;display:flex;align-items:center;gap:12px'>"
                        f"<span style='background:{DC['ok']};color:#fff;border-radius:4px;"
                        f"padding:2px 8px;font-weight:700;font-size:.82em'>\u2713</span>"
                        f"<span style='color:{DC['text1']};font-size:.92em'>{_esc(tf.description)}"
                        f" <span style='color:{DC['text2']};font-size:.82em'>"
                        f"(dampening: {tf.strength:.0%})</span></span></div>",
                        unsafe_allow_html=True)
                if R.get('correlations'):
                    cluster_corrs = [c for c in R['correlations'] if c.startswith('CLUSTER:')]
                    signal_corrs  = [c for c in R['correlations'] if not c.startswith('CLUSTER:')]

                    # ── Attack Vector Escalations ──────────────────────────────
                    # Map cluster names to human labels and the signals that fired in each
                    active_clusters = R.get('active_clusters', {})
                    _CL_LABEL = {
                        'spoof':              ('🎭', 'Identity Spoofing'),
                        'payload':            ('💣', 'Malicious Payload'),
                        'infrastructure':     ('🌐', 'Attack Infrastructure'),
                        'social_engineering': ('🎯', 'Social Engineering'),
                    }
                    # Escalation descriptions mapped to what they mean for the analyst
                    _ESC_EXPLAIN = {
                        'Spoof+Payload':            'A spoofed sender combined with a malicious attachment/link is the classic initial-access phishing pattern.',
                        'Spoof+SocialEng':          'A fake sender identity paired with manipulation tactics — hallmark of Business Email Compromise (BEC).',
                        'Infra+SocialEng':          'Attacker-controlled infrastructure hosting deceptive content — characteristic of credential-harvesting phishing.',
                        'Payload+Infra':            'Malware delivered through attacker-controlled hosting — indicates a staged, deliberate campaign.',
                        'Triple-vector':            'Spoofed identity + suspicious infrastructure + lure content — a full phishing kill-chain.',
                        'Spoof+Payload+SocialEng':  'A weaponized BEC: fake sender, social pressure, and a malicious payload — maximally dangerous.',
                        'All-vectors':              'Every attack vector active simultaneously — signature of a sophisticated, targeted campaign.',
                        'Spoof+Infra':              'A spoofed sender routing through suspicious infrastructure — typical of botnet-delivered phishing.',
                        'SocialEng+Infra':          'Social engineering lure hosted on suspicious infrastructure — credential-phishing setup.',
                    }

                    if cluster_corrs:
                        st.markdown(
                            f"<div style='font-weight:600;color:{DC['text1']};font-size:.95em;"
                            f"margin:14px 0 8px'>⚡ Multi-Vector Escalations</div>"
                            f"<div style='color:{DC['text2']};font-size:.80em;margin-bottom:10px'>"
                            f"When multiple attack vectors fire together their combined risk is "
                            f"greater than the sum of parts. Each row below shows what co-fired "
                            f"and why it matters.</div>",
                            unsafe_allow_html=True)

                        for c in cluster_corrs:
                            clean = c[len('CLUSTER: '):]
                            parts = clean.rsplit(' -> ', 1)
                            raw_desc = parts[0].strip()
                            bonus_raw = parts[1].strip() if len(parts) > 1 else ''
                            try:
                                bonus_val = float(bonus_raw.lstrip('+'))
                                bonus_pct = f"+{bonus_val*100:.0f} pts"
                            except Exception:
                                bonus_pct = bonus_raw

                            if 'CRITICAL' in raw_desc.upper():
                                esc_color, sev_label = DC['critical'], 'CRITICAL'
                            elif 'HIGH' in raw_desc.upper():
                                esc_color, sev_label = DC['high'], 'HIGH'
                            else:
                                esc_color, sev_label = DC['warn'], 'MEDIUM'

                            # Determine which clusters are in this escalation
                            fired_cluster_names = [
                                cn for cn in active_clusters
                                if cn.replace('_', '') in raw_desc.lower().replace(' ', '').replace('+', '').replace('-', '')]

                            # Get key for explanation lookup
                            explain_key = next(
                                (k for k in _ESC_EXPLAIN if k.lower().replace(' ', '') in
                                 raw_desc.lower().replace(' ', '').replace('+', '')),
                                None)
                            explain = _ESC_EXPLAIN.get(explain_key, '')

                            # Build cluster pill list
                            pills = ''
                            for cn, sigs in active_clusters.items():
                                em, label = _CL_LABEL.get(cn, ('🔴', cn.replace('_', ' ').title()))
                                real_sigs = [s for s in sigs if isinstance(s, dict) and s.get('prob', 1) > 0]
                                top_titles = [s['title'] for s in real_sigs[:2]] if real_sigs else []
                                sig_summary = ', '.join(top_titles) if top_titles else ''
                                pills += (
                                    f"<span style='display:inline-block;background:{esc_color}20;"
                                    f"border:1px solid {esc_color}55;border-radius:6px;"
                                    f"padding:3px 10px;margin:2px 4px 2px 0;font-size:.78em;"
                                    f"color:{DC['text1']}'>"
                                    f"<b>{em} {label}</b>"
                                    + (f"<span style='color:{DC['text2']}'> — {_esc(sig_summary)}</span>" if sig_summary else "")
                                    + "</span>")

                            st.markdown(
                                f"<div style='background:{esc_color}0e;border:1px solid {esc_color}44;"
                                f"border-left:5px solid {esc_color};border-radius:10px;"
                                f"padding:12px 16px;margin:6px 0'>"
                                # Top row: severity badge + score impact
                                f"<div style='display:flex;justify-content:space-between;"
                                f"align-items:center;margin-bottom:8px'>"
                                f"<span style='background:{esc_color};color:#fff;padding:2px 10px;"
                                f"border-radius:8px;font-size:.76em;font-weight:700'>{sev_label}</span>"
                                f"<span style='color:{esc_color};font-weight:700;font-size:.85em'>"
                                f"Score impact: {bonus_pct}</span></div>"
                                # Explanation
                                + (f"<div style='color:{DC['text1']};font-size:.87em;"
                                   f"margin-bottom:8px'>{_esc(explain)}</div>" if explain else "")
                                # Cluster pills
                                + (f"<div style='margin-top:4px'>{pills}</div>" if pills else "")
                                + "</div>",
                                unsafe_allow_html=True)

                    # ── Co-firing Signal Pairs ─────────────────────────────────
                    if signal_corrs:
                        with st.expander(f"🔗 {len(signal_corrs)} co-firing signal pair(s) — click to expand"):
                            st.caption("When two suspicious signals appear together their combined impact exceeds either alone.")
                            for c in signal_corrs:
                                parts = c.rsplit(' -> ', 1)
                                sig_part = parts[0]
                                bonus_raw = parts[1].strip() if len(parts) > 1 else ''
                                try:
                                    bv = float(bonus_raw.lstrip('+'))
                                    bonus_disp = f"+{bv*100:.0f} pts"
                                except Exception:
                                    bonus_disp = bonus_raw
                                a, b = (sig_part.split('+', 1) + [''])[:2]
                                st.markdown(
                                    f"<div style='display:flex;align-items:center;gap:8px;"
                                    f"padding:5px 0;border-bottom:1px solid {DC['border']}20'>"
                                    f"<code style='font-size:.80em;color:{DC['text1']}'>{_esc(a.strip())}</code>"
                                    f"<span style='color:{DC['text2']}'>+</span>"
                                    f"<code style='font-size:.80em;color:{DC['text1']}'>{_esc(b.strip())}</code>"
                                    f"<span style='margin-left:auto;color:{DC['accent']};"
                                    f"font-weight:700;font-size:.82em'>{bonus_disp}</span>"
                                    f"</div>",
                                    unsafe_allow_html=True)

            score = R['score']
            if score >= 65:
                note = "\u26d4 **QUARANTINE** -- Block delivery. Investigate sender and any clicked links."
                nc = DC['critical']
            elif score >= 40:
                note = "\u26a0\ufe0f **HOLD FOR REVIEW** -- Do not deliver without manual analyst review."
                nc = DC['warn']
            elif score >= 18:
                note = "\U0001f50d **DELIVER WITH CAUTION** -- Soft quarantine or add warning banner."
                nc = DC['accent']
            else:
                note = "\u2705 **RELEASE** -- No significant threats. Safe for delivery."
                nc = DC['ok']
            note_html = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', _esc(note))
            st.markdown(
                f"<div style='background:{nc}15;border-left:4px solid {nc};border-radius:8px;"
                f"padding:14px 18px;margin:16px 0'>"
                f"<div style='font-weight:700;color:{nc};margin-bottom:4px'>\U0001f4cb Analyst Recommendation</div>"
                f"<div style='color:{DC['text1']};font-size:.95em'>{note_html}</div></div>",
                unsafe_allow_html=True)

            # ── Explain My Score — unified plain-English panel ─────────────────
            # Verdict-aware: clean emails get clean-certainty language;
            # threat verdicts get threat-corroboration language.
            sb       = R.get('score_breakdown', {})
            _ac_val  = R.get('analysis_confidence', R['confidence'])
            _is_cln  = R['score'] < 18

            if _is_cln:
                _ac_col  = (DC['ok'] if _ac_val >= 70 else DC['warn'] if _ac_val >= 45 else DC['accent'])
                _ac_lbl  = ("Confirmed Clean" if _ac_val >= 75 else
                            ("Likely Clean"   if _ac_val >= 50 else
                             ("Unverified"    if _ac_val >= 30 else "Inconclusive")))
                _cert_hdr = "Clean Certainty"
            else:
                _ac_col  = (DC['ok'] if _ac_val >= 70 else DC['warn'] if _ac_val >= 45 else DC['critical'])
                _ac_lbl  = ("Strong"   if _ac_val >= 75 else
                            ("Moderate" if _ac_val >= 50 else
                             ("Weak"   if _ac_val >= 30 else "Very Weak")))
                _cert_hdr = "Evidence Strength"

            with st.expander("🔍 Explain My Score", expanded=False):

                # ── Header: one-sentence plain answer ────────────────────────────
                _score   = R['score']
                _n_real  = len([s for s in R['signals']
                                if not (s.probability == 0.0 and s.name.startswith('bec_')
                                        and s.name != 'bec_combined')])
                _n_trust = len(R.get('trust_factors', []))
                _n_esc   = len(sb.get('cluster_contributions', []))
                _n_damp  = len(sb.get('dampening_contributions', []))
                _n_corrs = len([c for c in R.get('correlations', []) if not c.startswith('CLUSTER:')])

                # Build a verdict-appropriate summary sentence
                if _is_cln:
                    if _n_real == 0:
                        _summary = (f"No threats were detected. "
                                    f"The score of **{_score}/100** reflects a clean email"
                                    + (f" with **{_n_trust} positive signal{'s' if _n_trust != 1 else ''}** "
                                       f"supporting that conclusion." if _n_trust else "."))
                    else:
                        _summary = (f"The score of **{_score}/100** is low. "
                                    f"**{_n_real} minor signal{'s' if _n_real != 1 else ''}** "
                                    f"were found but none were serious enough to flag as a threat"
                                    + (f", and **{_n_trust} positive factor{'s' if _n_trust != 1 else ''}** "
                                       f"confirmed legitimacy." if _n_trust else "."))
                    _cert_tip = ("Authentication passed — high certainty this is safe."   if _ac_val >= 75 else
                                 "Passes basic checks but authentication data is limited."  if _ac_val >= 50 else
                                 "No authentication data — legitimacy cannot be confirmed." if _ac_val >= 30 else
                                 "Insufficient data to confirm safety — treat with caution.")
                    _cert_line = (f"{_cert_hdr}: <b style='color:{_ac_col}'>{_ac_lbl} ({_ac_val}%)</b>"
                                  f" — {_cert_tip}")
                else:
                    _esc_phrase  = (f", boosted by {_n_esc} multi-attack combination{'s' if _n_esc > 1 else ''}"
                                    if _n_esc else "")
                    _damp_phrase = (f", then reduced by {_n_damp} trust factor{'s' if _n_damp > 1 else ''}"
                                    if _n_damp else "")
                    _summary = (f"The score of **{_score}/100** was built from "
                                f"**{_n_real} detection{'s' if _n_real != 1 else ''}**"
                                f"{_esc_phrase}{_damp_phrase}.")
                    _cert_tip = ("Multiple independent signals agree."              if _ac_val >= 75 else
                                 "Some evidence supports this verdict."             if _ac_val >= 50 else
                                 "Limited evidence — verify before acting."         if _ac_val >= 30 else
                                 "Minimal evidence — possible false positive.")
                    _cert_line = (f"{_cert_hdr}: <b style='color:{_ac_col}'>{_ac_lbl} ({_ac_val}%)</b>"
                                  f" — {_cert_tip}")

                st.markdown(
                    f"<div style='background:{DC['elev']};border-radius:10px;padding:16px 20px;margin-bottom:16px'>"
                    f"<div style='font-size:1.0em;color:{DC['text1']};line-height:1.7'>"
                    + re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', _esc(_summary))
                    + f"</div><div style='margin-top:8px;color:{DC['text2']};font-size:.84em'>"
                    + _cert_line
                    + "</div></div>",
                    unsafe_allow_html=True)

                # ── Section 1: How the score was built (step by step) ────────────
                st.markdown(
                    f"<div style='font-weight:700;color:{DC['text1']};font-size:.95em;margin-bottom:10px'>"
                    f"📊 How the score was built</div>",
                    unsafe_allow_html=True)

                pre_cls = sb.get('pre_cluster_score', 0)
                pre_dmp = sb.get('pre_dampen_score', 0)
                final_s = sb.get('final_score', _score)

                # Visual step-by-step score flow
                _step_items = [
                    (f"Detections found ({_n_real} signal{'s' if _n_real != 1 else ''})",
                     f"{pre_cls:.0f} pts", DC['accent'],
                     "Each detection adds risk points based on how serious it is and how certain we are about it."),
                ]
                if _n_esc > 0:
                    _esc_added = pre_dmp - pre_cls
                    _step_items.append((
                        f"Multi-attack bonus ({_n_esc} combination{'s' if _n_esc > 1 else ''} triggered)",
                        f"+{_esc_added*100:.0f} pts" if _esc_added > 0.005 else "applied",
                        DC['warn'],
                        "When multiple types of attacks are used together (e.g. spoofed identity + malware), "
                        "the risk is higher than the sum of parts. A bonus is added."
                    ))
                if _n_corrs > 0:
                    _step_items.append((
                        f"Signals that reinforce each other ({_n_corrs} pair{'s' if _n_corrs > 1 else ''})",
                        "bonus applied",
                        DC['accent'],
                        "Some detections are more suspicious when they appear together. A small extra is added for each pair."
                    ))
                if _n_damp > 0:
                    _damp_removed = pre_dmp - final_s / 100 if pre_dmp > 0 else 0
                    _step_items.append((
                        f"Legitimate signals reduced the score ({_n_damp} factor{'s' if _n_damp > 1 else ''})",
                        f"−{abs(pre_dmp*100 - final_s):.0f} pts",
                        DC['ok'],
                        "Things like passing SPF, DKIM and DMARC checks are positive signs. They pull the score down."
                    ))
                _step_items.append((
                    "Final risk score",
                    f"{final_s}/100",
                    _tc(R['threat_level']),
                    ""
                ))

                for i, (step_label, step_val, step_color, step_tip) in enumerate(_step_items):
                    is_last = (i == len(_step_items) - 1)
                    st.markdown(
                        f"<div style='display:flex;align-items:flex-start;gap:12px;margin:8px 0'>"
                        f"<div style='display:flex;flex-direction:column;align-items:center;flex-shrink:0'>"
                        f"<div style='width:28px;height:28px;border-radius:50%;background:{step_color};"
                        f"display:flex;align-items:center;justify-content:center;"
                        f"font-weight:700;font-size:.78em;color:#fff'>{i+1}</div>"
                        + (f"<div style='width:2px;flex:1;background:{DC['border']}44;margin:2px 0'></div>"
                           if not is_last else "")
                        + f"</div>"
                        f"<div style='flex:1;padding-bottom:{8 if not is_last else 0}px'>"
                        f"<div style='display:flex;justify-content:space-between;align-items:baseline'>"
                        f"<span style='color:{DC['text1']};font-weight:600;font-size:.90em'>{_esc(step_label)}</span>"
                        f"<span style='color:{step_color};font-weight:700;font-size:.92em;margin-left:12px;"
                        f"white-space:nowrap'>{_esc(step_val)}</span></div>"
                        + (f"<div style='color:{DC['text2']};font-size:.78em;margin-top:2px;line-height:1.45'>"
                           f"{_esc(step_tip)}</div>" if step_tip else "")
                        + f"</div></div>",
                        unsafe_allow_html=True)

                st.divider()

                # ── Section 2: What triggered the score (each detection) ──────────
                sig_contribs = sb.get('signal_contributions', [])
                if sig_contribs:
                    st.markdown(
                        f"<div style='font-weight:700;color:{DC['text1']};font-size:.95em;margin-bottom:4px'>"
                        f"🎯 What drove the score up</div>"
                        f"<div style='color:{DC['text2']};font-size:.80em;margin-bottom:10px'>"
                        f"Sorted by impact — highest contributing detections first.</div>",
                        unsafe_allow_html=True)

                    _TIER_PLAIN = {
                        1: ("Hard evidence",     DC['critical'],
                            "Confirmed by multiple sources — very high certainty"),
                        2: ("Strong indicator",  DC['high'],
                            "High-confidence signal from a reliable source"),
                        3: ("Suspicious pattern",DC['warn'],
                            "Something unusual — could be benign but worth noting"),
                        4: ("Weak hint",         DC['text2'],
                            "Low-weight contextual signal — rarely decisive alone"),
                    }
                    for sc_item in sorted(sig_contribs, key=lambda x: x['pts_added'], reverse=True):
                        if sc_item['pts_added'] < 0.1:
                            continue  # Skip near-zero contributors
                        tier_n = sc_item['tier']
                        t_label, t_color, t_tip = _TIER_PLAIN.get(tier_n, ("Signal", DC['text2'], ""))
                        pts = sc_item['pts_added']
                        bar_w = min(100, int(pts * 4))  # visual bar width
                        st.markdown(
                            f"<div style='background:{DC['elev']};border-radius:8px;padding:11px 14px;"
                            f"margin:5px 0;border-left:4px solid {t_color}'>"
                            f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                            f"<span style='color:{DC['text1']};font-weight:600;font-size:.89em'>"
                            f"{_esc(sc_item['title'] or sc_item['name'])}</span>"
                            f"<span style='color:{t_color};font-weight:700;font-size:.88em;"
                            f"white-space:nowrap;margin-left:10px'>+{pts:.1f} pts</span></div>"
                            f"<div style='display:flex;align-items:center;gap:8px;margin-top:5px'>"
                            f"<div style='flex:1;background:{DC['border']}44;border-radius:3px;height:5px'>"
                            f"<div style='width:{bar_w}%;background:{t_color};height:5px;border-radius:3px'></div></div>"
                            f"<span style='color:{DC['text2']};font-size:.76em;white-space:nowrap'>"
                            f"{t_label} · {sc_item['effective']*100:.0f}% weight</span></div>"
                            f"</div>",
                            unsafe_allow_html=True)

                st.divider()

                # ── Section 3: Multi-attack bonuses (escalations) ─────────────────
                cluster_contribs = sb.get('cluster_contributions', [])
                if cluster_contribs:
                    st.markdown(
                        f"<div style='font-weight:700;color:{DC['text1']};font-size:.95em;margin-bottom:4px'>"
                        f"⚡ Multi-attack combinations that boosted the score</div>"
                        f"<div style='color:{DC['text2']};font-size:.80em;margin-bottom:10px'>"
                        f"When attackers use more than one technique at once, the threat is greater than each part alone. "
                        f"The engine adds a bonus for each combination detected.</div>",
                        unsafe_allow_html=True)

                    _CL_PLAIN = {
                        'spoof':              ('🎭', 'Spoofed sender identity'),
                        'payload':            ('💣', 'Malicious attachment or file'),
                        'infrastructure':     ('🌐', 'Suspicious sending infrastructure'),
                        'social_engineering': ('🎯', 'Social manipulation content'),
                    }
                    # [v19] Also pull cluster_signal_subtotals for per-cluster breakdown
                    _cl_subtotals = sb.get('cluster_signal_subtotals', {})
                    for cc in cluster_contribs:
                        cl_parts = [_CL_PLAIN.get(c, ('🔴', c.replace('_',' ').title())) for c in cc['clusters']]
                        cl_pills = " + ".join(
                            f"<span style='background:{DC['warn']}22;border:1px solid {DC['warn']}55;"
                            f"border-radius:5px;padding:2px 9px;font-size:.78em;color:{DC['text1']}'>"
                            f"{em} {name}</span>"
                            for em, name in cl_parts)

                        # Build per-cluster subtotal chips
                        subtotal_chips = ""
                        for cn in cc['clusters']:
                            st_data = _cl_subtotals.get(cn, {})
                            st_w    = st_data.get('combined_weight', 0)
                            st_n    = st_data.get('signal_count', 0)
                            em, lbl = _CL_PLAIN.get(cn, ('🔴', cn.replace('_',' ').title()))
                            subtotal_chips += (
                                f"<span style='display:inline-block;background:{DC['elev']};"
                                f"border:1px solid {DC['border']};border-radius:6px;"
                                f"padding:3px 9px;margin:3px 4px 0 0;font-size:.76em;"
                                f"color:{DC['text2']}'>"
                                f"{em} {lbl}: {st_n} signal{'s' if st_n != 1 else ''}, "
                                f"{st_w*100:.0f}% combined weight"
                                f"</span>")

                        _dens = cc.get('density_mult', 1.0)
                        _dens_note = (f" (thin cluster — {_dens*100:.0f}% of max bonus)"
                                      if _dens < 0.95 else "")
                        st.markdown(
                            f"<div style='background:{DC['warn']}0d;border:1px solid {DC['warn']}44;"
                            f"border-left:4px solid {DC['warn']};border-radius:8px;"
                            f"padding:12px 16px;margin:5px 0'>"
                            f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>"
                            f"<div style='display:flex;flex-wrap:wrap;gap:4px'>{cl_pills}</div>"
                            f"<span style='color:{DC['warn']};font-weight:700;font-size:.90em;margin-left:10px;"
                            f"white-space:nowrap'>+{cc['pts_added']:.0f} pts{_dens_note}</span></div>"
                            f"<div style='color:{DC['text2']};font-size:.80em;margin-bottom:6px'>"
                            f"These attack types were detected at the same time. "
                            f"Combined they indicate a higher-effort, more targeted attack.</div>"
                            f"<div style='margin-top:4px'>{subtotal_chips}</div>"
                            f"</div>",
                            unsafe_allow_html=True)
                else:
                    st.markdown(
                        f"<div style='color:{DC['text2']};font-size:.84em;font-style:italic'>"
                        f"⚡ No multi-attack combinations detected — score reflects individual signals only.</div>",
                        unsafe_allow_html=True)

                st.divider()

                # ── Section 4: What reduced the score ───────────────────────────────
                damp_contribs = sb.get('dampening_contributions', [])
                if damp_contribs:
                    st.markdown(
                        f"<div style='font-weight:700;color:{DC['text1']};font-size:.95em;margin-bottom:4px'>"
                        f"🛡️ Legitimate signals that reduced the score</div>"
                        f"<div style='color:{DC['text2']};font-size:.80em;margin-bottom:10px'>"
                        f"When the email passes authentication or shows other signs of legitimacy, "
                        f"points are removed from the risk score.</div>",
                        unsafe_allow_html=True)
                    for dc_item in sorted(damp_contribs, key=lambda x: x['pts_removed'], reverse=True):
                        st.markdown(
                            f"<div style='background:{DC['ok']}0d;border-left:4px solid {DC['ok']};"
                            f"border-radius:8px;padding:11px 14px;margin:5px 0'>"
                            f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                            f"<span style='color:{DC['text1']};font-weight:600;font-size:.89em'>"
                            f"✅ {_esc(dc_item['description'])}</span>"
                            f"<span style='color:{DC['ok']};font-weight:700;font-size:.88em;"
                            f"white-space:nowrap;margin-left:10px'>−{dc_item['pts_removed']:.1f} pts</span></div>"
                            f"<div style='color:{DC['text2']};font-size:.78em;margin-top:3px'>"
                            f"Reduced the score by {dc_item['effective']*100:.0f}%</div></div>",
                            unsafe_allow_html=True)
                else:
                    st.markdown(
                        f"<div style='color:{DC['text2']};font-size:.84em;font-style:italic'>"
                        f"🛡️ No trust factors were applied — no authentication passes or other positive signals found.</div>",
                        unsafe_allow_html=True)

                st.divider()

                # ── Section 5: Certainty breakdown ─────────────────────────────
                st.markdown(
                    f"<div style='font-weight:700;color:{DC['text1']};font-size:.95em;margin-bottom:4px'>"
                    f"📐 Why {_cert_hdr} is {_ac_lbl}</div>"
                    f"<div style='color:{DC['text2']};font-size:.80em;margin-bottom:10px'>"
                    + (
                        # Clean verdict explanation
                        "For a clean verdict, certainty comes from authentication passes and the "
                        "absence of threats. More auth passes = higher certainty it's genuinely safe."
                        if _is_cln else
                        # Threat verdict explanation
                        "A high risk score with weak evidence means one strong signal drove it — "
                        "possible false positive. A high score with strong evidence means many "
                        "independent signals agree — reliable verdict."
                    )
                    + "</div>",
                    unsafe_allow_html=True)

                _cats = {s.category for s in R['signals'] if s.probability > 0}
                _cat_plain = {
                    'auth': 'Email authentication (SPF/DKIM/DMARC)',
                    'content': 'Email body and URL analysis',
                    'attachment': 'File attachments',
                    'network': 'IP/domain reputation',
                    'behavioral': 'Behaviour patterns (BEC/spoof)',
                    'yara': 'Malware signature matching',
                }
                # Auth trust factor helpers
                _tf_names    = {tf.name for tf in R.get('trust_factors', [])}
                _n_auth_pass = sum(1 for n in ('spf_pass','dkim_pass','dmarc_pass') if n in _tf_names)

                if _is_cln:
                    # For clean: green = more auth passes / fewer signals. Inverted logic.
                    _ev_rows = [
                        ("Auth checks that passed",    _n_auth_pass,
                         "SPF, DKIM, DMARC — each pass is positive evidence of safety",
                         DC['ok'] if _n_auth_pass >= 2 else (DC['warn'] if _n_auth_pass == 1 else DC['critical'])),
                        ("Total positive factors",     _n_trust,
                         "Clean IPs, known sender, clean attachments, etc.",
                         DC['ok'] if _n_trust >= 3 else DC['warn']),
                        ("Minor signals found",        _n_real,
                         "0 is ideal — any signal introduces some doubt even if low weight",
                         DC['ok'] if _n_real == 0 else (DC['warn'] if _n_real <= 2 else DC['critical'])),
                        ("Serious signals (Tier 1–2)", sum(1 for s in R['signals'] if s.tier <= 2 and s.probability > 0),
                         "None expected in a genuinely clean email",
                         DC['ok'] if not any(s.tier <= 2 and s.probability > 0 for s in R['signals'])
                         else DC['critical']),
                    ]
                else:
                    # For threat: green = more signals / more diversity (existing logic)
                    _ev_rows = [
                        ("Detections found",              _n_real,
                         "3+ is solid corroboration",
                         DC['ok'] if _n_real >= 3 else DC['warn']),
                        ("Areas they come from",           len(_cats),
                         f"{', '.join(_cat_plain.get(c, c) for c in sorted(_cats)[:3])}{'…' if len(_cats) > 3 else ''}",
                         DC['ok'] if len(_cats) >= 3 else DC['warn']),
                        ("Multi-attack combinations",      _n_esc,
                         "0 = single-vector, 1+ = coordinated attack",
                         DC['ok'] if _n_esc >= 1 else DC['accent']),
                        ("Signal pairs that agree",        _n_corrs,
                         "Signals that strengthen each other",
                         DC['ok'] if _n_corrs >= 2 else DC['accent']),
                        ("Legitimate factors present",     _n_trust,
                         "Auth passes that competed against the threat signals",
                         DC['warn'] if _n_trust >= 2 else DC['ok']),
                    ]

                for ev_label, ev_val, ev_tip, ev_color in _ev_rows:
                    bar_pct = min(100, ev_val * 25)
                    st.markdown(
                        f"<div style='display:flex;align-items:center;gap:10px;padding:5px 0;"
                        f"border-bottom:1px solid {DC['border']}22'>"
                        f"<span style='color:{DC['text2']};font-size:.83em;width:200px;flex-shrink:0'>{ev_label}</span>"
                        f"<div style='width:80px;background:{DC['elev']};border-radius:4px;height:7px;flex-shrink:0'>"
                        f"<div style='width:{bar_pct}%;background:{ev_color};height:7px;border-radius:4px'></div></div>"
                        f"<span style='color:{DC['text1']};font-weight:700;font-size:.88em;width:25px'>{ev_val}</span>"
                        f"<span style='color:{DC['text2']};font-size:.76em;flex:1'>{_esc(ev_tip)}</span></div>",
                        unsafe_allow_html=True)

            with st.expander("\U0001f4cb Email Metadata & Hashes"):
                meta = R.get('metadata', {})
                hashes = R.get('hashes', {})
                mc1, mc2 = st.columns(2)
                with mc1:
                    st.markdown(f"**From:** `{_esc(meta.get('from', chr(8212))[:80])}`")
                    st.markdown(f"**Subject:** `{_esc(meta.get('subject', chr(8212))[:80])}`")
                    st.markdown(f"**Date:** `{_esc(meta.get('date', chr(8212))[:60])}`")
                with mc2:
                    st.markdown(f"**MD5:** `{hashes.get('md5', chr(8212))}`")
                    st.markdown(f"**SHA256:** `{hashes.get('sha256', chr(8212))}`")

        with tabs[1]:
            st.subheader("\U0001f510 Email Authentication")
            auth = R['auth']
            c1, c2, c3, c4 = st.columns(4)
            for col, lbl, val in [(c1, "SPF", auth.spf), (c2, "DKIM", auth.dkim),
                                  (c3, "DMARC", auth.dmarc), (c4, "Hops", str(auth.hop_count))]:
                delta = "Valid" if val == "PASS" else ("Issue" if val in ("FAIL", "SOFTFAIL") else "")
                dcol = "normal" if val == "PASS" else ("inverse" if val in ("FAIL", "SOFTFAIL") else "off")
                col.metric(lbl, val, delta=delta, delta_color=dcol)
            abuse = R.get('abuse_data', {})
            if abuse and abuse.get('abuseConfidenceScore') is not None:
                ascore = abuse.get('abuseConfidenceScore', 0)
                ac_color = DC['critical'] if ascore >= 75 else (DC['high'] if ascore >= 40 else DC['ok'])
                st.markdown(
                    f"<div style='border-left:4px solid {ac_color};padding:14px;background:{ac_color}22;"
                    f"border-radius:8px;margin:12px 0'><b>\U0001f310 Source IP (AbuseIPDB)</b><br>"
                    f"Score: <b style='color:{ac_color}'>{ascore}/100</b> | "
                    f"Reports: {abuse.get('totalReports', 0)} | "
                    f"Country: {abuse.get('countryCode', '')} | "
                    f"ISP: {_esc(abuse.get('isp', '')[:40])}"
                    f"{'<br>\U0001f9c5 TOR Exit Node' if abuse.get('isTor') else ''}</div>",
                    unsafe_allow_html=True)
            # Show Spamhaus DNSBL result in auth tab if signal fired
            dnsbl_sigs = [s for s in R.get('signals', [])
                          if s.name in ('dnsbl_listed', 'dnsbl_pbl')]
            for ds in dnsbl_sigs:
                ds_color = DC['critical'] if ds.name == 'dnsbl_listed' else DC['warn']
                st.markdown(
                    f"<div style='border-left:4px solid {ds_color};padding:14px;"
                    f"background:{ds_color}22;border-radius:8px;margin:6px 0'>"
                    f"<b>🛡️ Spamhaus ZEN DNSBL</b><br>"
                    f"<span style='color:{ds_color};font-weight:700'>{_esc(ds.title)}</span>"
                    f"<br><span style='font-size:.88em;color:{DC['text2']}'>"
                    f"{_esc(ds.detail)}</span></div>",
                    unsafe_allow_html=True)
            # Show MX validation result if signal fired
            mx_sigs = [s for s in R.get('signals', []) if s.name == 'no_mx_record']
            for ms in mx_sigs:
                st.markdown(
                    f"<div style='border-left:4px solid {DC['warn']};padding:14px;"
                    f"background:{DC['warn']}22;border-radius:8px;margin:6px 0'>"
                    f"<b>📭 MX Record Check</b><br>"
                    f"<span style='font-size:.88em;color:{DC['text2']}'>"
                    f"{_esc(ms.detail)}</span></div>",
                    unsafe_allow_html=True)
            # Show clean DNSBL status if AbuseIPDB absent but DNS available
            if not dnsbl_sigs and not abuse and auth.source_ip and DNS_OK:
                st.markdown(
                    f"<div style='border-left:4px solid {DC['ok']};padding:10px 14px;"
                    f"background:{DC['ok']}12;border-radius:8px;margin:6px 0'>"
                    f"<b style='color:{DC['ok']}'>🛡️ Spamhaus DNSBL</b> "
                    f"<span style='color:{DC['text2']};font-size:.88em'>"
                    f"Source IP not listed in Spamhaus ZEN blocklist</span></div>",
                    unsafe_allow_html=True)
            if R.get('spoof'):
                st.error(f"\U0001f3ad {R['spoof']}")
            st.markdown("#### 📋 Detailed Analysis")

            # Always-populated auth breakdown — never empty
            _ACOLOR = {
                'PASS': DC['ok'], 'FAIL': DC['critical'], 'SOFTFAIL': DC['warn'],
                'NONE': DC['text2'], 'TEMPERROR': DC['warn'], 'PERMERROR': DC['warn'],
            }
            _SPF_EXPLAIN = {
                'PASS':      'The sending server is authorized by the domain owner. Strong positive signal.',
                'FAIL':      'The sending server is NOT authorized — this server has no right to send as this domain.',
                'SOFTFAIL':  'The domain suggests this server is probably not authorized. Weak but notable.',
                'NONE':      'No SPF record found — domain owner has not configured email authentication.',
                'TEMPERROR': 'Temporary DNS lookup failure during SPF evaluation — result is unreliable.',
                'PERMERROR': 'SPF record is malformed or has a configuration error.',
            }
            _DKIM_EXPLAIN = {
                'PASS':   'Cryptographic signature verified — message content has not been modified in transit.',
                'FAIL':   'Signature verification failed — content was modified or header was forged after signing.',
                'NONE':   'No DKIM signature present — common but removes one layer of authentication assurance.',
                'TEMPERROR': 'DNS lookup failed during DKIM verification.',
            }
            _DMARC_EXPLAIN = {
                'PASS':   'Domain policy is enforced and this email complies. Strongest authentication signal.',
                'FAIL':   'Email fails the domain\'s DMARC policy — domain owner declares this is not legitimate.',
                'NONE':   'No DMARC policy configured. Domain does not enforce authentication requirements.',
            }

            da_cols = st.columns(3)
            for col, (proto, val, explain_map) in zip(da_cols, [
                ('SPF',   auth.spf,   _SPF_EXPLAIN),
                ('DKIM',  auth.dkim,  _DKIM_EXPLAIN),
                ('DMARC', auth.dmarc, _DMARC_EXPLAIN),
            ]):
                color = _ACOLOR.get(val, DC['text2'])
                explain = explain_map.get(val, '')
                icon = '✅' if val == 'PASS' else ('🚨' if val in ('FAIL','SOFTFAIL') else 'ℹ️')
                with col:
                    st.markdown(
                        f"<div style='background:{color}12;border:1px solid {color}44;"
                        f"border-radius:8px;padding:10px 14px;height:100%'>"
                        f"<div style='font-weight:700;color:{DC['text2']};font-size:.78em'>{proto}</div>"
                        f"<div style='font-weight:700;color:{color};font-size:1.1em;margin:4px 0'>"
                        f"{icon} {val}</div>"
                        f"<div style='color:{DC['text2']};font-size:.78em;line-height:1.4'>"
                        f"{_esc(explain)}</div></div>",
                        unsafe_allow_html=True)

            # ── Email Origin & Routing (redesigned) ─────────────────────────
            # Replaces the old "ENVELOPE ANALYSIS" plain table.
            # Shows sender path as a logical forensic flow: WHO sent → FROM where
            # → HOW it got here — with risk context on every field.
            st.divider()
            st.markdown(
                f"<div style='font-size:1.05em;font-weight:700;color:{DC['text1']};"
                f"margin:8px 0 12px'>📨 Email Origin & Routing</div>",
                unsafe_allow_html=True)

            _env_cols = st.columns([1, 1])

            # ── LEFT: Sender identity chain ───────────────────────────────────
            with _env_cols[0]:
                # Header From
                if auth.from_full or auth.from_domain:
                    _fd = auth.from_domain or ''
                    _ff = auth.from_full or _fd
                    st.markdown(
                        f"<div style='background:{DC['elev']};border:1px solid {DC['border']}55;"
                        f"border-radius:8px;padding:12px 14px;margin-bottom:8px'>"
                        f"<div style='color:{DC['text2']};font-size:.76em;font-weight:600;"
                        f"letter-spacing:.05em;margin-bottom:4px'>📧 HEADER FROM</div>"
                        f"<div style='color:{DC['text1']};font-size:.88em;word-break:break-all'>"
                        f"{_esc(_ff[:90])}</div>"
                        f"<div style='color:{DC['text2']};font-size:.76em;margin-top:4px'>"
                        f"Domain visible to the recipient — what they see in their email client."
                        f"</div></div>",
                        unsafe_allow_html=True)

                # Return-Path comparison
                if auth.rp_domain:
                    _rp_match = auth.rp_domain == auth.from_domain
                    _rp_color = DC['ok'] if _rp_match else DC['critical']
                    _rp_icon  = '✅' if _rp_match else '🚨'
                    _rp_label = 'Matches From domain — replies go to the correct mailbox.' \
                                if _rp_match else \
                                f'DIFFERS from From domain — replies route to {auth.rp_domain}. ' \
                                f'This is the shadow-spoofing pattern used in BEC attacks.'
                    st.markdown(
                        f"<div style='background:{DC['elev']};border:1px solid {_rp_color}55;"
                        f"border-left:4px solid {_rp_color};"
                        f"border-radius:8px;padding:12px 14px;margin-bottom:8px'>"
                        f"<div style='color:{DC['text2']};font-size:.76em;font-weight:600;"
                        f"letter-spacing:.05em;margin-bottom:4px'>↩️ RETURN-PATH (ENVELOPE FROM)</div>"
                        f"<div style='color:{_rp_color};font-size:.88em;font-weight:600'>"
                        f"{_rp_icon} {_esc(auth.rp_domain)}</div>"
                        f"<div style='color:{DC['text2']};font-size:.76em;margin-top:4px'>"
                        f"{_esc(_rp_label)}</div></div>",
                        unsafe_allow_html=True)
                elif auth.from_domain:
                    st.markdown(
                        f"<div style='background:{DC['elev']};border:1px solid {DC['border']}33;"
                        f"border-radius:8px;padding:12px 14px;margin-bottom:8px'>"
                        f"<div style='color:{DC['text2']};font-size:.76em;font-weight:600;"
                        f"letter-spacing:.05em;margin-bottom:4px'>↩️ RETURN-PATH</div>"
                        f"<div style='color:{DC['text2']};font-size:.85em'>Not present or matches From.</div>"
                        f"</div>", unsafe_allow_html=True)

            # ── RIGHT: Network origin ──────────────────────────────────────────
            with _env_cols[1]:
                # Source IP — enriched with AbuseIPDB data if available
                if auth.source_ip:
                    _abuse_local = R.get('abuse_data', {}) or {}
                    _ip_score    = _abuse_local.get('abuseConfidenceScore')
                    _ip_isp      = _abuse_local.get('isp', '')
                    _ip_country  = _abuse_local.get('countryCode', '')
                    _ip_domain   = _abuse_local.get('domain', '')
                    if _ip_score is not None:
                        _ip_color = DC['critical'] if _ip_score >= 75 \
                                    else (DC['high'] if _ip_score >= 40 else DC['ok'])
                        _ip_badge = f"AbuseIPDB: <b style='color:{_ip_color}'>{_ip_score}/100</b>"
                    else:
                        _ip_color = DC['text2']
                        _ip_badge = "AbuseIPDB: not configured"
                    _ip_meta = ' · '.join(x for x in [_ip_country, _ip_isp[:30], _ip_domain[:25]] if x)
                    st.markdown(
                        f"<div style='background:{DC['elev']};border:1px solid {DC['border']}55;"
                        f"border-radius:8px;padding:12px 14px;margin-bottom:8px'>"
                        f"<div style='color:{DC['text2']};font-size:.76em;font-weight:600;"
                        f"letter-spacing:.05em;margin-bottom:4px'>🌐 ORIGINATING IP</div>"
                        f"<div style='color:{DC['accent']};font-size:.92em;font-weight:600;"
                        f"font-family:monospace'>{_esc(auth.source_ip)}</div>"
                        f"<div style='color:{DC['text2']};font-size:.76em;margin-top:5px'>"
                        f"{_ip_badge}"
                        + (f" &nbsp;·&nbsp; {_esc(_ip_meta)}" if _ip_meta else "")
                        + f"</div><div style='color:{DC['text2']};font-size:.74em;margin-top:3px'>"
                        f"First hop in the Received: chain — the actual sending server.</div></div>",
                        unsafe_allow_html=True)

                # Relay hops — with hop-delay anomaly context
                if auth.hop_count:
                    _hop_thresh   = 5
                    _hop_color    = DC['warn'] if auth.hop_count > _hop_thresh else DC['ok']
                    _hop_icon     = '⚠️' if auth.hop_count > _hop_thresh else '✅'
                    _hop_note     = (f"Unusually high hop count — {auth.hop_count} servers "
                                     f"in relay chain. May indicate routing obfuscation.")  \
                                    if auth.hop_count > _hop_thresh else \
                                    f"Normal relay depth ({auth.hop_count} hops)."
                    _delays_str   = ''
                    if auth.hop_delays:
                        _d_fmt = [f"{d:.0f}s" for d in auth.hop_delays[:4]]
                        _delays_str = f" &nbsp;·&nbsp; Hop delays: {', '.join(_d_fmt)}"
                    if auth.hop_anomaly:
                        _hop_color = DC['warn']
                    st.markdown(
                        f"<div style='background:{DC['elev']};border:1px solid {_hop_color}55;"
                        f"border-left:4px solid {_hop_color};"
                        f"border-radius:8px;padding:12px 14px;margin-bottom:8px'>"
                        f"<div style='color:{DC['text2']};font-size:.76em;font-weight:600;"
                        f"letter-spacing:.05em;margin-bottom:4px'>🔀 RELAY CHAIN</div>"
                        f"<div style='color:{_hop_color};font-size:.92em;font-weight:600'>"
                        f"{_hop_icon} {auth.hop_count} hop{'s' if auth.hop_count != 1 else ''}</div>"
                        f"<div style='color:{DC['text2']};font-size:.76em;margin-top:4px'>"
                        f"{_esc(_hop_note)}{_delays_str}</div>"
                        + (f"<div style='color:{DC['warn']};font-size:.76em;margin-top:3px'>"
                           f"⚠️ {_esc(auth.hop_anomaly)}</div>" if auth.hop_anomaly else "")
                        + "</div>", unsafe_allow_html=True)

            # ── Trusted gateway banner (inline in routing context) ────────────
            if auth.gateway_trust and auth.gateway_name:
                st.markdown(
                    f"<div style='background:{DC['ok']}12;border:1px solid {DC['ok']}44;"
                    f"border-radius:8px;padding:10px 14px;margin-top:4px'>"
                    f"<b style='color:{DC['ok']}'>🛡️ Security Gateway Pre-Screened:</b> "
                    f"<span style='color:{DC['text1']}'>{_esc(auth.gateway_name)}</span>"
                    f" &nbsp;<span style='color:{DC['text2']};font-size:.82em'>— "
                    f"This email passed through a known email security platform before delivery. "
                    f"Authentication results reflect the gateway's own checks.</span></div>",
                    unsafe_allow_html=True)


            # Auth.details items that weren't already shown above
            shown_prefixes = {'spf', 'dkim', 'dmarc', 'source ip', 'return-path', 'hop'}
            extra_details = [d for d in auth.details
                             if not any(d.lower().startswith(p) for p in shown_prefixes)]
            for d in extra_details:
                du = d.upper()
                if any(k in du for k in ["FAIL", "SPOOF", "WARNING", "HIJACK"]):
                    st.error(f"⚠️ {d}")
                elif any(k in du for k in ["PASS", "VERIFIED", "TRUSTED", "CLEAN", "GATEWAY"]):
                    st.success(f"✅ {d}")
                else:
                    st.info(f"ℹ️ {d}")

            if R['anomalies']:
                st.markdown("#### 🔎 Header Anomalies")
                for a in R['anomalies']:
                    if 'hijack' in a.lower():
                        st.error(f"🚨 {a}")
                    else:
                        st.warning(f"⚠️ {a}")

 # ══════════════════════════════════════════════════════════════════
        # TAB 3: URLs & Domains (Updated with Source Badges)
        # ══════════════════════════════════════════════════════════════════
        with tabs[2]:
            st.subheader("🌐 URL, Domain & IP Analysis")
            
            # --- Badge Styling Definition ---
            # Maps o.source -> (Label, BackgroundColor, TextColor)
            _src_map = {
                'header':      ('📡 Header',   '#475569', '#f8fafc'), # Slate-600
                'received':    ('📡 IP',       '#475569', '#f8fafc'),
                'body':        ('📧 Body',     '#334155', '#f8fafc'), # Slate-700
                'html_href':   ('🔗 Link',     '#334155', '#f8fafc'),
                'pdf_uri':     ('📄 PDF',      '#b91c1c', '#ffffff'), # Red-700
                'office_link': ('📝 Office',   '#2563eb', '#ffffff'), # Blue-600
                'qr':          ('📱 QR Code',  '#d97706', '#ffffff'), # Amber-600
            }

            ltms = R.get('link_mismatches', [])
            real_ltm = [m for m in ltms if not m.is_tracking]
            track_ltm = [m for m in ltms if m.is_tracking]
            
            if real_ltm:
                # Deduplicate by (display_domain, href_domain) pair
                seen_pairs = set()
                unique_ltm = []
                for m in real_ltm:
                    pair = (m.display_domain, m.href_domain)
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        unique_ltm.append(m)
                st.error(f"🚨 **{len(unique_ltm)} unique link-text mismatch(es)** "
                         f"({len(real_ltm)} total occurrences)")
                for m in unique_ltm:
                    st.markdown(
                        f"- **Display:** `{_esc(m.display_domain)}` "
                        f"→ **Links to:** `{_esc(m.href_domain)}`")
            if track_ltm:
                # Deduplicate tracking mismatches too
                seen_gw = set()
                unique_gw = []
                for m in track_ltm:
                    if m.href_domain not in seen_gw:
                        seen_gw.add(m.href_domain)
                        unique_gw.append(m)
                with st.expander(
                    f"🛡️ {len(track_ltm)} link(s) via security gateways "
                    f"(normal — suppressed from scoring)"):
                    st.markdown(
                        "These links were rewritten by email security gateways "
                        "(Proofpoint, Trend Micro, Mimecast, etc.) for click-time "
                        "URL scanning. This is **expected behavior** and not a phishing indicator.")
                    for m in unique_gw:
                        st.caption(
                            f"🛡️ `{_esc(m.display_domain)}` → "
                            f"`{_esc(m.href_domain)}` (security rewrite)")
            if real_ltm or track_ltm:
                st.divider()

            obs = R['observables']
            if obs:
                vt_obs = [o for o in obs if o.vt]

                # ── Classify every observable ──────────────────────────────────
                def _obs_display_level(o):
                    tl = o.vt.threat_level if o.vt else 'UNKNOWN'
                    di = o.vt.domain_intel if o.vt else None
                    try:
                        url_dom = _url_host(o.value) if o.type == 'url' else o.value.lower()  # FIX(v13): strip port
                        gw = is_tracking_domain(url_dom)
                    except Exception:
                        gw = False
                    if tl in ('CRITICAL', 'MALICIOUS'): return 'THREAT',   _tc(tl),      _ti(tl)
                    if tl == 'SUSPICIOUS':              return 'SUSPICIOUS',DC['warn'],   '⚠️'
                    if tl == 'UNKNOWN' and gw:          return 'GATEWAY',  DC['accent'],  '🛡️'
                    if tl == 'UNKNOWN' and di and di.trusted: return 'TRUSTED', DC['ok'], '✅'
                    if tl == 'UNKNOWN' and di and di.typosquat: return 'SUSPICIOUS', DC['warn'], '⚠️'
                    if tl == 'UNKNOWN':                 return 'UNKNOWN',  DC['unknown'], '❓'
                    return 'CLEAN', DC['ok'], '✅'

                threats  = [o for o in vt_obs if _obs_display_level(o)[0] in ('THREAT', 'SUSPICIOUS')]
                unknowns = [o for o in vt_obs if _obs_display_level(o)[0] in ('UNKNOWN',)]
                gateways = [o for o in vt_obs if _obs_display_level(o)[0] == 'GATEWAY']
                clean    = [o for o in vt_obs if _obs_display_level(o)[0] in ('CLEAN', 'TRUSTED')]

                # ── Summary bar ───────────────────────────────────────────────
                s1, s2, s3, s4 = st.columns(4)
                s1.metric("🔍 Scanned",  len(vt_obs))
                s2.metric("🚨 Threats",  len(threats),  delta=f"{len(threats)} flagged" if threats else None,
                          delta_color='inverse' if threats else 'off')
                s3.metric("❓ Unknown",  len(unknowns))
                s4.metric("✅ Clean",    len(clean) + len(gateways))
                st.divider()

                def _render_observable(o, expanded=False):
                    """Render one observable as a unified intel card."""
                    dl, dcolor, dic = _obs_display_level(o)
                    di = o.vt.domain_intel if o.vt else None
                    s_label, s_bg, s_fg = _src_map.get(o.source, ('🔎 ' + o.source, '#334155', '#eee'))

                    flags = []
                    if o.is_shortener:    flags.append('URL SHORTENER')
                    if o.suspicious_tld:  flags.append('SUSPICIOUS TLD')
                    try:
                        url_dom = _url_host(o.value) if o.type == 'url' else o.value.lower()  # FIX(v13): strip port
                        if is_tracking_domain(url_dom): flags.append('SECURITY GATEWAY')
                    except Exception: pass

                    flag_html = ''.join(
                        f"<span style='background:{DC['warn']}33;color:{DC['warn']};padding:1px 7px;"
                        f"border-radius:4px;font-size:.72em;margin-left:5px'>{f}</span>"
                        for f in flags)

                    header_label = f"{dic} {o.type.upper()}: {o.defanged[:60]}"
                    with st.expander(header_label, expanded=expanded):
                        # Top badges row
                        st.markdown(
                            f"<div style='display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-bottom:10px'>"
                            f"<span style='background:{s_bg};color:{s_fg};padding:2px 9px;"
                            f"border-radius:5px;font-size:.77em;font-weight:600'>{s_label}</span>"
                            f"<span style='background:{dcolor};color:#fff;padding:2px 9px;"
                            f"border-radius:5px;font-size:.77em;font-weight:700'>{dl}</span>"
                            f"{flag_html}"
                            f"<code style='color:{DC['accent']};font-size:.82em;margin-left:4px;word-break:break-all'>"
                            f"{_esc(o.defanged)}</code></div>",
                            unsafe_allow_html=True)

                        # Intel source table — VT / OTX / XForce in one compact block
                        intel_rows = []

                        # VirusTotal row
                        if o.vt and o.vt.success:
                            vt_color = _tc(o.vt.threat_level)
                            vt_detail = o.vt.reasoning or ''
                            if o.vt.malicious and o.vt.total:
                                vt_detail += f" ({o.vt.malicious}/{o.vt.total} engines)"
                            intel_rows.append(('🔍 VirusTotal',   o.vt.threat_level, vt_color, vt_detail))

                        # OTX row
                        if o.otx:
                            otx_lvl = o.otx.get('threat_level', '')
                            otx_rsn = o.otx.get('reasoning', '')
                            otx_p   = o.otx.get('pulse_count', 0)
                            otx_fam = o.otx.get('malware_families', [])
                            otx_extra = (f" · {otx_p} pulse(s)" if otx_p else '') + \
                                        (f" · {', '.join(otx_fam[:2])}" if otx_fam else '')
                            intel_rows.append(('🛸 OTX', otx_lvl, _tc(otx_lvl), otx_rsn + otx_extra))

                        # X-Force row
                        if o.xforce:
                            xf_lvl = o.xforce.get('threat_level', '')
                            xf_rsn = o.xforce.get('reasoning', '')
                            xf_cat = o.xforce.get('categories', [])
                            xf_extra = (f" · {', '.join(xf_cat[:2])}" if xf_cat else '')
                            intel_rows.append(('🔷 X-Force', xf_lvl, _tc(xf_lvl), xf_rsn + xf_extra))

                        if intel_rows:
                            # 1. Build the Centered, High-Visibility Table
                            rows_html = ''.join(
                                f"<tr style='border-bottom:1px solid {DC['border']}66; background:rgba(0,0,0,0.15);'>"
                                f"<td style='color:{DC['text1']};font-size:.85em;padding:10px;text-align:center;font-weight:600;white-space:nowrap;width:20%;'>{src}</td>"
                                f"<td style='padding:10px;text-align:center;width:20%;'>"
                                f"<span style='background:{col};color:#fff;padding:4px 12px;border-radius:6px;font-size:.75em;font-weight:bold;letter-spacing:0.5px;'>{lvl}</span></td>"
                                f"<td style='color:{DC['text1']};font-size:.85em;padding:10px;text-align:center;width:60%;'>{_esc(det[:120])}</td></tr>"
                                for src, lvl, col, det in intel_rows)
                            
                            # 2. Build Interactive Link Buttons for ALL active engines
                            link_buttons = []
                            
                            # VirusTotal Link
                            if o.type == 'ip':
                                vt_gui = f"https://www.virustotal.com/gui/ip-address/{o.value}"
                            elif o.type == 'domain':
                                vt_gui = f"https://www.virustotal.com/gui/domain/{o.value}"
                            else:
                                import base64 as _b64
                                _uid = _b64.urlsafe_b64encode(o.value.encode()).decode().strip('=')
                                vt_gui = f"https://www.virustotal.com/gui/url/{_uid}"
                            link_buttons.append(f"<a href='{vt_gui}' target='_blank' style='color:#38bdf8;text-decoration:none;font-size:.8em;background:#0f172a;padding:5px 12px;border-radius:6px;border:1px solid #334155'>🔍 VirusTotal ↗</a>")

                            # AlienVault OTX Link
                            if o.otx:
                                otx_path = 'ip' if o.type == 'ip' else 'domain'
                                otx_val = _url_host(o.value) if o.type == 'url' else o.value
                                otx_gui = f"https://otx.alienvault.com/indicator/{otx_path}/{otx_val}"
                                link_buttons.append(f"<a href='{otx_gui}' target='_blank' style='color:#38bdf8;text-decoration:none;font-size:.8em;background:#0f172a;padding:5px 12px;border-radius:6px;border:1px solid #334155'>🛸 AlienVault OTX ↗</a>")

                            # IBM X-Force Link
                            if o.xforce:
                                import urllib.parse
                                xf_path = 'ip' if o.type == 'ip' else 'url'
                                xf_val = urllib.parse.quote(o.value, safe='')
                                xf_gui = f"https://exchange.xforce.ibmcloud.com/{xf_path}/{xf_val}"
                                link_buttons.append(f"<a href='{xf_gui}' target='_blank' style='color:#38bdf8;text-decoration:none;font-size:.8em;background:#0f172a;padding:5px 12px;border-radius:6px;border:1px solid #334155'>🔷 IBM X-Force ↗</a>")

                            links_html = f"<div style='display:flex;gap:12px;justify-content:center;margin-top:12px;margin-bottom:6px;'>{''.join(link_buttons)}</div>"

                            # Render the table and the link buttons
                            st.markdown(
                                f"<table style='width:100%;border-collapse:collapse;background:{DC['card']};border-radius:8px;overflow:hidden;box-shadow:0 4px 6px rgba(0,0,0,0.1);'>"
                                f"{rows_html}</table>"
                                f"{links_html}",
                                unsafe_allow_html=True)

                        # Local domain intelligence
                        if di:
                            dom_parts = []
                            if di.category and di.category != 'unknown':
                                dom_parts.append(f"Category: <b>{_esc(di.category)}</b>")
                            if di.age_days > 0:
                                age_icon = '🆕' if di.age_days < 30 else '📅'
                                dom_parts.append(f"{age_icon} Age: {di.age_days}d")
                            if di.org:
                                dom_parts.append(f"Org: {_esc(di.org[:40])}")
                            if di.reasoning:
                                dom_parts.append(_esc(di.reasoning[:60]))
                            if dom_parts:
                                st.markdown(
                                    f"<div style='color:{DC['text2']};font-size:.78em;"
                                    f"margin-top:6px'>🔍 {' &nbsp;·&nbsp; '.join(dom_parts)}</div>",
                                    unsafe_allow_html=True)
                            if di.typosquat:
                                st.error(f"🚨 {di.typosquat}")

                # ── THREATS section ────────────────────────────────────────────
                if threats:
                    st.markdown(
                        f"<div style='color:{DC['critical']};font-weight:700;font-size:.95em;"
                        f"margin:6px 0 4px'>🚨 THREATS & SUSPICIOUS ({len(threats)})</div>",
                        unsafe_allow_html=True)
                    for o in threats:
                        _render_observable(o, expanded=True)
                    st.divider()

                # ── UNKNOWN section ────────────────────────────────────────────
                if unknowns:
                    st.markdown(
                        f"<div style='color:{DC['text1']};font-weight:700;font-size:.95em;"
                        f"margin:6px 0 2px'>❓ UNKNOWN — not in VirusTotal database ({len(unknowns)})</div>"
                        f"<div style='color:{DC['text2']};font-size:.78em;margin-bottom:6px'>"
                        f"UNKNOWN ≠ malicious. VT only indexes previously-scanned URLs. "
                        f"Review local intel and OTX/X-Force columns below.</div>",
                        unsafe_allow_html=True)
                    for o in unknowns:
                        _render_observable(o, expanded=False)
                    st.divider()

                # ── GATEWAYS section (collapsed) ───────────────────────────────
                if gateways:
                    with st.expander(f"🛡️ {len(gateways)} security gateway rewrite(s) — normal, not threats"):
                        st.caption("These links were rewritten by email security services (Proofpoint, Trend Micro, Mimecast) for click-time scanning.")
                        for o in gateways:
                            _render_observable(o, expanded=False)

                # ── CLEAN section (collapsed) ──────────────────────────────────
                if clean:
                    with st.expander(f"✅ {len(clean)} clean / trusted observable(s)"):
                        for o in clean:
                            _render_observable(o, expanded=False)

            else:
                st.success("✅ No observables extracted")
                
        with tabs[3]:
            st.subheader("\U0001f4ce Attachment Analysis")
            for risk in R.get('attachment_risks', []):
                if risk['severity'] == 'CRITICAL':
                    st.error(f"\U0001f6a8 [{risk['severity']}] {risk['desc']}")
                elif risk['severity'] == 'HIGH':
                    st.warning(f"\u26a0\ufe0f [{risk['severity']}] {risk['desc']}")
                else:
                    st.info(f"\u2139\ufe0f [{risk['severity']}] {risk['desc']}")
            # Filter out [Body] pseudo-entry and display real file attachments
            real_macros = [m for m in R['macros'] if m.filename != '[Body]']
            for m in real_macros:
                # Derive effective risk level from risk_score AND verdict/has_macros.
                # Before this fix, a PDF with /OpenAction had risk_score=0 (now fixed above),
                # but we keep this fallback so any future code path can't cause green+SUSPICIOUS.
                is_suspicious_verdict = m.verdict == 'SUSPICIOUS' or m.has_macros
                eff_score = m.risk_score
                if is_suspicious_verdict and eff_score < 30:
                    eff_score = 30  # Floor: SUSPICIOUS verdict always at least amber
                mc_color = DC['critical'] if eff_score >= 70 else (DC['high'] if eff_score >= 40 else (DC['warn'] if eff_score >= 30 else DC['ok']))
                mi = "\U0001f534" if eff_score >= 70 else ("\U0001f7e1" if eff_score >= 40 else ("\U0001f7e0" if eff_score >= 30 else "\U0001f7e2"))
                # Display label: show effective risk alongside raw score if they differ
                risk_label = str(m.risk_score)
                verdict_display = m.verdict or "SAFE"
                st.markdown(
                    f"<div style='border-left:4px solid {mc_color};background:{mc_color}22;padding:14px;"
                    f"margin:10px 0;border-radius:8px'>"
                    f"<h4 style='margin:0 0 6px 0'>{mi} {_esc(m.filename)}</h4>"
                    f"<p style='margin:0;font-size:.9em'><b>Type:</b> {_esc(m.file_type)} | "
                    f"<b>Risk:</b> {risk_label}/100 | "
                    f"<b>Verdict:</b> <span style='color:{mc_color};font-weight:700'>{_esc(verdict_display)}</span></p>"
                    f"{'<p style=\"margin:4px 0;color:'+DC['text2']+';font-size:.8em\">SHA256: '+_esc(m.sha256)+'</p>' if m.sha256 else ''}"
                    f"{'<p style=\"margin:4px 0;color:'+DC['critical']+';font-weight:700\">⚠️ MALWARE: '+_esc(m.mb_family)+'</p>' if m.mb_found else ''}"
                    f"</div>",
                    unsafe_allow_html=True)
                if m.pdf_uris:
                    with st.expander(f"\U0001f517 {len(m.pdf_uris)} embedded URL(s)"):
                        for u in m.pdf_uris:
                            st.code(defang(u))
                if m.details:
                    with st.expander("\U0001f4cb Analysis Details"):
                        for d in m.details:
                            st.text(d)
            if not real_macros and not R.get("attachment_risks"):
                # FIX(v16-F): Detect hyperlinks disguised as file attachments.
                # A common phishing technique: the email body has a link like
                # <a href="https://attacker.sharepoint.com/...">invoice.pdf</a>
                # The victim sees what looks like a PDF attachment but it is
                # actually a hyperlink. Detect this pattern and warn the analyst.
                _FILE_EXTS = (".pdf", ".docx", ".doc", ".xlsx", ".xls", ".zip",
                              ".exe", ".pptx", ".ppt", ".rar", ".7z", ".js", ".vbs")
                _fake_attach = [
                    m for m in R.get("link_mismatches", [])
                    if not m.is_tracking and
                    any(m.display_domain.lower().endswith(ext) for ext in _FILE_EXTS)
                ]
                if _fake_attach:
                    st.warning(
                        f"\u26a0\ufe0f **No actual file attachments found** — but "
                        f"**{len(_fake_attach)} hyperlink(s) are disguised as file names** "
                        f"(e.g. `{_fake_attach[0].display_domain}`). This is a classic "
                        f"phishing technique: the link LOOKS like an attachment but "
                        f"redirects to an external site. See the **URLs & Domains** tab.")
                else:
                    st.success("\u2705 No file attachments to analyze")

        with tabs[4]:
            st.subheader("\U0001f534 YARA Engine Results")

            # ── Engine status banner ──────────────────────────────────────────
            if YARA_OK:
                # Force a _get_yara() call so _yara_found_path / _yara_last_error
                # are populated before we render the status panel.
                _get_yara()
                ext_path = _external_yara_path()

                if _yara_cofense_loaded:
                    # ── SUCCESS: Cofense rules loaded ─────────────────────────
                    try:
                        with open(ext_path, 'r', encoding='utf-8', errors='ignore') as _fh:
                            _src = _fh.read()
                        _ext_count = _src.count('\nrule ') + (1 if _src.startswith('rule ') else 0)
                    except Exception:
                        _ext_count = 0
                    st.markdown(
                        f"<div style='background:#0f291e;border:1px solid #1a5c38;border-radius:8px;"
                        f"padding:10px 16px;margin-bottom:12px;color:#4ade80;font-size:.9em'>"
                        f"✅ <b>YARA Engine: {_BUILTIN_RULE_COUNT} built-in + {_ext_count:,} Cofense intel rules loaded</b>"
                        f"<span style='color:#6b7280'> | {os.path.basename(ext_path)}</span></div>",
                        unsafe_allow_html=True)

                elif _yara_found_path and _yara_last_error:
                    # ── FILE FOUND — two sub-cases ────────────────────────────
                    if _yara_last_error.startswith("\u26a0\ufe0f Auto-repaired:"):
                        # AMBER: repair succeeded — Cofense IS active, partial load
                        st.markdown(
                            f"<div style=\'background:#1f1a08;border:1px solid #854d0e;border-radius:8px;"
                            f"padding:10px 16px;margin-bottom:4px;color:#fde68a;font-size:.9em\'>"
                            f"\u26a0\ufe0f <b>YARA: triage_rules.yar auto-repaired \u2014 Cofense rules active (partial load)</b>"
                            f"<span style=\'color:#9ca3af\'> | {os.path.basename(_yara_found_path)}</span></div>",
                            unsafe_allow_html=True)
                        with st.expander("\u2139\ufe0f Repair details (click to expand)"):
                            st.warning(_yara_last_error)
                            st.caption(
                                "The .yar file had a syntax error (typically a truncated last rule from an "
                                "incomplete download). Sherlock automatically skipped the broken rule(s) and "
                                "loaded everything else. To fix permanently: re-download triage_rules.yar."
                            )
                    else:
                        # RED: both compile AND repair failed
                        st.markdown(
                            f"<div style=\'background:#2d1515;border:1px solid #7c2d12;border-radius:8px;"
                            f"padding:10px 16px;margin-bottom:4px;color:#fca5a5;font-size:.9em\'>"
                            f"\u274c <b>YARA: triage_rules.yar found but could not be loaded</b>"
                            f"<span style=\'color:#9ca3af\'> | {_yara_found_path}</span></div>",
                            unsafe_allow_html=True)
                        st.error(f"Error: {_yara_last_error}")
                        st.caption(
                            "File found but neither compile nor auto-repair succeeded. "
                            "Common causes: completely empty file, encoding corruption, or a YARA "
                            "module version incompatibility. "
                            f"To diagnose: python3 -c \"import yara; yara.compile(filepath=r\'{_yara_found_path}\')\"."
                        )
                else:
                    # ── FILE NOT FOUND ─────────────────────────────────────────
                    # Compute and display all paths that were searched so the user
                    # knows exactly where to place the file.
                    import inspect as _inspect
                    _search_dirs = set()
                    try:
                        _search_dirs.add(os.path.dirname(os.path.realpath(__file__)))
                    except Exception:
                        pass
                    try:
                        _search_dirs.add(os.getcwd())
                    except Exception:
                        pass
                    _search_dirs.add(_SENDER_DB_DIR_FOR_YARA)
                    _dirs_str = " | ".join(sorted(_search_dirs))

                    st.markdown(
                        f"<div style='background:#1a1f2e;border:1px solid #374151;border-radius:8px;"
                        f"padding:10px 16px;margin-bottom:4px;color:#9ca3af;font-size:.9em'>"
                        f"⚠️ <b>YARA Engine: {_BUILTIN_RULE_COUNT} built-in rules only</b>"
                        f"<span style='color:#6b7280'> | triage_rules.yar not found</span></div>",
                        unsafe_allow_html=True)
                    with st.expander("📂 Where to place triage_rules.yar (click to see searched paths)"):
                        st.markdown("**Sherlock searched these directories (place the file in any one):**")
                        for _d in sorted(_search_dirs):
                            _target = os.path.join(_d, 'triage_rules.yar')
                            _exists = "✅ found" if os.path.isfile(_target) else "❌ not here"
                            st.code(f"{_target}  ← {_exists}")
                        st.markdown("**Or set the environment variable before starting:**")
                        st.code("export SHERLOCK_YARA_RULES=/full/path/to/triage_rules.yar")
                        st.caption("After placing the file, re-run the analysis — no Streamlit restart needed.")
            # ── Hits ──────────────────────────────────────────────────────────
            hits = [(m.filename, y) for m in R['macros'] for y in m.yara_matches]
            threat_hits = [(fn, y) for fn, y in hits if not y.get('enrichment')]
            enrich_hits = [(fn, y) for fn, y in hits if y.get('enrichment')]

            if hits:
                # Summary metrics
                sev_counts = {}
                for _, y in threat_hits:
                    sev_counts[y['severity']] = sev_counts.get(y['severity'], 0) + 1
                c1, c2, c3, c4, c5 = st.columns(5)
                c1.metric("Total Hits", len(hits))
                c2.metric("🔴 CRITICAL", sev_counts.get('CRITICAL', 0))
                c3.metric("🟠 HIGH",     sev_counts.get('HIGH', 0))
                c4.metric("🟡 MEDIUM",   sev_counts.get('MEDIUM', 0))
                c5.metric("🟢 LOW/INFO", sev_counts.get('LOW', 0) + sev_counts.get('INFO', 0))

                st.markdown(
                    f"<b>{len(threat_hits)} threat rule(s) matched across "
                    f"{len(set(f for f, _ in threat_hits))} source(s)</b>",
                    unsafe_allow_html=True)

                # Group by filename
                from collections import defaultdict as _dd
                by_file = _dd(list)
                for fn, y in hits:
                    by_file[fn].append(y)

                for fn, ys in by_file.items():
                    threat_ys  = [y for y in ys if not y.get('enrichment')]
                    enrich_ys  = [y for y in ys if y.get('enrichment')]
                    icon = "📎" if fn != "[Email]" else "📧"
                    with st.expander(f"{icon} {fn} — {len(threat_ys)} hit(s)", expanded=True):
                        for y in threat_ys + enrich_ys:
                            yc   = _tc(y['severity'])
                            # Source badge: built-in vs Cofense
                            is_cofense = not any(
                                y['rule'] == r for r in [
                                    'VBA_Macro_Dropper','VBA_Obfuscated','PDF_JS_Exploit',
                                    'PDF_Launch','EXE_Magic','Archive_Sig','Phishing_Form',
                                    'Macro_Registry','PS_In_Macro'
                                ])
                            src_badge = (
                                "<span style='background:#374151;color:#d1d5db;padding:2px 8px;"
                                "border-radius:8px;font-size:.75em;margin-left:4px'>Cofense</span>"
                                if is_cofense else
                                "<span style='background:#1e3a5f;color:#93c5fd;padding:2px 8px;"
                                "border-radius:8px;font-size:.75em;margin-left:4px'>Built-in</span>"
                            )
                            tlp = y.get('tlp', '')
                            tlp_badge = (
                                f"<span style='background:#7c3aed;color:#fff;padding:2px 8px;"
                                f"border-radius:8px;font-size:.75em;margin-left:4px'>{_esc(tlp)}</span>"
                                if tlp else ""
                            )
                            enrich_note = (
                                "<span style='color:#6b7280;font-size:.8em'> — informational only, no score impact</span>"
                                if y.get('enrichment') else ""
                            )
                            strings_html = ""
                            if y.get('strings'):
                                matched = " | ".join(_esc(s) for s in y['strings'])
                                strings_html = (
                                    f"<div style='background:#0d1117;border-radius:4px;padding:6px 10px;"
                                    f"margin-top:6px;font-family:monospace;font-size:.82em;color:#7ee787'>"
                                    f"Matched: {matched}</div>"
                                )
                            st.markdown(
                                f"<div style='border-left:5px solid {yc};background:{yc}12;padding:14px 16px;"
                                f"margin:8px 0;border-radius:8px'>"
                                f"<div style='display:flex;align-items:center;gap:6px;flex-wrap:wrap'>"
                                f"<span style='color:{yc};font-weight:700;font-size:1em'>🔴 {_esc(y['rule'])}</span>"
                                f"<span style='background:{yc};color:#fff;padding:2px 10px;border-radius:12px;"
                                f"font-size:.78em;font-weight:700'>{_esc(y['severity'])}</span>"
                                f"{src_badge}{tlp_badge}</div>"
                                f"<div style='color:{DC['text1']};margin-top:4px'>{_esc(y['desc'])}{enrich_note}</div>"
                                f"{strings_html}</div>",
                                unsafe_allow_html=True)

            elif YARA_OK:
                st.success("\u2705 YARA engine scanned all files — 0 rule matches")
            else:
                st.warning("\u26a0\ufe0f YARA engine offline. Install: `pip install yara-python`")

        with tabs[5]:
            st.subheader("\U0001f5bc\ufe0f Image Forensics")
            if R['images']:
                for img in R['images']:
                    # Determine verdict for this image
                    has_threat = img.has_steg or any(
                        'steg' in f.lower() or 'overlay' in f.lower()
                        for f in img.findings)
                    has_qr = bool(img.qr_links)
                    is_tracker = any('tracking' in f.lower() or '<=2x2' in f
                                     for f in img.findings)

                    if has_threat:
                        ic_color = DC['critical']
                        verdict_text = "\U0001f6a8 SUSPICIOUS"
                        verdict_detail = "Steganography or hidden content detected"
                    elif has_qr:
                        ic_color = DC['warn']
                        verdict_text = "\u26a0\ufe0f QR CODE FOUND"
                        verdict_detail = "Contains QR code with embedded URL(s)"
                    elif is_tracker:
                        ic_color = DC['text2']
                        verdict_text = "\U0001f4e1 TRACKING PIXEL"
                        verdict_detail = "Tiny image used for email open tracking"
                    else:
                        ic_color = DC['ok']
                        verdict_text = "\u2705 CLEAN"
                        verdict_detail = "No threats, hidden data, or QR codes found"

                    # Image header with verdict badge
                    st.markdown(
                        f"<div style='border-left:4px solid {ic_color};background:{ic_color}12;"
                        f"padding:14px 16px;margin:10px 0;border-radius:8px'>"
                        f"<div style='display:flex;justify-content:space-between;align-items:center;"
                        f"flex-wrap:wrap;gap:8px'>"
                        f"<b style='color:{DC['text1']};font-size:1.05em'>"
                        f"\U0001f4f7 {_esc(img.filename)}</b>"
                        f"<span style='background:{ic_color};color:#fff;padding:4px 14px;"
                        f"border-radius:12px;font-size:.82em;font-weight:700'>"
                        f"{verdict_text}</span></div>"
                        f"<div style='color:{DC['text2']};font-size:.85em;margin-top:6px'>"
                        f"Format: {_esc(img.fmt or 'Unknown')} | "
                        f"Size: {img.size[0]}x{img.size[1]} | "
                        f"{verdict_detail}</div></div>",
                        unsafe_allow_html=True)

                    # Image preview + findings side by side
                    col_img, col_info = st.columns([1, 2])
                    with col_img:
                        if img.data:
                            try:
                                st.image(img.data, caption=img.filename,
                                         use_container_width=True)
                            except Exception:
                                st.caption("(Preview not available)")
                        else:
                            st.caption("(No image data)")
                    with col_info:
                        if img.findings:
                            for f in img.findings:
                                fl = f.lower()
                                if 'steg' in fl or 'overlay' in fl:
                                    st.error(f"\U0001f6a8 {f}")
                                elif 'qr' in fl:
                                    st.warning(f"\u26a0\ufe0f {f}")
                                elif 'ocr' in fl:
                                    st.info(f"\U0001f50d {f}")
                                elif 'tracking' in fl or '<=2x2' in fl:
                                    st.caption(f"\U0001f4e1 {f}")
                                else:
                                    st.info(f"\u2139\ufe0f {f}")
                        else:
                            st.success("\u2705 No anomalies detected in this image")
                        if img.ocr_text:
                            with st.expander("\U0001f50d OCR Extracted Text"):
                                st.text(img.ocr_text[:500])
                        if img.qr_links:
                            st.markdown("**📱 QR Code Links (scanned & defanged):**")
                            # Find the matching observable for this QR URL to get intel
                            qr_obs = {o.value: o for o in R['observables'] if o.source == 'qr'}
                            for ql in img.qr_links:
                                obs = qr_obs.get(ql)
                                # Determine worst threat level across all intel sources
                                levels = []
                                if obs:
                                    if obs.vt:    levels.append(obs.vt.threat_level)
                                    if obs.otx:   levels.append(obs.otx.get('threat_level', ''))
                                    if obs.xforce: levels.append(obs.xforce.get('threat_level', ''))
                                _rank = {'CRITICAL': 5, 'MALICIOUS': 4, 'HIGH': 3,
                                         'SUSPICIOUS': 2, 'UNKNOWN': 1, 'CLEAN': 0, '': 0}
                                worst = max(levels, key=lambda x: _rank.get(x, 0)) if levels else 'UNKNOWN'
                                badge_color = _tc(worst)
                                badge_icon  = {'CRITICAL': '🚨', 'MALICIOUS': '🚨',
                                               'HIGH': '🔴', 'SUSPICIOUS': '🟠',
                                               'UNKNOWN': '⚪', 'CLEAN': '✅'}.get(worst, '⚪')

                                # Build intel tooltip lines
                                intel_lines = []
                                if obs and obs.vt and obs.vt.success:
                                    intel_lines.append(f"VT: {obs.vt.threat_level} — {obs.vt.reasoning}")
                                if obs and obs.otx:
                                    intel_lines.append(f"OTX: {obs.otx.get('reasoning', 'No data')}")
                                if obs and obs.xforce:
                                    intel_lines.append(f"X-Force: {obs.xforce.get('reasoning', 'No data')}")

                                st.markdown(
                                    f"<div style='background:{badge_color}15;border-left:4px solid {badge_color};"
                                    f"border-radius:6px;padding:10px 14px;margin:6px 0'>"
                                    f"<div style='display:flex;align-items:center;gap:8px;flex-wrap:wrap'>"
                                    f"<span style='font-size:1.1em'>{badge_icon}</span>"
                                    f"<span style='background:{badge_color};color:#fff;padding:2px 8px;"
                                    f"border-radius:8px;font-size:.78em;font-weight:700'>{worst}</span>"
                                    f"<code style='color:{DC['accent']};word-break:break-all'>{_esc(defang(ql))}</code>"
                                    f"</div>"
                                    + (f"<div style='margin-top:6px;color:{DC['text2']};font-size:.82em'>"
                                       + "<br>".join(_esc(l) for l in intel_lines)
                                       + "</div>" if intel_lines else "")
                                    + "</div>",
                                    unsafe_allow_html=True)
                    st.divider()
            else:
                st.success("\u2705 No images found in this email")

        with tabs[6]:
            st.subheader("\U0001f4ca Complete Signal Table")
            # Filter out zero-probability BEC markers
            display_signals = [s for s in R['signals']
                               if not (s.probability == 0.0 and s.name.startswith('bec_')
                                       and s.name != 'bec_combined')]
            if display_signals:
                df = pd.DataFrame([{
                    'Tier': f"T{s.tier}", 'Category': s.category, 'Signal': s.title,
                    'Probability': f"{s.probability:.0%}", 'Confidence': f"{s.confidence:.0%}",
                    'Impact': f"{s.probability * s.confidence:.0%}", 'Detail': s.detail[:80]
                } for s in sorted(display_signals,
                                  key=lambda x: x.probability * x.confidence, reverse=True)])
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.success("\u2705 No findings")
            if R['trust_factors']:
                st.subheader("\U0001f6e1\ufe0f Trust Factor Table")
                tdf = pd.DataFrame([{
                    'Factor': tf.name, 'Strength': f"{tf.strength:.0%}",
                    'Confidence': f"{tf.confidence:.0%}", 'Description': tf.description
                } for tf in R['trust_factors']])
                st.dataframe(tdf, use_container_width=True, hide_index=True)

        with tabs[7]:
            st.subheader("\U0001f4be Export Options")
            ec1, ec2, ec3 = st.columns(3)
            with ec1:
                st.download_button("\U0001f4e5 Download TXT Report", txt,
                                   "sherlock_report.txt", "text/plain")
            with ec2:
                if PDF_REPORT_OK:
                    pdf = generate_pdf_report(txt)
                    if pdf:
                        st.download_button("\U0001f4e5 Download PDF Report", pdf,
                                           "sherlock_report.pdf", "application/pdf")
                else:
                    st.warning("Install reportlab for PDF export")
            with ec3:
                st.download_button("\U0001f4e5 Download JSON Data",
                                   json.dumps(R, default=str, indent=2),
                                   "sherlock_data.json", "application/json")

            st.divider()
            st.markdown(
                f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
                f"border:2px solid {DC['purple']};border-left:6px solid {DC['purple']};"
                f"border-radius:12px;padding:16px 20px;margin:12px 0'>"
                f"<div style='font-size:1.15em;font-weight:700;color:{DC['purple']}'>"
                f"\U0001f4cb ANALYST REPORT</div>"
                f"<div style='color:{DC['text2']};font-size:.85em;margin-top:4px'>"
                f"Auto-populated from analysis data &mdash; fully editable. "
                f"Edit, copy, and paste directly into your ticketing system or report.</div></div>",
                unsafe_allow_html=True)
            analyst_report_text = generate_analyst_report(R)
            st.text_area(
                label="Analyst Report (editable)",
                value=analyst_report_text,
                height=420,
                key="analyst_report_textarea",
                label_visibility="collapsed"
            )
            st.download_button(
                "\U0001f4e5 Download Analyst Report",
                analyst_report_text,
                "sherlock_analyst_report.txt",
                "text/plain"
            )

        # ── SOC Integration Tab ───────────────────────────────────────────────
        with tabs[8]:
            st.subheader("\U0001f50c SOC / SOAR Integration")

            # ── Case Identity ─────────────────────────────────────────────────
            current_case_id = st.session_state.get('case_id', '')
            st.markdown(
                f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
                f"border:2px solid {DC['purple']};border-left:6px solid {DC['purple']};"
                f"border-radius:12px;padding:16px 20px;margin:0 0 16px 0'>"
                f"<div style='display:flex;align-items:center;gap:14px;flex-wrap:wrap'>"
                f"<div>"
                f"<div style='color:{DC['text2']};font-size:.8em;font-weight:600;letter-spacing:.06em'>CASE ID</div>"
                f"<code style='color:{DC['accent']};font-size:1.05em'>{current_case_id or 'Not saved yet'}</code>"
                f"</div>"
                f"<div style='margin-left:auto'>"
                f"<span style='background:{DC['purple']};color:#fff;padding:5px 14px;border-radius:10px;"
                f"font-size:.82em;font-weight:700'>MD5: {R['hashes']['md5'][:16]}...</span>"
                f"</div></div></div>",
                unsafe_allow_html=True)

            # ── Case Status Workflow ──────────────────────────────────────────
            st.markdown(f"<div style='font-size:1.1em;font-weight:700;color:{DC['text1']};"
                        f"margin-bottom:8px'>\U0001f4cb Case Management</div>",
                        unsafe_allow_html=True)
            status_colors = {
                'NEW': DC['accent'], 'IN_PROGRESS': DC['warn'],
                'ESCALATED': DC['critical'], 'CLOSED': DC['ok'],
                'FALSE_POSITIVE': DC['text2'],
            }
            # Load current status from DB
            current_row = case_get(current_case_id) if current_case_id else None
            current_status = (current_row or {}).get('status', 'NEW')

            scol1, scol2, scol3 = st.columns([2, 2, 3])
            with scol1:
                new_status = st.selectbox(
                    "Set Status",
                    options=sorted(VALID_STATUSES),
                    index=sorted(VALID_STATUSES).index(current_status)
                          if current_status in VALID_STATUSES else 0,
                    key="soc_status_select"
                )
            with scol2:
                analyst_name = st.text_input("Analyst Name", value="", key="soc_analyst_name")
            with scol3:
                analyst_note_input = st.text_input(
                    "Add Note", placeholder="e.g. Confirmed FP — internal newsletter",
                    key="soc_note_input"
                )

            if st.button("\U0001f4be Save Status & Note", type="primary", key="soc_save_btn"):
                if current_case_id:
                    ok = case_update(
                        current_case_id,
                        status=new_status,
                        notes=((current_row or {}).get('analyst_notes', '') + "\n"
                               + f"[{datetime.now():%Y-%m-%d %H:%M}] {analyst_name or 'analyst'}: {analyst_note_input}").strip()
                        if analyst_note_input else None,
                        analyst=analyst_name or "analyst"
                    )
                    if ok:
                        st.success(f"\u2705 Case `{current_case_id[:8]}...` updated → **{new_status}**")
                    else:
                        st.error("Update failed — check logs")
                else:
                    st.warning("No case saved yet — run analysis first")

            # Show existing notes
            existing_notes = (current_row or {}).get('analyst_notes', '')
            if existing_notes:
                with st.expander("\U0001f4dd Analyst Notes History"):
                    st.text(existing_notes)

            st.divider()

            # ── API Endpoint Reference ────────────────────────────────────────
            st.markdown(f"<div style='font-size:1.1em;font-weight:700;color:{DC['text1']};"
                        f"margin-bottom:8px'>\U0001f310 REST API Endpoints</div>",
                        unsafe_allow_html=True)
            if True:  # stdlib http.server API is always available
                api_base = f"http://localhost:{Config.API_PORT}"
                endpoints = [
                    ("GET",   "/health",                          "Health check (no auth)"),
                    ("GET",   "/api/v1/stats",                    "Aggregate statistics"),
                    ("GET",   "/api/v1/cases?status=NEW&min_score=40", "List/filter cases"),
                    ("GET",   f"/api/v1/case/{current_case_id or '{case_id}'}", "Get full case"),
                    ("PATCH", f"/api/v1/case/{current_case_id or '{case_id}'}?status=CLOSED", "Update status"),
                    ("GET",   f"/api/v1/case/{current_case_id or '{case_id}'}/iocs", "IOC list"),
                    ("GET",   f"/api/v1/case/{current_case_id or '{case_id}'}/mitre", "MITRE ATT&CK"),
                    ("GET",   f"/api/v1/lookup/{R['hashes']['md5']}", "Cache lookup by MD5"),
                ]
                method_colors = {'GET': '#10b981', 'POST': '#3b82f6', 'PATCH': '#f59e0b'}
                rows_html = ""
                for method, path, desc in endpoints:
                    mc = method_colors.get(method, DC['text2'])
                    rows_html += (
                        f"<tr>"
                        f"<td style='padding:6px 10px;white-space:nowrap'>"
                        f"<span style='background:{mc};color:#fff;padding:2px 8px;"
                        f"border-radius:4px;font-size:.78em;font-weight:700'>{method}</span></td>"
                        f"<td style='padding:6px 10px'>"
                        f"<code style='color:{DC['accent']};font-size:.82em'>{api_base}{path}</code></td>"
                        f"<td style='padding:6px 10px;color:{DC['text2']};font-size:.82em'>{desc}</td>"
                        f"</tr>"
                    )
                st.markdown(
                    f"<table style='width:100%;border-collapse:collapse;background:{DC['card']};"
                    f"border-radius:10px;overflow:hidden'>"
                    f"<thead><tr style='background:{DC['elev']}'>"
                    f"<th style='padding:8px 10px;color:{DC['text2']};font-size:.8em;text-align:left'>Method</th>"
                    f"<th style='padding:8px 10px;color:{DC['text2']};font-size:.8em;text-align:left'>Endpoint</th>"
                    f"<th style='padding:8px 10px;color:{DC['text2']};font-size:.8em;text-align:left'>Description</th>"
                    f"</tr></thead><tbody>{rows_html}</tbody></table>",
                    unsafe_allow_html=True)
                st.caption(
                    f"\U0001f511 All endpoints (except /health) require header: "
                    f"`X-API-Key: {Config.API_KEY}`")

            st.divider()

            # ── MITRE ATT&CK Mappings ─────────────────────────────────────────
            st.markdown(f"<div style='font-size:1.1em;font-weight:700;color:{DC['text1']};"
                        f"margin-bottom:8px'>\U0001f6e1\ufe0f MITRE ATT&CK Mappings</div>",
                        unsafe_allow_html=True)
            mitre_hits = map_mitre(R['signals'])
            if mitre_hits:
                tactic_colors = {
                    'initial-access': DC['critical'], 'execution': DC['high'],
                    'defense-evasion': DC['warn'], 'credential-access': '#e879f9',
                    'lateral-movement': '#f472b6', 'impact': DC['critical'],
                    'command-and-control': DC['high'], 'reconnaissance': DC['warn'],
                    'resource-development': DC['text2'],
                }
                for t in mitre_hits:
                    tc_col = tactic_colors.get(t['tactic'], DC['accent'])
                    st.markdown(
                        f"<div style='background:{DC['card']};border-left:4px solid {tc_col};"
                        f"border-radius:8px;padding:10px 14px;margin:6px 0;"
                        f"display:flex;align-items:center;gap:12px;flex-wrap:wrap'>"
                        f"<code style='color:{tc_col};font-weight:700;font-size:.95em'>{t['technique_id']}</code>"
                        f"<span style='color:{DC['text1']};font-weight:600'>{t['technique_name']}</span>"
                        f"<span style='background:{tc_col}22;color:{tc_col};border:1px solid {tc_col}44;"
                        f"padding:2px 10px;border-radius:10px;font-size:.75em'>{t['tactic'].replace('-',' ').upper()}</span>"
                        f"<span style='color:{DC['text2']};font-size:.8em;margin-left:auto'>"
                        f"triggered by: <em>{t['signal_title']}</em></span>"
                        f"</div>",
                        unsafe_allow_html=True)
            else:
                st.success("\u2705 No MITRE ATT&CK techniques matched for this email")

            st.divider()

            # ── IOC Export ────────────────────────────────────────────────────
            st.markdown(f"<div style='font-size:1.1em;font-weight:700;color:{DC['text1']};"
                        f"margin-bottom:8px'>\U0001f9e9 IOC Export (SIEM-ready)</div>",
                        unsafe_allow_html=True)
            iocs = extract_iocs(R)
            ic1, ic2, ic3, ic4 = st.columns(4)
            ic1.metric("IPs",        len(iocs['ips']))
            ic2.metric("Domains",    len(iocs['domains']))
            ic3.metric("URLs",       len(iocs['urls']))
            ic4.metric("Hashes",     len(iocs['hashes']))

            ioc_tabs = st.tabs(["\U0001f310 Domains", "\U0001f517 URLs",
                                "\U0001f4e7 Emails", "\U0001f4a5 IPs", "#\ufe0f Hashes"])
            for ioc_tab, ioc_key, label in zip(
                ioc_tabs,
                ['domains', 'urls', 'emails', 'ips', 'hashes'],
                ['Domains', 'URLs', 'Emails', 'IPs', 'Hashes']
            ):
                with ioc_tab:
                    if ioc_key == 'hashes':
                        ioc_content = '\n'.join(f"{k}: {v}" for k, v in iocs['hashes'].items())
                    else:
                        ioc_content = '\n'.join(iocs[ioc_key]) if iocs[ioc_key] else f"No {label} found"
                    st.text_area(
                        label=label, value=ioc_content, height=140,
                        key=f"ioc_{ioc_key}", label_visibility="collapsed"
                    )

            ioc_flat = json.dumps(iocs, indent=2)
            st.download_button(
                "\U0001f4e5 Download IOCs (JSON)", ioc_flat,
                f"sherlock_iocs_{current_case_id[:8] if current_case_id else 'export'}.json",
                "application/json", key="ioc_dl"
            )

            st.divider()

            # ── SOAR JSON Output ──────────────────────────────────────────────
            st.markdown(f"<div style='font-size:1.1em;font-weight:700;color:{DC['text1']};"
                        f"margin-bottom:8px'>\U0001f916 SOAR JSON Payload</div>",
                        unsafe_allow_html=True)
            st.caption("Full structured payload — paste directly into your SOAR playbook or POST to the API.")
            try:
                soar_out = build_soar_json(R, current_case_id or "")
                soar_str = json.dumps(soar_out, indent=2, default=str)
            except Exception as _sje:
                soar_str = f"Error building SOAR JSON: {_sje}"
            st.text_area(
                label="SOAR JSON", value=soar_str, height=400,
                key="soar_json_area", label_visibility="collapsed"
            )
            st.download_button(
                "\U0001f4e5 Download SOAR JSON",
                soar_str,
                f"sherlock_soar_{current_case_id[:8] if current_case_id else 'export'}.json",
                "application/json", key="soar_dl"
            )

            st.divider()

            # ── Webhook Status ────────────────────────────────────────────────
            st.markdown(f"<div style='font-size:1.1em;font-weight:700;color:{DC['text1']};"
                        f"margin-bottom:8px'>\U0001f4e1 SOAR Webhook</div>",
                        unsafe_allow_html=True)
            wh_fired = (current_row or {}).get('webhook_fired', 0)
            if Config.SOAR_WEBHOOK_URL:
                wh_color = DC['ok'] if wh_fired else DC['text2']
                wh_icon  = "\u2705" if wh_fired else "\u23f3"
                wh_msg   = "Webhook fired successfully" if wh_fired else "Webhook pending / not triggered yet"
                st.markdown(
                    f"<div style='background:{wh_color}18;border-left:4px solid {wh_color};"
                    f"border-radius:8px;padding:10px 14px'>"
                    f"<b style='color:{wh_color}'>{wh_icon} {wh_msg}</b><br>"
                    f"<span style='color:{DC['text2']};font-size:.85em'>Target: "
                    f"<code>{Config.SOAR_WEBHOOK_URL}</code> | "
                    f"Min score to fire: {Config.WEBHOOK_MIN_SCORE}</span></div>",
                    unsafe_allow_html=True)
                if not wh_fired and current_case_id and R['score'] >= Config.WEBHOOK_MIN_SCORE:
                    if st.button("\U0001f4e1 Retry Webhook", key="retry_wh"):
                        try:
                            soar_retry = build_soar_json(R, current_case_id)
                            fire_webhook(current_case_id, soar_retry)
                            st.success("Webhook retry dispatched (check logs)")
                        except Exception as _we2:
                            st.error(f"Webhook retry error: {_we2}")
            else:
                st.info(
                    "\U0001f4e1 Webhook not configured. "
                    "Add `soar_webhook_url = \"https://your-soar/webhook\"` "
                    "to `.streamlit/secrets.toml` and restart.")

            st.divider()

            # ── Case History Table ────────────────────────────────────────────
            st.markdown(f"<div style='font-size:1.1em;font-weight:700;color:{DC['text1']};"
                        f"margin-bottom:8px'>\U0001f4c2 Recent Cases</div>",
                        unsafe_allow_html=True)
            recent = case_list(limit=20)
            if recent:
                df_cases = pd.DataFrame(recent)
                # Truncate long fields for display
                if 'from_addr' in df_cases.columns:
                    df_cases['from_addr'] = df_cases['from_addr'].str[:40]
                if 'subject' in df_cases.columns:
                    df_cases['subject'] = df_cases['subject'].str[:50]
                if 'submitted_at' in df_cases.columns:
                    df_cases['submitted_at'] = df_cases['submitted_at'].str[:19]
                if 'case_id' in df_cases.columns:
                    df_cases['case_id'] = df_cases['case_id'].str[:8] + "..."
                st.dataframe(df_cases, use_container_width=True, hide_index=True)
            else:
                st.info("No cases in the database yet.")

    except Exception as e:
        st.error(f"\u274c Analysis Error: {e}")
        import traceback
        with st.expander("\U0001f41b Debug Traceback"):
            st.code(traceback.format_exc())
        log.error(f"Analysis failed: {traceback.format_exc()}")

if __name__ == "__main__":
    main()