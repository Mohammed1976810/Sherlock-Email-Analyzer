"""
SHERLOCK - ENTERPRISE FORENSIC EMAIL ANALYZER v10.0
====================================================

Architecture: Signal-based nonlinear scoring engine.
Every analysis module produces ThreatSignal objects that feed into a
probability-combination engine with correlation bonuses, trust dampening,
signal hierarchy, and false-positive suppression.

NEW IN v10.0:
  + Nonlinear scoring engine (probability combination, not additive)
  + Signal hierarchy (hard evidence overrides heuristics)
  + Correlation layer (co-occurring signals amplify each other)
  + Trust vs Threat separation (gateway/auth trust dampens threat)
  + Confidence weighting per signal
  + False-positive dampening (marketing allowlists, sender memory)
  + BeautifulSoup HTML parsing (visible text extraction)
  + Text de-obfuscation / Unicode normalization
  + URL path entropy analysis
  + Tracking-domain allowlist for link-mismatch
  + Sender memory (SQLite first-seen tracking)
  + pdfminer.six stream decompression for PDF URIs
  + OCR via pytesseract for image-text phishing
  + Hop timing analysis (inter-hop delay detection)
  + Linguistic density analysis for BEC
  + Contradiction detection in social engineering
  + Trust MacroRaptor over manual keyword grep

Installation:
  pip install -r requirements.txt

Setup .streamlit/secrets.toml:
  vt_api_key        = "YOUR_VIRUSTOTAL_KEY"
  abuseipdb_key     = "YOUR_ABUSEIPDB_KEY"
  malwarebazaar_key = "YOUR_MB_KEY"
"""

# ═══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════
import streamlit as st
import email, email.policy, email.utils
import re, math, hashlib, json, html, tempfile, os, threading, io, time
import socket, logging, zipfile, contextlib, sqlite3, unicodedata
import pandas as pd, requests
from pathlib import Path
from urllib.parse import urlparse, unquote
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

try:
    from bs4 import BeautifulSoup, Comment
    BS4_OK = True
except ImportError:
    BS4_OK = False

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger("sherlock")

# Optional heavy deps – flags
PIL_OK = DNS_OK = QR_OK = OLETOOLS_OK = YARA_OK = False
STEGANO_OK = WHOIS_OK = PDF_REPORT_OK = PDFMINER_OK = OCR_OK = False

try:
    from PIL import Image as PilImage; PIL_OK = True
except Exception: pass
try:
    import dns.resolver; DNS_OK = True
except Exception: pass
try:
    from pyzbar.pyzbar import decode as decode_qr; QR_OK = True
except Exception: pass
try:
    from oletools.olevba import VBA_Parser
    from oletools.oleid import OleID
    from oletools.mraptor import MacroRaptor as _MacroRaptor
    OLETOOLS_OK = True
except Exception: pass
try:
    import yara; YARA_OK = True
except Exception: pass
try:
    from stegano import lsb; STEGANO_OK = True
except Exception: pass
try:
    import whois as whois_lib; WHOIS_OK = True
except Exception: pass
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    PDF_REPORT_OK = True
except Exception: pass
try:
    from pdfminer.high_level import extract_text as pdfminer_extract
    from pdfminer.pdfparser import PDFParser as PDFMinerParser
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfpage import PDFPage
    PDFMINER_OK = True
except Exception: pass
try:
    import pytesseract; OCR_OK = True
except Exception: pass

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
MAX_FILE_SIZE = 50 * 1024 * 1024
MAX_OBS = 25
REGEX_TIMEOUT = 2
DNS_TIMEOUT = 3
HTTP_TIMEOUT = 10

# ── Compiled patterns ────────────────────────────────────────────────────────
def _rc(p, f=0):
    if _RE_TIMEOUT:
        try: return _re_engine.compile(p, f, timeout=REGEX_TIMEOUT)
        except (TypeError, ValueError): return _re_engine.compile(p, f)
    return re.compile(p, f)

def _rcb(p, f=0):
    if _RE_TIMEOUT:
        try: return _re_engine.compile(p, f, timeout=REGEX_TIMEOUT)
        except (TypeError, ValueError): return _re_engine.compile(p, f)
    return re.compile(p, f)

PAT_EMAIL   = _rc(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PAT_DOMAIN  = _rc(r'@([\w\.-]+)')
PAT_URL     = _rc(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:[/?#][^\s<>"\']*)?', re.I)
PAT_HREF    = _rc(r'<a\s[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I|re.DOTALL)
PAT_IPV4    = _rc(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PAT_TZ      = _rc(r'[+-]\d{4}')
PAT_PDF_URI = _rcb(rb'/URI\s*\(([^)]{4,500})\)')
PAT_PDF_URL = _rcb(rb'https?://[^\s\x00<>(){}\[\]"\'\\]{10,300}')

# ── Keyword / classification sets ────────────────────────────────────────────
GOVERNMENT_TLDS  = {'.gov','.gov.uk','.gov.au','.gov.ca','.mil'}
EDUCATIONAL_TLDS = {'.edu','.ac.uk','.edu.au'}
MAJOR_TECH = {'google.com','microsoft.com','apple.com','amazon.com',
              'github.com','linkedin.com','facebook.com','twitter.com'}

KNOWN_PLATFORMS = {
    'amazonses.com':'Amazon SES','sendgrid.net':'SendGrid',
    'mailchimp.com':'Mailchimp','mailgun.org':'Mailgun',
    'outlook.com':'Microsoft 365','mandrillapp.com':'Mandrill',
    'sparkpostmail.com':'SparkPost','postmarkapp.com':'Postmark',
}

# Marketing / tracking domains – link-mismatch allowlist (FIX: false positives)
TRACKING_ALLOWLIST = {
    'sendgrid.net','mailchimp.com','mailgun.org','mandrillapp.com',
    'sparkpostmail.com','postmarkapp.com','list-manage.com',
    'click.mailchimp.com','links.m.example.com',
    'us-east-2.amazonses.com','email.mg.example.com',
    'click.pstmrk.it','ct.sendgrid.net','url.emailprotection.link',
    'safelinks.protection.outlook.com','urldefense.proofpoint.com',
    'urldefense.com',
}

MARKETING_RP_DOMAINS = {
    'amazonses.com','sendgrid.net','mailchimp.com','mailgun.org',
    'mandrillapp.com','sparkpostmail.com','postmarkapp.com',
    'bounces.google.com',
}

CLOUD_PROVIDERS = {
    'amazon': ['amazon.com','amazonaws.com'],
    'google': ['google.com','googlemail.com','googleusercontent.com'],
    'microsoft': ['microsoft.com','azure.com','outlook.com','office365.com'],
    'cloudflare': ['cloudflare.com','cloudflare.net'],
}

DISPLAY_NAME_BRANDS = [
    'microsoft','google','apple','amazon','paypal','facebook','netflix',
    'docusign','adobe','helpdesk','it support','security team','admin',
    'support','ceo','cfo','cto','chief executive','chief financial',
    'managing director','human resources','hr department','accounts payable',
]

DANGEROUS_EXTS = {
    '.exe','.scr','.bat','.cmd','.vbs','.js','.ps1','.hta','.pif',
    '.wsf','.msi','.com','.cpl','.inf','.reg','.lnk','.jar','.jnlp',
    '.ws','.vbe','.jse','.wsc','.wsh','.sct','.url','.application',
}

DOUBLE_EXT_PATS = [
    (r'\.pdf\.exe$','PDF→EXE'),(r'\.doc\.exe$','DOC→EXE'),
    (r'\.jpg\.exe$','JPG→EXE'),(r'\.pdf\.js$','PDF→JS'),
    (r'\.doc\.scr$','DOC→SCR'),(r'\.xls\.exe$','XLS→EXE'),
    (r'\.txt\.exe$','TXT→EXE'),(r'\.pdf\.vbs$','PDF→VBS'),
    (r'\.pdf\.bat$','PDF→BAT'),(r'\.docx?\.lnk$','DOC→LNK'),
    (r'\.pdf\.hta$','PDF→HTA'),(r'\.zip\.exe$','ZIP→EXE'),
    (r'\.csv\.exe$','CSV→EXE'),(r'\.pdf\.cmd$','PDF→CMD'),
    (r'\.png\.exe$','PNG→EXE'),(r'\.jpg\.js$','JPG→JS'),
]

VALID_MIMES = {
    'pdf':['application/pdf'],'docx':['application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/zip'],
    'xlsx':['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/zip'],
    'doc':['application/msword'],'xls':['application/vnd.ms-excel'],
    'zip':['application/zip','application/x-zip-compressed','application/octet-stream'],
    'rar':['application/x-rar-compressed','application/octet-stream'],
    'png':['image/png'],'jpg':['image/jpeg'],'jpeg':['image/jpeg'],
    'gif':['image/gif'],'txt':['text/plain'],'csv':['text/csv','text/plain'],
    'html':['text/html'],'rtf':['application/rtf','text/rtf'],
}

URL_SHORTENERS = {
    'bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd','buff.ly',
    'rebrand.ly','bl.ink','short.io','cutt.ly','rb.gy','snip.ly',
    'shorturl.at','tiny.cc','surl.li','v.gd','adf.ly',
}

SUSPICIOUS_TLDS = {
    '.xyz','.top','.club','.work','.buzz','.surf','.rest','.icu','.cam',
    '.monster','.cyou','.cfd','.sbs','.click','.link','.gq','.ml','.cf',
    '.ga','.tk','.pw','.cc','.ws','.bid','.loan','.trade','.racing',
    '.review','.cricket','.win','.party','.download','.stream',
}

BEC_KEYWORDS = {
    'wire_transfer':(['wire transfer','bank transfer','swift transfer',
                      'routing number','beneficiary','iban'],0.75),
    'gift_cards':(['gift card','itunes card','amazon gift','google play card',
                   'prepaid card','steam card'],0.65),
    'urgency':(['urgent','immediately','right away','asap',
                'time sensitive','before end of day'],0.40),
    'secrecy':(['keep this confidential','do not tell','between us',
                'keep quiet','discreet','off the record'],0.60),
    'authority':(['on behalf of the ceo','per the cfo','board has approved',
                  'i authorize you','skip the approval','executive decision'],0.65),
    'payment_redirect':(['new bank details','updated payment','change the account',
                         'new vendor account','revised invoice','updated invoice'],0.70),
}

BEC_CONTRADICTIONS = [
    (['urgent','immediately','asap'], ['no rush','no hurry','when you can',
                                        'at your convenience','take your time']),
]

SUSPICIOUS_PHRASES = {
    'verify_account':(
        [r'verify your account',r'validate your account',r'click to verify',r'account.*suspend'],20),
    'password_issue':(
        [r'password.*expire',r'password.*change',r'reset.*password'],15),
    'mailbox_full':(
        [r'mailbox.*full',r'quota.*exceeded',r'limit.*reached'],15),
    'generic_threat':(
        [r'final notice',r'legal action',r'court appearance',r'arrest warrant'],25),
    'credential_lure':(
        [r'click here to verify',r'click the link below',r'update your information',
         r'confirm your identity',r'log in to your account'],20),
}

PDF_META_NS = {'ns.adobe.com','purl.org/dc','w3.org/1999','w3.org/2000',
               'schemas.openxmlformats','schemas.microsoft.com'}

LEGIT_MAILERS = ['microsoft outlook','thunderbird','apple mail','lotus notes',
                 'evolution','mutt','sendgrid','mailchimp','postfix','exim',
                 'sendmail','amazon ses','mailgun','postmark','gmail','yahoo']

# ── YARA rules source ────────────────────────────────────────────────────────
YARA_SRC = r"""
rule VBA_Macro_Dropper { meta: description="VBA download+autoexec" severity="CRITICAL" category="macro"
  strings: $d1="URLDownloadToFile" nocase $d2="XMLHTTP" nocase $d3="WinHttpRequest" nocase
           $e1="AutoOpen" nocase $e2="Document_Open" nocase $e3="Workbook_Open" nocase $s="WScript.Shell" nocase
  condition: ($d1 or $d2 or $d3) and ($e1 or $e2 or $e3 or $s) }
rule VBA_Obfuscated { meta: description="Obfuscated VBA" severity="HIGH" category="macro"
  strings: $a="Chr(" nocase $b="StrReverse(" nocase $c="Environ(" nocase $d="CallByName(" nocase $e="Execute(" nocase $f="Asc(" nocase
  condition: 3 of them }
rule PDF_JS_Exploit { meta: description="PDF JS exploit" severity="HIGH" category="pdf"
  strings: $j1="/JavaScript" $j2="/JS" $ev="eval(" nocase $un="unescape(" nocase $oa="/OpenAction"
  condition: $oa and ($j1 or $j2) and ($ev or $un) }
rule PDF_Launch { meta: description="PDF /Launch" severity="CRITICAL" category="pdf"
  strings: $a="/Launch" $b="/Action" condition: $a and $b }
rule EXE_Magic { meta: description="Executable embedded" severity="CRITICAL" category="executable"
  strings: $mz={4D 5A} $pe="PE\x00\x00" $elf={7F 45 4C 46}
  condition: ($mz at 0) or ($elf at 0) or $pe }
rule Archive_Sig { meta: description="Archive" severity="MEDIUM" category="archive"
  strings: $z={50 4B 03 04} $r={52 61 72 21 1A 07} $s={37 7A BC AF 27 1C}
  condition: any of them }
rule Phishing_Form { meta: description="Credential form" severity="HIGH" category="phishing"
  strings: $f="<form" nocase $p="password" nocase $v="verify your account" nocase $s="account suspended" nocase $u="immediate action" nocase
  condition: $f and (2 of ($p,$v,$s,$u)) }
rule Macro_Registry { meta: description="Registry persistence" severity="HIGH" category="macro"
  strings: $r="RegWrite" nocase $h="HKEY_" nocase $k="CurrentVersion\\Run" nocase
  condition: $r and ($h or $k) }
rule PS_In_Macro { meta: description="PowerShell evasion" severity="CRITICAL" category="macro"
  strings: $p="PowerShell" nocase $e="-EncodedCommand" nocase $b="-ExecutionPolicy Bypass" nocase $h="-WindowStyle Hidden" nocase $d="DownloadString" nocase
  condition: $p and (2 of ($e,$b,$h,$d)) }
"""

_yara_rules = None
_yara_lock  = threading.Lock()
def _get_yara():
    global _yara_rules
    if _yara_rules is not None: return _yara_rules
    if not YARA_OK: return None
    with _yara_lock:
        if _yara_rules is not None: return _yara_rules
        try: _yara_rules = yara.compile(source=YARA_SRC); return _yara_rules
        except Exception as e: log.error(f"YARA compile: {e}"); return None


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
    filename: str; fmt: str = ""; size: Tuple[int,int] = (0,0)
    has_steg: bool = False; findings: List[str] = field(default_factory=list)
    data: Optional[bytes] = None; qr_links: List[str] = field(default_factory=list)
    ocr_text: str = ""

@dataclass
class Observable:
    type: str; value: str; defanged: str; source: str
    vt: Optional[VTResult] = None; reputation: str = "unknown"
    threat_score: int = 0; is_shortener: bool = False
    suspicious_tld: bool = False; path_entropy: float = 0.0

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

# ═══════════════════════════════════════════════════════════════════════════════
# SCORING ENGINE (nonlinear probability-based)
# ═══════════════════════════════════════════════════════════════════════════════

# Signal correlations: if both present, add bonus probability
SIGNAL_CORRELATIONS = [
    ('spf_fail','display_name_spoof',0.12),
    ('spf_fail','link_text_mismatch',0.10),
    ('shadow_spoofing','bec_wire_transfer',0.18),
    ('display_name_spoof','bec_authority',0.18),
    ('link_text_mismatch','credential_form',0.15),
    ('spf_fail','reply_to_hijack',0.14),
    ('malware_hash','yara_critical',0.08),
    ('url_shortener','suspicious_tld',0.08),
    ('spf_fail','shadow_spoofing',0.10),
    ('bec_wire_transfer','bec_urgency',0.15),
    ('bec_authority','bec_urgency',0.12),
    ('bec_payment_redirect','bec_urgency',0.14),
    ('bec_secrecy','bec_wire_transfer',0.12),
]

def run_scoring_engine(signals: List[ThreatSignal],
                       trust_factors: List[TrustFactor]) -> ScoringResult:
    """
    Nonlinear probability-combination scoring engine.

    1. Combine signal probabilities:  P = 1 - prod(1 - p_i * c_i)
    2. Apply correlation bonuses for co-occurring signals
    3. Dampen by trust factors
    4. Enforce signal hierarchy floors
    5. Map to verdict
    """
    result = ScoringResult(signals=signals, trust_factors=trust_factors)
    if not signals:
        result.explanation = "No threat signals detected"
        return result

    # Step 1: probability combination (with diminishing returns built in)
    survival = 1.0  # probability of being safe
    for s in signals:
        effective = s.probability * s.confidence
        effective = max(0.0, min(1.0, effective))
        survival *= (1.0 - effective)
    combined = 1.0 - survival

    # Step 2: correlation bonuses
    sig_names = {s.name for s in signals}
    for n1, n2, bonus in SIGNAL_CORRELATIONS:
        if n1 in sig_names and n2 in sig_names:
            s1 = next(s for s in signals if s.name == n1)
            s2 = next(s for s in signals if s.name == n2)
            boost = bonus * min(s1.confidence, s2.confidence)
            combined = min(1.0, combined + boost * (1.0 - combined))
            result.correlations_applied.append(
                f"{n1}+{n2} → +{boost:.2f}")

    # Step 3: trust dampening (only log non-trivial dampening)
    for tf in trust_factors:
        dampen = tf.strength * tf.confidence
        if dampen > 0.005:  # skip negligible dampening
            combined *= (1.0 - dampen)
            result.dampening_applied.append(
                f"{tf.name} → -{dampen:.0%} dampening")

    # Step 4: signal hierarchy floors
    tiers = {s.tier for s in signals}
    tier1 = [s for s in signals if s.tier == 1]
    tier2 = [s for s in signals if s.tier == 2]
    if tier1:
        combined = max(combined, 0.72)
        if tier2:
            combined = max(combined, 0.88)

    combined = max(0.0, min(1.0, combined))
    result.threat_probability = combined
    result.score = int(combined * 100)

    # Step 5: map to verdict
    s = result.score
    if s >= 85:
        result.verdict, result.threat_level, result.confidence = "MALICIOUS","CRITICAL",95
    elif s >= 65:
        result.verdict, result.threat_level, result.confidence = "LIKELY MALICIOUS","HIGH",85
    elif s >= 40:
        result.verdict, result.threat_level, result.confidence = "SUSPICIOUS","MEDIUM",72
    elif s >= 18:
        result.verdict, result.threat_level, result.confidence = "REVIEW","LOW",60
    else:
        result.verdict, result.threat_level, result.confidence = "CLEAN","SAFE",90

    # Build explanation
    top = sorted(signals, key=lambda x: x.probability*x.confidence, reverse=True)[:5]
    parts = [f"{t.title} (p={t.probability:.0%}×c={t.confidence:.0%})" for t in top]
    result.explanation = (
        f"Score {s}/100 — {len(signals)} signal(s), "
        f"{len(trust_factors)} trust factor(s). "
        f"Top: {'; '.join(parts)}")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# TEXT PROCESSING (BeautifulSoup + de-obfuscation)
# ═══════════════════════════════════════════════════════════════════════════════

# Unicode confusable map (Cyrillic/Greek → Latin)
_CONFUSABLES = str.maketrans({
    '\u0430':'a','\u0435':'e','\u043e':'o','\u0440':'p','\u0441':'c',
    '\u0443':'y','\u0445':'x','\u0456':'i','\u0458':'j','\u0455':'s',
    '\u04bb':'h','\u0501':'d','\u051b':'q','\u051d':'w',
    '\u0391':'A','\u0392':'B','\u0395':'E','\u0397':'H','\u0399':'I',
    '\u039a':'K','\u039c':'M','\u039d':'N','\u039f':'O','\u03a1':'P',
    '\u03a4':'T','\u03a7':'X','\u03a5':'Y','\u0396':'Z',
})

def normalize_text(text: str) -> str:
    """De-obfuscate text: collapse separators, normalize Unicode confusables."""
    if not text: return ""
    text = unicodedata.normalize('NFKC', text)
    text = text.translate(_CONFUSABLES)
    # Collapse noise: P.a.y.P.a.l → PayPal
    text = re.sub(r'(?<=\w)[.\-_\s]{1,2}(?=\w)', '', text)
    return text

def extract_visible_text(html_body: str) -> str:
    """Use BeautifulSoup to get only visible text (skip scripts, styles, hidden)."""
    if not html_body: return ""
    if not BS4_OK:
        return re.sub(r'<[^>]+>', ' ', html_body)

    soup = BeautifulSoup(html_body, 'html.parser')
    # Remove non-visible elements
    for tag in soup.find_all(['script','style','head','noscript']):
        tag.decompose()
    for tag in soup.find_all(True):
        style = tag.get('style','')
        if 'display:none' in style.replace(' ','') or 'visibility:hidden' in style.replace(' ',''):
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
        path = urlparse(url).path + (urlparse(url).query or '')
        if len(path) < 5: return 0.0
        c = Counter(path)
        n = len(path)
        return -sum((v/n)*math.log2(v/n) for v in c.values())
    except Exception:
        return 0.0

def is_tracking_domain(domain: str) -> bool:
    """Check if domain is a known email tracking/redirect service."""
    d = domain.lower().lstrip('www.')
    if d in TRACKING_ALLOWLIST: return True
    root = _root_domain(d)
    return root in TRACKING_ALLOWLIST


# ═══════════════════════════════════════════════════════════════════════════════
# SENDER MEMORY (SQLite – first-seen tracking)
# ═══════════════════════════════════════════════════════════════════════════════

_SENDER_DB_PATH = os.path.join(tempfile.gettempdir(), 'sherlock_senders.db')

def _sender_db():
    """Get or create sender memory database."""
    conn = sqlite3.connect(_SENDER_DB_PATH, check_same_thread=False)
    conn.execute('''CREATE TABLE IF NOT EXISTS senders (
        domain TEXT PRIMARY KEY, first_seen TEXT, count INTEGER DEFAULT 1
    )''')
    conn.commit()
    return conn

def check_sender(domain: str) -> Tuple[bool, int, int]:
    """Check if sender is known WITHOUT recording. Returns (is_known, times_seen, days_known)."""
    if not domain: return False, 0, 0
    domain = domain.lower()
    try:
        conn = _sender_db()
        row = conn.execute("SELECT first_seen, count FROM senders WHERE domain=?", (domain,)).fetchone()
        if row:
            first_seen = datetime.fromisoformat(row[0])
            days = (datetime.now() - first_seen).days
            return True, row[1], days
        return False, 0, 0
    except Exception as e:
        log.debug(f"Sender memory check error: {e}")
        return False, 0, 0

def record_sender_if_clean(domain: str, is_clean: bool):
    """Record sender ONLY if the email verdict is clean.
    Prevents attackers from building trust via repeated malicious emails."""
    if not domain or not is_clean: return
    domain = domain.lower()
    try:
        conn = _sender_db()
        row = conn.execute("SELECT count FROM senders WHERE domain=?", (domain,)).fetchone()
        now = datetime.now().isoformat()
        if row:
            conn.execute("UPDATE senders SET count=count+1 WHERE domain=?", (domain,))
        else:
            conn.execute("INSERT INTO senders (domain, first_seen, count) VALUES (?,?,1)", (domain, now))
        conn.commit()
    except Exception as e:
        log.debug(f"Sender memory record error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _esc(t): return html.escape(str(t)) if t else ""
def _root_domain(d):
    p = d.lower().split('.')
    for cc in ['co.uk','gov.uk','ac.uk','com.au','gov.au','co.nz','co.in']:
        if d.endswith('.'+cc): return '.'.join(p[-(len(cc.split('.'))+1):])
    return '.'.join(p[-2:]) if len(p)>=2 else d

def defang(v):
    if not isinstance(v,str): return str(v)
    return _esc(v.replace('http://','hxxp://').replace('https://','hxxps://').replace('.','\u200b[.]\u200b'))

def shannon_entropy(data) -> float:
    """Shannon entropy – correctly uses math.log2."""
    if not data: return 0.0
    if isinstance(data, str): data = data.encode('utf-8','ignore')
    if not data: return 0.0
    c = Counter(data); n = len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def _levenshtein(a, b):
    if len(a)<len(b): return _levenshtein(b,a)
    if not b: return len(a)
    prev = range(len(b)+1)
    for i,ca in enumerate(a):
        curr = [i+1]
        for j,cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca!=cb)))
        prev = curr
    return prev[-1]

_HOMOGLYPHS = {'0':'o','1':'l','l':'i','rn':'m','vv':'w','cl':'d'}

def check_typosquat(domain):
    d = domain.lower(); root = _root_domain(d).split('.')[0]
    if 'xn--' in d: return "IDN HOMOGRAPH: Punycode domain"
    brands = {'microsoft':'microsoft.com','google':'google.com','apple':'apple.com',
              'amazon':'amazon.com','paypal':'paypal.com','facebook':'facebook.com',
              'netflix':'netflix.com','linkedin':'linkedin.com','docusign':'docusign.com',
              'adobe':'adobe.com','chase':'chase.com','wellsfargo':'wellsfargo.com'}
    for bn, bd in brands.items():
        br = bd.split('.')[0]
        if root == br: continue
        dist = _levenshtein(root, br)
        if 0 < dist <= 2 and len(root) >= 4:
            return f"TYPOSQUAT: '{d}' is {dist} edit(s) from '{bd}'"
        norm = root
        for fake, real in _HOMOGLYPHS.items(): norm = norm.replace(fake, real)
        if norm == br and root != br:
            return f"HOMOGLYPH: '{d}' mimics '{bd}'"
        if bn in d and _root_domain(d) != bd:
            return f"BRAND ABUSE: '{d}' embeds '{bn}' but isn't '{bd}'"
    return None

def get_source_ip(msg):
    private = [re.compile(p) for p in [r'^10\.',r'^192\.168\.',r'^172\.(1[6-9]|2\d|3[01])\.',r'^127\.',r'^169\.254\.']]
    for h in reversed(msg.get_all('Received',[]) or []):
        for ip in PAT_IPV4.findall(str(h)):
            if not any(r.match(ip) for r in private): return ip
    return None

@contextlib.contextmanager
def _tmp_file(data, suffix=''):
    p = None
    try:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        f.write(data); f.close(); p = f.name; yield p
    finally:
        if p and os.path.exists(p):
            try: os.unlink(p)
            except: pass

def _is_cloud(isp):
    il = isp.lower()
    return any(d in il for prov in CLOUD_PROVIDERS.values() for d in prov)


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
        # Try to find date at end of Received header (after ';')
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
            delta = (timestamps[i] - timestamps[i-1]).total_seconds()
            delays.append(delta)
        except Exception:
            pass

    # Flag stalling: any hop > 15 minutes is suspicious
    stalls = [(i+1, d) for i, d in enumerate(delays) if d > 900]
    if stalls:
        worst = max(stalls, key=lambda x: x[1])
        anomaly = f"Hop {worst[0]} stalled {worst[1]/60:.0f}min (relay delay)"
    elif count == 0:
        anomaly = "No Received headers — locally crafted?"
    elif count == 1:
        anomaly = "Single hop — unusual for internet email"
    elif count > 15:
        anomaly = f"Excessive hops ({count}) — routing anomaly"

    return count, delays, anomaly


# ═══════════════════════════════════════════════════════════════════════════════
# DOMAIN INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

def domain_intel(domain: str) -> DomainIntel:
    di = DomainIntel(domain=domain)
    typo = check_typosquat(domain)
    if typo: di.typosquat = typo

    dl = domain.lower()
    for tld in GOVERNMENT_TLDS:
        if dl.endswith(tld):
            di.category='government'; di.trusted=True; di.reasoning=f'Gov ({tld})'; return di
    for tld in EDUCATIONAL_TLDS:
        if dl.endswith(tld):
            di.category='educational'; di.trusted=True; di.reasoning=f'Edu ({tld})'; return di
    for pd, desc in KNOWN_PLATFORMS.items():
        if dl == pd or dl.endswith('.'+pd):
            di.category='platform'; di.trusted=True; di.platform=desc; di.reasoning=f'Known: {desc}'; return di
    for td in MAJOR_TECH:
        if dl == td or dl.endswith('.'+td):
            di.category='major_tech'; di.trusted=True; di.reasoning=f'Major tech ({td})'; return di

    if WHOIS_OK:
        try:
            socket.setdefaulttimeout(DNS_TIMEOUT)
            w = whois_lib.whois(_root_domain(domain))
            if w.org: di.org = str(w.org[0] if isinstance(w.org,list) else w.org)
            if w.creation_date:
                cd = w.creation_date[0] if isinstance(w.creation_date,list) else w.creation_date
                if isinstance(cd, datetime):
                    di.age_days = (datetime.now()-cd).days
                    if di.age_days < 30: di.reasoning = f"New domain ({di.age_days}d)"
                    elif di.age_days > 365: di.reasoning = f"Established ({di.age_days}d)"
        except Exception: pass

    if not di.reasoning:
        try:
            socket.setdefaulttimeout(DNS_TIMEOUT); socket.gethostbyname(domain)
            di.reasoning = "Active domain"
        except Exception:
            di.reasoning = "Cannot resolve"
    return di


# ═══════════════════════════════════════════════════════════════════════════════
# VT / ABUSEIPDB / MALWAREBAZAAR
# ═══════════════════════════════════════════════════════════════════════════════

class _VTLimiter:
    def __init__(self): self._last=0.0; self._cnt=0; self._start=time.time(); self._lock=threading.Lock()
    def wait(self):
        with self._lock:
            now=time.time()
            if now-self._start>60: self._cnt=0; self._start=now
            if self._cnt>=4:
                sl=60-(now-self._start)
                if sl>0: time.sleep(sl+1)
                self._cnt=0; self._start=time.time()
            el=now-self._last
            if el<15 and self._cnt>0: time.sleep(15-el)
            self._last=time.time(); self._cnt+=1

class _Cache:
    def __init__(self): self._d={}; self._lock=threading.Lock()
    def get(self,k): 
        with self._lock: return self._d.get(hashlib.sha256(k.encode()).hexdigest())
    def put(self,k,v):
        with self._lock:
            if len(self._d)>800:
                for old in list(self._d)[:200]: del self._d[old]
            self._d[hashlib.sha256(k.encode()).hexdigest()] = v

try:
    _vt_lim = st.cache_resource(lambda: _VTLimiter())()
except: _vt_lim = _VTLimiter()

def _vt_cache():
    if 'vtc' not in st.session_state: st.session_state.vtc = _Cache()
    return st.session_state.vtc

VT_WEIGHTS = {'Google Safebrowsing':3,'Microsoft':3,'Kaspersky':3,'Sophos':3,
              'ESET':3,'Fortinet':3,'Symantec':3,'BitDefender':3,
              'McAfee':2,'Trend Micro':2,'Palo Alto Networks':2}

class Config:
    try: VT_KEY = st.secrets["vt_api_key"]
    except: VT_KEY = ""
    try: ABUSE_KEY = st.secrets["abuseipdb_key"]
    except: ABUSE_KEY = ""
    try: MB_KEY = st.secrets["malwarebazaar_key"]
    except: MB_KEY = ""

def _vt_consensus(stats, detailed=None, is404=False, dom=""):
    r = VTResult()
    if dom: r.domain_intel = domain_intel(dom)
    if is404:
        r.success=True; r.is_new=True
        r.threat_level = "CLEAN" if (r.domain_intel and r.domain_intel.trusted) else "UNKNOWN"
        r.reasoning = "Not in VT" if r.threat_level=="UNKNOWN" else f"New URL, trusted: {r.domain_intel.reasoning}"
        return r
    r.total=sum(stats.values()); r.malicious=stats.get('malicious',0); r.success=True
    if detailed:
        r.engines = [e for e,d in detailed.items() if d.get('category')=='malicious']
    w = sum(VT_WEIGHTS.get(e,1) for e in r.engines)
    r.weighted = w
    t1 = sum(1 for e in r.engines if VT_WEIGHTS.get(e,0)>=3)
    if r.malicious==0: r.threat_level="CLEAN"; r.reasoning=f"Clean ({stats.get('harmless',0)} safe)"
    elif t1>=2: r.threat_level="CRITICAL"; r.reasoning=f"{t1} major vendors flagged"
    elif w>=5: r.threat_level="CRITICAL"; r.reasoning=f"Consensus: {r.malicious} engines"
    elif r.malicious>=3: r.threat_level="MALICIOUS"; r.reasoning=f"{r.malicious} engines"
    elif r.malicious>=2: r.threat_level="SUSPICIOUS"; r.reasoning=f"{r.malicious} engines"
    else: r.threat_level="UNKNOWN"; r.reasoning="Single engine flag"
    return r

def check_vt(kind, value):
    c = _vt_cache(); cached = c.get(f"{kind}:{value}")
    if cached: return cached
    if not Config.VT_KEY: return VTResult(error="No API key")
    try:
        _vt_lim.wait()
        h = {"x-apikey": Config.VT_KEY}
        if kind=='url':
            uid = hashlib.sha256(value.encode()).hexdigest()
            resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers=h, timeout=HTTP_TIMEOUT)
        elif kind=='domain':
            resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{value}", headers=h, timeout=HTTP_TIMEOUT)
        else:
            resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{value}", headers=h, timeout=HTTP_TIMEOUT)
        dom = urlparse(value).netloc if kind=='url' else (value if kind=='domain' else '')
        if resp.status_code==200:
            a = resp.json().get('data',{}).get('attributes',{})
            r = _vt_consensus(a.get('last_analysis_stats',{}), a.get('last_analysis_results',{}), False, dom)
        elif resp.status_code==404:
            r = _vt_consensus({},{},True,dom)
        else:
            r = VTResult(error=f"HTTP {resp.status_code}")
        c.put(f"{kind}:{value}", r)
        return r
    except Exception as e:
        return VTResult(error=str(e)[:80])

def check_abuseipdb(ip):
    if not ip or not Config.ABUSE_KEY: return {}
    try:
        resp = requests.get('https://api.abuseipdb.com/api/v2/check',
            headers={'Key':Config.ABUSE_KEY,'Accept':'application/json'},
            params={'ipAddress':ip,'maxAgeInDays':'90','verbose':''},
            timeout=HTTP_TIMEOUT)
        if resp.status_code==200: return resp.json().get('data',{})
    except Exception: pass
    return {}

def check_malwarebazaar(data, filename):
    try:
        sha = hashlib.sha256(data).hexdigest()
        h = {'Auth-Key': Config.MB_KEY} if Config.MB_KEY else {}
        resp = requests.post('https://mb-api.abuse.ch/api/v1/',
            data={'query':'get_info','hash':sha}, headers=h, timeout=HTTP_TIMEOUT)
        if resp.status_code==200:
            d = resp.json()
            if d.get('query_status')=='ok' and d.get('data'):
                info = d['data'][0]
                return True, info.get('signature','Unknown'), info.get('tags',[]) or []
    except Exception: pass
    return False, "", []


# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def _dns_dmarc(domain):
    if not DNS_OK: return {'status':'UNKNOWN'}
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        for rd in dns.resolver.resolve(f'_dmarc.{domain}','TXT'):
            t = rd.to_text().strip('"')
            if 'v=DMARC1' in t:
                pm = re.search(r'p=(\w+)',t)
                return {'status':'FOUND','policy':pm.group(1) if pm else 'none','record':t}
        return {'status':'MISSING'}
    except: return {'status':'MISSING'}

def _dns_spf(domain):
    if not DNS_OK: return {'status':'UNKNOWN'}
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        for rd in dns.resolver.resolve(domain,'TXT'):
            t = rd.to_text().strip('"')
            if 'v=spf1' in t: return {'status':'FOUND','record':t}
        return {'status':'MISSING'}
    except: return {'status':'MISSING'}

def analyze_auth(msg) -> AuthResult:
    r = AuthResult()
    r.source_ip = get_source_ip(msg) or ""
    r.hop_count, r.hop_delays, r.hop_anomaly = analyze_hops(msg)
    if r.hop_anomaly: r.details.append(r.hop_anomaly)

    ah = str(msg.get('Authentication-Results','')).lower()
    sh = str(msg.get('Received-SPF','')).lower()

    # Vendor override
    vendor_pass = any('spf=pass' in str(msg.get(h,'')).lower() or 'spf-result=pass' in str(msg.get(h,'')).lower()
                      for h in ['X-FEAS-SPF','X-Forefront-Antispam-Report'])
    if vendor_pass: r.details.append("Vendor confirms SPF PASS")

    # SPF
    if vendor_pass or 'spf=pass' in ah or ('pass' in sh and 'spf' in sh):
        r.spf='PASS'; r.findings.append("SPF: PASS")
    elif 'spf=fail' in ah or ('fail' in sh and 'soft' not in sh):
        if vendor_pass: r.spf='PASS'; r.details.append("SPF: vendor override")
        else: r.spf='FAIL'; r.findings.append("SPF: FAIL")
    elif 'spf=softfail' in ah or 'softfail' in sh:
        r.spf='SOFTFAIL'; r.findings.append("SPF: SOFTFAIL")
    elif 'spf=temperror' in ah: r.spf='TEMPERROR'; r.findings.append("SPF: TEMPERROR")
    elif 'spf=permerror' in ah: r.spf='PERMERROR'; r.findings.append("SPF: PERMERROR")
    else: r.findings.append("SPF: NONE")

    # DKIM
    if 'dkim=pass' in ah: r.dkim='PASS'; r.findings.append("DKIM: PASS")
    elif 'dkim=fail' in ah: r.dkim='FAIL'; r.findings.append("DKIM: FAIL")
    else: r.findings.append("DKIM: NONE")

    # DMARC
    if 'dmarc=pass' in ah: r.dmarc='PASS'; r.findings.append("DMARC: PASS")
    elif 'dmarc=fail' in ah: r.dmarc='FAIL'; r.findings.append("DMARC: FAIL")
    else: r.findings.append("DMARC: NONE")

    # Gateway
    gw_checks = [
        ('X-Mimecast-Spam-Score','Mimecast', lambda v: int(v)<=1),
        ('X-IronPort-AV','Cisco IronPort', lambda v: True),
        ('X-Barracuda-Spam-Score','Barracuda', lambda v: float(v)<=1),
    ]
    for hdr, name, check in gw_checks:
        val = msg.get(hdr,'')
        if val:
            try:
                if check(val): r.gateway_trust=True; r.gateway_name=name; r.details.append(f"Gateway: {name}")
            except: pass
    if 'x-forefront-antispam-report' in str(msg.keys()).lower():
        scl = re.search(r'SCL:(\d+)', str(msg.get('x-forefront-antispam-report','')))
        if scl and int(scl.group(1))<=1:
            r.gateway_trust=True; r.gateway_name=r.gateway_name or "Microsoft 365"
    if msg.get('X-Proofpoint-Spam-Details'):
        r.gateway_trust=True; r.gateway_name=r.gateway_name or "Proofpoint"

    # Domains
    r.from_full = str(msg.get('From',''))
    r.rp_full = str(msg.get('Return-Path',''))
    fm = PAT_DOMAIN.search(r.from_full)
    rm = PAT_DOMAIN.search(r.rp_full)
    if fm:
        r.from_domain = fm.group(1).lower()
        if DNS_OK:
            r.live_verified = True
            r.live_dmarc = _dns_dmarc(r.from_domain)
            r.live_spf = _dns_spf(r.from_domain)
    if fm and rm:
        r.rp_domain = rm.group(1).lower()
        rp_root = _root_domain(r.rp_domain)
        if r.from_domain == r.rp_domain:
            pass
        elif rp_root in MARKETING_RP_DOMAINS:
            r.details.append(f"Marketing redirect via {r.rp_domain}")
        else:
            r.shadow_spoof = True
            r.findings.append(f"SHADOW SPOOF: {r.from_domain} vs {r.rp_domain}")
    elif fm:
        r.from_domain = fm.group(1).lower()

    return r


# ═══════════════════════════════════════════════════════════════════════════════
# HEADER ANOMALY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_headers(msg) -> Tuple[List[str], bool]:
    """Returns (anomalies, reply_to_hijack)."""
    anomalies = []
    reply_hijack = False

    mailer = str(msg.get('X-Mailer','') or msg.get('User-Agent','')).lower()
    if mailer and not any(l in mailer for l in LEGIT_MAILERS):
        if re.search(r'[a-z]{8,}v\d+',mailer) or mailer in ['test','spam','bulk']:
            anomalies.append(f"Unusual X-Mailer: '{mailer[:50]}'")

    from_addr = str(msg.get('From',''))
    reply_to = str(msg.get('Reply-To',''))
    if reply_to:
        fd = PAT_DOMAIN.search(from_addr)
        rd = PAT_DOMAIN.search(reply_to)
        if fd and rd and _root_domain(fd.group(1).lower()) != _root_domain(rd.group(1).lower()):
            reply_hijack = True
            anomalies.append(f"REPLY-TO HIJACK: From={fd.group(1)} vs Reply-To={rd.group(1)}")

    tzs = set()
    for h in msg.get_all('Received',[]) or []:
        m = PAT_TZ.search(str(h))
        if m: tzs.add(m.group(0))
    if len(tzs) > 4:
        anomalies.append(f"Timezone spread: {len(tzs)} zones")

    if not msg.get('Message-ID'):
        anomalies.append("Missing Message-ID")

    date_str = str(msg.get('Date',''))
    if date_str:
        try:
            md = email.utils.parsedate_to_datetime(date_str)
            diff = (md - datetime.now(md.tzinfo)).days
            if diff > 3:  # FIX: increased tolerance from 1 to 3 days
                anomalies.append(f"Future date: {diff}d ahead")
        except: pass

    return anomalies, reply_hijack


# ═══════════════════════════════════════════════════════════════════════════════
# BEC ENGINE (with linguistic density + contradiction detection)
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_bec(visible_text: str, subject: str, from_addr: str, word_count: int) -> BECResult:
    """BEC detection with linguistic density and contradiction detection."""
    r = BECResult()
    combined = normalize_text(f"{subject} {visible_text} {from_addr}").lower()
    if not combined.strip(): return r

    # Probability combination (not additive — diminishing returns built in)
    total_hits = 0
    survival = 1.0  # probability of NOT being BEC
    for cat, (keywords, prob) in BEC_KEYWORDS.items():
        for kw in keywords:
            matched = False
            try:
                matched = bool(re.search(kw, combined))
            except Exception:
                matched = kw in combined
            if matched:
                r.categories.append(cat)
                r.findings.append(f"[{cat}] '{kw}'")
                total_hits += 1
                survival *= (1.0 - prob)
                break
    r.score = 1.0 - survival

    # Linguistic density: BEC hit count / total words
    if word_count > 0:
        r.density = total_hits / max(word_count, 1)

    # Contradiction detection — dampens score
    for urgent_words, calm_words in BEC_CONTRADICTIONS:
        has_urgent = any(w in combined for w in urgent_words)
        has_calm = any(w in combined for w in calm_words)
        if has_urgent and has_calm:
            r.contradictions.append("Claims urgency but also says 'no rush' — inconsistent")
            r.score *= 0.5

    # Correlation combos — small boosts applied to remaining safe-probability
    cats = set(r.categories)
    combo_boost = 0.0
    if 'wire_transfer' in cats and 'urgency' in cats: combo_boost += 0.10
    if 'payment_redirect' in cats and 'urgency' in cats: combo_boost += 0.08
    if 'authority' in cats and ('wire_transfer' in cats or 'gift_cards' in cats): combo_boost += 0.10
    if 'secrecy' in cats and 'wire_transfer' in cats: combo_boost += 0.07
    if combo_boost > 0:
        r.score = r.score + combo_boost * (1.0 - r.score)  # boost into remaining space

    r.score = min(r.score, 0.95)  # never 100% certain from keywords alone
    if r.score >= 0.70: r.risk = "CRITICAL"; r.summary = f"HIGH-CONFIDENCE BEC (p={r.score:.0%})"
    elif r.score >= 0.45: r.risk = "HIGH"; r.summary = f"LIKELY BEC (p={r.score:.0%})"
    elif r.score >= 0.25: r.risk = "MEDIUM"; r.summary = f"BEC indicators (p={r.score:.0%})"
    elif r.score > 0: r.risk = "LOW"; r.summary = f"Minor BEC (p={r.score:.0%})"
    else: r.summary = "No BEC patterns"
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# DISPLAY NAME SPOOFING
# ═══════════════════════════════════════════════════════════════════════════════

def check_display_spoof(msg, org_domain=""):
    from_h = str(msg.get('From','')).strip()
    m = re.match(r'^"?([^"<@\n]{2,60}?)"?\s*<([^>]+)>', from_h)
    if not m: return None, "", ""
    dn = m.group(1).strip(); addr = m.group(2).strip().lower()
    dm = PAT_DOMAIN.search(addr)
    if not dm: return None, dn, ""
    sd = dm.group(1).lower()
    if org_domain and sd.endswith(org_domain): return None, dn, sd

    dnl = dn.lower()
    if '@' in dnl and '.' in dnl:
        return "HEADER INJECTION: Display name contains email", dn, sd
    for brand in DISPLAY_NAME_BRANDS:
        if brand in dnl:
            if brand.replace(' ','') not in sd:
                return f"BRAND SPOOF: Claims '{dn}' from '{sd}'", dn, sd
    return None, dn, sd


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACHMENT ANALYSIS (trust MacroRaptor, reduce redundancy)
# ═══════════════════════════════════════════════════════════════════════════════

def _yara_scan(data, fname=""):
    rules = _get_yara()
    if not rules or not data: return []
    data = data[:10*1024*1024]
    matches = []
    try:
        for hit in rules.match(data=data)[:50]:
            ms = []
            for sm in hit.strings:
                for inst in sm.instances:
                    try: ms.append(inst.matched_data.decode('utf-8','replace')[:40])
                    except: pass
            matches.append({
                'rule':hit.rule, 'severity':hit.meta.get('severity','MEDIUM'),
                'desc':hit.meta.get('description',hit.rule), 'cat':hit.meta.get('category',''),
                'strings':list(set(ms))[:5]
            })
    except Exception as e: log.error(f"YARA: {e}")
    return matches

def _pdf_uris(data):
    """Extract URIs from PDF. Uses pdfminer for stream decompression if available."""
    uris = set()

    # Method 1: pdfminer (handles compressed streams)
    if PDFMINER_OK:
        try:
            text = pdfminer_extract(io.BytesIO(data))
            for url in PAT_URL.findall(text or ''):
                uris.add(url)
        except Exception as e:
            log.debug(f"pdfminer failed: {e}")

    # Method 2: regex on raw bytes (fallback / supplement)
    for m in PAT_PDF_URI.finditer(data[:5*1024*1024]):
        try:
            raw = m.group(1).decode('latin-1','ignore').strip().replace('\x00','').replace('\r','').replace('\n','')
            if raw.startswith(('http','ftp')): uris.add(raw)
        except: pass
    for m in PAT_PDF_URL.finditer(data[:5*1024*1024]):
        try:
            raw = m.group(0).decode('latin-1','ignore').strip()
            raw = re.sub(r'[/>\)\]]+$','',raw)
            if len(raw)>=10 and '.' in raw: uris.add(raw)
        except: pass

    # Filter metadata
    return [u for u in list(uris)[:100]
            if not any(ns in u.lower() for ns in PDF_META_NS) and len(u)>=8]

def _office_uris(data):
    uris = set()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                if n.endswith('.rels'):
                    content = z.read(n).decode('utf-8','ignore')
                    for link in re.findall(r'Target=["\'](https?:[^"\']+)["\']', content, re.I):
                        if 'schemas.openxmlformats' not in link and 'schemas.microsoft' not in link:
                            uris.add(html.unescape(link))
    except: pass
    return list(uris)[:100]

def analyze_attachment(data, filename) -> MacroResult:
    """Analyze attachment. Trusts MacroRaptor verdict instead of redundant keyword grep."""
    r = MacroResult(filename=filename)
    r.md5 = hashlib.md5(data).hexdigest()
    r.sha256 = hashlib.sha256(data).hexdigest()

    # MalwareBazaar
    found, family, tags = check_malwarebazaar(data, filename)
    if found:
        r.mb_found=True; r.mb_family=family; r.risk_score=100
        r.details.append(f"MALWARE BAZAAR: {family}")

    # YARA — smart Archive_Sig handling (chameleon attack detection)
    yara_hits = _yara_scan(data, filename)
    is_valid_office = data[:4]==b'PK\x03\x04' and b'[Content_Types].xml' in data
    fl = filename.lower()
    is_archive_ext = fl.endswith(('.zip','.rar','.7z','.gz','.tar','.tgz','.bz2'))
    for m in yara_hits:
        if m['rule'] == 'Archive_Sig':
            if is_valid_office:
                continue  # Expected: .docx/.xlsx/.pptx are ZIP-based
            elif is_archive_ext:
                continue  # Expected: file claims to be an archive and is one
            else:
                # CHAMELEON ATTACK: file has archive magic bytes but claims
                # to be something else (e.g., invoice.pdf that's actually a ZIP)
                m['severity'] = 'HIGH'
                m['desc'] = (f"DISGUISED ARCHIVE: '{filename}' contains archive "
                             f"structure but claims to be a non-archive file")
                r.yara_matches.append(m)
                r.risk_score = max(r.risk_score, 50)
                r.details.append(f"CONTENT MISMATCH: '{filename}' is structurally an archive")
                continue
        r.yara_matches.append(m)
    if r.yara_matches:
        sev_score = {'CRITICAL':80,'HIGH':50,'MEDIUM':25}
        r.risk_score = max(r.risk_score, min(100, sum(sev_score.get(m['severity'],10) for m in r.yara_matches)))

    # PDF
    if data.startswith(b'%PDF'):
        r.file_type = "PDF"
        r.pdf_uris = _pdf_uris(data)
        if r.pdf_uris: r.details.append(f"{len(r.pdf_uris)} URI(s) extracted")
        for tag, desc in [(b'/OpenAction','Auto-exec'),(b'/JavaScript','JavaScript'),(b'/Launch','Launch cmd')]:
            if tag in data: r.has_macros=True; r.details.append(f"PDF tag: {desc}")
        r.verdict = "SUSPICIOUS" if (r.yara_matches or r.has_macros) else "SAFE"
        return r

    # Office (OLE or valid OOXML only — NOT plain ZIP files)
    is_ole = data.startswith(b'\xD0\xCF\x11\xE0')
    if is_ole or is_valid_office:
        r.file_type = "Office"
        r.pdf_uris.extend(_office_uris(data))
        if r.pdf_uris: r.details.append(f"{len(r.pdf_uris)} link(s)")

    elif data.startswith(b'PK\x03\x04') and not is_valid_office:
        # Plain ZIP/archive — do NOT run OleTools on it
        r.file_type = "Archive"
        r.pdf_uris.extend(_office_uris(data))  # still check for links inside
        if r.pdf_uris: r.details.append(f"{len(r.pdf_uris)} link(s) inside archive")
        r.verdict = "Archive file" if not r.yara_matches else f"SUSPICIOUS — {r.yara_matches[0]['rule']}"
        return r

    if r.file_type == "Office":
        if not OLETOOLS_OK:
            r.verdict = "Macro engine offline"; return r
        try:
            with _tmp_file(data, '.doc') as tmp:
                # OleID
                try:
                    for ind in OleID(tmp).check():
                        if ind.id=='ole_external_relationships' and ind.risk=='HIGH':
                            r.details.append("External data connections"); r.risk_score+=5
                        elif ind.risk in ['HIGH','MEDIUM']:
                            r.details.append(f"OleID: {ind.name} ({ind.risk})")
                            r.risk_score += 20 if ind.risk=='HIGH' else 10
                except Exception as e: log.warning(f"OleID: {e}")

                vba = VBA_Parser(tmp)
                if vba.detect_vba_macros():
                    r.has_macros = True
                    all_code = "\n".join(code for _,_,_,code in vba.extract_macros() if code)

                    # FIX: Trust MacroRaptor instead of redundant manual keyword search
                    try:
                        mr = _MacroRaptor(all_code)
                        mr.scan()
                        if mr.suspicious:
                            r.risk_score += 60
                            r.verdict = "SUSPICIOUS (MacroRaptor)"
                            r.details.append("MacroRaptor: SUSPICIOUS — auto-exec + risky ops")
                            # Only add specific flags from MacroRaptor
                            if mr.flags:
                                for flag_type, flag_match in [('A','auto-exec'),('W','write'),('X','execute')]:
                                    if flag_type in (mr.flags or ''):
                                        r.details.append(f"  MacroRaptor flag: {flag_match}")
                        else:
                            r.verdict = "SAFE — benign macros"
                            r.details.append("MacroRaptor: CLEAN")
                    except Exception:
                        r.verdict = "HAS MACROS (raptor failed)"

                    # Entropy as supplementary check only
                    ent = shannon_entropy(all_code)
                    if ent > 5.5:
                        r.risk_score += 15
                        r.details.append(f"High macro entropy ({ent:.1f})")

                    # YARA on VBA code
                    if YARA_OK:
                        for m in _yara_scan(all_code.encode('utf-8','ignore'), f"{filename}_vba"):
                            if m not in r.yara_matches: r.yara_matches.append(m)
                else:
                    r.verdict = "SAFE — no macros"
                vba.close()
        except Exception as e:
            r.verdict = f"Error: {str(e)[:40]}"
        return r

    if r.yara_matches:
        r.file_type = "Binary"; r.verdict = f"SUSPICIOUS — YARA: {r.yara_matches[0]['rule']}"
        return r
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# OBSERVABLE EXTRACTION (BeautifulSoup + heuristics)
# ═══════════════════════════════════════════════════════════════════════════════

def _normalize_url(url: str) -> str:
    """Normalize URL for deduplication: strip trailing slash, lowercase host."""
    try:
        p = urlparse(url)
        host = p.netloc.lower()
        path = p.path.rstrip('/')
        query = p.query
        norm = f"{p.scheme}://{host}{path}"
        if query: norm += f"?{query}"
        return norm
    except Exception:
        return url.rstrip('/')

def extract_observables(msg, html_body, text_body) -> Tuple[List[Observable], List[LinkMismatch]]:
    """Extract observables using DOM parsing. Detect link-text mismatches with tracking allowlist."""
    obs: List[Observable] = []
    mismatches: List[LinkMismatch] = []
    seen: Set[str] = set()

    def _add(typ, val, src, **kw):
        # Normalize URLs before deduplication
        norm_val = _normalize_url(val) if typ == 'url' else val.lower()
        key = f"{typ}:{norm_val}"
        if key in seen: return
        seen.add(key)
        o = Observable(type=typ, value=val, defanged=defang(val), source=src, **kw)
        if typ == 'url':
            o.is_shortener = urlparse(val).netloc.lower().lstrip('www.') in URL_SHORTENERS
            try:
                dom = urlparse(val).netloc.lower()
                o.suspicious_tld = any(dom.endswith(t) for t in SUSPICIOUS_TLDS)
            except: pass
            o.path_entropy = url_path_entropy(val)
        elif typ == 'domain':
            o.suspicious_tld = any(val.lower().endswith(t) for t in SUSPICIOUS_TLDS)
        obs.append(o)

    # HTML href extraction + link-text mismatch (with tracking allowlist)
    if BS4_OK and html_body:
        soup = BeautifulSoup(html_body, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if not href.startswith(('http://','https://')): continue
            _add('url', href, 'html_href')
            display = a.get_text(strip=True)
            if display:
                dm = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display)
                if dm:
                    dd = dm.group(1).lower().lstrip('www.')
                    hd = urlparse(href).netloc.lower().lstrip('www.')
                    hr = _root_domain(hd); dr = _root_domain(dd)
                    if hr != dr:
                        is_track = is_tracking_domain(hd)
                        mismatches.append(LinkMismatch(
                            href=href, display=display[:80],
                            href_domain=hd, display_domain=dd, is_tracking=is_track))
    elif html_body:
        for m in PAT_HREF.finditer(html_body):
            href = m.group(1).strip()
            if href.startswith(('http://','https://')): _add('url', href, 'html_href')

    # Body text URLs
    body = (html_body or '') + (text_body or '')
    for url in PAT_URL.findall(body)[:MAX_OBS]:
        _add('url', url, 'body')

    # Header domains
    for ea in PAT_EMAIL.findall(str(msg))[:MAX_OBS]:
        _add('domain', ea.split('@')[1].lower(), 'header')

    # IPs (FIX: was missing 172.16-31 private range)
    priv = [re.compile(p) for p in [r'^10\.',r'^192\.168\.',r'^172\.(1[6-9]|2\d|3[01])\.',r'^127\.',r'^169\.254\.',r'^0\.']]
    for h in msg.get_all('Received',[]) or []:
        for ip in PAT_IPV4.findall(str(h)):
            if not any(r.match(ip) for r in priv): _add('ip', ip, 'received')

    return obs, mismatches


# ═══════════════════════════════════════════════════════════════════════════════
# IMAGE ANALYSIS (with OCR)
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_image(part) -> Optional[ImageAnalysis]:
    fname = part.get_filename() or "image"
    r = ImageAnalysis(filename=fname)
    try:
        data = part.get_payload(decode=True)
        if not data: return None
        r.data = data
        if PIL_OK:
            img = PilImage.open(io.BytesIO(data))
            r.fmt = img.format or ""; r.size = img.size
            if img.size[0]<=2 and img.size[1]<=2: r.findings.append("Tracking pixel (≤2x2)")
            if QR_OK:
                try:
                    for d in decode_qr(img):
                        url = d.data.decode('utf-8','ignore')
                        r.qr_links.append(url); r.findings.append(f"QR: {url[:50]}")
                except: pass
            if STEGANO_OK and r.fmt in ['PNG','BMP','TIFF']:
                try:
                    if lsb.reveal(io.BytesIO(data)):
                        r.has_steg=True; r.findings.append("STEGANOGRAPHY: hidden LSB data")
                except: pass
            # OCR for image-text phishing
            if OCR_OK and r.fmt in ['PNG','JPEG','JPG','BMP','TIFF','GIF']:
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
# SIGNAL GENERATION (every module → ThreatSignal / TrustFactor)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_signals(auth, anomalies, reply_hijack, bec, spoof_result, spoof_dn, spoof_sd,
                     observables, macros, images, body_findings, link_mismatches,
                     abuse_data, attachment_risks, ocr_bec_hits) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    """Convert all analysis results into structured signals and trust factors."""
    sigs: List[ThreatSignal] = []
    trust: List[TrustFactor] = []

    # ── Auth signals ─────────────────────────────────────────────────────────
    if auth.spf == 'FAIL':
        sigs.append(ThreatSignal('spf_fail','auth',2, 0.70, 0.90,
            "SPF FAIL","Sending server not authorized", f"From: {auth.from_domain}"))
    elif auth.spf == 'SOFTFAIL':
        sigs.append(ThreatSignal('spf_softfail','auth',3, 0.35, 0.80,
            "SPF SOFTFAIL","Sender not fully authorized",""))
    elif auth.spf == 'PASS':
        trust.append(TrustFactor('spf_pass', 0.15, 0.90, "SPF passed"))

    if auth.dkim == 'FAIL':
        sigs.append(ThreatSignal('dkim_fail','auth',2, 0.50, 0.85,
            "DKIM FAIL","Message integrity compromised",""))
    elif auth.dkim == 'PASS':
        trust.append(TrustFactor('dkim_pass', 0.15, 0.90, "DKIM passed"))
    elif auth.dkim == 'NONE' and auth.spf in ('FAIL','SOFTFAIL'):
        sigs.append(ThreatSignal('dkim_none_compound','auth',3, 0.20, 0.70,
            "No DKIM + SPF issue","No cryptographic integrity",""))

    if auth.dmarc == 'FAIL':
        sigs.append(ThreatSignal('dmarc_fail','auth',2, 0.55, 0.85,
            "DMARC FAIL","Domain policy violated",""))
    elif auth.dmarc == 'PASS':
        trust.append(TrustFactor('dmarc_pass', 0.12, 0.90, "DMARC passed"))

    if auth.shadow_spoof:
        sigs.append(ThreatSignal('shadow_spoofing','auth',2, 0.75, 0.90,
            "Shadow Spoofing","From/Return-Path mismatch",
            f"{auth.from_domain} vs {auth.rp_domain}"))

    if auth.gateway_trust:
        trust.append(TrustFactor('gateway', 0.25, 0.85,
            f"Trusted gateway: {auth.gateway_name}"))

    if auth.hop_anomaly and 'stall' in auth.hop_anomaly.lower():
        sigs.append(ThreatSignal('hop_stall','network',4, 0.20, 0.60,
            "Hop Delay","Relay stalling detected", auth.hop_anomaly))

    # ── Header anomalies ─────────────────────────────────────────────────────
    if reply_hijack:
        sigs.append(ThreatSignal('reply_to_hijack','auth',2, 0.65, 0.85,
            "Reply-To Hijack","Replies redirected to different domain",""))
    for a in anomalies:
        if 'hijack' in a.lower(): continue  # already handled
        sigs.append(ThreatSignal(f'header_{a[:20]}','network',4, 0.15, 0.55,
            "Header Anomaly", a, ""))

    # ── Display name spoof ───────────────────────────────────────────────────
    if spoof_result:
        sigs.append(ThreatSignal('display_name_spoof','behavioral',2, 0.60, 0.80,
            "Display Name Spoof", spoof_result, f"'{spoof_dn}' from {spoof_sd}"))

    # ── BEC ───────────────────────────────────────────────────────────────────
    if bec.score >= 0.25:
        tier = 2 if bec.score >= 0.60 else 3
        sigs.append(ThreatSignal(f'bec_{"_".join(bec.categories[:2])}','behavioral',tier,
            min(bec.score, 0.85), 0.75 if bec.density > 0.02 else 0.55,
            "BEC Pattern", bec.summary, "; ".join(bec.findings[:3])))
    if bec.contradictions:
        trust.append(TrustFactor('bec_contradiction', 0.10, 0.60,
            "BEC contradiction: urgency + calm language"))

    # ── Link-text mismatches ──────────────────────────────────────────────────
    real_mismatches = [m for m in link_mismatches if not m.is_tracking]
    tracking_mismatches = [m for m in link_mismatches if m.is_tracking]
    if real_mismatches:
        sigs.append(ThreatSignal('link_text_mismatch','content',2, 0.55, 0.85,
            f"{len(real_mismatches)} Link-Text Mismatch(es)",
            "Displayed domain differs from link destination",
            f"e.g. shows '{real_mismatches[0].display_domain}' → '{real_mismatches[0].href_domain}'"))
    if tracking_mismatches:
        trust.append(TrustFactor('tracking_links', 0.05, 0.70,
            f"{len(tracking_mismatches)} link(s) via known tracking domains"))

    # ── Body findings ─────────────────────────────────────────────────────────
    for bf in body_findings:
        sigs.append(ThreatSignal(f'body_{bf[:15]}','content',4, 0.12, 0.50,
            "Content Alert", bf, ""))

    # ── URL heuristics ────────────────────────────────────────────────────────
    shorteners = [o for o in observables if o.is_shortener]
    if shorteners:
        sigs.append(ThreatSignal('url_shortener','content',4, 0.12, 0.60,
            f"{len(shorteners)} Shortened URL(s)","May hide destination",""))
    sus_tld = [o for o in observables if o.suspicious_tld]
    if sus_tld:
        sigs.append(ThreatSignal('suspicious_tld','content',4, 0.18, 0.65,
            f"{len(sus_tld)} Suspicious TLD(s)","Frequently-abused TLD",""))
    high_entropy_urls = [o for o in observables if o.type=='url' and o.path_entropy > 4.8]
    if high_entropy_urls:
        sigs.append(ThreatSignal('high_entropy_url','content',3, 0.25, 0.60,
            "High-Entropy URL Path","Likely phishing token",
            f"Entropy={high_entropy_urls[0].path_entropy:.1f}"))

    # ── Observables (VT results) — consolidated clean trust ─────────────────
    vt_clean_count = 0
    for o in observables:
        if o.vt and o.vt.success:
            if o.vt.threat_level in ('CRITICAL','MALICIOUS'):
                sigs.append(ThreatSignal(f'vt_{o.type}_{o.value[:20]}','network',1,
                    0.85 if o.vt.threat_level=='CRITICAL' else 0.70, 0.90,
                    f"VT: {o.type} flagged", o.vt.reasoning, o.defanged))
            elif o.vt.threat_level == 'SUSPICIOUS':
                sigs.append(ThreatSignal(f'vt_sus_{o.value[:20]}','network',3, 0.35, 0.65,
                    f"VT: {o.type} suspicious", o.vt.reasoning, o.defanged))
            elif o.vt.threat_level in ('CLEAN','LOW'):
                vt_clean_count += 1
    # Single consolidated trust factor for all clean VT results
    if vt_clean_count > 0:
        trust.append(TrustFactor('vt_clean_urls', min(0.15, vt_clean_count * 0.02), 0.75,
            f"{vt_clean_count} URL(s)/domain(s) verified clean by VirusTotal"))
    # Typosquat
    for o in observables:
        if o.vt and o.vt.domain_intel and o.vt.domain_intel.typosquat:
            sigs.append(ThreatSignal('typosquat','content',2, 0.50, 0.75,
                "Typosquat Domain", o.vt.domain_intel.typosquat, o.defanged))

    # ── AbuseIPDB ──────────────────────────────────────────────────────────────
    if abuse_data:
        ascore = abuse_data.get('abuseConfidenceScore',0)
        is_tor = abuse_data.get('isTor',False)
        is_cloud = _is_cloud(abuse_data.get('isp',''))
        if ascore >= 75 and not (is_cloud and auth.spf=='PASS'):
            sigs.append(ThreatSignal('abuse_ip_high','network',2, 0.65, 0.80,
                f"AbuseIPDB: {ascore}/100",
                f"{abuse_data.get('totalReports',0)} reports, ISP: {abuse_data.get('isp','')}",
                auth.source_ip))
        elif ascore >= 40 and not (is_cloud and auth.gateway_trust):
            sigs.append(ThreatSignal('abuse_ip_med','network',3, 0.30, 0.65,
                f"AbuseIPDB: {ascore}/100","Elevated",""))
        elif ascore < 10:
            trust.append(TrustFactor('ip_clean', 0.05, 0.60, f"AbuseIPDB clean ({ascore}/100)"))
        if is_tor:
            sigs.append(ThreatSignal('tor_exit','network',2, 0.50, 0.90,
                "TOR Exit Node","Source anonymized",""))

    # ── Attachment risks ──────────────────────────────────────────────────────
    for risk in attachment_risks:
        if risk['severity'] == 'CRITICAL':
            sigs.append(ThreatSignal(f"att_{risk['type']}_{risk['file'][:15]}",'attachment',2,
                0.60, 0.85, f"Attachment Risk: {risk['file']}", risk['desc'], ""))
        elif risk['severity'] == 'HIGH':
            sigs.append(ThreatSignal(f"att_{risk['type']}",'attachment',3, 0.30, 0.70,
                f"Attachment Risk: {risk['file']}", risk['desc'], ""))

    # ── Macro / YARA / MalwareBazaar ──────────────────────────────────────────
    for macro in macros:
        if macro.mb_found:
            sigs.append(ThreatSignal('malware_hash','attachment',1, 0.95, 0.98,
                f"MALWARE: {macro.filename}", f"MalwareBazaar: {macro.mb_family}", macro.sha256))
        for ym in macro.yara_matches:
            sev = ym['severity'].upper()
            prob = {'CRITICAL':0.80,'HIGH':0.50,'MEDIUM':0.25}.get(sev, 0.15)
            tier = 1 if sev=='CRITICAL' else (2 if sev=='HIGH' else 3)
            sigs.append(ThreatSignal(f"yara_{ym['rule']}",'attachment',tier, prob, 0.85,
                f"YARA: {ym['rule']}", ym['desc'], ""))
        if macro.has_macros and macro.risk_score >= 50:
            sigs.append(ThreatSignal(f"macro_{macro.filename[:15]}",'attachment',2,
                min(macro.risk_score/120, 0.80), 0.75,
                f"Risky Macros: {macro.filename}", macro.verdict, ""))

    # ── Image findings ────────────────────────────────────────────────────────
    for img in images:
        if img.has_steg:
            sigs.append(ThreatSignal('steganography','attachment',2, 0.70, 0.75,
                "Steganography", "Hidden data in image", img.filename))

    # ── OCR BEC hits ──────────────────────────────────────────────────────────
    if ocr_bec_hits:
        sigs.append(ThreatSignal('ocr_bec','content',3, 0.35, 0.55,
            "Image-Text BEC", f"OCR detected BEC in {ocr_bec_hits} image(s)",""))

    # ── Sender memory trust (check only — recording happens after clean verdict)
    if auth.from_domain:
        known, count, days = check_sender(auth.from_domain)
        if known and days > 30:
            trust.append(TrustFactor('known_sender', min(0.20, days/365*0.20), 0.75,
                f"Known sender: {auth.from_domain} ({days}d, {count} clean emails)"))

    return sigs, trust


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACHMENT RISK MATRIX
# ═══════════════════════════════════════════════════════════════════════════════

def get_attachment_risks(msg) -> List[Dict]:
    risks = []
    for part in msg.walk():
        if part.get_content_maintype()=='multipart': continue
        fname = part.get_filename() or ''; 
        if not fname: continue
        fl = fname.lower(); ct = part.get_content_type()
        for pat, desc in DOUBLE_EXT_PATS:
            if re.search(pat, fl):
                risks.append({'file':fname,'type':'double_ext','desc':f"Double ext: {desc}",'severity':'CRITICAL'}); break
        ext = '.'+fl.rsplit('.',1)[-1] if '.' in fl else ''
        if ext in DANGEROUS_EXTS:
            risks.append({'file':fname,'type':'dangerous_ext','desc':f"Dangerous: {ext}",'severity':'CRITICAL'})
        cext = fl.rsplit('.',1)[-1] if '.' in fl else ''
        vtypes = VALID_MIMES.get(cext,[])
        if vtypes and not any(v in ct.lower() for v in vtypes) and ct.lower() not in ['application/octet-stream']:
            risks.append({'file':fname,'type':'mime_mismatch','desc':f".{cext} as '{ct}'",'severity':'MEDIUM'})
    return risks


# ═══════════════════════════════════════════════════════════════════════════════
# CONTENT ANALYSIS HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def detect_tracking_pixels(html_body):
    findings = []
    if not html_body: return findings
    if re.search(r'<img[^>]+width=[\'"]?1[\'"]?[^>]+height=[\'"]?1[\'"]?', html_body, re.I):
        findings.append("1x1 Tracking Pixel")
    n = html_body.replace(" ","")
    if "color:white" in n or "color:#ffffff" in html_body.lower(): findings.append("Hidden white text")
    if "font-size:0" in n: findings.append("Zero-size font")
    if "display:none" in n: findings.append("display:none element")
    return findings

def detect_suspicious_language(visible_text, subject=""):
    findings = []
    combined = normalize_text(f"{subject} {visible_text}").lower()
    if len(combined) < 20: return findings
    for cat, (phrases, _) in SUSPICIOUS_PHRASES.items():
        for p in phrases:
            try:
                if re.search(p, combined): findings.append(f"Suspicious: '{p}' ({cat})"); break
            except:
                if p in combined: findings.append(f"Suspicious: '{p}' ({cat})"); break
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_text_report(report):
    sep = "="*90
    L = [sep, "SHERLOCK FORENSIC REPORT v10.0", sep,
         f"Date: {datetime.now():%Y-%m-%d %H:%M:%S}",
         f"MD5: {report['hashes']['md5']}  SHA256: {report['hashes']['sha256']}","",
         f"VERDICT: {report['verdict']}  |  Score: {report['score']}/100  |  "
         f"Threat: {report['threat_level']}  |  Confidence: {report['confidence']}%","",
         f"Explanation: {report['explanation']}",""]

    L += [sep,"SIGNALS (sorted by impact)",sep]
    for s in sorted(report['signals'], key=lambda x: x.probability*x.confidence, reverse=True):
        L.append(f"  [T{s.tier}/{s.category}] {s.title}  p={s.probability:.0%} c={s.confidence:.0%}")
        L.append(f"    {s.detail}")
        if s.evidence: L.append(f"    Evidence: {s.evidence}")

    if report['trust_factors']:
        L += ["",sep,"TRUST FACTORS",sep]
        for t in report['trust_factors']:
            L.append(f"  {t.name}: strength={t.strength:.0%} c={t.confidence:.0%} — {t.description}")

    if report['correlations']:
        L += ["",sep,"CORRELATIONS",sep]
        for c in report['correlations']: L.append(f"  {c}")

    auth = report['auth']
    L += ["",sep,"AUTHENTICATION",sep,
          f"SPF: {auth.spf}  DKIM: {auth.dkim}  DMARC: {auth.dmarc}",
          f"Source IP: {auth.source_ip or '—'}  Hops: {auth.hop_count}"]
    if auth.gateway_trust: L.append(f"Gateway: {auth.gateway_name}")
    if auth.hop_anomaly: L.append(f"Hop anomaly: {auth.hop_anomaly}")

    L += ["",sep,"ATTACHMENTS",sep]
    for m in report['macros']:
        L.append(f"  {m.filename}: {m.file_type} | Risk {m.risk_score}/100 | {m.verdict}")
        if m.mb_found: L.append(f"    MALWARE: {m.mb_family}")
        if m.sha256: L.append(f"    SHA256: {m.sha256}")

    L += ["",sep,"RECOMMENDATION",sep]
    if report['score'] >= 65: L.append("BLOCK / QUARANTINE")
    elif report['score'] >= 40: L.append("HOLD FOR MANUAL REVIEW")
    elif report['score'] >= 18: L.append("DELIVER WITH WARNING")
    else: L.append("RELEASE")
    L.append(sep)
    return '\n'.join(L)


def generate_pdf_report(text):
    if not PDF_REPORT_OK: return None
    try:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter)
        styles = getSampleStyleSheet()
        cs = ParagraphStyle('Code', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
        story = [Paragraph("Sherlock v10.0 Report", styles['Heading1']), Spacer(1,12)]
        for line in text.split('\n'):
            if '===' in line: story.append(Spacer(1,6))
            elif line.strip(): story.append(Paragraph(_esc(line).replace(' ','&nbsp;'), cs))
            else: story.append(Spacer(1,4))
        doc.build(story); buf.seek(0); return buf
    except: return None


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_email(msg_bytes, status_fn, progress_fn):
    """Main analysis pipeline. Every module feeds signals into the scoring engine."""
    if len(msg_bytes) > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds {MAX_FILE_SIZE//1024//1024}MB")

    msg = email.message_from_bytes(msg_bytes, policy=email.policy.default)
    subject = str(msg.get('Subject',''))
    from_addr = str(msg.get('From',''))

    org_domain = ""
    for hdr in ['Delivered-To','To']:
        m = PAT_DOMAIN.search(str(msg.get(hdr,'')))
        if m: org_domain = m.group(1).lower(); break

    # ── Extract bodies ────────────────────────────────────────────────────────
    status_fn("Extracting content...", "🔍")
    progress_fn(5)
    html_body = ""; text_body = ""
    for part in msg.walk():
        ct = part.get_content_type()
        try:
            d = part.get_payload(decode=True)
            if not d: continue
            decoded = d.decode('utf-8','ignore')
        except: continue
        if ct == 'text/html': html_body += decoded
        elif ct == 'text/plain': text_body += decoded

    visible_text = extract_visible_text(html_body) or text_body
    normalized = normalize_text(visible_text)
    word_count = len(normalized.split())

    # ── Content analysis ──────────────────────────────────────────────────────
    body_findings = detect_tracking_pixels(html_body)
    body_findings.extend(detect_suspicious_language(visible_text, subject))

    # ── Link-text mismatch + observables ──────────────────────────────────────
    status_fn("Extracting observables...", "🔗")
    progress_fn(10)
    observables, link_mismatches = extract_observables(msg, html_body, text_body)

    # ── BEC ───────────────────────────────────────────────────────────────────
    status_fn("BEC analysis...", "🎯")
    progress_fn(14)
    bec = analyze_bec(visible_text, subject, from_addr, word_count)

    # ── Headers ───────────────────────────────────────────────────────────────
    status_fn("Header analysis...", "🔎")
    progress_fn(18)
    anomalies, reply_hijack = analyze_headers(msg)

    # ── Display name ──────────────────────────────────────────────────────────
    spoof_result, spoof_dn, spoof_sd = check_display_spoof(msg, org_domain)
    progress_fn(22)

    # ── Authentication ────────────────────────────────────────────────────────
    status_fn("Verifying authentication...", "🔐")
    auth = analyze_auth(msg)
    progress_fn(28)

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    abuse_data = {}
    if auth.source_ip:
        status_fn(f"IP reputation: {auth.source_ip}", "🌐")
        abuse_data = check_abuseipdb(auth.source_ip)
    progress_fn(32)

    # ── VT scanning ───────────────────────────────────────────────────────────
    to_check = [o for o in observables if o.type in ('url','domain','ip')][:MAX_OBS]
    if to_check:
        total = len(to_check); done = 0
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(check_vt, o.type, o.value): o for o in to_check}
            for f in as_completed(futs):
                o = futs[f]; done += 1
                try:
                    o.vt = f.result()
                    if o.vt and o.vt.success:
                        if o.vt.threat_level in ('CRITICAL','MALICIOUS'): o.threat_score=100; o.reputation='malicious'
                        elif o.vt.threat_level=='SUSPICIOUS': o.threat_score=50; o.reputation='suspicious'
                        else: o.reputation='clean'
                except: pass
                progress_fn(32 + int(done/total*28))
    progress_fn(62)

    # ── Attachments ───────────────────────────────────────────────────────────
    status_fn("Scanning attachments...", "📎")
    macros = []
    for part in msg.walk():
        if part.get_content_maintype()=='multipart': continue
        fname = part.get_filename()
        if not fname: continue
        try:
            data = part.get_payload(decode=True)
            if not data: continue
            macro = analyze_attachment(data, fname)
            macros.append(macro)
            # Scan embedded URIs — tag source by file type
            uri_source = 'pdf_uri' if macro.file_type == 'PDF' else 'office_link'
            for u in macro.pdf_uris:
                if u.startswith('http'):
                    uo = Observable(type='url',value=u,defanged=defang(u),source=uri_source)
                    uo.vt = check_vt('url', u)
                    if uo.vt and uo.vt.success:
                        if uo.vt.threat_level in ('CRITICAL','MALICIOUS'):
                            uo.threat_score=100; uo.reputation='malicious'
                        elif uo.vt.threat_level == 'SUSPICIOUS':
                            uo.threat_score=50; uo.reputation='suspicious'
                        else:
                            uo.reputation='clean'
                    observables.append(uo)
        except Exception as e: log.error(f"Attachment {fname}: {e}")

    attachment_risks = get_attachment_risks(msg)

    # YARA on body
    if YARA_OK and visible_text:
        body_yara = _yara_scan(visible_text.encode('utf-8','ignore'), 'email_body')
        if body_yara:
            bm = MacroResult(filename="[Body]", file_type="HTML/Text",
                             yara_matches=body_yara, verdict=f"YARA: {body_yara[0]['rule']}")
            macros.append(bm)
    progress_fn(80)

    # ── Images + OCR ──────────────────────────────────────────────────────────
    status_fn("Image forensics + OCR...", "🖼️")
    images = []
    ocr_bec_hits = 0
    for part in msg.walk():
        if part.get_content_type().startswith('image/'):
            try:
                img = analyze_image(part)
                if img:
                    images.append(img)
                    # Scan QR links
                    for qr in img.qr_links:
                        qo = Observable(type='url',value=qr,defanged=defang(qr),source='qr')
                        qo.vt = check_vt('url', qr)
                        observables.append(qo)
                    # OCR text → BEC scan
                    if img.ocr_text:
                        ocr_bec = analyze_bec(img.ocr_text, "", "", len(img.ocr_text.split()))
                        if ocr_bec.score >= 0.25: ocr_bec_hits += 1
            except: pass
    progress_fn(90)

    # ── Generate signals ──────────────────────────────────────────────────────
    status_fn("Computing verdict...", "⚖️")
    signals, trust_factors = generate_signals(
        auth, anomalies, reply_hijack, bec, spoof_result, spoof_dn, spoof_sd,
        observables, macros, images, body_findings, link_mismatches,
        abuse_data, attachment_risks, ocr_bec_hits)

    # ── Run scoring engine ────────────────────────────────────────────────────
    scoring = run_scoring_engine(signals, trust_factors)

    # Record sender in memory ONLY if verdict is clean
    # (prevents attackers from building trust via repeated malicious emails)
    if auth.from_domain:
        record_sender_if_clean(auth.from_domain, scoring.score < 18)

    progress_fn(100)
    status_fn(f"Done! Verdict: {scoring.verdict}", "✅")
    time.sleep(0.3)

    return {
        'verdict': scoring.verdict, 'threat_level': scoring.threat_level,
        'score': scoring.score, 'confidence': scoring.confidence,
        'explanation': scoring.explanation,
        'signals': scoring.signals, 'trust_factors': scoring.trust_factors,
        'correlations': scoring.correlations_applied,
        'dampening': scoring.dampening_applied,
        'auth': auth, 'bec': bec, 'observables': observables,
        'macros': macros, 'images': images,
        'link_mismatches': link_mismatches,
        'body_findings': body_findings,
        'attachment_risks': attachment_risks,
        'abuse_data': abuse_data,
        'anomalies': anomalies, 'reply_hijack': reply_hijack,
        'spoof': spoof_result, 'spoof_dn': spoof_dn, 'spoof_sd': spoof_sd,
        'hashes': {'md5':hashlib.md5(msg_bytes).hexdigest(),
                   'sha256':hashlib.sha256(msg_bytes).hexdigest()},
        'metadata': {'from':str(msg.get('From','')), 'subject':subject,
                     'date':str(msg.get('Date',''))},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# REASONING CARD GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

DC = {
    'critical':'#ff5555','high':'#ff9500','medium':'#f1fa8c','low':'#50fa7b',
    'safe':'#50fa7b','unknown':'#94a3b8','bg':'#0f172a','card':'#1e293b',
    'elev':'#2d3748','border':'#334155','accent':'#38bdf8','purple':'#8b5cf6',
    'text1':'#e2e8f0','text2':'#94a3b8','ok':'#10b981','warn':'#f59e0b','err':'#ef4444',
}
SHADOW = '0 4px 6px -1px rgba(0,0,0,0.3)'

def _tc(level):
    return {'CRITICAL':DC['critical'],'MALICIOUS':DC['critical'],'HIGH':DC['high'],
            'SUSPICIOUS':DC['medium'],'MEDIUM':DC['medium'],'LOW':DC['low'],
            'CLEAN':DC['safe'],'SAFE':DC['safe']}.get((level or '').upper(), DC['unknown'])

def _ti(level):
    return {'CRITICAL':'🚨','MALICIOUS':'🚨','HIGH':'⚠️','SUSPICIOUS':'⚠️',
            'MEDIUM':'⚠️','LOW':'📋','CLEAN':'✅','SAFE':'✅'}.get((level or '').upper(),'❓')

def _card(icon, title, body, detail, color):
    """Render a single reasoning card (matching v9 design)."""
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
    """Build analytical reasoning cards from report data — explains WHAT IT MEANS."""
    cards = []
    auth = R['auth']
    sigs = R['signals']
    sig_names = {s.name for s in sigs}

    # 1. Sender Identity
    if auth.shadow_spoof and R.get('spoof'):
        cards.append(('👤','Sender Identity',
            f"🚨 **Double identity deception** — display name impersonation AND Return-Path "
            f"routes replies to **{auth.rp_domain}** instead of **{auth.from_domain}**. "
            f"The recipient sees a trusted name; replies go to the attacker.",
            f"From: {auth.from_full[:70]} | Return-Path: {auth.rp_domain}", DC['critical']))
    elif auth.shadow_spoof:
        cards.append(('👤','Sender Identity',
            f"⚠️ **Return-Path mismatch** — email appears from **{auth.from_domain}** "
            f"but replies route to **{auth.rp_domain}**.",
            f"From: {auth.from_full[:70]}", DC['critical']))
    elif R.get('spoof'):
        cards.append(('👤','Sender Identity',
            f"🚨 **Display name impersonation** — {R['spoof']}",
            f"Domain: {R.get('spoof_sd','')}", DC['high']))
    else:
        cards.append(('👤','Sender Identity',
            f"✅ **Sender identity consistent** — From, Return-Path, and envelope all "
            f"align to **{auth.from_domain or 'unknown'}**. No identity deception detected.",
            f"From: {auth.from_full[:70]}", DC['ok']))

    # 2. Authentication
    if auth.spf=='FAIL' and auth.dmarc=='FAIL':
        abody = ("🚨 **Authentication failure** — SPF confirms unauthorized sender, "
                 "DMARC violation means domain policy breached. Strongest spoofing signal.")
        acol = DC['critical']
    elif auth.spf=='FAIL':
        abody = f"⚠️ **Unauthorized sender** — server NOT in **{auth.from_domain}**'s SPF record."
        acol = DC['critical']
    elif auth.spf=='SOFTFAIL':
        abody = f"⚠️ **SPF softfail** — sender not fully authorized by **{auth.from_domain}**."
        acol = DC['warn']
    elif auth.spf=='PASS' and auth.dkim=='PASS' and auth.dmarc=='PASS':
        abody = "✅ **Full authentication chain intact** — SPF, DKIM, and DMARC all pass."
        acol = DC['ok']
    elif auth.spf=='PASS' and auth.dkim=='PASS':
        abody = "✅ **SPF + DKIM pass** — sender verified, message unmodified."
        acol = DC['ok']
    else:
        abody = f"SPF: {auth.spf} | DKIM: {auth.dkim} | DMARC: {auth.dmarc}"
        acol = DC['accent']
    if auth.gateway_trust:
        abody += f" 🛡️ Trusted gateway **{auth.gateway_name}** pre-screened this message."
    det = ""
    if auth.live_verified:
        sp = auth.live_spf.get('status','—'); dm = auth.live_dmarc.get('status','—')
        dp = auth.live_dmarc.get('policy','')
        det = f"Live DNS — SPF: {sp} | DMARC: {dm}" + (f" (policy={dp})" if dp else "")
    else:
        det = "Live DNS offline — install dnspython for verification"
    cards.append(('🔐','Authentication & DNS', abody, det, acol))

    # 3. Source IP
    abuse = R.get('abuse_data',{})
    if auth.source_ip and abuse:
        ascore = abuse.get('abuseConfidenceScore',0)
        if ascore >= 75:
            cards.append(('🌐','Source IP Reputation',
                f"🚨 **High-confidence malicious IP** — {abuse.get('totalReports',0)} abuse reports, "
                f"{ascore}/100 AbuseIPDB." + (" **TOR exit node.**" if abuse.get('isTor') else ""),
                f"ISP: {abuse.get('isp','—')} | Country: {abuse.get('countryCode','—')}",
                DC['critical']))
        elif ascore >= 40:
            cards.append(('🌐','Source IP Reputation',
                f"⚠️ **Elevated risk** — {abuse.get('totalReports',0)} reports ({ascore}/100).",
                f"ISP: {abuse.get('isp','—')}", DC['high']))
        else:
            cards.append(('🌐','Source IP Reputation',
                f"✅ **IP clean** — {ascore}/100 across 90-day lookback. No abuse history.",
                f"ISP: {abuse.get('isp','—')} | Country: {abuse.get('countryCode','—')}", DC['ok']))
    elif auth.source_ip:
        cards.append(('🌐','Source IP Reputation',
            f"ℹ️ **No reputation data** for {auth.source_ip} — add abuseipdb_key for scoring.",
            "Add abuseipdb_key to secrets.toml", DC['accent']))

    # 4. Link-Text Mismatches
    ltms = R.get('link_mismatches',[])
    real_ltm = [m for m in ltms if not m.is_tracking]
    if real_ltm:
        cards.append(('🔗','Link-Text Mismatches',
            f"🚨 **{len(real_ltm)} mismatch(es)** — displayed domain differs from actual link. "
            f"Classic phishing technique: victim sees a trusted name but clicks a malicious link.",
            f"e.g. Shows '{real_ltm[0].display_domain}' → links to '{real_ltm[0].href_domain}'",
            DC['critical']))

    # 5. Attachments
    real_att = [m for m in R['macros'] if m.filename != '[Body]']
    if real_att:
        mb = sum(1 for m in real_att if m.mb_found)
        yr = sum(len(m.yara_matches) for m in real_att)
        risks = len(R.get('attachment_risks',[]))
        if mb:
            fam = next((m.mb_family for m in real_att if m.mb_found),'Unknown')
            cards.append(('📎','Attachments',
                f"🚨 **Confirmed malware** — SHA256 matches MalwareBazaar: **{fam}**. "
                f"Quarantine immediately.", f"{len(real_att)} file(s) scanned", DC['critical']))
        elif yr:
            top = next((y['rule'] for m in real_att for y in m.yara_matches),'')
            cards.append(('📎','Attachments',
                f"⚠️ **YARA match** — {yr} rule(s) fired, top: **{top}**.",
                f"{len(real_att)} file(s)", DC['high']))
        elif risks:
            cards.append(('📎','Attachments',
                f"⚠️ **{risks} structural risk(s)** — deceptive file structure detected.",
                f"{len(real_att)} file(s)", DC['warn']))
        else:
            cards.append(('📎','Attachments',
                f"✅ **All {len(real_att)} attachment(s) clean** — YARA, MalwareBazaar, "
                f"macro analysis all clear.", "", DC['ok']))

    # 6. URLs & Domains
    url_obs = [o for o in R['observables'] if o.type in ('url','domain') and o.vt]
    if url_obs:
        threats = [o for o in url_obs if o.vt.threat_level in ('CRITICAL','MALICIOUS')]
        clean = [o for o in url_obs if o.vt.threat_level in ('CLEAN','LOW')]
        if threats:
            cards.append(('🌍','URLs & Domains',
                f"🚨 **{len(threats)} malicious URL(s)** confirmed by VirusTotal.",
                f"{len(url_obs)} scanned", DC['critical']))
        elif len(clean) == len(url_obs):
            cards.append(('🌍','URLs & Domains',
                f"✅ **All {len(clean)} URL(s) verified clean** by VirusTotal consensus.",
                f"{len(url_obs)} scanned", DC['ok']))
        else:
            cards.append(('🌍','URLs & Domains',
                f"📊 **{len(url_obs)} observable(s)** scanned — {len(threats)} threats, "
                f"{len(clean)} clean.", "", DC['accent']))

    # 7. BEC
    bec = R.get('bec')
    if bec and bec.score >= 0.25:
        cats = bec.categories
        if 'wire_transfer' in cats and 'urgency' in cats:
            bbody = "🚨 **Classic wire fraud** — urgent wire transfer language detected."
        elif 'gift_cards' in cats:
            bbody = "🚨 **Gift card scam** — requests for gift card purchases."
        elif 'payment_redirect' in cats:
            bbody = "🚨 **Payment redirect** — bank details change requested."
        else:
            bbody = bec.summary
        bcol = DC['critical'] if bec.score >= 0.6 else DC['high']
        cards.append(('🎯','BEC / Social Engineering', bbody,
            f"Score: {bec.score:.0%} | Categories: {', '.join(cats)}", bcol))

    # 8. Scan Coverage
    total_obs = len(R['observables'])
    vt_ok = sum(1 for o in R['observables'] if o.vt and o.vt.success)
    cards.append(('📊','Scan Coverage',
        f"📊 **{total_obs} observables** analyzed — VT: {vt_ok}/{total_obs} | "
        f"**{len(R['macros'])}** file(s) scanned by YARA + MalwareBazaar.",
        f"AbuseIPDB: {'active' if abuse else 'not configured'} | "
        f"{'YARA active' if YARA_OK else 'YARA offline'}", DC['accent']))

    return cards


# ═══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    st.set_page_config(page_title="Sherlock v10.0", layout="wide", page_icon="🔍")
    st.markdown(f"""<style>
.main{{background:linear-gradient(135deg,{DC['bg']} 0%,#1a1f2e 100%)}}
.stProgress > div > div > div > div{{background-image:linear-gradient(90deg,{DC['accent']},{DC['purple']},{DC['high']});border-radius:10px}}
.stTabs [data-baseweb="tab-list"]{{gap:6px;background:{DC['card']};padding:8px;border-radius:10px}}
.stTabs [data-baseweb="tab"]{{border-radius:8px;padding:10px 18px}}
.stTabs [aria-selected="true"]{{background:linear-gradient(135deg,{DC['accent']},{DC['purple']});box-shadow:0 0 20px rgba(59,130,246,0.3)}}
[data-testid="stMetricValue"]{{font-size:2em;font-weight:700;background:linear-gradient(135deg,{DC['accent']},{DC['purple']});-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
</style>""", unsafe_allow_html=True)

    st.title("🔍 SHERLOCK — FORENSIC EMAIL ANALYZER")
    st.caption("v10.0 | Signal-Based Nonlinear Scoring · Correlation Engine · BeautifulSoup · OCR · Sender Memory")

    if 'report' not in st.session_state: st.session_state.report = None
    if 'fhash' not in st.session_state: st.session_state.fhash = None

    with st.sidebar:
        st.markdown("### 📧 Upload Email")
        up = st.file_uploader("Select .eml file", type=['eml'])
        if up:
            fb = up.getvalue(); fh = hashlib.md5(fb).hexdigest()
            sz = len(fb)/(1024*1024)
            if sz > 50: st.error("❌ File too large"); st.stop()
            st.success(f"✅ Loaded ({sz:.2f} MB)")
            if st.session_state.fhash != fh:
                st.session_state.fhash = fh; st.session_state.report = None
        st.divider()
        st.markdown("### ✅ Module Status")
        for name, ok in [("BeautifulSoup",BS4_OK),("OleTools",OLETOOLS_OK),
                         ("YARA (9 rules)",YARA_OK),("pdfminer",PDFMINER_OK),
                         ("OCR",OCR_OK),("PIL (Image)",PIL_OK),
                         ("WHOIS",WHOIS_OK),("VirusTotal",bool(Config.VT_KEY)),
                         ("AbuseIPDB",bool(Config.ABUSE_KEY))]:
            st.metric(name, "✅ Online" if ok else "⚠️ Offline")

    if not up:
        st.info("👆 Upload an .eml file to begin analysis")
        c1,c2,c3 = st.columns(3)
        with c1:
            st.markdown("**🧠 Signal Engine**\n- Nonlinear scoring\n- Correlation bonuses\n- Signal hierarchy")
        with c2:
            st.markdown("**🔍 Smart Detection**\n- BeautifulSoup parsing\n- Text de-obfuscation\n- Link-text mismatch")
        with c3:
            st.markdown("**📊 Complete Analysis**\n- OCR image text\n- pdfminer PDF streams\n- Sender memory")
        return

    try:
        if st.session_state.report is None:
            pb = st.progress(0); sc = st.empty()
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
            sc.empty(); pb.empty()
            st.success(f"✅ Analysis complete in {time.time()-t0:.1f}s")

        R = st.session_state.report
        txt = generate_text_report(R)

        # ── Verdict banner ────────────────────────────────────────────────
        tc = _tc(R['threat_level']); ti = _ti(R['threat_level'])
        action = "✅ RELEASE" if R['score'] < 18 else ("🔍 REVIEW" if R['score'] < 40 else ("⚠️ HOLD" if R['score'] < 65 else "⛔ QUARANTINE"))
        ac = DC['ok'] if R['score']<18 else (DC['accent'] if R['score']<40 else (DC['warn'] if R['score']<65 else DC['critical']))
        st.markdown(
            f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
            f"padding:24px;border-radius:12px;margin:16px 0;border-left:6px solid {tc};"
            f"box-shadow:0 10px 15px -3px rgba(0,0,0,0.4)'>"
            f"<div style='display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:10px'>"
            f"<h2 style='margin:0;color:{DC['text1']}'>{ti} Verdict: {_esc(R['verdict'])}</h2>"
            f"<span style='background:{ac};color:#fff;padding:6px 14px;border-radius:20px;"
            f"font-weight:700;font-size:.9em'>{action}</span></div>"
            f"<p style='margin:0;color:{DC['text2']};font-size:1.05em'>"
            f"<b>Score:</b> <span style='color:{tc};font-weight:700'>{R['score']}/100</span> | "
            f"<b>Threat:</b> {_esc(R['threat_level'])} | "
            f"<b>Confidence:</b> {R['confidence']}%</p></div>",
            unsafe_allow_html=True)

        tabs = st.tabs(["📋 Report & Intelligence","🔐 Authentication","🌐 URLs & Domains",
                         "📎 Attachments","🔴 YARA","🖼️ Images","📊 All Findings","💾 Export"])

        # ══════════════════════════════════════════════════════════════════
        # TAB 1: Report & Intelligence (reasoning cards + key signals)
        # ══════════════════════════════════════════════════════════════════
        with tabs[0]:
            # Section: Reasoning Cards
            st.markdown(
                f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
                f"border:2px solid {DC['purple']};border-left:6px solid {DC['purple']};"
                f"border-radius:12px;padding:16px 20px;margin:12px 0'>"
                f"<div style='font-size:1.2em;font-weight:700;color:{DC['purple']}'>🧠 REASONING</div>"
                f"<div style='color:{DC['text2']};font-size:.85em'>"
                f"Analytical insights — <em>what it means, not just what was found</em></div></div>",
                unsafe_allow_html=True)

            try:
                reason_cards = build_reasoning_cards(R)
            except Exception as e:
                log.error(f"Reasoning cards: {e}"); reason_cards = []

            for i in range(0, len(reason_cards), 2):
                cols = st.columns(2)
                for j, col in enumerate(cols):
                    if i + j < len(reason_cards):
                        ic, ti_c, body, det, clr = reason_cards[i + j]
                        with col:
                            st.markdown(_card(ic, ti_c, body, det, clr), unsafe_allow_html=True)

            # Section: Key Threat Signals (top 5 only, human-readable)
            threat_sigs = sorted(R['signals'], key=lambda x: x.probability*x.confidence, reverse=True)
            if threat_sigs:
                st.markdown(
                    f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
                    f"border:2px solid {DC['accent']};border-left:6px solid {DC['accent']};"
                    f"border-radius:12px;padding:16px 20px;margin:16px 0'>"
                    f"<div style='font-size:1.2em;font-weight:700;color:{DC['accent']}'>🎯 KEY SIGNALS</div>"
                    f"<div style='color:{DC['text2']};font-size:.85em'>"
                    f"Top threat signals driving the verdict — per-signal explanation</div></div>",
                    unsafe_allow_html=True)

                for s in threat_sigs[:6]:
                    eff = s.probability * s.confidence
                    if eff >= 0.4: sc = DC['critical']; sev = "CRITICAL"
                    elif eff >= 0.2: sc = DC['high']; sev = "HIGH"
                    elif eff >= 0.08: sc = DC['warn']; sev = "MEDIUM"
                    else: sc = DC['text2']; sev = "LOW"
                    st.markdown(
                        f"<div style='background:{DC['bg']}88;border-radius:8px;padding:12px 14px;"
                        f"margin:8px 0;border-left:4px solid {sc}'>"
                        f"<div style='display:flex;justify-content:space-between;align-items:flex-start;"
                        f"flex-wrap:wrap;gap:6px'>"
                        f"<span style='font-weight:700;color:{sc};font-size:.95em'>{_esc(s.title)}</span>"
                        f"<span style='background:{sc};color:#fff;padding:2px 10px;border-radius:10px;"
                        f"font-size:.72em;font-weight:700;white-space:nowrap'>{sev} ({eff:.0%})</span></div>"
                        f"<div style='color:{DC['text2']};font-size:.85em;margin-top:5px'>"
                        f"<span style='color:{DC['border']}'>Why: </span>{_esc(s.detail)}</div>"
                        f"{'<div style=\"color:'+DC['text2']+';font-size:.78em;margin-top:2px;font-style:italic\">'+_esc(s.evidence)+'</div>' if s.evidence else ''}"
                        f"</div>",
                        unsafe_allow_html=True)
            else:
                st.success("✅ No threat signals detected — email appears clean")

            # Section: Mitigating Factors (trust + correlations)
            if R['trust_factors'] or R.get('correlations'):
                st.markdown(
                    f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
                    f"border:2px solid {DC['ok']};border-left:6px solid {DC['ok']};"
                    f"border-radius:12px;padding:16px 20px;margin:16px 0'>"
                    f"<div style='font-size:1.2em;font-weight:700;color:{DC['ok']}'>✅ MITIGATING FACTORS</div>"
                    f"<div style='color:{DC['text2']};font-size:.85em'>"
                    f"Positive signals that reduce the threat score</div></div>",
                    unsafe_allow_html=True)

                for tf in R['trust_factors']:
                    st.markdown(
                        f"<div style='background:{DC['card']};border:1px solid {DC['ok']}44;"
                        f"border-left:5px solid {DC['ok']};border-radius:8px;padding:12px 16px;"
                        f"margin:6px 0;display:flex;align-items:center;gap:12px'>"
                        f"<span style='background:{DC['ok']};color:#fff;border-radius:4px;"
                        f"padding:2px 8px;font-weight:700;font-size:.82em'>✓</span>"
                        f"<span style='color:{DC['text1']};font-size:.92em'>{_esc(tf.description)}"
                        f" <span style='color:{DC['text2']};font-size:.82em'>"
                        f"(dampening: {tf.strength:.0%})</span></span></div>",
                        unsafe_allow_html=True)

                if R.get('correlations'):
                    st.markdown(f"**🔗 Signal Correlations Applied:**")
                    for c in R['correlations']:
                        st.markdown(
                            f"<div style='background:{DC['accent']}12;border-left:3px solid {DC['accent']};"
                            f"border-radius:6px;padding:8px 12px;margin:4px 0;color:{DC['text1']};"
                            f"font-size:.88em'>{_esc(c)}</div>",
                            unsafe_allow_html=True)

            # Analyst recommendation
            score = R['score']
            if score >= 65:
                note = "⛔ **QUARANTINE** — Block delivery. Investigate sender and any clicked links."
                nc = DC['critical']
            elif score >= 40:
                note = "⚠️ **HOLD FOR REVIEW** — Do not deliver without manual analyst review."
                nc = DC['warn']
            elif score >= 18:
                note = "🔍 **DELIVER WITH CAUTION** — Soft quarantine or add warning banner."
                nc = DC['accent']
            else:
                note = "✅ **RELEASE** — No significant threats. Safe for delivery."
                nc = DC['ok']
            note_html = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', _esc(note))
            st.markdown(
                f"<div style='background:{nc}15;border-left:4px solid {nc};border-radius:8px;"
                f"padding:14px 18px;margin:16px 0'>"
                f"<div style='font-weight:700;color:{nc};margin-bottom:4px'>📋 Analyst Recommendation</div>"
                f"<div style='color:{DC['text1']};font-size:.95em'>{note_html}</div></div>",
                unsafe_allow_html=True)

            # Email metadata
            with st.expander("📋 Email Metadata & Hashes"):
                meta = R.get('metadata',{})
                hashes = R.get('hashes',{})
                mc1, mc2 = st.columns(2)
                with mc1:
                    st.markdown(f"**From:** `{_esc(meta.get('from','—')[:80])}`")
                    st.markdown(f"**Subject:** `{_esc(meta.get('subject','—')[:80])}`")
                    st.markdown(f"**Date:** `{_esc(meta.get('date','—')[:60])}`")
                with mc2:
                    st.markdown(f"**MD5:** `{hashes.get('md5','—')}`")
                    st.markdown(f"**SHA256:** `{hashes.get('sha256','—')}`")

        # ══════════════════════════════════════════════════════════════════
        # TAB 2: Authentication
        # ══════════════════════════════════════════════════════════════════
        with tabs[1]:
            st.subheader("🔐 Email Authentication")
            auth = R['auth']
            c1,c2,c3,c4 = st.columns(4)
            for col, lbl, val in [(c1,"SPF",auth.spf),(c2,"DKIM",auth.dkim),(c3,"DMARC",auth.dmarc),(c4,"Hops",str(auth.hop_count))]:
                delta = "Valid" if val=="PASS" else ("Issue" if val in ("FAIL","SOFTFAIL") else "")
                dcol = "normal" if val=="PASS" else ("inverse" if val in ("FAIL","SOFTFAIL") else "off")
                col.metric(lbl, val, delta=delta, delta_color=dcol)
            if auth.gateway_trust:
                st.success(f"🛡️ **Trusted Gateway:** {auth.gateway_name}")
            if auth.shadow_spoof:
                st.error(f"🚨 Shadow spoofing: From={auth.from_domain} vs Return-Path={auth.rp_domain}")
            if auth.hop_anomaly:
                st.warning(auth.hop_anomaly)
            if auth.hop_delays:
                stalls = [(i+1,d) for i,d in enumerate(auth.hop_delays) if d>300]
                for hop, delay in stalls:
                    st.warning(f"⚠️ Hop {hop}: {delay/60:.1f}min relay delay")
            abuse = R.get('abuse_data',{})
            if abuse and abuse.get('abuseConfidenceScore') is not None:
                ascore = abuse.get('abuseConfidenceScore',0)
                ac = DC['critical'] if ascore>=75 else (DC['high'] if ascore>=40 else DC['ok'])
                st.markdown(
                    f"<div style='border-left:4px solid {ac};padding:14px;background:{ac}22;"
                    f"border-radius:8px;margin:12px 0'><b>🌐 Source IP (AbuseIPDB)</b><br>"
                    f"Score: <b style='color:{ac}'>{ascore}/100</b> | "
                    f"Reports: {abuse.get('totalReports',0)} | "
                    f"Country: {abuse.get('countryCode','')} | "
                    f"ISP: {_esc(abuse.get('isp','')[:40])}"
                    f"{'<br>🧅 TOR Exit Node' if abuse.get('isTor') else ''}</div>",
                    unsafe_allow_html=True)
            if R.get('spoof'):
                st.error(f"🎭 {R['spoof']}")
            st.markdown("#### 📋 Detailed Analysis")
            for d in auth.details:
                du = d.upper()
                if any(k in du for k in ["FAIL","SPOOF","WARNING"]): st.error(f"⚠️ {d}")
                elif any(k in du for k in ["PASS","VERIFIED","TRUSTED","CLEAN","GATEWAY"]): st.success(f"✅ {d}")
                else: st.info(f"ℹ️ {d}")
            if R['anomalies']:
                st.markdown("#### 🔎 Header Anomalies")
                for a in R['anomalies']:
                    if 'hijack' in a.lower(): st.error(f"🚨 {a}")
                    else: st.warning(f"⚠️ {a}")

        # ══════════════════════════════════════════════════════════════════
        # TAB 3: URLs & Domains
        # ══════════════════════════════════════════════════════════════════
        with tabs[2]:
            st.subheader("🌐 URL, Domain & IP Analysis")
            ltms = R.get('link_mismatches',[])
            real_ltm = [m for m in ltms if not m.is_tracking]
            track_ltm = [m for m in ltms if m.is_tracking]
            if real_ltm:
                st.error(f"🚨 **{len(real_ltm)} link-text mismatch(es)** — displayed domain differs from actual link")
                for m in real_ltm:
                    st.markdown(f"- **Display:** `{_esc(m.display_domain)}` → **Links to:** `{_esc(m.href_domain)}`")
            if track_ltm:
                st.info(f"ℹ️ {len(track_ltm)} link(s) via known tracking/marketing domains (suppressed as expected)")
            if real_ltm or track_ltm: st.divider()

            obs = R['observables']
            if obs:
                vt_obs = [o for o in obs if o.vt]
                threat_cnt = sum(1 for o in vt_obs if o.vt.threat_level in ('CRITICAL','MALICIOUS'))
                clean_cnt = sum(1 for o in vt_obs if o.vt.threat_level in ('CLEAN','LOW'))
                pdf_cnt = sum(1 for o in vt_obs if o.source == 'pdf_uri')
                office_cnt = sum(1 for o in vt_obs if o.source == 'office_link')
                unk_cnt = sum(1 for o in vt_obs if o.vt.threat_level == 'UNKNOWN')

                mc1,mc2,mc3,mc4 = st.columns(4)
                mc1.metric("Total Scanned", len(vt_obs))
                mc2.metric("✅ Clean", clean_cnt)
                mc3.metric("🚨 Threats", threat_cnt)
                mc4.metric("📄 From Files", pdf_cnt + office_cnt)

                if unk_cnt:
                    st.info(f"ℹ️ **{unk_cnt} URL(s) show UNKNOWN** — not in VirusTotal database. UNKNOWN ≠ malicious; investigate if unexpected.")
                if pdf_cnt:
                    st.markdown(f"<div style='background:{DC['accent']}15;border-left:3px solid {DC['accent']};padding:8px 12px;border-radius:4px;margin:4px 0;color:{DC['text1']};font-size:.9em'>🔗 <b>{pdf_cnt} URL(s) extracted from PDF</b> attachment structure and scanned</div>", unsafe_allow_html=True)
                if office_cnt:
                    st.markdown(f"<div style='background:{DC['purple']}15;border-left:3px solid {DC['purple']};padding:8px 12px;border-radius:4px;margin:4px 0;color:{DC['text1']};font-size:.9em'>🔗 <b>{office_cnt} URL(s) extracted from Office</b> document relationships and scanned</div>", unsafe_allow_html=True)
                st.divider()

                # Source badge styling
                _src_badge = {
                    'pdf_uri':('📄 PDF','#0ea5e9','#fff'), 'office_link':('📝 Office','#8b5cf6','#fff'),
                    'html_href':('🔗 HREF','#475569','#e2e8f0'), 'body':('📧 Body','#475569','#e2e8f0'),
                    'image_qr':('📱 QR','#f59e0b','#000'), 'received':('📡 Header','#475569','#e2e8f0'),
                    'header':('📡 Header','#475569','#e2e8f0'),
                }
                _sort = {'CRITICAL':0,'MALICIOUS':1,'SUSPICIOUS':2,'HIGH':3,'UNKNOWN':4,'LOW':5,'CLEAN':6}
                for o in sorted(vt_obs, key=lambda x: _sort.get(x.vt.threat_level or '',7)):
                    tl = o.vt.threat_level or "UNKNOWN"; ic = _ti(tl); clr = _tc(tl)
                    sl, sb, sf = _src_badge.get(o.source, ('','#475569','#e2e8f0'))
                    flags = ""
                    if o.is_shortener: flags += " [SHORT]"
                    if o.suspicious_tld: flags += " [SUS-TLD]"
                    if o.path_entropy > 4.8: flags += " [HIGH-ENTROPY]"
                    with st.expander(f"{ic} {o.type.upper()}{flags}: {o.defanged[:55]}", expanded=tl in ('CRITICAL','MALICIOUS','SUSPICIOUS')):
                        badge = f"<span style='background:{sb};color:{sf};padding:2px 8px;border-radius:4px;font-size:.78em;font-weight:600;margin-right:8px'>{sl}</span>" if sl else ""
                        vt_lbl = f"<span style='background:{clr};color:#fff;padding:2px 8px;border-radius:4px;font-size:.78em;font-weight:600'>{_esc(tl)}</span>"
                        st.markdown(f"{badge}{vt_lbl} <code style='color:{DC['accent']};margin-left:8px'>{_esc(o.defanged)}</code>", unsafe_allow_html=True)
                        if o.vt.reasoning:
                            if tl in ('CRITICAL','MALICIOUS'): st.error(f"💡 {o.vt.reasoning}")
                            elif tl == 'SUSPICIOUS': st.warning(f"💡 {o.vt.reasoning}")
                            elif tl == 'CLEAN': st.success(f"✅ {o.vt.reasoning}")
                            elif tl == 'UNKNOWN': st.info(f"❓ {o.vt.reasoning} — not in VT database, not confirmed safe")
                            else: st.info(f"💡 {o.vt.reasoning}")
                        if o.vt.domain_intel:
                            di = o.vt.domain_intel
                            if di.typosquat: st.error(f"🚨 {di.typosquat}")
                            parts = []
                            if di.category and di.category != 'unknown': parts.append(f"**{di.category}**")
                            if di.age_days > 0: parts.append(f"{'🆕' if di.age_days<30 else '📅'} {di.age_days}d old")
                            if di.org: parts.append(f"Org: {di.org}")
                            if di.trusted: parts.append("🛡️ Trusted")
                            if parts: st.caption(" | ".join(parts))
            else:
                st.success("✅ No observables extracted")

        # ══════════════════════════════════════════════════════════════════
        # TAB 4: Attachments
        # ══════════════════════════════════════════════════════════════════
        with tabs[3]:
            st.subheader("📎 Attachment Analysis")
            for risk in R.get('attachment_risks',[]):
                if risk['severity']=='CRITICAL': st.error(f"🚨 [{risk['severity']}] {risk['desc']}")
                elif risk['severity']=='HIGH': st.warning(f"⚠️ [{risk['severity']}] {risk['desc']}")
                else: st.info(f"ℹ️ [{risk['severity']}] {risk['desc']}")
            if R.get('attachment_risks'): st.divider()

            for m in R['macros']:
                mc = DC['critical'] if m.risk_score>=70 else (DC['high'] if m.risk_score>=40 else DC['ok'])
                mi = "🔴" if m.risk_score>=70 else ("🟡" if m.risk_score>=40 else "🟢")
                st.markdown(
                    f"<div style='border-left:4px solid {mc};background:{mc}22;padding:14px;"
                    f"margin:10px 0;border-radius:8px'>"
                    f"<h4 style='margin:0 0 6px 0'>{mi} {_esc(m.filename)}</h4>"
                    f"<p style='margin:0;font-size:.9em'><b>Type:</b> {_esc(m.file_type)} | "
                    f"<b>Risk:</b> {m.risk_score}/100 | <b>Verdict:</b> {_esc(m.verdict)}</p>"
                    f"{'<p style=\"margin:4px 0;color:'+DC['text2']+';font-size:.8em\">SHA256: '+_esc(m.sha256)+'</p>' if m.sha256 else ''}"
                    f"{'<p style=\"margin:4px 0;color:'+DC['critical']+';font-weight:700\">☠️ MALWARE: '+_esc(m.mb_family)+'</p>' if m.mb_found else ''}"
                    f"</div>",
                    unsafe_allow_html=True)
                if m.pdf_uris:
                    with st.expander(f"🔗 {len(m.pdf_uris)} embedded URL(s)"):
                        for u in m.pdf_uris: st.code(defang(u))
                if m.details:
                    with st.expander("📋 Analysis Details"):
                        for d in m.details: st.text(d)

            if not R['macros']:
                st.success("✅ No attachments to analyze")

        # ══════════════════════════════════════════════════════════════════
        # TAB 5: YARA
        # ══════════════════════════════════════════════════════════════════
        with tabs[4]:
            st.subheader("🔴 YARA Engine Results")
            hits = [(m.filename, y) for m in R['macros'] for y in m.yara_matches]
            if hits:
                st.markdown(f"**{len(hits)} rule(s) fired across {len(set(f for f,_ in hits))} source(s)**")
                st.divider()
                for fn, y in hits:
                    yc = _tc(y['severity'])
                    st.markdown(
                        f"<div style='border-left:5px solid {yc};background:{yc}15;padding:16px;"
                        f"margin:10px 0;border-radius:8px'>"
                        f"<div style='display:flex;justify-content:space-between;margin-bottom:6px'>"
                        f"<span style='color:{yc};font-weight:700;font-size:1.05em'>🔴 {_esc(y['rule'])}</span>"
                        f"<span style='background:{yc};color:#fff;padding:2px 10px;border-radius:12px;"
                        f"font-size:.82em;font-weight:700'>{_esc(y['severity'])}</span></div>"
                        f"<div style='color:{DC['text1']}'>{_esc(y['desc'])}</div>"
                        f"<div style='color:{DC['text2']};font-size:.85em;margin-top:4px'>"
                        f"📄 {_esc(fn)}</div></div>",
                        unsafe_allow_html=True)
            elif YARA_OK:
                st.success("✅ YARA engine scanned all files — 0 rule matches")
            else:
                st.warning("⚠️ YARA engine offline. Install: `pip install yara-python`")

        # ══════════════════════════════════════════════════════════════════
        # TAB 6: Images
        # ══════════════════════════════════════════════════════════════════
        with tabs[5]:
            st.subheader("🖼️ Image Forensics")
            if R['images']:
                for img in R['images']:
                    has_threat = any('steg' in f.lower() or 'overlay' in f.lower() or 'pattern' in f.lower() for f in img.findings)
                    ic = DC['critical'] if has_threat else (DC['warn'] if img.qr_links else DC['ok'])
                    status = "⚠️ Suspicious" if has_threat else ("📱 QR Detected" if img.qr_links else "✅ Clean")
                    st.markdown(
                        f"<div style='border-left:4px solid {ic};background:{ic}15;padding:14px;margin:8px 0;border-radius:8px'>"
                        f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                        f"<b style='color:{DC['text1']}'>📷 {_esc(img.filename)}</b>"
                        f"<span style='background:{ic};color:#fff;padding:2px 10px;border-radius:10px;font-size:.8em;font-weight:600'>{status}</span>"
                        f"</div>"
                        f"<div style='color:{DC['text2']};font-size:.85em;margin-top:4px'>Format: {_esc(img.fmt)} | Size: {img.size[0]}x{img.size[1]}</div>"
                        f"</div>", unsafe_allow_html=True)
                    ic1, ic2 = st.columns([1, 2])
                    with ic1:
                        if img.data:
                            try: st.image(img.data, use_container_width=True)
                            except: st.caption("(Preview unavailable)")
                    with ic2:
                        for f in img.findings:
                            fl = f.lower()
                            if 'steg' in fl or 'overlay' in fl or 'pattern' in fl:
                                st.error(f"🚨 {f}")
                            elif 'qr' in fl:
                                st.warning(f"⚠️ {f}")
                            elif 'ocr' in fl:
                                st.info(f"🔍 {f}")
                            elif 'clean' in fl or '✅' in f:
                                st.success(f)
                            else:
                                st.info(f"ℹ️ {f}")
                        if img.ocr_text:
                            with st.expander("🔍 OCR Extracted Text"):
                                st.text(img.ocr_text[:500])
                        if img.qr_links:
                            st.markdown("**📱 QR Code Links:**")
                            for ql in img.qr_links:
                                st.code(defang(ql))
                    st.markdown("---")
            else:
                st.success("✅ No images found in this email")

        # ══════════════════════════════════════════════════════════════════
        # TAB 7: All Findings
        # ══════════════════════════════════════════════════════════════════
        with tabs[6]:
            st.subheader("📊 Complete Signal Table")
            if R['signals']:
                df = pd.DataFrame([{
                    'Tier': f"T{s.tier}", 'Category': s.category, 'Signal': s.title,
                    'Probability': f"{s.probability:.0%}", 'Confidence': f"{s.confidence:.0%}",
                    'Impact': f"{s.probability*s.confidence:.0%}", 'Detail': s.detail[:80]
                } for s in sorted(R['signals'], key=lambda x: x.probability*x.confidence, reverse=True)])
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.success("✅ No findings")

            if R['trust_factors']:
                st.subheader("🛡️ Trust Factor Table")
                tdf = pd.DataFrame([{
                    'Factor': tf.name, 'Strength': f"{tf.strength:.0%}",
                    'Confidence': f"{tf.confidence:.0%}", 'Description': tf.description
                } for tf in R['trust_factors']])
                st.dataframe(tdf, use_container_width=True, hide_index=True)

        # ══════════════════════════════════════════════════════════════════
        # TAB 8: Export
        # ══════════════════════════════════════════════════════════════════
        with tabs[7]:
            st.subheader("💾 Export Options")
            ec1, ec2, ec3 = st.columns(3)
            with ec1:
                st.download_button("📥 Download TXT Report", txt,
                                   "sherlock_report.txt", "text/plain")
            with ec2:
                if PDF_REPORT_OK:
                    pdf = generate_pdf_report(txt)
                    if pdf:
                        st.download_button("📥 Download PDF Report", pdf,
                                           "sherlock_report.pdf", "application/pdf")
                else:
                    st.warning("Install reportlab for PDF export")
            with ec3:
                st.download_button("📥 Download JSON Data",
                                   json.dumps(R, default=str, indent=2),
                                   "sherlock_data.json", "application/json")

    except Exception as e:
        st.error(f"❌ Analysis Error: {e}")
        import traceback
        with st.expander("🐛 Debug Traceback"):
            st.code(traceback.format_exc())
        log.error(f"Analysis failed: {traceback.format_exc()}")

if __name__ == "__main__":
    main()
