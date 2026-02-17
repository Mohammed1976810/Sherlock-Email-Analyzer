"""
SHERLOCK - ENTERPRISE FORENSIC EMAIL ANALYZER (ULTIMATE v9.0 - HARDENED & COMPLETE)
====================================================================================

Rebuilt from v8.1 with comprehensive bug fixes, accuracy improvements,
and completeness enhancements.

BUG FIXES APPLIED (from v8.1 audit):
  [CRITICAL] Fixed calculate_entropy - was using float.bit_length() (crashes)
  [CRITICAL] Fixed SecurePatterns staticmethod compatibility (Python <3.10 crash)
  [CRITICAL] Fixed duplicate dead-code loop in analyze_attachment_risks
  [CRITICAL] Removed debug comments left in production code
  [CRITICAL] Fixed safe_regex_search timeout on compiled patterns
  [ACCURACY] Added SPF softfail/temperror/permerror handling
  [ACCURACY] Added DKIM NONE scoring with compounding
  [ACCURACY] Fixed typosquatting with edit-distance detection
  [ACCURACY] Added HTML <a href> link extraction (primary phishing vector)
  [ACCURACY] Added link-text mismatch detection
  [ACCURACY] Capped total_score at 100 to prevent overflow
  [ACCURACY] Expanded VALID_MIME_TYPES, dangerous extensions, double extensions
  [ACCURACY] Added received chain hop analysis
  [ACCURACY] Added CEO/CFO authority claim detection in BEC
  [ACCURACY] Added URL shortener detection
  [ACCURACY] Added suspicious TLD detection
  [ACCURACY] Subject line now included in suspicious language analysis
  [ACCURACY] Fixed marketing platform return-path matching (exact domain match)
  [COMPLETE] Complete text/PDF report with all finding categories
  [CONSIST]  Consistent scoring, error handling, threat level mapping

FEATURES:
  + MalwareBazaar: Hash-match against confirmed malware database
  + AbuseIPDB: Source IP reputation scoring
  + Display Name Spoof Detector with organization context
  + BEC Engine: wire transfer, gift card, CEO impersonation detection
  + Header Anomaly Engine: Reply-To hijack, missing Message-ID, future dates
  + Attachment Risk Matrix: double extensions, dangerous extensions, mismatches
  + Smart Threat Narrative: attack pattern classifier with WHY explanations
  + VT Result Caching (session state)
  + Smart Office YARA Filter
  + PDF Metadata Namespace Filter
  + Office Link Extractor (Deep inspection of .docx/.xlsx/.pptx)
  + Received Chain Hop Analysis
  + Link-Text Mismatch Detection (href vs display text)
  + URL Shortener Detection
  + Suspicious TLD Flagging
  + Tracking Pixel & Hidden Text Detection
  + QR Code Link Extraction from Images

Installation:
  pip install -r requirements.txt

Setup .streamlit/secrets.toml:
  vt_api_key        = "YOUR_VIRUSTOTAL_KEY"
  abuseipdb_key     = "YOUR_ABUSEIPDB_KEY"
  malwarebazaar_key = "YOUR_MB_KEY"
"""

import streamlit as st
import email
import email.policy
import re
import math
import hashlib
import json
import pandas as pd
import requests
import html
import tempfile
import os
import threading
import io
import time
import socket
import logging
import zipfile
import contextlib
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Set
from datetime import datetime
from email.utils import parsedate_to_datetime
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# Use regex library for timeout support (ReDoS protection)
try:
    import regex
    REGEX_TIMEOUT_SUPPORTED = True
except ImportError:
    import re as regex
    REGEX_TIMEOUT_SUPPORTED = False
    logging.warning("regex module not available - using standard re (no timeout protection)")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════


class SecurityLimits:
    """Security and resource limits"""
    MAX_FILE_SIZE_MB = 50
    MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
    MAX_OBSERVABLES = 20
    MAX_FILENAME_LENGTH = 255
    REGEX_TIMEOUT_SECONDS = 2
    DNS_TIMEOUT_SECONDS = 3
    HTTP_TIMEOUT_SECONDS = 10
    MAX_REDIRECT_HOPS = 5
    MAX_PDF_URIS = 100
    MAX_YARA_MATCHES_PER_FILE = 50


class Thresholds:
    """Scoring thresholds"""
    VERDICT_MALICIOUS = 100
    VERDICT_LIKELY_MALICIOUS = 80
    VERDICT_SUSPICIOUS = 50
    VERDICT_REVIEW = 20
    VERDICT_CLEAN = 0

    ABUSE_IP_CRITICAL = 75
    ABUSE_IP_HIGH = 40
    ABUSE_IP_MEDIUM = 10

    # Cloud provider thresholds (higher tolerance)
    ABUSE_IP_CLOUD_CRITICAL = 90
    ABUSE_IP_CLOUD_HIGH = 50


# ═══════════════════════════════════════════════════════════════════════════════
# SECURE PATTERNS (FIX: module-level functions instead of staticmethod in class)
# ═══════════════════════════════════════════════════════════════════════════════

def _compile_pattern(pattern: str, flags=0):
    """Compile regex pattern with optional timeout support.

    Defined at module level to avoid Python <3.10 staticmethod-in-class-body bug.
    """
    if REGEX_TIMEOUT_SUPPORTED:
        try:
            return regex.compile(pattern, flags, timeout=SecurityLimits.REGEX_TIMEOUT_SECONDS)
        except (TypeError, ValueError):
            return regex.compile(pattern, flags)
    return re.compile(pattern, flags)


def _compile_bytes_pattern(pattern: bytes, flags=0):
    """Compile bytes pattern with optional timeout support."""
    if REGEX_TIMEOUT_SUPPORTED:
        try:
            return regex.compile(pattern, flags, timeout=SecurityLimits.REGEX_TIMEOUT_SECONDS)
        except (TypeError, ValueError):
            return regex.compile(pattern, flags)
    return re.compile(pattern, flags)


class SecurePatterns:
    """Compiled regex patterns with timeout support."""

    # Email patterns
    EMAIL_ADDRESS = _compile_pattern(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    DOMAIN_FROM_EMAIL = _compile_pattern(r'@([\w\.-]+)')

    # URL patterns (more restrictive)
    URL_HTTP = _compile_pattern(
        r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:[/?#][^\s<>"\']*)?',
        re.IGNORECASE)

    # HTML href extraction
    HTML_HREF = _compile_pattern(
        r'<a\s[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL)

    # IP patterns
    IPV4_ADDRESS = _compile_pattern(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    # Filename validation
    SAFE_FILENAME = _compile_pattern(r'^[a-zA-Z0-9_\-\.\s]+$')

    # PDF patterns (bytes)
    PDF_URI_SIMPLE = _compile_bytes_pattern(rb'/URI\s*\(([^)]{4,500})\)')
    PDF_URI_NESTED = _compile_bytes_pattern(
        rb'/URI\s*<<[^>]{0,200}?/URI\s*\(([^)]{4,500})\)')
    PDF_URI_HEX = _compile_bytes_pattern(
        rb'/URI\s*<([0-9A-Fa-f\s]{8,1000})>')
    PDF_BARE_URL = _compile_bytes_pattern(
        rb'https?://[^\s\x00<>(){}\[\]"\'\\]{10,300}')

    # Header patterns
    TIMEZONE_PATTERN = _compile_pattern(r'[+-]\d{4}')


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL PATTERN DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

BENIGN_MACRO_PATTERNS = {
    'date_formatting':   ['Format', 'Date', 'Now'],
    'print_dialog':      ['PrintOut', 'PrintPreview', 'PageSetup'],
    'user_interaction':  ['MsgBox', 'InputBox', 'UserForm', 'Button'],
    'formatting':        ['Font.Color', 'Interior.Color', 'Borders',
                          'Select', 'Activate'],
    'data_processing':   ['Range', 'Cells', 'ActiveSheet', 'Copy',
                          'Paste', 'Sort', 'WorksheetFunction'],
}

HIGH_RISK_MACRO_PATTERNS = {
    'network_activity':  ['URLDownloadToFile', 'XMLHTTP',
                          'WinHttpRequest', 'InternetOpen', 'WinInet'],
    'process_execution': ['Shell', 'CreateObject', 'WScript.Shell',
                          'Cmd.exe', 'PowerShell', 'Run', 'CallByName'],
    'file_operations':   ['FileSystemObject', 'Scripting.FileSystemObject',
                          'CreateTextFile', 'SaveAs', 'FileCopy'],
    'registry_access':   ['RegWrite', 'RegRead', 'RegDelete',
                          'WScript.Network'],
    'obfuscation':       ['Chr', 'Asc', 'StrReverse', 'Environ',
                          'Xor', 'Base64', 'Execute'],
}

# ═══════════════════════════════════════════════════════════════════════════════
# LIBRARY IMPORTS & AVAILABILITY FLAGS
# ═══════════════════════════════════════════════════════════════════════════════

PIL_OK = False
try:
    from PIL import Image as PilImage
    from PIL.ExifTags import TAGS
    PIL_OK = True
except Exception as e:
    logger.warning(f"PIL not available: {e}")

DNS_OK = False
try:
    import dns.resolver
    DNS_OK = True
except Exception as e:
    logger.warning(f"DNS resolver not available: {e}")

QR_OK = False
try:
    from pyzbar.pyzbar import decode as decode_qr
    QR_OK = True
except Exception as e:
    logger.warning(f"QR decoder not available: {e}")

OLETOOLS_OK = False
try:
    from oletools.olevba import VBA_Parser
    from oletools.oleid import OleID
    from oletools.mraptor import MacroRaptor
    OLETOOLS_OK = True
except Exception as e:
    logger.warning(f"OleTools not available: {e}")

PYPDF_OK = False
try:
    import PyPDF2
    PYPDF_OK = True
except Exception:
    logger.debug("PyPDF2 not available")

PEEPDF_OK = False
try:
    import peepdf
    from peepdf.PDFCore import PDFParser
    PEEPDF_OK = True
except Exception:
    pass

STEGANO_OK = False
try:
    from stegano import lsb
    STEGANO_OK = True
except Exception as e:
    logger.warning(f"Stegano not available: {e}")

WHOIS_OK = False
try:
    import whois as whois_lib
    WHOIS_OK = True
except Exception as e:
    logger.warning(f"WHOIS not available: {e}")

PDF_OK = False
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    PDF_OK = True
except Exception as e:
    logger.warning(f"ReportLab not available: {e}")

YARA_OK = False
try:
    import yara
    YARA_OK = True
    logger.info("YARA engine available")
except Exception as e:
    logger.warning(f"YARA not available: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
# SECURE UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════


def safe_html_escape(text: Any) -> str:
    """Safely escape HTML, handling None and non-string types."""
    if text is None:
        return ""
    return html.escape(str(text))


def validate_filename(filename: str) -> bool:
    """Validate filename for security."""
    if not filename or len(filename) > SecurityLimits.MAX_FILENAME_LENGTH:
        return False
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    return True


def safe_regex_search(pattern, text: str,
                      timeout: float = SecurityLimits.REGEX_TIMEOUT_SECONDS):
    """Safely execute regex with timeout protection.

    FIX: For compiled patterns, timeout is already baked in at compile time.
    For string patterns, compile with timeout then search.
    """
    try:
        if isinstance(pattern, str):
            if REGEX_TIMEOUT_SUPPORTED:
                compiled = regex.compile(
                    pattern, timeout=timeout)
                return compiled.search(text)
            return re.search(pattern, text)
        # Already compiled pattern -- just search
        return pattern.search(text)
    except Exception as e:
        if 'timeout' in str(e).lower() or 'TimeoutError' in type(e).__name__:
            logger.warning(f"Regex timeout on pattern: {str(pattern)[:50]}")
        else:
            logger.error(f"Regex error: {e}")
        return None


@contextlib.contextmanager
def safe_temp_file(data: bytes, suffix: str = ''):
    """Context manager for secure temporary file handling."""
    tmp_path = None
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp.write(data)
        tmp.close()
        tmp_path = tmp.name
        yield tmp_path
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception as e:
                logger.error(f"Failed to delete temp file {tmp_path}: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# BUILT-IN YARA RULES
# ═══════════════════════════════════════════════════════════════════════════════

YARA_RULES_SOURCE = r"""
rule VBA_Macro_Dropper {
    meta:
        description = "VBA macro with download AND auto-execute capability"
        severity    = "CRITICAL"
        category    = "macro"
    strings:
        $download1 = "URLDownloadToFile" nocase
        $download2 = "XMLHTTP"           nocase
        $download3 = "WinHttpRequest"    nocase
        $exec1     = "AutoOpen"          nocase
        $exec2     = "Document_Open"     nocase
        $exec3     = "Workbook_Open"     nocase
        $shell     = "WScript.Shell"     nocase
    condition:
        ($download1 or $download2 or $download3) and ($exec1 or $exec2 or $exec3 or $shell)
}

rule VBA_Obfuscated_Code {
    meta:
        description = "Heavily obfuscated VBA macro"
        severity    = "HIGH"
        category    = "macro"
    strings:
        $chr  = "Chr("        nocase
        $rev  = "StrReverse(" nocase
        $env  = "Environ("    nocase
        $call = "CallByName(" nocase
        $exec = "Execute("    nocase
        $asc  = "Asc("        nocase
    condition:
        3 of them
}

rule PDF_JavaScript_Exploit {
    meta:
        description = "PDF with JavaScript exploit indicators"
        severity    = "HIGH"
        category    = "pdf"
    strings:
        $js1      = "/JavaScript"
        $js2      = "/JS"
        $eval     = "eval("       nocase
        $unescape = "unescape(" nocase
        $action   = "/OpenAction"
    condition:
        $action and ($js1 or $js2) and ($eval or $unescape)
}

rule PDF_Launch_Action {
    meta:
        description = "PDF with /Launch action"
        severity    = "CRITICAL"
        category    = "pdf"
    strings:
        $s1 = "/Launch"
        $s2 = "/Action"
    condition:
        $s1 and $s2
}

rule Executable_Magic_Bytes {
    meta:
        description = "Executable file embedded"
        severity    = "CRITICAL"
        category    = "executable"
    strings:
        $mz  = { 4D 5A }
        $pe  = "PE\x00\x00"
        $elf = { 7F 45 4C 46 }
    condition:
        ($mz at 0) or ($elf at 0) or $pe
}

rule Archive_Signature {
    meta:
        description = "Compressed archive detected"
        severity    = "MEDIUM"
        category    = "archive"
    strings:
        $zip = { 50 4B 03 04 }
        $rar = { 52 61 72 21 1A 07 }
        $sz  = { 37 7A BC AF 27 1C }
    condition:
        any of them
}

rule Phishing_Credential_Harvest {
    meta:
        description = "HTML form targeting credentials"
        severity    = "HIGH"
        category    = "phishing"
    strings:
        $form      = "<form"                   nocase
        $pass      = "password"                nocase
        $verify    = "verify your account"     nocase
        $suspended = "account suspended"       nocase
        $urgent    = "immediate action required" nocase
    condition:
        $form and (2 of ($pass, $verify, $suspended, $urgent))
}

rule Macro_Registry_Persistence {
    meta:
        description = "Macro accessing registry"
        severity    = "HIGH"
        category    = "macro"
    strings:
        $reg1    = "RegWrite"             nocase
        $reg3    = "HKEY_"                nocase
        $run_key = "CurrentVersion\\Run"  nocase
    condition:
        $reg1 and ($reg3 or $run_key)
}

rule Suspicious_PowerShell_In_Macro {
    meta:
        description = "PowerShell with evasion flags"
        severity    = "CRITICAL"
        category    = "macro"
    strings:
        $ps1      = "PowerShell"              nocase
        $enc      = "-EncodedCommand"         nocase
        $bypass   = "-ExecutionPolicy Bypass" nocase
        $hidden   = "-WindowStyle Hidden"     nocase
        $download = "DownloadString"          nocase
    condition:
        $ps1 and (2 of ($enc, $bypass, $hidden, $download))
}
"""

_COMPILED_YARA_RULES = None
_YARA_COMPILE_LOCK = threading.Lock()


def get_compiled_yara_rules():
    """Thread-safe YARA compilation with caching."""
    global _COMPILED_YARA_RULES
    if _COMPILED_YARA_RULES is not None:
        return _COMPILED_YARA_RULES

    if not YARA_OK:
        return None

    with _YARA_COMPILE_LOCK:
        if _COMPILED_YARA_RULES is not None:
            return _COMPILED_YARA_RULES
        try:
            _COMPILED_YARA_RULES = yara.compile(source=YARA_RULES_SOURCE)
            logger.info("YARA rules compiled successfully")
            return _COMPILED_YARA_RULES
        except Exception as e:
            logger.error(f"YARA compile failed: {e}")
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# DESIGN SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

class DesignSystem:
    COLORS = {
        'critical':       '#ff5555',
        'high':           '#ff9500',
        'medium':         '#f1fa8c',
        'low':            '#50fa7b',
        'safe':           '#50fa7b',
        'clean':          '#50fa7b',
        'unknown':        '#94a3b8',
        'bg_dark':        '#0f172a',
        'bg_card':        '#1e293b',
        'bg_elevated':    '#2d3748',
        'border':         '#334155',
        'accent':         '#38bdf8',
        'accent_purple':  '#8b5cf6',
        'text_primary':   '#e2e8f0',
        'text_secondary': '#94a3b8',
        'success':        '#10b981',
        'warning':        '#f59e0b',
        'error':          '#ef4444',
    }

    SHADOWS = {
        'card':     '0 4px 6px -1px rgba(0, 0, 0, 0.3)',
        'elevated': '0 10px 15px -3px rgba(0, 0, 0, 0.4)',
        'glow':     '0 0 20px rgba(59, 130, 246, 0.3)',
        'strong':   '0 20px 25px -5px rgba(0, 0, 0, 0.5)',
    }

    @staticmethod
    def get_threat_color(threat_level: str) -> str:
        mapping = {
            'CRITICAL':   DesignSystem.COLORS['critical'],
            'MALICIOUS':  DesignSystem.COLORS['critical'],
            'HIGH':       DesignSystem.COLORS['high'],
            'SUSPICIOUS': DesignSystem.COLORS['medium'],
            'MEDIUM':     DesignSystem.COLORS['medium'],
            'LOW':        DesignSystem.COLORS['low'],
            'CLEAN':      DesignSystem.COLORS['safe'],
            'SAFE':       DesignSystem.COLORS['safe'],
            'UNKNOWN':    DesignSystem.COLORS['unknown'],
        }
        return mapping.get(
            (threat_level or 'UNKNOWN').upper(),
            DesignSystem.COLORS['unknown'])

    @staticmethod
    def risk_score_color(score: int) -> str:
        C = DesignSystem.COLORS
        if score >= 70:
            return C['critical']
        if score >= 40:
            return C['high']
        if score >= 15:
            return C['medium']
        return C['success']

    @staticmethod
    def risk_score_icon(score: int) -> str:
        if score >= 70:
            return "🔴"
        if score >= 40:
            return "🟡"
        if score >= 15:
            return "🟠"
        return "🟢"

    @staticmethod
    def badge_text_color(bg_color: str) -> str:
        light_backgrounds = {
            DesignSystem.COLORS['medium'],
            DesignSystem.COLORS['low'],
            DesignSystem.COLORS['safe'],
        }
        return '#000000' if bg_color in light_backgrounds else '#ffffff'

    @staticmethod
    def auth_status_color(status: str) -> str:
        C = DesignSystem.COLORS
        if status == 'PASS':
            return C['success']
        if status in ('FAIL', 'NXDOMAIN'):
            return C['critical']
        if status in ('MISSING', 'SOFTFAIL'):
            return C['warning']
        return C['unknown']


# ═══════════════════════════════════════════════════════════════════════════════
# SCORING WEIGHTS
# ═══════════════════════════════════════════════════════════════════════════════

class ScoringWeights:
    SPF_FAIL              = 60
    SPF_SOFTFAIL          = 30
    SPF_TEMPERROR         = 15
    DMARC_FAIL            = 50
    DKIM_FAIL             = 40
    DKIM_MISSING_WITH_SPF_FAIL = 15
    SHADOW_SPOOFING       = 70
    STEGANOGRAPHY         = 80
    CRITICAL_MACRO        = 100
    HIGH_RISK_MACRO       = 70
    MEDIUM_RISK_MACRO     = 40
    SUSPICIOUS_PDF        = 30
    KNOWN_MARKETING_LINK  = 10
    MALICIOUS_IP          = 90
    TYPOSQUAT             = 50
    YARA_CRITICAL         = 80
    YARA_HIGH             = 50
    YARA_MEDIUM           = 25
    MALWARE_BAZAAR_HIT    = 90
    ABUSEIPDB_HIGH        = 60
    ABUSEIPDB_MEDIUM      = 30
    HEADER_ANOMALY        = 25
    DISPLAY_NAME_SPOOF    = 55
    DOUBLE_EXTENSION      = 50
    CONTENT_TYPE_MISMATCH = 20
    BEC_CRITICAL          = 70
    BEC_HIGH              = 40
    BEC_MEDIUM            = 20
    LINK_TEXT_MISMATCH    = 35
    URL_SHORTENER         = 15
    SUSPICIOUS_TLD        = 20
    HOP_COUNT_ANOMALY     = 15


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class Config:
    try:
        VIRUSTOTAL_API_KEY = st.secrets["vt_api_key"]
    except Exception:
        VIRUSTOTAL_API_KEY = ""

    try:
        ABUSEIPDB_KEY = st.secrets["abuseipdb_key"]
    except Exception:
        ABUSEIPDB_KEY = ""

    try:
        MALWAREBAZAAR_KEY = st.secrets["malwarebazaar_key"]
    except Exception:
        MALWAREBAZAAR_KEY = ""

    MAX_FILE_SIZE_MB = SecurityLimits.MAX_FILE_SIZE_MB
    MAX_OBSERVABLES_TO_CHECK = SecurityLimits.MAX_OBSERVABLES
    VT_RATE_LIMIT_REQUESTS = 4
    VT_RATE_LIMIT_WINDOW = 60
    VT_REQUEST_DELAY = 15


# VT consensus thresholds
VT_CONSENSUS = {'CRITICAL': 5, 'MALICIOUS': 3, 'SUSPICIOUS': 2, 'UNKNOWN': 1}

VT_ENGINE_WEIGHTS = {
    'Google Safebrowsing': 3, 'Microsoft': 3, 'Kaspersky': 3, 'Sophos': 3,
    'ESET': 3, 'Fortinet': 3, 'Symantec': 3, 'BitDefender': 3,
    'McAfee': 2, 'Trend Micro': 2, 'Palo Alto Networks': 2,
}

# Known domains and platforms
GOVERNMENT_TLDS = ['.gov', '.gov.uk', '.gov.au', '.gov.ca', '.mil']
EDUCATIONAL_TLDS = ['.edu', '.ac.uk', '.edu.au']
MAJOR_TECH_DOMAINS = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'github.com', 'linkedin.com', 'twitter.com', 'facebook.com',
]

# FIX: Exact domain match for platforms (no substring)
KNOWN_PLATFORMS = {
    'amazonses.com':  'Amazon SES',
    'sendgrid.net':   'SendGrid',
    'mailchimp.com':  'Mailchimp',
    'mailgun.org':    'Mailgun',
    'outlook.com':    'Microsoft Office 365',
    'mandrillapp.com': 'Mandrill',
    'sparkpostmail.com': 'SparkPost',
    'postmarkapp.com': 'Postmark',
}

# Marketing/transactional email platform domains (for Return-Path matching)
MARKETING_RETURN_PATH_DOMAINS = {
    'amazonses.com', 'sendgrid.net', 'mailchimp.com', 'mailgun.org',
    'mandrillapp.com', 'sparkpostmail.com', 'postmarkapp.com',
    'em.mailchimp.com', 'bounces.google.com',
}

# Cloud providers (STRICT matching)
CLOUD_PROVIDERS_STRICT = {
    'amazon':       ['amazon.com', 'amazonaws.com', 'aws.amazon.com'],
    'google':       ['google.com', 'google.cloud', 'googlemail.com',
                     'googleusercontent.com'],
    'microsoft':    ['microsoft.com', 'azure.com', 'outlook.com',
                     'office365.com', 'office.com'],
    'cloudflare':   ['cloudflare.com', 'cloudflare.net'],
    'digitalocean': ['digitalocean.com'],
    'akamai':       ['akamai.com', 'akamai.net'],
}

# Display name impersonation targets
DISPLAY_NAME_IMPERSONATIONS = [
    'microsoft', 'google', 'apple', 'amazon', 'paypal', 'facebook',
    'netflix', 'docusign', 'adobe', 'helpdesk', 'it support',
    'security team', 'admin', 'support', 'ceo', 'cfo', 'cto',
    'chief executive', 'chief financial', 'managing director',
    'human resources', 'hr department', 'accounts payable',
]

# Expanded dangerous patterns
DOUBLE_EXTENSION_PATTERNS = [
    (r'\.pdf\.exe$',  'PDF hiding EXE'),
    (r'\.doc\.exe$',  'DOC hiding EXE'),
    (r'\.jpg\.exe$',  'JPG hiding EXE'),
    (r'\.png\.exe$',  'PNG hiding EXE'),
    (r'\.pdf\.js$',   'PDF hiding JS'),
    (r'\.doc\.scr$',  'DOC hiding SCR'),
    (r'\.pdf\.bat$',  'PDF hiding BAT'),
    (r'\.jpg\.js$',   'JPG hiding JS'),
    (r'\.xls\.exe$',  'XLS hiding EXE'),
    (r'\.txt\.exe$',  'TXT hiding EXE'),
    (r'\.csv\.exe$',  'CSV hiding EXE'),
    (r'\.pdf\.vbs$',  'PDF hiding VBS'),
    (r'\.doc\.ps1$',  'DOC hiding PS1'),
    (r'\.pdf\.hta$',  'PDF hiding HTA'),
    (r'\.zip\.exe$',  'ZIP hiding EXE'),
    (r'\.pdf\.cmd$',  'PDF hiding CMD'),
    (r'\.docx?\.lnk$', 'DOC hiding LNK'),
]

DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.hta',
    '.pif', '.wsf', '.msi', '.com', '.cpl', '.inf', '.reg', '.lnk',
    '.jar', '.jnlp', '.application', '.gadget', '.msp', '.mst',
    '.ws', '.vbe', '.jse', '.wsc', '.wsh', '.sct', '.url',
]

# Expanded BEC keywords with CEO/CFO authority detection
BEC_KEYWORDS = {
    'wire_transfer': (
        ['wire transfer', 'wire the funds', 'bank transfer',
         'swift transfer', 'iban', 'routing number',
         'account details', 'bank account', 'beneficiary'],
        ScoringWeights.BEC_CRITICAL,
    ),
    'gift_cards': (
        ['gift card', 'itunes card', 'amazon gift', 'google play card',
         'buy cards', 'prepaid card', 'steam card', 'ebay gift'],
        ScoringWeights.BEC_HIGH,
    ),
    'urgency': (
        ['urgent', 'immediately', 'right away', 'asap',
         'time sensitive', 'do this now', 'before end of day',
         'critical deadline', 'must be done today'],
        ScoringWeights.BEC_MEDIUM,
    ),
    'secrecy': (
        ['keep this confidential', 'do not tell', 'between us',
         'keep quiet', 'discreet', 'do not discuss',
         'off the record', 'private matter'],
        ScoringWeights.BEC_HIGH,
    ),
    'authority_claim': (
        ['on behalf of the ceo', 'acting on behalf', 'per the cfo',
         'board has approved', 'executive decision',
         'i am authorizing', 'i authorize you',
         'do not verify', 'skip the approval'],
        ScoringWeights.BEC_HIGH,
    ),
    'payment_redirect': (
        ['new bank details', 'updated payment', 'change the account',
         'new vendor account', 'payment information changed',
         'revised invoice', 'updated invoice'],
        ScoringWeights.BEC_CRITICAL,
    ),
}

# PDF metadata namespaces to filter
PDF_METADATA_NAMESPACES = {
    'ns.adobe.com', 'purl.org/dc', 'w3.org/1999', 'w3.org/2000',
    'schemas.openxmlformats', 'schemas.microsoft.com',
}

SUSPICIOUS_PHRASES = {
    'verify_account': (
        ['verify your account', 'validate your account',
         'click to verify', r'account.*suspended'], 20),
    'password_issue': (
        [r'password.*expire', r'password.*change',
         r'reset.*password', 'password will be deactivated'], 15),
    'mailbox_full': (
        [r'mailbox.*full', r'quota.*exceeded',
         r'limit.*reached', 'storage limit'], 15),
    'generic_threat': (
        ['final notice', 'legal action', 'court appearance',
         'arrest warrant', 'law enforcement', 'failure to comply'], 25),
    'credential_lure': (
        ['click here to verify', 'click the link below',
         'update your information', 'confirm your identity',
         'log in to your account', 'sign in immediately'], 20),
}

KNOWN_LEGIT_MAILERS = [
    'microsoft outlook', 'thunderbird', 'apple mail', 'lotus notes',
    'evolution', 'mutt', 'sendgrid', 'mailchimp', 'postfix', 'exim',
    'sendmail', 'amazon ses', 'mailgun', 'postmark', 'sparkpost',
    'google workspace', 'gmail', 'yahoo mail',
]

# URL shortener domains
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'rebrand.ly', 'bl.ink', 'short.io', 'cutt.ly',
    'rb.gy', 'snip.ly', 'shorturl.at', 'tiny.cc', 'surl.li',
    'v.gd', 'qr.ae', 'adf.ly', 'bc.vc', 'shorte.st',
}

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.work', '.buzz', '.surf', '.rest',
    '.icu', '.cam', '.monster', '.cyou', '.cfd', '.sbs',
    '.click', '.link', '.gq', '.ml', '.cf', '.ga', '.tk',
    '.pw', '.cc', '.ws', '.bid', '.loan', '.trade', '.racing',
    '.review', '.cricket', '.win', '.party', '.science',
    '.download', '.stream', '.accountant', '.date', '.faith',
}

# Expanded MIME type validation map
VALID_MIME_TYPES = {
    'pdf':  ['application/pdf', 'application/x-pdf'],
    'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document',
             'application/zip'],
    'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
             'application/zip'],
    'pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation',
             'application/zip'],
    'doc':  ['application/msword', 'application/vnd.ms-word'],
    'xls':  ['application/vnd.ms-excel'],
    'ppt':  ['application/vnd.ms-powerpoint'],
    'zip':  ['application/zip', 'application/x-zip-compressed',
             'application/octet-stream'],
    'rar':  ['application/x-rar-compressed', 'application/vnd.rar',
             'application/octet-stream'],
    '7z':   ['application/x-7z-compressed', 'application/octet-stream'],
    'png':  ['image/png'],
    'jpg':  ['image/jpeg', 'image/jpg'],
    'jpeg': ['image/jpeg', 'image/jpg'],
    'gif':  ['image/gif'],
    'bmp':  ['image/bmp', 'image/x-bmp'],
    'txt':  ['text/plain'],
    'csv':  ['text/csv', 'text/plain', 'application/csv'],
    'html': ['text/html'],
    'rtf':  ['application/rtf', 'text/rtf'],
    'msg':  ['application/vnd.ms-outlook'],
    'eml':  ['message/rfc822'],
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class YaraMatch:
    rule_name: str
    severity: str
    description: str
    category: str
    matched_strings: List[str] = field(default_factory=list)


@dataclass
class BECResult:
    score: int = 0
    risk_level: str = "NONE"
    triggered_categories: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class DisplayNameSpoofResult:
    detected: bool = False
    display_name: str = ""
    sender_domain: str = ""
    impersonated_brand: str = ""
    findings: List[str] = field(default_factory=list)
    score: int = 0


@dataclass
class AttachmentRiskItem:
    filename: str
    risk_type: str
    description: str
    score: int
    severity: str


@dataclass
class AbuseIPResult:
    checked: bool = False
    abuse_score: int = 0
    total_reports: int = 0
    country: str = ""
    isp: str = ""
    threat_level: str = "UNKNOWN"
    is_tor: bool = False
    findings: List[str] = field(default_factory=list)


@dataclass
class HeaderAnomalyResult:
    anomalies: List[str] = field(default_factory=list)
    score: int = 0
    reply_to_hijack: bool = False


@dataclass
class MalwareBazaarResult:
    filename: str = ""
    found: bool = False
    malware_family: str = ""
    tags: List[str] = field(default_factory=list)
    first_seen: str = ""
    threat_level: str = "UNKNOWN"


@dataclass
class DomainIntelligence:
    domain: str
    category: str = "unknown"
    trusted: bool = False
    score_modifier: int = 0
    reasoning: str = ""
    whois_org: str = ""
    whois_country: str = ""
    domain_age_days: int = 0
    registrar: str = ""
    is_government: bool = False
    is_educational: bool = False
    is_commercial: bool = False
    platform_info: str = ""
    typosquat_warning: str = ""


@dataclass
class VTResult:
    success: bool = False
    total_engines: int = 0
    raw_malicious: int = 0
    weighted_malicious: float = 0.0
    malicious_engines: List[str] = field(default_factory=list)
    threat_level: str = "UNKNOWN"
    reasoning: str = ""
    detailed_reasoning: List[str] = field(default_factory=list)
    error: str = ""
    is_new_url: bool = False
    domain_intel: Optional[DomainIntelligence] = None


@dataclass
class AuthResult:
    spf: str = "NONE"
    dkim: str = "NONE"
    dmarc: str = "NONE"
    score: int = 0
    source_ip: str = ""
    shadow_spoofing: bool = False
    from_domain: str = ""
    return_path_domain: str = ""
    from_full: str = ""
    return_path_full: str = ""
    findings: List[str] = field(default_factory=list)
    detailed_analysis: List[str] = field(default_factory=list)
    gateway_trust: bool = False
    gateway_name: str = ""
    live_dns_spf: Dict = field(default_factory=dict)
    live_dns_dmarc: Dict = field(default_factory=dict)
    live_dns_verified: bool = False
    return_path_match: bool = False
    hop_count: int = 0
    hop_anomaly: str = ""


@dataclass
class MacroContext:
    has_benign: bool = False
    benign_patterns: List[str] = field(default_factory=list)
    has_risky: bool = False
    risky_patterns: List[str] = field(default_factory=list)
    auto_execute: List[str] = field(default_factory=list)
    entropy_score: float = 0.0
    risk_score: int = 0
    verdict: str = ""
    reasoning: List[str] = field(default_factory=list)
    detailed_analysis: List[str] = field(default_factory=list)


@dataclass
class MacroResult:
    filename: str
    file_type: str = "Unknown"
    has_macros: bool = False
    context: Optional[MacroContext] = None
    risk_score: int = 0
    verdict: str = ""
    details: List[str] = field(default_factory=list)
    yara_matches: List[YaraMatch] = field(default_factory=list)
    pdf_uris: List[str] = field(default_factory=list)
    malware_bazaar: Optional[MalwareBazaarResult] = None
    file_md5: str = ""
    file_sha256: str = ""


@dataclass
class ImageAnalysis:
    filename: str
    format: str = ""
    size: Tuple[int, int] = (0, 0)
    has_steganography: bool = False
    findings: List[str] = field(default_factory=list)
    image_data: Optional[bytes] = None
    qr_links: List[str] = field(default_factory=list)


@dataclass
class Observable:
    type: str
    value: str
    defanged: str
    source: str
    vt_result: Optional[VTResult] = None
    reputation: str = "unknown"
    threat_score: int = 0
    is_marketing: bool = False
    is_shortener: bool = False
    suspicious_tld: bool = False


@dataclass
class LinkTextMismatch:
    href: str
    display_text: str
    href_domain: str
    display_domain: str
    severity: str = "HIGH"


@dataclass
class ReceivedHopInfo:
    hop_number: int
    from_server: str
    by_server: str
    timestamp: str = ""
    ip: str = ""


@dataclass
class ThreatNarrative:
    attack_pattern: str = "clean"
    attack_label: str = "✅ Likely Legitimate"
    attack_description: str = ""
    key_signals: List[Dict] = field(default_factory=list)
    correlated_findings: List[str] = field(default_factory=list)
    mitigating_factors: List[str] = field(default_factory=list)
    score_breakdown: List[Dict] = field(default_factory=list)
    analyst_notes: List[str] = field(default_factory=list)
    verdict_explanation: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# THREAD-SAFE VT CACHE
# ═══════════════════════════════════════════════════════════════════════════════

class ThreadSafeCache:
    """Thread-safe cache for VT results."""

    def __init__(self):
        self._cache: Dict[str, VTResult] = {}
        self._lock = threading.Lock()
        self._max_size = 1000

    def get(self, key: str) -> Optional[VTResult]:
        cache_key = hashlib.sha256(key.encode()).hexdigest()
        with self._lock:
            return self._cache.get(cache_key)

    def set(self, key: str, value: VTResult):
        cache_key = hashlib.sha256(key.encode()).hexdigest()
        with self._lock:
            if len(self._cache) >= self._max_size:
                keys_to_remove = list(self._cache.keys())[
                    :self._max_size // 5]
                for k in keys_to_remove:
                    del self._cache[k]
            self._cache[cache_key] = value

    def clear(self):
        with self._lock:
            self._cache.clear()


def get_vt_cache() -> ThreadSafeCache:
    """Get thread-safe VT cache."""
    if 'vt_cache_safe' not in st.session_state:
        st.session_state.vt_cache_safe = ThreadSafeCache()
    return st.session_state.vt_cache_safe


# ═══════════════════════════════════════════════════════════════════════════════
# YARA ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def yara_scan_bytes(data: bytes, filename: str = "") -> List[YaraMatch]:
    """Scan bytes with YARA rules."""
    matches = []
    rules = get_compiled_yara_rules()
    if not rules or not data:
        return matches

    max_yara_size = 10 * 1024 * 1024
    if len(data) > max_yara_size:
        logger.warning(
            f"File {filename} too large for YARA ({len(data)} bytes)")
        data = data[:max_yara_size]

    try:
        yara_hits = rules.match(data=data)
        for hit in yara_hits[:SecurityLimits.MAX_YARA_MATCHES_PER_FILE]:
            severity = hit.meta.get('severity', 'MEDIUM')
            description = hit.meta.get('description', hit.rule)
            category = hit.meta.get('category', 'unknown')
            matched_strings = []

            for string_match in hit.strings:
                for instance in string_match.instances:
                    try:
                        decoded = instance.matched_data.decode(
                            'utf-8', errors='replace')[:50]
                        matched_strings.append(decoded)
                    except Exception:
                        pass

            matches.append(YaraMatch(
                rule_name=hit.rule,
                severity=severity,
                description=description,
                category=category,
                matched_strings=list(set(matched_strings))[:5],
            ))

        if matches:
            logger.info(
                f"YARA: {len(matches)} rule(s) matched in '{filename}'")
    except Exception as e:
        logger.error(f"YARA scan error on '{filename}': {e}")

    return matches


def yara_score_from_matches(matches: List[YaraMatch]) -> int:
    """Calculate risk score from YARA matches."""
    score = 0
    for match in matches:
        sev = match.severity.upper()
        if sev == 'CRITICAL':
            score += ScoringWeights.YARA_CRITICAL
        elif sev == 'HIGH':
            score += ScoringWeights.YARA_HIGH
        elif sev == 'MEDIUM':
            score += ScoringWeights.YARA_MEDIUM
    return min(score, 100)


# ═══════════════════════════════════════════════════════════════════════════════
# PDF FORENSICS
# ═══════════════════════════════════════════════════════════════════════════════

def is_pdf_metadata_uri(uri: str) -> bool:
    """Check if URI is PDF/XML metadata namespace."""
    try:
        parsed = urlparse(uri)
        host = parsed.netloc.lower().lstrip('www.')
        path = parsed.path.lower()

        for ns in PDF_METADATA_NAMESPACES:
            if ns in host or ns in f"{host}{path}":
                return True

        if re.match(r'^/\d{4}/', path) and '#' in uri:
            return True
    except Exception:
        pass
    return False


def extract_pdf_uris(pdf_data: bytes) -> List[str]:
    """Extract URIs from PDF with ReDoS protection."""
    found_uris: Set[str] = set()

    max_pdf_search = 5 * 1024 * 1024
    if len(pdf_data) > max_pdf_search:
        logger.warning("PDF too large for full URI extraction")
        pdf_data = pdf_data[:max_pdf_search]

    try:
        for m in SecurePatterns.PDF_URI_SIMPLE.finditer(pdf_data):
            try:
                raw = m.group(1).decode('latin-1', errors='ignore').strip()
                raw = raw.replace('\x00', '').replace(
                    '\r', '').replace('\n', '')
                if raw.startswith(('http', 'ftp')):
                    found_uris.add(raw)
            except Exception:
                pass

        for m in SecurePatterns.PDF_URI_NESTED.finditer(pdf_data):
            try:
                raw = m.group(1).decode('latin-1', errors='ignore').strip()
                raw = raw.replace('\x00', '').replace(
                    '\r', '').replace('\n', '')
                if raw.startswith(('http', 'ftp')):
                    found_uris.add(raw)
            except Exception:
                pass

        for m in SecurePatterns.PDF_BARE_URL.finditer(pdf_data):
            try:
                raw = m.group(0).decode('latin-1', errors='ignore').strip()
                raw = re.sub(r'[/>\)\]]+$', '', raw)
                if len(raw) >= 10 and '.' in raw:
                    found_uris.add(raw)
            except Exception:
                pass

    except Exception as e:
        if 'timeout' in str(e).lower():
            logger.error("PDF URI extraction timed out")
        else:
            logger.error(f"PDF URI extraction error: {e}")
        return []

    clean_uris = []
    for uri in list(found_uris)[:SecurityLimits.MAX_PDF_URIS]:
        cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', uri).strip()
        if len(cleaned) >= 8 and not is_pdf_metadata_uri(cleaned):
            clean_uris.append(cleaned)

    return clean_uris


def sanitize_uri_for_display(uri: str) -> str:
    """Defang URI for display."""
    return defang(uri)


# ═══════════════════════════════════════════════════════════════════════════════
# OFFICE LINK EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

def extract_office_uris(file_data: bytes) -> List[str]:
    """Extract links from Office files (.docx, .xlsx, .pptx)."""
    uris: Set[str] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(file_data)) as z:
            for name in z.namelist():
                if name.endswith('.rels'):
                    try:
                        content = z.read(name).decode(
                            'utf-8', errors='ignore')
                        links = re.findall(
                            r'Target=["\']((?:http|https|ftp):[^"\']+)["\']',
                            content, re.I)
                        for link in links:
                            if ("schemas.openxmlformats" not in link
                                    and "schemas.microsoft" not in link):
                                uris.add(html.unescape(link))
                    except Exception:
                        pass
    except Exception:
        pass

    return list(uris)[:SecurityLimits.MAX_PDF_URIS]


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def get_root_domain(domain: str) -> str:
    """Extract root domain."""
    parts = domain.lower().split('.')
    cc_tlds = ['co.uk', 'gov.uk', 'ac.uk', 'com.au', 'gov.au',
               'co.nz', 'co.za', 'co.in', 'com.br']
    for cctld in cc_tlds:
        if domain.endswith('.' + cctld):
            parts_needed = len(cctld.split('.')) + 1
            return '.'.join(parts[-parts_needed:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def defang(value: str) -> str:
    """Defang URL/domain for safe display."""
    if not isinstance(value, str):
        return str(value)
    d = value.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
    d = d.replace('.', '[.]')
    return safe_html_escape(d)


def calculate_entropy(data) -> float:
    """Calculate Shannon entropy.

    FIX: v8.1 used float.bit_length() which raises AttributeError.
    Correctly uses math.log2 now.
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        data_bytes = data.encode('utf-8', errors='ignore')
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        return 0.0

    if len(data_bytes) == 0:
        return 0.0

    counter = Counter(data_bytes)
    length = len(data_bytes)

    entropy = 0.0
    for count in counter.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return entropy


def get_threat_icon(threat_level: str) -> str:
    """Get icon for threat level."""
    icons = {
        'CRITICAL': '🚨', 'MALICIOUS': '🚨', 'HIGH': '⚠️',
        'SUSPICIOUS': '⚠️', 'MEDIUM': '⚠️', 'LOW': '📋',
        'CLEAN': '✅', 'SAFE': '✅', 'UNKNOWN': '❓',
    }
    return icons.get((threat_level or '').upper(), '❓')


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


# Homoglyph map for common confusable characters
_HOMOGLYPHS = {
    '0': 'o', '1': 'l', 'l': 'i', 'rn': 'm',
    'vv': 'w', 'cl': 'd', 'nn': 'm',
}


def check_typosquatting(domain: str) -> Optional[str]:
    """Check for typosquatting using edit distance and homoglyph detection.

    FIX: v8.1 had a basic substring check and unused suspicious_chars list.
    Now uses Levenshtein distance and homoglyph detection.
    """
    domain = domain.lower()
    root = get_root_domain(domain).split('.')[0]

    # IDN homograph detection
    if 'xn--' in domain:
        return "⚠️ IDN HOMOGRAPH: Punycode domain detected — may visually mimic a trusted domain"

    major_brands = {
        'microsoft': 'microsoft.com',
        'google':    'google.com',
        'apple':     'apple.com',
        'amazon':    'amazon.com',
        'paypal':    'paypal.com',
        'facebook':  'facebook.com',
        'netflix':   'netflix.com',
        'linkedin':  'linkedin.com',
        'dropbox':   'dropbox.com',
        'docusign':  'docusign.com',
        'adobe':     'adobe.com',
        'github':    'github.com',
        'twitter':   'twitter.com',
        'instagram': 'instagram.com',
        'outlook':   'outlook.com',
        'yahoo':     'yahoo.com',
        'chase':     'chase.com',
        'wellsfargo': 'wellsfargo.com',
        'bankofamerica': 'bankofamerica.com',
    }

    for brand_name, brand_domain in major_brands.items():
        brand_root = brand_domain.split('.')[0]

        # Exact match is legitimate
        if root == brand_root:
            continue

        # Edit distance check (catch transpositions, insertions, deletions)
        dist = _levenshtein_distance(root, brand_root)
        if 0 < dist <= 2 and len(root) >= 4:
            return (f"⚠️ TYPOSQUAT: '{domain}' is {dist} edit(s) from "
                    f"'{brand_domain}' — likely impersonation")

        # Homoglyph substitution check
        normalized = root
        for fake, real in _HOMOGLYPHS.items():
            normalized = normalized.replace(fake, real)
        if normalized == brand_root and root != brand_root:
            return (f"⚠️ HOMOGLYPH: '{domain}' uses look-alike characters "
                    f"to mimic '{brand_domain}'")

        # Brand name embedded in subdomain
        if brand_name in domain and domain != brand_domain:
            brand_root_in_domain = get_root_domain(domain)
            if brand_root not in brand_root_in_domain:
                return (f"⚠️ BRAND ABUSE: '{domain}' embeds '{brand_name}' "
                        f"but root domain is '{brand_root_in_domain}'")

    return None


def get_public_source_ip(msg) -> Optional[str]:
    """Extract true source IP from headers."""
    private_ranges = [
        re.compile(r'^10\.'),
        re.compile(r'^192\.168\.'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
        re.compile(r'^127\.'),
        re.compile(r'^0\.'),
        re.compile(r'^169\.254\.'),
    ]

    received_headers = msg.get_all('Received', [])
    if received_headers:
        received_headers = list(reversed(received_headers))

    for header in received_headers:
        try:
            ips = SecurePatterns.IPV4_ADDRESS.findall(str(header))
            for ip in ips:
                if not any(r.match(ip) for r in private_ranges):
                    return ip
        except Exception:
            continue

    return None


def analyze_received_chain(msg) -> Tuple[int, List[ReceivedHopInfo], str]:
    """Analyze Received header chain for hop count and anomalies.

    NEW: Detects abnormal hop counts and timing gaps.
    """
    received_headers = msg.get_all('Received', []) or []
    hop_count = len(received_headers)
    hops: List[ReceivedHopInfo] = []
    anomaly = ""

    for i, header in enumerate(reversed(received_headers)):
        header_str = str(header)
        hop = ReceivedHopInfo(hop_number=i + 1, from_server="", by_server="")

        from_match = re.search(r'from\s+(\S+)', header_str, re.I)
        by_match = re.search(r'by\s+(\S+)', header_str, re.I)
        if from_match:
            hop.from_server = from_match.group(1)[:60]
        if by_match:
            hop.by_server = by_match.group(1)[:60]

        ip_match = SecurePatterns.IPV4_ADDRESS.search(header_str)
        if ip_match:
            hop.ip = ip_match.group(0)

        hops.append(hop)

    # Detect anomalies
    if hop_count == 0:
        anomaly = "⚠️ No Received headers — email may be locally crafted"
    elif hop_count == 1:
        anomaly = "⚠️ Single hop — unusual for internet email delivery"
    elif hop_count > 15:
        anomaly = (f"⚠️ Excessive hops ({hop_count}) — "
                   "possible routing manipulation or mail loop")

    return hop_count, hops, anomaly


def analyze_infrastructure(msg) -> Tuple[bool, str, List[str]]:
    """Check for trusted email gateways."""
    trusted = False
    gateway = ""
    notes = []

    if 'X-Mimecast-Spam-Score' in msg:
        try:
            score = int(msg.get('X-Mimecast-Spam-Score', '100'))
            if score <= 1:
                trusted = True
                gateway = "Mimecast"
                notes.append("Routed via Mimecast (Clean)")
        except Exception:
            pass

    if 'X-IronPort-AV' in msg:
        trusted = True
        gateway = "Cisco IronPort"
        notes.append("Scanned by Cisco IronPort")

    if 'x-forefront-antispam-report' in msg:
        report_hdr = str(msg.get('x-forefront-antispam-report', ''))
        scl_match = re.search(r'SCL:(\d+)', report_hdr)
        if scl_match:
            scl = int(scl_match.group(1))
            if scl <= 1:
                trusted = True
                gateway = gateway or "Microsoft Office 365"
                notes.append(f"Microsoft SCL: {scl} (Clean)")

    if 'X-Barracuda-Spam-Score' in msg:
        try:
            score = float(msg.get('X-Barracuda-Spam-Score', '10'))
            if score <= 1.0:
                trusted = True
                gateway = gateway or "Barracuda"
                notes.append(f"Barracuda score: {score} (Clean)")
        except Exception:
            pass

    if 'X-Proofpoint-Spam-Details' in msg:
        trusted = True
        gateway = gateway or "Proofpoint"
        notes.append("Scanned by Proofpoint")

    return trusted, gateway, notes


def is_url_shortener(url: str) -> bool:
    """Check if URL uses a known shortener service."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().lstrip('www.')
        return domain in URL_SHORTENERS
    except Exception:
        return False


def has_suspicious_tld(domain: str) -> bool:
    """Check if domain uses a frequently-abused TLD."""
    domain_lower = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return True
    return False


def detect_link_text_mismatches(html_body: str) -> List[LinkTextMismatch]:
    """Detect <a href="evil.com">bank.com</a> style mismatches.

    NEW: Primary phishing detection mechanism.
    """
    mismatches = []
    if not html_body:
        return mismatches

    try:
        for match in SecurePatterns.HTML_HREF.finditer(html_body):
            href = match.group(1).strip()
            display_raw = match.group(2).strip()

            # Strip HTML tags from display text
            display_text = re.sub(r'<[^>]+>', '', display_raw).strip()

            if not href.startswith(('http://', 'https://')):
                continue
            if not display_text:
                continue

            try:
                href_domain = urlparse(href).netloc.lower().lstrip('www.')
            except Exception:
                continue

            # Check if display text looks like a URL/domain
            display_domain_match = re.search(
                r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                display_text)
            if not display_domain_match:
                continue

            display_domain = display_domain_match.group(1).lower().lstrip(
                'www.')

            # Compare root domains
            href_root = get_root_domain(href_domain)
            display_root = get_root_domain(display_domain)

            if href_root != display_root:
                mismatches.append(LinkTextMismatch(
                    href=href,
                    display_text=display_text[:100],
                    href_domain=href_domain,
                    display_domain=display_domain,
                    severity="HIGH",
                ))

    except Exception as e:
        logger.error(f"Link-text mismatch detection error: {e}")

    return mismatches[:20]


# ═══════════════════════════════════════════════════════════════════════════════
# DOMAIN INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

def verify_domain_with_whois(domain: str) -> DomainIntelligence:
    """Verify domain with WHOIS."""
    intel = DomainIntelligence(domain=domain)

    typo_warning = check_typosquatting(domain)
    if typo_warning:
        intel.typosquat_warning = typo_warning
        intel.score_modifier = 40
        intel.reasoning = typo_warning
        intel.category = 'suspicious_typo'

    for tld in GOVERNMENT_TLDS:
        if domain.lower().endswith(tld):
            intel.category = 'government'
            intel.trusted = True
            intel.is_government = True
            intel.score_modifier = -30
            intel.reasoning = f'Government domain ({tld})'
            return intel

    for tld in EDUCATIONAL_TLDS:
        if domain.lower().endswith(tld):
            intel.category = 'educational'
            intel.trusted = True
            intel.is_educational = True
            intel.score_modifier = -20
            intel.reasoning = f'Educational institution ({tld})'
            return intel

    for platform_domain, desc in KNOWN_PLATFORMS.items():
        if domain.lower() == platform_domain or domain.lower().endswith(
                '.' + platform_domain):
            intel.category = 'email_platform'
            intel.trusted = True
            intel.score_modifier = -15
            intel.platform_info = desc
            intel.reasoning = f'Known platform: {desc}'
            return intel

    for tech_domain in MAJOR_TECH_DOMAINS:
        if domain.lower() == tech_domain or domain.lower().endswith(
                '.' + tech_domain):
            intel.category = 'major_tech'
            intel.trusted = True
            intel.score_modifier = -25
            intel.reasoning = f'Major tech company ({tech_domain})'
            return intel

    if WHOIS_OK:
        try:
            socket.setdefaulttimeout(SecurityLimits.DNS_TIMEOUT_SECONDS)
            whois_data = whois_lib.whois(get_root_domain(domain))

            if whois_data.org:
                intel.whois_org = str(
                    whois_data.org[0] if isinstance(
                        whois_data.org, list) else whois_data.org)

            if whois_data.creation_date:
                creation = whois_data.creation_date
                if isinstance(creation, list):
                    creation = creation[0]

                if isinstance(creation, datetime):
                    age = (datetime.now() - creation).days
                    intel.domain_age_days = age

                    if age < 30:
                        intel.reasoning = (
                            f"Recently registered ({age}d) — higher risk")
                        intel.score_modifier = max(
                            intel.score_modifier, 30)
                    elif age > 365:
                        intel.reasoning = (
                            f"Established domain ({age}d old)")
                        intel.score_modifier = min(
                            intel.score_modifier, -5)

            if intel.whois_org:
                org_lower = intel.whois_org.lower()
                if any(kw in org_lower for kw in [
                        'government', 'ministry', 'gov', 'federal']):
                    intel.category = 'government'
                    intel.trusted = True
                    intel.score_modifier = -20
                    intel.reasoning = f"Gov org: {intel.whois_org}"
                elif any(kw in org_lower for kw in [
                        'university', 'college', 'education']):
                    intel.category = 'educational'
                    intel.trusted = True
                    intel.score_modifier = -15
                    intel.reasoning = f"Edu org: {intel.whois_org}"
                else:
                    intel.category = 'commercial'
                    intel.is_commercial = True
                    if not intel.reasoning:
                        intel.reasoning = (
                            f"Registered to: {intel.whois_org}")

        except Exception as e:
            logger.debug(f"WHOIS failed for {domain}: {e}")
            try:
                socket.setdefaulttimeout(
                    SecurityLimits.DNS_TIMEOUT_SECONDS)
                socket.gethostbyname(domain)
                intel.reasoning = "Active domain (WHOIS unavailable)"
                intel.category = 'verified_active'
            except Exception:
                intel.reasoning = "Cannot verify domain"
                intel.score_modifier = 15
    else:
        try:
            socket.setdefaulttimeout(SecurityLimits.DNS_TIMEOUT_SECONDS)
            socket.gethostbyname(domain)
            intel.reasoning = "Active domain"
        except Exception:
            intel.reasoning = "Cannot verify domain"
            intel.score_modifier = 15

    return intel


# ═══════════════════════════════════════════════════════════════════════════════
# VT RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════════

class VTRateLimiter:
    """Thread-safe rate limiter for VT."""

    def __init__(self):
        self.last_request_time = 0.0
        self.request_count = 0
        self.minute_start = time.time()
        self.lock = threading.Lock()

    def wait_if_needed(self):
        with self.lock:
            current_time = time.time()

            if current_time - self.minute_start > Config.VT_RATE_LIMIT_WINDOW:
                self.request_count = 0
                self.minute_start = current_time

            if self.request_count >= Config.VT_RATE_LIMIT_REQUESTS:
                sleep_time = (Config.VT_RATE_LIMIT_WINDOW
                              - (current_time - self.minute_start))
                if sleep_time > 0:
                    time.sleep(sleep_time + 1)
                self.request_count = 0
                self.minute_start = time.time()

            elapsed = current_time - self.last_request_time
            if elapsed < Config.VT_REQUEST_DELAY and self.request_count > 0:
                time.sleep(Config.VT_REQUEST_DELAY - elapsed)

            self.last_request_time = time.time()
            self.request_count += 1


@st.cache_resource
def get_vt_limiter():
    return VTRateLimiter()


vt_limiter = get_vt_limiter()

# ═══════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════


def analyze_vt_consensus(stats: Dict, detailed_results: Dict = None,
                         is_404: bool = False,
                         domain: str = "") -> VTResult:
    """Analyze VT consensus."""
    result = VTResult()

    if domain:
        result.domain_intel = verify_domain_with_whois(domain)

    if is_404:
        result.success = True
        result.is_new_url = True
        if result.domain_intel and result.domain_intel.trusted:
            result.threat_level = "CLEAN"
            result.reasoning = (
                f"New URL, trusted domain: "
                f"{result.domain_intel.reasoning}")
        else:
            result.threat_level = "UNKNOWN"
            result.reasoning = "Not in VirusTotal database"
        return result

    result.total_engines = sum(stats.values())
    result.raw_malicious = stats.get('malicious', 0)
    result.success = True

    if detailed_results:
        for engine, data in detailed_results.items():
            if data.get('category') == 'malicious':
                result.malicious_engines.append(engine)

    weighted_count = 0.0
    tier1_count = 0
    tier1_engines = []

    for engine in result.malicious_engines:
        weight = VT_ENGINE_WEIGHTS.get(engine, 1.0)
        weighted_count += weight
        if weight >= 3:
            tier1_count += 1
            tier1_engines.append(engine)

    result.weighted_malicious = weighted_count

    if result.raw_malicious == 0:
        result.threat_level = "CLEAN"
        result.reasoning = (
            f"Clean — {stats.get('harmless', 0)} engines verified safe")
    elif tier1_count >= 2:
        result.threat_level = "CRITICAL"
        result.reasoning = (
            f"CRITICAL: {tier1_count} major vendors flagged")
    elif weighted_count >= VT_CONSENSUS['CRITICAL']:
        result.threat_level = "CRITICAL"
        result.reasoning = (
            f"Consensus: {result.raw_malicious} engines")
    elif result.raw_malicious >= VT_CONSENSUS['MALICIOUS']:
        result.threat_level = "MALICIOUS"
        result.reasoning = f"{result.raw_malicious} engines flagged"
    elif result.raw_malicious >= VT_CONSENSUS['SUSPICIOUS']:
        result.threat_level = "SUSPICIOUS"
        result.reasoning = f"{result.raw_malicious} engines flagged"
    else:
        result.threat_level = "UNKNOWN"
        result.reasoning = "Single engine flagged"

    return result


def check_vt_url(url: str) -> VTResult:
    """Check URL with VirusTotal."""
    cache = get_vt_cache()
    cached = cache.get(f"url:{url}")
    if cached:
        return cached

    if not Config.VIRUSTOTAL_API_KEY:
        return VTResult(success=False, error="No API Key")

    try:
        vt_limiter.wait_if_needed()
        domain = urlparse(url).netloc
        url_id = hashlib.sha256(url.encode()).hexdigest()
        headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=SecurityLimits.HTTP_TIMEOUT_SECONDS)

        if response.status_code == 200:
            data = response.json()
            attrs = data.get('data', {}).get('attributes', {})
            result = analyze_vt_consensus(
                attrs.get('last_analysis_stats', {}),
                attrs.get('last_analysis_results', {}),
                False, domain)
        elif response.status_code == 404:
            result = analyze_vt_consensus({}, {}, True, domain)
        else:
            result = VTResult(
                success=False, error=f"HTTP {response.status_code}")

        cache.set(f"url:{url}", result)
        return result

    except Exception as e:
        logger.error(f"VT URL check failed: {e}")
        return VTResult(success=False, error=str(e)[:100])


def check_vt_domain(domain: str) -> VTResult:
    """Check domain with VirusTotal."""
    cache = get_vt_cache()
    cached = cache.get(f"domain:{domain}")
    if cached:
        return cached

    if not Config.VIRUSTOTAL_API_KEY:
        return VTResult(success=False, error="No API Key")

    try:
        vt_limiter.wait_if_needed()
        headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}

        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers,
            timeout=SecurityLimits.HTTP_TIMEOUT_SECONDS)

        if response.status_code == 200:
            data = response.json()
            attrs = data.get('data', {}).get('attributes', {})
            result = analyze_vt_consensus(
                attrs.get('last_analysis_stats', {}),
                attrs.get('last_analysis_results', {}),
                False, domain)
        elif response.status_code == 404:
            result = analyze_vt_consensus({}, {}, True, domain)
        else:
            result = VTResult(
                success=False, error=f"HTTP {response.status_code}")

        cache.set(f"domain:{domain}", result)
        return result

    except Exception as e:
        logger.error(f"VT domain check failed: {e}")
        return VTResult(success=False, error=str(e)[:100])


def check_vt_ip(ip: str) -> VTResult:
    """Check IP with VirusTotal."""
    cache = get_vt_cache()
    cached = cache.get(f"ip:{ip}")
    if cached:
        return cached

    if not Config.VIRUSTOTAL_API_KEY:
        try:
            socket.setdefaulttimeout(SecurityLimits.DNS_TIMEOUT_SECONDS)
            hostname = socket.gethostbyaddr(ip)[0]
            reasoning = f"No VT API — rDNS: {hostname}"
        except Exception:
            reasoning = "No VT API — No reverse DNS"

        result = VTResult(
            success=False,
            error="No API Key",
            threat_level="UNKNOWN",
            reasoning=reasoning)
        cache.set(f"ip:{ip}", result)
        return result

    try:
        vt_limiter.wait_if_needed()
        headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}

        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=SecurityLimits.HTTP_TIMEOUT_SECONDS)

        if response.status_code == 200:
            data = response.json()
            attrs = data.get('data', {}).get('attributes', {})
            result = analyze_vt_consensus(
                attrs.get('last_analysis_stats', {}),
                attrs.get('last_analysis_results', {}))

            as_owner = attrs.get('as_owner', '')
            country = attrs.get('country', '')
            if as_owner or country:
                extra = []
                if as_owner:
                    extra.append(f"Owner: {as_owner}")
                if country:
                    extra.append(f"Country: {country}")
                result.reasoning += " · " + " | ".join(extra)

        elif response.status_code == 404:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                reasoning = f"IP not in VT DB · rDNS: {hostname}"
            except Exception:
                reasoning = "IP not in VT DB · No reverse DNS"

            result = VTResult(
                success=True, threat_level="UNKNOWN",
                reasoning=reasoning)
        else:
            result = VTResult(
                success=False, error=f"HTTP {response.status_code}")

        cache.set(f"ip:{ip}", result)
        return result

    except Exception as e:
        logger.error(f"VT IP check failed: {e}")
        return VTResult(success=False, error=str(e)[:100])


# ═══════════════════════════════════════════════════════════════════════════════
# ABUSEIPDB
# ═══════════════════════════════════════════════════════════════════════════════

def is_cloud_provider(isp: str) -> bool:
    """Strict cloud provider matching."""
    isp_lower = isp.lower()
    for provider, domains in CLOUD_PROVIDERS_STRICT.items():
        for domain in domains:
            if domain in isp_lower:
                return True
    return False


def check_abuseipdb(ip: str) -> AbuseIPResult:
    """Check IP reputation with AbuseIPDB."""
    result = AbuseIPResult(checked=False)

    if not ip or not Config.ABUSEIPDB_KEY:
        return result

    try:
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={
                'Key': Config.ABUSEIPDB_KEY,
                'Accept': 'application/json',
            },
            params={
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': '',
            },
            timeout=SecurityLimits.HTTP_TIMEOUT_SECONDS)

        if resp.status_code == 200:
            data = resp.json().get('data', {})
            result.checked = True
            result.abuse_score = data.get('abuseConfidenceScore', 0)
            result.total_reports = data.get('totalReports', 0)
            result.country = data.get('countryCode', '')
            result.isp = data.get('isp', '')
            result.is_tor = data.get('isTor', False)

            is_cloud = is_cloud_provider(result.isp)

            if is_cloud:
                critical_threshold = Thresholds.ABUSE_IP_CLOUD_CRITICAL
                high_threshold = Thresholds.ABUSE_IP_CLOUD_HIGH
            else:
                critical_threshold = Thresholds.ABUSE_IP_CRITICAL
                high_threshold = Thresholds.ABUSE_IP_HIGH

            if result.abuse_score >= critical_threshold:
                result.threat_level = "CRITICAL"
                result.findings.append(
                    f"🚨 AbuseIPDB: {result.abuse_score}/100 "
                    f"({result.total_reports} reports)")
            elif result.abuse_score >= high_threshold:
                result.threat_level = "HIGH"
                result.findings.append(
                    f"⚠️ AbuseIPDB: {result.abuse_score}/100")
            elif result.abuse_score >= Thresholds.ABUSE_IP_MEDIUM:
                result.threat_level = "MEDIUM"
                result.findings.append(
                    f"ℹ️ AbuseIPDB: {result.abuse_score}/100")
            else:
                result.threat_level = "CLEAN"
                result.findings.append(
                    f"✅ AbuseIPDB: Clean "
                    f"({result.abuse_score}/100)")

            if result.is_tor:
                result.findings.append("🧅 TOR Exit Node Detected")
                result.threat_level = "HIGH"

    except Exception as e:
        logger.debug(f"AbuseIPDB check failed: {e}")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# MALWARE BAZAAR
# ═══════════════════════════════════════════════════════════════════════════════

def check_malware_bazaar(file_data: bytes,
                         filename: str) -> MalwareBazaarResult:
    """Query MalwareBazaar for known malware."""
    result = MalwareBazaarResult(filename=filename)

    try:
        sha256 = hashlib.sha256(file_data).hexdigest()

        headers = {}
        if Config.MALWAREBAZAAR_KEY:
            headers['Auth-Key'] = Config.MALWAREBAZAAR_KEY

        resp = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': sha256},
            headers=headers,
            timeout=SecurityLimits.HTTP_TIMEOUT_SECONDS)

        if resp.status_code == 200:
            data = resp.json()
            if data.get('query_status') == 'ok' and data.get('data'):
                info = data['data'][0]
                result.found = True
                result.malware_family = info.get('signature', 'Unknown')
                result.tags = info.get('tags', []) or []
                result.first_seen = info.get('first_seen', '')
                result.threat_level = "CRITICAL"

    except Exception as e:
        logger.debug(
            f"MalwareBazaar check failed for '{filename}': {e}")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# HEADER ANOMALY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_header_anomalies(msg) -> HeaderAnomalyResult:
    """Detect header anomalies."""
    result = HeaderAnomalyResult()

    # X-Mailer check
    mailer_val = str(
        msg.get('X-Mailer', '') or msg.get('User-Agent', '')).lower()
    if mailer_val:
        is_legit = any(
            legit in mailer_val for legit in KNOWN_LEGIT_MAILERS)
        if not is_legit:
            if (re.search(r'[a-z]{8,}v\d+\.\d+', mailer_val)
                    or mailer_val in ['test', 'spam', 'bulk']):
                result.anomalies.append(
                    f"⚠️ Unusual X-Mailer: '{mailer_val[:60]}'")
                result.score += ScoringWeights.HEADER_ANOMALY

    # Reply-To hijack
    from_addr = str(msg.get('From', ''))
    reply_to = str(msg.get('Reply-To', ''))
    if reply_to:
        fdm = SecurePatterns.DOMAIN_FROM_EMAIL.search(from_addr)
        rdm = SecurePatterns.DOMAIN_FROM_EMAIL.search(reply_to)
        if fdm and rdm:
            from_root = get_root_domain(fdm.group(1).lower())
            reply_root = get_root_domain(rdm.group(1).lower())
            if from_root != reply_root:
                result.reply_to_hijack = True
                result.anomalies.append(
                    f"🚨 REPLY-TO HIJACK: From={fdm.group(1)} "
                    f"vs Reply-To={rdm.group(1)}")
                result.score += ScoringWeights.HEADER_ANOMALY * 2

    # Timezone inconsistency (threshold=4 to reduce false positives)
    timezones = []
    for h in (msg.get_all('Received', []) or []):
        match = SecurePatterns.TIMEZONE_PATTERN.search(str(h))
        if match:
            timezones.append(match.group(0))

    if len(set(timezones)) > 4:
        result.anomalies.append(
            f"⚠️ Timezone inconsistency: "
            f"{len(set(timezones))} different zones")
        result.score += ScoringWeights.HEADER_ANOMALY

    # Missing Message-ID
    if not msg.get('Message-ID'):
        result.anomalies.append("⚠️ Missing Message-ID")
        result.score += 15

    # Future date
    date_str = str(msg.get('Date', ''))
    if date_str:
        try:
            msg_date = parsedate_to_datetime(date_str)
            diff = (msg_date - datetime.now(msg_date.tzinfo)).days
            if diff > 1:
                result.anomalies.append(
                    f"🚨 FUTURE DATE: {diff} days ahead")
                result.score += 30
        except Exception:
            pass

    # Received chain hop analysis
    hop_count, _, hop_anomaly = analyze_received_chain(msg)
    if hop_anomaly:
        result.anomalies.append(hop_anomaly)
        result.score += ScoringWeights.HOP_COUNT_ANOMALY

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# BEC ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_bec(body_text: str, subject: str,
                from_addr: str) -> BECResult:
    """Detect BEC patterns including CEO/CFO authority claims."""
    result = BECResult()
    combined = f"{subject} {body_text} {from_addr}".lower()

    for category, (keywords, weight) in BEC_KEYWORDS.items():
        matched = False
        for kw in keywords:
            if matched:
                break
            try:
                if re.search(kw, combined):
                    matched = True
            except Exception:
                matched = kw in combined

            if matched:
                result.score += weight
                if category not in result.triggered_categories:
                    result.triggered_categories.append(category)
                    result.findings.append(
                        f"Keyword: '{kw}' ({category})")

    # Combination bonuses
    if ('wire_transfer' in result.triggered_categories
            and 'urgency' in result.triggered_categories):
        result.score += 30
        result.findings.append("🚨 COMBO: Urgent wire transfer")

    if ('payment_redirect' in result.triggered_categories
            and 'urgency' in result.triggered_categories):
        result.score += 25
        result.findings.append("🚨 COMBO: Urgent payment redirect")

    if ('authority_claim' in result.triggered_categories
            and ('wire_transfer' in result.triggered_categories
                 or 'gift_cards' in result.triggered_categories)):
        result.score += 30
        result.findings.append(
            "🚨 COMBO: Authority claim + financial request")

    if ('secrecy' in result.triggered_categories
            and 'wire_transfer' in result.triggered_categories):
        result.score += 20
        result.findings.append(
            "🚨 COMBO: Secrecy + wire transfer")

    # Risk level
    if result.score >= 80:
        result.risk_level = "CRITICAL"
        result.summary = (
            f"🚨 HIGH-CONFIDENCE BEC: Score {result.score}")
    elif result.score >= 50:
        result.risk_level = "HIGH"
        result.summary = f"⚠️ LIKELY BEC: Score {result.score}"
    elif result.score >= 25:
        result.risk_level = "MEDIUM"
        result.summary = (
            f"⚠️ BEC INDICATORS: Score {result.score}")
    elif result.score > 0:
        result.risk_level = "LOW"
        result.summary = "ℹ️ Minor BEC indicators"
    else:
        result.summary = "✅ No BEC patterns"

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# DISPLAY NAME SPOOFING
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_display_name_spoof(
        msg, org_domain: str = "") -> DisplayNameSpoofResult:
    """Detect display name spoofing."""
    result = DisplayNameSpoofResult()
    from_header = str(msg.get('From', ''))

    if not from_header:
        return result

    display_match = re.match(
        r'^"?([^"<@\n]{2,60}?)"?\s*<([^>]+)>', from_header.strip())
    if not display_match:
        return result

    display_name = display_match.group(1).strip()
    sender_email = display_match.group(2).strip().lower()

    sender_dm = SecurePatterns.DOMAIN_FROM_EMAIL.search(sender_email)
    if not sender_dm:
        return result

    sender_domain = sender_dm.group(1).lower()
    result.display_name = display_name
    result.sender_domain = sender_domain
    dn_lower = display_name.lower()

    if org_domain and sender_domain.endswith(org_domain):
        return result

    # Pattern 1: Header injection (email in display name)
    if '@' in dn_lower and '.' in dn_lower:
        result.detected = True
        result.score = 65
        result.findings.append(
            "🚨 HEADER INJECTION: Display name contains email address")

    # Pattern 2: Brand mismatch
    for brand in DISPLAY_NAME_IMPERSONATIONS:
        if brand in dn_lower:
            brand_slug = brand.replace(' ', '')
            is_legit = (
                brand_slug in sender_domain
                or any(sender_domain.endswith(tld)
                       for tld in GOVERNMENT_TLDS + EDUCATIONAL_TLDS))
            if not is_legit:
                result.detected = True
                result.impersonated_brand = brand.title()
                result.score = max(
                    result.score, ScoringWeights.DISPLAY_NAME_SPOOF)
                result.findings.append(
                    f"🚨 BRAND SPOOF: Claims '{display_name}' "
                    f"but from '{sender_domain}'")
                break

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACHMENT RISK MATRIX
# ═══════════════════════════════════════════════════════════════════════════════

def detect_tracking_pixels(html_body: str) -> List[str]:
    """Detect tracking pixels and hidden content in HTML."""
    findings = []
    if not html_body:
        return findings

    if re.search(
            r'<img[^>]+width=[\'"]?1[\'"]?[^>]+height=[\'"]?1[\'"]?',
            html_body, re.I):
        findings.append("⚠️ Found 1x1 Tracking Pixel (Privacy Risk)")

    if "canarytokens.com" in html_body:
        findings.append("⚠️ Found Canary Token (Tracking/Trap)")

    normalized = html_body.replace(" ", "")
    if "color:white" in normalized or "color:#ffffff" in html_body.lower():
        findings.append(
            "⚠️ HIDDEN TEXT: White-on-white text "
            "(Bayesian poisoning attempt)")

    if "font-size:0" in normalized:
        findings.append(
            "⚠️ HIDDEN TEXT: Zero-size font (content obfuscation)")

    if "display:none" in normalized:
        findings.append(
            "⚠️ HIDDEN CONTENT: display:none element detected")

    return findings


def analyze_suspicious_language(body_text: str,
                                subject: str = "") -> List[str]:
    """Detect suspicious language patterns.

    FIX: Now also checks subject line. Gated on minimum length.
    """
    findings = []
    combined = f"{subject} {body_text}".strip()
    if len(combined) < 20:
        return []

    lower_combined = combined.lower()

    for cat, (phrases, score) in SUSPICIOUS_PHRASES.items():
        for phrase in phrases:
            try:
                if re.search(phrase, lower_combined):
                    findings.append(
                        f"Suspicious Language: '{phrase}' ({cat})")
                    break
            except Exception:
                if phrase in lower_combined:
                    findings.append(
                        f"Suspicious Language: '{phrase}' ({cat})")
                    break

    return findings


def update_status(status_container, message: str, icon: str,
                  color: str = None):
    """Render a styled status update bar in Streamlit."""
    if color is None:
        color = DesignSystem.COLORS['accent']
    safe_message = html.escape(message)
    shadow = DesignSystem.SHADOWS['card']
    text_color = DesignSystem.COLORS['text_primary']
    status_container.markdown(
        f"<div style='background:linear-gradient(90deg,{color}22 0%,"
        f"transparent 100%);border-left:4px solid {color};"
        f"padding:12px 16px;border-radius:6px;margin:8px 0;"
        f"box-shadow:{shadow}'>"
        f"<span style='font-size:1.2em;margin-right:8px'>{icon}</span>"
        f"<span style='color:{text_color};"
        f"font-weight:500'>{safe_message}</span></div>",
        unsafe_allow_html=True)


def render_threat_badge(threat_level: str) -> str:
    """Render a professional styled threat level badge."""
    color = DesignSystem.get_threat_color(threat_level)
    text = DesignSystem.badge_text_color(color)
    icon = get_threat_icon(threat_level)
    return (
        f"<span style='background:{color};color:{text};"
        f"padding:6px 14px;border-radius:20px;font-weight:600;"
        f"font-size:0.9em;text-transform:uppercase'>"
        f"{icon} {threat_level}</span>")


def _enrich_ip_context(ip: str) -> str:
    """Lightweight IP enrichment: reverse DNS lookup."""
    parts = []
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            parts.append(f"rDNS: {hostname}")
    except Exception:
        pass
    return ' · '.join(parts) if parts else "No reverse DNS record"


def analyze_attachment_risks(msg) -> List[AttachmentRiskItem]:
    """Analyze attachment risks.

    FIX: Removed duplicate dead-code loop from v8.1.
    """
    risks = []

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue

        fname = part.get_filename() or ''
        if not fname:
            continue

        if not validate_filename(fname):
            risks.append(AttachmentRiskItem(
                filename=fname[:50],
                risk_type='invalid_filename',
                description="Invalid filename (possible path traversal)",
                score=40,
                severity='HIGH'))
            continue

        ct = part.get_content_type()
        fl = fname.lower()

        # Double extension detection
        for pattern, description in DOUBLE_EXTENSION_PATTERNS:
            if re.search(pattern, fl):
                risks.append(AttachmentRiskItem(
                    filename=fname,
                    risk_type='double_extension',
                    description=f"Double extension: {description}",
                    score=ScoringWeights.DOUBLE_EXTENSION,
                    severity='CRITICAL'))
                break

        # Dangerous extension detection
        ext = '.' + fl.rsplit('.', 1)[-1] if '.' in fl else ''
        if ext in DANGEROUS_EXTENSIONS:
            risks.append(AttachmentRiskItem(
                filename=fname,
                risk_type='dangerous_extension',
                description=f"Executable type '{ext}'",
                score=ScoringWeights.DOUBLE_EXTENSION,
                severity='CRITICAL'))

        # Content-Type mismatch detection
        clean_ext = fl.rsplit('.', 1)[-1] if '.' in fl else ''
        valid_types = VALID_MIME_TYPES.get(clean_ext, [])
        if valid_types:
            ct_lower = ct.lower()
            is_valid = (
                any(vt in ct_lower for vt in valid_types)
                or ct_lower in [
                    'application/octet-stream',
                    'binary/octet-stream'])
            if not is_valid:
                risks.append(AttachmentRiskItem(
                    filename=fname,
                    risk_type='content_type_mismatch',
                    description=(
                        f"Content-Type mismatch: "
                        f".{clean_ext} as '{ct}'"),
                    score=ScoringWeights.CONTENT_TYPE_MISMATCH,
                    severity='MEDIUM'))

    return risks


# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════

class ActiveAuthVerifier:
    @staticmethod
    def verify_dmarc_record(domain: str) -> dict:
        if not DNS_OK or not domain:
            return {'status': 'UNKNOWN', 'record': None}
        try:
            socket.setdefaulttimeout(SecurityLimits.DNS_TIMEOUT_SECONDS)
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if 'v=DMARC1' in txt_record:
                    p_tag = re.search(r'p=(\w+)', txt_record)
                    policy = p_tag.group(1) if p_tag else 'none'
                    return {
                        'status': 'FOUND',
                        'policy': policy,
                        'record': txt_record}
            return {'status': 'MISSING', 'record': None}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {'status': 'NXDOMAIN', 'record': None}
        except Exception as e:
            return {'status': 'ERROR', 'error': str(e)}

    @staticmethod
    def verify_spf_record(domain: str) -> dict:
        if not DNS_OK or not domain:
            return {'status': 'UNKNOWN'}
        try:
            socket.setdefaulttimeout(SecurityLimits.DNS_TIMEOUT_SECONDS)
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if 'v=spf1' in txt_record:
                    return {'status': 'FOUND', 'record': txt_record}
            return {'status': 'MISSING'}
        except Exception:
            return {'status': 'MISSING'}


def analyze_authentication(msg) -> AuthResult:
    """Analyze email authentication.

    FIX: Added SPF softfail/temperror/permerror handling.
    FIX: Added DKIM NONE compounding with SPF failures.
    FIX: Fixed marketing platform return-path matching (exact domain).
    """
    result = AuthResult()

    # Extract true source IP
    true_source_ip = get_public_source_ip(msg)
    if true_source_ip:
        result.source_ip = true_source_ip
        result.detailed_analysis.append(
            f"True Source IP: {true_source_ip}")

    # Received chain analysis
    hop_count, hops, hop_anomaly = analyze_received_chain(msg)
    result.hop_count = hop_count
    if hop_anomaly:
        result.hop_anomaly = hop_anomaly
        result.detailed_analysis.append(hop_anomaly)

    auth_header = str(
        msg.get('Authentication-Results', '')).lower()
    spf_header = str(msg.get('Received-SPF', '')).lower()

    # Check vendor headers
    vendor_spf_pass = False
    vendor_headers = [
        str(msg.get('X-FEAS-SPF', '')).lower(),
        str(msg.get('X-Forefront-Antispam-Report', '')).lower(),
    ]
    for v_header in vendor_headers:
        if 'spf=pass' in v_header or 'spf-result=pass' in v_header:
            vendor_spf_pass = True
            result.detailed_analysis.append(
                "✅ Vendor confirms SPF PASS")

    # SPF determination
    spf_status = "NONE"
    if (vendor_spf_pass or 'spf=pass' in auth_header
            or ('pass' in spf_header and 'spf' in spf_header)):
        spf_status = 'PASS'
        result.findings.append("SPF: PASS")
        result.detailed_analysis.append("SPF: PASS — Authorized")

    elif 'spf=fail' in auth_header or ('fail' in spf_header
                                       and 'soft' not in spf_header):
        # Check if fail is on a private IP
        fail_ip_match = re.search(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?not permitted',
            auth_header)
        failed_ip = fail_ip_match.group(1) if fail_ip_match else None

        private_patterns = [
            re.compile(r'^10\.'),
            re.compile(r'^192\.168\.'),
            re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
            re.compile(r'^127\.'),
        ]
        is_private = bool(
            failed_ip
            and any(r.match(failed_ip) for r in private_patterns))

        if vendor_spf_pass:
            spf_status = 'PASS'
            result.detailed_analysis.append(
                "SPF: Vendor override (gateway trust)")
        elif is_private:
            spf_status = 'NONE'
            result.detailed_analysis.append(
                f"ℹ️ SPF Fail on internal IP {failed_ip} (ignored)")
            result.findings.append("SPF: Internal relay (ignored)")
        else:
            spf_status = 'FAIL'
            result.findings.append("SPF: FAIL")
            result.detailed_analysis.append(
                "SPF: FAIL — Unauthorized sender")

    elif 'spf=softfail' in auth_header or 'softfail' in spf_header:
        spf_status = 'SOFTFAIL'
        result.findings.append("SPF: SOFTFAIL")
        result.detailed_analysis.append(
            "SPF: SOFTFAIL — Sender not fully authorized "
            "(domain transitioning or misconfigured)")

    elif 'spf=temperror' in auth_header or 'temperror' in spf_header:
        spf_status = 'TEMPERROR'
        result.findings.append("SPF: TEMPERROR")
        result.detailed_analysis.append(
            "SPF: TEMPERROR — Temporary DNS failure during check")

    elif 'spf=permerror' in auth_header or 'permerror' in spf_header:
        spf_status = 'PERMERROR'
        result.findings.append("SPF: PERMERROR")
        result.detailed_analysis.append(
            "SPF: PERMERROR — Permanent SPF record error")

    result.spf = spf_status

    # Score for SPF status
    if spf_status == 'FAIL':
        result.score += ScoringWeights.SPF_FAIL
    elif spf_status == 'SOFTFAIL':
        result.score += ScoringWeights.SPF_SOFTFAIL
    elif spf_status in ('TEMPERROR', 'PERMERROR'):
        result.score += ScoringWeights.SPF_TEMPERROR

    # DKIM
    if 'dkim=pass' in auth_header:
        result.dkim = 'PASS'
        result.findings.append("DKIM: PASS")
        result.detailed_analysis.append(
            "DKIM: PASS — Signature valid")
    elif 'dkim=fail' in auth_header:
        result.dkim = 'FAIL'
        result.findings.append("DKIM: FAIL")
        result.score += ScoringWeights.DKIM_FAIL
    else:
        result.dkim = 'NONE'
        result.findings.append("DKIM: Not configured")
        # Compound scoring: DKIM NONE + SPF failure = worse
        if spf_status in ('FAIL', 'SOFTFAIL'):
            result.score += ScoringWeights.DKIM_MISSING_WITH_SPF_FAIL
            result.detailed_analysis.append(
                "⚠️ No DKIM + SPF issue — no cryptographic "
                "message integrity")

    # DMARC
    if 'dmarc=pass' in auth_header:
        result.dmarc = 'PASS'
        result.findings.append("DMARC: PASS")
    elif 'dmarc=fail' in auth_header:
        result.dmarc = 'FAIL'
        result.findings.append("DMARC: FAIL")
        result.score += ScoringWeights.DMARC_FAIL
    else:
        result.dmarc = 'NONE'
        result.findings.append("DMARC: Not configured")

    # Gateway trust
    trusted, gateway_name, notes = analyze_infrastructure(msg)
    if trusted:
        result.gateway_trust = True
        result.gateway_name = gateway_name
        result.detailed_analysis.extend(notes)

    # Domain extraction
    result.from_full = str(msg.get('From', ''))
    result.return_path_full = str(msg.get('Return-Path', ''))

    from_match = SecurePatterns.DOMAIN_FROM_EMAIL.search(
        result.from_full)
    return_match = SecurePatterns.DOMAIN_FROM_EMAIL.search(
        result.return_path_full)

    if from_match:
        from_domain = from_match.group(1).lower()
        result.from_domain = from_domain

        # Live DNS verification
        if DNS_OK:
            result.live_dns_verified = True
            result.live_dns_dmarc = (
                ActiveAuthVerifier.verify_dmarc_record(from_domain))
            result.live_dns_spf = (
                ActiveAuthVerifier.verify_spf_record(from_domain))

    if from_match and return_match:
        result.from_domain = from_match.group(1).lower()
        result.return_path_domain = return_match.group(1).lower()

        # FIX: Exact domain matching for marketing platforms
        rp_root = get_root_domain(result.return_path_domain)
        is_marketing = rp_root in MARKETING_RETURN_PATH_DOMAINS

        if result.from_domain == result.return_path_domain:
            result.return_path_match = True
        elif is_marketing:
            result.return_path_match = True
            result.detailed_analysis.append(
                f"Legitimate redirection via "
                f"{result.return_path_domain}")
        else:
            result.return_path_match = False
            result.shadow_spoofing = True
            result.score += ScoringWeights.SHADOW_SPOOFING
            result.findings.append(
                f"SHADOW SPOOFING: From {result.from_domain} "
                f"vs Return-Path {result.return_path_domain}")
    elif from_match and not return_match:
        result.from_domain = from_match.group(1).lower()
        result.return_path_match = True

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# MACRO ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_macro_context(vba_code: str,
                          auto_exec: List[str]) -> MacroContext:
    """Analyze macro context."""
    context = MacroContext()
    context.auto_execute = auto_exec
    context.entropy_score = calculate_entropy(vba_code)

    if context.entropy_score > 5.5:
        context.risk_score += 40
        context.reasoning.append(
            f"High entropy ({context.entropy_score:.2f})")

    for category, keywords in BENIGN_MACRO_PATTERNS.items():
        for keyword in keywords:
            if keyword.lower() in vba_code.lower():
                context.has_benign = True
                if category not in context.benign_patterns:
                    context.benign_patterns.append(category)

    weights = {
        'network_activity':  50,
        'process_execution': 40,
        'obfuscation':       35,
        'registry_access':   30,
        'file_operations':   25,
    }

    for category, keywords in HIGH_RISK_MACRO_PATTERNS.items():
        for keyword in keywords:
            if keyword.lower() in vba_code.lower():
                context.has_risky = True
                if category not in context.risky_patterns:
                    context.risky_patterns.append(category)
                    context.risk_score += weights.get(category, 20)

    if context.auto_execute:
        if context.has_risky:
            context.risk_score += 40
            context.reasoning.append(
                "Auto-execute + risky operations")

    if context.risk_score >= 100:
        context.verdict = "CRITICAL"
    elif context.risk_score >= 70:
        context.verdict = "HIGH"
    elif context.risk_score >= 40:
        context.verdict = "MEDIUM"
    else:
        context.verdict = "SAFE"

    return context


def analyze_macro_complete(file_data: bytes,
                           filename: str) -> Optional[MacroResult]:
    """Complete attachment analysis with secure temp file handling."""
    result = MacroResult(filename=filename)
    result.file_md5 = hashlib.md5(file_data).hexdigest()
    result.file_sha256 = hashlib.sha256(file_data).hexdigest()

    # MalwareBazaar
    try:
        mb = check_malware_bazaar(file_data, filename)
        result.malware_bazaar = mb
        if mb.found:
            result.risk_score = 100
            result.details.append(
                f"🚨 MALWARE BAZAAR: {mb.malware_family}")
    except Exception as e:
        logger.error(f"MalwareBazaar error: {e}")

    # YARA scan (stricter Office filter)
    if YARA_OK:
        raw_matches = yara_scan_bytes(file_data, filename)

        is_valid_office = (
            b'[Content_Types].xml' in file_data
            and file_data[:4] == b'PK\x03\x04')

        result.yara_matches = []
        for m in raw_matches:
            if m.rule_name == 'Archive_Signature' and is_valid_office:
                logger.info(
                    f"Smart Office Filter: suppressed "
                    f"Archive_Signature on '{filename}'")
                continue
            result.yara_matches.append(m)

        if result.yara_matches:
            result.risk_score = max(
                result.risk_score,
                yara_score_from_matches(result.yara_matches))

    # PDF Analysis
    if file_data.startswith(b'%PDF'):
        result.file_type = "PDF"

        extracted_uris = extract_pdf_uris(file_data)
        if extracted_uris:
            result.pdf_uris = extracted_uris
            result.details.append(
                f"🔗 PDF URIs: {len(extracted_uris)} link(s)")

        if PEEPDF_OK:
            try:
                with safe_temp_file(file_data, '.pdf') as tmp_path:
                    parser = PDFParser()
                    ret, pdf = parser.parse(
                        tmp_path, forceMode=True, looseMode=True)
                    if ret == 0 and pdf:
                        stats = pdf.getStats()
                        if stats.get('js', 0) > 0:
                            result.risk_score += 40
                            result.details.append(
                                "Embedded JavaScript")
                        if stats.get('launch', 0) > 0:
                            result.risk_score += 50
                            result.details.append(
                                "Launch command (critical)")
            except Exception as e:
                logger.debug(f"Peepdf error: {e}")

        suspicious_tags = {
            b'/OpenAction': 'Auto-execution',
            b'/JavaScript': 'JavaScript',
            b'/Launch':     'Launch command',
        }
        found_tags = [
            desc for tag, desc in suspicious_tags.items()
            if tag in file_data]
        if found_tags:
            result.has_macros = True
            result.details.append(
                f"Suspicious tags: {', '.join(found_tags)}")

        if not result.verdict:
            result.verdict = (
                "SUSPICIOUS" if result.yara_matches else "SAFE")

        return result

    # Office Document Analysis
    if file_data.startswith((b'\xD0\xCF\x11\xE0', b'PK\x03\x04')):
        result.file_type = "Office Document"

        office_links = extract_office_uris(file_data)
        if office_links:
            result.pdf_uris.extend(office_links)
            result.details.append(
                f"🔗 Office links: {len(office_links)}")

        if not OLETOOLS_OK:
            result.verdict = "Macro Engine Offline"
            return result

        try:
            with safe_temp_file(file_data, '.doc') as tmp_path:
                try:
                    oid = OleID(tmp_path)
                    for indicator in oid.check():
                        if indicator.id == 'ole_external_relationships':
                            if indicator.risk == 'HIGH':
                                result.details.append(
                                    "ℹ️ External data connections")
                                result.risk_score += 5
                            continue

                        if indicator.risk in ['HIGH', 'MEDIUM']:
                            result.details.append(
                                f"OleID: {indicator.name} "
                                f"({indicator.risk})")
                            result.risk_score += (
                                20 if indicator.risk == 'HIGH'
                                else 10)
                except Exception as e:
                    logger.warning(f"OleID check failed: {e}")

                vba = VBA_Parser(tmp_path)
                if vba.detect_vba_macros():
                    result.has_macros = True
                    all_code = ""
                    auto_exec = []

                    for (_, _, _, code) in vba.extract_macros():
                        if code:
                            all_code += code + "\n"

                    try:
                        mr = MacroRaptor(all_code)
                        mr.scan()
                        if mr.suspicious:
                            result.risk_score += 20
                            result.details.append(
                                "MacroRaptor: SUSPICIOUS")
                    except Exception:
                        pass

                    for kw in ['AutoOpen', 'AutoExec',
                               'Workbook_Open', 'Document_Open']:
                        if kw.lower() in all_code.lower():
                            auto_exec.append(kw)

                    ctx = analyze_macro_context(all_code, auto_exec)
                    result.context = ctx
                    result.risk_score += ctx.risk_score
                    result.verdict = ctx.verdict
                    result.details.extend(ctx.detailed_analysis)

                    if YARA_OK and all_code:
                        vba_yara = yara_scan_bytes(
                            all_code.encode('utf-8', errors='ignore'),
                            f"{filename}_vba")
                        for m in vba_yara:
                            if m not in result.yara_matches:
                                result.yara_matches.append(m)
                else:
                    result.verdict = "SAFE — No macros"

                vba.close()

        except Exception as e:
            result.verdict = f"Error: {str(e)[:50]}"
            logger.error(f"Office analysis error: {e}")

        return result

    # Unknown file
    if result.yara_matches:
        result.file_type = "Unknown/Binary"
        result.verdict = (
            f"SUSPICIOUS — YARA: "
            f"{result.yara_matches[0].rule_name}")
        return result

    return None


# ═══════════════════════════════════════════════════════════════════════════════
# OBSERVABLE EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def extract_observables(msg) -> List[Observable]:
    """Extract observables from email.

    FIX: Now extracts HTML <a href> links (primary phishing vector).
    FIX: Detects URL shorteners and suspicious TLDs.
    """
    obs: List[Observable] = []
    body_text = ''
    body_html = ''

    for part in msg.walk():
        ct = part.get_content_type()
        try:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            decoded = payload.decode('utf-8', errors='ignore')
        except Exception:
            continue

        if ct == 'text/html':
            body_html += decoded
            body_text += decoded
        elif ct == 'text/plain':
            body_text += decoded

    # Extract URLs from HTML href attributes (primary phishing vector)
    try:
        for match in SecurePatterns.HTML_HREF.finditer(body_html):
            href = match.group(1).strip()
            if href.startswith(('http://', 'https://')):
                o = Observable(
                    type='url', value=href,
                    defanged=defang(href), source='html_href')
                o.is_shortener = is_url_shortener(href)
                try:
                    domain = urlparse(href).netloc.lower()
                    o.suspicious_tld = has_suspicious_tld(domain)
                except Exception:
                    pass
                obs.append(o)
    except Exception as e:
        logger.error(f"HTML href extraction error: {e}")

    # Extract URLs from body text via regex
    try:
        for url in SecurePatterns.URL_HTTP.findall(
                body_text)[:SecurityLimits.MAX_OBSERVABLES]:
            o = Observable(
                type='url', value=url,
                defanged=defang(url), source='body')
            o.is_shortener = is_url_shortener(url)
            try:
                domain = urlparse(url).netloc.lower()
                o.suspicious_tld = has_suspicious_tld(domain)
            except Exception:
                pass
            obs.append(o)
    except Exception:
        logger.error("URL extraction timeout - possible ReDoS")

    # Domains from email addresses
    try:
        for ea in SecurePatterns.EMAIL_ADDRESS.findall(
                str(msg))[:SecurityLimits.MAX_OBSERVABLES]:
            domain = ea.split('@')[1].lower()
            o = Observable(
                type='domain', value=domain,
                defanged=defang(domain), source='header')
            o.suspicious_tld = has_suspicious_tld(domain)
            obs.append(o)
    except Exception:
        pass

    # IPs from Received headers
    for header in (msg.get_all('Received', []) or []):
        try:
            for ip in SecurePatterns.IPV4_ADDRESS.findall(str(header)):
                if not ip.startswith(
                        ('10.', '192.168.', '127.', '172.16.',
                         '169.254.', '0.')):
                    obs.append(Observable(
                        type='ip', value=ip,
                        defanged=ip.replace('.', '[.]'),
                        source='received_header'))
        except Exception:
            pass

    # Deduplicate (preserve first occurrence, prefer html_href source)
    seen: Set[Tuple[str, str]] = set()
    unique = []
    for o in obs:
        key = (o.type, o.value)
        if key not in seen:
            seen.add(key)
            unique.append(o)

    return unique


def check_single_observable(obs: Observable) -> Observable:
    """Check single observable with VT."""
    time.sleep(0.05)

    try:
        if obs.type == 'url':
            obs.vt_result = check_vt_url(obs.value)
        elif obs.type == 'domain':
            obs.vt_result = check_vt_domain(obs.value)
        elif obs.type == 'ip':
            obs.vt_result = check_vt_ip(obs.value)

        if obs.vt_result and obs.vt_result.success:
            if obs.vt_result.threat_level == "CRITICAL":
                obs.threat_score = 100
                obs.reputation = 'malicious'
            elif obs.vt_result.threat_level == "MALICIOUS":
                obs.threat_score = 80
                obs.reputation = 'malicious'
            elif obs.vt_result.threat_level == "SUSPICIOUS":
                obs.threat_score = 50
                obs.reputation = 'suspicious'
            else:
                obs.reputation = 'clean'

    except Exception as e:
        logger.error(f"Error checking '{obs.value}': {e}")

    return obs


# ═══════════════════════════════════════════════════════════════════════════════
# VERDICT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_mitigation_credit(auth, observables, macros,
                                findings, abuse_ip):
    """Calculate mitigation credit."""
    credit, reasons = 0, []

    has_trusted_gateway = auth.gateway_trust
    spf_dkim_pass = (auth.spf == 'PASS' and auth.dkim == 'PASS')
    dmarc_pass = (auth.dmarc == 'PASS')

    # Hard signals block mitigation
    has_confirmed_malware = any(
        m.malware_bazaar and m.malware_bazaar.found for m in macros)
    has_malicious_url = any(
        o.vt_result and o.vt_result.raw_malicious >= 3
        for o in observables if o.vt_result)
    has_critical_yara = any(
        ym.severity == 'CRITICAL'
        for m in macros for ym in m.yara_matches)
    has_auth_failure = (
        auth.spf == 'FAIL' or auth.dmarc == 'FAIL'
        or auth.shadow_spoofing)
    has_display_spoof = any(
        f.get('category') == 'SPOOF' for f in findings)
    has_high_abuse_ip = (
        abuse_ip.checked
        and abuse_ip.abuse_score >= Thresholds.ABUSE_IP_CRITICAL)

    if (has_confirmed_malware or has_malicious_url
            or has_critical_yara or has_auth_failure
            or has_display_spoof or has_high_abuse_ip):
        return 0, ["No mitigation — hard threat signal present"]

    all_clean = not any(
        o.vt_result and o.vt_result.success
        and o.type in ['url', 'domain']
        and o.vt_result.threat_level in ['MALICIOUS', 'CRITICAL']
        for o in observables)

    if has_trusted_gateway and spf_dkim_pass and all_clean:
        credit = 40
        reasons.append(
            f"Tier A: Gateway({auth.gateway_name})"
            f"+SPF+DKIM+clean URLs (-40pts)")
        if dmarc_pass:
            credit += 10
            reasons.append("DMARC PASS bonus (-10pts)")
    elif has_trusted_gateway and spf_dkim_pass:
        credit = 25
        reasons.append(
            f"Tier B: Gateway({auth.gateway_name})"
            f"+SPF+DKIM (-25pts)")
    elif spf_dkim_pass:
        credit = 15
        reasons.append(
            "Tier C: SPF+DKIM (no gateway) (-15pts)")
    elif has_trusted_gateway:
        credit = 10
        reasons.append(
            f"Tier D: Gateway({auth.gateway_name}) "
            f"only (-10pts)")

    return credit, reasons


def calculate_verdict(
    observables, macros, auth, images, body_findings,
    bec: BECResult,
    header_anomaly: HeaderAnomalyResult,
    abuse_ip: AbuseIPResult,
    display_name_spoof: DisplayNameSpoofResult,
    attachment_risks: List[AttachmentRiskItem],
    link_mismatches: List[LinkTextMismatch],
) -> tuple:
    """Calculate verdict with all fixes applied.

    FIX: Score capped at 100. Link-text mismatch scoring added.
    FIX: URL shortener and suspicious TLD scoring added.
    """
    total_score = 0
    findings = []

    # Authentication signals
    if auth.spf == 'FAIL':
        total_score += ScoringWeights.SPF_FAIL
        findings.append({
            'category': 'AUTH', 'item': 'SPF', 'threat': 'HIGH',
            'score': ScoringWeights.SPF_FAIL,
            'reasoning': 'SPF FAIL — unauthorized sender'})
    elif auth.spf == 'SOFTFAIL':
        total_score += ScoringWeights.SPF_SOFTFAIL
        findings.append({
            'category': 'AUTH', 'item': 'SPF', 'threat': 'MEDIUM',
            'score': ScoringWeights.SPF_SOFTFAIL,
            'reasoning': 'SPF SOFTFAIL — sender not fully authorized'})

    if auth.dmarc == 'FAIL':
        total_score += ScoringWeights.DMARC_FAIL
        findings.append({
            'category': 'AUTH', 'item': 'DMARC', 'threat': 'HIGH',
            'score': ScoringWeights.DMARC_FAIL,
            'reasoning': 'DMARC failed'})

    if auth.shadow_spoofing:
        total_score += ScoringWeights.SHADOW_SPOOFING
        findings.append({
            'category': 'AUTH', 'item': 'Shadow Spoofing',
            'threat': 'HIGH',
            'score': ScoringWeights.SHADOW_SPOOFING,
            'reasoning': 'Shadow spoofing detected'})

    # Display name spoof
    if display_name_spoof.detected:
        total_score += display_name_spoof.score
        findings.append({
            'category': 'SPOOF',
            'item': f'Display Name: {display_name_spoof.display_name}',
            'threat': 'HIGH', 'score': display_name_spoof.score,
            'reasoning': (
                display_name_spoof.findings[0]
                if display_name_spoof.findings
                else 'Display name impersonation')})

    # Body findings
    for bf in body_findings:
        total_score += 10
        findings.append({
            'category': 'BODY', 'item': 'Content',
            'threat': 'MEDIUM', 'score': 10, 'reasoning': bf})

    # Link-text mismatches
    for ltm in link_mismatches:
        total_score += ScoringWeights.LINK_TEXT_MISMATCH
        findings.append({
            'category': 'PHISHING',
            'item': f'Link-Text Mismatch',
            'threat': 'HIGH',
            'score': ScoringWeights.LINK_TEXT_MISMATCH,
            'reasoning': (
                f"Display shows '{ltm.display_domain}' "
                f"but links to '{ltm.href_domain}'")})

    # URL shortener scoring
    shortener_obs = [
        o for o in observables if o.is_shortener]
    if shortener_obs:
        total_score += ScoringWeights.URL_SHORTENER
        findings.append({
            'category': 'URL', 'item': 'URL Shortener',
            'threat': 'LOW',
            'score': ScoringWeights.URL_SHORTENER,
            'reasoning': (
                f'{len(shortener_obs)} shortened URL(s) — '
                f'may hide destination')})

    # Suspicious TLD scoring
    sus_tld_obs = [
        o for o in observables if o.suspicious_tld]
    if sus_tld_obs:
        total_score += ScoringWeights.SUSPICIOUS_TLD
        findings.append({
            'category': 'URL', 'item': 'Suspicious TLD',
            'threat': 'MEDIUM',
            'score': ScoringWeights.SUSPICIOUS_TLD,
            'reasoning': (
                f'{len(sus_tld_obs)} URL(s) with '
                f'frequently-abused TLD')})

    # BEC scoring
    if bec.score >= 25:
        adjusted_bec_score = bec.score
        if auth.gateway_trust and bec.score < 60:
            adjusted_bec_score = int(bec.score * 0.7)
            bec.summary += " (Slightly suppressed by gateway)"

        bec_threat = (
            'CRITICAL' if adjusted_bec_score >= 80
            else ('HIGH' if adjusted_bec_score >= 50 else 'MEDIUM'))
        total_score += adjusted_bec_score
        findings.append({
            'category': 'BEC',
            'item': 'Business Email Compromise',
            'threat': bec_threat,
            'score': adjusted_bec_score,
            'reasoning': bec.summary})

    # Header anomalies
    if header_anomaly.score >= 25:
        total_score += header_anomaly.score
        for anomaly in header_anomaly.anomalies:
            findings.append({
                'category': 'HEADER', 'item': 'Anomaly',
                'threat': 'MEDIUM',
                'score': header_anomaly.score,
                'reasoning': anomaly})

    # AbuseIPDB
    if (abuse_ip.checked
            and abuse_ip.abuse_score >= Thresholds.ABUSE_IP_MEDIUM):
        is_cloud = is_cloud_provider(abuse_ip.isp)
        is_authorized = (auth.spf == 'PASS' or auth.gateway_trust)

        if is_cloud and is_authorized:
            findings.append({
                'category': 'IP_REPUTATION', 'item': 'Source IP',
                'threat': 'INFO', 'score': 0,
                'reasoning': (
                    f'AbuseIPDB {abuse_ip.abuse_score}/100 '
                    f'suppressed (Authorized Cloud)')})
        else:
            score_add = (
                ScoringWeights.ABUSEIPDB_HIGH
                if abuse_ip.threat_level in ['CRITICAL', 'HIGH']
                else ScoringWeights.ABUSEIPDB_MEDIUM)
            total_score += score_add
            findings.append({
                'category': 'IP_REPUTATION', 'item': 'Source IP',
                'threat': 'HIGH', 'score': score_add,
                'reasoning': (
                    f'AbuseIPDB: {abuse_ip.abuse_score}/100')})

    # Attachment risks
    for risk in attachment_risks:
        if risk.severity in ['CRITICAL', 'HIGH']:
            total_score += risk.score
            findings.append({
                'category': 'ATTACHMENT', 'item': risk.filename,
                'threat': risk.severity, 'score': risk.score,
                'reasoning': risk.description})

    # Observable scores
    for obs in observables:
        if obs.threat_score >= 50:
            total_score += obs.threat_score
            threat_cat = (
                'CRITICAL' if obs.threat_score >= 80 else 'HIGH')
            findings.append({
                'category': obs.type.upper(),
                'item': obs.defanged[:80],
                'threat': threat_cat,
                'score': obs.threat_score,
                'reasoning': (
                    obs.vt_result.reasoning if obs.vt_result
                    else "Threat")})

    # Macro/attachment analysis
    for macro in macros:
        if macro.malware_bazaar and macro.malware_bazaar.found:
            total_score += ScoringWeights.MALWARE_BAZAAR_HIT
            findings.append({
                'category': 'MALWARE_BAZAAR',
                'item': macro.filename,
                'threat': 'CRITICAL',
                'score': ScoringWeights.MALWARE_BAZAAR_HIT,
                'reasoning': (
                    f'Known malware: '
                    f'{macro.malware_bazaar.malware_family}')})

        if macro.risk_score >= ScoringWeights.HIGH_RISK_MACRO:
            total_score += macro.risk_score
            threat_cat = (
                'CRITICAL'
                if macro.risk_score >= ScoringWeights.CRITICAL_MACRO
                else 'HIGH')
            findings.append({
                'category': 'MACRO', 'item': macro.filename,
                'threat': threat_cat,
                'score': macro.risk_score,
                'reasoning': macro.verdict})

        for ym in macro.yara_matches:
            if ym.severity == 'CRITICAL':
                total_score += ScoringWeights.YARA_CRITICAL
                findings.append({
                    'category': 'YARA', 'item': ym.rule_name,
                    'threat': 'CRITICAL',
                    'score': ScoringWeights.YARA_CRITICAL,
                    'reasoning': ym.description})

    # Image steganography
    for img in images:
        if img.has_steganography:
            total_score += ScoringWeights.STEGANOGRAPHY
            findings.append({
                'category': 'IMAGE', 'item': img.filename,
                'threat': 'HIGH',
                'score': ScoringWeights.STEGANOGRAPHY,
                'reasoning': 'Steganography detected'})

    # Mitigation credit
    mitigation_credit, mitigation_reasons = (
        calculate_mitigation_credit(
            auth, observables, macros, findings, abuse_ip))

    if mitigation_credit > 0:
        total_score = max(0, total_score - mitigation_credit)
        for reason in mitigation_reasons:
            findings.append({
                'category': 'MITIGATION',
                'item': 'Auth/Gateway Credit',
                'threat': 'INFO',
                'score': -mitigation_credit,
                'reasoning': reason})

    # FIX: Cap total_score at a maximum
    total_score = min(total_score, 100)

    # Gateway trust override for low-score emails
    if auth.gateway_trust and total_score < 40:
        total_score = 0
        return "CLEAN", "SAFE", 92, findings, total_score

    # Verdict based on thresholds
    if total_score >= Thresholds.VERDICT_MALICIOUS:
        verdict, threat_level, confidence = "MALICIOUS", "CRITICAL", 95
    elif total_score >= Thresholds.VERDICT_LIKELY_MALICIOUS:
        verdict, threat_level, confidence = (
            "LIKELY MALICIOUS", "HIGH", 85)
    elif total_score >= Thresholds.VERDICT_SUSPICIOUS:
        verdict, threat_level, confidence = (
            "SUSPICIOUS", "MEDIUM", 70)
    elif total_score >= Thresholds.VERDICT_REVIEW:
        verdict, threat_level, confidence = (
            "REVIEW RECOMMENDED", "LOW", 60)
    else:
        verdict, threat_level, confidence = "CLEAN", "SAFE", 90

    return verdict, threat_level, confidence, findings, total_score


# ═══════════════════════════════════════════════════════════════════════════════
# IMAGE FORENSICS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_reasoning_summary(report: Dict) -> List[Dict]:
    """Produce reasoning cards with analytical insights."""
    cards = []
    auth = report['auth']
    macros = report['macros']
    obs = report['observables']
    bec = report.get('bec')
    ha = report.get('header_anomaly')
    dns_obj = report.get('display_name_spoof')
    abuse = report.get('abuse_ip')
    att_risks = report.get('attachment_risks', [])
    link_mismatches = report.get('link_mismatches', [])
    DC = DesignSystem.COLORS

    # Card 1: Sender Identity
    from_domain = auth.from_domain or "unknown"
    rp_domain = auth.return_path_domain or "—"
    if auth.shadow_spoofing and dns_obj and dns_obj.detected:
        sender_body = (
            f"🚨 **Double identity deception** — display name "
            f"impersonates '{dns_obj.impersonated_brand or dns_obj.display_name}' "
            f"AND the Return-Path routes replies to **{rp_domain}** "
            f"instead of **{from_domain}**.")
        sender_color = DC['critical']
    elif auth.shadow_spoofing:
        sender_body = (
            f"⚠️ **Return-Path mismatch** — email appears from "
            f"**{from_domain}** but replies route to **{rp_domain}**.")
        sender_color = DC['critical']
    elif dns_obj and dns_obj.detected:
        brand = dns_obj.impersonated_brand or dns_obj.display_name
        sender_body = (
            f"🚨 **Display name impersonation** — claims to be "
            f"'{brand}' but sends from **{dns_obj.sender_domain}**.")
        sender_color = DC['high']
    else:
        sender_body = (
            f"✅ **Sender identity consistent** — From, Return-Path, "
            f"and envelope all align to **{from_domain}**.")
        sender_color = DC['success']
    cards.append({
        'icon': '👤', 'title': 'Sender Identity',
        'body': sender_body,
        'detail': (
            f"From: {auth.from_full[:80] or '—'} | "
            f"Return-Path: {rp_domain}"),
        'color': sender_color})

    # Card 2: Authentication & Live DNS
    if auth.spf == 'FAIL' and auth.dmarc == 'FAIL':
        auth_insight = (
            "🚨 **Triple auth failure** — SPF confirms unauthorized "
            "sender, DMARC violation means domain policy breached.")
        auth_color = DC['critical']
    elif auth.spf == 'FAIL':
        auth_insight = (
            f"⚠️ **Unauthorized sender** — server NOT listed in "
            f"**{from_domain}**'s SPF record.")
        auth_color = DC['critical']
    elif auth.spf == 'SOFTFAIL':
        auth_insight = (
            f"⚠️ **SPF softfail** — sender not fully authorized by "
            f"**{from_domain}** (domain may be transitioning).")
        auth_color = DC['warning']
    elif auth.dkim == 'FAIL' and auth.spf == 'PASS':
        auth_insight = (
            "⚠️ **DKIM signature invalid** despite SPF passing — "
            "message may have been modified in transit.")
        auth_color = DC['warning']
    elif auth.dmarc == 'NONE':
        auth_insight = (
            "⚠️ **No DMARC enforcement** — domain owner cannot "
            "instruct servers to reject spoofed messages.")
        auth_color = DC['warning']
    elif (auth.spf == 'PASS' and auth.dkim == 'PASS'
          and auth.dmarc == 'PASS'):
        auth_insight = (
            "✅ **Full authentication chain intact** — SPF, DKIM, "
            "and DMARC all pass.")
        auth_color = DC['success']
    else:
        auth_insight = (
            f"SPF: {auth.spf} | DKIM: {auth.dkim} | "
            f"DMARC: {auth.dmarc}")
        auth_color = DC['accent']
    if auth.gateway_trust:
        auth_insight += (
            f" 🛡️ Trusted gateway **{auth.gateway_name}** "
            f"pre-screened this message.")
    if auth.live_dns_verified:
        spf_dns = auth.live_dns_spf.get('status', '—')
        dmarc_dns = auth.live_dns_dmarc.get('status', '—')
        dmarc_pol = auth.live_dns_dmarc.get('policy', '')
        spf_snip = auth.live_dns_spf.get('record', '')[:50]
        dns_detail = (
            f"Live DNS — SPF: {spf_dns} [{spf_snip or 'no record'}] | "
            f"DMARC: {dmarc_dns}"
            + (f" (policy={dmarc_pol})" if dmarc_pol else ""))
    else:
        dns_detail = (
            "Live DNS offline — install dnspython for "
            "real-time verification")
    cards.append({
        'icon': '🔐', 'title': 'Authentication & Live DNS',
        'body': auth_insight, 'detail': dns_detail,
        'color': auth_color})

    # Card 3: Source IP
    if auth.source_ip:
        if abuse and abuse.checked:
            if abuse.abuse_score >= 75:
                ip_insight = (
                    f"🚨 **High-confidence malicious IP** — "
                    f"{abuse.total_reports} abuse reports, "
                    f"{abuse.abuse_score}/100 AbuseIPDB score."
                    + (" **TOR exit node.**" if abuse.is_tor else ""))
                ip_color = DC['critical']
            elif abuse.abuse_score >= 40:
                ip_insight = (
                    f"⚠️ **Elevated IP risk** — "
                    f"{abuse.total_reports} abuse reports "
                    f"({abuse.abuse_score}/100).")
                ip_color = DC['high']
            elif abuse.abuse_score >= 10:
                ip_insight = (
                    f"ℹ️ **Minor IP history** — "
                    f"({abuse.abuse_score}/100).")
                ip_color = DC['accent']
            else:
                ip_insight = (
                    f"✅ **IP reputation clean** — "
                    f"{abuse.abuse_score}/100.")
                ip_color = DC['success']
            ip_detail = (
                f"ISP: {abuse.isp or '—'} | "
                f"Country: {abuse.country or '—'}"
                + (" | 🧅 TOR" if abuse.is_tor else ""))
        else:
            rdns_hint = _enrich_ip_context(auth.source_ip)
            ip_insight = (
                f"ℹ️ **No reputation data** for "
                f"**{auth.source_ip}**."
                + (f" ({rdns_hint})"
                   if rdns_hint != "No reverse DNS record" else ""))
            ip_detail = "Add abuseipdb_key for IP reputation"
            ip_color = DC['accent']
        cards.append({
            'icon': '🌐', 'title': 'Source IP Reputation',
            'body': ip_insight, 'detail': ip_detail,
            'color': ip_color})

    # Card 4: Link-Text Mismatches
    if link_mismatches:
        ltm_insight = (
            f"🚨 **{len(link_mismatches)} link-text mismatch(es)** — "
            f"displayed domain differs from actual link destination. "
            f"Classic phishing technique.")
        ltm_detail = "; ".join(
            f"Shows '{m.display_domain}' → links to '{m.href_domain}'"
            for m in link_mismatches[:3])
        cards.append({
            'icon': '🔗', 'title': 'Link-Text Mismatches',
            'body': ltm_insight, 'detail': ltm_detail,
            'color': DC['critical']})

    # Card 5: PDF Embedded URLs
    pdf_macros = [m for m in macros if m.pdf_uris]
    total_pdf_uris = sum(len(m.pdf_uris) for m in pdf_macros)
    if total_pdf_uris > 0:
        pdf_threats = sum(
            1 for o in obs if o.source == 'pdf_uri'
            and o.vt_result
            and o.vt_result.threat_level in ['MALICIOUS', 'CRITICAL'])
        if pdf_threats:
            pdf_insight = (
                f"🚨 **Malicious URLs inside PDF** — "
                f"{pdf_threats} of {total_pdf_uris} flagged.")
            pdf_color = DC['critical']
        else:
            pdf_insight = (
                f"📎 **{total_pdf_uris} URL(s) extracted from PDF**.")
            pdf_color = DC['accent']
        cards.append({
            'icon': '🔗', 'title': 'PDF Embedded URLs',
            'body': pdf_insight,
            'detail': (
                f"Files: "
                f"{', '.join(m.filename for m in pdf_macros)}"),
            'color': pdf_color})

    # Card 6: Attachments
    real_attachments = [
        m for m in macros if m.filename != "[Email Body]"]
    if real_attachments:
        mb_hits = sum(
            1 for m in real_attachments
            if m.malware_bazaar and m.malware_bazaar.found)
        yara_hits = sum(
            len(m.yara_matches) for m in real_attachments)
        if mb_hits:
            fam = next(
                (m.malware_bazaar.malware_family
                 for m in real_attachments
                 if m.malware_bazaar and m.malware_bazaar.found),
                "Unknown")
            att_insight = (
                f"🚨 **Confirmed malware** — matches "
                f"MalwareBazaar: **{fam}**.")
            att_color = DC['critical']
        elif yara_hits:
            top_rule = next(
                (ym.rule_name
                 for m in real_attachments
                 for ym in m.yara_matches), "Unknown")
            att_insight = (
                f"⚠️ **YARA match** — {yara_hits} rule(s), "
                f"top: **{top_rule}**.")
            att_color = DC['high']
        elif att_risks:
            att_insight = (
                f"⚠️ **{len(att_risks)} structural risk(s)** — "
                f"deceptive file structure.")
            att_color = DC['warning']
        else:
            att_insight = (
                f"✅ **All {len(real_attachments)} "
                f"attachment(s) clean**.")
            att_color = DC['success']
        cards.append({
            'icon': '📎', 'title': 'Attachments',
            'body': att_insight,
            'detail': (
                f"Risk matrix: {len(att_risks)} "
                f"structural risk(s)"),
            'color': att_color})

    # Card 7: URLs & Domains
    url_obs = [
        o for o in obs
        if o.type in ['url', 'domain'] and o.vt_result]
    if url_obs:
        threat_urls = [
            o for o in url_obs
            if o.vt_result.threat_level in ['MALICIOUS', 'CRITICAL']]
        clean_urls = [
            o for o in url_obs
            if o.vt_result.threat_level in ['CLEAN', 'LOW']]
        shortener_urls = [o for o in url_obs if o.is_shortener]
        sus_tld_urls = [o for o in url_obs if o.suspicious_tld]

        if threat_urls:
            url_insight = (
                f"🚨 **{len(threat_urls)} malicious URL(s)** "
                f"confirmed by VirusTotal.")
            url_color = DC['critical']
        elif shortener_urls:
            url_insight = (
                f"⚠️ **{len(shortener_urls)} shortened URL(s)** — "
                f"may hide destination.")
            url_color = DC['warning']
        elif sus_tld_urls:
            url_insight = (
                f"⚠️ **{len(sus_tld_urls)} suspicious TLD(s)**.")
            url_color = DC['warning']
        elif clean_urls and not threat_urls:
            url_insight = (
                f"✅ **All URLs verified clean** — "
                f"{len(clean_urls)} passed VT.")
            url_color = DC['success']
        else:
            url_insight = f"Scanned **{len(url_obs)}** observable(s)."
            url_color = DC['accent']
        cards.append({
            'icon': '🌍', 'title': 'URLs & Domains',
            'body': url_insight,
            'detail': f"{len(url_obs)} scanned",
            'color': url_color})

    # Card 8: BEC
    if bec and bec.score >= 25:
        cats = bec.triggered_categories
        if 'wire_transfer' in cats and 'urgency' in cats:
            bec_insight = (
                "🚨 **Classic wire fraud pattern** — urgent wire "
                "transfer language detected.")
        elif 'gift_cards' in cats:
            bec_insight = (
                "🚨 **Gift card scam** — requests for gift card "
                "purchases detected.")
        elif 'payment_redirect' in cats:
            bec_insight = (
                "🚨 **Payment redirect** — bank details change "
                "requested.")
        elif 'authority_claim' in cats:
            bec_insight = (
                "⚠️ **Authority claim** — sender claims executive "
                "authority.")
        else:
            bec_insight = bec.summary
        bec_color = DC['critical'] if bec.score >= 80 else DC['high']
        cards.append({
            'icon': '🎯', 'title': 'BEC / Social Engineering',
            'body': bec_insight,
            'detail': (
                f"Score: {bec.score} | "
                f"Triggered: {', '.join(cats)}"),
            'color': bec_color})

    # Card 9: Header Anomalies
    if ha and ha.anomalies:
        if ha.reply_to_hijack:
            ha_insight = (
                "🚨 **Reply-To hijack** — replies silently "
                "redirected to attacker.")
        else:
            ha_insight = (
                f"⚠️ **{len(ha.anomalies)} header anomaly(ies)**.")
        ha_color = DC['high'] if ha.reply_to_hijack else DC['warning']
        cards.append({
            'icon': '🔎', 'title': 'Header Anomalies',
            'body': ha_insight,
            'detail': ' | '.join(ha.anomalies[:3]),
            'color': ha_color})

    # Card 10: YARA
    all_yara_hits = [
        ym for m in macros for ym in m.yara_matches]
    critical_yara = [
        ym for ym in all_yara_hits if ym.severity == 'CRITICAL']
    if all_yara_hits:
        if critical_yara:
            yara_insight = (
                f"🚨 **{len(critical_yara)} CRITICAL YARA match(es)** — "
                f"**{critical_yara[0].rule_name}** fired.")
        else:
            yara_insight = (
                f"⚠️ **{len(all_yara_hits)} YARA rule(s) matched**.")
        yara_color = DC['critical'] if critical_yara else DC['high']
    else:
        yara_insight = "✅ **No YARA matches** — all rules clean."
        yara_color = DC['success'] if YARA_OK else DC['unknown']
    cards.append({
        'icon': '🔴', 'title': 'YARA Engine Results',
        'body': yara_insight,
        'detail': (
            f"{'YARA active' if YARA_OK else 'YARA offline'} | "
            f"9 rules | {len(all_yara_hits)} matches"),
        'color': yara_color})

    # Card 11: Scan Coverage
    total_obs = len(obs)
    vt_scanned = sum(
        1 for o in obs if o.vt_result and o.vt_result.success)
    cov_insight = (
        f"📊 **{total_obs} observables** analyzed — "
        f"VT: {vt_scanned}/{total_obs} | "
        f"**{len(macros)}** file(s) scanned.")
    cards.append({
        'icon': '📊', 'title': 'Scan Coverage',
        'body': cov_insight,
        'detail': (
            f"AbuseIPDB: "
            f"{'enabled' if (abuse and abuse.checked) else 'not configured'}"),
        'color': DC['accent']})

    return cards


def analyze_image_complete(part) -> Optional[ImageAnalysis]:
    """Analyze image attachments."""
    filename = part.get_filename() or "unknown_image"
    result = ImageAnalysis(filename=filename)

    try:
        img_data = part.get_payload(decode=True)
        if not img_data:
            return None

        result.image_data = img_data

        if PIL_OK:
            try:
                img = PilImage.open(io.BytesIO(img_data))
                result.format = img.format or ""
                result.size = img.size

                w, h = img.size
                if w <= 2 and h <= 2:
                    result.findings.append(
                        "⚠️ Tracking Pixel (≤2x2)")
                elif w <= 5 and h <= 5:
                    result.findings.append(
                        "⚠️ Suspicious micro-image")

                if QR_OK:
                    try:
                        decoded = decode_qr(img)
                        for d in decoded:
                            url = d.data.decode(
                                'utf-8', errors='ignore')
                            result.qr_links.append(url)
                            result.findings.append(
                                f"📱 QR Code: {url[:50]}")
                    except Exception as e:
                        logger.debug(f"QR decode error: {e}")

                if STEGANO_OK and img.format in [
                        'PNG', 'BMP', 'TIFF']:
                    try:
                        secret = lsb.reveal(io.BytesIO(img_data))
                        if secret:
                            result.has_steganography = True
                            result.findings.append(
                                "🚨 STEGANOGRAPHY: Hidden LSB data")
                    except Exception:
                        pass

            except Exception as e:
                result.findings.append(
                    f"Image parsing error: {str(e)[:100]}")
                logger.error(
                    f"Image analysis error for {filename}: {e}")
        else:
            result.findings.append("PIL unavailable")

    except Exception as e:
        logger.error(
            f"Critical image analysis failure for {filename}: {e}")
        return None

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT NARRATIVE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

ATTACK_PATTERNS = {
    'credential_phishing': {
        'indicators': [
            'html_form_with_credentials', 'spf_fail',
            'new_domain', 'redirect_chain',
            'link_text_mismatch', 'url_shortener'],
        'label': '🎣 Credential Phishing',
        'description': 'Designed to steal login credentials',
        'threshold': 2,
    },
    'malware_delivery': {
        'indicators': [
            'macro_dropper', 'executable_attachment',
            'malware_bazaar', 'yara_critical'],
        'label': '🦠 Malware Delivery',
        'description': 'Attempting to install malicious software',
        'threshold': 1,
    },
    'spear_phishing': {
        'indicators': [
            'display_name_spoof', 'shadow_spoofing',
            'typosquat', 'dmarc_fail'],
        'label': '🎯 Spear Phishing',
        'description': 'Impersonating a trusted entity',
        'threshold': 1,
    },
    'bec_attack': {
        'indicators': [
            'bec_wire_transfer', 'bec_gift_cards',
            'bec_authority', 'bec_payment_redirect'],
        'label': '💼 Business Email Compromise',
        'description': 'Financial fraud via social engineering',
        'threshold': 1,
    },
    'pdf_exploit': {
        'indicators': [
            'pdf_launch_action', 'pdf_javascript',
            'pdf_uri_malicious'],
        'label': '📄 PDF Exploit',
        'description': 'PDF exploiting reader vulnerabilities',
        'threshold': 1,
    },
    'clean': {
        'indicators': [],
        'label': '✅ Likely Legitimate',
        'description': 'No strong indicators detected',
        'threshold': 0,
    },
}

YARA_WHY = {
    'VBA_Macro_Dropper': (
        "combines download capability with auto-execute"),
    'Suspicious_PowerShell_In_Macro': (
        "launches PowerShell with evasion flags"),
    'PDF_Launch_Action': (
        "contains /Launch action that can execute programs"),
    'Executable_Magic_Bytes': "has MZ/PE/ELF file headers",
    'PDF_JavaScript_Exploit': (
        "contains PDF JavaScript with /OpenAction"),
    'VBA_Obfuscated_Code': (
        "contains multiple obfuscation functions"),
    'Phishing_Credential_Harvest': (
        "contains HTML form collecting credentials"),
    'Macro_Registry_Persistence': (
        "writes to Windows registry Run key"),
}


def generate_threat_narrative(
    observables, macros, auth, images, body_findings,
    header_anomaly: HeaderAnomalyResult,
    abuse_ip: AbuseIPResult,
    display_name_spoof: DisplayNameSpoofResult,
    attachment_risks: List[AttachmentRiskItem],
    bec: BECResult,
    link_mismatches: List[LinkTextMismatch],
    total_score: int, verdict: str, confidence: int,
) -> ThreatNarrative:
    """Generate threat narrative."""
    n = ThreatNarrative()
    active: Set[str] = set()

    all_yara = [m for macro in macros for m in macro.yara_matches]
    malware_hits = [
        m for m in macros
        if m.malware_bazaar and m.malware_bazaar.found]

    for risk in attachment_risks:
        if risk.risk_type == 'content_type_mismatch':
            active.add('content_type_mismatch')
        if risk.risk_type == 'double_extension':
            active.add('double_extension')
        if risk.risk_type == 'dangerous_extension':
            active.add('dangerous_extension')

    for ym in all_yara:
        if ym.rule_name in [
                'VBA_Macro_Dropper',
                'Suspicious_PowerShell_In_Macro']:
            active.add('macro_dropper')
            active.add('yara_critical')
        if ym.category == 'executable':
            active.add('executable_attachment')
            active.add('yara_critical')
        if ym.rule_name == 'Phishing_Credential_Harvest':
            active.add('html_form_with_credentials')
        if ym.rule_name == 'PDF_Launch_Action':
            active.add('pdf_launch_action')
        if ym.rule_name == 'PDF_JavaScript_Exploit':
            active.add('pdf_javascript')

    if malware_hits:
        active.add('malware_bazaar')
    if auth.spf == 'FAIL':
        active.add('spf_fail')
    if auth.dmarc == 'FAIL':
        active.add('dmarc_fail')
    if auth.shadow_spoofing:
        active.add('shadow_spoofing')
    if display_name_spoof.detected:
        active.add('display_name_spoof')
    if link_mismatches:
        active.add('link_text_mismatch')
    if any(o.is_shortener for o in observables):
        active.add('url_shortener')

    # BEC indicators
    if bec.score >= 50:
        if 'wire_transfer' in bec.triggered_categories:
            active.add('bec_wire_transfer')
        if 'gift_cards' in bec.triggered_categories:
            active.add('bec_gift_cards')
        if 'authority_claim' in bec.triggered_categories:
            active.add('bec_authority')
        if 'payment_redirect' in bec.triggered_categories:
            active.add('bec_payment_redirect')

    # Attack pattern classification
    best_pattern = 'clean'
    best_count = 0

    if total_score >= 40:
        for pname, pdata in ATTACK_PATTERNS.items():
            if pname == 'clean':
                continue
            matched = sum(
                1 for ind in pdata['indicators'] if ind in active)
            if matched >= pdata['threshold'] and matched > best_count:
                best_count = matched
                best_pattern = pname

    n.attack_pattern = best_pattern
    n.attack_label = ATTACK_PATTERNS[best_pattern]['label']
    n.attack_description = ATTACK_PATTERNS[best_pattern]['description']

    # Key signals
    signals = []

    if auth.spf == 'FAIL':
        signals.append({
            'signal': 'SPF Authentication Failed',
            'severity': 'HIGH',
            'score': ScoringWeights.SPF_FAIL,
            'why': f"Server not authorized for '{auth.from_domain}'"})
    elif auth.spf == 'SOFTFAIL':
        signals.append({
            'signal': 'SPF Softfail',
            'severity': 'MEDIUM',
            'score': ScoringWeights.SPF_SOFTFAIL,
            'why': 'Sender not fully authorized'})

    if auth.shadow_spoofing:
        signals.append({
            'signal': 'Shadow Spoofing',
            'severity': 'HIGH',
            'score': ScoringWeights.SHADOW_SPOOFING,
            'why': (
                f"From '{auth.from_domain}' vs "
                f"Return-Path '{auth.return_path_domain}'")})

    if display_name_spoof.detected:
        signals.append({
            'signal': 'Display Name Impersonation',
            'severity': 'HIGH',
            'score': display_name_spoof.score,
            'why': (
                f"Claims '{display_name_spoof.impersonated_brand}' "
                f"but from '{display_name_spoof.sender_domain}'")})

    for ltm in link_mismatches[:2]:
        signals.append({
            'signal': 'Link-Text Mismatch',
            'severity': 'HIGH',
            'score': ScoringWeights.LINK_TEXT_MISMATCH,
            'why': (
                f"Shows '{ltm.display_domain}' but "
                f"links to '{ltm.href_domain}'")})

    for ym in [
            m for m in all_yara
            if m.severity == 'CRITICAL'][:3]:
        why = YARA_WHY.get(
            ym.rule_name, f"Matches pattern: {ym.rule_name}")
        signals.append({
            'signal': f'YARA: {ym.rule_name}',
            'severity': 'CRITICAL',
            'score': ScoringWeights.YARA_CRITICAL,
            'why': why})

    if malware_hits:
        m = malware_hits[0]
        signals.append({
            'signal': f'Known Malware: {m.filename}',
            'severity': 'CRITICAL',
            'score': ScoringWeights.MALWARE_BAZAAR_HIT,
            'why': (
                f"SHA256 matches confirmed malware: "
                f"{m.malware_bazaar.malware_family}")})

    if (abuse_ip.checked
            and abuse_ip.abuse_score >= Thresholds.ABUSE_IP_MEDIUM):
        is_cloud = is_cloud_provider(abuse_ip.isp)
        is_authorized = (auth.spf == 'PASS' or auth.gateway_trust)

        if not (is_cloud and is_authorized):
            score_contrib = (
                ScoringWeights.ABUSEIPDB_HIGH
                if abuse_ip.threat_level in ['CRITICAL', 'HIGH']
                else ScoringWeights.ABUSEIPDB_MEDIUM)
            signals.append({
                'signal': (
                    f'Malicious Source IP — AbuseIPDB: '
                    f'{abuse_ip.abuse_score}/100'),
                'severity': 'HIGH',
                'score': score_contrib,
                'why': (
                    f"IP has {abuse_ip.total_reports} abuse reports. "
                    f"ISP: {abuse_ip.isp}")})

    if bec.score >= 50:
        signals.append({
            'signal': 'BEC Indicators',
            'severity': 'HIGH',
            'score': bec.score,
            'why': f"BEC patterns: {bec.summary}"})

    signals.sort(key=lambda x: x['score'], reverse=True)
    n.key_signals = signals[:7]

    # Correlations
    correlations = []
    if 'spf_fail' in active and 'display_name_spoof' in active:
        correlations.append("🔗 SPF FAIL + Display Name Spoof")
    if ('html_form_with_credentials' in active
            and ('spf_fail' in active or 'new_domain' in active)):
        correlations.append("🔗 Credential Harvest + Auth Failure")
    if 'link_text_mismatch' in active and 'spf_fail' in active:
        correlations.append(
            "🔗 Link-Text Mismatch + Auth Failure")
    if ('bec_wire_transfer' in active
            and 'shadow_spoofing' in active):
        correlations.append(
            "🔗 Wire Transfer BEC + Shadow Spoofing")
    n.correlated_findings = correlations

    # Mitigating factors
    mitigating = []
    if auth.gateway_trust:
        mitigating.append(f"Trusted Gateway: {auth.gateway_name}")
    if auth.dkim == 'PASS' and auth.spf == 'PASS':
        mitigating.append("Both SPF and DKIM passed")

    risky_macros = [m for m in macros if m.risk_score > 20]
    if macros and not risky_macros and not attachment_risks:
        mitigating.append(
            f"All {len(macros)} attachment(s) verified clean")

    url_obs = [o for o in observables if o.type == 'url']
    if url_obs:
        clean_urls = [
            o for o in url_obs
            if o.vt_result
            and o.vt_result.threat_level in ['CLEAN', 'LOW', 'SAFE']]
        if len(clean_urls) == len(url_obs):
            mitigating.append(
                f"All {len(url_obs)} URL(s) verified clean")

    n.mitigating_factors = mitigating

    # Score breakdown
    bd = []
    if auth.spf == 'FAIL':
        bd.append({
            'source': 'SPF FAIL',
            'pts': ScoringWeights.SPF_FAIL, 'cat': 'AUTH'})
    elif auth.spf == 'SOFTFAIL':
        bd.append({
            'source': 'SPF SOFTFAIL',
            'pts': ScoringWeights.SPF_SOFTFAIL, 'cat': 'AUTH'})
    if display_name_spoof.detected:
        bd.append({
            'source': 'Display Name Spoof',
            'pts': display_name_spoof.score, 'cat': 'SPOOF'})
    if link_mismatches:
        bd.append({
            'source': 'Link-Text Mismatch',
            'pts': ScoringWeights.LINK_TEXT_MISMATCH,
            'cat': 'PHISHING'})
    bd.sort(key=lambda x: x['pts'], reverse=True)
    n.score_breakdown = bd[:8]

    # Analyst notes
    notes = []
    if total_score >= 80:
        notes.append("⛔ ACTION: Quarantine immediately")
    elif total_score >= 50:
        notes.append("⚠️ ACTION: Hold for manual review")
    elif total_score >= 20:
        notes.append("🔍 ACTION: Soft quarantine / user warning")
    else:
        notes.append("✅ ACTION: Release to inbox")
    n.analyst_notes = notes

    n.verdict_explanation = (
        f"Score {total_score} — "
        + ('Threat signals present' if total_score >= 50
           else 'No significant threats'))

    return n


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_forensic_report(report: Dict) -> str:
    """Generate comprehensive text report.

    FIX: Now includes BEC, header anomalies, display name spoof,
    attachment risks, link mismatches, and received chain analysis.
    """
    lines = []
    sep = "=" * 100

    lines += [
        sep,
        "FORENSIC EMAIL ANALYSIS REPORT — SHERLOCK v9.0 (HARDENED)",
        sep,
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"MD5: {report['hashes']['md5']}",
        f"SHA256: {report['hashes']['sha256']}",
        "",
        f"VERDICT: {report['verdict']}",
        (f"Threat: {report['threat_level']} | "
         f"Confidence: {report['confidence']}% | "
         f"Score: {report['threat_score']}"),
        "",
    ]

    # Authentication
    auth = report['auth']
    lines += [
        sep, "AUTHENTICATION", sep,
        (f"SPF: {auth.spf} | DKIM: {auth.dkim} | "
         f"DMARC: {auth.dmarc}"),
    ]
    if auth.source_ip:
        lines.append(f"Source IP: {auth.source_ip}")
    if auth.gateway_trust:
        lines.append(f"Gateway: {auth.gateway_name} (Trusted)")
    if auth.hop_count:
        lines.append(f"Received Hops: {auth.hop_count}")
    if auth.hop_anomaly:
        lines.append(f"Hop Anomaly: {auth.hop_anomaly}")
    for detail in auth.detailed_analysis[:10]:
        lines.append(f"  - {detail}")

    # Display Name Spoof
    dns_spoof = report.get('display_name_spoof')
    if dns_spoof and dns_spoof.detected:
        lines += ["", sep, "DISPLAY NAME SPOOFING", sep]
        lines.append(
            f"Display Name: {dns_spoof.display_name}")
        lines.append(
            f"Sender Domain: {dns_spoof.sender_domain}")
        lines.append(
            f"Impersonated: {dns_spoof.impersonated_brand}")
        for f in dns_spoof.findings:
            lines.append(f"  - {f}")

    # BEC
    bec = report.get('bec')
    if bec and bec.score > 0:
        lines += ["", sep, "BEC ANALYSIS", sep]
        lines.append(
            f"Risk Level: {bec.risk_level} | "
            f"Score: {bec.score}")
        lines.append(f"Summary: {bec.summary}")
        for f in bec.findings:
            lines.append(f"  - {f}")

    # Header Anomalies
    ha = report.get('header_anomaly')
    if ha and ha.anomalies:
        lines += ["", sep, "HEADER ANOMALIES", sep]
        for a in ha.anomalies:
            lines.append(f"  - {a}")

    # Link-Text Mismatches
    link_mismatches = report.get('link_mismatches', [])
    if link_mismatches:
        lines += ["", sep, "LINK-TEXT MISMATCHES", sep]
        for ltm in link_mismatches:
            lines.append(
                f"  Display: {ltm.display_domain} -> "
                f"Actual: {ltm.href_domain}")

    # AbuseIPDB
    abuse = report.get('abuse_ip')
    if abuse and abuse.checked:
        lines += ["", sep, "IP REPUTATION (AbuseIPDB)", sep]
        lines.append(
            f"Score: {abuse.abuse_score}/100 | "
            f"Reports: {abuse.total_reports}")
        lines.append(
            f"ISP: {abuse.isp} | Country: {abuse.country}")
        if abuse.is_tor:
            lines.append("TOR EXIT NODE DETECTED")

    # Threat Narrative
    narr = report.get('narrative')
    if narr:
        lines += [
            "", sep, "THREAT NARRATIVE", sep,
            f"Attack Pattern: {narr.attack_label}",
            f"Explanation: {narr.verdict_explanation}",
        ]
        if narr.key_signals:
            lines.append("\nKey Signals:")
            for s in narr.key_signals[:5]:
                lines.append(
                    f"  [{s['severity']}] +{s['score']}  "
                    f"{s['signal']}")
                lines.append(f"    {s['why'][:120]}")

    # Attachments
    lines += ["", sep, "ATTACHMENTS", sep]
    if report['macros']:
        for macro in report['macros']:
            lines.append(
                f"File: {macro.filename} | "
                f"Risk: {macro.risk_score}/100 | "
                f"{macro.verdict}")
            if macro.file_sha256:
                lines.append(f"  SHA256: {macro.file_sha256}")
            if macro.malware_bazaar and macro.malware_bazaar.found:
                lines.append(
                    f"  MALWARE: {macro.malware_bazaar.malware_family}")
    else:
        lines.append("No attachments")

    # Attachment Risks
    att_risks = report.get('attachment_risks', [])
    if att_risks:
        lines += ["", sep, "ATTACHMENT RISKS", sep]
        for risk in att_risks:
            lines.append(
                f"  [{risk.severity}] {risk.filename}: "
                f"{risk.description}")

    # Findings
    if report['findings']:
        lines += ["", sep, "ALL FINDINGS", sep]
        for f in report['findings']:
            lines.append(
                f"  [{f.get('threat', '?')}] "
                f"{f.get('category', '?')}: "
                f"{f.get('reasoning', '?')}")

    # Recommendation
    lines += ["", sep, "RECOMMENDATION", sep]
    if report['verdict'] == "CLEAN":
        lines.append("RELEASE EMAIL — No threats detected")
    elif report['verdict'] in ["MALICIOUS", "LIKELY MALICIOUS"]:
        lines.append("BLOCK/QUARANTINE EMAIL — Threats confirmed")
    else:
        lines.append("MANUAL REVIEW REQUIRED")

    lines.append(sep)
    return '\n'.join(lines)


def generate_pdf_report(text_report: str) -> Optional[io.BytesIO]:
    """Generate PDF report."""
    if not PDF_OK:
        return None

    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle(
            'Title', parent=styles['Heading1'],
            alignment=1, spaceAfter=20)

        code_style = ParagraphStyle(
            'Code', parent=styles['Normal'],
            fontName='Courier', fontSize=9,
            leading=11, spaceAfter=2)

        story.append(Paragraph(
            "Sherlock Forensic Report — v9.0 (Hardened)",
            title_style))
        story.append(Spacer(1, 12))

        for line in text_report.split('\n'):
            if "=====" in line:
                story.append(Spacer(1, 8))
            else:
                sanitized = safe_html_escape(line).replace(
                    ' ', '&nbsp;')
                if not sanitized.strip():
                    story.append(Spacer(1, 4))
                else:
                    story.append(Paragraph(sanitized, code_style))

        doc.build(story)
        buffer.seek(0)
        return buffer

    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ANALYSIS ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_email_complete(msg_bytes: bytes, status_container,
                           progress_bar):
    """Main analysis function."""

    if len(msg_bytes) > SecurityLimits.MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File exceeds {SecurityLimits.MAX_FILE_SIZE_MB}MB limit")

    msg = email.message_from_bytes(
        msg_bytes, policy=email.policy.default)
    subject = str(msg.get('Subject', ''))
    from_addr = str(msg.get('From', ''))

    # Extract org domain for smart display name checking
    org_domain = ""
    delivered_to = str(msg.get('Delivered-To', ''))
    if '@' in delivered_to:
        parts = delivered_to.split('@')
        if len(parts) == 2:
            org_domain = parts[1].strip().lower()

    if not org_domain:
        to_header = str(msg.get('To', ''))
        to_match = SecurePatterns.DOMAIN_FROM_EMAIL.search(to_header)
        if to_match:
            org_domain = to_match.group(1).lower()

    # Extract observables
    update_status(
        status_container, "Extracting observables...", "🔍")
    progress_bar.progress(5)
    observables = extract_observables(msg)

    # Extract body
    body_content = ""
    body_text = ""
    for part in msg.walk():
        ct = part.get_content_type()
        if ct == 'text/html':
            try:
                d = part.get_payload(decode=True)
                if d:
                    body_content += d.decode(
                        'utf-8', errors='ignore')
            except Exception:
                pass
        elif ct == 'text/plain':
            try:
                d = part.get_payload(decode=True)
                if d:
                    body_text += d.decode(
                        'utf-8', errors='ignore')
            except Exception:
                pass

    combined_body = body_content + body_text

    # Detect tracking pixels and suspicious language
    body_findings = detect_tracking_pixels(body_content)
    lang_hits = analyze_suspicious_language(
        combined_body, subject)
    body_findings.extend(lang_hits)

    # Link-text mismatch detection
    update_status(
        status_container, "Checking link-text mismatches...",
        "🔗", DesignSystem.COLORS['accent_purple'])
    link_mismatches = detect_link_text_mismatches(body_content)
    if link_mismatches:
        update_status(
            status_container,
            f"⚠️ {len(link_mismatches)} link-text mismatch(es) found",
            "🚨", DesignSystem.COLORS['critical'])

    # BEC analysis
    update_status(
        status_container, "BEC pattern analysis...",
        "🎯", DesignSystem.COLORS['high'])
    try:
        bec = analyze_bec(combined_body, subject, from_addr)
    except Exception as e:
        logger.error(f"BEC analysis failed: {e}")
        bec = BECResult()
    progress_bar.progress(8)

    # Header anomaly analysis
    update_status(
        status_container, "Scanning header anomalies...",
        "🔎", DesignSystem.COLORS['accent_purple'])
    try:
        header_anomaly = analyze_header_anomalies(msg)
    except Exception as e:
        logger.error(f"Header anomaly failed: {e}")
        header_anomaly = HeaderAnomalyResult()
    progress_bar.progress(12)

    # Display name spoof check
    update_status(
        status_container, "Checking display name spoofing...",
        "🎭", DesignSystem.COLORS['high'])
    try:
        display_name_spoof = analyze_display_name_spoof(
            msg, org_domain)
        if display_name_spoof.detected:
            update_status(
                status_container,
                (f"⚠️ Display name spoof: "
                 f"{display_name_spoof.impersonated_brand}"),
                "🚨", DesignSystem.COLORS['critical'])
    except Exception as e:
        logger.error(f"Display name check failed: {e}")
        display_name_spoof = DisplayNameSpoofResult()
    progress_bar.progress(16)

    # Authentication analysis
    update_status(
        status_container,
        "Verifying email authentication (Live DNS)...",
        "🔐", DesignSystem.COLORS['accent'])
    try:
        auth = analyze_authentication(msg)
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        auth = AuthResult()
    progress_bar.progress(22)

    # AbuseIPDB
    abuse_ip = AbuseIPResult()
    if auth.source_ip and Config.ABUSEIPDB_KEY:
        update_status(
            status_container,
            f"Checking source IP reputation: {auth.source_ip}",
            "🌐")
        try:
            abuse_ip = check_abuseipdb(auth.source_ip)
        except Exception as e:
            logger.error(f"AbuseIPDB failed: {e}")
    progress_bar.progress(28)

    # VT observable scanning
    obs_to_check = [
        o for o in observables
        if o.type in ['url', 'domain', 'ip']
    ][:Config.MAX_OBSERVABLES_TO_CHECK]

    if obs_to_check:
        total_obs = len(obs_to_check)
        completed_obs = 0

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(check_single_observable, o): o
                for o in obs_to_check}
            for future in as_completed(futures):
                completed_obs += 1
                try:
                    result_obs = future.result()
                    for i, o in enumerate(observables):
                        if o.value == result_obs.value:
                            observables[i] = result_obs
                    pct = 28 + int(
                        (completed_obs / total_obs) * 35)
                    progress_bar.progress(pct)
                except Exception as e:
                    logger.error(
                        f"Observable check failed: {e}")

    progress_bar.progress(65)

    # Attachment analysis
    update_status(
        status_container, "Scanning attachments...",
        "📎", DesignSystem.COLORS['high'])
    macros = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue

        fname = part.get_filename()
        if not fname:
            continue

        try:
            data = part.get_payload(decode=True)
            if data:
                macro = analyze_macro_complete(data, fname)
                if macro:
                    macros.append(macro)

                    if macro.pdf_uris:
                        pdf_obs_list = [
                            Observable(
                                type='url', value=u,
                                defanged=defang(u),
                                source='pdf_uri')
                            for u in macro.pdf_uris
                            if u.startswith(('http', 'ftp'))]

                        with ThreadPoolExecutor(
                                max_workers=4) as ex:
                            f2obs = {
                                ex.submit(check_vt_url, o.value): o
                                for o in pdf_obs_list}
                            for fut in as_completed(f2obs):
                                o = f2obs[fut]
                                try:
                                    res = fut.result()
                                    o.vt_result = res
                                    if (res and res.success
                                            and res.threat_level in [
                                                "CRITICAL",
                                                "MALICIOUS"]):
                                        o.threat_score = 100
                                        o.reputation = 'malicious'
                                    elif (res and res.success
                                          and res.threat_level
                                          == "SUSPICIOUS"):
                                        o.threat_score = 50
                                        o.reputation = 'suspicious'
                                except Exception:
                                    pass
                                observables.append(o)
        except Exception as e:
            logger.error(
                f"Attachment analysis failed for {fname}: {e}")

    try:
        attachment_risks = analyze_attachment_risks(msg)
    except Exception as e:
        logger.error(f"Attachment risk analysis failed: {e}")
        attachment_risks = []

    # YARA scan on body
    if YARA_OK and combined_body:
        try:
            body_yara = yara_scan_bytes(
                combined_body.encode('utf-8', errors='ignore'),
                'email_body')
            if body_yara:
                bm = MacroResult(
                    filename="[Email Body]",
                    file_type="HTML/Text",
                    yara_matches=body_yara)
                bm.risk_score = yara_score_from_matches(body_yara)
                bm.verdict = f"YARA: {body_yara[0].rule_name}"
                for ym in body_yara:
                    bm.details.append(
                        f"🔴 YARA [{ym.severity}] {ym.rule_name}")
                macros.append(bm)
        except Exception as e:
            logger.error(f"Body YARA scan failed: {e}")

    progress_bar.progress(85)

    # Image forensics
    update_status(
        status_container, "Performing image forensics...",
        "🖼️", DesignSystem.COLORS['medium'])
    images = []
    for part in msg.walk():
        if part.get_content_type().startswith('image/'):
            try:
                img_analysis = analyze_image_complete(part)
                if img_analysis:
                    images.append(img_analysis)

                    for qr_link in img_analysis.qr_links:
                        qr_obs = Observable(
                            type='url', value=qr_link,
                            defanged=defang(qr_link),
                            source='image_qr')
                        try:
                            qr_obs.vt_result = check_vt_url(qr_link)
                            if (qr_obs.vt_result
                                    and qr_obs.vt_result.threat_level
                                    in ["CRITICAL", "MALICIOUS"]):
                                qr_obs.threat_score = 100
                                qr_obs.reputation = 'malicious'
                        except Exception:
                            pass
                        observables.append(qr_obs)
            except Exception as e:
                logger.error(f"Image forensics failed: {e}")

    progress_bar.progress(92)
    update_status(
        status_container, "Calculating verdict...", "⚖️")

    # Calculate verdict
    try:
        verdict, threat_level, confidence, findings, threat_score = (
            calculate_verdict(
                observables, macros, auth, images, body_findings,
                bec, header_anomaly, abuse_ip, display_name_spoof,
                attachment_risks, link_mismatches))
    except Exception as e:
        logger.error(f"Verdict calculation failed: {e}")
        verdict = "ERROR"
        threat_level = "UNKNOWN"
        confidence = 0
        findings = []
        threat_score = 0

    # Generate narrative
    try:
        narrative = generate_threat_narrative(
            observables, macros, auth, images, body_findings,
            header_anomaly, abuse_ip, display_name_spoof,
            attachment_risks, bec, link_mismatches,
            threat_score, verdict, confidence)
    except Exception as e:
        logger.error(f"Narrative generation failed: {e}")
        narrative = ThreatNarrative()

    # Compile report
    report = {
        'verdict': verdict,
        'threat_level': threat_level,
        'confidence': confidence,
        'threat_score': threat_score,
        'findings': findings,
        'observables': observables,
        'macros': macros,
        'images': images,
        'auth': auth,
        'narrative': narrative,
        'bec': bec,
        'header_anomaly': header_anomaly,
        'abuse_ip': abuse_ip,
        'display_name_spoof': display_name_spoof,
        'attachment_risks': attachment_risks,
        'link_mismatches': link_mismatches,
        'hashes': {
            'md5': hashlib.md5(msg_bytes).hexdigest(),
            'sha256': hashlib.sha256(msg_bytes).hexdigest(),
        },
        'metadata': {
            'from': from_addr,
            'subject': subject,
            'date': str(msg.get('Date', '')),
        },
    }

    progress_bar.progress(100)
    verdict_color = DesignSystem.get_threat_color(threat_level)
    update_status(
        status_container,
        f"Analysis complete! Verdict: {verdict}",
        "✅", verdict_color)
    time.sleep(0.5)

    return report


# ═══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Main Streamlit application."""
    DC = DesignSystem.COLORS
    DS = DesignSystem.SHADOWS

    st.set_page_config(
        page_title="Sherlock — Forensic Analyzer v9.0",
        layout="wide", page_icon="🔍")

    st.markdown(f"""<style>
.main{{background:linear-gradient(135deg,{DC['bg_dark']} 0%,#1a1f2e 100%)}}
.stProgress > div > div > div > div{{background-image:linear-gradient(90deg,{DC['accent']},{DC['accent_purple']},{DC['high']});border-radius:10px}}
.stTabs [data-baseweb="tab-list"]{{gap:6px;background:{DC['bg_card']};padding:8px;border-radius:10px}}
.stTabs [data-baseweb="tab"]{{border-radius:8px;padding:10px 18px}}
.stTabs [aria-selected="true"]{{background:linear-gradient(135deg,{DC['accent']},{DC['accent_purple']});box-shadow:{DS['glow']}}}
[data-testid="stMetricValue"]{{font-size:2em;font-weight:700;background:linear-gradient(135deg,{DC['accent']},{DC['accent_purple']});-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
</style>""", unsafe_allow_html=True)

    st.title("🔍 SHERLOCK — FORENSIC EMAIL ANALYZER")
    st.caption(
        "v9.0 (HARDENED) | YARA • MalwareBazaar • AbuseIPDB • "
        "BEC Engine • Link-Text Mismatch • Smart Threat Narrative")

    if 'report_data' not in st.session_state:
        st.session_state.report_data = None
    if 'uploaded_file_hash' not in st.session_state:
        st.session_state.uploaded_file_hash = None

    # Sidebar
    with st.sidebar:
        st.markdown("### 📧 Upload Email")
        uploaded = st.file_uploader("Select .eml file", type=['eml'])

        if uploaded:
            file_bytes = uploaded.getvalue()
            file_hash = hashlib.md5(file_bytes).hexdigest()
            file_size_mb = len(file_bytes) / (1024 * 1024)

            if file_size_mb > Config.MAX_FILE_SIZE_MB:
                st.error(
                    f"❌ File exceeds "
                    f"{Config.MAX_FILE_SIZE_MB}MB limit")
                st.stop()

            st.success(f"✅ Loaded ({file_size_mb:.2f} MB)")

            if st.session_state.uploaded_file_hash != file_hash:
                st.session_state.uploaded_file_hash = file_hash
                st.session_state.report_data = None

        st.divider()
        st.markdown("### ✅ Module Status")

        status_items = [
            ("OleTools", OLETOOLS_OK),
            ("PIL (Image)", PIL_OK),
            ("WHOIS", WHOIS_OK),
            ("QR Decoder", QR_OK),
            ("YARA (9 rules)", YARA_OK),
            ("AbuseIPDB", bool(Config.ABUSEIPDB_KEY)),
            ("VirusTotal", bool(Config.VIRUSTOTAL_API_KEY)),
        ]

        for name, ok in status_items:
            st.metric(name, "✅ Online" if ok else "⚠️ Offline")

        if not YARA_OK:
            st.code("pip install yara-python")
        if not Config.VIRUSTOTAL_API_KEY:
            st.warning("⚠️ Add vt_api_key to secrets.toml")
        if not Config.ABUSEIPDB_KEY:
            st.info("💡 Add abuseipdb_key for IP reputation")

    # Main content
    if not uploaded:
        st.info("👆 Upload an .eml file to begin analysis")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(
                "**🔒 Security Hardened**\n"
                "- ReDoS protection\n"
                "- Secure temp files\n"
                "- Input validation")
        with col2:
            st.markdown(
                "**🧠 Smart Analysis**\n"
                "- Attack pattern ID\n"
                "- Link-text mismatch\n"
                "- Org-aware spoofing")
        with col3:
            st.markdown(
                "**🔴 Deep Inspection**\n"
                "- YARA + MalwareBazaar\n"
                "- PDF URI forensics\n"
                "- Office link extraction")
        return

    # Perform analysis
    try:
        if st.session_state.report_data is None:
            progress_bar = st.progress(0)
            status_container = st.empty()

            start = time.time()
            st.session_state.report_data = analyze_email_complete(
                file_bytes, status_container, progress_bar)
            elapsed = time.time() - start

            progress_bar.empty()
            status_container.empty()
            st.success(f"✅ Analysis complete in {elapsed:.1f}s")

        report = st.session_state.report_data
        txt_report = generate_forensic_report(report)

        # Display verdict
        tc = DesignSystem.get_threat_color(report['threat_level'])
        ti = get_threat_icon(report['threat_level'])

        st.markdown(
            f"""<div style='background:linear-gradient(135deg,"""
            f"""{DC['bg_card']},{DC['bg_elevated']});"""
            f"""padding:20px;border-radius:12px;margin:20px 0;"""
            f"""border-left:5px solid {tc};"""
            f"""box-shadow:{DS['elevated']}'>"""
            f"""<h2 style='margin:0;color:{DC['text_primary']}'>"""
            f"""{ti} Verdict: """
            f"""{safe_html_escape(report['verdict'])}</h2>"""
            f"""<p style='margin:10px 0 0 0;"""
            f"""color:{DC['text_secondary']};font-size:1.05em'>"""
            f"""<b>Threat:</b> """
            f"""{safe_html_escape(report['threat_level'])} | """
            f"""<b>Confidence:</b> {report['confidence']}% | """
            f"""<b>Score:</b> {report['threat_score']}"""
            f"""</p></div>""",
            unsafe_allow_html=True)

        # Tabs
        (tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8) = st.tabs([
            "📋 Report & Intelligence",
            "🔐 Authentication",
            "🌐 URLs & Domains",
            "📎 Attachments",
            "🔴 YARA Results",
            "🖼️ Images",
            "📊 Findings",
            "💾 Export",
        ])

        # Tab 1: Report & Intelligence
        with tab1:
            auth_obj = report['auth']
            narr = report.get('narrative')

            # Reasoning cards
            st.markdown(
                f"<div style='background:linear-gradient(135deg,"
                f"{DC['bg_card']},{DC['bg_elevated']});"
                f"border:2px solid {DC['accent_purple']};"
                f"border-left:6px solid {DC['accent_purple']};"
                f"border-radius:12px;padding:16px 20px;"
                f"margin:12px 0'>"
                f"<div style='font-size:1.2em;font-weight:700;"
                f"color:{DC['accent_purple']}'>🧠 REASONING</div>"
                f"<div style='color:{DC['text_secondary']};"
                f"font-size:.85em'>Analytical insights</div></div>",
                unsafe_allow_html=True)

            try:
                reasoning_cards = generate_reasoning_summary(report)
            except Exception as _re:
                logger.error(f"Reasoning summary failed: {_re}")
                reasoning_cards = []

            for i in range(0, len(reasoning_cards), 2):
                cols = st.columns(2)
                for j, col in enumerate(cols):
                    if i + j < len(reasoning_cards):
                        card = reasoning_cards[i + j]
                        c = card['color']
                        body_html = re.sub(
                            r'\*\*(.+?)\*\*', r'<b>\1</b>',
                            html.escape(card['body']))
                        with col:
                            st.markdown(
                                f"<div style='background:"
                                f"linear-gradient(135deg,"
                                f"{DC['bg_card']},"
                                f"{DC['bg_elevated']});"
                                f"border:1px solid {c}55;"
                                f"border-left:4px solid {c};"
                                f"border-radius:10px;"
                                f"padding:14px 16px;"
                                f"margin:6px 0'>"
                                f"<div style='font-weight:700;"
                                f"color:{c};margin-bottom:6px;"
                                f"font-size:.95em'>"
                                f"{card['icon']} "
                                f"{html.escape(card['title'])}</div>"
                                f"<div style='color:"
                                f"{DC['text_primary']};"
                                f"font-size:.88em;margin-bottom:6px;"
                                f"line-height:1.45'>"
                                f"{body_html}</div>"
                                f"<div style='color:"
                                f"{DC['text_secondary']};"
                                f"font-size:.76em;border-top:1px "
                                f"solid {DC['border']};"
                                f"padding-top:5px;margin-top:4px'>"
                                f"{html.escape(card['detail'][:160])}"
                                f"</div></div>",
                                unsafe_allow_html=True)

            # Threat Narrative
            if narr and narr.key_signals:
                st.markdown(
                    f"<div style='background:linear-gradient(135deg,"
                    f"{DC['bg_card']},{DC['bg_elevated']});"
                    f"border:2px solid {DC['accent']};"
                    f"border-left:6px solid {DC['accent']};"
                    f"border-radius:12px;padding:16px 20px;"
                    f"margin:16px 0'>"
                    f"<div style='font-size:1.2em;font-weight:700;"
                    f"color:{DC['accent']}'>🎯 THREAT NARRATIVE"
                    f"</div></div>",
                    unsafe_allow_html=True)

                narr_color = DesignSystem.get_threat_color(
                    report['threat_level'])
                st.markdown(
                    f"<div style='background:{narr_color}15;"
                    f"border-left:5px solid {narr_color};"
                    f"border-radius:10px;padding:16px 18px;"
                    f"margin-bottom:14px'>"
                    f"<h4 style='margin:0 0 6px 0;"
                    f"color:{narr_color}'>"
                    f"{html.escape(narr.attack_label)}</h4>"
                    f"<div style='color:{DC['text_secondary']};"
                    f"font-size:.9em'>"
                    f"{html.escape(narr.attack_description)}</div>"
                    f"<div style='margin-top:8px;"
                    f"color:{DC['text_primary']};font-size:.9em'>"
                    f"<strong>Assessment:</strong> "
                    f"{html.escape(narr.verdict_explanation)}</div>"
                    f"</div>",
                    unsafe_allow_html=True)

                st.markdown("##### 🔑 Key Signals")
                for sig in narr.key_signals:
                    sc = DesignSystem.get_threat_color(sig['severity'])
                    sc_txt = DesignSystem.badge_text_color(sc)
                    st.markdown(
                        f"<div style='background:{DC['bg_dark']}55;"
                        f"border-radius:8px;padding:12px 14px;"
                        f"margin:8px 0;border-left:4px solid {sc}'>"
                        f"<div style='display:flex;"
                        f"justify-content:space-between;"
                        f"align-items:flex-start;flex-wrap:wrap;"
                        f"gap:6px'>"
                        f"<span style='font-weight:700;color:{sc};"
                        f"font-size:.95em'>"
                        f"{html.escape(sig['signal'])}</span>"
                        f"<span style='background:{sc};"
                        f"color:{sc_txt};padding:1px 8px;"
                        f"border-radius:10px;font-size:.72em;"
                        f"font-weight:700'>"
                        f"{sig['severity']} +{sig['score']}</span>"
                        f"</div>"
                        f"<div style='color:{DC['text_secondary']};"
                        f"font-size:.85em;margin-top:5px'>"
                        f"<span style='color:{DC['border']}'>"
                        f"Why: </span>"
                        f"{html.escape(sig['why'])}</div></div>",
                        unsafe_allow_html=True)

                if narr.mitigating_factors:
                    st.markdown("##### ✅ Mitigating Factors")
                    for m_fact in narr.mitigating_factors:
                        st.success(f"✓ {m_fact}")

                if narr.analyst_notes:
                    for note in narr.analyst_notes:
                        if note.startswith("⛔"):
                            st.error(note)
                        elif note.startswith("⚠️"):
                            st.warning(note)
                        else:
                            st.success(note)

        # Tab 2: Authentication
        with tab2:
            st.subheader("🔐 Email Authentication")
            auth = report['auth']
            col1, col2, col3, col4 = st.columns(4)
            col1.metric(
                "SPF", auth.spf,
                delta=("Valid" if auth.spf == "PASS"
                       else "Issue"),
                delta_color=(
                    "normal" if auth.spf == "PASS"
                    else "inverse"))
            col2.metric(
                "DKIM", auth.dkim,
                delta=("Valid" if auth.dkim == "PASS"
                       else "Issue"),
                delta_color=(
                    "normal" if auth.dkim == "PASS"
                    else "inverse"))
            col3.metric(
                "DMARC", auth.dmarc,
                delta=("Valid" if auth.dmarc == "PASS"
                       else "Issue"),
                delta_color=(
                    "normal" if auth.dmarc == "PASS"
                    else "inverse"))
            col4.metric("Hops", auth.hop_count)

            if auth.gateway_trust:
                st.success(
                    f"✅ **Trusted Gateway:** {auth.gateway_name}")
            if auth.shadow_spoofing:
                st.error(
                    f"🚨 Shadow spoofing: From={auth.from_domain} "
                    f"vs Return-Path={auth.return_path_domain}")
            if auth.hop_anomaly:
                st.warning(auth.hop_anomaly)

            abuse_ip_rep = report.get('abuse_ip')
            if abuse_ip_rep and abuse_ip_rep.checked:
                ip_color = DesignSystem.get_threat_color(
                    abuse_ip_rep.threat_level)
                st.markdown(
                    f"<div style='border-left:4px solid {ip_color};"
                    f"background:{ip_color}22;padding:14px;"
                    f"border-radius:8px;margin:12px 0'>"
                    f"<b>🌐 Source IP (AbuseIPDB)</b><br>"
                    f"Score: <b style='color:{ip_color}'>"
                    f"{abuse_ip_rep.abuse_score}/100</b> | "
                    f"Reports: {abuse_ip_rep.total_reports} | "
                    f"Country: {abuse_ip_rep.country} | "
                    f"ISP: {html.escape((abuse_ip_rep.isp or '')[:40])}"
                    + ("| 🧅 TOR" if abuse_ip_rep.is_tor else "")
                    + "</div>",
                    unsafe_allow_html=True)

            dns_obj_rep = report.get('display_name_spoof')
            if dns_obj_rep and dns_obj_rep.detected:
                for finding in dns_obj_rep.findings:
                    st.error(finding)

            st.markdown("#### 📋 Detailed Analysis")
            for detail in auth.detailed_analysis:
                upper = detail.upper()
                if any(kw in upper for kw in [
                        "WARNING", "FAIL", "SPOOF"]):
                    st.error(f"⚠️ {detail}")
                elif any(kw in upper for kw in [
                        "PASS", "VERIFIED", "TRUSTED", "CLEAN"]):
                    st.success(f"✅ {detail}")
                else:
                    st.info(f"ℹ️ {detail}")

            ha = report.get('header_anomaly')
            if ha and ha.anomalies:
                st.divider()
                st.markdown("#### 🔎 Header Anomalies")
                for anomaly in ha.anomalies:
                    if "🚨" in anomaly:
                        st.error(anomaly)
                    else:
                        st.warning(anomaly)

        # Tab 3: URLs & Domains
        with tab3:
            st.subheader("🌐 URL, Domain & IP Analysis")

            # Link-text mismatches
            ltms = report.get('link_mismatches', [])
            if ltms:
                st.error(
                    f"🚨 **{len(ltms)} link-text mismatch(es) "
                    f"detected** — displayed domain differs from "
                    f"actual link destination")
                for ltm in ltms:
                    st.markdown(
                        f"- **Display:** `{html.escape(ltm.display_domain)}` "
                        f"→ **Links to:** `{html.escape(ltm.href_domain)}`")
                st.divider()

            if report['observables']:
                all_obs = report['observables']
                threat_cnt = sum(
                    1 for o in all_obs
                    if o.vt_result
                    and o.vt_result.threat_level in [
                        "MALICIOUS", "CRITICAL"])
                clean_cnt = sum(
                    1 for o in all_obs
                    if o.vt_result
                    and o.vt_result.threat_level in [
                        "CLEAN", "LOW"])
                short_cnt = sum(
                    1 for o in all_obs if o.is_shortener)
                sus_tld_cnt = sum(
                    1 for o in all_obs if o.suspicious_tld)

                c1, c2, c3, c4, c5 = st.columns(5)
                c1.metric("Total", len(all_obs))
                c2.metric("✅ Clean", clean_cnt)
                c3.metric("🚨 Threats", threat_cnt)
                c4.metric("🔗 Shortened", short_cnt)
                c5.metric("⚠️ Sus. TLD", sus_tld_cnt)

                st.divider()

                _sort = {
                    'CRITICAL': 0, 'MALICIOUS': 1,
                    'SUSPICIOUS': 2, 'HIGH': 3,
                    'UNKNOWN': 4, 'LOW': 5, 'CLEAN': 6, '': 7}
                sorted_obs = sorted(
                    [o for o in all_obs if o.vt_result],
                    key=lambda o: _sort.get(
                        o.vt_result.threat_level or '', 7))

                for idx, obs_item in enumerate(sorted_obs, 1):
                    if obs_item.vt_result:
                        threat = (
                            obs_item.vt_result.threat_level
                            or "UNKNOWN")
                        icon = get_threat_icon(threat)
                        type_lbl = obs_item.type.upper()
                        tags = ""
                        if obs_item.source == 'pdf_uri':
                            tags += " [PDF]"
                        if obs_item.source == 'image_qr':
                            tags += " [QR]"
                        if obs_item.source == 'html_href':
                            tags += " [HREF]"
                        if obs_item.is_shortener:
                            tags += " [SHORT]"
                        if obs_item.suspicious_tld:
                            tags += " [SUS-TLD]"

                        with st.expander(
                            f"{icon} **{type_lbl}{tags} #{idx}**: "
                            f"{obs_item.defanged[:60]}",
                            expanded=threat in [
                                "MALICIOUS", "CRITICAL",
                                "SUSPICIOUS"]):
                            st.markdown(
                                f"**Value:** `{obs_item.defanged}`")
                            st.markdown(
                                render_threat_badge(threat),
                                unsafe_allow_html=True)

                            if obs_item.vt_result.reasoning:
                                if threat in [
                                        "MALICIOUS", "CRITICAL"]:
                                    st.error(
                                        f"💡 "
                                        f"{obs_item.vt_result.reasoning}")
                                elif threat == "SUSPICIOUS":
                                    st.warning(
                                        f"💡 "
                                        f"{obs_item.vt_result.reasoning}")
                                elif threat == "CLEAN":
                                    st.success(
                                        f"✅ "
                                        f"{obs_item.vt_result.reasoning}")
                                else:
                                    st.info(
                                        f"💡 "
                                        f"{obs_item.vt_result.reasoning}")

                            if (obs_item.vt_result.domain_intel
                                    and obs_item.vt_result.domain_intel
                                    .typosquat_warning):
                                st.error(
                                    obs_item.vt_result.domain_intel
                                    .typosquat_warning)
            else:
                st.success("✅ No observables extracted")

        # Tab 4: Attachments
        with tab4:
            st.subheader("📎 Attachment Analysis")
            att_risks = report.get('attachment_risks', [])
            if att_risks:
                for risk in att_risks:
                    if risk.severity == 'CRITICAL':
                        st.error(
                            f"🚨 [{risk.severity}] "
                            f"{risk.description}")
                    elif risk.severity == 'HIGH':
                        st.warning(
                            f"⚠️ [{risk.severity}] "
                            f"{risk.description}")
                    else:
                        st.info(
                            f"ℹ️ [{risk.severity}] "
                            f"{risk.description}")
                st.divider()

            if report['macros']:
                for macro in report['macros']:
                    m_color = DesignSystem.risk_score_color(
                        macro.risk_score)
                    m_icon = DesignSystem.risk_score_icon(
                        macro.risk_score)
                    st.markdown(
                        f"<div style='border-left:4px solid "
                        f"{m_color};background:{m_color}22;"
                        f"padding:14px;margin:10px 0;"
                        f"border-radius:8px'>"
                        f"<h4 style='margin:0 0 6px 0'>"
                        f"{m_icon} "
                        f"{html.escape(macro.filename)}</h4>"
                        f"<p style='margin:0;font-size:.9em'>"
                        f"<b>Type:</b> "
                        f"{html.escape(macro.file_type)} | "
                        f"<b>Risk:</b> {macro.risk_score}/100 | "
                        f"<b>Verdict:</b> "
                        f"{html.escape(str(macro.verdict))}</p>"
                        f"</div>",
                        unsafe_allow_html=True)

                    if macro.pdf_uris:
                        with st.expander(
                                f"🔗 {len(macro.pdf_uris)} "
                                f"Embedded URL(s)"):
                            for uri in macro.pdf_uris:
                                st.code(
                                    sanitize_uri_for_display(uri))

                    if macro.details:
                        with st.expander("📋 Analysis Details"):
                            for det in macro.details:
                                if any(kw in det for kw in [
                                        "CRITICAL", "MALWARE"]):
                                    st.error(f"🚨 {det}")
                                elif any(kw in det for kw in [
                                        "YARA", "SUSPICIOUS"]):
                                    st.warning(f"⚠️ {det}")
                                elif any(kw in det for kw in [
                                        "SAFE", "Clean"]):
                                    st.success(f"✅ {det}")
                                else:
                                    st.info(f"ℹ️ {det}")
            else:
                st.success("✅ No suspicious attachments")

        # Tab 5: YARA Results
        with tab5:
            st.subheader("🔴 YARA Engine Results")
            all_yara_hits = [
                (macro.filename, ym)
                for macro in report['macros']
                for ym in macro.yara_matches]
            if all_yara_hits:
                st.markdown(
                    f"**{len(all_yara_hits)} rule(s) fired**")
                for fname, ym in all_yara_hits:
                    sc = DesignSystem.get_threat_color(ym.severity)
                    st.markdown(
                        f"<div style='border-left:5px solid {sc};"
                        f"background:{sc}15;padding:16px;"
                        f"margin:10px 0;border-radius:8px'>"
                        f"<span style='color:{sc};font-weight:700'>"
                        f"🔴 {html.escape(ym.rule_name)}</span>"
                        f" [{html.escape(ym.severity)}]<br>"
                        f"{html.escape(ym.description)}<br>"
                        f"<span style='font-size:.85em;"
                        f"color:{DC['text_secondary']}'>"
                        f"📄 {html.escape(fname)}</span></div>",
                        unsafe_allow_html=True)
            else:
                if YARA_OK:
                    st.success(
                        "✅ YARA engine scanned all files — "
                        "0 matches")
                else:
                    st.warning(
                        "⚠️ YARA offline. "
                        "Install: `pip install yara-python`")

        # Tab 6: Images
        with tab6:
            st.subheader("🖼️ Image Forensics")
            if report['images']:
                for img in report['images']:
                    with st.expander(
                            f"📷 {img.filename}", expanded=True):
                        if img.image_data:
                            st.image(
                                img.image_data,
                                use_container_width=True)
                        st.text(
                            f"Format: {img.format} | "
                            f"Size: {img.size}")
                        for f in img.findings:
                            if "STEGANOGRAPHY" in f:
                                st.error(f"🚨 {f}")
                            elif "QR" in f:
                                st.warning(f"⚠️ {f}")
                            else:
                                st.info(f"ℹ️ {f}")
            else:
                st.success("✅ No images found")

        # Tab 7: Findings
        with tab7:
            st.subheader("📊 Key Findings")
            if report['findings']:
                critical_f = [
                    f for f in report['findings']
                    if f['threat'] == 'CRITICAL']
                high_f = [
                    f for f in report['findings']
                    if f['threat'] == 'HIGH']
                medium_f = [
                    f for f in report['findings']
                    if f['threat'] in ['MEDIUM', 'SUSPICIOUS']]

                if critical_f:
                    st.markdown("### 🚨 Critical")
                    for f in critical_f:
                        st.error(
                            f"**{f['category']}** — "
                            f"{f['reasoning']}")
                if high_f:
                    st.markdown("### ⚠️ High Priority")
                    for f in high_f:
                        st.warning(
                            f"**{f['category']}** — "
                            f"{f['reasoning']}")
                if medium_f:
                    with st.expander(
                            f"📊 Medium ({len(medium_f)})"):
                        for f in medium_f:
                            st.info(
                                f"**{f['category']}** — "
                                f"{f['reasoning']}")

                st.divider()
                st.dataframe(
                    pd.DataFrame(report['findings']),
                    use_container_width=True, hide_index=True)
            else:
                st.success("✅ No security issues detected")

        # Tab 8: Export
        with tab8:
            st.subheader("💾 Export Options")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.download_button(
                    label="📥 Download TXT Report",
                    data=txt_report,
                    file_name="sherlock_report.txt",
                    mime="text/plain")
            with col2:
                if PDF_OK:
                    pdf_buffer = generate_pdf_report(txt_report)
                    if pdf_buffer:
                        st.download_button(
                            label="📥 Download PDF Report",
                            data=pdf_buffer,
                            file_name="sherlock_report.pdf",
                            mime="application/pdf")
                    else:
                        st.error("PDF generation failed")
                else:
                    st.warning(
                        "Install reportlab for PDF export")
            with col3:
                st.download_button(
                    label="📥 Download JSON Data",
                    data=json.dumps(
                        report, default=str, indent=2),
                    file_name="sherlock_data.json",
                    mime="application/json")

    except Exception as e:
        st.error(f"❌ Analysis Error: {e}")
        import traceback
        with st.expander("🐛 Debug Traceback"):
            st.code(traceback.format_exc())
        logger.error(f"Analysis failed: {traceback.format_exc()}")


if __name__ == "__main__":
    main()
