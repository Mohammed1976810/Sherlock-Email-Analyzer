"""All constants, keyword sets, patterns, and thresholds — single source of truth.

Design: sets and frozensets for O(1) membership; dicts for classification mapping;
compiled regexes at module level. No linear scans in hot paths.
"""
from __future__ import annotations
import re

# ── Limits ────────────────────────────────────────────────────────────────────
MAX_FILE_SIZE       = 50 * 1024 * 1024
MAX_OBS             = 25
VT_BUDGET_SECS      = 120
REGEX_TIMEOUT        = 2
DNS_TIMEOUT          = 3
HTTP_TIMEOUT         = 10
MAX_HTML_SIZE        = 5 * 1024 * 1024
MAX_IMAGE_SIZE       = 20 * 1024 * 1024
MAX_ZIP_EXTRACT      = 1 * 1024 * 1024
PDFMINER_TIMEOUT     = 5
CONTENT_TYPES_SEARCH = 4096

# ── Compiled patterns (module-level, compiled once) ───────────────────────────
PAT_EMAIL   = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PAT_DOMAIN  = re.compile(r'@([\w\.-]+)')
PAT_URL     = re.compile(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:[/?#][^\s<>"\']*)?', re.I)
PAT_HREF    = re.compile(r'<a\s[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.DOTALL)
PAT_IPV4    = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PAT_TZ      = re.compile(r'[+-]\d{4}')
PAT_PDF_URI = re.compile(rb'/URI\s*\(([^)]{4,500})\)')
PAT_PDF_URL = re.compile(rb'https?://[^\s\x00<>(){}\[\]"\'\\]{10,300}')

PRIVATE_IP_PATTERNS = [
    re.compile(r'^10\.'), re.compile(r'^192\.168\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^127\.'), re.compile(r'^169\.254\.'), re.compile(r'^0\.'),
]

# ── Compound TLDs — frozenset for O(1) suffix lookup ─────────────────────────
# Used by root_domain(). Previous: linear scan over 150+ strings.
COMPOUND_TLDS: frozenset = frozenset({
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
    'com.eg', 'org.eg', 'net.eg', 'edu.eg', 'gov.eg',
    'com.sa', 'org.sa', 'net.sa', 'edu.sa',
    'com.ae', 'org.ae', 'net.ae', 'ac.ae',
    'com.kw', 'com.qa', 'com.bh', 'com.om', 'com.jo', 'com.lb',
    'com.iq', 'com.tr', 'org.tr', 'net.tr', 'edu.tr',
    'com.pk', 'com.bd', 'com.lk', 'com.np', 'com.vn',
    'com.ph', 'com.my', 'com.ng', 'com.ke', 'com.gh',
    'com.co', 'com.cl', 'com.pe', 'com.ec', 'com.uy', 'com.do',
})

# Build reverse lookup: for any "co.uk" -> length 2 (parts count of the compound TLD)
_COMPOUND_TLD_PARTS = {ct: len(ct.split('.')) for ct in COMPOUND_TLDS}

# ── Domain classification sets ────────────────────────────────────────────────
GOVERNMENT_TLDS: frozenset = frozenset({
    '.gov', '.gov.uk', '.gov.au', '.gov.ca', '.gov.nz', '.gov.za', '.gov.in',
    '.gov.sg', '.gov.ae', '.gov.eg', '.gov.sa', '.gov.qa', '.mil', '.mil.uk',
    '.gc.ca', '.gob.mx', '.gob.ar', '.gob.cl', '.gob.pe', '.gob.es',
    '.go.jp', '.go.kr', '.go.th', '.go.ke', '.go.tz', '.go.id',
    '.gouv.fr', '.gouv.ci', '.govt.nz', '.government.nl',
})
EDUCATIONAL_TLDS: frozenset = frozenset({
    '.edu', '.edu.au', '.edu.cn', '.edu.hk', '.edu.tw', '.edu.sg',
    '.edu.my', '.edu.ph', '.edu.pk', '.edu.in', '.edu.eg', '.edu.sa',
    '.edu.br', '.edu.mx', '.edu.co', '.edu.ar', '.edu.ng', '.edu.za',
    '.ac.uk', '.ac.nz', '.ac.za', '.ac.in', '.ac.jp', '.ac.kr',
    '.ac.th', '.ac.id', '.ac.ir', '.ac.il', '.ac.ae', '.ac.ke',
    '.uni.edu', '.university',
})

KNOWN_PLATFORMS: dict = {
    'amazonses.com': 'Amazon SES', 'sendgrid.net': 'SendGrid',
    'mailchimp.com': 'Mailchimp', 'mailgun.org': 'Mailgun',
    'outlook.com': 'Microsoft 365', 'mandrillapp.com': 'Mandrill',
    'sharepoint.com': 'Microsoft SharePoint',
    'sharepointonline.com': 'Microsoft SharePoint Online',
    'teams.microsoft.com': 'Microsoft Teams',
    'onedrive.com': 'Microsoft OneDrive', 'office.com': 'Microsoft Office',
    'office365.com': 'Microsoft Office 365',
    'microsoftonline.com': 'Microsoft Online',
    'live.com': 'Microsoft Live', 'azure.com': 'Microsoft Azure',
    'azurewebsites.net': 'Azure Web Apps', 'windows.net': 'Azure Storage',
    'docs.google.com': 'Google Docs', 'drive.google.com': 'Google Drive',
    'meet.google.com': 'Google Meet', 'mail.google.com': 'Gmail',
    'box.com': 'Box', 'dropbox.com': 'Dropbox',
    'atlassian.net': 'Atlassian', 'slack.com': 'Slack',
    'zoom.us': 'Zoom', 'webex.com': 'Cisco Webex',
    'docusign.com': 'DocuSign', 'docusign.net': 'DocuSign',
    'adobe.com': 'Adobe', 'salesforce.com': 'Salesforce',
    'servicenow.com': 'ServiceNow', 'workday.com': 'Workday',
}
_KNOWN_PLATFORM_SET: frozenset = frozenset(KNOWN_PLATFORMS.keys())

MAJOR_TECH: frozenset = frozenset({
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'github.com', 'linkedin.com', 'facebook.com', 'twitter.com',
})

TRACKING_ALLOWLIST: frozenset = frozenset({
    'sendgrid.net', 'mailchimp.com', 'mailgun.org', 'mandrillapp.com',
    'sparkpostmail.com', 'postmarkapp.com', 'list-manage.com',
    'safelinks.protection.outlook.com', 'urldefense.proofpoint.com',
    'urldefense.com', 'url.emailprotection.link',
    'trendmicro.com', 'smex-ctp.trendmicro.com',
    'cloudmark.com', 'fireeye.com', 'mimecast.com', 'mimecastprotect.com',
    'protect-eu.mimecast.com', 'protect-us.mimecast.com',
    'barracuda.com', 'linkprotect.cudasvc.com',
    'secureweb.cisco.com', 'ironport.com', 'sophos.com',
    'proofpoint.com', 'pphosted.com', 'symantec.com',
    'hornetsecurity.com', 'retarus.com',
})

MARKETING_RP_DOMAINS: frozenset = frozenset({
    'amazonses.com', 'sendgrid.net', 'mailchimp.com', 'mailgun.org',
    'mandrillapp.com', 'sparkpostmail.com', 'postmarkapp.com',
    'bounces.google.com',
})

FREEMAIL_DOMAINS: frozenset = frozenset({
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'protonmail.com', 'icloud.com', 'mail.com', 'zoho.com', 'yandex.com',
    'gmx.com', 'live.com', 'inbox.com', 'fastmail.com', 'tutanota.com',
})

URL_SHORTENERS: frozenset = frozenset({
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'bl.ink', 'short.io', 'cutt.ly', 'rb.gy', 'snip.ly',
    'shorturl.at', 'tiny.cc', 'surl.li', 'v.gd', 'adf.ly',
})

SUSPICIOUS_TLDS: frozenset = frozenset({
    '.xyz', '.top', '.club', '.work', '.buzz', '.surf', '.rest', '.icu', '.cam',
    '.monster', '.cyou', '.cfd', '.sbs', '.click', '.link', '.gq', '.ml', '.cf',
    '.ga', '.tk', '.pw', '.cc', '.ws', '.bid', '.loan', '.trade', '.racing',
    '.review', '.cricket', '.win', '.party', '.download', '.stream',
})

DANGEROUS_EXTS: frozenset = frozenset({
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.hta', '.pif',
    '.wsf', '.msi', '.com', '.cpl', '.inf', '.reg', '.lnk', '.jar', '.jnlp',
    '.ws', '.vbe', '.jse', '.wsc', '.wsh', '.sct', '.url', '.application',
    '.iso', '.img', '.vhd', '.vhdx', '.vmdk', '.wim',
})

CONTAINER_EXTS: frozenset = frozenset({'.zip', '.7z', '.rar', '.gz', '.tar', '.bz2', '.xz'})

PROTECTED_BRANDS: frozenset = frozenset({
    'paypal.com', 'apple.com', 'microsoft.com', 'google.com', 'amazon.com',
    'netflix.com', 'facebook.com', 'instagram.com', 'whatsapp.com',
    'linkedin.com', 'twitter.com', 'x.com', 'dropbox.com', 'docusign.com',
    'adobe.com', 'office365.com', 'live.com', 'outlook.com', 'wellsfargo.com',
    'bankofamerica.com', 'chase.com', 'citibank.com', 'irs.gov', 'gov.uk',
})

# ── Display-name spoof lists ─────────────────────────────────────────────────
DISPLAY_NAME_BRANDS = [
    'microsoft', 'google', 'apple', 'amazon', 'paypal', 'facebook', 'netflix',
    'docusign', 'adobe',
]
DISPLAY_NAME_TITLES = [
    'helpdesk', 'it support', 'security team', 'admin', 'support',
    'ceo', 'cfo', 'cto', 'chief executive', 'chief financial',
    'managing director', 'human resources', 'hr department', 'accounts payable',
]

# ── Double-extension patterns (compiled) ──────────────────────────────────────
DOUBLE_EXT_PATS = [
    (re.compile(p, re.I), desc) for p, desc in [
        (r'\.pdf\.exe$', 'PDF→EXE'), (r'\.doc\.exe$', 'DOC→EXE'),
        (r'\.jpg\.exe$', 'JPG→EXE'), (r'\.pdf\.js$',  'PDF→JS'),
        (r'\.doc\.scr$', 'DOC→SCR'), (r'\.xls\.exe$', 'XLS→EXE'),
        (r'\.pdf\.vbs$', 'PDF→VBS'), (r'\.pdf\.bat$', 'PDF→BAT'),
        (r'\.docx?\.lnk$', 'DOC→LNK'), (r'\.zip\.exe$', 'ZIP→EXE'),
    ]
]

VALID_MIMES: dict = {
    'pdf': ['application/pdf'], 'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
    'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
    'doc': ['application/msword'], 'xls': ['application/vnd.ms-excel'],
    'zip': ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'],
    'png': ['image/png'], 'jpg': ['image/jpeg'], 'jpeg': ['image/jpeg'],
    'gif': ['image/gif'], 'txt': ['text/plain'], 'csv': ['text/csv', 'text/plain'],
}

# ── BEC Keywords (tiered) ────────────────────────────────────────────────────
TIER1_BEC = frozenset({'wire_transfer', 'gift_cards', 'secrecy', 'payment_redirect'})
TIER2_BEC = frozenset({'authority', 'invoice_fraud', 'mfa_bypass', 'ceo_fraud', 'credential_harvest'})
TIER3_BEC = frozenset({'urgency', 'shipping_scam'})

BEC_KEYWORDS: dict = {
    'wire_transfer':    (['wire transfer', 'bank transfer', 'swift transfer',
                          'routing number', 'beneficiary account', 'iban number',
                          'send the funds', 'transfer the funds'], 0.75),
    'gift_cards':       (['gift card', 'itunes card', 'amazon gift card',
                          'google play card', 'steam gift card', 'buy gift cards',
                          'scratch the card'], 0.70),
    'secrecy':          (['keep this between us', 'do not tell anyone',
                          'do not discuss this', 'keep this confidential from',
                          'do not cc anyone', 'reply to me only',
                          'do not forward this'], 0.65),
    'payment_redirect': (['new bank details', 'new banking details',
                          'updated bank account', 'change the payment account',
                          'new vendor account number',
                          'please update your records with'], 0.72),
    'authority':        (['skip the normal approval', 'bypass the approval process',
                          'i authorize you to proceed',
                          'acting on behalf of the ceo'], 0.50),
    'invoice_fraud':    (['please update your payment to our new account',
                          'our bank details have changed',
                          'new payment instructions attached'], 0.58),
    'mfa_bypass':       (['share the verification code with me',
                          'send me the code you received',
                          'approve the sign-in on my behalf',
                          'forward the authentication code'], 0.62),
    'ceo_fraud':        (['do not call me on this',
                          'reply only by email on this matter',
                          'handle this without going through the normal process',
                          'i cannot take calls right now but need this done'], 0.55),
    'credential_harvest': (['enter your credentials to continue',
                            'your session has expired click to re-authenticate',
                            'click here to verify your account or it will be suspended'], 0.60),
    'urgency':          (['must be done today without fail',
                          'critical deadline do not delay',
                          'process this before close of business today',
                          'cannot wait this is extremely urgent'], 0.30),
    'shipping_scam':    ([], 0.0),  # disabled — fires on legitimate carriers
}

BEC_CONTRADICTIONS = [
    (['urgent', 'immediately', 'asap'],
     ['no rush', 'no hurry', 'when you can', 'at your convenience', 'take your time']),
]

SUSPICIOUS_PHRASES: dict = {
    'verify_account':       ([r'verify your account', r'validate your account', r'click to verify', r'account.*suspend'], 20),
    'password_issue':       ([r'password.*expire', r'password.*change', r'reset.*password'], 15),
    'mailbox_full':         ([r'mailbox.*full', r'quota.*exceeded', r'limit.*reached'], 15),
    'generic_threat':       ([r'final notice', r'legal action', r'court appearance', r'arrest warrant'], 25),
    'credential_lure':      ([r'click here to verify', r'click the link below', r'update your information'], 20),
    'payment_diversion':    ([r'bank.*details.*changed', r'new.*account.*number', r'please.*update.*payment'], 30),
    'mfa_social_eng':       ([r'approve.*request', r'deny if not you', r'sign-in attempt.*detected'], 25),
    'invoice_pressure':     ([r'invoice.*attached', r'payment.*overdue', r'amount.*due.*today'], 20),
    'conversation_hijack':  ([r're:.*meeting', r'as we discussed', r'per our.*conversation'], 10),
}

# ── Legit mailer fingerprints ─────────────────────────────────────────────────
LEGIT_MAILERS: frozenset = frozenset([
    'microsoft outlook', 'thunderbird', 'apple mail', 'lotus notes', 'evolution',
    'mutt', 'sendgrid', 'mailchimp', 'postfix', 'exim', 'sendmail',
    'amazon ses', 'mailgun', 'postmark', 'gmail', 'yahoo',
])

# ── Threat cluster definitions ────────────────────────────────────────────────
# signal_prefixes: any signal whose name starts with one of these belongs to the cluster
THREAT_CLUSTERS: dict = {
    'spoof': {
        'exact': frozenset({
            'spf_fail', 'spf_softfail', 'dkim_fail', 'dmarc_fail',
            'shadow_spoofing', 'display_name_spoof', 'reply_to_hijack',
            'dns_spf_contradiction', 'dns_dmarc_contradiction',
        }),
        'prefixes': (),
        'description': 'Sender identity spoofing',
    },
    'payload': {
        'exact': frozenset({'malware_hash', 'steganography'}),
        'prefixes': ('yara_', 'pdf_tags_', 'macro_'),
        'description': 'Malicious payload delivery',
    },
    'infrastructure': {
        'exact': frozenset({
            'suspicious_tld', 'url_shortener', 'typosquat', 'high_entropy_url',
            'abuse_ip_high', 'tor_exit', 'domain_new', 'dga_domain_entropy',
            'dga_domain_consonant', 'dnsbl_listed', 'dnsbl_pbl', 'no_mx_record',
        }),
        'prefixes': ('otx_', 'xforce_'),
        'description': 'Attacker-controlled infrastructure',
    },
    'social_engineering': {
        'exact': frozenset({
            'bec_combined', 'bec_wire_transfer', 'bec_urgency', 'bec_authority',
            'bec_secrecy', 'bec_payment_redirect', 'bec_invoice_fraud',
            'bec_mfa_bypass', 'bec_ceo_fraud', 'bec_credential_harvest',
            'link_text_mismatch', 'credential_form', 'ocr_bec',
        }),
        'prefixes': (),
        'description': 'Social engineering / BEC',
    },
}

# ── Verdict mapping (score thresholds) ────────────────────────────────────────
VERDICT_MAP = [
    (85, "MALICIOUS",        "CRITICAL"),
    (65, "LIKELY MALICIOUS", "HIGH"),
    (40, "SUSPICIOUS",       "MEDIUM"),
    (18, "REVIEW",           "LOW"),
    (0,  "CLEAN",            "SAFE"),
]

# ── Category density thresholds (diminishing returns) ─────────────────────────
CATEGORY_DENSITY: dict = {
    'auth': 5, 'behavioral': 4, 'content': 3,
    'network': 3, 'attachment': 2, 'yara': 99,
}

# ── PDF security tags ────────────────────────────────────────────────────────
PDF_CRITICAL_TAGS: frozenset = frozenset({"/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/RichMedia"})
PDF_CONTEXT_TAGS:  frozenset = frozenset({"/OpenAction", "/AA", "/XFA", "/AcroForm", "/JBIG2Decode"})
PDF_META_NS: frozenset = frozenset({'ns.adobe.com', 'purl.org/dc', 'w3.org/1999', 'w3.org/2000',
                                     'schemas.openxmlformats', 'schemas.microsoft.com'})

# ── VT engine weights ────────────────────────────────────────────────────────
VT_WEIGHTS: dict = {
    'Google Safebrowsing': 3, 'Microsoft': 3, 'Kaspersky': 3, 'Sophos': 3,
    'ESET': 3, 'Fortinet': 3, 'Symantec': 3, 'BitDefender': 3,
    'McAfee': 2, 'Trend Micro': 2, 'Palo Alto Networks': 2,
}

# ── MITRE ATT&CK mapping ─────────────────────────────────────────────────────
MITRE_MAP: dict = {
    'spf_fail':             ('T1566',     'Phishing',                    'initial-access'),
    'dkim_fail':            ('T1566',     'Phishing',                    'initial-access'),
    'dmarc_fail':           ('T1566',     'Phishing',                    'initial-access'),
    'display_name_spoof':   ('T1036',     'Masquerading',                'defense-evasion'),
    'shadow_spoofing':      ('T1036.005', 'Match Legitimate Name',       'defense-evasion'),
    'reply_to_hijack':      ('T1534',     'Internal Spearphishing',      'lateral-movement'),
    'bec_combined':         ('T1657',     'Financial Theft',             'impact'),
    'link_text_mismatch':   ('T1027',     'Obfuscated Files/Info',       'defense-evasion'),
    'url_shortener':        ('T1027',     'Obfuscated Files/Info',       'defense-evasion'),
    'malware_hash':         ('T1204.002', 'Malicious File Execution',    'execution'),
    'abuse_ip_high':        ('T1071',     'App Layer Protocol',          'command-and-control'),
    'domain_new':           ('T1583.001', 'Acquire Infrastructure',      'resource-development'),
    'dga_domain_entropy':   ('T1568.002', 'Domain Generation Algorithms','command-and-control'),
}
