# Sherlock - Enterprise Forensic Email Analyzer

**v9.0 (Security Hardened)** — A complete, production-grade forensic email analysis tool built with Streamlit.

## What It Does

Sherlock analyzes `.eml` email files and produces a comprehensive forensic report covering:

- **Email Authentication** — SPF, DKIM, DMARC verification with live DNS checks
- **Sender Identity** — Display name spoofing, shadow spoofing, return-path mismatch detection
- **URL/Domain Analysis** — VirusTotal multi-engine scanning, WHOIS enrichment, typosquatting detection
- **Link-Text Mismatch Detection** — Detects `<a href="evil.com">bank.com</a>` phishing patterns
- **Attachment Forensics** — YARA behavioral rules, MalwareBazaar hash matching, macro analysis (OleTools)
- **PDF Deep Inspection** — Embedded URI extraction, JavaScript/Launch action detection
- **Office Link Extraction** — Deep inspection of `.docx/.xlsx/.pptx` relationship files
- **BEC Detection** — Wire transfer, gift card, CEO impersonation, payment redirect patterns
- **IP Reputation** — AbuseIPDB scoring with TOR exit node detection
- **Image Forensics** — QR code extraction, steganography detection, tracking pixel identification
- **Header Anomaly Detection** — Reply-To hijacking, timezone inconsistencies, hop count analysis
- **Smart Threat Narrative** — Attack pattern classification with per-signal analyst explanations

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure API keys (optional but recommended)
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Edit .streamlit/secrets.toml with your keys

# Run the analyzer
streamlit run sherlock_analyzer.py
```

## API Keys

All API keys are **optional**. The analyzer works without them but with reduced capability:

| Service | Purpose | Free Tier | Required? |
|---------|---------|-----------|-----------|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | URL/domain/IP multi-engine scanning | 4 req/min | No |
| [AbuseIPDB](https://www.abuseipdb.com/register) | Source IP reputation scoring | 1000 checks/day | No |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Known malware hash matching | Unlimited | No |

Without API keys, the analyzer still provides:
- Full email authentication analysis (SPF/DKIM/DMARC)
- YARA behavioral scanning (9 built-in rules)
- Macro analysis (OleTools)
- BEC pattern detection
- Header anomaly detection
- Link-text mismatch detection
- Display name spoof detection
- Attachment risk matrix
- WHOIS/DNS domain intelligence

## Architecture

### Scoring System

The analyzer uses a weighted scoring system (0-100) with these categories:

| Category | Weight | Description |
|----------|--------|-------------|
| SPF FAIL | 60 | Unauthorized sending server |
| SPF SOFTFAIL | 30 | Partially unauthorized sender |
| DMARC FAIL | 50 | Domain policy violation |
| DKIM FAIL | 40 | Message integrity compromised |
| Shadow Spoofing | 70 | From/Return-Path domain mismatch |
| Display Name Spoof | 55 | Brand impersonation in display name |
| Link-Text Mismatch | 35 | Displayed URL differs from actual link |
| Malware (YARA Critical) | 80 | Behavioral pattern match |
| MalwareBazaar Hit | 90 | Confirmed known malware hash |
| BEC Critical | 70 | Wire transfer + urgency patterns |
| AbuseIPDB High | 60 | High-abuse source IP |

### Verdict Thresholds

| Score | Verdict | Action |
|-------|---------|--------|
| 0-19 | CLEAN | Release |
| 20-49 | REVIEW RECOMMENDED | Soft quarantine |
| 50-79 | SUSPICIOUS | Hold for review |
| 80-99 | LIKELY MALICIOUS | Quarantine |
| 100 | MALICIOUS | Block immediately |

### Mitigation Credits

Trusted gateways (Mimecast, Proofpoint, Microsoft O365, Cisco IronPort, Barracuda) and passing authentication reduce the score, but **never** override hard threat signals like confirmed malware, malicious VT consensus, or critical YARA matches.

## Security Fixes (v8.1 → v9.0)

- **[CRITICAL]** Fixed `calculate_entropy` — was using `float.bit_length()` which crashes with `AttributeError`
- **[CRITICAL]** Fixed `SecurePatterns` staticmethod compatibility for Python < 3.10
- **[CRITICAL]** Removed duplicate dead-code loop in `analyze_attachment_risks`
- **[CRITICAL]** Removed debug comments left in production code
- **[CRITICAL]** Fixed `safe_regex_search` timeout handling on compiled patterns
- **[ACCURACY]** Added SPF softfail/temperror/permerror handling (previously ignored)
- **[ACCURACY]** Added DKIM NONE compounding with SPF failures
- **[ACCURACY]** Fixed typosquatting detection with Levenshtein edit distance and homoglyph detection
- **[ACCURACY]** Added HTML `<a href>` link extraction (primary phishing vector was missed)
- **[ACCURACY]** Added link-text mismatch detection (`<a href="evil.com">bank.com</a>`)
- **[ACCURACY]** Capped `total_score` at 100 to prevent overflow
- **[ACCURACY]** Expanded MIME type validation (added .doc, .xls, .rar, .csv, .txt, etc.)
- **[ACCURACY]** Expanded dangerous extensions (added .wsf, .msi, .com, .lnk, etc.)
- **[ACCURACY]** Expanded double extension patterns (16 patterns, up from 4)
- **[ACCURACY]** Added received chain hop analysis
- **[ACCURACY]** Added CEO/CFO authority claim detection in BEC engine
- **[ACCURACY]** Added URL shortener detection
- **[ACCURACY]** Added suspicious TLD flagging
- **[ACCURACY]** Subject line now included in suspicious language analysis
- **[ACCURACY]** Fixed marketing platform return-path matching (exact domain, not substring)
- **[COMPLETE]** Complete text/PDF report now includes all finding categories
- **[CONSIST]** Consistent scoring, error handling, and threat level mapping throughout

## Optional Dependencies

Some features require system-level packages:

```bash
# For QR code scanning (requires libzbar)
# Ubuntu/Debian:
sudo apt-get install libzbar0

# macOS:
brew install zbar

# For YARA rules
pip install yara-python
```

## License

MIT
