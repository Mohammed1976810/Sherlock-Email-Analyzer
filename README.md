# Sherlock - Enterprise Forensic Email Analyzer v10.0

**Signal-based nonlinear scoring engine** for forensic email analysis. Every detection module produces structured `ThreatSignal` objects that feed into a probability-combination engine with correlation bonuses, trust dampening, and signal hierarchy enforcement.

## Architecture: Why v10 Is Different

Previous versions used **additive scoring** — each finding added points, features existed but didn't meaningfully contribute to the verdict, and findings didn't align with the final result.

v10 uses a **signal-based architecture** where:

1. **Every module produces `ThreatSignal` objects** with a threat probability (0-1) and confidence (0-1)
2. **Signals combine nonlinearly**: `P = 1 - prod(1 - p_i * c_i)` — diminishing returns are built in
3. **Correlation bonuses** amplify co-occurring signals (e.g., SPF fail + display name spoof)
4. **Trust factors** dampen threat probability (gateway trust, DKIM pass, known sender)
5. **Signal hierarchy** enforces floors — hard evidence (malware hash, VT consensus) guarantees minimum severity
6. The **verdict maps directly to the combined probability**, so findings always explain the result

### Signal Tiers

| Tier | Type | Example | Effect |
|------|------|---------|--------|
| 1 | Hard Evidence | Malware hash, VT ≥5 engines, YARA critical | Minimum 72% threat |
| 2 | Strong Signal | SPF fail, shadow spoofing, display name spoof | Combined normally |
| 3 | Heuristic | BEC keywords, suspicious language, high entropy URL | Combined normally |
| 4 | Contextual | URL shortener, suspicious TLD, header anomaly | Combined normally |

### Verdict Mapping

| Score | Verdict | Action |
|-------|---------|--------|
| 0-17 | CLEAN | Release |
| 18-39 | REVIEW | Deliver with warning |
| 40-64 | SUSPICIOUS | Hold for manual review |
| 65-84 | LIKELY MALICIOUS | Quarantine |
| 85-100 | MALICIOUS | Block immediately |

## Smart Features

### Text Processing
- **BeautifulSoup** DOM parsing extracts only visible text (skips `display:none`, scripts, styles)
- **Unicode de-obfuscation** normalizes Cyrillic/Greek confusables and collapses noise characters (`P.a.y.P.a.l` → `PayPal`)

### URL Intelligence
- **Path entropy analysis** — high entropy URL paths (e.g., `domain.com/8f7a9c2b3d...`) indicate phishing tokens
- **Tracking domain allowlist** — suppresses false positives from SendGrid, Mailchimp, Proofpoint SafeLinks, etc.
- **Suspicious TLD detection** — flags `.xyz`, `.top`, `.tk` and 30+ frequently-abused TLDs

### Sender Memory
- **SQLite database** tracks first-seen dates for sender domains
- Known senders (seen >30 days ago) get automatic trust dampening
- Reduces false positives on recurring correspondents

### PDF Forensics
- **pdfminer.six** decompresses PDF streams before searching for URIs (regex-only missed compressed objects)
- Regex fallback for non-standard PDFs

### Image Analysis
- **OCR via pytesseract** extracts text from image attachments and feeds it into BEC/keyword scanners
- Detects image-based phishing that bypasses text filters

### BEC Detection
- **Linguistic density** measures BEC keywords relative to total word count
- **Contradiction detection** halves BEC score when urgency words conflict with calm language ("urgent" + "no rush")
- Expanded keyword sets: wire transfer, gift cards, urgency, secrecy, authority claims, payment redirects

### Macro Analysis
- **Trusts MacroRaptor** verdict instead of redundant manual keyword grep
- Entropy analysis as supplementary check only
- YARA scanning on extracted VBA code

### Hop Timing
- Parses Received header timestamps and calculates inter-hop delays
- Flags stalling relays (>15 min delay) which indicate compromised servers or greylisting

### Future Date Tolerance
- Increased from 1 day to 3 days to reduce false positives from misconfigured mail servers

## Quick Start

```bash
pip install -r requirements.txt
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Edit secrets.toml with your API keys (optional)
streamlit run sherlock_analyzer.py
```

## API Keys (Optional)

| Service | Purpose | Free Tier |
|---------|---------|-----------|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | Multi-engine URL/domain/IP scanning | 4 req/min |
| [AbuseIPDB](https://www.abuseipdb.com/register) | Source IP reputation | 1000/day |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Known malware hash matching | Unlimited |

## System Dependencies (Optional)

```bash
# OCR support
sudo apt-get install tesseract-ocr  # Ubuntu/Debian
brew install tesseract               # macOS

# QR code scanning
sudo apt-get install libzbar0       # Ubuntu/Debian
brew install zbar                    # macOS
```

## License

MIT
