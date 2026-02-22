"""Core data models — single source of truth for all typed structures."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any


@dataclass
class ThreatSignal:
    name: str
    category: str          # auth | content | attachment | network | behavioral | yara
    tier: int              # 1=hard evidence  2=strong  3=heuristic  4=contextual
    probability: float     # P(threat | signal present)
    confidence: float      # certainty in the detection itself
    title: str
    detail: str
    evidence: str = ""

    @property
    def impact(self) -> float:
        return self.probability * self.confidence


@dataclass
class TrustFactor:
    name: str
    strength: float
    confidence: float
    description: str

    @property
    def effective(self) -> float:
        return self.strength * self.confidence


@dataclass
class DomainIntel:
    domain: str
    category: str = "unknown"
    trusted: bool = False
    age_days: int = 0
    org: str = ""
    reasoning: str = ""
    typosquat: str = ""
    platform: str = ""


@dataclass
class VTResult:
    success: bool = False
    total: int = 0
    malicious: int = 0
    weighted: float = 0.0
    engines: List[str] = field(default_factory=list)
    threat_level: str = "UNKNOWN"
    reasoning: str = ""
    error: str = ""
    is_new: bool = False
    domain_intel: Optional[DomainIntel] = None


@dataclass
class AuthResult:
    spf: str = "NONE"
    dkim: str = "NONE"
    dmarc: str = "NONE"
    source_ip: str = ""
    from_domain: str = ""
    rp_domain: str = ""
    from_full: str = ""
    rp_full: str = ""
    shadow_spoof: bool = False
    gateway_trust: bool = False
    gateway_name: str = ""
    hop_count: int = 0
    hop_anomaly: str = ""
    hop_delays: List[float] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)
    live_spf: Dict = field(default_factory=dict)
    live_dmarc: Dict = field(default_factory=dict)
    live_verified: bool = False

    @property
    def auth_clean(self) -> bool:
        return (self.spf == "PASS" and self.dkim == "PASS"
                and self.dmarc == "PASS" and not self.shadow_spoof)


@dataclass
class BECResult:
    score: float = 0.0
    risk: str = "NONE"
    density: float = 0.0
    categories: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    summary: str = ""
    tier1_hit: bool = False


@dataclass
class AttachmentResult:
    filename: str
    file_type: str = "Unknown"
    has_macros: bool = False
    risk_score: int = 0
    verdict: str = ""
    details: List[str] = field(default_factory=list)
    yara_matches: List[Dict] = field(default_factory=list)
    embedded_uris: List[str] = field(default_factory=list)
    mb_found: bool = False
    mb_family: str = ""
    md5: str = ""
    sha256: str = ""


@dataclass
class ImageAnalysis:
    filename: str
    fmt: str = ""
    size: Tuple[int, int] = (0, 0)
    has_steg: bool = False
    findings: List[str] = field(default_factory=list)
    data: Optional[bytes] = None
    qr_links: List[str] = field(default_factory=list)
    ocr_text: str = ""


@dataclass
class Observable:
    type: str               # url | domain | ip
    value: str
    defanged: str
    source: str             # html_href | body | header | received | pdf_uri | qr | ...
    vt: Optional[VTResult] = None
    reputation: str = "unknown"
    threat_score: int = 0
    is_shortener: bool = False
    suspicious_tld: bool = False
    path_entropy: float = 0.0
    is_wrapper: bool = False
    otx: Dict = field(default_factory=dict)
    xforce: Dict = field(default_factory=dict)


@dataclass
class LinkMismatch:
    href: str
    display: str
    href_domain: str
    display_domain: str
    is_tracking: bool = False


@dataclass
class ScoringResult:
    threat_probability: float = 0.0
    score: int = 0
    verdict: str = "CLEAN"
    threat_level: str = "SAFE"
    confidence: int = 90
    analysis_confidence: int = 50
    signals: List[ThreatSignal] = field(default_factory=list)
    trust_factors: List[TrustFactor] = field(default_factory=list)
    correlations_applied: List[str] = field(default_factory=list)
    dampening_applied: List[str] = field(default_factory=list)
    explanation: str = ""
    signal_contributions: List[Dict] = field(default_factory=list)
    pre_escalation_score: float = 0.0
    pre_dampen_score: float = 0.0
    cluster_contributions: List[Dict] = field(default_factory=list)
    dampening_contributions: List[Dict] = field(default_factory=list)
    cluster_signal_subtotals: Dict = field(default_factory=dict)
    active_clusters: Dict[str, List[ThreatSignal]] = field(default_factory=dict)
    dominant_vector: str = ""
